'use strict';
const fs = require('fs');
const path = require('path');
const { parseCargoLock } = require('./cargo-lock');
const { fetchCrate } = require('./fetcher');
const { fetchGitTree } = require('./git-tree');
const { diff, normalizeSource, pushFlag } = require('./differ');
const { isSuspicious, severityOf } = require('./severity');
const { applyAllowlist } = require('./allowlist');
const { pool } = require('./util');

/**
 * Core scan loop shared by --scan, --daemon and --ci.
 *
 * Fetches, extracts and diffs each not-yet-checked registry package with bounded
 * concurrency. Git trees + build.rs/source blobs are cached per owner/repo/tag.
 * Detects: BUILD_RS_INJECTED, BUILD_RS_MODIFIED, SOURCE_MODIFIED,
 * FILE_NOT_IN_GIT, BINARY_NOT_IN_GIT, CHECKSUM_MISMATCH, YANKED.
 *
 * @param {object} opts
 * @param {string} [opts.lockPath]
 * @param {Array<{name,version}>} [opts.packages]
 * @param {import('better-sqlite3').Database} [opts.db]
 * @param {(msg:string)=>void} [opts.log]
 * @param {number} [opts.concurrency]
 * @param {Array} [opts.allowRules]  allowlist rules (from src/allowlist)
 * @returns {Promise<{newCount:number, suspicious:Array, results:Array, suppressedCount:number}>}
 */
async function runScan(opts = {}) {
  const log = opts.log || (() => {});
  const db = opts.db; // a store (see src/store.js); required
  if (!db) throw new Error('runScan requires opts.db (a store instance)');
  const concurrency = Math.max(1, opts.concurrency || 5);
  const allowRules = opts.allowRules || [];

  const packages = opts.packages || parseCargoLock(opts.lockPath || 'Cargo.lock');

  const seen = new Set();
  const todo = [];
  for (const p of packages) {
    const key = `${p.name}@${p.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (db.isChecked(p.name, p.version)) continue;
    todo.push(p);
  }

  log(`${packages.length} registry package(s) in lockfile, ${todo.length} not yet checked.`);

  const treeCache = new Map();
  const blobCache = new Map();
  const state = { gitRateLimited: false, suppressed: 0 };

  const results = await pool(todo, concurrency, (p) =>
    checkOne(p, { db, log, treeCache, blobCache, state, allowRules }).catch((e) => {
      log(`  [error] ${p.name}@${p.version}: ${e.message}`);
      return { ...p, status: 'ERROR', error: e.message, flags: [] };
    })
  );

  const suspicious = results
    .filter((r) => r.status === 'SUSPICIOUS')
    .map((r) => ({ name: r.name, version: r.version, flags: r.flags }));
  const newCount = results.filter((r) => r.status !== 'ERROR').length;

  db.recordRun({ new_count: newCount, suspicious_count: suspicious.length });

  return { newCount, suspicious, results, suppressedCount: state.suppressed };
}

async function checkOne(p, ctx) {
  const { db, log, treeCache, blobCache, state, allowRules } = ctx;
  const label = `${p.name}@${p.version}`;

  const crate = await fetchCrate(p.name, p.version);
  try {
    // Trusted Publishing (OIDC) attested record — strongest anchor, unforgeable.
    const tp = crate.trustpub;
    const attestedSha = tp && tp.sha ? tp.sha : undefined;
    const attestedRepo =
      tp && tp.provider === 'github' && tp.repository ? `https://github.com/${tp.repository}` : undefined;
    const vcsSha = crate.vcsInfo ? crate.vcsInfo.sha1 : undefined;

    // Git tree (cached per repo+commit — workspace siblings from the same commit
    // share it). Prefer attested commit, then self-reported vcs commit, then tags.
    let gt = { gitFiles: null, ref: null, owner: null, repo: null, host: null, viaCommit: false, refKind: null, provider: null };
    if (!state.gitRateLimited) {
      try {
        gt = await cachedGitTree(
          crate.repository, p.name, p.version,
          { vcsSha, attestedSha, attestedRepo }, treeCache
        );
      } catch (e) {
        if (e.rateLimited) {
          state.gitRateLimited = true;
          log(`  ! ${e.message}`);
          log('  ! Skipping git comparison for remaining crates this run.');
        } else throw e;
      }
    }

    // path_in_vcs from .cargo_vcs_info.json is authoritative when present.
    const diffOpts = crate.vcsInfo ? { knownPrefix: crate.vcsInfo.pathInVcs } : {};
    const result = diff(crate.crateFiles, gt.gitFiles, crate.prefix, diffOpts);
    let flags = [...result.flags];

    // TRUSTED_PUBLISH (info) — positive assurance; verified against attested sha.
    if (tp && tp.sha) pushFlag(flags, 'TRUSTED_PUBLISH', String(tp.sha).slice(0, 7));

    // VCS_MISMATCH (info) — self-reported publish commit disagrees with the
    // attested one. Advisory; the file diff (against the attested sha) is the
    // real guard, so this never alone marks the package suspicious.
    if (attestedSha && vcsSha && attestedSha !== vcsSha) {
      pushFlag(flags, 'VCS_MISMATCH', `${String(vcsSha).slice(0, 7)}!=${String(attestedSha).slice(0, 7)}`);
    }

    // CHECKSUM_MISMATCH — artifact does not match crates.io's recorded hash.
    if (crate.checksumOk === false) {
      pushFlag(flags, 'CHECKSUM_MISMATCH', `${p.name}-${p.version}.crate`);
    }

    // YANKED — advisory.
    if (crate.yanked) pushFlag(flags, 'YANKED', null);

    // Confirm content-diff suspects (build.rs + source .rs) with normalised
    // content, so line-ending noise never triggers a MODIFIED flag.
    if (!state.gitRateLimited && gt.provider && result.contentSuspects) {
      for (const s of result.contentSuspects) {
        try {
          const localPath = path.join(crate.dir, `${p.name}-${p.version}`, s.rel);
          const local = fs.readFileSync(localPath, 'utf8');
          const gitPath = result.gitPrefix ? `${result.gitPrefix}/${s.rel}` : s.rel;
          const remote = await cachedBlob(gt, gitPath, blobCache);
          if (remote != null && normalizeSource(remote) !== normalizeSource(local)) {
            pushFlag(flags, s.isBuildRs ? 'BUILD_RS_MODIFIED' : 'SOURCE_MODIFIED', s.rel);
          }
        } catch (e) {
          if (e.rateLimited) state.gitRateLimited = true;
          // else: leave unconfirmed (non-fatal)
        }
      }
    }

    // Allowlist suppression.
    const { kept, suppressed } = applyAllowlist(allowRules, p.name, p.version, flags);
    if (suppressed.length) {
      state.suppressed += suppressed.length;
      log(`  (suppressed ${suppressed.length} allowlisted finding(s) for ${label})`);
    }
    flags = kept;

    // Status: SUSPICIOUS if any flag is >= medium severity; NO_GIT_TAG carries
    // through when we had no tree and produced no flags.
    let status;
    if (isSuspicious(flags)) status = 'SUSPICIOUS';
    else if (result.status === 'NO_GIT_TAG') status = 'NO_GIT_TAG';
    else status = 'CLEAN';

    db.recordPackage({ name: p.name, version: p.version, status, flags });

    const marker =
      status === 'SUSPICIOUS' ? 'SUSPICIOUS !!' :
      status === 'CLEAN' ? 'clean' : status.toLowerCase();
    const root = result.gitPrefix ? ` (git root: ${result.gitPrefix})` : '';
    const at = gt.viaCommit ? ` @${String(gt.ref).slice(0, 7)}${gt.refKind === 'attested' ? '✓' : ''}` : '';
    const hostTag = gt.host && gt.host !== 'github' ? ` [${gt.host}]` : '';
    const info = flags.filter((f) => severityOf(f) === 'info').map((f) => f.flag).join(',');
    log(`  [${marker}] ${label}${hostTag}${root}${at}${info ? ` {${info}}` : ''}`);

    return { ...p, status, flags, gitPrefix: result.gitPrefix, viaCommit: gt.viaCommit, ref: gt.ref, host: gt.host, refKind: gt.refKind };
  } finally {
    crate.cleanup();
  }
}

async function cachedGitTree(repository, name, version, opts, cache) {
  // Key by the strongest available commit (workspace siblings published from the
  // same release commit reuse one fetch); else by version.
  const anchor = opts.attestedSha || opts.vcsSha || 'v' + version;
  const preKey = `${opts.attestedRepo || repository}::${anchor}`;
  if (cache.has(preKey)) return cache.get(preKey);
  const gt = await fetchGitTree(repository, name, version, opts);
  cache.set(preKey, gt);
  return gt;
}

async function cachedBlob(gt, filePath, cache) {
  const key = `${gt.host}/${gt.owner}/${gt.repo}/${gt.ref}/${filePath}`;
  if (cache.has(key)) return cache.get(key);
  const content = await gt.provider.raw(gt.ref, filePath);
  cache.set(key, content);
  return content;
}

module.exports = { runScan };
