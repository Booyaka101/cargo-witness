'use strict';
const fs = require('fs');
const path = require('path');
const { fetchCrate } = require('./fetcher');
const { fetchGitTree } = require('./git-tree');
const { diff, normalizeSource } = require('./differ');
const { severityOf } = require('./severity');

const C = {
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', cyan: '\x1b[36m',
  bold: '\x1b[1m', dim: '\x1b[2m', reset: '\x1b[0m',
};

/**
 * `--diff <name> <version>` — human investigation view for one crate: resolve
 * the source commit, list which files diverge, and print a unified diff of any
 * modified Rust source (especially build.rs) so a human can judge the finding.
 */
async function inspectDiff(name, version, { log = console.log } = {}) {
  const crate = await fetchCrate(name, version);
  try {
    const tp = crate.trustpub;
    const attestedSha = tp && tp.sha ? tp.sha : undefined;
    const attestedRepo = tp && tp.provider === 'github' && tp.repository ? `https://github.com/${tp.repository}` : undefined;
    const vcsSha = crate.vcsInfo ? crate.vcsInfo.sha1 : undefined;

    const tree = await fetchGitTree(crate.repository, name, version, { vcsSha, attestedSha, attestedRepo });

    log(`${C.bold}cargo-witness --diff ${name}@${version}${C.reset}`);
    if (!tree.gitFiles) {
      log(`${C.yellow}No comparable source found (repository=${crate.repository || 'none'}). Nothing to diff.${C.reset}`);
      return { status: 'NO_GIT_TAG' };
    }
    const anchor =
      tree.refKind === 'attested' ? `attested commit ${short(tree.ref)} (OIDC)` :
      tree.refKind === 'vcs' ? `published commit ${short(tree.ref)} (.cargo_vcs_info.json)` :
      `tag ${tree.ref}`;
    log(`${C.dim}source: ${tree.host} ${tree.owner}/${tree.repo} @ ${anchor}${C.reset}\n`);

    const knownPrefix = crate.vcsInfo ? { knownPrefix: crate.vcsInfo.pathInVcs } : {};
    const result = diff(crate.crateFiles, tree.gitFiles, crate.prefix, knownPrefix);

    if (result.flags.length === 0 && (!result.contentSuspects || result.contentSuspects.length === 0)) {
      log(`${C.green}No divergence: every published file matches the source.${C.reset}`);
      return { status: result.status };
    }

    // Absence-based flags.
    for (const f of result.flags) {
      const col = severityOf(f) === 'high' ? C.red : severityOf(f) === 'medium' ? C.yellow : C.cyan;
      log(`${col}● ${f.flag}${f.file ? ` ${f.file}` : ''}${C.reset}`);
    }

    // Content diffs for confirmed-different .rs files.
    for (const s of result.contentSuspects || []) {
      const localPath = path.join(crate.dir, `${name}-${version}`, s.rel);
      let local = '';
      try { local = fs.readFileSync(localPath, 'utf8'); } catch { continue; }
      const gitPath = result.gitPrefix ? `${result.gitPrefix}/${s.rel}` : s.rel;
      let remote = null;
      try { remote = await tree.provider.raw(tree.ref, gitPath); } catch { /* ignore */ }
      if (remote == null) continue;
      if (normalizeSource(remote) === normalizeSource(local)) continue; // benign (line endings)

      const flag = s.isBuildRs ? 'BUILD_RS_MODIFIED' : 'SOURCE_MODIFIED';
      log(`\n${C.bold}${s.isBuildRs ? C.red : C.yellow}▼ ${flag}: ${s.rel}${C.reset}`);
      log(`${C.dim}  (− source / + published)${C.reset}`);
      printUnifiedDiff(remote, local, log);
    }
    log('');
    return { status: result.status, flags: result.flags };
  } finally {
    crate.cleanup();
  }
}

function short(sha) {
  return String(sha).slice(0, 10);
}

/** Minimal LCS-based line diff. `a`=old (git), `b`=new (published). */
function diffOps(aStr, bStr) {
  const a = String(aStr).replace(/\r\n/g, '\n').split('\n');
  const b = String(bStr).replace(/\r\n/g, '\n').split('\n');
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Uint32Array(n + 1));
  for (let i = m - 1; i >= 0; i--)
    for (let j = n - 1; j >= 0; j--)
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);

  const ops = [];
  let i = 0, j = 0;
  while (i < m && j < n) {
    if (a[i] === b[j]) { ops.push([' ', a[i]]); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { ops.push(['-', a[i]]); i++; }
    else { ops.push(['+', b[j]]); j++; }
  }
  while (i < m) ops.push(['-', a[i++]]);
  while (j < n) ops.push(['+', b[j++]]);
  return ops;
}

/** Render a unified diff (hunks with context). */
function printUnifiedDiff(aStr, bStr, log, { maxLines = 4000, context = 3 } = {}) {
  const alen = String(aStr).split('\n').length, blen = String(bStr).split('\n').length;
  if (alen > maxLines || blen > maxLines) {
    log(`${C.dim}  (files too large to inline-diff: ${alen} vs ${blen} lines)${C.reset}`);
    return;
  }
  const ops = diffOps(aStr, bStr);

  // Render only hunks around changes (with `context` unchanged lines).
  const keep = new Array(ops.length).fill(false);
  ops.forEach((o, k) => {
    if (o[0] !== ' ') for (let d = -context; d <= context; d++) if (ops[k + d]) keep[k + d] = true;
  });
  let lastPrinted = -2;
  ops.forEach((o, k) => {
    if (!keep[k]) return;
    if (k > lastPrinted + 1) log(`${C.dim}  …${C.reset}`);
    const col = o[0] === '+' ? C.green : o[0] === '-' ? C.red : C.dim;
    log(`${col}  ${o[0]} ${o[1]}${C.reset}`);
    lastPrinted = k;
  });
}

module.exports = { inspectDiff, diffOps };
