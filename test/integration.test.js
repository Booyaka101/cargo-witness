'use strict';
// End-to-end OFFLINE integration test. A local HTTP server mocks crates.io API,
// the static CDN, the GitHub git-trees API (with real blob shas) and
// raw.githubusercontent.com. We build real .crate tarballs on the fly and run
// the full scanner, asserting every detection plus allowlist suppression.
//
// Server runs in-process; scanner is driven in-process (no child spawn), so
// there is no spawnSync/serve deadlock.

const assert = require('assert');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const tar = require('tar');

let passed = 0;
function okName(n) { passed++; console.log(`  ok  ${n}`); }
function failName(n, e) { console.error(`  FAIL ${n}: ${e.message}`); process.exitCode = 1; }

function gitBlobSha(buf) {
  const h = crypto.createHash('sha1');
  h.update(`blob ${buf.length}\0`); h.update(buf);
  return h.digest('hex');
}

// Build a gzipped .crate tarball from { relpath: content }.
async function buildCrate(name, version, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-build-'));
  const top = path.join(dir, `${name}-${version}`);
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(top, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  const cratePath = path.join(dir, `${name}-${version}.crate`);
  await tar.create({ gzip: true, file: cratePath, cwd: dir }, [`${name}-${version}`]);
  const buf = fs.readFileSync(cratePath);
  const sha = crypto.createHash('sha256').update(buf).digest('hex');
  fs.rmSync(dir, { recursive: true, force: true });
  return { buf, sha };
}

async function main() {
  const R = {}; // name@version -> fixture
  const clean = 'fn main() { println!("cargo:rerun-if-changed=build.rs"); }\n';

  async function add(name, version, { files, repo, tag, commit, gitFiles, yanked, checksumOverride, trustpub }) {
    const { buf, sha } = await buildCrate(name, version, files);
    R[`${name}@${version}`] = {
      buf, sha: checksumOverride || sha, repo, tag, commit,
      gitFiles: gitFiles || {}, // gitRepoPath -> content
      yanked: !!yanked, trustpub: trustpub || null,
    };
  }
  const vcs = (sha1, pathInVcs = '') => JSON.stringify({ git: { sha1 }, path_in_vcs: pathInVcs });

  // 1. CLEAN
  await add('clean', '1.0.0', {
    files: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}', 'build.rs': clean },
    repo: 'https://github.com/acme/clean', tag: 'v1.0.0',
    gitFiles: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}', 'build.rs': clean },
  });
  // 2. BUILD_RS_INJECTED
  await add('injected', '2.0.0', {
    files: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}', 'build.rs': 'fn main(){ exfil(); }' },
    repo: 'https://github.com/acme/injected', tag: 'v2.0.0',
    gitFiles: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}' },
  });
  // 3. BUILD_RS_MODIFIED (build.rs in both, content differs)
  await add('modified', '3.0.0', {
    files: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}', 'build.rs': 'fn main(){ steal(); }' },
    repo: 'https://github.com/acme/modified', tag: 'v3.0.0',
    gitFiles: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}', 'build.rs': 'fn main(){ /* ok */ }' },
  });
  // 4. WORKSPACE member (build.rs under subdir, matching)
  await add('wsmember', '4.0.0', {
    files: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}', 'src/b.rs': 'pub fn b(){}', 'build.rs': clean },
    repo: 'https://github.com/acme/workspace', tag: 'v4.0.0',
    gitFiles: {
      'wsmember/Cargo.toml': 'a', 'wsmember/src/lib.rs': 'pub fn a(){}',
      'wsmember/src/b.rs': 'pub fn b(){}', 'wsmember/build.rs': clean, 'other/Cargo.toml': 'z',
    },
  });
  // 5. CHECKSUM_MISMATCH
  await add('badsum', '5.0.0', {
    files: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}' },
    repo: 'https://github.com/acme/badsum', tag: 'v5.0.0',
    gitFiles: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}' },
    checksumOverride: 'deadbeef'.repeat(8),
  });
  // 6. BINARY_NOT_IN_GIT
  await add('binblob', '6.0.0', {
    files: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}', 'vendor/prebuilt.so': Buffer.from([0, 1, 2, 3]) },
    repo: 'https://github.com/acme/binblob', tag: 'v6.0.0',
    gitFiles: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}' },
  });
  // 7. SOURCE_MODIFIED (non-build.rs .rs content differs)
  await add('srcmod', '7.0.0', {
    files: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){ backdoor(); }' },
    repo: 'https://github.com/acme/srcmod', tag: 'v7.0.0',
    gitFiles: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}' },
  });
  // 8. FILE_NOT_IN_GIT (extra .rs only in artifact)
  await add('extrs', '8.0.0', {
    files: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}', 'src/sneaky.rs': 'fn x(){}' },
    repo: 'https://github.com/acme/extrs', tag: 'v8.0.0',
    gitFiles: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}' },
  });
  // 9. YANKED (otherwise clean)
  await add('yankedcrate', '9.0.0', {
    files: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}' },
    repo: 'https://github.com/acme/yankedcrate', tag: 'v9.0.0',
    gitFiles: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}' }, yanked: true,
  });
  // 10. EXACT-COMMIT verification via .cargo_vcs_info.json (NO tag served —
  //     only resolvable by commit sha). Root crate.
  const SHA10 = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
  await add('vcsclean', '10.0.0', {
    files: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}', 'build.rs': clean, '.cargo_vcs_info.json': vcs(SHA10, '') },
    repo: 'https://github.com/acme/vcsclean', commit: SHA10, // no tag
    gitFiles: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}', 'build.rs': clean },
  });
  // 11. EXACT-COMMIT + authoritative path_in_vcs (workspace member, no tag).
  const SHA11 = 'ffee0011223344556677889900aabbccddeeff00';
  await add('vcswsm', '11.0.0', {
    files: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}', '.cargo_vcs_info.json': vcs(SHA11, 'member') },
    repo: 'https://github.com/acme/vcsws', commit: SHA11, // no tag
    gitFiles: { 'member/Cargo.toml': 'a', 'member/src/lib.rs': 'pub fn a(){}', 'other/Cargo.toml': 'z' },
  });

  // 12. TRUSTED_PUBLISH: attested commit (no vcs info); verified via trustpub.sha.
  const SHA12 = '1234abcd5678ef90';
  await add('tpclean', '12.0.0', {
    files: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}', 'build.rs': clean },
    repo: 'https://github.com/acme/tp', commit: SHA12,
    gitFiles: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}', 'build.rs': clean },
    trustpub: { provider: 'github', repository: 'acme/tp', sha: SHA12 },
  });
  // 13. VCS_MISMATCH: attested sha != self-reported .cargo_vcs_info sha1.
  const SHA13A = 'aaaa1111bbbb2222';
  const SHA13B = 'cccc3333dddd4444';
  await add('tpmismatch', '13.0.0', {
    files: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}', '.cargo_vcs_info.json': vcs(SHA13B, '') },
    repo: 'https://github.com/acme/tpm', commit: SHA13A, // tree served at ATTESTED sha
    gitFiles: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}' },
    trustpub: { provider: 'github', repository: 'acme/tpm', sha: SHA13A },
  });

  const findRepoRef = (owner, repo, ref) =>
    Object.values(R).find((e) => e.repo === `https://github.com/${owner}/${repo}` && (e.tag === ref || e.commit === ref));

  // Crates whose versions are all gone from the mock registry but whose
  // crate-level endpoint still answers 200 (the arrayref@0.3.10 shape).
  const DELETED_BUT_CRATE_EXISTS = new Set(['goneversion']);
  const hits = { api: 0 }; // every /api/v1/crates request (absence + re-check accounting)

  const server = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url);
    let m;
    if ((m = url.match(/^\/api\/v1\/crates\/([^/]+)\/([^/?]+)$/))) {
      hits.api++;
      if (m[1] === 'boom') { res.writeHead(500); return res.end('{}'); }
      const e = R[`${m[1]}@${m[2]}`];
      if (!e) { res.writeHead(404); return res.end('{}'); }
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ version: {
        dl_path: `/api/v1/crates/${m[1]}/${m[2]}/download`,
        repository: e.repo, checksum: e.sha, yanked: e.yanked, trustpub_data: e.trustpub,
      } }));
    }
    if ((m = url.match(/^\/api\/v1\/crates\/([^/?]+)$/))) {
      hits.api++;
      const exists = DELETED_BUT_CRATE_EXISTS.has(m[1]) || Object.keys(R).some((k) => k.startsWith(`${m[1]}@`));
      if (!exists) { res.writeHead(404); return res.end('{}'); }
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ crate: { name: m[1] } }));
    }
    if ((m = url.match(/^\/crates\/([^/]+)\/([^/]+)-([^/]+)\.crate$/))) {
      const e = R[`${m[2]}@${m[3]}`];
      if (!e) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'content-type': 'application/gzip' });
      return res.end(e.buf);
    }
    if ((m = url.match(/^\/repos\/([^/]+)\/([^/]+)\/git\/trees\/([^/?]+)/))) {
      const e = findRepoRef(m[1], m[2], m[3]);
      if (!e) { res.writeHead(404); return res.end('{"message":"Not Found"}'); }
      const tree = Object.entries(e.gitFiles).map(([p, content]) => ({
        path: p, type: 'blob', sha: gitBlobSha(Buffer.from(content)),
      }));
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ tree, truncated: false }));
    }
    if ((m = url.match(/^\/([^/]+)\/([^/]+)\/([^/]+)\/(.+)$/))) {
      const e = findRepoRef(m[1], m[2], m[3]);
      const content = e && e.gitFiles[m[4]];
      if (content == null) { res.writeHead(404); return res.end(); }
      res.writeHead(200); return res.end(content);
    }
    res.writeHead(404); res.end();
  });

  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  process.env.CARGO_WITNESS_CRATES_API = `${base}/api/v1`;
  process.env.CARGO_WITNESS_CRATES_STATIC = base;
  process.env.CARGO_WITNESS_GITHUB_API = base;
  process.env.CARGO_WITNESS_GITHUB_RAW = base;
  process.env.CARGO_WITNESS_NO_NOTIFY = '1';

  const { runScan } = require('../src/scanner');
  const { openDb } = require('../src/db');

  const dbPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cw-db-')), 'witness.db');
  const db = openDb(dbPath);

  const packages = [
    'clean@1.0.0', 'injected@2.0.0', 'modified@3.0.0', 'wsmember@4.0.0', 'badsum@5.0.0',
    'binblob@6.0.0', 'srcmod@7.0.0', 'extrs@8.0.0', 'yankedcrate@9.0.0',
    'vcsclean@10.0.0', 'vcswsm@11.0.0', 'tpclean@12.0.0', 'tpmismatch@13.0.0',
  ].map((k) => { const [name, version] = k.split('@'); return { name, version }; });

  const { results, suspicious } = await runScan({ packages, db, concurrency: 4, log: () => {} });
  const by = {}; for (const r of results) by[r.name] = r;
  const flagsOf = (r) => (r.flags || []).map((f) => f.flag);

  const cases = [
    ['clean crate -> CLEAN', () => assert.strictEqual(by['clean'].status, 'CLEAN')],
    ['injected build.rs -> BUILD_RS_INJECTED', () => assert.ok(flagsOf(by['injected']).includes('BUILD_RS_INJECTED'))],
    ['modified build.rs -> BUILD_RS_MODIFIED', () => assert.ok(flagsOf(by['modified']).includes('BUILD_RS_MODIFIED'), JSON.stringify(by['modified']))],
    ['workspace member -> CLEAN, prefix resolved', () => { assert.strictEqual(by['wsmember'].status, 'CLEAN', JSON.stringify(by['wsmember'])); assert.strictEqual(by['wsmember'].gitPrefix, 'wsmember'); }],
    ['bad checksum -> CHECKSUM_MISMATCH', () => assert.ok(flagsOf(by['badsum']).includes('CHECKSUM_MISMATCH'))],
    ['binary only in artifact -> BINARY_NOT_IN_GIT', () => assert.ok(flagsOf(by['binblob']).includes('BINARY_NOT_IN_GIT'))],
    ['source file modified -> SOURCE_MODIFIED', () => assert.ok(flagsOf(by['srcmod']).includes('SOURCE_MODIFIED'), JSON.stringify(by['srcmod']))],
    ['extra .rs -> FILE_NOT_IN_GIT', () => assert.ok(flagsOf(by['extrs']).includes('FILE_NOT_IN_GIT'))],
    ['yanked (else clean) -> CLEAN + YANKED flag', () => { assert.strictEqual(by['yankedcrate'].status, 'CLEAN', JSON.stringify(by['yankedcrate'])); assert.ok(flagsOf(by['yankedcrate']).includes('YANKED')); }],
    ['exact-commit verify (no tag) -> CLEAN via commit', () => { assert.strictEqual(by['vcsclean'].status, 'CLEAN', JSON.stringify(by['vcsclean'])); assert.strictEqual(by['vcsclean'].viaCommit, true); }],
    ['exact-commit + authoritative path_in_vcs -> CLEAN, prefix=member', () => { assert.strictEqual(by['vcswsm'].status, 'CLEAN', JSON.stringify(by['vcswsm'])); assert.strictEqual(by['vcswsm'].gitPrefix, 'member'); assert.strictEqual(by['vcswsm'].viaCommit, true); }],
    ['trusted-publish attested -> CLEAN + TRUSTED_PUBLISH, refKind=attested', () => { assert.strictEqual(by['tpclean'].status, 'CLEAN', JSON.stringify(by['tpclean'])); assert.ok(flagsOf(by['tpclean']).includes('TRUSTED_PUBLISH')); assert.strictEqual(by['tpclean'].refKind, 'attested'); }],
    ['attested != self-reported -> VCS_MISMATCH (info, still clean)', () => { assert.ok(flagsOf(by['tpmismatch']).includes('VCS_MISMATCH'), JSON.stringify(by['tpmismatch'])); assert.strictEqual(by['tpmismatch'].status, 'CLEAN'); }],
    ['6 suspicious total (info-only flags stay clean)', () => assert.strictEqual(suspicious.length, 6, `got ${suspicious.length}`)],
  ];
  for (const [n, fn] of cases) { try { fn(); okName(n); } catch (e) { failName(n, e); } }

  // Allowlist: suppress binblob's binary finding -> becomes CLEAN.
  const db2 = openDb(path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cw-db2-')), 'w.db'));
  const allowRules = [{ name: 'binblob', flag: 'BINARY_NOT_IN_GIT' }];
  const r2 = await runScan({ packages: [{ name: 'binblob', version: '6.0.0' }], db: db2, allowRules, log: () => {} });
  try {
    assert.strictEqual(r2.results[0].status, 'CLEAN', JSON.stringify(r2.results[0]));
    assert.strictEqual(r2.suppressedCount, 1);
    okName('allowlist suppresses BINARY_NOT_IN_GIT -> CLEAN');
  } catch (e) { failName('allowlist', e); }

  // --- Registry absence (the arrayref@0.3.10 pattern, 2026-08-20) -----------
  const { createMemoryStore } = require('../src/store');
  const flagNames = (r) => (r.flags || []).map((f) => f.flag);

  const rAbsent = await runScan({
    packages: [
      { name: 'goneversion', version: '1.0.0' },
      { name: 'gonecrate', version: '1.0.0' },
    ],
    db: createMemoryStore(), log: () => {},
  });
  const byA = {}; for (const r of rAbsent.results) byA[r.name] = r;
  try {
    assert.strictEqual(byA['goneversion'].status, 'SUSPICIOUS', JSON.stringify(byA['goneversion']));
    assert.ok(flagNames(byA['goneversion']).includes('VERSION_REMOVED'));
    assert.strictEqual(byA['goneversion'].flags[0].severity, 'high');
    assert.ok(byA['goneversion'].flags[0].detail.includes('removed'), byA['goneversion'].flags[0].detail);
    okName('version 404 + crate 200 -> SUSPICIOUS {VERSION_REMOVED} (high)');
  } catch (e) { failName('VERSION_REMOVED', e); }
  try {
    assert.strictEqual(byA['gonecrate'].status, 'SUSPICIOUS', JSON.stringify(byA['gonecrate']));
    assert.ok(flagNames(byA['gonecrate']).includes('CRATE_REMOVED'));
    assert.ok(byA['gonecrate'].flags[0].detail.includes('unreachable'), byA['gonecrate'].flags[0].detail);
    assert.strictEqual(rAbsent.suspicious.length, 2);
    okName('both 404 -> SUSPICIOUS {CRATE_REMOVED}, detail says crate unreachable');
  } catch (e) { failName('CRATE_REMOVED', e); }

  // Allowlist can suppress an absence finding.
  const rAllow = await runScan({
    packages: [{ name: 'goneversion', version: '1.0.0' }],
    db: createMemoryStore(), log: () => {},
    allowRules: [{ name: 'goneversion', flag: 'VERSION_REMOVED' }],
  });
  try {
    assert.strictEqual(rAllow.results[0].status, 'CLEAN', JSON.stringify(rAllow.results[0]));
    assert.strictEqual(rAllow.suppressedCount, 1);
    okName('allowlist suppresses VERSION_REMOVED -> CLEAN');
  } catch (e) { failName('allowlist VERSION_REMOVED', e); }

  // A 5xx is still an ERROR (fetchRetry owns it), never a removal finding.
  const rBoom = await runScan({
    packages: [{ name: 'boom', version: '1.0.0' }],
    db: createMemoryStore(), log: () => {},
  });
  try {
    assert.strictEqual(rBoom.results[0].status, 'ERROR', JSON.stringify(rBoom.results[0]));
    assert.ok(rBoom.results[0].error.includes('500'), rBoom.results[0].error);
    assert.strictEqual(rBoom.suspicious.length, 0);
    okName('500 -> ERROR, not a finding');
  } catch (e) { failName('500 -> ERROR', e); }

  // Alternate-registry package: a crates.io 404 proves nothing -> ERROR.
  const rAlt = await runScan({
    packages: [{ name: 'altpkg', version: '1.0.0', source: 'registry+sparse+https://my-registry.example/index/' }],
    db: createMemoryStore(), log: () => {},
  });
  try {
    assert.strictEqual(rAlt.results[0].status, 'ERROR', JSON.stringify(rAlt.results[0]));
    assert.ok(rAlt.results[0].error.includes('404'));
    okName('alt-registry 404 -> ERROR, never CRATE_REMOVED');
  } catch (e) { failName('alt-registry', e); }

  // --- Re-check pass: a version deleted AFTER it was cleared ----------------
  await add('recheckgone', '14.0.0', {
    files: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}' },
    repo: 'https://github.com/acme/recheckgone', tag: 'v14.0.0',
    gitFiles: { 'Cargo.toml': 'a', 'src/lib.rs': 'pub fn a(){}' },
  });
  const rgPkg = [{ name: 'recheckgone', version: '14.0.0' }];
  const db5 = openDb(path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cw-db5-')), 'w.db'));
  const s1 = await runScan({ packages: rgPkg, db: db5, log: () => {} });
  try {
    assert.strictEqual(s1.results[0].status, 'CLEAN', JSON.stringify(s1.results[0]));
    okName('re-check seed: crate scans CLEAN while still on the registry');
  } catch (e) { failName('recheck seed', e); }

  // The registry deletes the version (crate remains).
  delete R['recheckgone@14.0.0'];
  DELETED_BUT_CRATE_EXISTS.add('recheckgone');

  // Within 24h: no registry requests at all (scan pass skips, re-check not due).
  let before = hits.api;
  const s2 = await runScan({ packages: rgPkg, db: db5, log: () => {} });
  try {
    assert.strictEqual(hits.api, before, `expected 0 requests, got ${hits.api - before}`);
    assert.strictEqual(s2.suspicious.length, 0);
    assert.strictEqual(s2.rechecked.length, 0);
    okName('unchanged lockfile within 24h -> no re-check requests');
  } catch (e) { failName('recheck within 24h', e); }

  // Stale row + --no-recheck: still no requests.
  db5._db.prepare('UPDATE packages SET meta_checked_at = ?').run(Date.now() - 25 * 3600 * 1000);
  before = hits.api;
  const s3 = await runScan({ packages: rgPkg, db: db5, log: () => {}, recheck: false });
  try {
    assert.strictEqual(hits.api, before);
    assert.strictEqual(s3.rechecked.length, 0);
    okName('--no-recheck skips the re-check pass');
  } catch (e) { failName('--no-recheck', e); }

  // Stale row, re-check on: the CLEAN verdict flips to SUSPICIOUS.
  const s4 = await runScan({ packages: rgPkg, db: db5, log: () => {} });
  try {
    assert.strictEqual(s4.rechecked.length, 1, JSON.stringify(s4.rechecked));
    assert.strictEqual(s4.rechecked[0].status, 'SUSPICIOUS');
    assert.ok(flagNames(s4.rechecked[0]).includes('VERSION_REMOVED'), JSON.stringify(s4.rechecked[0]));
    assert.strictEqual(s4.suspicious.length, 1);
    assert.strictEqual(db5.getStoredStatus('recheckgone', '14.0.0').status, 'SUSPICIOUS');
    assert.ok(db5.getSuspicious().some((r) => r.name === 'recheckgone'));
    okName('re-check flips a previously-CLEAN deleted version to SUSPICIOUS');
  } catch (e) { failName('recheck flip', e); }

  // Fresh meta_checked_at after the re-check: next run is quiet again.
  before = hits.api;
  const s5 = await runScan({ packages: rgPkg, db: db5, log: () => {} });
  try {
    assert.strictEqual(hits.api, before);
    assert.strictEqual(s5.suspicious.length, 0);
    okName('re-checked row is fresh again -> no repeat requests or re-alerts');
  } catch (e) { failName('recheck refresh', e); }

  // Memory-store backend parity for the re-check.
  const mem = createMemoryStore();
  mem.recordPackage({ name: 'recheckgone', version: '14.0.0', status: 'CLEAN', flags: [] });
  mem._packages.get('recheckgone@14.0.0').meta_checked_at = Date.now() - 25 * 3600 * 1000;
  const m1 = await runScan({ packages: rgPkg, db: mem, log: () => {} });
  try {
    assert.strictEqual(m1.rechecked.length, 1, JSON.stringify(m1.rechecked));
    assert.strictEqual(m1.rechecked[0].status, 'SUSPICIOUS');
    assert.ok(flagNames(m1.rechecked[0]).includes('VERSION_REMOVED'));
    okName('memory store re-check parity');
  } catch (e) { failName('memory recheck', e); }

  // Rate limiting during the re-check degrades to a note, never a finding.
  const mem2 = createMemoryStore();
  mem2.recordPackage({ name: 'boom', version: '1.0.0', status: 'CLEAN', flags: [] });
  mem2._packages.get('boom@1.0.0').meta_checked_at = Date.now() - 25 * 3600 * 1000;
  const m2 = await runScan({ packages: [{ name: 'boom', version: '1.0.0' }], db: mem2, log: () => {} });
  try {
    assert.strictEqual(m2.rechecked.length, 0);
    assert.strictEqual(m2.suspicious.length, 0);
    assert.strictEqual(mem2.getStoredStatus('boom', '1.0.0').status, 'CLEAN');
    okName('5xx during re-check keeps the previous verdict');
  } catch (e) { failName('recheck 5xx', e); }

  // --- CLI end to end: exit codes, human output, --json, SARIF --------------
  const { spawn } = require('child_process');
  const binPath = path.join(__dirname, '..', 'bin', 'cargo-witness.js');
  const runCli = (cliArgs) => new Promise((resolve) => {
    const child = spawn(process.execPath, [binPath, ...cliArgs], { env: process.env });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
  const cratesIoSrc = 'registry+https://github.com/rust-lang/crates.io-index';
  const lockFor = (entries) => {
    const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cw-lock-')), 'Cargo.lock');
    fs.writeFileSync(p, entries.map(([n, v]) =>
      `[[package]]\nname = "${n}"\nversion = "${v}"\nsource = "${cratesIoSrc}"\n`).join('\n'));
    return p;
  };
  const tmpDb = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cw-clidb-')), 'w.db');

  const goneLock = lockFor([['goneversion', '1.0.0'], ['gonecrate', '1.0.0']]);
  const sarifPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cw-sarif-')), 'out.sarif');
  const cli1 = await runCli(['--scan', '--lock', goneLock, '--db', tmpDb(), '--sarif', sarifPath]);
  try {
    assert.strictEqual(cli1.code, 1, `exit ${cli1.code}\n${cli1.stdout}\n${cli1.stderr}`);
    assert.ok(cli1.stdout.includes('  [SUSPICIOUS !!] goneversion@1.0.0 {VERSION_REMOVED}'), cli1.stdout);
    assert.ok(cli1.stdout.includes('removed from the registry'), cli1.stdout);
    assert.ok(cli1.stdout.includes('  [SUSPICIOUS !!] gonecrate@1.0.0 {CRATE_REMOVED}'), cli1.stdout);
    okName('CLI --scan on a removed version exits 1 with the flagged line + detail');
  } catch (e) { failName('CLI exit 1', e); }
  try {
    const sarif = JSON.parse(fs.readFileSync(sarifPath, 'utf8'));
    const rules = sarif.runs[0].tool.driver.rules;
    for (const id of ['VERSION_REMOVED', 'CRATE_REMOVED']) {
      const rule = rules.find((r) => r.id === id);
      assert.ok(rule, `missing SARIF rule ${id}`);
      assert.strictEqual(rule.defaultConfiguration.level, 'error');
      assert.ok(sarif.runs[0].results.some((r) => r.ruleId === id && r.level === 'error'));
    }
    okName('SARIF carries VERSION_REMOVED + CRATE_REMOVED rules at level error');
  } catch (e) { failName('SARIF rules', e); }

  const cli2 = await runCli(['--scan', '--lock', goneLock, '--db', tmpDb(), '--json', '-q']);
  try {
    assert.strictEqual(cli2.code, 1);
    const j = JSON.parse(cli2.stdout);
    assert.strictEqual(j.suspiciousCount, 2);
    assert.strictEqual(j.recheckedCount, 0);
    assert.ok(j.suspicious.some((s) => s.name === 'goneversion' && s.flags[0].flag === 'VERSION_REMOVED'));
    assert.ok(j.results.some((r) => r.name === 'gonecrate' && r.status === 'SUSPICIOUS'));
    okName('CLI --json carries the new flags and recheckedCount');
  } catch (e) { failName('CLI --json', e); }

  const cli3 = await runCli(['--scan', '--lock', lockFor([['clean', '1.0.0']]), '--db', tmpDb(), '-q']);
  try {
    assert.strictEqual(cli3.code, 0, `exit ${cli3.code}\n${cli3.stdout}\n${cli3.stderr}`);
    okName('CLI --scan on a still-published version exits 0');
  } catch (e) { failName('CLI exit 0', e); }

  server.close(); db.close(); db2.close(); db5.close();
  console.log(`\n${passed} assertions passed.`);
  console.log(process.exitCode ? 'SOME TESTS FAILED' : 'ALL TESTS PASSED');
}

main().catch((e) => { console.error('integration crashed:', e); process.exit(1); });
