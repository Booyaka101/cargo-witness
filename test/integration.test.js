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

  const server = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url);
    let m;
    if ((m = url.match(/^\/api\/v1\/crates\/([^/]+)\/([^/?]+)$/))) {
      const e = R[`${m[1]}@${m[2]}`];
      if (!e) { res.writeHead(404); return res.end('{}'); }
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ version: {
        dl_path: `/api/v1/crates/${m[1]}/${m[2]}/download`,
        repository: e.repo, checksum: e.sha, yanked: e.yanked, trustpub_data: e.trustpub,
      } }));
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

  server.close(); db.close(); db2.close();
  console.log(`\n${passed} assertions passed.`);
  console.log(process.exitCode ? 'SOME TESTS FAILED' : 'ALL TESTS PASSED');
}

main().catch((e) => { console.error('integration crashed:', e); process.exit(1); });
