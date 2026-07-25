'use strict';
// Unit test for the multi-host providers. A local mock serves GitHub, GitLab
// (paginated) and Gitea/Codeberg tree+raw endpoints on distinct path prefixes.

const assert = require('assert');
const http = require('http');
const crypto = require('crypto');

let passed = 0;
function test(name) { passed++; console.log(`  ok  ${name}`); }
function fail(name, e) { console.error(`  FAIL ${name}: ${e.message}`); process.exitCode = 1; }

const sha = (s) => crypto.createHash('sha1').update(`blob ${Buffer.byteLength(s)}\0${s}`).digest('hex');

async function main() {
  // Fixture: files at a ref, per host.
  const FILES = { 'src/lib.rs': 'A', 'build.rs': 'B', 'src/util.rs': 'C' };
  const REF = 'commitsha123';

  const server = http.createServer((req, res) => {
    const u = require('url').parse(req.url, true);
    const p = decodeURIComponent(u.pathname);
    let m;
    // GitHub tree
    if ((m = p.match(/^\/repos\/([^/]+)\/([^/]+)\/git\/trees\/(.+)$/))) {
      if (m[3] === '429ref') { res.writeHead(403, { 'x-ratelimit-remaining': '0' }); return res.end('{}'); }
      const tree = Object.entries(FILES).map(([path, c]) => ({ path, type: 'blob', sha: sha(c) }));
      res.writeHead(200); return res.end(JSON.stringify({ tree, truncated: false }));
    }
    // GitHub raw: /ghraw/o/r/ref/path
    if ((m = p.match(/^\/ghraw\/([^/]+)\/([^/]+)\/([^/]+)\/(.+)$/))) {
      const c = FILES[m[4]]; if (c == null) { res.writeHead(404); return res.end(); }
      res.writeHead(200); return res.end(c);
    }
    // GitLab tree (paginated): /glapi/projects/ENC/repository/tree
    if (p === '/glapi/projects/o%2Fr/repository/tree' || /^\/glapi\/projects\/.+\/repository\/tree$/.test(p)) {
      const page = Number(u.query.page || '1');
      const entries = Object.entries(FILES).map(([path, c]) => ({ path, type: 'blob', id: sha(c) }));
      // page 1 -> first 2 with x-next-page:2 ; page 2 -> last 1, no next
      if (page === 1) {
        res.writeHead(200, { 'x-next-page': '2' });
        return res.end(JSON.stringify(entries.slice(0, 2)));
      }
      res.writeHead(200, { 'x-next-page': '' });
      return res.end(JSON.stringify(entries.slice(2)));
    }
    // GitLab raw: /glraw/o/r/-/raw/ref/path
    if ((m = p.match(/^\/glraw\/([^/]+)\/([^/]+)\/-\/raw\/([^/]+)\/(.+)$/))) {
      const c = FILES[m[4]]; if (c == null) { res.writeHead(404); return res.end(); }
      res.writeHead(200); return res.end(c);
    }
    // Gitea tree: /gtapi/repos/o/r/git/trees/ref
    if ((m = p.match(/^\/gtapi\/repos\/([^/]+)\/([^/]+)\/git\/trees\/(.+)$/))) {
      const tree = Object.entries(FILES).map(([path, c]) => ({ path, type: 'blob', sha: sha(c) }));
      res.writeHead(200); return res.end(JSON.stringify({ tree, truncated: false, total_count: tree.length, page: 1 }));
    }
    // Gitea raw: /gtraw/o/r/raw/commit/ref/path
    if ((m = p.match(/^\/gtraw\/([^/]+)\/([^/]+)\/raw\/commit\/([^/]+)\/(.+)$/))) {
      const c = FILES[m[4]]; if (c == null) { res.writeHead(404); return res.end(); }
      res.writeHead(200); return res.end(c);
    }
    res.writeHead(404); res.end();
  });

  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  process.env.CARGO_WITNESS_GITHUB_API = base;
  process.env.CARGO_WITNESS_GITHUB_RAW = `${base}/ghraw`;
  process.env.CARGO_WITNESS_GITLAB_API = `${base}/glapi`;
  process.env.CARGO_WITNESS_GITLAB_RAW = `${base}/glraw`;
  process.env.CARGO_WITNESS_GITEA_API = `${base}/gtapi`;
  process.env.CARGO_WITNESS_GITEA_RAW = `${base}/gtraw`;

  const { resolveHost } = require('../src/hosts');

  const expectSha = { 'src/lib.rs': sha('A'), 'build.rs': sha('B'), 'src/util.rs': sha('C') };

  async function checkProvider(label, url, expectHost) {
    const prov = resolveHost(url);
    assert.ok(prov, `resolveHost(${url}) null`);
    assert.strictEqual(prov.host, expectHost);
    const t = await prov.tree(REF);
    assert.strictEqual(t.status, 200, JSON.stringify(t));
    assert.strictEqual(t.gitFiles.size, 3, `${label} size ${t.gitFiles.size}`);
    for (const [f, s] of Object.entries(expectSha)) assert.strictEqual(t.gitFiles.get(f), s, `${label} sha ${f}`);
    const raw = await prov.raw(REF, 'build.rs');
    assert.strictEqual(raw, 'B', `${label} raw`);
  }

  try {
    await checkProvider('github', 'https://github.com/o/r', 'github');
    test('GitHub provider: tree shas + raw');
    await checkProvider('gitlab', 'https://gitlab.com/o/r', 'gitlab');
    test('GitLab provider: paginated tree (2 pages) + raw');
    await checkProvider('gitea', 'https://codeberg.org/o/r', 'gitea');
    test('Gitea/Codeberg provider: tree + raw');

    assert.strictEqual(resolveHost('https://bitbucket.org/o/r'), null);
    test('unsupported host -> null');

    const gh = resolveHost('https://github.com/o/r');
    const t = await gh.tree('429ref');
    assert.strictEqual(t.rateLimited, true);
    test('rate-limit (403) surfaces rateLimited');
  } catch (e) { fail('hosts', e); }

  server.close();
  console.log(`\n${passed} assertions passed.`);
  console.log(process.exitCode ? 'SOME TESTS FAILED' : 'ALL TESTS PASSED');
}

main().catch((e) => { console.error('hosts crashed:', e); process.exit(1); });
