'use strict';
const assert = require('assert');
const { parseManifestDeps, diffManifests } = require('../src/manifest');

let passed = 0;
function ok(name) { passed++; console.log(`  ok  ${name}`); }
function fail(name, e) { console.error(`  FAIL ${name}: ${e.message}`); process.exitCode = 1; }
async function test(name, fn) {
  try { await fn(); ok(name); } catch (e) { fail(name, e); }
}

// Git tree stub: file map (path -> content) plus a raw() that counts fetches.
function tree(files, { truncated = false } = {}) {
  const gitFiles = new Map(Object.keys(files).map((p) => [p, 'sha']));
  gitFiles.truncated = truncated;
  let rawCalls = 0;
  const raw = async (p) => { rawCalls++; return p in files ? files[p] : null; };
  return { gitFiles, raw, calls: () => rawCalls };
}

const names = (r) => r.flags.map((f) => f.file);

async function main() {
  // ---- parser ---------------------------------------------------------------

  await test('parser collects every dependency kind, including underscore aliases', () => {
    const r = parseManifestDeps(`
[dependencies]
serde = "1"
[build-dependencies]
cc = "1"
[dev-dependencies]
quickcheck = "1"
[build_dependencies]
old_build = "1"
[dev_dependencies]
old_dev = "1"
`);
    assert.deepStrictEqual([...r.names].sort(), ['cc', 'old_build', 'old_dev', 'quickcheck', 'serde']);
  });

  await test('parser resolves the renamed form to the real crate name', () => {
    const r = parseManifestDeps('[dependencies]\nalias = { version = "1", package = "real-name" }\n');
    assert.deepStrictEqual([...r.names], ['real-name']);
  });

  await test('parser walks target-specific tables (quoted cfg and plain triple)', () => {
    const r = parseManifestDeps(`
[target.'cfg(windows)'.dependencies]
winapi = "0.3"
[target.x86_64-unknown-linux-gnu.build-dependencies]
cc = "1"
`);
    assert.deepStrictEqual([...r.names].sort(), ['cc', 'winapi']);
  });

  await test('parser marks workspace = true entries (inline and dotted) as inherited', () => {
    const r = parseManifestDeps('[dependencies]\nserde.workspace = true\ntokio = { workspace = true }\n');
    assert.deepStrictEqual([...r.inherited].sort(), ['serde', 'tokio']);
    assert.strictEqual(r.names.size, 0);
  });

  await test('parser reads [workspace.dependencies] with renames', () => {
    const r = parseManifestDeps('[workspace.dependencies]\nserde = "1"\nt = { package = "tokio", version = "1" }\n');
    assert.strictEqual(r.workspaceDeps.get('serde'), 'serde');
    assert.strictEqual(r.workspaceDeps.get('t'), 'tokio');
  });

  await test('parser throws on invalid TOML', () => {
    assert.throws(() => parseManifestDeps('not toml ['));
  });

  // ---- lane -----------------------------------------------------------------

  const pkg = '[package]\nname = "foo"\nversion = "1.0.0"\n';

  await test('worked example: proc-macro1 in artifact build-dependencies only -> DEP_INJECTED high', async () => {
    const t = tree({ 'Cargo.toml': `${pkg}[dependencies]\nserde = "1"\n` });
    const r = await diffManifests({ name: 'foo',
      artifactToml: `${pkg}[dependencies]\nserde = "1"\n[build-dependencies]\nproc-macro1 = "1.0.107"\n`,
      gitFiles: t.gitFiles, gitPrefix: '', raw: t.raw,
    });
    assert.strictEqual(r.skipped, null);
    assert.deepStrictEqual(names(r), ['proc-macro1']);
    assert.strictEqual(r.flags[0].flag, 'DEP_INJECTED');
    assert.strictEqual(r.flags[0].severity, 'high');
    assert.ok(r.flags[0].detail.includes('absent from the git source'));
  });

  await test('identical dependency sets -> no flags, both sets returned', async () => {
    const t = tree({ 'Cargo.toml': `${pkg}[dependencies]\nserde = "1"\n` });
    const r = await diffManifests({ name: 'foo',
      artifactToml: `${pkg}[dependencies]\nserde = "1.0.200"\n`,
      gitFiles: t.gitFiles, gitPrefix: '', raw: t.raw,
    });
    assert.deepStrictEqual(r.flags, []);
    assert.deepStrictEqual(r.artifactDeps, ['serde']);
    assert.deepStrictEqual(r.gitDeps, ['serde']);
  });

  await test('workspace inheritance resolves against the root [workspace.dependencies]', async () => {
    const t = tree({
      'member/Cargo.toml': `${pkg}[dependencies]\ntokio.workspace = true\n`,
      'Cargo.toml': '[workspace]\nmembers = ["member"]\n[workspace.dependencies]\ntokio = "1"\n',
    });
    const r = await diffManifests({ name: 'foo',
      artifactToml: `${pkg}[dependencies]\ntokio = "1.38.0"\n`,
      gitFiles: t.gitFiles, gitPrefix: 'member', raw: t.raw,
    });
    assert.strictEqual(r.skipped, null);
    assert.deepStrictEqual(r.flags, []);
    assert.deepStrictEqual(r.gitDeps, ['tokio']);
  });

  await test('workspace inheritance with a rename compares the real crate name', async () => {
    const t = tree({
      'member/Cargo.toml': `${pkg}[dependencies]\nt = { workspace = true }\n`,
      'Cargo.toml': '[workspace.dependencies]\nt = { package = "tokio", version = "1" }\n',
    });
    const r = await diffManifests({ name: 'foo',
      artifactToml: `${pkg}[dependencies]\nt = { package = "tokio", version = "1" }\n`,
      gitFiles: t.gitFiles, gitPrefix: 'member', raw: t.raw,
    });
    assert.deepStrictEqual(r.flags, []);
    assert.deepStrictEqual(r.gitDeps, ['tokio']);
  });

  await test('crate that is its own workspace root resolves inheritance without a second fetch', async () => {
    const t = tree({
      'Cargo.toml': `${pkg}[dependencies]\nserde.workspace = true\n[workspace.dependencies]\nserde = "1"\n`,
    });
    const r = await diffManifests({ name: 'foo',
      artifactToml: `${pkg}[dependencies]\nserde = "1"\n`,
      gitFiles: t.gitFiles, gitPrefix: '', raw: t.raw,
    });
    assert.deepStrictEqual(r.flags, []);
    assert.strictEqual(t.calls(), 1);
  });

  await test('unresolvable workspace inheritance suppresses with a reason', async () => {
    const t = tree({
      'member/Cargo.toml': `${pkg}[dependencies]\nmystery.workspace = true\n`,
      'Cargo.toml': '[workspace.dependencies]\nother = "1"\n',
    });
    const r = await diffManifests({ name: 'foo',
      artifactToml: `${pkg}[dependencies]\nmystery = "1"\n[build-dependencies]\nproc-macro1 = "1"\n`,
      gitFiles: t.gitFiles, gitPrefix: 'member', raw: t.raw,
    });
    assert.deepStrictEqual(r.flags, []);
    assert.ok(r.skipped.includes('mystery'), r.skipped);
  });

  await test('target-specific injected dependency is flagged', async () => {
    const t = tree({ 'Cargo.toml': `${pkg}[dependencies]\nserde = "1"\n` });
    const r = await diffManifests({ name: 'foo',
      artifactToml: `${pkg}[dependencies]\nserde = "1"\n[target.'cfg(unix)'.dependencies]\nsneaky = "1"\n`,
      gitFiles: t.gitFiles, gitPrefix: '', raw: t.raw,
    });
    assert.deepStrictEqual(names(r), ['sneaky']);
  });

  await test('truncated git tree suppresses with a reason', async () => {
    const t = tree({ 'Cargo.toml': `${pkg}` }, { truncated: true });
    const r = await diffManifests({ name: 'foo',
      artifactToml: `${pkg}[build-dependencies]\nproc-macro1 = "1"\n`,
      gitFiles: t.gitFiles, gitPrefix: '', raw: t.raw,
    });
    assert.deepStrictEqual(r.flags, []);
    assert.ok(r.skipped.includes('truncated'), r.skipped);
    assert.strictEqual(t.calls(), 0);
  });

  await test('unparseable artifact manifest suppresses with a reason', async () => {
    const t = tree({ 'Cargo.toml': `${pkg}` });
    const r = await diffManifests({ name: 'foo', artifactToml: 'not toml [', gitFiles: t.gitFiles, gitPrefix: '', raw: t.raw });
    assert.deepStrictEqual(r.flags, []);
    assert.ok(r.skipped.includes('artifact Cargo.toml failed to parse'), r.skipped);
  });

  await test('unparseable git manifest suppresses with a reason', async () => {
    const t = tree({ 'Cargo.toml': 'not toml [' });
    const r = await diffManifests({ name: 'foo',
      artifactToml: `${pkg}[dependencies]\nserde = "1"\n`,
      gitFiles: t.gitFiles, gitPrefix: '', raw: t.raw,
    });
    assert.deepStrictEqual(r.flags, []);
    assert.ok(r.skipped.includes('could not be fetched'), r.skipped);
  });

  await test('git tree without a Cargo.toml at the prefix suppresses', async () => {
    const t = tree({ 'other/Cargo.toml': pkg });
    const r = await diffManifests({ name: 'foo',
      artifactToml: `${pkg}[dependencies]\nserde = "1"\n`,
      gitFiles: t.gitFiles, gitPrefix: 'member', raw: t.raw,
    });
    assert.ok(r.skipped.includes('no Cargo.toml at member/Cargo.toml'), r.skipped);
    assert.strictEqual(t.calls(), 0);
  });

  await test('raw fetch returning null (404) suppresses', async () => {
    const t = tree({ 'Cargo.toml': pkg });
    const gitFiles = t.gitFiles;
    const r = await diffManifests({ name: 'foo',
      artifactToml: `${pkg}[dependencies]\nserde = "1"\n`,
      gitFiles, gitPrefix: '', raw: async () => null,
    });
    assert.ok(r.skipped.includes('could not be fetched'), r.skipped);
  });

  await test('artifact with no dependencies never fetches the git manifest', async () => {
    const t = tree({ 'Cargo.toml': pkg });
    const r = await diffManifests({ name: 'foo', artifactToml: pkg, gitFiles: t.gitFiles, gitPrefix: '', raw: t.raw });
    assert.deepStrictEqual(r.flags, []);
    assert.strictEqual(r.skipped, null);
    assert.strictEqual(t.calls(), 0);
  });

  await test('git manifest belonging to a different crate suppresses (mis-resolved ref)', async () => {
    // Observed live: rand_core@0.9.5 fell back to tag 0.9.5, which is the tag
    // of the sibling `rand` crate; its manifest would mass-flag real deps.
    const t = tree({ 'Cargo.toml': '[package]\nname = "rand"\nversion = "0.9.5"\n[dependencies]\nrand_core = "0.5"\n' });
    const r = await diffManifests({
      name: 'rand_core',
      artifactToml: '[package]\nname = "rand_core"\nversion = "0.9.5"\n[dependencies]\ngetrandom = "0.3"\n',
      gitFiles: t.gitFiles, gitPrefix: '', raw: t.raw,
    });
    assert.deepStrictEqual(r.flags, []);
    assert.ok(r.skipped.includes('"rand", not "rand_core"'), r.skipped);
  });

  await test('git manifest without [package] (virtual workspace root) suppresses', async () => {
    // Observed live: varisat-* crates without path_in_vcs resolved to the
    // repository root, whose virtual manifest declares zero dependencies.
    const t = tree({ 'Cargo.toml': '[workspace]\nmembers = ["a", "b"]\n' });
    const r = await diffManifests({
      name: 'foo',
      artifactToml: `${pkg}[dependencies]\nserde = "1"\n`,
      gitFiles: t.gitFiles, gitPrefix: '', raw: t.raw,
    });
    assert.deepStrictEqual(r.flags, []);
    assert.ok(r.skipped.includes('no [package] table'), r.skipped);
  });

  await test('rate-limit errors from raw propagate (scanner owns the state)', async () => {
    const t = tree({ 'Cargo.toml': pkg });
    const err = new Error('403'); err.rateLimited = true;
    await assert.rejects(
      diffManifests({
        name: 'foo',
        artifactToml: `${pkg}[dependencies]\nserde = "1"\n`,
        gitFiles: t.gitFiles, gitPrefix: '', raw: async () => { throw err; },
      }),
      (e) => e.rateLimited === true
    );
  });

  console.log(`\n${passed} assertions passed.`);
  console.log(process.exitCode ? 'SOME TESTS FAILED' : 'ALL TESTS PASSED');
}

main().catch((e) => { console.error('manifest suite crashed:', e); process.exit(1); });
