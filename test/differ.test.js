'use strict';
const assert = require('assert');
const { diff, resolveGitPrefix } = require('../src/differ');
const { gitBlobSha } = require('../src/fetcher');

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`  ok  ${name}`); }
  catch (e) { console.error(`  FAIL ${name}: ${e.message}`); process.exitCode = 1; }
}

const sha = (content) => gitBlobSha(Buffer.from(content));

// Build a crate file map (path WITH prefix -> blob sha).
function crate(name, version, files) {
  const m = new Map();
  for (const [rel, content] of Object.entries(files)) m.set(`${name}-${version}/${rel}`, sha(content));
  return m;
}
// Build a git file map (repo path -> blob sha).
function git(files, { truncated = false } = {}) {
  const m = new Map();
  for (const [p, content] of Object.entries(files)) m.set(p, sha(content));
  m.truncated = truncated;
  return m;
}
const flagNames = (r) => r.flags.map((f) => f.flag);

test('single-crate repo, matching source → CLEAN', () => {
  const c = crate('foo', '1.0.0', { 'Cargo.toml': 'x', 'src/lib.rs': 'A', 'README.md': 'r' });
  const g = git({ 'Cargo.toml': 'x', 'src/lib.rs': 'A', 'README.md': 'r', '.gitignore': 'i' });
  const r = diff(c, g, 'foo-1.0.0/');
  assert.strictEqual(r.status, 'CLEAN', JSON.stringify(r));
  assert.strictEqual(r.gitPrefix, '');
});

test('build.rs in crate but not git → BUILD_RS_INJECTED', () => {
  const c = crate('foo', '1.0.0', { 'Cargo.toml': 'x', 'src/lib.rs': 'A', 'build.rs': 'evil' });
  const g = git({ 'Cargo.toml': 'x', 'src/lib.rs': 'A' });
  const r = diff(c, g, 'foo-1.0.0/');
  assert.strictEqual(r.status, 'SUSPICIOUS');
  assert.ok(flagNames(r).includes('BUILD_RS_INJECTED'));
});

test('workspace crate with build.rs in subdir (matching) → CLEAN, prefix resolved', () => {
  const c = crate('serde', '1.0.197', { 'Cargo.toml': 'x', 'src/lib.rs': 'A', 'src/de/mod.rs': 'D', 'build.rs': 'B' });
  const g = git({
    'serde/Cargo.toml': 'x', 'serde/src/lib.rs': 'A', 'serde/src/de/mod.rs': 'D', 'serde/build.rs': 'B',
    'serde_derive/Cargo.toml': 'y', 'serde_derive/src/lib.rs': 'Z',
  });
  const r = diff(c, g, 'serde-1.0.197/');
  assert.strictEqual(r.status, 'CLEAN', JSON.stringify(r));
  assert.strictEqual(r.gitPrefix, 'serde');
});

test('workspace crate, build.rs injected (absent in subdir) → SUSPICIOUS', () => {
  const c = crate('serde', '1.0.197', { 'Cargo.toml': 'x', 'src/lib.rs': 'A', 'src/de/mod.rs': 'D', 'build.rs': 'B' });
  const g = git({
    'serde/Cargo.toml': 'x', 'serde/src/lib.rs': 'A', 'serde/src/de/mod.rs': 'D',
    'serde_derive/Cargo.toml': 'y',
  });
  const r = diff(c, g, 'serde-1.0.197/');
  assert.ok(flagNames(r).includes('BUILD_RS_INJECTED'));
});

test('binary only in artifact → BINARY_NOT_IN_GIT', () => {
  const c = crate('foo', '1.0.0', { 'Cargo.toml': 'x', 'src/lib.rs': 'A', 'vendor/evil.so': 'BIN' });
  const g = git({ 'Cargo.toml': 'x', 'src/lib.rs': 'A' });
  const r = diff(c, g, 'foo-1.0.0/');
  const bin = r.flags.find((f) => f.flag === 'BINARY_NOT_IN_GIT');
  assert.ok(bin && bin.file === 'vendor/evil.so');
  assert.strictEqual(bin.severity, 'high');
});

test('extra .rs source only in artifact → FILE_NOT_IN_GIT (medium)', () => {
  const c = crate('foo', '1.0.0', { 'Cargo.toml': 'x', 'src/lib.rs': 'A', 'src/sneaky.rs': 'S' });
  const g = git({ 'Cargo.toml': 'x', 'src/lib.rs': 'A' });
  const r = diff(c, g, 'foo-1.0.0/');
  const f = r.flags.find((x) => x.flag === 'FILE_NOT_IN_GIT');
  assert.ok(f && f.file === 'src/sneaky.rs' && f.severity === 'medium', JSON.stringify(r));
});

test('shared .rs with differing sha → contentSuspect (scanner confirms)', () => {
  const c = crate('foo', '1.0.0', { 'Cargo.toml': 'x', 'src/lib.rs': 'EVIL' });
  const g = git({ 'Cargo.toml': 'x', 'src/lib.rs': 'GOOD' });
  const r = diff(c, g, 'foo-1.0.0/');
  assert.deepStrictEqual(r.contentSuspects.map((s) => s.rel), ['src/lib.rs']);
});

test('truncated tree suppresses absence flags', () => {
  const c = crate('foo', '1.0.0', { 'Cargo.toml': 'x', 'src/lib.rs': 'A', 'build.rs': 'B' });
  const g = git({ 'Cargo.toml': 'x', 'src/lib.rs': 'A' }, { truncated: true });
  const r = diff(c, g, 'foo-1.0.0/');
  assert.strictEqual(r.flags.length, 0, JSON.stringify(r));
  assert.strictEqual(r.truncated, true);
});

test('null gitFiles → NO_GIT_TAG', () => {
  const c = crate('foo', '1.0.0', { 'src/lib.rs': 'A', 'build.rs': 'B' });
  const r = diff(c, null, 'foo-1.0.0/');
  assert.strictEqual(r.status, 'NO_GIT_TAG');
  assert.strictEqual(r.flags.length, 0);
});

test('auto-generated files ignored', () => {
  const c = crate('foo', '1.0.0', { 'Cargo.toml': 'DIFFERENT', 'Cargo.toml.orig': 'z', '.cargo_vcs_info.json': 'j', 'src/lib.rs': 'A' });
  const g = git({ 'Cargo.toml': 'x', 'src/lib.rs': 'A' });
  const r = diff(c, g, 'foo-1.0.0/');
  assert.strictEqual(r.status, 'CLEAN', JSON.stringify(r));
});

test('knownPrefix (path_in_vcs) used directly → CLEAN, prefix honoured', () => {
  const c = crate('foo', '1.0.0', { 'Cargo.toml': 'x', 'src/lib.rs': 'A', 'build.rs': 'B' });
  const g = git({ 'member/Cargo.toml': 'x', 'member/src/lib.rs': 'A', 'member/build.rs': 'B', 'other/Cargo.toml': 'z' });
  const r = diff(c, g, 'foo-1.0.0/', { knownPrefix: 'member' });
  assert.strictEqual(r.status, 'CLEAN', JSON.stringify(r));
  assert.strictEqual(r.gitPrefix, 'member');
});

test('knownPrefix that does not match the tree → NO_GIT_TAG (self-correcting)', () => {
  const c = crate('foo', '1.0.0', { 'Cargo.toml': 'x', 'src/lib.rs': 'A' });
  const g = git({ 'totally/different.rs': 'z', 'unrelated/Cargo.toml': 'q' });
  const r = diff(c, g, 'foo-1.0.0/', { knownPrefix: '' });
  assert.strictEqual(r.status, 'NO_GIT_TAG');
});

test('resolveGitPrefix locates nested crate root', () => {
  const rel = new Map([['src/lib.rs', 's1'], ['src/util.rs', 's2'], ['build.rs', 's3']]);
  const g = git({
    'crates/foo/Cargo.toml': 't', 'crates/foo/src/lib.rs': 's1', 'crates/foo/src/util.rs': 's2',
    'crates/bar/Cargo.toml': 't', 'crates/bar/src/lib.rs': 'z',
  });
  const { gitPrefix, confidence } = resolveGitPrefix(rel, g);
  assert.strictEqual(gitPrefix, 'crates/foo');
  assert.ok(confidence >= 0.66, `confidence=${confidence}`);
});

console.log(`\n${passed} assertions passed.`);
console.log(process.exitCode ? 'SOME TESTS FAILED' : 'ALL TESTS PASSED');
