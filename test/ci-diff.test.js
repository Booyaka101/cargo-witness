'use strict';
const assert = require('assert');
const { diffAddedPackages } = require('../src/ci');
const child = require('child_process');

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`  ok  ${name}`); }
  catch (e) { console.error(`  FAIL ${name}: ${e.message}`); process.exitCode = 1; }
}

// Stub execFileSync by intercepting git via a wrapper: diffAddedPackages calls
// git diff. We test the PARSING by monkey-patching child_process.execFileSync.
const realExec = child.execFileSync;
function withGitDiff(output, fn) {
  child.execFileSync = () => output;
  try { return fn(); } finally { child.execFileSync = realExec; }
}

test('parses added name+version pairs', () => {
  const diff = `diff --git a/Cargo.lock b/Cargo.lock
index 111..222 100644
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -10,6 +10,12 @@
+[[package]]
+name = "evil-crate"
+version = "6.6.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "def"
`;
  const added = withGitDiff(diff, () => diffAddedPackages('Cargo.lock'));
  assert.deepStrictEqual(added, [{ name: 'evil-crate', version: '6.6.6' }]);
});

test('ignores +++ header line and context', () => {
  const diff = `+++ b/Cargo.lock
+name = "foo"
+version = "1.2.3"
 name = "unchanged"
 version = "9.9.9"
`;
  const added = withGitDiff(diff, () => diffAddedPackages('Cargo.lock'));
  assert.deepStrictEqual(added, [{ name: 'foo', version: '1.2.3' }]);
});

test('no additions -> empty', () => {
  const added = withGitDiff('', () => diffAddedPackages('Cargo.lock'));
  assert.deepStrictEqual(added, []);
});

test('git failure -> empty (graceful)', () => {
  child.execFileSync = () => { throw new Error('fatal: bad revision HEAD~1'); };
  try {
    assert.deepStrictEqual(diffAddedPackages('Cargo.lock'), []);
  } finally { child.execFileSync = realExec; }
});

console.log(`\n${passed} assertions passed.`);
console.log(process.exitCode ? 'SOME TESTS FAILED' : 'ALL TESTS PASSED');
