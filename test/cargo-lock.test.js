'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { parseCargoLock } = require('../src/cargo-lock');

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`  ok  ${name}`); }
  catch (e) { console.error(`  FAIL ${name}: ${e.message}`); process.exitCode = 1; }
}

function write(content) {
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cw-lock-')), 'Cargo.lock');
  fs.writeFileSync(p, content);
  return p;
}

test('parses registry packages, skips local + git', () => {
  const p = write(`
version = 3

[[package]]
name = "my-app"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "local-git-dep"
version = "2.0.0"
source = "git+https://github.com/foo/bar#deadbeef"

[[package]]
name = "anyhow"
version = "1.0.86"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "def"
`);
  const pkgs = parseCargoLock(p);
  assert.deepStrictEqual(
    pkgs.sort((a, b) => a.name.localeCompare(b.name)),
    [
      { name: 'anyhow', version: '1.0.86' },
      { name: 'serde', version: '1.0.197' },
    ]
  );
});

test('handles CRLF line endings', () => {
  const p = write(
    ['[[package]]', 'name = "serde"', 'version = "1.0.0"',
      'source = "registry+https://github.com/rust-lang/crates.io-index"'].join('\r\n')
  );
  assert.deepStrictEqual(parseCargoLock(p), [{ name: 'serde', version: '1.0.0' }]);
});

test('package with no source (workspace root) is skipped', () => {
  const p = write(`[[package]]
name = "root-crate"
version = "0.1.0"
`);
  assert.deepStrictEqual(parseCargoLock(p), []);
});

test('alt registry (registry+...) still counted', () => {
  const p = write(`[[package]]
name = "internal"
version = "3.1.4"
source = "registry+sparse+https://my-registry.example/index/"
`);
  assert.deepStrictEqual(parseCargoLock(p), [{ name: 'internal', version: '3.1.4' }]);
});

console.log(`\n${passed} assertions passed.`);
console.log(process.exitCode ? 'SOME TESTS FAILED' : 'ALL TESTS PASSED');
