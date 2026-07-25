'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { severityOf, maxSeverity, isSuspicious, atLeast } = require('../src/severity');
const { applyAllowlist, loadAllowlist } = require('../src/allowlist');
const { toSarif } = require('../src/sarif');
const { diffOps } = require('../src/inspect');

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`  ok  ${name}`); }
  catch (e) { console.error(`  FAIL ${name}: ${e.message}`); process.exitCode = 1; }
}

// --- severity ---------------------------------------------------------------
test('severity mapping + maxSeverity', () => {
  assert.strictEqual(severityOf('BUILD_RS_INJECTED'), 'high');
  assert.strictEqual(severityOf({ flag: 'SOURCE_MODIFIED' }), 'medium');
  assert.strictEqual(severityOf('YANKED'), 'info');
  assert.strictEqual(maxSeverity([{ flag: 'YANKED' }, { flag: 'SOURCE_MODIFIED' }]), 'medium');
  assert.strictEqual(maxSeverity([{ flag: 'YANKED' }, { flag: 'BUILD_RS_INJECTED' }]), 'high');
  assert.strictEqual(maxSeverity([]), null);
});

test('isSuspicious: medium+ yes, info-only no', () => {
  assert.strictEqual(isSuspicious([{ flag: 'YANKED' }]), false);
  assert.strictEqual(isSuspicious([{ flag: 'FILE_NOT_IN_GIT' }]), true);
  assert.strictEqual(isSuspicious([{ flag: 'CHECKSUM_MISMATCH' }]), true);
});

test('atLeast threshold gating', () => {
  assert.strictEqual(atLeast('high', 'medium'), true);
  assert.strictEqual(atLeast('medium', 'high'), false);
  assert.strictEqual(atLeast('info', 'medium'), false);
  assert.strictEqual(atLeast(null, 'info'), false);
});

// --- allowlist --------------------------------------------------------------
test('applyAllowlist suppresses matching, keeps others', () => {
  const rules = [
    { name: 'ring', flag: 'BINARY_NOT_IN_GIT' },
    { name: 'foo', version: '1.2.3', flag: 'SOURCE_MODIFIED', file: 'src/gen.rs' },
  ];
  const r1 = applyAllowlist(rules, 'ring', '0.17.0', [
    { flag: 'BINARY_NOT_IN_GIT', file: 'a.so' }, { flag: 'BUILD_RS_INJECTED', file: 'build.rs' },
  ]);
  assert.strictEqual(r1.suppressed.length, 1);
  assert.strictEqual(r1.kept.length, 1);
  assert.strictEqual(r1.kept[0].flag, 'BUILD_RS_INJECTED');

  // version mismatch → not suppressed
  const r2 = applyAllowlist(rules, 'foo', '9.9.9', [{ flag: 'SOURCE_MODIFIED', file: 'src/gen.rs' }]);
  assert.strictEqual(r2.suppressed.length, 0);

  // exact version+file match → suppressed
  const r3 = applyAllowlist(rules, 'foo', '1.2.3', [{ flag: 'SOURCE_MODIFIED', file: 'src/gen.rs' }]);
  assert.strictEqual(r3.suppressed.length, 1);
});

test('loadAllowlist reads file, tolerates missing', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-allow-'));
  const p = path.join(dir, '.cargo-witness.json');
  fs.writeFileSync(p, JSON.stringify({ allow: [{ name: 'x', flag: 'YANKED' }] }));
  assert.strictEqual(loadAllowlist(p).rules.length, 1);
  assert.deepStrictEqual(loadAllowlist(path.join(dir, 'nope.json')).rules, []);
});

// --- sarif ------------------------------------------------------------------
test('toSarif produces valid-shaped 2.1.0 log', () => {
  const sarif = toSarif(
    [{ name: 'evil', version: '6.6.6', flags: [{ flag: 'BUILD_RS_INJECTED', file: 'build.rs' }] }],
    'Cargo.lock'
  );
  assert.strictEqual(sarif.version, '2.1.0');
  assert.ok(sarif.$schema.includes('sarif-2.1.0'));
  const run = sarif.runs[0];
  assert.strictEqual(run.tool.driver.name, 'cargo-witness');
  assert.strictEqual(run.results.length, 1);
  assert.strictEqual(run.results[0].ruleId, 'BUILD_RS_INJECTED');
  assert.strictEqual(run.results[0].level, 'error');
  assert.ok(run.tool.driver.rules.some((r) => r.id === 'BUILD_RS_INJECTED'));
});

// --- diff algorithm --------------------------------------------------------
test('diffOps: detects added/removed lines (build.rs injection shape)', () => {
  const git = 'fn main() {}\n';
  const pub_ = 'fn main() {\n    steal_env();\n}\n';
  const ops = diffOps(git, pub_);
  const added = ops.filter((o) => o[0] === '+').map((o) => o[1]);
  const removed = ops.filter((o) => o[0] === '-').map((o) => o[1]);
  assert.ok(added.some((l) => l.includes('steal_env')), JSON.stringify(ops));
  assert.ok(removed.some((l) => l.includes('fn main() {}')));
});

test('diffOps: identical input → no +/- ops', () => {
  const ops = diffOps('a\nb\nc', 'a\nb\nc');
  assert.ok(ops.every((o) => o[0] === ' '));
});

console.log(`\n${passed} assertions passed.`);
console.log(process.exitCode ? 'SOME TESTS FAILED' : 'ALL TESTS PASSED');
