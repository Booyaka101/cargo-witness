'use strict';
// The runtime `action.yml` declares has an expiry date. GitHub removes Node 20
// from the runners on 2026-09-23, at which point an action declaring it does
// not launch, before any of this code runs, with no fallback. This suite is
// the alarm: it goes red while there is still time to move.

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const cp = require('child_process');
const os = require('os');

const { RUNTIMES, LEAD_DAYS, readUsing, withRuntime, checkRuntime } = require('../scripts/action-runtime');

const ACTION_YML = path.join(__dirname, '..', 'action.yml');
const VALIDATE = path.join(__dirname, '..', 'scripts', 'validate-action.js');

/** readUsing takes a path; these cases are easier to state as a string. */
function readUsingFrom(body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-read-'));
  try {
    const p = path.join(dir, 'action.yml');
    fs.writeFileSync(p, body);
    return readUsing(p);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

let passed = 0;
function test(name) { passed++; console.log(`  ok  ${name}`); }
function fail(name, e) { console.error(`  FAIL ${name}: ${e.message}`); process.exitCode = 1; }
function check(name, fn) { try { fn(); test(name); } catch (e) { fail(name, e); } }

check('action.yml declares a runtime GitHub still runs', () => {
  const using = readUsing(ACTION_YML);
  const r = checkRuntime(using);
  assert.ok(r.ok, r.reason);
});

check('the declared runtime matches the bundled main script', () => {
  const yml = fs.readFileSync(ACTION_YML, 'utf8');
  assert.match(yml, /^\s+main:\s*dist\/action\.js$/m);
  assert.ok(fs.existsSync(path.join(__dirname, '..', 'dist', 'action.js')), 'dist/action.js is missing');
});

check('a runtime past its removal date is rejected', () => {
  assert.strictEqual(checkRuntime('node16').ok, false);
  assert.strictEqual(checkRuntime('node20', new Date('2026-09-24T00:00:00Z')).ok, false);
});

check('a runtime inside the lead window is rejected while it still works', () => {
  // 2026-09-01: node20 launches fine that day, and we want to have moved.
  const r = checkRuntime('node20', new Date('2026-09-01T00:00:00Z'));
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /2026-09-23/);
});

check('a runtime with no announced removal passes', () => {
  assert.strictEqual(checkRuntime('node24').ok, true);
  assert.strictEqual(RUNTIMES.node24.removedOn, null);
});

check('an unknown runtime is rejected', () => {
  assert.strictEqual(checkRuntime('node26').ok, false);
  assert.strictEqual(checkRuntime(null).ok, false);
});

check('LEAD_DAYS gives real notice', () => {
  assert.ok(LEAD_DAYS >= 90, 'less than a quarter is not enough warning to ship a release');
});

check('readUsing handles quotes, comments and an absent key', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-using-'));
  const write = (body) => {
    const p = path.join(dir, 'action.yml');
    fs.writeFileSync(p, body);
    return p;
  };
  assert.strictEqual(readUsing(write("runs:\n  using: 'node24'\n  main: x.js\n")), 'node24');
  assert.strictEqual(readUsing(write('runs:\n  using: node24 # pinned\n  main: x.js\n')), 'node24');
  // `using` under some other top-level key is not the action's runtime.
  assert.strictEqual(readUsing(write('inputs:\n  using:\n    default: node20\n')), null);
  fs.rmSync(dir, { recursive: true, force: true });
});

check('withRuntime rewrites runs.using and nothing else', () => {
  const decoy = [
    'inputs:', '  using:', '    default: node20',
    'runs:', "  using: 'node24'", '  main: dist/action.js', '',
  ].join('\n')
  ;
  const swapped = withRuntime(decoy, 'node20');
  assert.strictEqual(readUsingFrom(swapped), 'node20');
  // The decoy input keeps its own default: only the line under `runs:` moves.
  assert.ok(swapped.includes('    default: node20'));
  assert.ok(swapped.includes("  using: 'node20'"), 'the original quote style survives');
  assert.strictEqual(withRuntime('name: x', 'node20'), 'name: x');
});

check('validate-action passes the shipped action.yml', () => {
  const r = cp.spawnSync(process.execPath, [VALIDATE], { encoding: 'utf8' });
  assert.strictEqual(r.status, 0, r.stdout + r.stderr);
});

check('validate-action still fails on a schema error that is not the runtime', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-badaction-'));
  const p = path.join(dir, 'action.yml');
  fs.writeFileSync(p, fs.readFileSync(ACTION_YML, 'utf8').replace(/^runs:$/m, 'bogus-top-level: 1\nruns:'));
  const r = cp.spawnSync(process.execPath, [VALIDATE, p], { encoding: 'utf8' });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.strictEqual(r.status, 1, 'a real schema error must still fail the build');
  assert.match(r.stderr, /bogus-top-level/);
});

check('engines.node is not below what our dependencies require', () => {
  // better-sqlite3 is a native module. On a Node it does not support it does not
  // throw, it segfaults, which reads as a phantom crash rather than a bad
  // install. Claiming a floor lower than any dependency's is how that happens.
  const ours = require('../package.json').engines.node;
  const floor = (spec) => Number(String(spec).replace(/[^\d.]/g, '').split('.')[0]);
  for (const dep of ['better-sqlite3']) {
    const theirs = require(`${dep}/package.json`).engines.node;
    assert.ok(floor(ours) >= floor(theirs), `package.json says node ${ours} but ${dep} needs ${theirs}`);
  }
});

console.log(`\n${passed} assertions passed.`);
console.log(process.exitCode ? 'SOME TESTS FAILED' : 'ALL TESTS PASSED');
