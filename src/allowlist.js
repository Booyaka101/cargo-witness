'use strict';
const fs = require('fs');
const path = require('path');

/**
 * Allowlist / suppression. A project may legitimately ship, say, a prebuilt
 * binary; the allowlist mutes accepted findings so real ones stay visible.
 *
 * File (default `.cargo-witness.json` in cwd, or via --config):
 *   {
 *     "allow": [
 *       { "name": "ring", "flag": "BINARY_NOT_IN_GIT" },
 *       { "name": "foo", "version": "1.2.3", "flag": "SOURCE_MODIFIED", "file": "src/gen.rs" }
 *     ]
 *   }
 * Omitted `version` / `flag` / `file` (or "*") match anything.
 */
function loadAllowlist(configPath) {
  const p = configPath || path.join(process.cwd(), '.cargo-witness.json');
  let raw;
  try {
    raw = fs.readFileSync(p, 'utf8');
  } catch {
    return { rules: [], path: null };
  }
  let data;
  try {
    data = JSON.parse(raw);
  } catch (e) {
    throw new Error(`invalid allowlist ${p}: ${e.message}`);
  }
  const rules = Array.isArray(data.allow) ? data.allow : [];
  return { rules, path: p };
}

function matches(rule, name, version, flag) {
  const f = flag; // { flag, file }
  const wild = (v) => v === undefined || v === null || v === '*';
  if (rule.name !== name) return false;
  if (!wild(rule.version) && rule.version !== version) return false;
  if (!wild(rule.flag) && rule.flag !== f.flag) return false;
  if (!wild(rule.file) && rule.file !== f.file) return false;
  return true;
}

/**
 * Partition a package's flags into kept vs suppressed by the allowlist.
 * @returns {{kept:Array, suppressed:Array}}
 */
function applyAllowlist(rules, name, version, flags) {
  if (!rules || rules.length === 0) return { kept: flags, suppressed: [] };
  const kept = [];
  const suppressed = [];
  for (const f of flags) {
    if (rules.some((r) => matches(r, name, version, f))) suppressed.push(f);
    else kept.push(f);
  }
  return { kept, suppressed };
}

module.exports = { loadAllowlist, applyAllowlist };
