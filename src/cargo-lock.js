'use strict';
const fs = require('fs');

/**
 * STEP 1 — Cargo.lock parser.
 *
 * Cargo.lock is TOML. We walk it line-by-line collecting the fields of each
 * [[package]] block. A package is only returned when its `source` field
 * contains 'registry+' — that means it came from a registry (crates.io etc.),
 * which is the only case we can diff against a published artifact. Packages
 * with a `git+...` source or with no source at all (the local workspace crate)
 * are skipped.
 *
 * @param {string} lockPath path to Cargo.lock
 * @returns {Array<{name:string, version:string}>}
 */
function parseCargoLock(lockPath) {
  const text = fs.readFileSync(lockPath, 'utf8');
  const lines = text.split(/\r?\n/);

  const packages = [];
  let cur = null; // {name, version, source}

  const flush = () => {
    if (cur && cur.name && cur.version && cur.source && cur.source.includes('registry+')) {
      packages.push({ name: cur.name, version: cur.version });
    }
    cur = null;
  };

  for (const raw of lines) {
    const line = raw.trim();
    if (line === '[[package]]') {
      flush();
      cur = { name: null, version: null, source: null };
      continue;
    }
    // A new top-level table other than [[package]] ends the current package.
    if (line.startsWith('[') && line !== '[[package]]') {
      flush();
      continue;
    }
    if (!cur) continue;

    if (line.startsWith('name = ')) {
      cur.name = parseTomlString(line.slice('name = '.length));
    } else if (line.startsWith('version = ')) {
      cur.version = parseTomlString(line.slice('version = '.length));
    } else if (line.startsWith('source = ')) {
      cur.source = parseTomlString(line.slice('source = '.length));
    }
  }
  flush();

  return packages;
}

/** Strip surrounding double-quotes from a TOML string value. */
function parseTomlString(v) {
  const s = v.trim();
  if (s.startsWith('"') && s.endsWith('"')) {
    return s.slice(1, -1);
  }
  return s;
}

module.exports = { parseCargoLock };
