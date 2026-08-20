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
 * @param {{withSource?:boolean}} [opts] include each package's `source` string
 *        (used by the scanner to keep crates.io absence probing off alternate
 *        registries). Off by default so the return shape stays stable.
 * @returns {Array<{name:string, version:string, source?:string}>}
 */
function parseCargoLock(lockPath, opts = {}) {
  let text;
  try {
    text = fs.readFileSync(lockPath, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') {
      throw new Error(
        `Cargo.lock not found at ${lockPath}. Run from a Rust project directory, ` +
        'or point at one with --lock <path>.'
      );
    }
    throw e;
  }
  const lines = text.split(/\r?\n/);

  const packages = [];
  let cur = null; // {name, version, source}

  const flush = () => {
    if (cur && cur.name && cur.version && cur.source && cur.source.includes('registry+')) {
      const p = { name: cur.name, version: cur.version };
      if (opts.withSource) p.source = cur.source;
      packages.push(p);
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

/**
 * True when a Cargo.lock `source` string points at crates.io (git or sparse
 * index). Absence probing only makes sense there: a crates.io 404 for a crate
 * that lives on an alternate registry proves nothing.
 */
function isCratesIoSource(source) {
  return /github\.com\/rust-lang\/crates\.io-index|index\.crates\.io/.test(String(source));
}

module.exports = { parseCargoLock, isCratesIoSource };
