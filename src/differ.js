'use strict';
const { severityOf, isSuspicious } = require('./severity');

/**
 * STEP 5 — Differ.
 *
 * Compares a published .crate against its git tag to detect supply-chain
 * tampering. Uses git blob shas (from the trees API) to content-compare every
 * shared file with no extra network calls; only sha MISMATCHES need a content
 * fetch to confirm (done by the scanner, to avoid line-ending false positives).
 *
 * WORKSPACE-AWARE: many crates live in a repo subdirectory (cargo workspaces).
 * e.g. published `serde` has `build.rs` at its root but git has `serde/build.rs`.
 * We locate the crate's root inside the tree (via its Cargo.toml location,
 * corroborated by matching files) before comparing — removing that false
 * positive without hiding a real injection.
 *
 * @param {Map<string,string>} crateFiles  path (WITH prefix) -> git blob sha
 * @param {Map<string,string>|null} gitFiles  repo path -> git blob sha (or null)
 * @param {string} prefix  the `{name}-{version}/` prefix to strip
 * @param {{knownPrefix?:string}} [opts]  authoritative path_in_vcs from
 *        .cargo_vcs_info.json; when given, used directly instead of heuristics.
 * @returns {{
 *   status:string, flags:Array, gitPrefix?:string, confidence?:number,
 *   hasBuildRs?:boolean, buildRsInGit?:boolean,
 *   contentSuspects?:Array<{rel:string, isBuildRs:boolean}>, truncated?:boolean
 * }}
 */

const AUTO_GENERATED = new Set([
  'Cargo.toml',
  '.cargo_vcs_info.json',
  '.cargo-ok',
  'Cargo.toml.orig',
  'Cargo.lock',
]);

const BINARY_EXTS = ['.so', '.dll', '.exe', '.dylib', '.wasm', '.a', '.lib', '.o'];

function diff(crateFiles, gitFiles, prefix, opts = {}) {
  if (!gitFiles) return { status: 'NO_GIT_TAG', flags: [] };

  // Crate-relative map: strip the `{name}-{version}/` prefix.
  const relCrate = new Map();
  for (const [f, sha] of crateFiles) {
    const rel = f.startsWith(prefix) ? f.slice(prefix.length) : f;
    if (rel) relCrate.set(rel, sha);
  }

  // If .cargo_vcs_info.json gave us the authoritative subdirectory, use it
  // directly (still scoring it, so a mismatched repo/commit is caught). Else
  // fall back to locating the crate root heuristically.
  let gitPrefix, confidence;
  if (opts.knownPrefix !== undefined && opts.knownPrefix !== null) {
    gitPrefix = opts.knownPrefix;
    confidence = scoreAt(gitPrefix, relCrate, gitFiles);
  } else {
    ({ gitPrefix, confidence } = resolveGitPrefix(relCrate, gitFiles));
  }

  const gitKey = (rel) => (gitPrefix ? `${gitPrefix}/${rel}` : rel);
  const inGit = (rel) => gitFiles.has(gitKey(rel));
  const gitSha = (rel) => gitFiles.get(gitKey(rel));

  if (confidence < 0.5) {
    return {
      status: 'NO_GIT_TAG',
      flags: [],
      gitPrefix,
      confidence: round(confidence),
      hasBuildRs: relCrate.has('build.rs'),
      buildRsInGit: false,
      contentSuspects: [],
      note: 'crate files could not be confidently located within the git tree',
    };
  }

  const truncated = !!gitFiles.truncated;
  const flags = [];
  const contentSuspects = [];
  const hasBuildRs = relCrate.has('build.rs');
  const buildRsInGit = hasBuildRs ? inGit('build.rs') : false;

  // A truncated tree can't prove a file is absent, so we suppress absence-based
  // flags (INJECTED / NOT_IN_GIT) and only trust checksum + present-file content.
  if (!truncated) {
    if (hasBuildRs && !buildRsInGit) pushFlag(flags, 'BUILD_RS_INJECTED', 'build.rs');

    for (const [rel] of relCrate) {
      if (AUTO_GENERATED.has(rel)) continue;
      const lower = rel.toLowerCase();
      if (BINARY_EXTS.some((e) => lower.endsWith(e)) && !inGit(rel)) {
        pushFlag(flags, 'BINARY_NOT_IN_GIT', rel);
      } else if (lower.endsWith('.rs') && rel !== 'build.rs' && !inGit(rel)) {
        // A Rust source file present in the artifact but absent from git.
        pushFlag(flags, 'FILE_NOT_IN_GIT', rel);
      }
    }
  }

  // Content divergence via blob-sha: shared .rs files whose sha differs. The
  // scanner confirms each (normalised content) before flagging, to avoid
  // line-ending false positives.
  for (const [rel, sha] of relCrate) {
    if (!rel.toLowerCase().endsWith('.rs')) continue;
    if (!inGit(rel)) continue;
    const g = gitSha(rel);
    if (g && g !== sha) contentSuspects.push({ rel, isBuildRs: rel === 'build.rs' });
  }

  return {
    status: isSuspicious(flags) ? 'SUSPICIOUS' : 'CLEAN',
    flags,
    gitPrefix,
    confidence: round(confidence),
    hasBuildRs,
    buildRsInGit,
    contentSuspects,
    truncated,
  };
}

function pushFlag(flags, flag, file, detail) {
  const f = { flag, file, severity: severityOf(flag) };
  if (detail) f.detail = detail;
  flags.push(f);
}

/**
 * Locate the crate's root inside the git tree. Candidate prefixes = directories
 * containing a Cargo.toml (workspace crate roots) plus ''. Score each by the
 * fraction of the crate's comparable files present at `prefix/<file>`.
 * @returns {{gitPrefix:string, confidence:number}}
 */
function resolveGitPrefix(relCrate, gitFiles) {
  const comparable = comparableFiles(relCrate);
  if (comparable.length === 0) return { gitPrefix: '', confidence: 0 };

  const candidates = new Set(['']);
  for (const p of gitFiles.keys()) {
    if (p === 'Cargo.toml') candidates.add('');
    else if (p.endsWith('/Cargo.toml')) candidates.add(p.slice(0, -'/Cargo.toml'.length));
  }

  let best = { gitPrefix: '', score: -1 };
  for (const prefix of candidates) {
    const score = scoreComparable(prefix, comparable, gitFiles);
    if (score > best.score || (score === best.score && prefix.length < best.gitPrefix.length)) {
      best = { gitPrefix: prefix, score };
    }
  }
  return { gitPrefix: best.gitPrefix, confidence: best.score };
}

function comparableFiles(relCrate) {
  return [...relCrate.keys()].filter((f) => !AUTO_GENERATED.has(f));
}

function scoreComparable(prefix, comparable, gitFiles) {
  if (comparable.length === 0) return 0;
  let hits = 0;
  for (const rel of comparable) {
    if (gitFiles.has(prefix ? `${prefix}/${rel}` : rel)) hits++;
  }
  return hits / comparable.length;
}

/** Score how well the crate's files match the git tree at a specific prefix. */
function scoreAt(prefix, relCrate, gitFiles) {
  return scoreComparable(prefix, comparableFiles(relCrate), gitFiles);
}

/**
 * Normalise source text for content comparison so benign line-ending /
 * trailing-newline differences never produce false MODIFIED alerts.
 */
function normalizeSource(text) {
  return String(text).replace(/\r\n/g, '\n').replace(/\s+$/g, '');
}

function round(n) {
  return Math.round(n * 100) / 100;
}

module.exports = { diff, resolveGitPrefix, scoreAt, normalizeSource, pushFlag, AUTO_GENERATED, BINARY_EXTS };
