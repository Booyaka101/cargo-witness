'use strict';
const { parse } = require('smol-toml');
const { pushFlag } = require('./differ');

/**
 * Manifest lane — compare dependency NAMES between the published artifact's
 * Cargo.toml and the git tree's, flagging names only the artifact declares
 * (DEP_INJECTED, the arrayref@0.3.10 pattern: one added manifest line, no
 * source change). Names only, never versions: cargo rewrites the manifest at
 * package time (inlines workspace inheritance, rewrites path deps, reorders
 * keys), which is exactly why the byte diff of Cargo.toml is on the skip list.
 *
 * Every unknown suppresses the flag rather than guessing: truncated tree,
 * manifest that fails to parse on either side, unfetchable git manifest,
 * unresolvable workspace inheritance, or a git-side manifest that is not this
 * crate's ([package].name mismatch, seen live when a bare-version tag belongs
 * to a sibling crate or a prefix resolves to a virtual workspace root). The
 * reason is returned in `skipped` so --diff can explain the suppression.
 */

const DEP_KINDS = [
  'dependencies',
  'build-dependencies', 'build_dependencies',
  'dev-dependencies', 'dev_dependencies',
];

/**
 * Extract declared dependencies from parsed Cargo.toml text.
 * The renamed form (`alias = { package = "real-name" }`) yields the real crate
 * name; `alias = { workspace = true }` entries land in `inherited` for the
 * caller to resolve against [workspace.dependencies].
 * @returns {{names:Set<string>, inherited:Set<string>, workspaceDeps:Map<string,string>|null,
 *   packageName:string|null}}
 */
function parseManifestDeps(text) {
  const doc = parse(String(text));
  const names = new Set();
  const inherited = new Set();
  // [project] is cargo's deprecated alias for [package].
  const pkgTable = doc.package || doc.project;
  const packageName =
    pkgTable && typeof pkgTable === 'object' && typeof pkgTable.name === 'string'
      ? pkgTable.name : null;

  const collect = (tbl) => {
    if (tbl === undefined) return;
    if (tbl === null || typeof tbl !== 'object' || Array.isArray(tbl)) {
      throw new Error('dependency table is not a table');
    }
    for (const [key, val] of Object.entries(tbl)) {
      if (typeof val === 'string') names.add(key);
      else if (val && typeof val === 'object' && !Array.isArray(val)) {
        if (val.workspace === true) inherited.add(key);
        else if (typeof val.package === 'string') names.add(val.package);
        else names.add(key);
      } else throw new Error(`unrecognised dependency entry "${key}"`);
    }
  };

  for (const kind of DEP_KINDS) collect(doc[kind]);
  if (doc.target && typeof doc.target === 'object' && !Array.isArray(doc.target)) {
    for (const cfg of Object.values(doc.target)) {
      if (cfg && typeof cfg === 'object' && !Array.isArray(cfg)) {
        for (const kind of DEP_KINDS) collect(cfg[kind]);
      }
    }
  }

  let workspaceDeps = null;
  const ws = doc.workspace && doc.workspace.dependencies;
  if (ws && typeof ws === 'object' && !Array.isArray(ws)) {
    workspaceDeps = new Map();
    for (const [key, val] of Object.entries(ws)) {
      const real = val && typeof val === 'object' && typeof val.package === 'string' ? val.package : key;
      workspaceDeps.set(key, real);
    }
  }

  return { names, inherited, workspaceDeps, packageName };
}

/**
 * Run the lane. `raw(path)` fetches a git blob's content at the compared ref
 * (null on 404); the repo-root Cargo.toml is fetched only when a
 * `workspace = true` entry actually needs it.
 *
 * @param {object} p
 * @param {string} p.name  the crate being scanned
 * @param {string} p.artifactToml  the published artifact's Cargo.toml text
 * @param {Map<string,string>} p.gitFiles  repo path -> blob sha (with .truncated)
 * @param {string} p.gitPrefix  resolved crate root inside the repo ('' = root)
 * @param {(path:string)=>Promise<string|null>} p.raw
 * @returns {Promise<{flags:Array, artifactDeps:string[], gitDeps:string[]|null, skipped:string|null}>}
 */
async function diffManifests({ name, artifactToml, gitFiles, gitPrefix, raw }) {
  const skip = (reason) => ({ flags: [], artifactDeps: null, gitDeps: null, skipped: reason });

  if (gitFiles.truncated) return skip('git tree is truncated, absence cannot be proven');

  let artifact;
  try {
    artifact = parseManifestDeps(artifactToml);
  } catch (e) {
    return skip(`artifact Cargo.toml failed to parse (${e.message})`);
  }
  // Artifact-side `workspace = true` should not survive `cargo package`; if one
  // does, dropping it only shrinks the artifact set (never a false flag).
  const artifactDeps = [...artifact.names].sort();
  if (artifactDeps.length === 0) {
    return { flags: [], artifactDeps, gitDeps: null, skipped: null };
  }

  const manifestPath = gitPrefix ? `${gitPrefix}/Cargo.toml` : 'Cargo.toml';
  if (!gitFiles.has(manifestPath)) return skip(`git tree has no Cargo.toml at ${manifestPath || '(root)'}`);

  let git;
  try {
    const text = await raw(manifestPath);
    if (text == null) return skip(`git-side ${manifestPath} could not be fetched`);
    git = parseManifestDeps(text);
  } catch (e) {
    if (e.rateLimited) throw e;
    return skip(`git-side ${manifestPath} could not be fetched (${e.message})`);
  }

  // The manifest at the resolved prefix must be THIS crate's: a mis-resolved
  // ref or prefix can land on a sibling crate's manifest or a virtual
  // workspace root (both observed on real crates), whose dependency set would
  // mass-flag every real dependency.
  if (git.packageName !== name) {
    return skip(git.packageName
      ? `git-side ${manifestPath} is the manifest of "${git.packageName}", not "${name}"`
      : `git-side ${manifestPath} has no [package] table (workspace root?)`);
  }

  const gitNames = new Set(git.names);
  if (git.inherited.size > 0) {
    let rootDeps = git.workspaceDeps; // the crate may itself be the workspace root
    if (gitPrefix && [...git.inherited].some((k) => !rootDeps || !rootDeps.has(k))) {
      try {
        const rootText = await raw('Cargo.toml');
        if (rootText == null) return skip('workspace root Cargo.toml could not be fetched');
        const root = parseManifestDeps(rootText);
        if (root.workspaceDeps) {
          rootDeps = new Map([...(root.workspaceDeps || []), ...(rootDeps || [])]);
        }
      } catch (e) {
        if (e.rateLimited) throw e;
        return skip(`workspace root Cargo.toml could not be fetched (${e.message})`);
      }
    }
    for (const key of git.inherited) {
      if (!rootDeps || !rootDeps.has(key)) {
        return skip(`workspace inheritance for "${key}" could not be resolved`);
      }
      gitNames.add(rootDeps.get(key));
    }
  }

  const flags = [];
  for (const dep of artifactDeps) {
    if (!gitNames.has(dep)) {
      pushFlag(flags, 'DEP_INJECTED', dep,
        'dependency declared in the published artifact but absent from the git source');
    }
  }
  return { flags, artifactDeps, gitDeps: [...gitNames].sort(), skipped: null };
}

module.exports = { parseManifestDeps, diffManifests };
