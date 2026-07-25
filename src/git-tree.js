'use strict';
const { resolveHost } = require('./hosts');

/**
 * STEP 4 — Resolve and fetch the source tree to compare against.
 *
 * Ref priority (strongest first):
 *   1. attestedSha — crates.io Trusted-Publishing OIDC record (`trustpub_data.sha`).
 *      The publisher cannot forge this; it's the gold-standard anchor.
 *   2. vcsSha — `.cargo_vcs_info.json` git.sha1 (publisher self-report).
 *   3. tag formats — v{ver} / {ver} / {name}-{ver} / {name}-v{ver} (older crates).
 *
 * Works across GitHub / GitLab / Gitea-Codeberg via src/hosts.js.
 *
 * @param {string} repository  repo URL (may be overridden by attestedRepo)
 * @param {string} name
 * @param {string} version
 * @param {{vcsSha?:string, attestedSha?:string, attestedRepo?:string}} [opts]
 * @returns {Promise<{
 *   gitFiles:Map|null, ref:string|null, owner:string|null, repo:string|null,
 *   host:string|null, viaCommit:boolean, refKind:string|null, provider:object|null
 * }>}
 */
async function fetchGitTree(repository, name, version, opts = {}) {
  const primary = opts.attestedRepo || repository;
  const provider = resolveHost(primary);
  const none = { gitFiles: null, ref: null, owner: null, repo: null, host: null, viaCommit: false, refKind: null, provider: null };
  if (!provider) return none;

  const refs = [];
  if (opts.attestedSha) refs.push({ ref: opts.attestedSha, kind: 'attested' });
  if (opts.vcsSha && opts.vcsSha !== opts.attestedSha) refs.push({ ref: opts.vcsSha, kind: 'vcs' });
  for (const r of [`v${version}`, `${version}`, `${name}-${version}`, `${name}-v${version}`]) {
    refs.push({ ref: r, kind: 'tag' });
  }

  for (const { ref, kind } of refs) {
    const t = await provider.tree(ref);
    if (t.status === 200) {
      return {
        gitFiles: t.gitFiles, ref, owner: provider.owner, repo: provider.repo,
        host: provider.host, viaCommit: kind !== 'tag', refKind: kind, provider,
      };
    }
    if (t.rateLimited) throw rateErr(provider, t);
    // 404 / other → try next ref.
  }

  return { ...none, owner: provider.owner, repo: provider.repo, host: provider.host };
}

function rateErr(provider, t) {
  const err = new Error(
    `${provider.host} API ${t.status} for ${provider.owner}/${provider.repo} (ratelimit remaining=${t.remaining}). ` +
    `Set ${tokenEnv(provider.host)} to raise the limit.`
  );
  err.rateLimited = true;
  return err;
}

function tokenEnv(host) {
  return host === 'gitlab' ? 'GITLAB_TOKEN' : host === 'gitea' ? 'GITEA_TOKEN' : 'GITHUB_TOKEN';
}

module.exports = { fetchGitTree };
