'use strict';
const { config } = require('./config');
const { fetchRetry } = require('./util');

/**
 * Git host providers. Each provider knows how to fetch a recursive file tree
 * (path -> git blob sha) and a raw file at a ref (commit sha or tag) for one
 * hosting platform. The scanner is host-agnostic — it just asks the resolved
 * provider for trees/blobs.
 *
 * Supported: GitHub, GitLab (incl. self-hosted), Gitea/Forgejo (incl. Codeberg).
 *
 * Tree return: { status, gitFiles?: Map<path,sha>, rateLimited?, remaining? }
 * Raw return:  string | null   (throws Error{rateLimited} on 403/429)
 */

const MAX_PAGES = 60; // safety cap for paginated hosts (~6k GitLab / 60k Gitea files)

/**
 * Resolve a repository URL to a provider bound to {owner, repo}. Returns null
 * for unsupported hosts (→ NO_GIT_TAG).
 */
function resolveHost(repository) {
  const p = parseRepo(repository);
  if (!p) return null;
  const { host, owner, repo } = p;

  if (host === 'github.com') return githubProvider(owner, repo);
  if (host === 'gitlab.com' || /(^|\.)gitlab\./i.test(host)) return gitlabProvider(host, owner, repo);
  if (host === 'codeberg.org' || /(^|\.)gitea|forgejo/i.test(host)) return giteaProvider(host, owner, repo);
  return null;
}

/** Parse a repo URL into { host, owner, repo }. */
function parseRepo(repository) {
  if (!repository || typeof repository !== 'string') return null;
  const m = repository.match(
    /^https?:\/\/([^/]+)\/([^/]+)\/([^/#?]+?)(?:\.git)?(?:[/#?].*)?$/i
  );
  if (!m) return null;
  return { host: m[1].toLowerCase(), owner: m[2], repo: m[3] };
}

// --------------------------------------------------------------------------
// GitHub
// --------------------------------------------------------------------------
function githubProvider(owner, repo) {
  const headers = () => {
    const h = { Accept: 'application/vnd.github+json' };
    if (process.env.GITHUB_TOKEN) h.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    return h;
  };
  return {
    host: 'github', owner, repo,
    async tree(ref) {
      const url = `${config.githubApiBase}/repos/${owner}/${repo}/git/trees/${encodeURIComponent(ref)}?recursive=1`;
      const res = await fetchRetry(url, { headers: headers() });
      if (res.status === 200) {
        const data = await res.json();
        const map = new Map();
        for (const it of data.tree || []) if (it.type === 'blob') map.set(it.path, it.sha);
        map.truncated = !!data.truncated;
        return { status: 200, gitFiles: map };
      }
      return rateOrStatus(res);
    },
    raw: rawFetcher((ref, path) =>
      `${config.githubRawBase}/${owner}/${repo}/${encodeURIComponent(ref)}/${encPath(path)}`, headers),
  };
}

// --------------------------------------------------------------------------
// GitLab (paginated; blob sha in `id`)
// --------------------------------------------------------------------------
function gitlabProvider(host, owner, repo) {
  const apiBase = config.gitlabApiBase || `https://${host}/api/v4`;
  const rawBase = config.gitlabRawBase || `https://${host}`;
  const project = encodeURIComponent(`${owner}/${repo}`);
  const headers = () => {
    const h = {};
    if (process.env.GITLAB_TOKEN) h['PRIVATE-TOKEN'] = process.env.GITLAB_TOKEN;
    return h;
  };
  return {
    host: 'gitlab', owner, repo,
    async tree(ref) {
      const map = new Map();
      let truncated = false;
      for (let page = 1; page <= MAX_PAGES; page++) {
        const url = `${apiBase}/projects/${project}/repository/tree?ref=${encodeURIComponent(ref)}&recursive=true&per_page=100&page=${page}`;
        const res = await fetchRetry(url, { headers: headers() });
        if (res.status !== 200) {
          if (page === 1) return rateOrStatus(res);
          break; // partial: stop, keep what we have
        }
        const arr = await res.json();
        for (const it of arr) if (it.type === 'blob') map.set(it.path, it.id);
        const next = res.headers.get('x-next-page');
        if (!next) break;
        if (page === MAX_PAGES) truncated = true;
      }
      map.truncated = truncated;
      return { status: 200, gitFiles: map };
    },
    raw: rawFetcher((ref, path) =>
      `${rawBase}/${owner}/${repo}/-/raw/${encodeURIComponent(ref)}/${encPath(path)}`, headers),
  };
}

// --------------------------------------------------------------------------
// Gitea / Forgejo / Codeberg (GitHub-compatible tree; blob sha in `sha`)
// --------------------------------------------------------------------------
function giteaProvider(host, owner, repo) {
  const apiBase = config.giteaApiBase || `https://${host}/api/v1`;
  const rawBase = config.giteaRawBase || `https://${host}`;
  const headers = () => {
    const h = { Accept: 'application/json' };
    if (process.env.GITEA_TOKEN) h.Authorization = `token ${process.env.GITEA_TOKEN}`;
    return h;
  };
  return {
    host: 'gitea', owner, repo,
    async tree(ref) {
      const map = new Map();
      let truncated = false;
      for (let page = 1; page <= MAX_PAGES; page++) {
        const url = `${apiBase}/repos/${owner}/${repo}/git/trees/${encodeURIComponent(ref)}?recursive=true&per_page=1000&page=${page}`;
        const res = await fetchRetry(url, { headers: headers() });
        if (res.status !== 200) {
          if (page === 1) return rateOrStatus(res);
          break;
        }
        const data = await res.json();
        const entries = data.tree || [];
        for (const it of entries) if (it.type === 'blob') map.set(it.path, it.sha);
        if (data.truncated) truncated = true;
        const total = data.total_count || entries.length;
        if (map.size >= total || entries.length === 0) break;
        if (page === MAX_PAGES) truncated = true;
      }
      map.truncated = truncated;
      return { status: 200, gitFiles: map };
    },
    raw: rawFetcher((ref, path) =>
      `${rawBase}/${owner}/${repo}/raw/commit/${encodeURIComponent(ref)}/${encPath(path)}`, headers),
  };
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------
function rawFetcher(urlFor, headers) {
  return async (ref, filePath) => {
    const res = await fetchRetry(urlFor(ref, filePath), { headers: headers() });
    if (res.status === 404) return null;
    if (!res.ok) {
      const err = new Error(`raw fetch ${res.status} for ${filePath}`);
      if (res.status === 403 || res.status === 429) err.rateLimited = true;
      throw err;
    }
    return await res.text();
  };
}

function rateOrStatus(res) {
  if (res.status === 403 || res.status === 429) {
    return { status: res.status, rateLimited: true, remaining: res.headers.get('x-ratelimit-remaining') };
  }
  return { status: res.status };
}

function encPath(path) {
  return path.split('/').map(encodeURIComponent).join('/');
}

module.exports = { resolveHost, parseRepo };
