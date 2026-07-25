'use strict';

/**
 * Storage interface used by the scanner/ci/report:
 *   isChecked(name, version) -> boolean
 *   recordPackage({name, version, status, flags})
 *   recordRun({new_count, suspicious_count})
 *   getSuspicious() -> Array<{name,version,checked_at,status,flags}>
 *   getStoredStatus(name, version) -> {status, flags} | null
 *   getRuns(limit) -> Array<{id,run_at,new_count,suspicious_count}>
 *   close()
 *
 * Two backends implement it:
 *   - SqliteStore (src/db.js) — persistent, native (better-sqlite3). Used by the
 *     CLI/daemon so history survives across runs.
 *   - MemoryStore (here) — pure JS, zero native deps. Used by the GitHub Action,
 *     whose runner is ephemeral (no prior DB to persist) and must run a bundle
 *     with NO platform-specific binary. Also handy for tests.
 */
function createMemoryStore() {
  const packages = new Map(); // `${name}@${version}` -> row
  const runs = [];
  let runId = 0;

  const key = (n, v) => `${n}@${v}`;

  return {
    isChecked(name, version) {
      return packages.has(key(name, version));
    },
    recordPackage({ name, version, status, flags }) {
      packages.set(key(name, version), {
        name, version, checked_at: Date.now(), status, flags: flags || [],
      });
    },
    recordRun({ new_count, suspicious_count }) {
      runs.push({ id: ++runId, run_at: Date.now(), new_count, suspicious_count });
    },
    getSuspicious() {
      return [...packages.values()]
        .filter((r) => r.status === 'SUSPICIOUS')
        .sort((a, b) => b.checked_at - a.checked_at)
        .map((r) => ({ ...r, flags: [...r.flags] }));
    },
    getStoredStatus(name, version) {
      const r = packages.get(key(name, version));
      return r ? { status: r.status, flags: [...r.flags] } : null;
    },
    getRuns(limit = 20) {
      return runs.slice(-limit).reverse();
    },
    close() {},
  };
}

module.exports = { createMemoryStore };
