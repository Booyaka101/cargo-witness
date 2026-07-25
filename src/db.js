'use strict';
const path = require('path');
const os = require('os');
const fs = require('fs');
const Database = require('better-sqlite3');

/**
 * STEP 2 — SQLite-backed store at ~/.cargo-witness/witness.db.
 * Implements the store interface documented in src/store.js.
 *
 *   packages(name, version, checked_at, status, flags, PK(name,version))
 *   runs(id PK, run_at, new_count, suspicious_count)
 */

function defaultDbPath() {
  return path.join(os.homedir(), '.cargo-witness', 'witness.db');
}

/**
 * Open the persistent SQLite store. Returns an object implementing the store
 * interface (see src/store.js).
 * @param {string} [dbPath]
 */
function openDb(dbPath = defaultDbPath()) {
  if (dbPath !== ':memory:') fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS packages (
      name        TEXT NOT NULL,
      version     TEXT NOT NULL,
      checked_at  INTEGER NOT NULL,
      status      TEXT NOT NULL,
      flags       TEXT NOT NULL,
      PRIMARY KEY (name, version)
    );
    CREATE TABLE IF NOT EXISTS runs (
      id                INTEGER PRIMARY KEY,
      run_at            INTEGER NOT NULL,
      new_count         INTEGER NOT NULL,
      suspicious_count  INTEGER NOT NULL
    );
  `);

  const stmts = {
    checked: db.prepare('SELECT 1 FROM packages WHERE name = ? AND version = ?'),
    upsert: db.prepare(
      `INSERT INTO packages (name, version, checked_at, status, flags)
       VALUES (@name, @version, @checked_at, @status, @flags)
       ON CONFLICT(name, version) DO UPDATE SET
         checked_at = excluded.checked_at,
         status     = excluded.status,
         flags      = excluded.flags`
    ),
    insertRun: db.prepare(
      'INSERT INTO runs (run_at, new_count, suspicious_count) VALUES (?, ?, ?)'
    ),
    suspicious: db.prepare(
      "SELECT name, version, checked_at, status, flags FROM packages WHERE status = 'SUSPICIOUS' ORDER BY checked_at DESC"
    ),
    status: db.prepare('SELECT status, flags FROM packages WHERE name = ? AND version = ?'),
    runs: db.prepare('SELECT id, run_at, new_count, suspicious_count FROM runs ORDER BY run_at DESC LIMIT ?'),
  };

  return {
    _db: db, // escape hatch (tests)
    isChecked(name, version) {
      return !!stmts.checked.get(name, version);
    },
    recordPackage({ name, version, status, flags }) {
      stmts.upsert.run({
        name, version, checked_at: Date.now(), status, flags: JSON.stringify(flags || []),
      });
    },
    recordRun({ new_count, suspicious_count }) {
      stmts.insertRun.run(Date.now(), new_count, suspicious_count);
    },
    getSuspicious() {
      return stmts.suspicious.all().map((r) => ({ ...r, flags: safeParse(r.flags) }));
    },
    getStoredStatus(name, version) {
      const r = stmts.status.get(name, version);
      return r ? { status: r.status, flags: safeParse(r.flags) } : null;
    },
    getRuns(limit = 20) {
      return stmts.runs.all(limit);
    },
    close() {
      db.close();
    },
  };
}

function safeParse(s) {
  try { return JSON.parse(s); } catch { return []; }
}

module.exports = { defaultDbPath, openDb };
