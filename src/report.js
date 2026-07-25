'use strict';
const { severityOf, maxSeverity } = require('./severity');

const C = {
  red: '\x1b[31m', yellow: '\x1b[33m', cyan: '\x1b[36m',
  bold: '\x1b[1m', dim: '\x1b[2m', reset: '\x1b[0m',
};

const SEV_COLOR = { high: C.red, medium: C.yellow, info: C.cyan };

/**
 * STEP 8 (--report) — print SUSPICIOUS packages from SQLite, coloured by
 * severity. With {json:true} print machine-readable JSON instead.
 */
function printReport(store, { json = false } = {}) {
  const rows = store.getSuspicious();

  if (json) {
    process.stdout.write(
      JSON.stringify(
        rows.map((r) => ({
          name: r.name, version: r.version, status: r.status,
          severity: maxSeverity(r.flags), checked_at: r.checked_at, flags: r.flags,
        })),
        null, 2
      ) + '\n'
    );
    return rows;
  }

  console.log(`${C.bold}cargo-witness — SUSPICIOUS packages${C.reset}\n`);

  if (rows.length === 0) {
    console.log(`${C.dim}  (none) — no suspicious crates recorded.${C.reset}\n`);
    return rows;
  }

  const header = pad('SEV', 8) + pad('PACKAGE', 30) + pad('VERSION', 14) + 'FLAGS';
  console.log(`${C.bold}${header}${C.reset}`);
  console.log(`${C.dim}${'-'.repeat(header.length + 8)}${C.reset}`);

  for (const r of rows) {
    const sev = maxSeverity(r.flags) || 'medium';
    const color = SEV_COLOR[sev] || C.red;
    const flags = (r.flags || [])
      .map((f) => {
        const name = typeof f === 'string' ? f : f.flag;
        const file = typeof f === 'string' ? null : f.file;
        return `${name}${file ? `(${file})` : ''}`;
      })
      .join(', ');
    const line = pad(sev.toUpperCase(), 8) + pad(r.name, 30) + pad(r.version, 14) + flags;
    console.log(`${color}${line}${C.reset}`);
  }
  const high = rows.filter((r) => maxSeverity(r.flags) === 'high').length;
  console.log('');
  console.log(
    `${C.bold}${C.red}${rows.length} suspicious package(s)` +
    (high ? ` (${high} high severity)` : '') +
    `. Investigate before building.${C.reset}\n`
  );
  return rows;
}

/** --history: recent scan runs. */
function printHistory(store, limit = 20) {
  const runs = store.getRuns(limit);
  console.log(`${C.bold}cargo-witness — recent runs${C.reset}\n`);
  if (runs.length === 0) {
    console.log(`${C.dim}  (no runs recorded yet)${C.reset}\n`);
    return runs;
  }
  console.log(`${C.bold}${pad('WHEN', 26) + pad('CHECKED', 10) + 'SUSPICIOUS'}${C.reset}`);
  for (const r of runs) {
    const when = new Date(r.run_at).toISOString();
    const sc = r.suspicious_count > 0 ? `${C.red}${r.suspicious_count}${C.reset}` : '0';
    console.log(pad(when, 26) + pad(String(r.new_count), 10) + sc);
  }
  console.log('');
  return runs;
}

function pad(s, n) {
  s = String(s);
  return s.length >= n ? s.slice(0, n - 1) + ' ' : s + ' '.repeat(n - s.length);
}

module.exports = { printReport, printHistory };
