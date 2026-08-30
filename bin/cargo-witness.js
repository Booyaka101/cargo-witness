#!/usr/bin/env node
'use strict';
const fs = require('fs');
const cron = require('node-cron');
const { openDb } = require('../src/db');
const { runScan } = require('../src/scanner');
const { printReport, printHistory } = require('../src/report');
const { notifySuspicious } = require('../src/notifier');
const { runCi } = require('../src/ci');
const { inspectDiff } = require('../src/inspect');
const { loadAllowlist } = require('../src/allowlist');
const { toSarif } = require('../src/sarif');
const { maxSeverity, atLeast } = require('../src/severity');
const pkg = require('../package.json');

function parseArgs(argv) {
  const args = {
    mode: null, lock: 'Cargo.lock', concurrency: 5, json: false, quiet: false,
    db: undefined, now: false, failOn: 'medium', sarif: undefined, config: undefined,
    recheck: true,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--scan': args.mode = 'scan'; break;
      case '--daemon': args.mode = 'daemon'; break;
      case '--report': args.mode = 'report'; break;
      case '--history': args.mode = 'history'; break;
      case '--diff': args.mode = 'diff'; args.diffName = argv[++i]; args.diffVersion = argv[++i]; break;
      case '--ci': args.mode = 'ci'; break;
      case '--lock': args.lock = argv[++i]; break;
      case '--concurrency': args.concurrency = Math.max(1, parseInt(argv[++i], 10) || 5); break;
      case '--db': args.db = argv[++i]; break;
      case '--config': args.config = argv[++i]; break;
      case '--sarif': args.sarif = argv[++i]; break;
      case '--fail-on': args.failOn = String(argv[++i] || 'medium').toLowerCase(); break;
      case '--json': args.json = true; break;
      case '--quiet': case '-q': args.quiet = true; break;
      case '--no-recheck': args.recheck = false; break;
      case '--now': args.now = true; break;
      case '--version': case '-V': args.mode = 'version'; break;
      case '--help': case '-h': args.mode = 'help'; break;
      default:
        if (a.startsWith('-')) { process.stderr.write(`Unknown option: ${a}\n`); args.mode = 'help'; }
    }
  }
  if (!['high', 'medium', 'info'].includes(args.failOn)) args.failOn = 'medium';
  return args;
}

const HELP = `cargo-witness v${pkg.version} — detect Rust supply-chain attacks by
diffing published crates against their git source.

Usage:
  cargo-witness --scan   [options]   One-time scan; exit non-zero if suspicious.
  cargo-witness --daemon [options]   Nightly scan at 03:00 (node-cron).
  cargo-witness --report [options]   Print SUSPICIOUS packages (severity table).
  cargo-witness --history            Print recent scan runs.
  cargo-witness --diff <name> <ver>  Show how a crate's artifact differs from source.
  cargo-witness --ci     [options]   CI: scan only newly-added packages,
                                     print JSON, exit 1 if any SUSPICIOUS.

Options:
  --lock <path>          Path to Cargo.lock (default: Cargo.lock)
  --concurrency <n>      Parallel crate checks (default: 5)
  --db <path>            SQLite DB path (default: ~/.cargo-witness/witness.db)
  --config <path>        Allowlist file (default: ./.cargo-witness.json)
  --fail-on <level>      Exit non-zero at/above severity: high|medium|info
                         (default: medium)
  --sarif <path>         Write a SARIF 2.1.0 report (for code scanning)
  --no-recheck           Skip the 24h registry metadata re-check of
                         already-cleared packages (yanked/removed state)
  --json                 Machine-readable output (--scan / --report)
  --now                  (--daemon) run one scan immediately on startup
  --quiet, -q            Suppress per-crate progress lines
  --version, -V          Print version
  --help, -h             This help

Env:
  GITHUB_TOKEN             Raise GitHub API rate limit (60/hr -> 5000/hr).
  CARGO_WITNESS_NO_NOTIFY  Disable desktop notifications.
`;

function makeLog(args) {
  return args.quiet ? () => {} : (m) => console.log(m);
}

function writeSarif(sarifPath, suspicious, lockPath) {
  if (!sarifPath) return;
  fs.writeFileSync(sarifPath, JSON.stringify(toSarif(suspicious, lockPath), null, 2));
}

/** Exit code from findings given the fail-on threshold. */
function gateExit(suspicious, failOn) {
  const worst = suspicious
    .map((p) => maxSeverity(p.flags))
    .reduce((a, b) => (atLeast(b, a || 'info') ? b : a), null);
  return worst && atLeast(worst, failOn) ? 1 : 0;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.mode === 'version') { process.stdout.write(`${pkg.version}\n`); return; }
  if (!args.mode || args.mode === 'help') {
    process.stdout.write(HELP);
    process.exit(args.mode ? 0 : 1);
  }

  if (args.mode === 'report') { printReport(openDb(args.db), { json: args.json }); return; }
  if (args.mode === 'history') { printHistory(openDb(args.db)); return; }

  if (args.mode === 'diff') {
    if (!args.diffName || !args.diffVersion) {
      process.stderr.write('Usage: cargo-witness --diff <name> <version>\n');
      process.exit(2);
    }
    await inspectDiff(args.diffName, args.diffVersion);
    return;
  }

  if (args.mode === 'ci') {
    const { exitCode } = await runCi(args.lock, {
      concurrency: args.concurrency, store: openDb(args.db), sarif: args.sarif,
      configPath: args.config, failOn: args.failOn, recheck: args.recheck,
    });
    process.exit(exitCode);
  }

  if (args.mode === 'scan') {
    const db = openDb(args.db);
    const allow = loadAllowlist(args.config);
    if (allow.path && !args.quiet) console.log(`Using allowlist: ${allow.path}`);
    const { newCount, suspicious, results, rechecked, suppressedCount } = await runScan({
      lockPath: args.lock, db, concurrency: args.concurrency,
      allowRules: allow.rules, log: makeLog(args), recheck: args.recheck,
    });
    notifySuspicious(suspicious);
    writeSarif(args.sarif, suspicious, args.lock);

    if (args.json) {
      process.stdout.write(JSON.stringify({
        newCount, suspiciousCount: suspicious.length, suppressedCount,
        recheckedCount: (rechecked || []).length, suspicious,
        results: results.map((r) => ({
          name: r.name, version: r.version, status: r.status, flags: r.flags || [],
          ...(r.manifestSkipped ? { manifestSkipped: r.manifestSkipped } : {}),
        })),
        rechecked: (rechecked || []).map((r) => ({ name: r.name, version: r.version, status: r.status, flags: r.flags || [] })),
      }, null, 2) + '\n');
    } else {
      console.log('');
      console.log(`Done. ${newCount} package(s) checked, ${suspicious.length} SUSPICIOUS` +
        (suppressedCount ? `, ${suppressedCount} suppressed` : '') +
        ((rechecked || []).length ? `, ${rechecked.length} re-checked` : '') + '.');
      if (args.sarif) console.log(`SARIF written to ${args.sarif}`);
      if (suspicious.length > 0) console.log("Run 'cargo-witness --report' for details.");
    }
    process.exit(gateExit(suspicious, args.failOn));
  }

  if (args.mode === 'daemon') {
    const log = makeLog(args);
    const allow = loadAllowlist(args.config);
    const doScan = async () => {
      const stamp = new Date().toISOString();
      console.log(`[${stamp}] cargo-witness daemon: starting scan`);
      try {
        const db = openDb(args.db);
        const { newCount, suspicious } = await runScan({
          lockPath: args.lock, db, concurrency: args.concurrency, allowRules: allow.rules, log,
          recheck: args.recheck,
        });
        notifySuspicious(suspicious);
        console.log(`[${new Date().toISOString()}] scan complete: ${newCount} checked, ${suspicious.length} SUSPICIOUS`);
      } catch (e) {
        console.error(`daemon scan error: ${e.message}`);
      }
      console.log('cargo-witness daemon: next scan at 03:00');
    };

    console.log('cargo-witness daemon: next scan at 03:00');
    const task = cron.schedule('0 3 * * *', doScan);
    task.start();

    const shutdown = () => {
      console.log('\ncargo-witness daemon: shutting down');
      try { task.stop(); } catch { /* ignore */ }
      process.exit(0);
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

    if (args.now) await doScan();
    process.stdin.resume();
    return;
  }
}

main().catch((e) => {
  console.error('cargo-witness fatal:', e.message);
  process.exit(2);
});
