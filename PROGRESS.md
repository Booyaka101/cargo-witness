# cargo-witness — progress

Status: **v1.2 complete.** Production-hardened, fully tested (offline + live),
npm-publishable, portable GitHub Action, Docker.

## v1.2 — attestation + multi-host (the durability moves)

- **Trusted Publishing verification.** Reads crates.io `trustpub_data` (OIDC,
  unforgeable) and verifies against the **attested commit** in preference to
  self-reported source. `TRUSTED_PUBLISH` (info, positive) + `VCS_MISMATCH` (info)
  when self-report ≠ attestation. This is the "compose with attestation" second act.
- **Multi-host** (`src/hosts.js`): GitHub, GitLab (paginated), Gitea/Codeberg —
  auto-detected from the repo URL; per-host tokens. Closes the off-GitHub gap.
- **`--diff <name> <version>`**: unified-diff investigation view.
- **Live-proven**: `sequoia-openpgp@2.4.1` verified on **GitLab** (subdir `openpgp`,
  commit `@0b0c8c7`, 10-page pagination) CLEAN; `cargo-semver-checks@0.49.0`
  verified against its **attested** commit `@7c7bbfa✓` with `TRUSTED_PUBLISH`.
- 49 assertions across 6 suites (adds `hosts.test.js` + trustpub/diff coverage).

## v1.1 — exact-commit verification (the durability upgrade)

Reads `.cargo_vcs_info.json` from each `.crate` to verify against the **exact
published commit** (`git.sha1`) and use the authoritative `path_in_vcs`, instead
of guessing a tag. Falls back to tag formats for older crates / unreachable
commits. **Live-proven**: all 8 fixture crates resolved via exact commit
(`serde`/`serde_derive` both `@5fa711d`, one shared cached fetch) and stayed
CLEAN. Removes the main coverage gap and hardens the moat (verifies the precise
commit the artifact claims). 40 assertions across 5 suites, all green.

## Detections (7 flags, severity-ranked)

| Flag | Severity |
|------|----------|
| BUILD_RS_INJECTED | high |
| BUILD_RS_MODIFIED | high |
| BINARY_NOT_IN_GIT | high |
| CHECKSUM_MISMATCH | high |
| SOURCE_MODIFIED | medium |
| FILE_NOT_IN_GIT | medium |
| YANKED | info |

Content diffs use the git trees API blob SHA (no extra network); a SHA mismatch is
confirmed against newline-normalised raw content before flagging.

## VERIFIED working

- `npm test` — 5 suites, 36 assertions, all green. Includes a fully-offline
  integration test (mock crates.io/CDN/GitHub with real blob SHAs, on-the-fly
  `.crate` tarballs) asserting every detection + allowlist suppression.
- **Live**: scanned 16 diverse real crates (serde workspace, libc/serde build.rs,
  proc-macro2/quote/syn/once_cell macro-heavy) → **0 false positives**; all CLEAN.
  Rate-limit exhaustion degraded gracefully to NO_GIT_TAG (never errored/false-flagged).
- **CLI**: `--scan` (concurrency, --sarif, --json), `--report` (severity table +
  `--json`), `--history`, `--ci`, `--daemon` (--now, graceful SIGINT/SIGTERM).
- **Severity gating**: `--fail-on high|medium|info` verified (HIGH fails both;
  MEDIUM passes high, fails medium).
- **Allowlist**: `.cargo-witness.json` / `--config` suppression verified end-to-end.
- **SARIF 2.1.0**: written & schema-shaped for empty and non-empty results.
- **GitHub Action**: bundled `dist/action.js` is **native-free** (0 native refs,
  single 429kB file). Driven end-to-end against a standalone mock → exit 1,
  BUILD_RS_INJECTED, job summary + `suspicious-count`/`suspicious` outputs + error
  annotation. `action.yml` passes `@action-validator/cli` (inputs + outputs).
- **Packaging**: `npm pack --dry-run` clean; MIT LICENSE, files whitelist,
  metadata, prepublishOnly (build + test). package-lock.json present.
- **Hygiene**: CHANGELOG, SECURITY, CONTRIBUTING, Dockerfile (+.dockerignore),
  CI workflow, example consumer workflow.

## Architecture

- `src/store.js` — storage interface; `MemoryStore` (pure JS, action/tests).
- `src/db.js` — `SqliteStore` (better-sqlite3, CLI/daemon persistence).
- scanner/ci/report depend only on the store interface — the Action graph never
  imports better-sqlite3, so its ncc bundle carries no platform binary.
- `src/severity.js`, `src/allowlist.js`, `src/sarif.js`, `src/config.js`,
  `src/util.js` (retry/backoff + concurrency pool).

## Deviations from the literal brief (all necessary for correctness)

1. Download URL — `dl_path` 403s on the CDN; use direct `.crate` pattern.
2. Repository at `version.repository`, not `crate.repository`.
3. Workspace-aware differ (brief's root-vs-root false-positives serde et al.).
4. `action.yml` uses `node20` (validator rejects node24; acceptance gates on it).
5. CI consults stored status for known added packages.
6. Action uses an in-memory store (native module can't ship in a cross-OS bundle).

## Possible future work (not required)

- Detect injected/modified non-`.rs` assets (e.g. `.rlib`, embedded data).
- Sparse/alternate-registry artifact URLs (currently crates.io CDN only).
- Persist SARIF history; optional Slack/webhook notifier alongside desktop.
