# cargo-witness — progress

Status: **v1.4.0 complete, PR #11 open, all 6 CI checks green on 2f35a17**
(feat/manifest-lane -> master; owner merges, tags v1.4.0 on the merge commit
once its checks are green, then `npm publish`). Production-hardened, fully
tested (offline + live), npm-publishable, portable GitHub Action, Docker.

## v1.4 manifest lane: DEP_INJECTED (closing the arrayref live window)

The arrayref@0.3.10 republish added ONE manifest line (`[build-dependencies]
proc-macro1 = "1.0.107"`) and touched no source, so 1.3.0's file diff named
nothing inside the 86-107 minute live window; VERSION_REMOVED only fires after
crates.io deletes the version. Cargo.toml is deliberately byte-diff-skipped
(cargo rewrites it at package time), so the fix is a NAME-level comparison.

- **`src/manifest.js`** — `parseManifestDeps` (smol-toml; all dep tables incl.
  `[target.<cfg>.*dependencies]` + underscore aliases; `package = "..."`
  renames resolve to the real crate name; `workspace = true` entries collected
  for resolution; `[workspace.dependencies]` + `[package]`/`[project]` name
  extracted) and `diffManifests` (async lane; artifact set vs git set, one
  DEP_INJECTED (high) per name only the artifact declares; flag `file` = dep
  name so the existing allowlist matches per crate AND per dependency).
- **Conservative by design** — every unknown suppresses and records a reason
  (`skipped`): truncated tree, unparseable manifest either side, unfetchable
  git manifest, unresolvable workspace inheritance, confidence < 0.5
  (NO_GIT_TAG), and a **package-identity check**: the git-side manifest's
  `[package].name` must equal the scanned crate. That last one was driven by
  two REAL false-positive classes found during measurement (see below).
  `--diff` prints the reason, or both dependency sets side by side.
- Wiring: scanner lane after `diff()` (rate-limit propagates to
  `state.gitRateLimited`; `manifestSkipped` carried on the result row and in
  `--json`), `--diff` section + `printDepSets`, severity table, SARIF rule at
  error, README, screenshot `docs/screenshot-diff-dep.png` (labelled
  reconstruction; the real 0.3.10 artifact is deleted).

### Measurement (the brief's no-false-positives proof)

First run over rust-lang/cargo's lockfile fired DEP_INJECTED on 4 real crates.
Both root causes were mis-resolved git locations, not parser bugs:

1. **rand_core@0.9.5** fell back to tag `0.9.5` = the 2019 tag of the sibling
   `rand` crate (bare `{ver}` tag format matches sibling tags in multi-crate
   repos). Lane saw `rand`'s manifest. Pre-existing 1.3.0 noise on the same
   crates (FILE_NOT_IN_GIT/SOURCE_MODIFIED) comes from the same weakness.
2. **varisat-*@0.2.2** (2020, `.cargo_vcs_info.json` without `path_in_vcs`)
   heuristically resolved to the repo root, whose VIRTUAL workspace manifest
   declares zero deps.

Fix: the package-identity check above (no exception lists). Re-run:
ws (42) + ripgrep (52) + rust-lang/cargo (523) = **617 crates checked,
0 DEP_INJECTED**, 0 lane skips on ws/rg (crates.io 429s meant the cargo
lockfile took four passes against one accumulating DB to finish all 523; the
totals above are read back out of the three DBs). A third identity-check catch
turned up in that data: `im-rc`, whose repository manifest names the crate
`im`. Remaining suspicious rows are pre-existing 1.3.0 verdicts (crossbeam
SOURCE_MODIFIED on shipped file copies, ring's pregenerated .o
BINARY_NOT_IN_GIT, etc.), unchanged by this release.

### Known, deliberate (v1.4)

- Bare `{ver}` tag fallback can still land on a sibling crate's tag in
  multi-crate repos (pre-existing; affects FILE_NOT_IN_GIT/SOURCE_MODIFIED
  noise for old crates without vcs info). The manifest lane is shielded by the
  identity check; reordering tag formats is future work.
- Artifact-side `workspace = true` entries (which `cargo package` never emits)
  are dropped from the artifact set — shrinks it, never a false flag.
- One extra git blob fetch per crate (the git-side Cargo.toml must be read as
  content; the trees API only gives shas). Cached per repo/ref/path so
  workspace siblings and the shared root reuse a fetch. Documented in README.
- The lane compares NAMES only. A dependency that exists in both manifests but
  whose *source* was repointed (e.g. a git/registry swap on the same name) is
  out of scope, deliberately, because version and source strings are exactly
  what cargo rewrites.

### Next steps (v1.5 candidates, in rough value order)

1. **Tag-resolution ordering.** Bare `{ver}` before `{name}-{ver}` is what put
   rand_core on `rand`'s tag. Trying name-qualified formats first, or
   validating a candidate tag by the manifest's `[package].name` (the check
   already written for the lane), would cut pre-existing FILE_NOT_IN_GIT and
   SOURCE_MODIFIED noise on old crates. Cheap and well-scoped.
2. **DEP_REMOVED / feature-set diff (info).** A dependency in git but not the
   artifact, and `[features]` divergence, would round out the manifest lane.
   Kept out of 1.4 because it is not the attack shape and would add noise.
3. **Escalate a DEP_INJECTED whose injected crate has a build script.** The
   arrayref payload lived in `proc-macro1`'s build.rs, not arrayref's. Fetching
   the injected crate's own manifest/artifact would let the finding say "and
   that crate runs a build script", which is the sentence a triager wants.
4. Persist SARIF history; optional Slack/webhook notifier alongside desktop.
5. Sparse/alternate-registry artifact URLs (currently crates.io CDN only).

## v1.3 registry-absence detection + 24h re-check (the arrayref response)

Driven by the 2026-08-20 RSRT disclosure (arrayref@0.3.10 86 min online,
internment@0.8.7 90, append-only-vec@0.1.9 107; crates.io DELETED the versions).

- **VERSION_REMOVED / CRATE_REMOVED (both HIGH).** `fetchCrateMeta` returns a
  typed absence on 404 (all other non-ok still throw; fetchRetry owns 429/5xx),
  disambiguated by one GET on `/crates/{name}`: 200 = version withdrawn, 404 =
  crate gone. Handled in `checkOne` before any download; allowlist-suppressible;
  in `--json`, `--report`, desktop notify; SARIF rules at level error.
- **Re-check pass.** `meta_checked_at` persisted in BOTH stores (sqlite column
  + migration for old DBs; memory store). `runScan` second pass over recorded
  lockfile packages staler than 24h: metadata only, no tarball/git; honours
  `--concurrency`; `--no-recheck` skips; rate limits keep the previous verdict.
  CI mode passes all added packages so a stale known verdict can refresh.
- **Alt-registry safety**: `parseCargoLock(.., {withSource:true})` +
  `isCratesIoSource`; non-crates.io entries keep the old throw (ERROR, never a
  false CRATE_REMOVED).
- **VERIFIED live 2026-08-20**: arrayref@0.3.10 -> exit 1,
  `[SUSPICIOUS !!] arrayref@0.3.10 {VERSION_REMOVED}` + detail line, SARIF rule
  error, report row HIGH; arrayref@0.3.9 -> exit 0; rerun within 24h -> zero
  registry requests; backdated store -> recheckedCount 1, verdict preserved.
- `npm test`: 6 suites, 71 assertions (49 existing unchanged + 22 new), green.

### Review pass (cb76be2) — three real defects found and fixed

1. **CI absence-probed alternate registries.** `diffAddedPackages` returns only
   name+version, so an added alt-registry crate reached the scanner with no
   `source` and was probed against crates.io; a 404 there could have produced a
   false `CRATE_REMOVED`. `ci.js` now carries `source` over from the lockfile.
   (The `--scan` path was always safe: it parses sources itself.)
2. **`recheckMaxAgeMs: 0` silently meant 24h** (`||` on a falsy 0, now `??`).
3. **`--diff` on a withdrawn version died** on the missing artifact; it now
   explains the removal and points at `~/.cargo/registry/cache`.

Also: extracted the allowlist-suppression block (had reached three copies);
covered the pre-1.3 **DB migration** every existing user hits on upgrade, a
**network outage** staying ERROR, and the re-check touching **neither CDN nor
git host**. Similarity check per house rules: `recheckOne` vs `checkOne` 10.3%,
vs the absence branch 17.4% — well under the 60% extract threshold.

### Known, deliberate: `--scan` reports NEW findings only

A second `--scan` of an unchanged lockfile exits 0 even when a package is
already recorded SUSPICIOUS (pass 1 skips checked pairs; the re-check only
promotes *newly* suspicious rows). This is pre-1.3 behaviour and intentional:
`--report` shows accumulated state, and `--ci` re-surfaces stored SUSPICIOUS
verdicts for added packages so the gate still fires. Not changed here, because
altering `--scan` exit semantics is a bigger behavioural change than this
release should carry.

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
