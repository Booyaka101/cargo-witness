# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-08-20

### Added

- **Registry-absence detection: `VERSION_REMOVED` and `CRATE_REMOVED` (both HIGH).**
  On 2026-08-20 the [Rust Security Response Team disclosed a supply chain attack
  on arrayref](https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/):
  `arrayref@0.3.10` (86 minutes online), `internment@0.8.7` (90) and
  `append-only-vec@0.1.9` (107) were republished with a dependency on the
  typosquat `proc-macro1`, whose build script downloads and executes a payload
  at build time. crates.io responded by **deleting** the versions. cargo-witness
  1.2.1 saw that deletion as a plain fetch error: one `[error]` line, exit 0.
  Now a 404 from the version endpoint is treated as the signal it is, with one
  disambiguating request to the crate endpoint: crate still there means
  `VERSION_REMOVED`; crate gone entirely means `CRATE_REMOVED`. Both are
  allowlist-suppressible, appear in `--json`, `--report` and desktop
  notifications, and get SARIF rules at level `error`. Non-404 failures
  (outages, rate limits, 5xx) still retry and report as errors, never as
  findings, and alternate-registry lockfile entries are never probed.
- **24h metadata re-check of already-cleared packages.** The store (both the
  SQLite and in-memory backends) now records a `meta_checked_at` timestamp, and
  every scan runs a second, cheap pass over previously-recorded packages still
  in the lockfile whose metadata is older than 24 hours: crates.io metadata
  only, no tarball download, no git-tree fetch. A version that is yanked or
  deleted *after* cargo-witness cleared it flips to SUSPICIOUS on the next
  daemon run instead of staying silently green forever. Disable with
  `--no-recheck`. Rate limiting during the re-check keeps the previous verdict
  and retries next run.
- `--diff <name> <version>` on a withdrawn version now reports the removal and
  points at the local registry cache (`~/.cargo/registry/cache`), where the
  already-fetched `.crate` would still be, instead of failing on the download.

### Changed

- **This changes verdicts.** A lockfile pinning a withdrawn version that passed
  under 1.2.1 (exit 0 with an `[error]` line) now fails with a HIGH finding
  under the default `--fail-on medium`. That is the point of the release: on
  the machine that already fetched and executed the malicious build script,
  `cargo build` keeps working from the local cache and prints nothing.
- Scope note, to be accurate about what cargo already does: a cold build
  (empty registry cache) does fail when a locked version has vanished, but with
  a famously unhelpful error (rust-lang/cargo#10063, open since 2021) that
  never suggests the version was pulled as malicious. And RustSec closed the
  arrayref malware report (rustsec/advisory-db#3161) as not planned, so
  `cargo-audit` has no advisory to fire on for this incident. This detection is
  for the already-fetched, already-executed case, and for turning a silent
  exit-0 into a HIGH finding.

## [1.2.0] - 2026-07-25

### Added

- **Trusted Publishing verification.** Reads crates.io's `trustpub_data` (the
  OIDC-attested record of the CI run that published the crate — which the
  publisher cannot forge) and verifies against that **attested commit** in
  preference to any self-reported source. Adds `TRUSTED_PUBLISH` (info, a
  positive assurance signal) and `VCS_MISMATCH` (info) when the self-reported
  `.cargo_vcs_info.json` commit disagrees with the attested one.
- **Multi-host support.** Resolves and compares source on **GitHub, GitLab**
  (paginated tree API) **and Gitea/Forgejo/Codeberg**, in addition to GitHub —
  closing the coverage gap for the many crates hosted off GitHub. Per-host tokens
  (`GITLAB_TOKEN`, `GITEA_TOKEN`) raise rate limits; self-hosted instances are
  auto-detected from the repository hostname.
- **`--diff <name> <version>`** — an investigation view that resolves the source
  commit and prints a unified diff of any modified Rust source (especially
  `build.rs`) so a human can judge a finding.
- Launch materials and FAQ under `docs/`.

### Changed

- Ref-resolution priority is now: attested commit → `.cargo_vcs_info.json`
  commit → git tag. Git-host access is abstracted behind `src/hosts.js`.

## [1.1.0] - 2026-07-25

### Added

- **Exact-commit verification.** cargo-witness now reads `.cargo_vcs_info.json`
  from each `.crate` (present in modern crates) to obtain the precise `git.sha1`
  the artifact was published from and fetches the git tree at *that commit* —
  eliminating tag-guessing and its `NO_GIT_TAG` coverage gap. Verified crates
  show the short commit (`@abc1234`).
- **Authoritative subdirectory.** The crate's `path_in_vcs` is used directly as
  the workspace root instead of the heuristic resolver (still score-validated, so
  a mismatched repo/commit self-corrects to `NO_GIT_TAG`).

### Changed

- Git-tree cache is keyed by exact commit, so workspace siblings published from
  the same release commit (e.g. `serde` + `serde_derive`) share a single fetch.
- Tag-format guessing (`v{ver}` / `{ver}` / `{name}-{ver}` / `{name}-v{ver}`) is
  now the *fallback* for older crates without vcs info, or when the recorded
  commit is unreachable on the remote.

## [1.0.0] - 2026-07-25

### Added

- Initial public release of **cargo-witness**, a tool + daemon + GitHub Action
  that detects Rust supply-chain attacks by diffing published crate artifacts
  from `static.crates.io` against their git source.
- Artifact acquisition pipeline: downloads each crate's `.crate` archive from
  the CDN, extracts it, and fetches the matching git tag's file tree from GitHub
  for comparison.
- Detection flags, each with an associated severity:
  - `BUILD_RS_INJECTED` (HIGH) — a `build.rs` present in the published crate but
    absent from git source (the "onering" attack pattern).
  - `BUILD_RS_MODIFIED` (HIGH) — a `build.rs` present in both, but the published
    content differs from git.
  - `SOURCE_MODIFIED` (MEDIUM) — a non-`build.rs` source file whose published
    content differs from git, verified via git blob SHA and normalized content.
  - `FILE_NOT_IN_GIT` (MEDIUM) — a source file present in the artifact but absent
    from git.
  - `BINARY_NOT_IN_GIT` (HIGH) — a precompiled `.so`/`.dll`/`.exe`/`.dylib`/`.wasm`
    binary shipped only in the artifact.
  - `CHECKSUM_MISMATCH` (HIGH) — the artifact's computed sha256 does not match the
    crates.io-recorded checksum.
  - `YANKED` (INFO) — the version is yanked on crates.io.
- CLI with four modes: `--scan`, `--daemon`, `--report`, and `--ci`.
- CLI options: `--lock <path>`, `--concurrency <n>`, `--db <path>`, `--json`,
  `--now`, `--quiet`, `--fail-on <high|medium|info>`, `--sarif <path>`,
  `--history`, and `--version`.
- Environment configuration: `GITHUB_TOKEN` (raises the GitHub API rate limit)
  and `CARGO_WITNESS_NO_NOTIFY` (disables desktop notifications).
- GitHub Action packaged for `node20`, emitting a job summary and the
  `suspicious-count` and `suspicious` step outputs, plus `fail-on`, `sarif` and
  `config` inputs. The action bundle is **native-free** (uses an in-memory store,
  so no platform-specific `better-sqlite3` binary is committed to `dist/`).
- SARIF 2.1.0 output (`--sarif <path>` / action `sarif` input) for code scanning.
- Allowlist-based suppression of known-benign findings via `.cargo-witness.json`
  (or `--config <path>`).
- `--fail-on <high|medium|info>` severity gate for `--scan` and `--ci`.
- Resilient networking with retry and exponential backoff.
- Bounded concurrency for artifact downloads and comparisons.
- Git-tree caching to avoid redundant GitHub API calls.
- Checksum verification of downloaded artifacts against crates.io.
- Workspace-subdirectory resolution to locate a crate's source within a
  multi-crate repository.

[1.3.0]: https://github.com/Booyaka101/cargo-witness/releases/tag/v1.3.0
[1.2.0]: https://github.com/Booyaka101/cargo-witness/releases/tag/v1.2.0
[1.1.0]: https://github.com/Booyaka101/cargo-witness/releases/tag/v1.1.0
[1.0.0]: https://github.com/Booyaka101/cargo-witness/releases/tag/v1.0.0
