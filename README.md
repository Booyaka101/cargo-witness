# cargo-witness

**Detect Rust supply-chain attacks by diffing published crate artifacts against their git source.**

`cargo-witness` downloads the exact `.crate` artifact that Cargo installs from
`static.crates.io`, extracts it, and compares it against the **precise git commit
the artifact was published from** — read from the `.cargo_vcs_info.json` embedded
in every modern crate (falling back to git-tag resolution for older ones). The
headline detection is **`BUILD_RS_INJECTED`**:
a `build.rs` file present in the published crate but absent from the git source —
the exact pattern of the *onering* supply-chain attack (June 10, 2026), where a
malicious build script was slipped into the published artifact without ever
appearing in the public repository.

### Detections

| Flag | Meaning |
|------|---------|
| **`BUILD_RS_INJECTED`** | `build.rs` in the published crate, absent from git (the *onering* pattern). |
| **`BUILD_RS_MODIFIED`** | `build.rs` present in both, but the published content differs from the git source (newline-normalised). |
| **`BINARY_NOT_IN_GIT`** | A precompiled `.so/.dll/.exe/.dylib/.wasm` shipped in the artifact but not in source. |
| **`CHECKSUM_MISMATCH`** | The downloaded artifact's sha256 does not match the checksum crates.io recorded — CDN/artifact tampering. |
| **`VERSION_REMOVED`** | crates.io no longer serves this version but the crate exists. Deletion is how crates.io responds to a malicious publish (the *arrayref* incident, Aug 20, 2026). |
| **`CRATE_REMOVED`** | crates.io no longer serves the crate at all (version and crate both 404). |
| `VCS_MISMATCH` (info) | The self-reported publish commit disagrees with the OIDC-attested commit. |
| `TRUSTED_PUBLISH` (info) | Positive signal: published via crates.io Trusted Publishing and verified against the attested commit. |
| `YANKED` (info) | The version is yanked on crates.io. |

A `high` or `medium` flag → the package is recorded `SUSPICIOUS` and (interactively)
raises a desktop notification. `info` flags are surfaced but don't mark the
package suspicious.

## Why this catches what a `git clone` review misses

Developers audit source on GitHub. But `cargo build` runs the artifact from
crates.io, which is a *separate upload* — an attacker with a publish token can
inject a `build.rs` into the artifact that never touches the repo. `cargo-witness`
compares the thing that actually runs on your machine against the thing you
reviewed.

## Verification anchor (attested → self-reported → tag)

cargo-witness compares against the strongest source anchor available, in order:

1. **Attested commit (Trusted Publishing).** If crates.io recorded a Trusted
   Publishing (OIDC) run for the version, its `trustpub_data.sha` is the commit
   the CI build actually ran from — and the publisher **cannot forge it**. This
   is the gold standard; such crates show `@<sha>✓` and a `TRUSTED_PUBLISH` signal.
2. **Self-reported commit.** Otherwise, the `git.sha1` + `path_in_vcs` embedded in
   the crate's `.cargo_vcs_info.json` — the exact commit the publisher recorded at
   package time (`@<sha>`). If it disagrees with an attested commit, `VCS_MISMATCH`.
3. **Git tag.** For older crates without vcs info, tag formats `v{ver}` / `{ver}` /
   `{name}-{ver}` / `{name}-v{ver}`.

Either way there's no blind tag-guessing when a commit is known, giving
near-complete, precise coverage (e.g. `serde@1.0.197 (git root: serde) @5fa711d`).

## Supported git hosts

**GitHub, GitLab** (incl. self-hosted; paginated tree API) **and
Gitea/Forgejo/Codeberg**. The host is detected from the crate's repository URL.
Set `GITHUB_TOKEN` / `GITLAB_TOKEN` / `GITEA_TOKEN` to raise the respective rate
limits. Repos on unsupported hosts are reported `NO_GIT_TAG` (not a verdict).

## Workspace-aware (no false positives on serde et al.)

Most popular crates live in a **subdirectory** of their repo (cargo workspaces).
`serde@1.0.197`, for example, ships `build.rs` at the crate root, but in git it
lives at `serde/build.rs`. A naïve root-vs-root comparison would flag serde — one
of the most-used crates in existence — as an injection. cargo-witness locates the
crate's true root **inside** the git tree (anchored on the crate's own
`Cargo.toml` location and corroborated by matching source files) before comparing.
This removes the false positive **without** hiding a real injection: an injected
`build.rs` is absent even at the correctly-resolved subdirectory. (See
`test/differ.test.js` — both cases are covered.)

## Install / run

```bash
npm install          # installs deps (better-sqlite3 native build)

# One-time scan of a project's Cargo.lock:
node bin/cargo-witness.js --scan --lock path/to/Cargo.lock

# Nightly daemon (03:00, node-cron); desktop-notifies on any SUSPICIOUS finding:
node bin/cargo-witness.js --daemon --lock path/to/Cargo.lock

# Print all recorded SUSPICIOUS packages as a red table:
node bin/cargo-witness.js --report

# CI mode: scan only packages newly ADDED in the last commit, print JSON,
# exit 1 if any are SUSPICIOUS:
node bin/cargo-witness.js --ci --lock Cargo.lock
```

Once published to npm you can run it with `npx cargo-witness --scan`.

### Options

| Option | Effect |
|--------|--------|
| `--lock <path>` | Path to `Cargo.lock` (default `Cargo.lock`). |
| `--concurrency <n>` | Parallel crate checks (default 5). |
| `--db <path>` | SQLite DB path (default `~/.cargo-witness/witness.db`). |
| `--config <path>` | Allowlist file (default `./.cargo-witness.json`). |
| `--fail-on <level>` | Exit non-zero at/above severity `high\|medium\|info` (default `medium`). |
| `--sarif <path>` | Write a SARIF 2.1.0 report for GitHub code scanning. |
| `--no-recheck` | Skip the 24h registry metadata re-check of already-cleared packages. |
| `--json` | Machine-readable output (`--scan` / `--report`). |
| `--now` | (`--daemon`) run one scan immediately on startup. |
| `--quiet`, `-q` | Suppress per-crate progress lines. |
| `--version`, `-V` | Print version. |

Extra modes: `--history` prints recent scan runs; `--report --json` emits the
suspicious list as JSON; `--diff <name> <version>` shows exactly how a crate's
published artifact differs from its source (unified diff of modified `build.rs` /
source), for triaging a finding.

`--scan` and `--ci` exit non-zero when a finding meets `--fail-on`, so they
double as gates in any pipeline. `--daemon` shuts down cleanly on Ctrl-C / SIGTERM.

### Allowlist (suppressing accepted findings)

Some crates legitimately ship, say, a prebuilt binary. Mute accepted findings
with `.cargo-witness.json` (or `--config <path>`):

```json
{
  "allow": [
    { "name": "ring", "flag": "BINARY_NOT_IN_GIT" },
    { "name": "foo", "version": "1.2.3", "flag": "SOURCE_MODIFIED", "file": "src/gen.rs" }
  ]
}
```

Omitted `version` / `flag` / `file` (or `"*"`) match anything. Suppressed findings
are counted and reported but don't mark the package SUSPICIOUS.

### Environment

| Var | Effect |
|-----|--------|
| `GITHUB_TOKEN` | Raises the GitHub git-trees API limit from 60/hr to 5000/hr. Recommended for scanning large lockfiles. |
| `CARGO_WITNESS_NO_NOTIFY` | Disables desktop notifications (set this in CI/headless). |

Network calls retry with exponential backoff on 429/5xx and honour
`Retry-After` / `x-ratelimit-reset`. Git trees and `build.rs` blobs are cached
per repo tag, so cargo workspace siblings (e.g. `serde` + `serde_derive`) reuse a
single fetch.

State is stored in a SQLite DB at `~/.cargo-witness/witness.db`. Already-checked
`name@version` pairs are skipped on subsequent runs, so daemon scans are cheap.

## Registry removal, and the re-check the store exists for

On Aug 20, 2026 the Rust Security Response Team disclosed a
[supply chain attack on arrayref](https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/):
`arrayref@0.3.10` (86 minutes online), `internment@0.8.7` (90) and
`append-only-vec@0.1.9` (107) were republished depending on the typosquat
`proc-macro1`, whose `build.rs` downloads and executes a payload **at build
time**. crates.io's response was to **delete** the versions. cargo-witness
treats that deletion as the signal it is: a lockfile pinning a withdrawn
version gets a HIGH `VERSION_REMOVED` / `CRATE_REMOVED` finding and a non-zero
exit under the default `--fail-on medium`.

To be accurate about what cargo already does: a **cold** build does fail when a
locked version has vanished from the index, but with a famously unhelpful
error ([rust-lang/cargo#10063](https://github.com/rust-lang/cargo/issues/10063),
open since 2021) that never hints the version was pulled as malicious. On the
machine that matters, the one that ran `cargo update` inside the attack
window, executed the malicious `build.rs`, and still has the `.crate` in
`~/.cargo/registry`, **cargo builds on in silence**; the RSRT's own
remediation advice is a manual find over that cache. And RustSec closed the
arrayref malware report
([rustsec/advisory-db#3161](https://github.com/rustsec/advisory-db/issues/3161))
as not planned, so `cargo-audit` users have no advisory to fire on for this
incident at all. This detection is for that already-fetched, already-executed
case, and for turning a silent exit-0 into a HIGH finding.

Deletion usually happens *after* the malicious version was fetched; the
attack window is minutes to hours. That is what the persistent SQLite store is
for: every scan runs a second, cheap pass over previously-cleared packages
still in the lockfile whose metadata is older than 24h (crates.io metadata
only, no tarball download, no git-tree fetch) and updates their
yanked/removed state. A version withdrawn after cargo-witness cleared it flips
to SUSPICIOUS on the next daemon run instead of staying green forever. Disable
with `--no-recheck`; rate limits during the re-check keep the previous verdict
and retry next run. Alternate (non-crates.io) registry entries are never
probed, and only a genuine 404 counts; outages and 5xx stay errors.

## GitHub Action

`action.yml` runs cargo-witness in CI mode and **fails the build** (exit 1) if a
newly-added dependency is suspicious:

```yaml
- uses: your-org/cargo-witness@v1
  id: witness
  with:
    cargo-lock: Cargo.lock
    github-token: ${{ github.token }}
    fail-on: medium          # high | medium | info
    sarif: cargo-witness.sarif # optional, for code scanning
# Later steps can read outputs:
#   ${{ steps.witness.outputs.suspicious-count }}
#   ${{ steps.witness.outputs.suspicious }}   # JSON array
```

Inputs: `cargo-lock`, `github-token`, `fail-on`, `sarif`, `config`. It writes a
**job summary** (a table of any suspicious packages) and sets the
`suspicious-count` / `suspicious` step outputs.

The action entry is bundled to `dist/action.js` with `npm run build:action`
(`@vercel/ncc`). The bundle is **native-free**: the action uses an in-memory
store (its runner is ephemeral), so no platform-specific `better-sqlite3` binary
is committed to `dist/` — it runs on any GitHub runner OS. The CLI/daemon keep the
persistent SQLite store for cross-run history.

A ready-to-copy example is in
[`docs/example-workflow.yml`](docs/example-workflow.yml).

## Docker

```bash
docker build -t cargo-witness .
docker run --rm -v "$PWD:/work" -w /work cargo-witness --scan --lock Cargo.lock
```

A two-stage build (`Dockerfile`) compiles `better-sqlite3` in a builder stage and
ships a slim final image; default entrypoint runs the daemon.

## Best first distribution step

**Publish to npm as `cargo-witness`** (`npm publish`) so any Rust team can add a
one-line `npx cargo-witness --ci` step to their pipeline — then post the *onering*
detection story (build.rs injected into the artifact but absent from git) to
r/rust and the RustSec / rustsec-advisory community, which is exactly the audience
already primed by that attack.

## How it works (pipeline)

1. **`src/cargo-lock.js`** — parse `Cargo.lock`, keep only `registry+` packages.
2. **`src/store.js`** / **`src/db.js`** — storage interface with two backends: a
   persistent SQLite store (CLI/daemon) and a pure-JS in-memory store (Action/tests).
3. **`src/fetcher.js`** — GET crates.io API v1 for repository + checksum + yanked;
   download the `.crate` from `static.crates.io/crates/{name}/{name}-{ver}.crate`;
   verify sha256; extract; compute each file's git blob SHA.
4. **`src/git-tree.js`** — GitHub git-trees API (path → blob SHA), trying tag
   formats `v{ver}`, `{ver}`, `{name}-{ver}`, `{name}-v{ver}`; raw-blob fetch for
   content confirmation.
5. **`src/differ.js`** — workspace-aware diff (blob-SHA content compare) →
   `CLEAN` / `SUSPICIOUS` / `NO_GIT_TAG` plus flags.
6. **`src/severity.js`** / **`src/allowlist.js`** — severity model + suppression.
7. **`src/scanner.js`** / **`src/notifier.js`** — orchestrate, record, desktop-notify.
8. **`src/report.js`** / **`src/sarif.js`** — severity table / JSON / SARIF output.
9. **`bin/cargo-witness.js`** — CLI; **`src/action.js`** — GitHub Action entry.

## Implementation notes (verified against live services)

- The crates.io **version** endpoint (`/api/v1/crates/{n}/{v}`) returns only
  `{ version: {...} }` — there is **no** top-level `crate` object; the repository
  URL is at `version.repository`.
- The API's `dl_path` (`/api/v1/crates/{n}/{v}/download`) is a crates.io redirect
  path, **not** a static.crates.io path — prefixing it onto `static.crates.io`
  returns **403**. cargo-witness downloads from the direct CDN pattern instead.
- `action.yml` uses `using: node20` (current LTS runner, and the value that
  passes `action-validator`). GitHub also supports `node24`; swap it in once your
  `action-validator` schema includes it.
- Content comparison uses the **git blob SHA** returned by the trees API
  (`sha1("blob "+len+"\0"+content)`), so every shared file is content-checked with
  **no extra network calls**; only a SHA mismatch triggers a raw fetch, which is
  then confirmed against newline-normalised content to avoid CRLF false positives.
- Bundling a native module into a GitHub Action would commit a platform-specific
  binary that breaks on other runner OSes; the action therefore uses the in-memory
  store and its bundle is native-free.

## Tests

```bash
npm test        # 6 suites, 49 assertions
```

- `differ.test.js` — blob-SHA diff, workspace false-positive fix, real-attack
  detection, truncated-tree handling, content-suspect detection.
- `cargo-lock.test.js` — lockfile parser (registry vs git/local, CRLF, alt registries).
- `ci-diff.test.js` — CI added-package diff parsing.
- `units.test.js` — severity model, allowlist suppression, SARIF shape, diff algorithm.
- `hosts.test.js` — GitHub / GitLab (paginated) / Gitea-Codeberg providers, rate-limit handling.
- `integration.test.js` — **fully offline** end-to-end: a local mock server serves
  crates.io / static CDN / GitHub (with real blob SHAs), real `.crate` tarballs are
  built on the fly, and every detection (`BUILD_RS_INJECTED`, `BUILD_RS_MODIFIED`,
  `SOURCE_MODIFIED`, `FILE_NOT_IN_GIT`, `BINARY_NOT_IN_GIT`, `CHECKSUM_MISMATCH`,
  `YANKED`, `TRUSTED_PUBLISH`, `VCS_MISMATCH`, exact-commit + `path_in_vcs`
  resolution, workspace resolution, allowlist) is asserted.
