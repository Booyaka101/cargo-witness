# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in cargo-witness, please report it
privately so it can be addressed before public disclosure.

Preferred method:

- Open a private [security advisory](https://github.com/Booyaka101/cargo-witness/security/advisories/new)
  on the GitHub repository.

Alternatively:

- Email **security@example.com** with a description of the issue, the affected
  version, and steps to reproduce.

Please do **not** open a public issue for security reports.

We aim to acknowledge reports within a few business days and will keep you
informed of progress toward a fix. When a fix is released, we are happy to
credit reporters who wish to be named.

## Supported Versions

Security fixes are provided for the following release lines:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Scope

cargo-witness is a **detection aid, not a guarantee**. It flags divergences
between a published crate artifact (from `static.crates.io`) and the crate's
git source, surfacing patterns commonly associated with supply-chain tampering
(for example, an injected or modified `build.rs`, files or binaries present only
in the artifact, or a checksum mismatch).

Because the tool reasons about the difference between two sources, false
negatives are possible. Notably:

- If a repository has **no matching git tag** for a published version, the tool
  cannot establish a trusted baseline to diff against, and tampering may go
  undetected.
- If the **git source itself is compromised**, a malicious artifact may match
  its (also malicious) source and produce no finding.
- Detection depends on the availability and accuracy of upstream data from
  crates.io and GitHub.

A clean result from cargo-witness should be treated as one signal among many,
not as proof that a dependency is safe. Use it alongside other supply-chain
controls such as pinning, review, and provenance verification.
