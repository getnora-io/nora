# Governance

NORA uses a **Benevolent Dictator For Life (BDFL)** governance model.
This document describes how decisions are made, how releases are shipped, and how breaking changes are handled.

For contributor roles and responsibilities, see [CONTRIBUTING.md](CONTRIBUTING.md).
For vulnerability reporting, see [SECURITY.md](SECURITY.md).

## Decision Process

### Architecture

Architectural decisions are recorded as ADRs in [ARCHITECTURE.md](ARCHITECTURE.md).
ADRs document the context, decision, and consequences of significant technical choices.
New ADRs are proposed via pull request and require maintainer approval.

### Features

Feature requests and design discussions happen in [GitHub Issues](https://github.com/getnora-io/nora/issues).
Community feedback from the [Telegram group](https://t.me/getnora) is triaged into issues before implementation.
The maintainer makes final decisions on scope and priority.

### Breaking Changes

NORA follows [Semantic Versioning](https://semver.org/):

- **Pre-1.0** — breaking changes may occur in minor versions with a CHANGELOG entry
- **Post-1.0** — breaking changes require:
  1. Deprecation notice in a minor release
  2. Minimum one minor version cycle before removal
  3. Migration guide in release notes

Configuration variables, CLI flags, and API endpoints are all covered by this policy.

## Release Process

Every release passes through four gates:

| Gate | What runs | Blocks |
|------|-----------|--------|
| **Pre-commit** | `cargo fmt`, `cargo clippy`, version consistency check | Commit |
| **Pre-push** | Full test suite, `cargo-deny` | Push |
| **CI** | 12 parallel jobs (lint, test, clippy, security audit, semver-checks, CodeQL, integration) | Merge |
| **Release** | Version gate (Cargo.toml = OpenAPI = Cargo.lock = git tag), build + sign + SBOM | Publish |

Releases are signed with [cosign](https://github.com/sigstore/cosign) and include SBOM in CycloneDX and SPDX formats.

Only the maintainer can trigger a release by pushing a version tag.

## Versioning

The [version gate script](scripts/pre-commit-check.sh) enforces consistency:

- `Cargo.toml` version = OpenAPI spec version = `Cargo.lock` version
- Git tag must match on release
- CI fails immediately on mismatch

## Communication

| Channel | Purpose |
|---------|---------|
| [GitHub Issues](https://github.com/getnora-io/nora/issues) | Bugs, feature requests, design discussions |
| [Telegram @getnora](https://t.me/getnora) | Community chat, quick questions |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [getnora.dev](https://getnora.dev) | Documentation |

## Project Continuity

The [getnora-io](https://github.com/getnora-io) GitHub organization has multiple admin accounts.
Source code is MIT-licensed, enabling anyone to fork and continue the project independently.
