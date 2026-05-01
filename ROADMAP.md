# Roadmap

This is the public roadmap for NORA Community Edition.
Versions and scope may change based on community feedback and real-world usage.

For completed milestones, see [CHANGELOG.md](CHANGELOG.md).

## Completed

- **v0.4.0** — `nora mirror` CLI for lockfile-based prefetch
- **v0.5.0** — Full Cargo and PyPI registries (sparse index, twine upload)
- **v0.6.0** — Retention policies, garbage collection, Maven immutability
- **v0.7.0** — 13 registry formats, declarative registry selection, curation layer
- **v0.7.1** — Min-release-age filter for supply chain protection
- **v0.7.3** — Circuit breaker for upstream proxies, version consistency gate

## v0.8 — Integrity & Hardening

Focus: supply chain integrity, platform coverage, security hardening.

- **Hash Pin Store** — immutable hash verification for stored artifacts. Detect tampering at the storage level. ([design](ARCHITECTURE.md))
- **Auth rate limiting** — per-IP throttling on failed authentication attempts
- **Publish date extraction** — extend min-release-age to all 13 registry formats (currently: npm, PyPI, Cargo, Go)
- **Metadata cleanup** — automatic removal of metadata entries with zero versions
- **arm64 support** — Linux arm64 binary and multi-arch Docker image ([#193](https://github.com/getnora-io/nora/issues/193))
- **Token UI auth fix** — token management requires authentication regardless of anonymous_read setting ([#221](https://github.com/getnora-io/nora/issues/221))

## v0.9 — Enterprise Auth

Focus: production-grade authentication for CI/CD pipelines and corporate environments.

- **OIDC / Workload Identity** — zero-secret auth for GitHub Actions and GitLab CI JWT
- **Hot reload** — apply curation policy and configuration changes without restart
- **Audit log to stdout** — structured JSON logs for multi-replica deployments and SIEM integration ([#175](https://github.com/getnora-io/nora/issues/175))

## v1.0 — Stability

Focus: API stability guarantee and production confidence.

- **Semver contract** — stable API, configuration format, and storage layout
- **`nora integrity verify`** — CLI command to verify all stored artifacts against pinned hashes
- **Migration guide** — upgrade path from any v0.x release
- **Digest quarantine** — age-based hold for newly pushed Docker images ([#213](https://github.com/getnora-io/nora/issues/213))

## Post-1.0

These features are planned but not targeted for the initial stable release:

- **deb/rpm package repository** ([#128](https://github.com/getnora-io/nora/issues/128), [#209](https://github.com/getnora-io/nora/issues/209))
- **`nora-migrate` CLI** — batch migration from Nexus, Artifactory, GitLab registries ([#172](https://github.com/getnora-io/nora/issues/172))
- **Image signing policy** — cosign verification on upstream pulls
- **Windows binary** ([#210](https://github.com/getnora-io/nora/issues/210))
- **Docker min-release-age** — age-based filtering for container images
- **npm search API** — full-text search across cached packages

## How to Influence the Roadmap

Open an [issue](https://github.com/getnora-io/nora/issues) or join the [Telegram community](https://t.me/getnora).
Feature priority is driven by real production use cases.
