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
- **v0.7.3** — Docker auth fix, raw directory browser, version consistency gate
- **v0.8.0** — Hash Pin Store, auth rate limiting, trusted proxies, Cache-Control
- **v0.8.3** — Outbound HTTP/SOCKS5 proxy, structured audit log, 994 tests
- **v0.9.0** — Circuit breaker, OIDC, hot reload, arm64, streaming uploads, Docker namespacing, metadata TTL, Cache-Control completeness
- **v0.9.4** — Conditional-request revalidation, single-flight coalescing, per-registry observability, dual-stack IPv4+IPv6 bind, Docker Range pulls
- **v0.9.5** — First-seen digest quarantine across all 11 proxy registries, release-age with trusted upstream dates, token access-control and Docker quarantine-bypass hardening ([#213](https://github.com/getnora-io/nora/issues/213))

## v1.0 — Stability

Focus: API stability guarantee and production confidence.

- **Semver contract** — stable API, configuration format, and storage layout
- **`nora integrity verify`** — CLI command to verify all stored artifacts against pinned hashes
- **Migration guide** — upgrade path from any v0.x release

## Post-1.0

These features are planned but not targeted for the initial stable release:

- **deb/rpm package repository** ([#128](https://github.com/getnora-io/nora/issues/128), [#209](https://github.com/getnora-io/nora/issues/209))
- **`nora-migrate` CLI** — batch migration from Nexus, Artifactory, GitLab registries ([#172](https://github.com/getnora-io/nora/issues/172))
- **Image signing policy** — cosign verification on upstream pulls
- **Windows binary** ([#210](https://github.com/getnora-io/nora/issues/210))
- **npm search API** — full-text search across cached packages

## How to Influence the Roadmap

Open an [issue](https://github.com/getnora-io/nora/issues) or join the [Telegram community](https://t.me/getnora).
Feature priority is driven by real production use cases.
