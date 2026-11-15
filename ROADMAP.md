# Roadmap

This is the public roadmap for NORA Community Edition.
Versions and scope may change based on community feedback and real-world usage.

## Next — 1.5.0

- **Explicit curation mode** — with a proxy registry enabled, NORA stops at startup unless `curation.mode` is set (`off`, `audit` or `enforce`); 1.4.0 warns about it ([#1135](https://github.com/getnora-io/nora/issues/1135)).
- **One definition of an artifact count** — the dashboard, `/api/ui/stats` and the `nora_artifacts_total` metric count the same thing ([#1135](https://github.com/getnora-io/nora/issues/1135)).

## Planned

- **Image signing policy** — cosign verification on upstream pulls.
- **Semver contract** — stable API, configuration format and storage layout.
- **`nora integrity verify`** — check every stored artifact against its pinned hash.
- **Batch migration** — from Nexus, Artifactory and GitLab registries, beyond the one-shot `nora import` ([#172](https://github.com/getnora-io/nora/issues/172)).
- **Windows binary** ([#210](https://github.com/getnora-io/nora/issues/210)).
- **npm search API** — full-text search across cached packages.

## Shipped

Highlights per release; [CHANGELOG.md](CHANGELOG.md) has every change.

- **v1.4.1** — registry answers are inert in a browser; a ranged answer serves the version its headers describe; a write without a digest leaves no stale pin
- **v1.4.0** — published Cargo crates, npm packages and pushed Docker tags are never answered by an upstream; `-` and `_` name one crate; Hugging Face Hub proxy; reproducible builds
- **v1.3.6** — token minting bound to the caller's authority; raw downloads served inert
- **v1.3.5** — curation and internal namespaces judge every name and version the way its format resolves it
- **v1.3.4** — npm upstreams by scope, per-upstream circuit breakers, unknown configuration keys reported
- **v1.3.3** — one upstream fetch per Docker layer, large layers through slow links, package upgrades that restart the service
- **v1.3.2** — CPAN proxy, Docker blobs streamed while they are fetched
- **v1.2.0** — resumable downloads for every format, Docker cross-repo blob mount
- **v1.1.0** — rpm/deb pull-through proxy and offline mirror, per-rule OIDC namespace scope
- **v1.0.1** — Google Cloud Storage backend, structured APT layout, rpm/deb reindex
- **v1.0.0** — RPM and Debian/APT registries, signed repository indexes, `nora import` from Artifactory and Nexus
- **v0.9.5** — first-seen digest quarantine across all proxy registries, release age with trusted upstream dates, token access-control hardening ([#213](https://github.com/getnora-io/nora/issues/213))
- **v0.9.4** — multi-upstream PyPI, conditional-request revalidation, single-flight coalescing, per-registry metrics, dual-stack bind, Docker Range pulls
- **v0.9.3** — security hardening, null-byte protection, configuration refactor
- **v0.9.2** — Prometheus metrics, Ansible Galaxy v3
- **v0.9.1** — NuGet V3 stabilization, Cargo ETag
- **v0.9.0** — circuit breaker, OIDC, hot reload, arm64, streaming uploads, Docker namespacing, metadata TTL
- **v0.8.3** — outbound HTTP/SOCKS5 proxy, structured audit log
- **v0.8.0** — hash pin store, auth rate limiting, trusted proxies, Cache-Control
- **v0.7.3** — Docker auth fix, raw directory browser, version consistency gate
- **v0.7.1** — minimum-release-age filter
- **v0.7.0** — 13 registry formats, declarative registry selection, curation layer
- **v0.6.4** — signed releases and SBOM
- **v0.6.1** — Helm chart
- **v0.6.0** — retention policies, garbage collection, Maven immutability
- **v0.5.0** — full Cargo and PyPI registries (sparse index, twine upload)
- **v0.4.0** — `nora mirror` for lockfile-based prefetch

## How to Influence the Roadmap

Open an [issue](https://github.com/getnora-io/nora/issues) or join the [Telegram community](https://t.me/getnora).
Feature priority is driven by real production use cases.
