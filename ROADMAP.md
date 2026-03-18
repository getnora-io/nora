# Roadmap

> This roadmap reflects current priorities. It may change based on community feedback.

## Recently Completed

- **v0.2.32** — Docker dashboard fix for namespaced images, `library/` auto-prepend for Hub official images
- **v0.2.31** — npm full proxy (URL rewriting, scoped packages, publish, SHA-256 integrity cache, metadata TTL)
- **v0.2.29** — Upstream authentication for all protocols (Docker, Maven, npm, PyPI)

## In Progress

- **`nora mirror`** — Pre-fetch dependencies from lockfiles for air-gapped environments ([#40](https://github.com/getnora-io/nora/issues/40))
  - npm: `package-lock.json` (v1/v2/v3)
  - pip: `requirements.txt`
  - cargo: `Cargo.lock`
  - maven: dependency list

## Next Up

- **Consistent env var naming** — Unify `NORA_*_PROXY` / `NORA_*_UPSTREAMS` across all protocols ([#39](https://github.com/getnora-io/nora/issues/39))
- **Package blocklist** — Deny specific packages or versions via config ([#41](https://github.com/getnora-io/nora/issues/41))
- **Multiple upstreams for npm/PyPI** — Same as Maven already supports
- **v1.0.0 release** — Stable API, production-ready

## Future

- Docker image mirroring ([#42](https://github.com/getnora-io/nora/issues/42))
- Virtual repositories via config (named endpoints with custom search order)
- Path-based ACL (per-namespace write permissions)
- OIDC/LDAP authentication
- HA mode (stateless API + external database)
- Golang modules proxy
- Content trust (Cosign/Notation verification)

## How to Influence

Open an issue or join [Telegram](https://t.me/getnora) to discuss priorities.
