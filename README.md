# NORA

**One binary, seventeen package formats, no database.** NORA is a self-hosted artifact registry and pull-through cache for Docker, Maven, npm, PyPI, Cargo, Go and more, with supply-chain controls built in.

[![Release](https://img.shields.io/github/v/release/getnora-io/nora)](https://github.com/getnora-io/nora/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/getnora/nora)](https://hub.docker.com/r/getnora/nora)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/nora)](https://artifacthub.io/packages/helm/nora/nora)
[![CI](https://img.shields.io/github/actions/workflow/status/getnora-io/nora/ci.yml?label=CI)](https://github.com/getnora-io/nora/actions)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/getnora-io/nora/badge)](https://scorecard.dev/viewer/?uri=github.com/getnora-io/nora)
[![CII Best Practices](https://www.bestpractices.dev/projects/12207/badge)](https://www.bestpractices.dev/projects/12207)
[![Docs](https://img.shields.io/badge/docs-getnora.dev-green)](https://getnora.dev)
[![Telegram](https://img.shields.io/badge/Telegram-community-blue?logo=telegram)](https://t.me/getnora)

```bash
docker run -d -p 4000:4000 -v nora-data:/data getnora/nora:latest
```

Open [http://localhost:4000/ui/](http://localhost:4000/ui/): the registry is ready.

<p align="center">
  <img src=".github/assets/dashboard.png" alt="NORA dashboard" width="960" />
</p>

## Why NORA

- **Small and quick to start.** A static binary of about 23 MB with no database and no runtime to install; it answers in under a second and idles at about 15 MB of memory ([BENCHMARKS.md](BENCHMARKS.md)).
- **Seventeen formats, hosted and proxied.** One registry for containers, language packages, OS packages and Hugging Face models, on local disk, S3-compatible storage or Google Cloud Storage.
- **What you publish stays yours.** A package, crate or image published to NORA is never replaced by an upstream package of the same name. Curation — allowlist, blocklist, minimum release age, quarantine of new versions, internal namespaces — decides what reaches your builds.
- **Ready to operate.** A web UI in English, Russian and Chinese, API tokens with read, write and admin roles, keyless publishing from GitHub Actions and GitLab CI with OIDC, rate limits, an audit log and Prometheus metrics.
- **Works without the internet.** `nora mirror` prefetches what your lockfiles name for air-gapped networks, `nora import` moves an Artifactory or Nexus repository in, and `nora backup` / `nora restore` keep a copy.

## Supported formats

| Format | Proxy & cache | Hosted |
|--------|:---:|:---:|
| Docker / OCI | ✅ | ✅ |
| Maven | ✅ | ✅ |
| npm | ✅ | ✅ |
| PyPI | ✅ | ✅ |
| Cargo | ✅ | ✅ |
| Go modules | ✅ | — |
| Raw files | — | ✅ |
| RubyGems | ✅ | — |
| Terraform | ✅ | — |
| Ansible Galaxy | ✅ | — |
| NuGet | ✅ | — |
| Pub (Dart, Flutter) | ✅ | — |
| Conan (C, C++) | ✅ | — |
| CPAN | ✅ | — |
| RPM (yum, dnf) | opt-in | ✅ |
| Debian / APT | opt-in | ✅ |
| Hugging Face Hub | opt-in | — |

Opt-in: the Hugging Face proxy (`NORA_HF_ENABLED=true`) and RPM/Debian pull-through (`[rpm.proxies]`, `[deb.proxies]`). Default upstreams, protocol coverage and client notes for each format: [COMPAT.md](COMPAT.md).

## Install

- **Docker:** `getnora/nora` on Docker Hub and `ghcr.io/getnora-io/nora` (amd64, arm64), with RED OS and Astra Linux SE variants (`<version>-redos`, `<version>-astra`).
- **Kubernetes:** `helm repo add nora https://getnora-io.github.io/helm-charts && helm install nora nora/nora` ([Helm guide](https://getnora.dev/deployment/helm/)).
- **Binary, `.deb` / `.rpm` packages, from source:** [installation guide](https://getnora.dev/getting-started/installation/).

Upgrading: [upgrade guide](https://getnora.dev/deployment/upgrade-guide/).

## Use

```bash
# Docker
docker tag myapp:latest localhost:4000/myapp:latest
docker push localhost:4000/myapp:latest

# npm
npm config set registry http://localhost:4000/npm/

# pip
pip install --index-url http://localhost:4000/simple/ requests
```

Every format has its own page with client setup, publishing and proxy options: [registries](https://getnora.dev/registries/docker/).

## Configure

NORA reads environment variables or a `config.toml`. A registry that proxies upstream packages should say how they are checked:

```bash
NORA_CURATION_MODE=enforce NORA_CURATION_MIN_RELEASE_AGE=7d \
NORA_CURATION_QUARANTINE=enforce \
  docker run -d -p 4000:4000 -v nora-data:/data getnora/nora:latest
```

All settings: [configuration reference](https://getnora.dev/configuration/settings/), [curation](https://getnora.dev/configuration/curation/), [authentication](https://getnora.dev/configuration/authentication/), [S3 storage](https://getnora.dev/configuration/s3-storage/). Metrics and dashboards: [MONITORING.md](MONITORING.md).

## Security

Releases are signed with cosign and ship SBOMs (SPDX, CycloneDX) and SLSA provenance. Advisories are published on [GitHub](https://github.com/getnora-io/nora/security/advisories); report a vulnerability as described in [SECURITY.md](SECURITY.md).

## Roadmap

Next is 1.5.0: an explicit `curation.mode` whenever a proxy registry is enabled, and one definition of an artifact count across the dashboard, the API and the metrics. See [ROADMAP.md](ROADMAP.md) and [CHANGELOG.md](CHANGELOG.md).

## Ecosystem

- [**Dozor**](https://github.com/getnora-io/dozor) compiles the OSV advisory feed and an inventory of your registry into a curation blocklist that NORA enforces.
- [**Helm chart**](https://github.com/getnora-io/helm-charts) for Kubernetes.

## Community

Questions and ideas: [Telegram](https://t.me/getnora) and [issues](https://github.com/getnora-io/nora/issues). Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [GOVERNANCE.md](GOVERNANCE.md).

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 The NORA Authors.
