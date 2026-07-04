---
title: Terraform
description: Caching proxy for the Terraform registry — Registry + Network Mirror protocols.
---

The Terraform registry provides a transparent caching proxy for [registry.terraform.io](https://registry.terraform.io). NORA serves two complementary protocols from a single mount: the standard Registry Protocol (provider/module metadata and download URL rewriting) and the Network Mirror Protocol (version index and signed archive distribution).

## Client Configuration

Configure Terraform to install providers through the NORA network mirror. Add to `~/.terraformrc`:

```hcl
provider_installation {
  network_mirror {
    url = "https://nora.example.com/terraform/"
  }
}
```

> **Note:** Terraform requires the network mirror URL to use `https:` and end with a trailing slash.

To install a provider directly using the Registry Protocol (without a `~/.terraformrc` change), point `TERRAFORM_REGISTRY_DISCOVERY_RETRY` at NORA or configure a custom hostname alias in your provider source:

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
```

Then rely on the `~/.terraformrc` network mirror block above to redirect downloads.

## Upstream Proxy

By default, NORA proxies to the public Terraform registry (`https://registry.terraform.io`). To use a private or air-gapped registry:

```bash
export NORA_TF_PROXY=https://registry.internal.example.com
export NORA_TF_PROXY_AUTH=user:password
```

NORA rewrites all `download_url` fields in provider metadata responses and all archive URLs in mirror index responses to point through itself, so clients always download through the proxy.

## Features

| Feature | Status | Notes |
|---------|--------|-------|
| Provider version listing | Full | Registry Protocol |
| Provider download URL rewriting | Full | Proxied binary served via NORA |
| Provider binary caching | Full | Immutable on first download |
| Module version listing | Full | Registry Protocol |
| Module download redirect | Full | `X-Terraform-Get` rewritten |
| Network Mirror index | Full | `index.json` per provider |
| Network Mirror archives | Full | `{version}.json` with `zh:` hashes |
| Provider/module publish | -- | Proxy-only (read) |

**Environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `NORA_TF_ENABLED` | Enable Terraform registry | `false` |
| `NORA_TF_PROXY` | Upstream registry URL | `https://registry.terraform.io` |
| `NORA_TF_PROXY_AUTH` | Upstream auth (`user:pass`) | *(none)* |
| `NORA_TF_PROXY_TIMEOUT` | Proxy timeout in seconds (metadata) | `30` |
| `NORA_TF_PROXY_TIMEOUT_DL` | Proxy timeout in seconds (binary download) | `120` |
| `NORA_TF_METADATA_TTL` | Metadata cache TTL in seconds | `300` |
| `NORA_TF_SERVE_STALE` | Serve cached metadata when upstream is unreachable | `true` |

**config.toml:**

```toml
[terraform]
enabled = true
proxy = "https://registry.terraform.io"
# proxy_auth = "user:pass"
proxy_timeout = 30
proxy_timeout_dl = 120
metadata_ttl = 300
serve_stale = true
```

## Endpoints

### Registry Protocol

| Path | Method | Description |
|------|--------|-------------|
| `/terraform/.well-known/terraform.json` | GET | Service discovery |
| `/terraform/v1/providers/{ns}/{type}/versions` | GET | Provider version list |
| `/terraform/v1/providers/{ns}/{type}/{ver}/download/{os}/{arch}` | GET | Provider download metadata (`download_url` rewritten to NORA) |
| `/terraform/v1/providers/download/{*path}` | GET | Provider binary (immutable cache) |
| `/terraform/v1/modules/{ns}/{name}/{provider}/versions` | GET | Module version list |
| `/terraform/v1/modules/{ns}/{name}/{provider}/{ver}/download` | GET | Module download redirect (`X-Terraform-Get`) |
| `/terraform/v1/modules/download/{ns}/{name}/{provider}/{ver}/source` | GET | Module source archive |

### Network Mirror Protocol

| Path | Method | Description |
|------|--------|-------------|
| `/terraform/{hostname}/{ns}/{type}/index.json` | GET | Available versions for a provider |
| `/terraform/{hostname}/{ns}/{type}/{version}.json` | GET | Archive URLs and `zh:` SHA-256 hashes |

## Caching Behavior

- **Metadata** (provider/module version lists, download metadata, mirror index): TTL-cached for `NORA_TF_METADATA_TTL` seconds (default 300). Stale entries are served when upstream is unreachable and `NORA_TF_SERVE_STALE=true`.
- **Binaries and source archives**: cached on first download with `Cache-Control: public, max-age=31536000, immutable`. Subsequent requests are served from local storage without contacting upstream.

## Known Limitations

- Single upstream only: the `{hostname}` path segment in a Network Mirror request is validated but not routed. Only providers available from the configured `NORA_TF_PROXY` upstream will resolve correctly.
- In Network Mirror mode, Terraform skips the origin-registry GPG signature check. NORA does not verify `SHA256SUMS.sig` at ingest time — archives carry a `zh:` SHA-256 hash for integrity. Upgrade path: verify the signed `SHA256SUMS` file at ingest and store the result as a contract.
- Provider and module publish are not supported. Use `terraform registry push` directly against the upstream registry.
