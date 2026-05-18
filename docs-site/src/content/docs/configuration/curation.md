---
title: Curation
description: Configure package access control with blocklists, allowlists, release age quarantine, and hot reload
---


Curation lets you control which packages can be installed through NORA. Use it to block known-malicious packages, enforce an allowlist of approved dependencies, quarantine new releases, or isolate internal namespaces.

---

## Modes

Curation has three modes:

| Mode | Behavior |
|------|----------|
| `off` | No curation checks (default) |
| `audit` | Check all packages, log violations, but allow all requests |
| `enforce` | Check all packages, block violations with 403 |

```bash
export NORA_CURATION_MODE="enforce"
```

```toml
[curation]
mode = "enforce"
```

:::tip
Start with `audit` mode to observe what would be blocked before switching to `enforce`. Check your logs for `curation_violation` events.
:::

---

## Blocklist

A blocklist blocks specific packages by name, version, or pattern. Create a JSON file:

```json
[
  {
    "registry": "npm",
    "name": "event-stream",
    "reason": "Known supply-chain attack (CVE-2018-16492)"
  },
  {
    "registry": "npm",
    "name": "colors",
    "versions": [">=1.4.1"],
    "reason": "Intentional sabotage in 1.4.1+"
  },
  {
    "registry": "pypi",
    "name": "jeIlyfish",
    "reason": "Typosquat of jellyfish"
  }
]
```

Configure the path:

```bash
export NORA_CURATION_BLOCKLIST_PATH="/etc/nora/blocklist.json"
```

```toml
[curation]
blocklist_path = "/etc/nora/blocklist.json"
```

---

## Allowlist

An allowlist restricts installations to only approved packages. When an allowlist is active, any package not on the list is blocked.

```json
[
  {
    "registry": "npm",
    "name": "express"
  },
  {
    "registry": "npm",
    "name": "lodash",
    "versions": ["4.17.21"]
  },
  {
    "registry": "pypi",
    "name": "requests",
    "integrity": "sha256:abcdef1234567890..."
  }
]
```

```bash
export NORA_CURATION_ALLOWLIST_PATH="/etc/nora/allowlist.json"
```

When `require_integrity` is enabled, allowlist entries must include an `integrity` field that matches the package checksum:

```toml
[curation]
allowlist_path = "/etc/nora/allowlist.json"
require_integrity = true
```

---

## On-Failure Behavior

When a curation filter encounters an error (e.g., corrupted blocklist, I/O failure), the `on_failure` setting determines what happens:

| Value | Behavior |
|-------|----------|
| `closed` | Block the request (fail-safe, default) |
| `open` | Allow the request (fail-open) |

```toml
[curation]
on_failure = "closed"
```

:::caution
`open` mode means a broken filter silently allows all packages. Use `closed` in production unless you have a specific reason to prefer availability over security.
:::

---

## Hot Reload with SIGHUP

NORA supports reloading curation policy without restarting:

```bash
kill -HUP $(pgrep nora)
```

SIGHUP reloads:
- Curation mode, blocklist, and allowlist files
- Bypass token

SIGHUP does **not** reload:
- Server settings (host, port, public_url)
- Authentication configuration
- Storage configuration
- Registry enable/disable flags

On reload failure, the previous configuration is preserved and an error is logged.

---

## Bypass Token

For emergency access when curation is blocking a critical package, set a bypass token:

```bash
export NORA_CURATION_BYPASS_TOKEN="emergency-token-keep-secret"
```

Clients pass the token in the `X-Nora-Bypass` header:

```bash
# npm
npm install express --registry http://nora:4000/npm/ \
  --header "X-Nora-Bypass: emergency-token-keep-secret"
```

:::danger[Security]
The bypass token skips all curation checks. Treat it like a root password -- store it in a secrets manager and rotate it after use. Never put it in `config.toml`.
:::

---

## Internal Namespaces

Packages matching internal namespace patterns skip curation checks entirely. This is a security boundary -- internal packages are never proxied upstream regardless of curation mode.

```toml
[curation]
internal_namespaces = ["@mycompany/**", "com.mycompany.**"]
```

```bash
export NORA_CURATION_INTERNAL_NS="@mycompany/**,com.mycompany.**"
```

---

## Minimum Release Age Quarantine

Block packages that were published less than a configurable duration ago. This gives the community time to detect supply-chain attacks before your builds pull new releases.

```toml
[curation]
min_release_age = "7d"    # global default

# Per-registry overrides
[curation.npm]
min_release_age = "3d"

[curation.pypi]
min_release_age = "14d"
```

Supported duration formats: `12h`, `3d`, `1w`, `2w`.

```bash
export NORA_CURATION_MIN_RELEASE_AGE="7d"
export NORA_CURATION_NPM_MIN_RELEASE_AGE="3d"
```

---

## Full config.toml Example

```toml
[curation]
mode = "enforce"
on_failure = "closed"
blocklist_path = "/etc/nora/blocklist.json"
allowlist_path = "/etc/nora/allowlist.json"
# bypass_token = ""  # prefer NORA_CURATION_BYPASS_TOKEN env var
require_integrity = false
internal_namespaces = ["@mycompany/**", "com.mycompany.**"]
min_release_age = "7d"

[curation.npm]
min_release_age = "3d"

[curation.pypi]
min_release_age = "14d"
```

---

## See Also

- [Settings](/configuration/settings/) -- complete environment variable reference
- [Authentication](/configuration/authentication/) -- user management and access control
- [Production Deployment](/deployment/production/) -- production deployment guide
