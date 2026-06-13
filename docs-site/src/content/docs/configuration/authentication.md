---
title: Authentication
description: Configure authentication, OIDC workload identity, API tokens, and access control in NORA
---


NORA supports multiple authentication methods: htpasswd-based credentials, OIDC workload identity (for CI/CD systems), and API tokens. Authentication is disabled by default and must be explicitly enabled.

---

## Enabling Authentication

Set the `NORA_AUTH_ENABLED` environment variable or configure it in `config.toml`:

```bash
# Environment variable
export NORA_AUTH_ENABLED=true
```

```toml
# config.toml
[auth]
enabled = true
htpasswd_file = "users.htpasswd"
token_storage = "data/tokens"
```

---

## htpasswd Setup

NORA uses Apache-compatible htpasswd files for user management. Create a password file using `htpasswd` (from `apache2-utils`) or any compatible tool:

### Creating the htpasswd file

```bash
# Install htpasswd (Debian/Ubuntu)
apt-get install apache2-utils

# Create file with first user
htpasswd -Bc users.htpasswd admin

# Add additional users
htpasswd -B users.htpasswd developer
htpasswd -B users.htpasswd ci-bot
```

The `-B` flag uses bcrypt hashing, which is the recommended algorithm.

### Mount the file

**Docker:**

```bash
docker run -d \
  --name nora \
  -p 4000:4000 \
  -v /data/nora:/data \
  -v /etc/nora/users.htpasswd:/app/users.htpasswd:ro \
  -e NORA_AUTH_ENABLED=true \
  -e NORA_AUTH_HTPASSWD_FILE=/app/users.htpasswd \
  ghcr.io/getnora-io/nora:latest
```

**Kubernetes:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: nora-htpasswd
type: Opaque
stringData:
  users.htpasswd: |
    admin:$2y$05$...
    ci-bot:$2y$05$...
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nora
spec:
  template:
    spec:
      containers:
        - name: nora
          env:
            - name: NORA_AUTH_ENABLED
              value: "true"
            - name: NORA_AUTH_HTPASSWD_FILE
              value: /etc/nora/users.htpasswd
          volumeMounts:
            - name: htpasswd
              mountPath: /etc/nora
              readOnly: true
      volumes:
        - name: htpasswd
          secret:
            secretName: nora-htpasswd
```

---

## Anonymous Read Mode

When `NORA_AUTH_ANONYMOUS_READ=true`, unauthenticated users can pull/download artifacts, but authentication is still required for push/upload operations.

```bash
export NORA_AUTH_ENABLED=true
export NORA_AUTH_ANONYMOUS_READ=true
```

```toml
# config.toml
[auth]
enabled = true
anonymous_read = true
```

This is useful for organizations that want open read access (e.g., shared libraries) while restricting who can publish artifacts.

| Operation | Anonymous Read = false | Anonymous Read = true |
|-----------|----------------------|----------------------|
| Pull / Download | Auth required | No auth needed |
| Push / Upload | Auth required | Auth required |
| Delete / Admin | Auth required | Auth required |

---

## OIDC Workload Identity

NORA supports OIDC (OpenID Connect) workload identity for CI/CD systems like GitHub Actions and GitLab CI. This allows pipelines to authenticate without storing long-lived secrets -- the CI platform issues a short-lived JWT that NORA validates directly.

### How It Works

1. Your CI platform (GitHub Actions, GitLab CI) issues a short-lived OIDC token with claims identifying the workflow, repository, and branch.
2. The pipeline sends this token as a `Bearer` token to NORA.
3. NORA validates the JWT signature against the provider's JWKS endpoint, checks the issuer, audience, and lifetime, then maps the `sub` claim to a role via configured rules.

No static secrets are stored in your CI -- only the OIDC audience needs to be configured.

### Configuration

```toml
# config.toml
[auth]
enabled = true

[auth.oidc]
enabled = true
leeway_secs = 60          # Clock skew tolerance (default: 60)
jwks_cache_secs = 3600    # JWKS key cache TTL (default: 3600)

[[auth.oidc.providers]]
name = "github-actions"
issuer = "https://token.actions.githubusercontent.com"
audience = "nora"
algorithms = ["RS256", "ES256"]
max_token_lifetime_secs = 900
enabled = true

# Restrict this issuer to a namespace prefix (default ["*"] = unrestricted).
# Segment-aware globs: myorg/* = direct children, myorg/** = any depth.
namespace_scope = ["myorg/**"]
# "enforce" (default, 403 on out-of-scope writes) or "audit" (log + count only).
namespace_scope_enforcement = "enforce"

# Role rules: first match wins. Glob patterns on the `sub` claim.
[[auth.oidc.providers.role_rules]]
pattern = "repo:myorg/*:ref:refs/heads/main"
role = "write"

[[auth.oidc.providers.role_rules]]
pattern = "repo:myorg/*"
role = "read"
```

Environment variable override:

```bash
export NORA_AUTH_OIDC_ENABLED=true
```

### Namespace Scoping

`namespace_scope` restricts which artifact namespaces an issuer's tokens may **write** to. It applies to publish and delete (PUT/POST/DELETE) on the docker, raw, npm, maven, pypi, and cargo registries. Reads are never gated, and scoping applies to OIDC identities only — not API tokens or Basic auth.

The scope is matched against the artifact's **coordinate** (not the URL path), segment by segment:

| Registry | Coordinate matched | Example scope |
|----------|--------------------|---------------|
| docker   | image name (`myorg/app`)          | `myorg/**` |
| raw      | object path (`myorg/sub/file`)    | `myorg/**` |
| npm      | package incl. scope (`@myorg/pkg`) | `@myorg/**` |
| maven    | groupId/artifactId (`com/myorg/lib`) | `com/myorg/**` |
| pypi     | normalized project name (`myproj`) | `myproj` |
| cargo    | crate name (`mycrate`)            | `mycrate` |

Matching is anchored on `/` boundaries: `*` matches exactly one segment and `**` matches zero or more. So `myorg/*` matches `myorg/app` but **not** `myorg-evil/app` and **not** `myorg/team/app` — use `myorg/**` for nested paths. The default `["*"]` disables scoping; an empty list `[]` denies all writes (a deliberate lockout). pypi and cargo have flat namespaces (no `/`), so scope them by exact name or use `**`.

A write outside the scope returns `403 Forbidden`.

> **Upgrade note:** until this release, `namespace_scope` was accepted but never enforced. If you already set it to something other than `["*"]`, this version will start returning 403 for out-of-scope writes — review your config before upgrading. To stage the change, set `namespace_scope_enforcement = "audit"`: out-of-scope writes are allowed but logged and counted via the `nora_auth_namespace_scope_total{provider,decision="would_deny"}` metric. Switch back to `"enforce"` once the metric is clean.

### GitHub Actions Setup

1. Configure NORA with the GitHub OIDC issuer (as shown above).
2. Add the `id-token: write` permission to your workflow.
3. Use the token directly -- no secrets needed.

```yaml
name: Publish to NORA
on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Get OIDC Token
        id: oidc
        run: |
          TOKEN=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=nora" | jq -r '.value')
          echo "::add-mask::$TOKEN"
          echo "token=$TOKEN" >> "$GITHUB_OUTPUT"

      - name: Push to NORA
        run: |
          # Docker
          echo "${{ steps.oidc.outputs.token }}" | \
            docker login registry.example.com -u oidc --password-stdin
          docker push registry.example.com/myapp:${{ github.sha }}

          # Or npm
          echo "//registry.example.com/:_authToken=${{ steps.oidc.outputs.token }}" > .npmrc
          npm publish
```

### GitLab CI Setup

```toml
# config.toml
[[auth.oidc.providers]]
name = "gitlab-ci"
issuer = "https://gitlab.com"   # or your self-hosted GitLab URL
audience = "nora"
algorithms = ["RS256"]
max_token_lifetime_secs = 300
enabled = true

[[auth.oidc.providers.role_rules]]
pattern = "project_path:mygroup/*:ref_type:branch:ref:main"
role = "write"

[[auth.oidc.providers.role_rules]]
pattern = "project_path:mygroup/*"
role = "read"
```

```yaml
# .gitlab-ci.yml
publish:
  image: docker:latest
  id_tokens:
    NORA_TOKEN:
      aud: nora
  script:
    - echo "$NORA_TOKEN" | docker login $NORA_REGISTRY -u oidc --password-stdin
    - docker push $NORA_REGISTRY/myapp:$CI_COMMIT_SHA
```

### Role Rules

Role rules use glob patterns matched against the JWT `sub` claim. The first matching rule wins.

| Pattern | Matches |
|---------|---------|
| `repo:myorg/*:ref:refs/heads/main` | Any repo in myorg, main branch only |
| `repo:myorg/*` | Any repo in myorg, any branch |
| `repo:myorg/app:*` | Specific repo, any ref |
| `*` | Everything (catch-all) |

Available roles: `read`, `write`, `admin`.

### Security Properties

- **Algorithm whitelist**: Only RS256 and ES256 by default. Symmetric algorithms (HS256/HS384/HS512) are always rejected.
- **Strict issuer binding**: NORA never follows `jku`/`x5u` headers from the token. Keys are always fetched from the configured issuer URL.
- **Token lifetime ceiling**: Tokens with `exp - iat` exceeding `max_token_lifetime_secs` are rejected, even if not yet expired.
- **Stale JWKS fallback**: If JWKS refresh fails (network issue), NORA serves stale cached keys to maintain availability.
- **Per-provider kill switch**: Disable a provider instantly with `enabled = false` without removing its configuration.

### Multiple Providers

You can configure multiple OIDC providers simultaneously:

```toml
[[auth.oidc.providers]]
name = "github-actions"
issuer = "https://token.actions.githubusercontent.com"
audience = "nora"
# ...

[[auth.oidc.providers]]
name = "gitlab-ci"
issuer = "https://gitlab.example.com"
audience = "nora"
# ...
```

NORA routes each token to the correct provider based on the `iss` claim.

---

## API Tokens

API tokens provide programmatic access without exposing htpasswd credentials. Tokens are prefixed with `nra_` for easy identification and use Argon2 hashing.

### Token Roles

| Role | Permissions |
|------|------------|
| `read` | Pull and download artifacts only |
| `write` | Pull, push, and download artifacts |
| `admin` | Full access including token management |

### Creating a Token

```bash
curl -X POST http://localhost:4000/api/tokens \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-password",
    "role": "write",
    "ttl_days": 90,
    "description": "CI/CD pipeline token"
  }'
```

Response:

```json
{
  "token": "nra_a1b2c3d4e5f6...",
  "expires_in_days": 90
}
```

Save the token value immediately -- it is only shown once at creation time.

### Listing Tokens

```bash
curl -X POST http://localhost:4000/api/tokens/list \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-password"
  }'
```

Response:

```json
{
  "tokens": [
    {
      "hash_prefix": "a1b2c3",
      "created_at": 1714200000,
      "expires_at": 1721976000,
      "last_used": 1714300000,
      "description": "CI/CD pipeline token",
      "role": "write"
    }
  ]
}
```

### Revoking a Token

Use the `hash_prefix` from the list response:

```bash
curl -X POST http://localhost:4000/api/tokens/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-password",
    "hash_prefix": "a1b2c3"
  }'
```

---

## Docker Login

NORA supports standard Docker authentication. When auth is enabled, use `docker login` before push/pull operations:

```bash
# Login with htpasswd credentials
docker login localhost:4000
# Username: admin
# Password: ****

# Login with API token (use token as password, any username)
docker login localhost:4000 -u token -p nra_a1b2c3d4e5f6...
```

For automated workflows, use `--password-stdin`:

```bash
echo "nra_a1b2c3d4e5f6..." | docker login localhost:4000 -u token --password-stdin
```

---

## CI/CD Integration

For CI/CD pipelines, prefer [OIDC Workload Identity](#oidc-workload-identity) over static API tokens when your CI platform supports it (GitHub Actions, GitLab CI). OIDC eliminates secret management entirely.

If OIDC is not available, use API tokens as shown below.

### GitHub Actions (with API Token)

```yaml
name: Build and Push
on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Login to NORA
        run: |
          echo "${{ secrets.NORA_TOKEN }}" | \
            docker login registry.example.com -u token --password-stdin

      - name: Build and Push
        run: |
          docker build -t registry.example.com/myapp:${{ github.sha }} .
          docker push registry.example.com/myapp:${{ github.sha }}
```

For non-Docker registries (npm, PyPI, Cargo, etc.), use the token in the appropriate client configuration:

```yaml
      # npm
      - name: Publish npm package
        env:
          NORA_TOKEN: ${{ secrets.NORA_TOKEN }}
        run: |
          echo "//registry.example.com/:_authToken=${NORA_TOKEN}" > .npmrc
          npm publish --registry=https://registry.example.com

      # PyPI (twine)
      - name: Publish Python package
        env:
          NORA_TOKEN: ${{ secrets.NORA_TOKEN }}
        run: |
          twine upload --repository-url https://registry.example.com/pypi/ \
            -u token -p "${NORA_TOKEN}" dist/*
```

### GitLab CI

```yaml
stages:
  - build
  - publish

variables:
  NORA_REGISTRY: registry.example.com

build:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - echo "$NORA_TOKEN" | docker login $NORA_REGISTRY -u token --password-stdin
  script:
    - docker build -t $NORA_REGISTRY/myapp:$CI_COMMIT_SHA .
    - docker push $NORA_REGISTRY/myapp:$CI_COMMIT_SHA

publish-maven:
  stage: publish
  image: maven:3.9
  script:
    - >
      mvn deploy
      -DaltDeploymentRepository=nora::https://${NORA_REGISTRY}/maven2
      -Dserver.username=token
      -Dserver.password=${NORA_TOKEN}
```

Store `NORA_TOKEN` as a masked CI/CD variable in GitLab project settings.

---

## Token Security Best Practices

1. **Use scoped tokens.** Create `read` tokens for pull-only workloads and `write` tokens only for pipelines that publish.
2. **Set TTL.** Always specify `ttl_days` when creating tokens. Rotate tokens regularly.
3. **Do not commit tokens.** Use CI/CD secrets (GitHub Secrets, GitLab CI Variables) to inject tokens at runtime.
4. **Revoke on compromise.** If a token is leaked, revoke it immediately using the API.
5. **Use anonymous read when possible.** If your artifacts are not sensitive, enable `NORA_AUTH_ANONYMOUS_READ=true` to reduce token management overhead.

---

## See Also

- [Configuration Reference](/configuration/settings/) -- all environment variables
- [Curation](/configuration/curation/) -- package access control
- [Production Deployment](/deployment/production/) -- TLS and proxy setup
- [GitHub OIDC documentation](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect) -- GitHub Actions OIDC setup
- [GitLab CI OIDC](https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html) -- GitLab CI/CD ID tokens
