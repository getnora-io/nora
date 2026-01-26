# NORA Roadmap / TODO

## v0.2.0 - DONE
- [x] Unit tests (75 tests passing)
- [x] Input validation (path traversal protection)
- [x] Rate limiting (brute-force protection)
- [x] Request ID tracking
- [x] Migrate command (local <-> S3)
- [x] Error handling (thiserror)
- [x] SVG brand icons

---

## v0.3.0 - OIDC / Workload Identity Federation

### Killer Feature: OIDC for CI/CD
Zero-secret authentication for GitHub Actions, GitLab CI, etc.

**Goal:** Replace manual `ROBOT_TOKEN` rotation with federated identity.

```yaml
# GitHub Actions example
permissions:
  id-token: write
steps:
  - name: Login to NORA
    uses: nora/login-action@v1
```

### Config Structure (draft)

```toml
[auth.oidc]
enabled = true

# GitHub Actions
[[auth.oidc.providers]]
name = "github-actions"
issuer = "https://token.actions.githubusercontent.com"
audience = "https://nora.example.com"

[[auth.oidc.providers.rules]]
# Claim matching (supports glob)
match = { repository = "my-org/*", ref = "refs/heads/main" }
# Granted permissions
permissions = ["push:my-org/*", "pull:*"]

[[auth.oidc.providers.rules]]
match = { repository = "my-org/*", ref = "refs/heads/*" }
permissions = ["pull:*"]

# GitLab CI
[[auth.oidc.providers]]
name = "gitlab-ci"
issuer = "https://gitlab.com"
audience = "https://nora.example.com"

[[auth.oidc.providers.rules]]
match = { project_path = "my-group/*" }
permissions = ["push:my-group/*", "pull:*"]
```

### Implementation Tasks
- [ ] JWT validation library (jsonwebtoken crate)
- [ ] OIDC discovery (/.well-known/openid-configuration)
- [ ] JWKS fetching and caching
- [ ] Claims extraction and glob matching
- [ ] Permission resolution from rules
- [ ] Token exchange endpoint (POST /auth/oidc/token)
- [ ] GitHub Action: `nora/login-action`

---

## v0.4.0 - Transparent Docker Hub Proxy

### Pain Point
Harbor forces tag changes: `docker pull my-harbor/proxy-cache/library/nginx`
This breaks Helm charts hardcoded to `nginx`.

### Goal
Transparent pull-through cache:
```bash
docker pull nora.example.com/nginx  # -> proxies to Docker Hub
```

### Implementation Tasks
- [ ] Registry v2 API interception
- [ ] Upstream registry configuration
- [ ] Cache layer management
- [ ] Rate limit handling (Docker Hub limits)

---

## v0.5.0 - Repo-level RBAC

### Challenge
Per-repository permissions need fast lookup (100 layers per push).

### Solution
Glob patterns for 90% of cases:
```toml
[[auth.rules]]
subject = "team-frontend"
permissions = ["push:frontend/*", "pull:*"]

[[auth.rules]]
subject = "ci-bot"
permissions = ["push:*/release-*", "pull:*"]
```

### Implementation Tasks
- [ ] In-memory permission cache
- [ ] Glob pattern matcher (globset crate)
- [ ] Permission inheritance (org -> project -> repo)

---

## Target Audience

1. DevOps engineers tired of Java/Go monsters
2. Edge/IoT installations (Raspberry Pi, branch offices)
3. Educational platforms (student labs)
4. CI/CD pipelines (GitHub Actions, GitLab CI)

## Competitive Advantages

| Feature | NORA | Harbor | Nexus |
|---------|------|--------|-------|
| Memory | <100MB | 2GB+ | 4GB+ |
| OIDC for CI | v0.3.0 | No | No |
| Transparent proxy | v0.4.0 | No (tag rewrite) | Partial |
| Single binary | Yes | No (microservices) | No (Java) |
| Zero-config upgrade | Yes | Complex | Complex |

---

## v0.6.0 - Online Garbage Collection

### Pain Point
Harbor GC blocks registry for hours. Can't push during cleanup.

### Goal
Non-blocking garbage collection with zero downtime.

### Implementation Tasks
- [ ] Mark-and-sweep without locking
- [ ] Background blob cleanup
- [ ] Progress reporting via API/CLI
- [ ] `nora gc --dry-run` preview

---

## v0.7.0 - Retention Policies

### Pain Point
"Keep last 10 tags" sounds simple, works poorly everywhere.

### Goal
Declarative retention rules in config:

```toml
[[retention]]
match = "*/dev-*"
keep_last = 5

[[retention]]
match = "*/release-*"
keep_last = 20
older_than = "90d"

[[retention]]
match = "**/pr-*"
older_than = "7d"
```

### Implementation Tasks
- [ ] Glob pattern matching for repos/tags
- [ ] Age-based and count-based rules
- [ ] Dry-run mode
- [ ] Scheduled execution (cron-style)

---

## v0.8.0 - Multi-tenancy & Quotas

### Pain Point
Harbor projects have quotas but configuration is painful. Nexus has no real isolation.

### Goal
Simple namespaces with limits:

```toml
[[tenants]]
name = "team-frontend"
storage_quota = "50GB"
rate_limit = { push = 100, pull = 1000 }  # per hour

[[tenants]]
name = "team-backend"
storage_quota = "100GB"
```

### Implementation Tasks
- [ ] Tenant isolation (namespace prefix)
- [ ] Storage quota tracking
- [ ] Per-tenant rate limiting
- [ ] Usage reporting API

---

## v0.9.0 - Smart Replication

### Pain Point
Harbor replication rules are complex, errors silently swallowed.

### Goal
Simple CLI-driven replication with clear feedback:

```bash
nora replicate --to remote-dc --filter "prod/*" --dry-run
nora replicate --from gcr.io/my-project/* --to local/imported/
```

### Implementation Tasks
- [ ] Push-based replication to remote NORA
- [ ] Pull-based import from external registries (Docker Hub, GCR, ECR, Quay)
- [ ] Filter by glob patterns
- [ ] Progress bar and detailed logs
- [ ] Retry logic with exponential backoff

---

## v1.0.0 - Production Ready

### Features to polish
- [ ] Full CLI (`nora images ls`, `nora tag`, `nora delete`)
- [ ] Webhooks with filters and retry logic
- [ ] Enhanced Prometheus metrics (per-repo stats, cache hit ratio, bandwidth per tenant)
- [ ] TUI dashboard (optional)
- [ ] Helm chart for Kubernetes deployment
- [ ] Official Docker image on ghcr.io

---

## Future Ideas (v1.x+)

### Cold Storage Tiering
Auto-move old tags to S3 Glacier:
```toml
[[storage.tiering]]
match = "*"
older_than = "180d"
move_to = "s3-glacier"
```

### Vulnerability Scanning Integration
Not built-in (use Trivy), but:
- [ ] Webhook on push -> trigger external scan
- [ ] Store scan results as OCI artifacts
- [ ] Block pull if critical CVEs (policy)

### Image Signing (Cosign/Notation)
- [ ] Signature storage (OCI artifacts)
- [ ] Policy enforcement (reject unsigned)

### P2P Distribution (Dragonfly/Kraken style)
For large clusters pulling same image simultaneously.

---

---

## Architecture / DDD

### Current State (v0.2.0)
Monolithic structure, all in `nora-registry/src/`:
```
src/
├── main.rs          # CLI + server setup
├── auth.rs          # htpasswd + basic auth
├── tokens.rs        # API tokens
├── storage/         # Storage backends (local, s3)
├── registry/        # Protocol handlers (docker, maven, npm, cargo, pypi)
├── ui/              # Web dashboard
└── ...
```

### Target Architecture (v1.0+)

#### Domain-Driven Design Boundaries

```
nora/
├── nora-core/              # Domain layer (no dependencies)
│   ├── src/
│   │   ├── artifact.rs     # Artifact, Digest, Tag, Manifest
│   │   ├── repository.rs   # Repository, Namespace
│   │   ├── identity.rs     # User, ServiceAccount, Token
│   │   ├── policy.rs       # Permission, Rule, Quota
│   │   └── events.rs       # DomainEvent (ArtifactPushed, etc.)
│
├── nora-auth/              # Authentication bounded context
│   ├── src/
│   │   ├── htpasswd.rs     # Basic auth provider
│   │   ├── oidc.rs         # OIDC/JWT provider
│   │   ├── token.rs        # API token provider
│   │   └── rbac.rs         # Permission resolver
│
├── nora-storage/           # Storage bounded context
│   ├── src/
│   │   ├── backend.rs      # StorageBackend trait
│   │   ├── local.rs        # Filesystem
│   │   ├── s3.rs           # S3-compatible
│   │   ├── tiered.rs       # Hot/cold tiering
│   │   └── gc.rs           # Garbage collection
│
├── nora-registry/          # Application layer (HTTP API)
│   ├── src/
│   │   ├── api/
│   │   │   ├── oci.rs      # OCI Distribution API (/v2/)
│   │   │   ├── maven.rs    # Maven repository
│   │   │   ├── npm.rs      # npm registry
│   │   │   ├── cargo.rs    # Cargo registry
│   │   │   └── pypi.rs     # PyPI (simple API)
│   │   ├── proxy/          # Upstream proxy/cache
│   │   ├── webhook/        # Event webhooks
│   │   └── ui/             # Web dashboard
│
├── nora-cli/               # CLI application
│   ├── src/
│   │   ├── commands/
│   │   │   ├── serve.rs
│   │   │   ├── images.rs   # nora images ls/delete/tag
│   │   │   ├── gc.rs       # nora gc
│   │   │   ├── backup.rs   # nora backup/restore
│   │   │   ├── migrate.rs  # nora migrate
│   │   │   └── replicate.rs
│   │   └── tui/            # Optional TUI dashboard
│
└── nora-sdk/               # Client SDK (for nora/login-action)
    └── src/
        ├── client.rs       # HTTP client
        └── oidc.rs         # Token exchange
```

#### Key Principles

1. **Hexagonal Architecture**
   - Core domain has no external dependencies
   - Ports (traits) define boundaries
   - Adapters implement ports (S3, filesystem, OIDC providers)

2. **Event-Driven**
   - Domain events: `ArtifactPushed`, `ArtifactDeleted`, `TagCreated`
   - Webhooks subscribe to events
   - Async processing for GC, replication

3. **CQRS-lite**
   - Commands: Push, Delete, CreateToken
   - Queries: List, Get, Search
   - Separate read/write paths for hot endpoints

4. **Configuration as Code**
   - All policies in `nora.toml`
   - No database for config (file-based)
   - GitOps friendly

#### Trait Boundaries (Ports)

```rust
// nora-core/src/ports.rs

#[async_trait]
pub trait ArtifactStore {
    async fn push_blob(&self, digest: &Digest, data: Bytes) -> Result<()>;
    async fn get_blob(&self, digest: &Digest) -> Result<Bytes>;
    async fn push_manifest(&self, repo: &Repository, tag: &Tag, manifest: &Manifest) -> Result<()>;
    async fn get_manifest(&self, repo: &Repository, reference: &Reference) -> Result<Manifest>;
    async fn list_tags(&self, repo: &Repository) -> Result<Vec<Tag>>;
    async fn delete(&self, repo: &Repository, reference: &Reference) -> Result<()>;
}

#[async_trait]
pub trait IdentityProvider {
    async fn authenticate(&self, credentials: &Credentials) -> Result<Identity>;
    async fn authorize(&self, identity: &Identity, action: &Action, resource: &Resource) -> Result<bool>;
}

#[async_trait]
pub trait EventPublisher {
    async fn publish(&self, event: DomainEvent) -> Result<()>;
}
```

#### Migration Path

| Phase | Action |
|-------|--------|
| v0.3 | Extract `nora-auth` crate (OIDC work) |
| v0.4 | Extract `nora-core` domain types |
| v0.5 | Extract `nora-storage` with trait boundaries |
| v0.6+ | Refactor registry handlers to use ports |
| v1.0 | Full hexagonal architecture |

### Technical Debt to Address

- [ ] Remove `unwrap()` in non-test code (started in e9984cf)
- [ ] Add tracing spans to all handlers
- [ ] Consistent error types across modules
- [ ] Extract hardcoded limits to config
- [ ] Add OpenTelemetry support (traces, not just metrics)

### Performance Requirements

| Metric | Target |
|--------|--------|
| Memory (idle) | <50MB |
| Memory (under load) | <100MB |
| Startup time | <1s |
| Blob throughput | Wire speed (no processing overhead) |
| Manifest latency | <10ms p99 |
| Auth check | <1ms (cached) |

### Security Requirements

- [ ] No secrets in logs (already redacting)
- [ ] TLS termination (or trust reverse proxy)
- [ ] Content-addressable storage (immutable blobs)
- [ ] Audit log for all mutations
- [ ] SBOM generation for NORA itself

---

## Notes

- S3 storage: already implemented
- Web UI: minimalist read-only dashboard (done)
- TUI: consider for v1.0
- Vulnerability scanning: out of scope (use Trivy externally)
- Image signing: out of scope for now (use cosign externally)
