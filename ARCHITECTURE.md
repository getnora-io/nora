# Architecture

This document describes the high-level architecture of NORA, a multi-protocol
artifact registry. It is intended for contributors who want to understand the
codebase and for operators evaluating NORA for production use.

NORA is a single Rust binary (~42k lines of production code) that implements up to 13
registry protocols over one HTTP port. It is a registry — it provides
protocol-compliant interfaces for package managers (docker, npm, cargo,
pip, etc.), not a storage system. There is no database, no JVM, no
plugin runtime. The filesystem (or S3) is the only source of truth.

## Design Principles

1. **Single binary, zero dependencies.** One `nora` binary, one config file,
   one data directory. No sidecar processes, no external databases, no package
   managers at runtime. A `cp -r /data/ backup/` is a complete backup.

2. **Filesystem is the database.** All state lives on disk (or S3) as files.
   In-memory indexes are rebuilt on startup. There are no schema migrations,
   no WAL corruption risks, no `VACUUM` commands. Docker Distribution serves
   Docker Hub with the same approach.

3. **Security is free.** Blocklists, allowlists, namespace isolation, integrity
   verification — all included in the open-source release. Security features
   should not be premium add-ons.

4. **Explicit over abstract.** Each registry format has its own handler module
   with explicit routes, explicit config, explicit tests. There are no trait
   vtables dispatching requests at runtime. You can `grep` for any endpoint
   and find exactly one handler.

5. **Add formats from demand, not from checklists.** A format is added when
   real users ask for it, the protocol is well-specified, and the maintainers
   can guarantee: proxy works, hosted works, tests exist, docs exist.

## System Architecture

```
                           ┌─────────────────────┐
                           │    HTTP :4000        │
                           └──────────┬──────────┘
                                      │
                           ┌──────────▼──────────┐
                           │     Auth Layer       │
                           │  (htpasswd + tokens) │
                           └──────────┬──────────┘
                                      │
                           ┌──────────▼──────────┐
                           │    Rate Limiter      │
                           │ (auth/upload/general)│
                           └──────────┬──────────┘
                                      │
          ┌───────────────────────────┼───────────────────────────┐
          │                           │                           │
   ┌──────▼──────┐           ┌───────▼───────┐          ┌───────▼───────┐
   │   Docker    │           │     Maven     │   ...    │    Debian     │
   │  /v2/*      │           │  /maven2/*    │  (x15)   │    /deb/*     │
   └──────┬──────┘           └───────┬───────┘          └───────┬───────┘
          │                           │                           │
          └───────────────────────────┼───────────────────────────┘
                                      │
                           ┌──────────▼──────────┐
                           │   Curation Engine   │
                           │ blocklist→allowlist  │
                           │ →namespace→integrity │
                           └──────────┬──────────┘
                                      │
                           ┌──────────▼──────────┐
                           │      Storage        │
                           │  local | s3 | gcs   │
                           └─────────────────────┘
```

Every HTTP request follows this path top-to-bottom. The registry handler is
selected by URL prefix (`/v2/` = Docker, `/maven2/` = Maven, etc.). Curation
runs only on proxy downloads — hosted artifacts are trusted at publish time.

### Trust Boundaries

User input enters the system at the registry handler layer. Each handler
validates package names, versions, and paths before constructing storage keys.
The `validation.rs` module provides `validate_storage_key()`, which rejects
path traversal, null bytes, and excessively long keys.

The storage-key trust boundary is enforced centrally, not per handler. The
`Storage` wrapper in `storage/mod.rs` calls `validate_storage_key()` as the
first act of every method that takes a key — `put`, `get`, `delete`, `stat`,
`list`, `get_verified`, and the range/reader variants. A handler cannot reach
the underlying `StorageBackend` without passing through this choke point, so
the invariant holds even if a new handler forgets to validate. A few handlers
(`raw`, `cargo_registry`, `pub_dart`) also validate at the edge as
defence-in-depth, but the load-bearing check lives in the wrapper.

Integrity verification is a typed gate on the read path. `Storage::get_verified`
returns a `GateOutcome` (`verified.rs`): `Verified` when a recorded hash pin
matched the bytes, or `Unpinned` for an open-world key with no pin. Callers must
`match` on the outcome — the open-world case cannot be silently mistaken for a
verified one. A pin mismatch returns `IntegrityViolation` rather than the bytes,
so the gate fails closed.

The curation layer is a second trust boundary for proxy traffic. When mode is
`enforce`, a package must pass all filters (blocklist, allowlist, namespace,
integrity) before reaching storage. When mode is `audit`, blocked packages
are logged but not rejected. The default-deny posture means: if the curation
engine errors, the request is blocked (fail-closed).

## Code Map

The tree below tracks the module declarations in `main.rs` (the binary) and
`lib.rs` (the library surface used by tests and fuzz targets).

```
nora/
├── nora-registry/src/
│   ├── main.rs              # CLI (clap), server startup, route + middleware assembly
│   ├── lib.rs              # Library surface: re-exports validation + verified for tests/fuzz
│   ├── registry_type.rs     # RegistryType enum shared across all modules
│   │
│   ├── config/             # Configuration (split by concern, not one file)
│   │   ├── mod.rs           #   Top-level Config, defaults, env-override wiring
│   │   ├── server.rs        #   Server + TLS settings
│   │   ├── storage.rs       #   Storage backend selection (local/s3)
│   │   ├── auth.rs          #   Auth, OIDC, trusted-proxy settings
│   │   ├── registries.rs    #   Declarative [registries] selection
│   │   ├── curation.rs      #   Curation mode + rule paths
│   │   ├── rate_limit.rs    #   Rate-limit tiers
│   │   ├── circuit_breaker.rs # Circuit-breaker thresholds
│   │   ├── gc.rs / retention.rs / audit_cfg.rs # GC, retention, audit config
│   │   └── registry/        #   Per-format config structs (docker.rs, maven.rs, ...)
│   │
│   ├── registry/            # One file per format — routes + handlers
│   │   ├── docker.rs        #   Docker Registry v2 (OCI distribution spec)
│   │   ├── docker_auth.rs   #   Docker token auth (Bearer challenges)
│   │   ├── maven.rs         #   Maven repository (POM/JAR), mounted at /maven2/
│   │   ├── npm.rs           #   npm registry (packument + tarball)
│   │   ├── cargo_registry.rs #  Cargo sparse index (RFC 2789)
│   │   ├── pypi.rs          #   PyPI (PEP 503/691)
│   │   ├── go.rs            #   Go module proxy (GOPROXY protocol)
│   │   ├── raw.rs           #   Raw file storage
│   │   ├── gems.rs          #   RubyGems (specs.4.8 + gem push)
│   │   ├── terraform.rs     #   Terraform module registry v1
│   │   ├── ansible.rs       #   Ansible Galaxy v3
│   │   ├── nuget.rs         #   NuGet v3 (service index)
│   │   ├── pub_dart.rs      #   Pub (Dart/Flutter)
│   │   ├── conan.rs         #   Conan v2 (revisions API)
│   │   ├── rpm.rs           #   RPM hosted repos (server-generated repodata)
│   │   ├── deb.rs           #   Debian/APT flat repos (server-generated indexes)
│   │   └── mod.rs           #   Re-exports: docker_routes(), maven_routes(), ...
│   │
│   ├── storage/
│   │   ├── mod.rs           #   StorageBackend trait + Storage wrapper (validate + pin gate)
│   │   ├── local.rs         #   Local filesystem implementation
│   │   └── object.rs        #   Object-store implementation (S3-compatible + GCS)
│   │
│   ├── auth/               # Authentication (middleware + providers)
│   │   ├── mod.rs           #   auth_middleware, provider dispatch
│   │   ├── htpasswd.rs      #   htpasswd parsing
│   │   ├── oidc.rs          #   OIDC workload-identity provider
│   │   ├── namespace.rs     #   OIDC namespace_scope authorization
│   │   └── token_routes.rs  #   Token management API routes
│   ├── tokens.rs            # API token CRUD (tokens.json persistence)
│   ├── rate_limit.rs        # Token-bucket rate limiting (tower middleware)
│   ├── curation.rs          # Filter chain: blocklist, allowlist, namespace, integrity
│   ├── validation.rs        # Input validation: storage keys, package names, null bytes
│   │
│   ├── verified.rs          # Compile-time integrity witnesses (GateOutcome typestate)
│   ├── hash_pin_store.rs    # SHA-256 pins recorded on put(), verified on get()
│   ├── digest_quarantine.rs # First-seen tracking for proxy-fetched digests
│   ├── circuit_breaker.rs   # Per-registry circuit breaker for upstream proxy calls
│   ├── proxy_coalesce.rs    # Single-flight coalescing on the proxy cache-miss path
│   ├── cache_ttl.rs         # Unified cache TTL logic for proxy registries
│   ├── docker_key_migration.rs # Migrate legacy flat Docker keys to namespaced form
│   │
│   ├── gc.rs                # Garbage collection (orphan blob cleanup)
│   ├── retention.rs         # Retention policies (keep-N, max-age)
│   ├── backup.rs            # Backup/restore (tar.gz)
│   ├── migrate.rs           # Storage migration (local ↔ s3)
│   ├── mirror/              # Pre-fetch CLI (nora mirror npm/docker)
│   │
│   ├── health.rs            # /health endpoint (per-registry health)
│   ├── metrics.rs           # /metrics endpoint (Prometheus format) + leak detection
│   ├── audit.rs             # Audit log (append-only JSONL)
│   ├── activity_log.rs      # Recent activity (in-memory ring buffer)
│   ├── dashboard_metrics.rs # Aggregated stats for UI dashboard
│   ├── admin.rs             # Admin control-plane API (/api/v1/admin/, admin-gated)
│   │
│   ├── ui/                  # Embedded web UI (server-rendered HTML)
│   │   ├── mod.rs           #   Routes (/ui/*), public-path rewrite middleware
│   │   ├── templates.rs     #   HTML templates (inline, no template engine)
│   │   ├── components.rs    #   Sidebar, nav, icons
│   │   ├── api.rs           #   Dashboard JSON API
│   │   ├── i18n.rs          #   English/Russian UI strings
│   │   ├── static_assets.rs #   Embedded CSS/JS (Tailwind, htmx)
│   │   ├── static/          #   tailwind.css, htmx.min.js
│   │   └── logo.jpg         #   UI logo asset
│   │
│   ├── openapi.rs           # OpenAPI spec generation (utoipa)
│   ├── signing.rs           # rpm/deb index signing (OpenPGP key + InRelease/repomd.xml.asc)
│   ├── secrets/             # Secret value handling (env vars, redaction)
│   ├── request_id.rs        # X-Request-Id middleware
│   ├── repo_index.rs        # In-memory repository index
│   └── test_helpers.rs      # Shared test utilities
│
├── fuzz/                    # Cargo-fuzz targets
└── scripts/                # CI helpers: coherence-check.sh, verify-changelog.sh,
                            # lock-audit.sh, pre-commit-check.sh, post-release-gate.sh, ...

# Documentation is maintained separately and published at https://getnora.dev
```

### Middleware Order

Request middleware order is load-bearing and must not be reordered. In axum the
last applied `.layer()` is the outermost (runs first), so the assembly in
`main.rs` produces this execution order, outermost to innermost:

```
reject_null_bytes → metrics → auth → ui-rewrite → leak_detection → request_id → handler
```

`reject_null_bytes` is outermost so null-byte path attacks are blocked before
anything else touches the request; `request_id` is innermost so the request ID
is available to handlers.

## Architecture Decisions

### ADR-1: Single Binary

**Decision:** NORA ships as one statically-linked binary. All 15 registry
handlers, the UI, the curation engine, and the CLI tools are compiled into
a single executable.

**Context:** Other registry solutions use plugin architectures: Nexus has
OSGi bundles, Pulp has Python plugins per format, Artifactory has Java
modules. Each approach introduces dependency management, version
compatibility matrices, and runtime loading failures.

**Rationale:** A single binary eliminates deployment complexity. There are
no plugins to install, no versions to align, no ClassNotFoundExceptions.
The stripped binary is ~22 MB; the Alpine Docker image is ~31 MB. The
trade-off is that unused formats still occupy binary space — mitigated
by Cargo features for compile-time exclusion if needed.

### ADR-2: Filesystem as Source of Truth

**Decision:** All persistent state is stored as files on disk (or S3 objects).
There is no embedded database in the open-source release.

**Context:** Nexus migrated from filesystem to OrientDB for metadata. The
migration took 2+ years and introduced corruption bugs that persist today.
SQLite would provide structured queries but adds a second source of truth
that can diverge from the actual files on disk.

**Rationale:**
- `cp -r /data/ backup/` is a complete, consistent backup
- No schema migrations, no WAL corruption, no `VACUUM`
- Retention uses file mtime (publish date) — no metadata DB needed
- Search uses in-memory HashMap rebuilt on startup (~5ms for 10k packages)
- Token storage uses `tokens.json` — same pattern as htpasswd
- Docker Distribution serves Docker Hub at scale with pure filesystem storage

### ADR-3: Two Storage Backends (Local + S3)

**Decision:** NORA supports exactly two storage backends: local filesystem
and S3-compatible object storage. No third backend will be added.

**Context:** The option of using Nexus/Artifactory/GitLab as
storage backends was considered, effectively making NORA a caching proxy
in front of other registries.

**Rationale:** Each storage backend is a maintenance surface. S3 covers
every cloud provider and on-prem S3-compatible stores. Local covers single-node and
development. A third backend (e.g., GCS-native, Azure Blob) adds testing
burden without meaningful capability gain — both are S3-compatible. For
migrating away from other registries, the `nora migrate` CLI copies
artifacts directly rather than proxying through the old system.

### ADR-4: Explicit Handlers over Plugin Traits

**Decision:** Each registry format is an explicit Rust module with its own
routes, handlers, config struct, and tests. There is no `RegistryPlugin`
trait with runtime dispatch.

**Context:** Adding a new registry format requires dozens of insertion points
across 9 files (see "Adding a New Registry" below). A contributor noted
this as high coupling.

**Rationale:** A trait-based plugin system would reduce the number of
insertion points but introduce a new abstraction layer: a `RegistryPlugin`
trait with associated types, default method implementations, and runtime
dispatch. In Rust, this means `Box<dyn RegistryPlugin>` or generics
threaded through every handler — both add complexity without removing it.
Each registry protocol has unique semantics (Docker has content-addressable
blobs, Maven has checksums-as-files, Cargo has sparse index). A common
trait would either be too narrow (requiring per-format escape hatches) or
too broad (leaking abstraction through dozens of `Option<T>` fields).

The explicit approach has practical advantages:

- **Testability.** Each handler is a standalone module with its own test
  block. Over 1,400 unit and integration tests run with `cargo test`. No plugin
  loading, no mock trait implementations, no integration harness.
- **Compile-time completeness.** When a new `RegistryType` variant is
  added, the compiler flags every unhandled match arm. Missing a
  touchpoint is a build error, not a runtime surprise.
- **Readability.** `grep "conan"` finds every place in the codebase that
  mentions Conan. No indirection through vtables or trait objects.

New registry formats are added rarely (6 were added in v0.7.0, none
expected until v0.9+). The cost of a few dozen mechanical edits once is lower
than the cost of maintaining a plugin abstraction layer forever.

### ADR-5: Curation is File-First, GitOps-Native

**Decision:** Curation rules (blocklists, allowlists) are JSON files on
disk. They can be loaded from lockfiles (`nora curation init --from-lockfile`).
There is no API for writing curation rules.

**Context:** Nexus Firewall stores rules in its database. When the database
corrupts or the feature is accidentally disabled, all rules disappear. In
one documented incident, 588 packages leaked through a disabled Nexus
Defender.

**Rationale:** File-based rules are version-controlled, diff-able, and
reviewed in pull requests. The curation engine loads rules into an
in-memory HashMap for O(1) lookup. The API is read-only (query decisions).
The fail-closed default means: if the curation engine errors during
evaluation, the request is blocked — not allowed.

### ADR-6: Embedded Minimal UI

**Decision:** The web UI is server-rendered HTML embedded in the binary.
It is read-only (browse registries, view packages, check health) with
minimal CRUD (manage API tokens).

**Context:** A contributor suggested extracting the UI into a standalone
SPA (React/Vue/Svelte).

**Rationale:** 90% of users interact with NORA through CLI tools (docker,
npm, cargo, pip), not through a browser. The embedded UI serves the
remaining 10% — operators checking health and browsing artifacts. A
full SPA would add a Node.js build pipeline, CORS configuration, and a
separate deployment artifact. The current approach keeps operational
overhead at zero: the UI is always available, always in sync with the
API, requires no separate process. A standalone SPA is a roadmap
consideration for the future.

### ADR-7: Dynamic Registry Loading

**Decision:** Every registry format — including the original 7 — has an
`enabled` boolean in config. Any format can be turned off. Disabled
registries consume zero resources — no routes are mounted, no background
tasks run.

**Context:** With 15 formats available, most users need only 2-5.
Mounting all routes unconditionally wastes memory and widens the attack
surface.

**Rationale:** The original 7 formats (Docker, Maven, npm, Cargo, PyPI,
Go, Raw) default to enabled for backward compatibility. The 8 newer
formats (RubyGems, Terraform, Ansible, NuGet, Pub, Conan, RPM, Debian)
default to disabled. Any combination is valid — you can run NORA with only Docker
and PyPI by setting `NORA_MAVEN_ENABLED=false`, `NORA_NPM_ENABLED=false`,
etc. The `RegistryType::all()` iterator and `enabled_registries()` method
let subsystems (health, metrics, UI) auto-discover which formats are
active.

### ADR-8: Security by Default

**Decision:** All security features (auth, rate limiting, curation,
namespace isolation) are included in the open-source release and
enabled by default where safe.

**Context:** In other registry solutions, security is a paid add-on:
Artifactory requires Xray for CVE scanning, Nexus requires
Firewall/Lifecycle for package filtering. This creates an incentive
where security is paywalled.

**Rationale:** Rate limiting is enabled by default. Auth requires
explicit opt-in (htpasswd file). Curation defaults to `off` but
switching to `enforce` is one config change. Namespace isolation is
always active when configured, regardless of curation mode. The goal
is: a default NORA deployment should be harder to attack than a default
Nexus/Artifactory deployment.

### ADR-9: Conditional Requests are Per-Protocol

**Decision:** Conditional request semantics (ETag, If-Match, If-None-Match)
are implemented per-registry following each format's upstream specification.
There is no shared conditional-request middleware.

**Context:** RFC 9110 defines conditional requests for HTTP. Each registry
protocol has its own immutability model: Docker uses content-addressable
digests, Maven/npm/Cargo/PyPI enforce version immutability at publish time,
Raw has no upstream spec. Implementing a generic conditional-request layer
would either be too narrow (not matching protocol-specific semantics) or too
broad (imposing HTTP semantics on protocols that don't need them).

**Rationale:** Raw is the only format that benefits from RFC 9110 conditional
PUT because it's a plain file store with no versioning scheme. Other formats
already have protocol-defined immutability. Adding ETag/If-Match to Maven or
npm would conflict with their publish APIs. The per-protocol approach follows
ADR-4: each handler owns its full request lifecycle.

## Adding a New Registry

Adding a new registry format touches roughly 20 files. The code half is
compile-enforced (exhaustive matches with no wildcard arms), the rest is
CI-enforced (`coherence-check.sh`, e2e contracts). The full list, traced
from the Conan (v0.7.0) and RPM handlers:

| # | File | What to add |
|---|------|-------------|
| 1 | `registry/<format>.rs` | **New file.** Routes, handlers, proxy/publish logic, curation calls, tests. 400-1200 lines. |
| 2 | `registry/mod.rs` | `mod <format>;` and `pub use <format>::routes as <format>_routes;` |
| 3 | `registry_type.rs` | Enum variant + match arms in `as_str()`, `mount_point()`, `display_name()`, `all()`, `from_str_opt()` |
| 4 | `config/registry/<format>.rs` | **New file.** `<Format>Config` struct + Default + `NORA_<FORMAT>_*` env overrides; `mod`/`pub use` in `config/registry/mod.rs` |
| 5 | `config/mod.rs` | `Config` field, `enabled_registries_legacy()`, `is_enabled_proxy()`, `quarantine_mode_for()`, `apply_env_overrides()`, serde-default test |
| 6 | `config/curation.rs` + `main.rs` | Curation override field + min-age pairing (proxy formats only; hosted-only formats like Raw/RPM skip this) |
| 7 | `main.rs` | Route merge match arm in `run_server()` |
| 8 | `test_helpers.rs` | Config field + route merge match arm |
| 9 | `repo_index.rs` | Index-builder match arm (`INDEX_PATTERN` + `build_generic_index` usually suffices) |
| 10 | `metrics.rs` | Path branch in `detect_registry()` + test path |
| 11 | `ui/components.rs` | Sidebar nav tuple + icon + sidebar tests |
| 12 | `ui/mod.rs` | `/ui/<format>` routes + page title |
| 13 | `ui/templates.rs` | Install command, icon dispatch, display name, column labels |
| 14 | `ui/api.rs` | `RegistryStats` field, dashboard upstreams arm, detail dispatch |
| 15 | `openapi.rs` | Tag, description string, path entries, stub functions |
| 16 | `gc.rs` | Coverage-report prefix (formats without an orphan graph) |
| 17 | `coherence-check.sh` | Format name in `EXPECTED_REGISTRIES` |
| 18 | `tests/e2e/tests/contracts/registry-contracts.ts` | UI contract entry |
| 19 | Docs | `README.md`, `COMPAT.md`, `ARCHITECTURE.md`, `CHANGELOG.md`, `llms.txt`, `dist/nora.env.example` |

Several subsystems auto-discover new formats via `RegistryType::all()`
and require no per-format edits: health checks, cache TTLs, rate limiting,
retention, activity log, and dashboard statistics.

## Known Trade-offs

**~20 files touched per format.** Adding a registry requires dozens of
mechanical edits. A trait-based plugin system would reduce this but
add an abstraction layer that must be maintained forever. Registries are
added rarely — the explicit approach trades one-time boilerplate for
permanent simplicity, compile-time completeness checks, and full test
coverage of each format in isolation.

**No high availability.** NORA runs as a single instance with a single
RWO volume. This is a design decision, not a missing feature. Artifact
registries have a read-heavy, write-light workload — a single instance
with S3 storage handles thousands of pulls per minute. Kubernetes
`Recreate` strategy ensures zero-downtime upgrades for reads served from
client-side caches.

**DRY violations between handlers.** Registry handlers share structural
patterns (proxy logic, curation calls, config loading) but differ in
protocol details. The duplication is real. The mitigation path is
`macro_rules!` scaffolding for boilerplate, not trait-based abstraction.

**Embedded UI is minimal.** The server-rendered UI covers browsing and
health monitoring but not advanced operations (user management, audit
queries, visual curation rule editing). These are better served by
external tools (Grafana dashboards, git-based rule management).

## What NORA Is Not

- **Not a CI/CD system.** NORA is a registry — it provides
  protocol-compliant access to artifacts. It does not build, test, or
  deploy them.
- **Not a vulnerability scanner.** Curation blocks known-bad packages.
  For CVE scanning of your own artifacts, use Trivy, Grype, or similar.
- **Not a package builder.** NORA does not compile source code into
  packages. Use `cargo publish`, `npm publish`, `mvn deploy` to create
  artifacts, then push them to NORA.
- **Not a CDN.** For geo-distributed artifact delivery, put a CDN
  (CloudFront, Cloudflare) in front of NORA.
- **Not a middleware.** NORA is a standalone registry, not a caching
  layer in front of Nexus or Artifactory. For migration, use
  `nora migrate`.
