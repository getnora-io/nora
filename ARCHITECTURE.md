# Architecture

This document describes the high-level architecture of NORA, a multi-protocol
artifact registry. It is intended for contributors who want to understand the
codebase and for operators evaluating NORA for production use.

NORA is a single Rust binary (~34k lines) that implements up to 13
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
   │   Docker    │           │     Maven     │   ...    │    Conan      │
   │  /v2/*      │           │  /maven/*     │  (x13)   │   /conan/*    │
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
                           │   local | s3        │
                           └─────────────────────┘
```

Every HTTP request follows this path top-to-bottom. The registry handler is
selected by URL prefix (`/v2/` = Docker, `/maven/` = Maven, etc.). Curation
runs only on proxy downloads — hosted artifacts are trusted at publish time.

### Trust Boundaries

User input enters the system at the registry handler layer. Each handler
validates package names, versions, and paths before constructing storage keys.
The `validation.rs` module provides `validate_storage_key()` which rejects
path traversal, null bytes, and excessively long keys. All 13 handlers call
this function before any storage operation.

The curation layer is a second trust boundary for proxy traffic. When mode is
`enforce`, a package must pass all filters (blocklist, allowlist, namespace,
integrity) before reaching storage. When mode is `audit`, blocked packages
are logged but not rejected. The default-deny posture means: if the curation
engine errors, the request is blocked (fail-closed).

## Code Map

```
nora/
├── nora-registry/src/
│   ├── main.rs              # CLI (clap), server startup, route assembly
│   ├── config.rs            # All configuration: structs, defaults, env overrides
│   ├── registry_type.rs     # RegistryType enum shared across all modules
│   │
│   ├── registry/            # One file per format — routes + handlers
│   │   ├── docker.rs        #   Docker Registry v2 (OCI distribution spec)
│   │   ├── docker_auth.rs   #   Docker token auth (Bearer challenges)
│   │   ├── maven.rs         #   Maven repository (POM/JAR)
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
│   │   └── mod.rs           #   Re-exports: docker_routes(), maven_routes(), ...
│   │
│   ├── storage/
│   │   ├── mod.rs           #   StorageBackend trait (put/get/delete/list/stat)
│   │   ├── local.rs         #   Local filesystem implementation
│   │   └── s3.rs            #   S3-compatible implementation
│   │
│   ├── auth.rs              # htpasswd parsing, token issuance, middleware
│   ├── tokens.rs            # API token CRUD (tokens.json persistence)
│   ├── rate_limit.rs        # Token-bucket rate limiting (tower middleware)
│   ├── curation.rs          # Filter chain: blocklist, allowlist, namespace, integrity
│   ├── validation.rs        # Input validation: storage keys, package names
│   │
│   ├── gc.rs                # Garbage collection (orphan blob cleanup)
│   ├── retention.rs         # Retention policies (keep-N, max-age)
│   ├── backup.rs            # Backup/restore (tar.gz)
│   ├── migrate.rs           # Storage migration (local ↔ s3)
│   ├── mirror/              # Pre-fetch CLI (nora mirror npm/docker)
│   │
│   ├── health.rs            # /health endpoint (per-registry health)
│   ├── metrics.rs           # /metrics endpoint (Prometheus format)
│   ├── audit.rs             # Audit log (append-only JSONL)
│   ├── activity_log.rs      # Recent activity (in-memory ring buffer)
│   ├── dashboard_metrics.rs # Aggregated stats for UI dashboard
│   │
│   ├── ui/                  # Embedded web UI (server-rendered HTML)
│   │   ├── mod.rs           #   Routes (/ui/*)
│   │   ├── templates.rs     #   HTML templates (inline, no template engine)
│   │   ├── components.rs    #   Sidebar, nav, icons
│   │   ├── api.rs           #   Dashboard JSON API
│   │   ├── i18n.rs          #   English/Russian UI strings
│   │   ├── logo.rs          #   Embedded JPEG logo (base64)
│   │   └── static_assets.rs #   Embedded CSS/JS (Tailwind, htmx)
│   │
│   ├── openapi.rs           # OpenAPI spec generation (utoipa)
│   ├── secrets/             # Secret value handling (env vars, redaction)
│   ├── request_id.rs        # X-Request-Id middleware
│   ├── error.rs             # Error types
│   ├── repo_index.rs        # In-memory repository index
│   └── test_helpers.rs      # Shared test utilities
│
├── fuzz/                    # Cargo-fuzz targets
├── scripts/
│   ├── coherence-check.sh   # CI: code ↔ config consistency
│   └── docs-quality-gate.py # CI: docs ↔ code fact verification (13 checks)
└── docs-site/               # Documentation (Astro/Starlight)
```

## Architecture Decisions

### ADR-1: Single Binary

**Decision:** NORA ships as one statically-linked binary. All 13 registry
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
every cloud provider and on-prem MinIO. Local covers single-node and
development. A third backend (e.g., GCS-native, Azure Blob) adds testing
burden without meaningful capability gain — both are S3-compatible. For
migrating away from other registries, the `nora migrate` CLI copies
artifacts directly rather than proxying through the old system.

### ADR-4: Explicit Handlers over Plugin Traits

**Decision:** Each registry format is an explicit Rust module with its own
routes, handlers, config struct, and tests. There is no `RegistryPlugin`
trait with runtime dispatch.

**Context:** Adding a new registry format requires 24 insertion points
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
  block. All 851 tests run in ~15 seconds with `cargo test`. No plugin
  loading, no mock trait implementations, no integration harness.
- **Compile-time completeness.** When a new `RegistryType` variant is
  added, the compiler flags every unhandled match arm. Missing a
  touchpoint is a build error, not a runtime surprise.
- **Readability.** `grep "conan"` finds every place in the codebase that
  mentions Conan. No indirection through vtables or trait objects.

New registry formats are added rarely (6 were added in v0.7.0, none
expected until v0.9+). The cost of 24 mechanical edits once is lower
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

**Context:** With 13 formats available, most users need only 2-5.
Mounting all routes unconditionally wastes memory and widens the attack
surface.

**Rationale:** The original 7 formats (Docker, Maven, npm, Cargo, PyPI,
Go, Raw) default to enabled for backward compatibility. The 6 newer
formats (RubyGems, Terraform, Ansible, NuGet, Pub, Conan) default to
disabled. Any combination is valid — you can run NORA with only Docker
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

## Adding a New Registry

Adding a new registry format requires 24 insertion points across
9 files. The full list, traced from the Conan handler added in v0.7.0:

| # | File | Touchpoints | What to add |
|---|------|:-----------:|-------------|
| 1 | `registry/<format>.rs` | 1 | **New file.** Routes, handlers, proxy logic, curation calls, tests. 400-1200 lines. |
| 2 | `registry/mod.rs` | 2 | `mod <format>;` and `pub use <format>::routes as <format>_routes;` |
| 3 | `registry_type.rs` | 6 | Enum variant + match arms in `as_str()`, `mount_point()`, `display_name()`, `all()`, `from_str_opt()` |
| 4 | `config.rs` | 6 | Struct field in Config, `<Format>Config` struct + Default impl, `enabled_registries()`, `NORA_<FORMAT>_ENABLED` env, proxy env block, `Config::default()` |
| 5 | `main.rs` | 1 | Route merge match arm in `run_server()` |
| 6 | `metrics.rs` | 1 | Path branch in `detect_registry()` |
| 7 | `openapi.rs` | 4 | Tag in `tags()`, description string, path entries, stub functions |
| 8 | `test_helpers.rs` | 2 | Config field + route merge match arm |
| 9 | `coherence-check.sh` | 1 | Format name in `EXPECTED_REGISTRIES` |
| | **Total** | **24** | |

Several subsystems auto-discover new formats via `RegistryType::all()`
and require no per-format edits: health checks, curation engine,
dashboard statistics, and `docs-quality-gate.py`.

## Known Trade-offs

**24 touchpoints per format.** Adding a registry requires 24 mechanical
edits across 9 files. A trait-based plugin system would reduce this but
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
