# Changelog
## [Unreleased]

## [0.9.2] - 2026-05-23

### Added
- **Prometheus P0 metrics** — `nora_downloads_total`, `nora_uploads_total`, `nora_storage_bytes`, `nora_cache_requests_total`, `nora_upstream_request_duration_seconds` histogram with per-registry labels (#431, #432, #443)
- **Grafana dashboard** — production-ready dashboard JSON in `dist/grafana-dashboard.json` with documentation (#436, #437)
- **Ansible Galaxy v3 compliance** — pagination forwarding, artifact route alias, spec name validation (#433, #434, #438, #444, #445)
- **.deb/.rpm packaging** — `nfpm` configuration for native Linux packages (#209, #435)
- **Circuit breaker gauge initialization** — `nora_circuit_breaker_state` emits 0 (CLOSED) at startup for all enabled registries (#441)
- **PyPI URL-rewrite tests** — 11 tests covering trailing-slash and double-slash regressions (#387)
- 1086 total tests (up from 1049)

### Fixed
- **npm upstream URL leak (P0 security)** — metadata responses no longer expose `registry.npmjs.org` URLs (#439)
- **Cargo sparse index `api` field** — `config.json` now returns correct `/cargo/api` path instead of `/cargo` (#442)
- **PyPI trailing-slash URL rewrite** — response body URLs no longer contain double-slash `//simple` (#387)

### Changed
- Dashboard screenshot updated to v0.9.2 with populated metrics panels (#429, #430)
- README and SECURITY.md synced with v0.9.2 (#428)

## [0.9.1] - 2026-05-21

### Added
- **NuGet gzip registration** — `RegistrationsBaseUrl/3.6.0` responses compressed with gzip per NuGet V3 spec (#421)
- **NuGet semVerLevel filtering** — search and autocomplete hide SemVer 2.0 packages when `semVerLevel` not specified (#421)
- **NuGet service index generation** — generate service index from scratch instead of rewriting upstream, ensures all `@id` URLs point to Nora (#404, #405)
- **NuGet Chocolatey/PowerShell aliases** — `/chocolatey/` and `/powershell/` path aliases for NuGet V3 endpoints (#412, #419)
- **NuGet local autocomplete fallback** — autocomplete works in air-gap mode using cached package index (#414, #417)
- **NuGet serve-stale** — serve cached metadata when upstream is unreachable, with `X-Nora-Stale` header (#409, #410, #411)
- **NuGet deprecation/vulnerability pass-through** — registration responses preserve deprecation and vulnerability metadata from upstream (#425)
- **Cargo ETag + HTTP 304** — sparse index responses include SHA-256 ETag; `If-None-Match` returns 304 Not Modified (#397)
- **Upstream URL leak detection metric** — Prometheus counter `nora_upstream_url_leak_total{registry, leak_type}` fires when response bodies/headers contain upstream registry URLs (#386, #426)
- **NuGet E2E test suite** — 11 dotnet client fixture projects covering restore, analyzers, source generators, native RID, SemVer2, version ranges, case insensitivity, lock files, deep transitive deps, and Chocolatey alias

### Fixed
- **NuGet URL rewriting** — registration index/page `@id` and `packageContent` URLs no longer leak `api.nuget.org` (#388, #392, #393, #394, #400)
- **NuGet background fetch** — index fetch routed through `proxy_fetch_text` to respect proxy and circuit breaker settings (#413, #416)
- **NuGet upstream URL stripping** — strip path component from upstream proxy URL to prevent double-path (#407, #408)
- **NuGet serve_stale config** — respect `serve_stale` config flag in search/autocomplete fallback (#423)
- **PyPI PEP 691 typed structs** — replaced ad-hoc JSON manipulation with typed Serde structs for spec conformance (#390, #398)
- **PyPI file hash key** — renamed `digests` to `hashes` to support PEP 691 specification (#389, #399)
- **npm scoped package tarball key** — correct tarball storage key for `@scope/package` in UI detail view (#402, #403)
- **Air-gap URL leaks** — fixed upstream URL leaks across NuGet, Terraform, and Ansible registries (#400)
- **Curation test serialization** — serialize env-override tests with mutex to prevent flaky parallel failures (#406)

### Changed
- **NuGet search endpoint discovery** — dynamically discover search/autocomplete endpoints from upstream service index instead of hardcoding (#370, #418)
- **NuGet metadata proxy timeout** — reduced from default to 2s for faster fallback to cache (#415, #420)
- **URL-leak invariant tests** — added URL-leak detection tests for NuGet and npm registries (#390, #395)
- 1049 total tests (up from 994)

## [0.9.0] - 2026-05-16

### Added
- **OIDC / Workload Identity** — zero-secret auth for GitHub Actions and GitLab CI JWT tokens (#342)
- **Cache-Control completeness** — extend caching headers to all remaining registries (#340)
- **Docker streaming blob uploads** — chunked upload processing eliminates OOM on large images (#368)
- **Docker path-based upstream routing** — route pulls to specific upstreams by image path prefix (#365)
- **Docker metadata TTL + stale-while-error** — cached manifests revalidate against upstream after configurable TTL; serve stale on upstream failure (#311)
- **Docker/OCI mirror namespacing** — per-upstream namespace prefix isolates storage keys, with lazy migration from legacy flat layout (#323)
- **Per-registry circuit breaker overrides** — `[circuit_breaker.overrides."registry:url"]` allows custom thresholds per upstream (#339)
- **Streaming read_timeout for Docker blobs** — per-chunk timeout prevents stuck connections on large layer downloads (#341)
- **Hot reload for curation policy** — SIGHUP reloads blocklist/allowlist without restart using lock-free ArcSwap (#343)
- **linux/arm64 support** — multi-platform Docker images and binary releases for ARM64 (#193)
- **Production deployment files** — `deploy/docker-compose.prod.yml` and `deploy/nora.service` systemd unit (#307)

### Changed
- **Manifest response builder** — extracted `manifest_response()` helper, removing 3 duplicate return paths in Docker registry (#338)
- **Env var naming convention** — shortened variables to `NORA_{SECTION}_{FIELD}` pattern (under 30 chars), e.g. `NORA_TF_*`, `NORA_CURATION_INTERNAL_NS`

## [0.8.4] - 2026-05-15

### Fixed
- Add Content-Length header to `library/` fallback manifest response (#337)
- Docker 3+ path segments (`org/team/app`) routed correctly (#309)
- GC blob ordering — blobs deleted before manifests to prevent dangling references (#305)
- GC graceful SIGTERM — flush pending deletions on shutdown (#306)
- AuditLog singleton — single instance instead of duplicate per registry (#308)
- UI mount points table shows all configured upstreams (#312)
- Token owner set to real authenticated user instead of "admin" (#322)
- Race conditions, non-atomic writes, and version sorting (#318, #334)
- Log storage write failures instead of silently discarding (#317, #332)
- Security hardening — health endpoint sanitization, auth warning, Docker realm validation (#330)
- Security hardening — XSS protection, injection prevention, input validation (#319, #335)
- Raw registry Cache-Control changed from `immutable` to configurable `no-cache` default (#302, #329)
- NuGet: use shared http_client for flatcontainer index fetch (#331)
- Catch panics in background cache tasks, consolidate Go registry spawns (#333)
- Log audit write and serialization failures instead of swallowing (#321, #327)
- Write `.crate` tarball before sparse index to prevent zombie versions (#316, #328)
- Move blocking file I/O out of upload session lock scope (#313, #326)
- Use proxy-aware client IP in token API rate limiting (#314, #325)
- Flush token `last_used` on graceful shutdown (#304, #324)

### Changed
- README and ROADMAP synced with current state (#344)
- Configuration reference updated with raw `cache_control` docs (#303)

## [0.8.3] - 2026-05-13

### Added
- Outbound HTTP/SOCKS5 proxy support (#296)
- Structured audit log with configurable output (#286)
- Raw registry RFC 9110 conditional PUT (#278)
- Raw registry POST /raw/-/reindex endpoint (#276)
- Reverse proxy setup guide (#275)

### Fixed
- Duplicate library/ prefix block in Docker download_blob (#297, #285)
- Security hardening: HTML escape, brute-force, realm validation (#292)
- Warn-level log when all proxy upstreams fail (#284)
- Log all silent storage and proxy errors (#282)
- PyPI: merge upstream and local files in simple index (#295)
- Flaky quarantine persistence test under tarpaulin (#299)
- OpenAPI 429 docs, 405 with Allow header (#279)

### Changed
- 994 total tests (up from 910)

## [0.8.2] - 2026-05-07

### Fixed
- **TTL race condition** — unified TTL semantics across registries; repo_index invalidation no longer races with concurrent publishes (#266)
- **NuGet autocomplete leak** — `SearchAutocompleteService` URLs in service index now rewrite to NORA instead of leaking to `azuresearch-*.nuget.org`. New `/nuget/v3/autocomplete` proxy endpoint with graceful fallback (#262)
- **NuGet gallery leak** — `SearchGalleryQueryService` root URLs (`azuresearch-{usnc,ussc}.nuget.org/`) now rewrite to NORA. Zero azuresearch URLs remain in service index
- **NuGet 429 during cache warming** — registry proxy routes no longer double-limited by `general_limiter` + `upload_limiter`. Removes 429 errors during `dotnet restore` with many packages while keeping auth rate limiting active
- **E2E test paths** — NuGet smoke tests used wrong paths (`/v3/flat/` → `/v3/flatcontainer/`, `/v3/search` → `/v3/query`)

### Added
- **NuGet search fallback** — local search from repo index when upstream is unavailable, download tracking for proxied packages (#261)
- **Env var naming guideline** — `CONTRIBUTING.md` documents `NORA_{SECTION}_{FIELD}` pattern with abbreviation convention (`NORA_CB_*`)
- 910 total tests (up from 909)

### Changed
- Docker base images switched to real RED OS and Astra Linux images (#260)
- NuGet autocomplete config: env var `NORA_NUGET_AUTOCOMPLETE`, config field `autocomplete`

## [0.8.1] - 2026-05-06

### Fixed
- **UI polish** — improved dashboard layout and proxy index reliability
- **Error logging** — better error messages for proxy failures (#259)

## [0.8.0] - 2026-05-02

### Added
- **Hash Pin Store** — content-addressable integrity verification for all stored artifacts, `put_if_absent()` semantics with NDJSON persistence (#229)
- **Trusted proxy support** — `NORA_AUTH_TRUSTED_PROXIES` accepts CIDR ranges for X-Forwarded-For extraction (#230)
- **Cache-Control headers** — proper caching directives for proxy registries: Docker, Maven, npm, Cargo, PyPI, Go, Pub, Raw (#230)
- **Auth rate limiting** — per-IP exponential backoff on failed authentication (429+Retry-After) (#229)
- **Docker publish_locks eviction** — automatic cleanup of stale upload locks (#230)
- **GOVERNANCE.md and ROADMAP.md** — project governance model and public roadmap (#228)
- **Version consistency gate** — `scripts/pre-commit-check.sh` validates Cargo.toml vs OpenAPI vs Cargo.lock versions, enforced in release pipeline (#224, #225)
- 908 total tests (up from 851)

### Fixed
- **Docker proxy timeout** — default timeout raised from 60s/120s to 300s, large image pulls no longer time out (#233)
- **Unicode path validation** — non-ASCII characters in Maven/Raw upload paths now return 400 instead of 500 (#234)
- **Docker /v2/ auth** — require authentication per Docker V2 spec (#220)
- **Curation bypass token timing** — constant-time comparison using `subtle` crate (#230)
- **S3 paginated listing** — storage size calculation now handles >1000 objects correctly (#230)
- **Docker temp file cleanup** — upload temp files are removed on failure (#230)
- **OpenAPI schema deduplication** — removed 8 duplicate type definitions (#227)
- **OpenAPI status codes** — documented 400/409/413/422/503 responses that API already returns (#235)

### Changed
- Mobile-responsive UI — dashboard grid, hidden table columns on small screens, Raw registry "Files" tab (#218)
- Startup metric renamed to `startup_duration_ms` with Cold Start display on dashboard (#218)
- Guardrails: semver-checks, Renovate config, pre-commit hooks, clippy deny rules (#225)
- cargo-deny-action bumped to v2.0.17 (#231)

### Security
- Rate limiting hardening for token endpoints (#229)
- Curation completeness checks for all registry formats (#230)
- Raw registry glob pattern validation (#230)

## [0.7.3] - 2026-05-01

### Fixed
- **Docker /v2/ auth flow** — endpoint now correctly returns 401 Unauthorized with WWW-Authenticate header when auth is enabled. Previously, Docker clients received 200 OK without authentication, causing `docker login` to appear successful while `docker pull`/`docker push` failed with "unauthorized" (#219)
- **Raw registry curation bypass** — raw was the only registry without `check_download()`, completely bypassing curation enforce mode. All 13 registries are now curated consistently
- **Timing side-channel on bypass token** — replaced string comparison with constant-time comparison (`subtle` crate) to prevent timing attacks
- **Maven glob matching** — `com.evil.**` pattern now correctly matches `com.evil:lib` (colon separator for Maven groupId:artifactId)
- **Mobile dashboard** — responsive layout with 3-column stats grid, compact padding, and word-wrap on small screens

### Added
- **Raw directory browser** — nested navigation with breadcrumbs, folder/file icons, directories-first sorting. Browse raw artifacts at any depth
- **Docker Hub images** — NORA is now published to Docker Hub as `getnora/nora` alongside GHCR
- **Docker-Distribution-API-Version header** — `/v2/` response now includes `registry/2.0` header per Docker Registry V2 spec
- **Startup time metric** — `startup_duration_ms` exposed on dashboard (cold start tracking)
- 857 tests (up from 851)

## [0.7.2] - 2026-04-28

### Added
- **Publish date extraction** — curation min-release-age filter now extracts real publish dates from cached metadata for npm, PyPI, Cargo, and Go registries (#207)
- **Per-registry curation overrides** — configure min_release_age per registry via TOML (`[curation.npm] min_release_age = "3d"`) or env (`NORA_CURATION_NPM_MIN_RELEASE_AGE`) (#205)
- `parse_iso8601_to_unix()` helper for ISO 8601 / RFC 3339 date parsing across registry formats

### Fixed
- Raw registry: UI now updates immediately after upload/delete — added missing `repo_index.invalidate("raw")` calls (#212)

### Verified
- Token RBAC: `last_used` tracking (deferred flush), auto-expire rejection, description field — all functional (#206)

## [0.7.1] - 2026-04-27

### Added
- **Min-release-age filter** — block packages younger than N days/hours/weeks (#132). Config: `min_release_age = "7d"`, env `NORA_CURATION_MIN_RELEASE_AGE`
- **Token RBAC** — read/write/admin roles per token, expiry badges in UI, expired tokens sorted to bottom (#124)
- **Dynamic stats footer** — demo builds show live binary size, VmRSS, registry count from /proc (replaces hardcoded values)
- 850 total tests (up from 821)

### Changed
- Token list UI: expired tokens show red badge, sorted to bottom with reduced opacity
- `format_expiry()` replaces `format_timestamp()` for token expiry display — correctly shows "in 28d" for future, "expired 3d ago" for past
- `#[non_exhaustive]` on `Role` enum for forward compatibility

## [0.7.0] - 2026-04-27

### Added
- **Declarative registry selection** — `[registries] enable = ["docker","npm"]` / `"all"` / `["all","-maven"]`, env `NORA_REGISTRIES_ENABLE`, 3-tier priority (env > TOML > legacy)
- **Curation layer** — policy engine for download filtering across all 13 registries (#184-#190)
  - Blocklist/allowlist rules with glob patterns and namespace isolation
  - Three modes: `off` (passthrough), `audit` (log only), `enforce` (block downloads)
  - Integrity verification via SHA256/SHA512 checksums
  - CVE blocking via blocklist rules (manual CVE entries)
  - CLI tools: `nora curation validate`, `nora curation explain`
- RubyGems proxy registry (`/gems/`) — compact index, gem/gemspec immutable caching, TTL-based index refresh (#141)
- Terraform proxy registry (`/terraform/`) — provider/module proxy with service discovery, download_url rewriting (#133)
- Ansible Galaxy proxy registry (`/ansible/`) — Galaxy v3 API, collection tarball immutable caching (#134)
- NuGet v3 proxy registry (`/nuget/`) — service index @id URL rewriting, .nupkg/.nuspec immutable caching (#140)
- Pub (Dart/Flutter) proxy registry (`/pub/`) — package metadata URL rewriting, SHA256-verified archive caching (#166, based on PR #191 by @mit-73)
- Conan V2 proxy registry (`/conan/`) — recipe/package caching with immutable revision-scoped storage, ConanCenter upstream (#142)
- Dynamic registry loading — only enabled registries mount routes, appear in UI sidebar and health endpoint
- Per-registry `enabled` flag in config (env: `NORA_DOCKER_ENABLED`, `NORA_MAVEN_ENABLED`, etc.)
- Shared `RegistryType` enum for type-safe cross-module registry identification
- UI: 13-registry sidebar with format-specific SVG icons, dashboard cards for all registries
- Short-SHA Docker tags in CI builds (#182, #192)

### Changed
- Copyright updated to "The NORA Authors"
- OpenAPI spec version synced with Cargo.toml

## [0.6.5] - 2026-04-23

### Fixed
- UI install commands now respect `NORA_PUBLIC_URL` for all registries — PyPI, npm, Go, Raw, Docker (#177)
- Docker `WWW-Authenticate` realm uses `NORA_PUBLIC_URL` instead of hardcoded "Nora" (#177)
- PyPI simple index generates absolute download URLs using `NORA_PUBLIC_URL` (#177)

## [0.6.4] - 2026-04-22

### Fixed
- S3 storage mode: removed Dockerfile ENV override that forced local mode regardless of config.toml (#173)
- Audit log and dashboard metrics: create parent directories before file open (fixes crash with readOnlyRootFilesystem)
- Security: update rustls-webpki to 0.103.13 (RUSTSEC-2026-0104)
## [0.6.3] - 2026-04-19

### Fixed
- GC and Retention schedulers now share a cleanup lock preventing concurrent `storage.delete()` races (#164)
- Publish lock race conditions: Maven lock guard was inside if-block (P0), Cargo lock key was per-version instead of per-crate (P1), Docker pull counter lacked lock (P2) (#160)
- Raw registry enforces immutability — overwrites return 409 Conflict instead of silently replacing files (#162)
- Retention `dry_run=true` validation warning added (symmetric with GC) (#162)
- Flaky test: `validate()` read env var directly, parallel tests broke each other (#160)
- `llms.txt` mirror CLI examples corrected: `--image` → `--images`, `--package` → `--packages`, pip/cargo/maven use `--lockfile` (#161)

### Changed
- OpenAPI spec expanded: npm publish, Cargo publish, PyPI upload, Cargo sparse index, Docker manifest delete endpoints documented (#161, #163)
- README env var table expanded from 10 to 24 variables with full descriptions (#163)
- README mirror subcommand examples added for all 6 formats (#163)
- Maven auth column corrected from "proxy-only" to full auth support (#163)
- Coherence CI pipeline added: version sync, env var coverage, registry list, dead code budget, license check (#156)
- Negative integration tests added for auth and validation (#156)
- Config validation warns on Docker proxy credentials in env var (#157)
- Config validation warns on relative paths with explicit config (#154)
- Maven env var overrides added, S3 default port fixed to 9000 (#153)
- Docker pull counter added with publish lock (#160)
- `lock-audit.sh` script and Makefile targets added (#160)
- 633 total tests (up from 588)

## [0.6.2] - 2026-04-17

### Fixed
- Upgrade Alpine 3.20 → 3.21, patching 18 CVEs (5 HIGH: OpenSSL, musl, zlib-ng)

### Changed
- ArtifactHub logo added to Helm chart metadata

## [0.6.1] - 2026-04-17

### Added
- Helm chart support — `helm repo add nora https://getnora-io.github.io/helm-charts`

### Changed
- README updated for v0.6.0

## [0.6.0] - 2026-04-17

### Added
- **Maven registry** — immutable releases with publish mutex, checksum generation (MD5, SHA-1, SHA-256, SHA-512), `maven-metadata.xml` auto-generation
- **Retention policies** — `keep_last`, `older_than_days`, `exclude` patterns per registry; `retention-plan` (dry-run) and `retention-apply --yes` (safe-by-default)
- **Background retention scheduler** — `retention.enabled = true` with configurable interval, single-flight lock prevents overlapping runs
- **Retention Prometheus metrics** — `nora_retention_versions_deleted_total`, `nora_retention_bytes_freed_total`, `nora_retention_duration_seconds`, `nora_retention_last_run_timestamp`
- **GC expanded to all registries** — Go incomplete version detection (missing `.info` or `.zip`), Cargo index/crate cross-check, Maven/npm/PyPI checksum orphans, Docker blob orphans
- **GC/Retention visibility** — reports uncovered registries with file counts after each run
- **Go retention collector** — `keep_last` for Go modules, parsing `module/@v/version.{info,mod,zip}`
- **Audit log** — one entry per retention run with keys/bytes/duration
- 588 total tests (up from 577)

### Changed
- GC now requires `--apply` flag to delete (dry-run by default)
- Retention requires `--yes` to apply (plan-only by default)
- Binary size reduced from 60MB to 21MB (stripped debug symbols in release profile)
- `RetentionConfig` expanded with `enabled`, `interval` fields and env var overrides (`NORA_RETENTION_ENABLED`, `NORA_RETENTION_INTERVAL`)

### Fixed
- `md-5` crate aligned to `0.11` (compatible with `digest 0.11`), replacing `md5 0.7` which lacked `Digest` trait
- Clippy warnings cleaned up across all modules
- `dead_code` warning on `ArtifactMeta` suppressed
- Token sorting uses `sort_by_key` for stability

## [0.5.0] - 2026-04-07

### Added
- **Cargo sparse index (RFC 2789)** — cargo can now use NORA as a proper registry with `sparse+http://` protocol, including `config.json`, prefix-based index lookup, and `cargo publish` wire format support
- **Cargo publish** — full publish flow with wire format parsing, version immutability (409 Conflict), SHA-256 checksums in sparse index, and proper `warnings` response format
- **PyPI twine upload** — `twine upload` via multipart/form-data with SHA-256 verification, filename validation, and version immutability
- **PEP 691 JSON API** — content negotiation via `Accept: application/vnd.pypi.simple.v1+json` for package index and version listing, with hash digests in responses
- 577 total tests (up from 504), including 25 new Cargo tests and 18 new PyPI tests

### Fixed
- Go and Raw registries missing from Prometheus metrics (`detect_registry` labeled both as "other") (PR #97, @TickTockBent)
- Go and Raw registries missing from `/health` endpoint `registries` object (PR #97, @TickTockBent)
- Garbage collection scoped to Docker-only blobs — prevents GC from deleting non-Docker registry data (PR #109, @TickTockBent)
- Correct `zeroize` annotation placement and avoid secret cloning in `protected.rs` (PR #108, @TickTockBent)
- Cargo dependency field mapping: `version_req` correctly renamed to `req` and `explicit_name_in_toml` to `package` in sparse index entries, matching Cargo registry specification
- Cargo crate names normalized to lowercase across all endpoints (publish, download, metadata, sparse index) for consistent storage keys
- Cargo publish write ordering: index written before .crate tarball to prevent orphaned files on partial failure
- Cargo conflict errors now return Cargo-compatible JSON format (`{"errors": [{"detail": "..."}]}`)
- PyPI hash fragments preserved when rewriting upstream links (PEP 503 compliance)
- Redundant path traversal checks removed from crate name validation (charset already excludes unsafe characters)

### Changed
- Cargo sparse index and config.json responses include `Cache-Control: public, max-age=300`
- Cargo .crate downloads include `Cache-Control: public, max-age=31536000, immutable` and `Content-Type: application/x-tar`
- axum upgraded with `multipart` feature for PyPI upload support


## [0.4.0] - 2026-04-05

### Added
- **Docker image mirroring** — nora mirror docker fetches manifests and blobs from upstream registries (Docker Hub, ghcr.io, etc.) and pushes into NORA (#41)
- **yarn.lock support** — nora mirror yarn parses v1 format with scoped packages and dedup (#44)
- **--json output for mirror** — nora mirror npm --json outputs structured JSON for CI/CD pipelines (#43)
- **Storage size in /health** — total_size_bytes field in health endpoint response (#42)
- 499 total tests (up from 466), 61.5% code coverage (up from 43%)

### Changed
- fetch_blob_from_upstream and fetch_manifest_from_upstream are now pub for reuse in mirror module

### Fixed
- Go and Raw registries missing from Prometheus metrics (`detect_registry` labeled both as "other") (PR #97, @TickTockBent)
- Go and Raw registries missing from `/health` endpoint `registries` object (PR #97, @TickTockBent)
- Garbage collection scoped to Docker-only blobs — prevents GC from deleting non-Docker registry data (PR #109, @TickTockBent)
- Correct `zeroize` annotation placement and avoid secret cloning in `protected.rs` (PR #108, @TickTockBent)
- tarpaulin exclude-files paths corrected to workspace-relative (coverage jumped from 29% to 61%) (#92)
- Env var naming unified across all registries (#39, #90)

## [0.3.1] - 2026-04-05

### Added
- **Token verification cache** — in-memory with 5min TTL, eliminates repeated Argon2id on every request
- **Property-based tests** (proptest) for Docker/OCI manifest parsers (#84)
- 466 total tests, 43% code coverage (up from 22%) (#87)
- MSRV declared in Cargo.toml (#84)

### Changed
- Upload sessions moved from global static to AppState
- Blocking I/O replaced with async in hot paths
- Production docker-compose includes Caddy reverse proxy
- clippy.toml added for consistent lint rules

### Fixed
- Go and Raw registries missing from Prometheus metrics (`detect_registry` labeled both as "other") (PR #97, @TickTockBent)
- Go and Raw registries missing from `/health` endpoint `registries` object (PR #97, @TickTockBent)
- Garbage collection scoped to Docker-only blobs — prevents GC from deleting non-Docker registry data (PR #109, @TickTockBent)
- Correct `zeroize` annotation placement and avoid secret cloning in `protected.rs` (PR #108, @TickTockBent)
- Proxy request deduplication — concurrent requests coalesced (#83)
- Multi-registry GC now handles all 7 registry types (#83)
- TOCTOU race condition in credential validation (#83)
- Config validation at startup — fail fast with clear errors (#73)
- Raw registry in dashboard sidebar, footer stats updated (#64)
- tarpaulin.toml config format (#88)

### Security
- sha2 0.10→0.11, hmac 0.12→0.13 (#75)
- Credential hygiene — cleared from memory after use (#83)
- cosign-installer 3.8.0→4.1.1 (#71)

### Documentation
- Development Setup in CONTRIBUTING.md (#76)
- Roadmap consolidated into README (#65, #66)
- Helm OCI docs and logging env vars documented

## [0.3.0] - 2026-03-21

### Added
- **Go module proxy** — full GOPROXY protocol support (list, info, mod, zip, latest) (#59)
- **Upstream proxy retry** with configurable timeout and backoff (#56)
- **Maven proxy-only mode** — proxy Maven artifacts without local storage (#56)
- **Anonymous read mode** docs — Go proxy section in README (#62)
- Integration tests: Docker push/pull, npm install, upstream timeout (#57)
- Go proxy and Raw registry integration tests in smoke suite (#72)
- Config validation at startup — clear errors instead of runtime panics
- Dockerfile HEALTHCHECK for standalone deployments (#72)
- rust-toolchain.toml for reproducible builds (#72)

### Changed
- **Token hashing migrated from SHA-256 to Argon2id** — existing tokens auto-migrate on first use (#55)
- UI: Raw registry in sidebar, footer stats updated (32MB, 7 registries) (#64)
- README restructured: roadmap in README, removed stale ROADMAP.md (#65, #66)

### Fixed
- Go and Raw registries missing from Prometheus metrics (`detect_registry` labeled both as "other") (PR #97, @TickTockBent)
- Go and Raw registries missing from `/health` endpoint `registries` object (PR #97, @TickTockBent)
- Garbage collection scoped to Docker-only blobs — prevents GC from deleting non-Docker registry data (PR #109, @TickTockBent)
- Correct `zeroize` annotation placement and avoid secret cloning in `protected.rs` (PR #108, @TickTockBent)
- Remove all unwrap() from production code — proper error handling throughout (#72)
- Add `#![forbid(unsafe_code)]` — no unsafe code allowed at crate level (#72)
- Add input validation to Cargo registry endpoints (#72)
- Improve expect() messages with descriptive context (#72)
- Remove 7 unnecessary clone() calls (#72)
- Restore .gitleaks.toml lost during merge (#58)
- Update SECURITY.md — add 0.3.x to supported versions (#72)

### Security
- Update rustls-webpki 0.103.9 → 0.103.10 (RUSTSEC-2026-0049)
- Argon2id token hashing replaces SHA-256 (#55)
- `#![forbid(unsafe_code)]` enforced (#72)
- Zero unwrap() in production code (#72)

## [0.2.35] - 2026-03-20

### Added
- **Anonymous read mode** (`NORA_AUTH_ANONYMOUS_READ=true`): allow pull/download without credentials while requiring auth for push. Use case: public demo registries, read-only mirrors.

### Fixed
- Go and Raw registries missing from Prometheus metrics (`detect_registry` labeled both as "other") (PR #97, @TickTockBent)
- Go and Raw registries missing from `/health` endpoint `registries` object (PR #97, @TickTockBent)
- Garbage collection scoped to Docker-only blobs — prevents GC from deleting non-Docker registry data (PR #109, @TickTockBent)
- Correct `zeroize` annotation placement and avoid secret cloning in `protected.rs` (PR #108, @TickTockBent)
- Pin slsa-github-generator and codeql-action by SHA instead of tag
- Replace anonymous tuple with named struct in activity grouping (readability)
- Replace unwrap() with if-let pattern in activity grouping (safety)
- Add warning message on SLSA attestation failure instead of silent suppression

## [0.2.34] - 2026-03-20

### Fixed
- Go and Raw registries missing from Prometheus metrics (`detect_registry` labeled both as "other") (PR #97, @TickTockBent)
- Go and Raw registries missing from `/health` endpoint `registries` object (PR #97, @TickTockBent)
- Garbage collection scoped to Docker-only blobs — prevents GC from deleting non-Docker registry data (PR #109, @TickTockBent)
- Correct `zeroize` annotation placement and avoid secret cloning in `protected.rs` (PR #108, @TickTockBent)
- **UI**: Group consecutive identical activity entries — repeated cache hits show as "artifact (x4)" instead of 4 identical rows
- **UI**: Fix table cell padding in Mount Points and Activity tables — th/td alignment now consistent
- **Security**: Update tar crate 0.4.44 → 0.4.45 (CVE-2026-33055 PAX size header bypass, CVE-2026-33056 symlink chmod traversal)

### Added
- 82 new unit tests across 7 modules (activity_log, audit, config, dashboard_metrics, error, metrics, repo_index)
- Test coverage badge in README (12.55% → 21.56%)
- Dashboard GIF (EN/RU crossfade) in README
- 7 missing environment variables added to docs (NORA_PUBLIC_URL, S3 credentials, NPM_METADATA_TTL, Raw config)

### Changed
- README restructured: tagline + docker run + GIF first, badges moved to Security section
- Remove hardcoded OpenSSF Scorecard version from README


## [0.2.33] - 2026-03-19

### Security
- Verify blob digest (SHA256) on upload — reject mismatches with DIGEST_INVALID error
- Reject sha512 digests (only sha256 supported for blob uploads)
- Add upload session limits: max 100 concurrent, 2GB per session, 30min TTL (configurable via NORA_MAX_UPLOAD_SESSIONS, NORA_MAX_UPLOAD_SESSION_SIZE_MB)
- Bind upload sessions to repository name (prevent session fixation attacks)
- Add security headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- Run containers as non-root user (USER nora) in all Dockerfiles

### Fixed
- Go and Raw registries missing from Prometheus metrics (`detect_registry` labeled both as "other") (PR #97, @TickTockBent)
- Go and Raw registries missing from `/health` endpoint `registries` object (PR #97, @TickTockBent)
- Garbage collection scoped to Docker-only blobs — prevents GC from deleting non-Docker registry data (PR #109, @TickTockBent)
- Correct `zeroize` annotation placement and avoid secret cloning in `protected.rs` (PR #108, @TickTockBent)
- Filter .meta.json from Docker tag list (fixes ArgoCD Image Updater tag recursion)
- Fix catalog endpoint to show namespaced images correctly (library/alpine instead of library)

### Added
- CodeQL workflow for SAST analysis
- SLSA provenance attestation for release artifacts

### Changed
- Configurable upload session size for ML models via NORA_MAX_UPLOAD_SESSION_SIZE_MB (default 2048 MB)

## [0.2.32] - 2026-03-18

### Fixed / Исправлено
- **Docker dashboard**: Namespaced images (library/alpine, grafana/grafana) now visible in UI — index builder finds manifests by position, not fixed index
- **Docker proxy**: Auto-prepend `library/` for single-segment official Hub images (nginx, alpine, node) — no need to explicitly use library/ prefix
- **CI**: Fixed cargo-deny license checks (NCSA for libfuzzer-sys, MIT for fuzz crate, unused-allowed-license config)
- **Docker dashboard**: Namespaced-образы (library/alpine, grafana/grafana) теперь отображаются в UI
- **Docker proxy**: Автоподстановка `library/` для официальных образов Docker Hub (nginx, alpine, node) — больше не нужно указывать library/ вручную
- **CI**: Исправлены проверки лицензий cargo-deny


## [0.2.31] - 2026-03-16

### Added / Добавлено
- **npm URL rewriting**: Tarball URLs in proxied metadata now rewritten to point to NORA (previously tarballs bypassed NORA and downloaded directly from npmjs.org)
- **npm scoped packages**: Full support for `@scope/package` in proxy handler and repository index
- **npm publish**: `PUT /npm/{package}` accepts standard npm publish payload with base64-encoded tarballs
- **npm metadata TTL**: Configurable cache TTL (`NORA_NPM_METADATA_TTL`, default 300s) with stale-while-revalidate fallback
- **Immutable cache**: SHA256 integrity verification on cached npm tarballs — detects tampering on cache hit
- **npm URL rewriting**: Tarball URL в проксированных метаданных теперь переписываются на NORA (ранее тарболы шли напрямую из npmjs.org)
- **npm scoped packages**: Полная поддержка `@scope/package` в прокси-хендлере и индексе репозитория
- **npm publish**: `PUT /npm/{package}` принимает стандартный npm publish payload с base64-тарболами
- **npm metadata TTL**: Настраиваемый TTL кеша (`NORA_NPM_METADATA_TTL`, default 300s) с stale-while-revalidate
- **Immutable cache**: SHA256 проверка целостности npm-тарболов — обнаружение подмены при отдаче из кеша

### Security / Безопасность
- **Path traversal protection**: Attachment filename validation in npm publish (rejects `../`, `/`, `\`)
- **Package name mismatch**: npm publish rejects payloads where URL path doesn't match `name` field (anti-spoofing)
- **Version immutability**: npm publish returns 409 Conflict on duplicate version
- **Защита от path traversal**: Валидация имён файлов в npm publish (отклоняет `../`, `/`, `\`)
- **Проверка имени пакета**: npm publish отклоняет payload если имя в URL не совпадает с полем `name` (anti-spoofing)
- **Иммутабельность версий**: npm publish возвращает 409 Conflict при попытке перезаписать версию

### Fixed / Исправлено
- **npm proxy_auth**: `proxy_auth` field was configured but not wired into `fetch_from_proxy` — now sends Basic Auth header to upstream
- **npm proxy_auth**: Поле `proxy_auth` было в конфиге, но не передавалось в `fetch_from_proxy` — теперь отправляет Basic Auth в upstream


---

## [0.2.30] - 2026-03-16

### Fixed / Исправлено
- **Dashboard**: Docker upstream now shown in mount points table (was null)
- **Dashboard**: Docker namespaced repositories (library/alpine, grafana/grafana) now visible in UI
- **Dashboard**: npm proxy-cached packages now appear in package list
- **Dashboard**: Отображение Docker upstream в таблице точек монтирования (было null)
- **Dashboard**: Namespaced Docker-репозитории (library/alpine, grafana/grafana) теперь видны в UI
- **Dashboard**: npm-пакеты из прокси-кеша теперь отображаются в списке пакетов

## [0.2.29] - 2026-03-15

### Added / Добавлено
- **Upstream Authentication**: All registry proxies now support Basic Auth credentials for private upstream registries
- **Аутентификация upstream**: Все прокси реестров теперь поддерживают Basic Auth для приватных upstream-реестров
  - Docker: `NORA_DOCKER_UPSTREAMS="https://registry.corp.com|user:pass"`
  - Maven: `NORA_MAVEN_PROXIES="https://nexus.corp.com/maven2|user:pass"`
  - npm: `NORA_NPM_PROXY_AUTH="user:pass"`
  - PyPI: `NORA_PYPI_PROXY_AUTH="user:pass"`
- **Plaintext credential warning**: NORA logs a warning at startup if credentials are stored in config.toml instead of env vars
- **Предупреждение о plaintext credentials**: NORA логирует предупреждение при старте, если credentials хранятся в config.toml вместо переменных окружения

### Changed / Изменено
- Extracted `basic_auth_header()` helper for consistent auth across all protocols
- Вынесен хелпер `basic_auth_header()` для единообразной авторизации всех протоколов

### Removed / Удалено
- Removed unused `DockerAuth::fetch_with_auth()` method (dead code cleanup)
- Удалён неиспользуемый метод `DockerAuth::fetch_with_auth()` (очистка мёртвого кода)
## [0.2.28] - 2026-03-13

### Fixed / Исправлено
- **docker-compose.yml**: Fixed image reference from `getnora/nora:latest` to `ghcr.io/getnora-io/nora:latest`
- **docker-compose.yml**: Исправлена ссылка на образ с `getnora/nora:latest` на `ghcr.io/getnora-io/nora:latest`

### Documentation / Документация
- **Authentication Guide**: Added complete auth setup guide in README — htpasswd, API tokens, RBAC roles, curl examples
- **Руководство по аутентификации**: Добавлено полное руководство по настройке auth в README — htpasswd, API-токены, RBAC-роли, примеры curl
- **FSTEC builds**: Documented `Dockerfile.astra` and `Dockerfile.redos` purpose in README
- **Сборки ФСТЭК**: Документировано назначение `Dockerfile.astra` и `Dockerfile.redos` в README
- **TLS / HTTPS**: Added reverse proxy setup guide (Caddy, Nginx) and `insecure-registries` Docker config for internal deployments
- **TLS / HTTPS**: Добавлено руководство по настройке reverse proxy (Caddy, Nginx) и конфигурация `insecure-registries` Docker для внутренних инсталляций

### Removed / Удалено
- Removed stale `CHANGELOG.md.bak` from repository
- Удалён устаревший `CHANGELOG.md.bak` из репозитория
## [0.2.27] - 2026-03-03

### Added / Добавлено
- **Configurable body limit**: `NORA_BODY_LIMIT_MB` env var (default: `2048` = 2GB) — replaces hardcoded 100MB limit that caused `413 Payload Too Large` on large Docker image push
- **Настраиваемый лимит тела запроса**: переменная `NORA_BODY_LIMIT_MB` (по умолчанию: `2048` = 2GB) — заменяет захардкоженный лимит 100MB, вызывавший `413 Payload Too Large` при push больших Docker-образов
- **Docker Delete API**: `DELETE /v2/{name}/manifests/{reference}` and `DELETE /v2/{name}/blobs/{digest}` per Docker Registry V2 spec (returns 202 Accepted)
- **Docker Delete API**: `DELETE /v2/{name}/manifests/{reference}` и `DELETE /v2/{name}/blobs/{digest}` по спецификации Docker Registry V2 (возвращает 202 Accepted)
- Namespace-qualified DELETE variants (`/v2/{ns}/{name}/...`)
- Audit log integration for delete operations

### Fixed / Исправлено
- Docker push of images >100MB no longer fails with 413 error
- Push Docker-образов >100MB больше не падает с ошибкой 413
## [0.2.26] - 2026-03-03

### Added / Добавлено
- **Helm OCI support**: `helm push` / `helm pull` now works out of the box via OCI protocol
- **Поддержка Helm OCI**: `helm push` / `helm pull` теперь работают из коробки через OCI протокол
- **RBAC**: Token-based role system with three roles — `read`, `write`, `admin` (default: `read`)
- **RBAC**: Ролевая система на основе токенов — `read`, `write`, `admin` (по умолчанию: `read`)
- **Audit log**: Persistent append-only JSONL audit trail for all registry operations (`{storage}/audit.jsonl`)
- **Аудит**: Персистентный append-only JSONL лог всех операций реестра (`{storage}/audit.jsonl`)
- **GC command**: `nora gc --dry-run` — garbage collection for orphaned blobs (mark-and-sweep)
- **Команда GC**: `nora gc --dry-run` — сборка мусора для осиротевших блобов (mark-and-sweep)

### Fixed / Исправлено
- **Helm OCI pull**: Fixed OCI manifest media type detection — manifests with non-Docker `config.mediaType` now correctly return `application/vnd.oci.image.manifest.v1+json`
- **Helm OCI pull**: Исправлено определение media type OCI манифестов — манифесты с не-Docker `config.mediaType` теперь корректно возвращают `application/vnd.oci.image.manifest.v1+json`
- **Docker-Content-Digest**: Added missing header in blob upload response (required by Helm OCI client)
- **Docker-Content-Digest**: Добавлен отсутствующий заголовок в ответе на загрузку blob (требуется клиентом Helm OCI)

### Security / Безопасность
- Read-only tokens (`role: read`) are now blocked from PUT/POST/DELETE/PATCH operations with HTTP 403
- Токены только для чтения (`role: read`) теперь блокируются при PUT/POST/DELETE/PATCH с HTTP 403
## [0.2.25] - 2026-03-03

### Fixed / Исправлено
- **Rate limiter fix**: Added `NORA_RATE_LIMIT_ENABLED` env var (default: `true`) to disable rate limiting on internal deployments
- **Исправление rate limiter**: Добавлена переменная `NORA_RATE_LIMIT_ENABLED` (по умолчанию: `true`) для отключения rate limiting на внутренних инсталляциях
- **SmartIpKeyExtractor**: Upload and general routes now use `SmartIpKeyExtractor` (reads `X-Forwarded-For`) instead of `PeerIpKeyExtractor` — fixes 429 errors behind reverse proxy / Docker bridge
- **SmartIpKeyExtractor**: Маршруты upload и general теперь используют `SmartIpKeyExtractor` (читает `X-Forwarded-For`) вместо `PeerIpKeyExtractor` — устраняет ошибки 429 за reverse proxy / Docker bridge

### Dependencies / Зависимости
- `clap` 4.5.56 → 4.5.60
- `uuid` 1.20.0 → 1.21.0
- `tempfile` 3.24.0 → 3.26.0
- `bcrypt` 0.17.1 → 0.18.0
- `indicatif` 0.17.11 → 0.18.4

### CI/CD
- `actions/checkout` 4 → 6
- `actions/upload-artifact` 4 → 7
- `softprops/action-gh-release` 1 → 2
- `aquasecurity/trivy-action` 0.30.0 → 0.34.2
- `docker/build-push-action` 5 → 6
- Move scan/release to self-hosted runner with NORA cache
- Сканирование/релиз перенесены на self-hosted runner с кэшем через NORA
## [0.2.24] - 2026-02-24

### Added / Добавлено
- `install.sh` installer script live at <https://getnora.io/install.sh> — `curl -fsSL https://getnora.io/install.sh | sh`
- Скрипт установки `install.sh` доступен на <https://getnora.io/install.sh>

### CI/CD
- Restore Astra Linux SE Docker image build, Trivy scan, and release artifact (`-astra` tag)
- Восстановлена сборка Docker-образа для Astra Linux SE, сканирование Trivy и артефакт релиза (тег `-astra`)
## [0.2.23] - 2026-02-24

### Added / Добавлено
- Binary (`nora`) + SHA-256 checksum attached to every GitHub Release
- Бинарник (`nora`) и SHA-256 контрольная сумма прикреплены к каждому релизу GitHub

### Fixed / Исправлено
- Security: bump `prometheus` 0.13 → 0.14 (CVE-2025-53605) and `bytes` 1.11.0 → 1.11.1 (CVE-2026-25541)
- Безопасность: обновлены `prometheus` 0.13 → 0.14 (CVE-2025-53605) и `bytes` 1.11.0 → 1.11.1 (CVE-2026-25541)

### CI/CD
- Add Dependabot for automated dependency updates / Добавлен Dependabot для автоматического обновления зависимостей
- Pin `aquasecurity/trivy-action` to `0.30.0`, bump to `0.34.1`; scan gate blocks release on HIGH/CRITICAL CVE
- Закреплён `trivy-action@0.30.0`, обновлён до `0.34.1`; сканирование блокирует релиз при HIGH/CRITICAL CVE
- Upgrade `codeql-action` v3 → v4 / Обновлён `codeql-action` v3 → v4
- Fix `deny.toml` deprecated keys (`copyleft`, `unlicensed` removed in `cargo-deny`) / Исправлены устаревшие ключи в `deny.toml`
- Fix binary path in Docker image (`/usr/local/bin/nora`) / Исправлен путь бинарника в Docker-образе
- Pin build job to `nora` runner label / Джоб сборки закреплён за runner'ом с меткой `nora`
- Allow `CDLA-Permissive-2.0` license (`webpki-roots`) / Разрешена лицензия `CDLA-Permissive-2.0`
- Ignore `RUSTSEC-2025-0119` (unmaintained transitive dep `number_prefix` via `indicatif`)

### Dependencies / Зависимости
- `chrono` 0.4.43 → 0.4.44
- `quick-xml` 0.31.0 → 0.39.2
- `toml` 0.8.23 → 1.0.3+spec-1.1.0
- `flate2` 1.1.8 → 1.1.9
- `softprops/action-gh-release` 1 → 2
- `actions/checkout` 4 → 6
- `docker/build-push-action` 5 → 6

### Documentation / Документация
- Replace text title with SVG logo; `O` styled in blue-600 / Заголовок заменён SVG-логотипом; буква `O` стилизована в blue-600
## [0.2.22] - 2026-02-24

### Changed / Изменено
- First stable release with Docker images published to container registry
- Первый стабильный релиз с Docker-образами, опубликованными в container registry
## [0.2.21] - 2026-02-24

### CI/CD
- Consolidate all Docker builds into a single job to fix runner network issues / Все Docker-сборки объединены в один job для устранения сетевых проблем runner'а
- Build musl static binary for maximum portability / Сборка musl-бинарника для максимальной переносимости
- Add security scanning (Trivy) + SBOM generation to release pipeline / Добавлено сканирование безопасности (Trivy) и генерация SBOM в pipeline релиза
- Add Cargo cache to speed up builds / Добавлен кэш Cargo для ускорения сборок
- Replace `gitleaks` GitHub Action with CLI (no license requirement) / `gitleaks` Action заменён CLI-вызовом (лицензия не требуется)
- Use GitHub-runner's own Rust toolchain (avoid path conflicts) / Используется Rust toolchain самого GitHub-runner'а
- Use shared runner filesystem instead of artifact API (avoids network upload latency) / Общая файловая система runner'а вместо artifact API
- Remove Astra Linux build temporarily / Сборка для Astra Linux временно удалена
## [0.2.20] - 2026-02-23

### Added / Добавлено
- Parallel CI builds for Astra Linux and RedOS / Параллельная сборка в CI для Astra Linux и RedOS

### Changed / Изменено
- Use `FROM scratch` base image for Astra Linux and RedOS Docker builds / Базовый образ `FROM scratch` для Docker-сборок Astra Linux и RedOS
- Shared `reqwest::Client` across all registry handlers / Общий `reqwest::Client` для всех registry-обработчиков

### Fixed / Исправлено
- Auth: replace `starts_with` with explicit `matches!` for token path checks / Аутентификация: `starts_with` заменён явной проверкой `matches!` для путей с токенами
- Remove unnecessary QEMU step for amd64-only builds / Удалён лишний шаг QEMU для amd64-сборок
## [0.2.19] - 2026-01-31

### Added / Добавлено
- Pre-commit hook to prevent accidental commits of sensitive files / Pre-commit хук для защиты от случайного коммита чувствительных файлов
- README badges: build status, version, license / Бейджи в README: статус сборки, версия, лицензия

### Performance / Производительность
- In-memory repository index with pagination for faster dashboard load / Индекс репозитория в памяти с пагинацией для ускорения загрузки дашборда

### Fixed / Исправлено
- Use `div_ceil` instead of manual ceiling division / Использован `div_ceil` вместо ручной реализации деления с округлением вверх
## [0.2.18] - 2026-01-31

### Changed
- Logo styling refinements
## [0.2.17] - 2026-01-31

### Added
- Copyright headers to all source files (Volkov Pavel | DevITWay)
- SPDX-License-Identifier: MIT in all .rs files
## [0.2.16] - 2026-01-31

### Changed
- N○RA branding: stylized O logo across dashboard
- Fixed O letter alignment in logo
## [0.2.15] - 2026-01-31

### Fixed
- Go and Raw registries missing from Prometheus metrics (`detect_registry` labeled both as "other") (PR #97, @TickTockBent)
- Go and Raw registries missing from `/health` endpoint `registries` object (PR #97, @TickTockBent)
- Garbage collection scoped to Docker-only blobs — prevents GC from deleting non-Docker registry data (PR #109, @TickTockBent)
- Correct `zeroize` annotation placement and avoid secret cloning in `protected.rs` (PR #108, @TickTockBent)
- Code formatting (cargo fmt)
## [0.2.14] - 2026-01-31

### Fixed
- Go and Raw registries missing from Prometheus metrics (`detect_registry` labeled both as "other") (PR #97, @TickTockBent)
- Go and Raw registries missing from `/health` endpoint `registries` object (PR #97, @TickTockBent)
- Garbage collection scoped to Docker-only blobs — prevents GC from deleting non-Docker registry data (PR #109, @TickTockBent)
- Correct `zeroize` annotation placement and avoid secret cloning in `protected.rs` (PR #108, @TickTockBent)
- Docker dashboard now shows actual image size from manifest layers (config + layers sum)
- Previously showed only manifest file size (~500 B instead of actual image size)
## [0.2.13] - 2026-01-31

### Fixed
- Go and Raw registries missing from Prometheus metrics (`detect_registry` labeled both as "other") (PR #97, @TickTockBent)
- Go and Raw registries missing from `/health` endpoint `registries` object (PR #97, @TickTockBent)
- Garbage collection scoped to Docker-only blobs — prevents GC from deleting non-Docker registry data (PR #109, @TickTockBent)
- Correct `zeroize` annotation placement and avoid secret cloning in `protected.rs` (PR #108, @TickTockBent)
- npm dashboard now shows correct version count and package sizes
- Parses metadata.json for versions, dist.unpackedSize, and time.modified
- Previously showed 0 versions / 0 B for all packages
## [0.2.12] - 2026-01-30

### Added

#### Configurable Rate Limiting
- Rate limits now configurable via `config.toml` and environment variables
- New config section `[rate_limit]` with parameters: `auth_rps`, `auth_burst`, `upload_rps`, `upload_burst`, `general_rps`, `general_burst`
- Environment variables: `NORA_RATE_LIMIT_{AUTH|UPLOAD|GENERAL}_{RPS|BURST}`

#### Secrets Provider Architecture
- Trait-based secrets management (`SecretsProvider` trait)
- ENV provider as default (12-Factor App pattern)
- Protected secrets with `zeroize` (memory zeroed on drop)
- Redacted Debug impl prevents secret leakage in logs
- New config section `[secrets]` with `provider` and `clear_env` options

#### Docker Image Metadata
- Support for image metadata retrieval

#### Documentation
- Bilingual onboarding guide (EN/RU)
## [0.2.11] - 2026-01-26

### Added
- Internationalization (i18n) support
- PyPI registry proxy
- UI improvements
## [0.2.10] - 2026-01-26

### Changed
- Dark theme applied to all UI pages
## [0.2.9] - 2026-01-26

### Changed
- Version bump release
## [0.2.8] - 2026-01-26

### Added
- Dashboard endpoint added to OpenAPI documentation
## [0.2.7] - 2026-01-26

### Added
- Dynamic version display in UI sidebar
## [0.2.6] - 2026-01-26

### Added

#### Dashboard Metrics
- Global stats panel: downloads, uploads, artifacts, cache hit rate, storage
- Extended registry cards with artifact count, size, counters
- Activity log (last 20 events)

#### UI
- Dark theme (bg: #0f172a, cards: #1e293b)
## [0.2.5] - 2026-01-26

### Fixed
- Go and Raw registries missing from Prometheus metrics (`detect_registry` labeled both as "other") (PR #97, @TickTockBent)
- Go and Raw registries missing from `/health` endpoint `registries` object (PR #97, @TickTockBent)
- Garbage collection scoped to Docker-only blobs — prevents GC from deleting non-Docker registry data (PR #109, @TickTockBent)
- Correct `zeroize` annotation placement and avoid secret cloning in `protected.rs` (PR #108, @TickTockBent)
- Docker push/pull: added PATCH endpoint for chunked uploads
## [0.2.4] - 2026-01-26

### Fixed
- Go and Raw registries missing from Prometheus metrics (`detect_registry` labeled both as "other") (PR #97, @TickTockBent)
- Go and Raw registries missing from `/health` endpoint `registries` object (PR #97, @TickTockBent)
- Garbage collection scoped to Docker-only blobs — prevents GC from deleting non-Docker registry data (PR #109, @TickTockBent)
- Correct `zeroize` annotation placement and avoid secret cloning in `protected.rs` (PR #108, @TickTockBent)
- Rate limiting: health/metrics endpoints now exempt
- Increased upload rate limits for Docker parallel requests
## [0.2.0] - 2026-01-25

### Added

#### UI: SVG Brand Icons
- Replaced emoji icons with proper SVG brand icons (Simple Icons style)
- Docker, Maven, npm, Cargo, PyPI icons now render as scalable vector graphics
- Consistent icon styling across dashboard, sidebar, and detail pages

#### Testing Infrastructure
- Unit tests for LocalStorage (8 tests): put/get, list, stat, health_check
- Unit tests for S3Storage with wiremock HTTP mocking (11 tests)
- Integration tests for auth/htpasswd (7 tests)
- Token lifecycle tests (11 tests)
- Validation tests (21 tests)
- **Total: 75 tests passing**

#### Security: Input Validation (`validation.rs`)
- Path traversal protection: rejects `../`, `..\\`, null bytes, absolute paths
- Docker image name validation per OCI distribution spec
- Content digest validation (`sha256:[64 hex]`, `sha512:[128 hex]`)
- Docker tag/reference validation
- Storage key length limits (max 1024 chars)

#### Security: Rate Limiting (`rate_limit.rs`)
- Auth endpoints: 1 req/sec, burst 5 (brute-force protection)
- Upload endpoints: 10 req/sec, burst 20
- General endpoints: 100 req/sec, burst 200
- Uses `tower_governor` 0.8 with `PeerIpKeyExtractor`

#### Observability: Request ID Tracking (`request_id.rs`)
- `X-Request-ID` header added to all responses
- Accepts upstream request ID or generates UUID v4
- Tracing spans include request_id for log correlation

#### CLI: Migrate Command (`migrate.rs`)
- `nora migrate --from local --to s3` - migrate between storage backends
- `--dry-run` flag for preview without copying
- Progress bar with indicatif
- Skips existing files in destination
- Summary statistics (migrated, skipped, failed, bytes)

#### Error Handling (`error.rs`)
- `AppError` enum with `IntoResponse` for Axum
- Automatic conversion from `StorageError` and `ValidationError`
- JSON error responses with request_id support

### Changed
- `StorageError` now uses `thiserror` derive macro
- `TokenError` now uses `thiserror` derive macro
- Storage wrapper validates keys before delegating to backend
- Docker registry handlers validate name, digest, reference inputs
- Body size limit set to 100MB default via `DefaultBodyLimit`

### Dependencies Added
- `thiserror = "2"` - typed error handling
- `tower_governor = "0.8"` - rate limiting
- `governor = "0.10"` - rate limiting backend
- `tempfile = "3"` (dev) - temporary directories for tests
- `wiremock = "0.6"` (dev) - HTTP mocking for S3 tests

### Files Added
- `src/validation.rs` - input validation module
- `src/migrate.rs` - storage migration module
- `src/error.rs` - application error types
- `src/request_id.rs` - request ID middleware
- `src/rate_limit.rs` - rate limiting configuration
## [0.1.0] - 2026-01-24

### Added
- Multi-protocol support: Docker Registry v2, Maven, npm, Cargo, PyPI
- Web UI dashboard
- Swagger UI (`/api-docs`)
- Storage backends: Local filesystem, S3-compatible
- Smart proxy/cache for Maven and npm
- Health checks (`/health`, `/ready`)
- Basic authentication (htpasswd with bcrypt)
- API tokens (revocable, per-user)
- Prometheus metrics (`/metrics`)
- JSON structured logging
- Environment variable configuration
- Graceful shutdown (SIGTERM/SIGINT)
- Backup/restore commands
