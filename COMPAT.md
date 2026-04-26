# NORA Registry Protocol Compatibility

This document describes which parts of each registry protocol are implemented in NORA.

**Legend:** Full = complete implementation, Partial = basic support with limitations, Stub = placeholder, — = not implemented

## Docker (OCI Distribution Spec 1.1)

| Endpoint | Method | Status | Notes |
|----------|--------|--------|-------|
| `/v2/` | GET | Full | API version check |
| `/v2/_catalog` | GET | Full | List all repositories |
| `/v2/{name}/tags/list` | GET | Full | List image tags |
| `/v2/{name}/manifests/{ref}` | GET | Full | By tag or digest |
| `/v2/{name}/manifests/{ref}` | HEAD | Full | Check manifest exists |
| `/v2/{name}/manifests/{ref}` | PUT | Full | Push manifest |
| `/v2/{name}/manifests/{ref}` | DELETE | Full | Delete manifest |
| `/v2/{name}/blobs/{digest}` | GET | Full | Download layer/config |
| `/v2/{name}/blobs/{digest}` | HEAD | Full | Check blob exists |
| `/v2/{name}/blobs/{digest}` | DELETE | Full | Delete blob |
| `/v2/{name}/blobs/uploads/` | POST | Full | Start chunked upload |
| `/v2/{name}/blobs/uploads/{uuid}` | PATCH | Full | Upload chunk |
| `/v2/{name}/blobs/uploads/{uuid}` | PUT | Full | Complete upload |
| Namespaced `{ns}/{name}` | * | Full | Two-level paths |
| Deep paths `a/b/c/name` | * | — | Max 2-level (`org/image`) |
| Token auth (Bearer) | — | Full | WWW-Authenticate challenge |
| Cross-repo blob mount | POST | — | Not implemented |
| Referrers API | GET | — | OCI 1.1 referrers |

### Known Limitations
- Max 2-level image path: `org/image:tag` works, `org/sub/path/image:tag` returns 404
- Large monolithic blob PUT (>~500MB) may fail even with high body limit
- No cross-repository blob mounting

## npm

| Feature | Status | Notes |
|---------|--------|-------|
| Package metadata (GET) | Full | JSON with all versions |
| Scoped packages `@scope/name` | Full | URL-encoded path |
| Tarball download | Full | SHA256 verified |
| Tarball URL rewriting | Full | Points to NORA, not upstream |
| Publish (`npm publish`) | Full | Immutable versions |
| Unpublish | — | Not implemented |
| Dist-tags (`latest`, `next`) | Partial | Read from metadata, no explicit management |
| Search (`/-/v1/search`) | — | Not implemented |
| Audit (`/-/npm/v1/security/advisories`) | — | Not implemented |
| Upstream proxy | Full | Configurable TTL |

## Maven

| Feature | Status | Notes |
|---------|--------|-------|
| Artifact download (GET) | Full | JAR, POM, checksums |
| Artifact upload (PUT) | Full | Any file type |
| GroupId path layout | Full | Dots → slashes |
| SHA1/MD5 checksums | Full | Stored alongside artifacts |
| `maven-metadata.xml` | Partial | Stored as-is, no auto-generation |
| SNAPSHOT versions | — | No SNAPSHOT resolution |
| Multi-proxy fallback | Full | Tries proxies in order |
| Content-Type by extension | Full | .jar, .pom, .xml, .sha1, .md5 |

### Known Limitations
- `maven-metadata.xml` not auto-generated on publish (must be uploaded explicitly)
- No SNAPSHOT version management (`-SNAPSHOT` → latest timestamp)

## Cargo (Sparse Index, RFC 2789)

| Feature | Status | Notes |
|---------|--------|-------|
| `config.json` | Full | `dl` and `api` fields |
| Sparse index lookup | Full | Prefix rules (1/2/3/ab/cd) |
| Crate download | Full | `.crate` files by version |
| `cargo publish` | Full | Length-prefixed JSON + .crate |
| Dependency metadata | Full | `req`, `package` transforms |
| SHA256 verification | Full | On publish |
| Cache-Control headers | Full | `immutable` for downloads, `max-age=300` for index |
| Yank/unyank | — | Not implemented |
| Owner management | — | Not implemented |
| Categories/keywords | Partial | Stored but not searchable |

## PyPI (PEP 503/691)

| Feature | Status | Notes |
|---------|--------|-------|
| Simple index (HTML) | Full | PEP 503 |
| Simple index (JSON) | Full | PEP 691, via Accept header |
| Package versions page | Full | HTML + JSON |
| File download | Full | Wheel, sdist, egg |
| `twine upload` | Full | Multipart form-data |
| SHA256 hashes | Full | In metadata links |
| Case normalization | Full | `My-Package` → `my-package` |
| Upstream proxy | Full | Configurable TTL |
| JSON API metadata | Full | `application/vnd.pypi.simple.v1+json` |
| Yanking | — | Not implemented |
| Upload signatures (PGP) | — | Not implemented |

## pub.dev (Hosted Repository v2)

| Feature | Status | Notes |
|---------|--------|-------|
| Package search | Full | `GET /api/packages?q=...` |
| Package metadata | Full | `GET /api/packages/{package}` |
| Version metadata | Full | `GET /api/packages/{package}/versions/{version}` |
| Security advisories | Full | `GET /api/packages/{package}/advisories` |
| Archive download | Full | `GET /packages/{package}/versions/{version}.tar.gz` |
| Upstream proxy | Full | `pub.dev` by default, custom hosted repos supported |
| URL rewriting | Full | `archive_url`, `package_url`, `url`, `next_url` point to NORA |
| Checksum verification | Full | SHA-256 sidecar stored for cached archives |
| Publish / upload | — | Not implemented |

## Go Module Proxy (GOPROXY)

| Feature | Status | Notes |
|---------|--------|-------|
| `/@v/list` | Full | List known versions |
| `/@v/{version}.info` | Full | Version metadata JSON |
| `/@v/{version}.mod` | Full | go.mod file |
| `/@v/{version}.zip` | Full | Module zip archive |
| `/@latest` | Full | Latest version info |
| Module path escaping | Full | `!x` → `X` per spec |
| Immutability | Full | .info, .mod, .zip immutable after first write |
| Size limit for .zip | Full | Configurable |
| `$GONOSUMDB` / `$GONOSUMCHECK` | — | Not relevant (client-side) |
| Upstream proxy | — | Direct storage only |

## Raw File Storage

| Feature | Status | Notes |
|---------|--------|-------|
| Upload (PUT) | Full | Any file type |
| Download (GET) | Full | Content-Type by extension |
| Delete (DELETE) | Full | |
| Exists check (HEAD) | Full | Returns size + Content-Type |
| Max file size | Full | Configurable (default 1MB) |
| Directory listing | — | Not implemented |
| Versioning | — | Overwrite-only |

## Helm OCI

Helm charts are stored as OCI artifacts via the Docker registry endpoints. `helm push` and `helm pull` work through the standard `/v2/` API.

| Feature | Status | Notes |
|---------|--------|-------|
| `helm push` (OCI) | Full | Via Docker PUT manifest/blob |
| `helm pull` (OCI) | Full | Via Docker GET manifest/blob |
| Helm repo index (`index.yaml`) | — | Not implemented (OCI only) |

## Cross-Cutting Features

| Feature | Status | Notes |
|---------|--------|-------|
| Authentication (Bearer/Basic) | Full | Per-request token validation |
| Anonymous read | Full | `NORA_AUTH_ANONYMOUS_READ=true` |
| Rate limiting | Full | `tower_governor`, per-IP |
| Prometheus metrics | Full | `/metrics` endpoint |
| Health check | Full | `/health` |
| Swagger/OpenAPI | Full | `/api-docs` |
| S3 backend | Full | AWS, MinIO, any S3-compatible |
| Local filesystem backend | Full | Default, content-addressable |
| Activity log | Full | Recent push/pull in dashboard |
| Backup/restore | Full | CLI commands |
| Mirror CLI | Full | `nora mirror` for npm/pip/cargo/maven/docker |
