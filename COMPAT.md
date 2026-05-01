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

## RubyGems

Caching proxy for rubygems.org. Immutable gem/gemspec caching with TTL-based index refresh.

| Feature | Status | Notes |
|---------|--------|-------|
| Compact index (`/info/{name}`) | Full | TTL-cached |
| Gem download (`/gems/{name}-{ver}.gem`) | Full | Immutable cache |
| Gemspec (`/quick/Marshal.4.8/...`) | Full | Immutable cache |
| Full index (`specs.4.8.gz`) | Full | TTL-cached |
| Latest index (`latest_specs.4.8.gz`) | Full | TTL-cached |
| Gem push | — | Proxy-only (read) |

Client: `bundle config mirror.https://rubygems.org http://nora:4000/gems/`

## Terraform

Caching proxy for registry.terraform.io. Provider binaries are immutably cached; metadata uses TTL.

| Feature | Status | Notes |
|---------|--------|-------|
| Service discovery (`.well-known/terraform.json`) | Full | Points to NORA |
| Provider versions list | Full | TTL-cached |
| Provider download metadata | Full | `download_url` rewritten to NORA |
| Provider binary download | Full | Immutable cache |
| Module versions list | Full | TTL-cached |
| Module download | Full | `X-Terraform-Get` header pass-through |
| Provider publish | — | Proxy-only (read) |

Client: `provider_installation { network_mirror { url = "http://nora:4000/terraform/" } }`

## Ansible Galaxy (v3 API)

Caching proxy for galaxy.ansible.com. Collection tarballs are immutably cached.

| Feature | Status | Notes |
|---------|--------|-------|
| Collection list | Full | TTL-cached |
| Collection detail | Full | TTL-cached |
| Collection versions | Full | TTL-cached |
| Version detail | Full | TTL-cached |
| Tarball download | Full | Immutable cache |
| Collection publish | — | Proxy-only (read) |

Client: `ansible-galaxy collection install ns.name -s http://nora:4000/ansible/`

## NuGet (v3 API)

Caching proxy for api.nuget.org. Service index URLs are rewritten to point through NORA.

| Feature | Status | Notes |
|---------|--------|-------|
| Service index (`/v3/index.json`) | Full | `@id` URLs rewritten to NORA |
| Registration index | Full | TTL-cached |
| Version list (flat container) | Full | TTL-cached |
| `.nupkg` download | Full | Immutable cache |
| `.nuspec` download | Full | Immutable cache |
| Package push | — | Proxy-only (read) |
| Search | — | Not implemented |

Client: `dotnet nuget add source http://nora:4000/nuget/v3/index.json -n nora`

## Pub (Dart/Flutter)

Caching proxy for pub.dev. Package archives are immutably cached with SHA256 verification.

| Feature | Status | Notes |
|---------|--------|-------|
| Package search (`/api/packages?q=`) | Full | Response URL rewriting |
| Package metadata (`/api/packages/{name}`) | Full | `archive_url` rewritten to NORA |
| Version metadata | Full | Cached |
| Security advisories | Full | Cached |
| Archive download (`.tar.gz`) | Full | Immutable cache, SHA256 verified |
| Package publish | — | Proxy-only (read) |

Client: `export PUB_HOSTED_URL=http://nora:4000/pub && dart pub get`

## Conan (C/C++)

Caching proxy for ConanCenter (center2.conan.io). Recipe and package files are immutably cached (scoped to revision hashes). Metadata uses TTL-based caching.

| Feature | Status | Notes |
|---------|--------|-------|
| Ping (`/v2/ping`) | Full | Returns `X-Conan-Server-Capabilities: revisions` |
| Recipe search | Full | Proxied to upstream |
| Recipe latest revision | Full | TTL-cached |
| Recipe revision list | Full | TTL-cached |
| Recipe file list | Full | Immutable cache (revision-scoped) |
| Recipe file download | Full | Immutable cache |
| Package latest revision | Full | TTL-cached |
| Package revision list | Full | TTL-cached |
| Package file list | Full | Immutable cache (revision-scoped) |
| Package file download | Full | Immutable cache |
| Recipe/package upload | — | Proxy-only (read) |
| Authentication | — | Anonymous read only |

Client: `conan remote add nora http://nora:4000/conan`

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
| S3 backend | Full | AWS S3, Ceph RGW, any S3-compatible |
| Local filesystem backend | Full | Default, content-addressable |
| Activity log | Full | Recent push/pull in dashboard |
| Backup/restore | Full | CLI commands |
| Mirror CLI | Full | `nora mirror` for npm/pip/cargo/maven/docker |
