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
- Registry-mirror caching depends on Docker's image store / distribution client, not the storage driver. Docker applies the wrong credentials to mirror endpoints — it sends the upstream registry's credentials to the mirror (and on the containerd path clobbers per-mirror `hosts.toml` credentials), so an authenticated mirror pull fails and Docker falls back to the upstream, skipping the cache. Both the legacy and containerd code paths are affected ([moby/moby#30880](https://github.com/moby/moby/issues/30880), [#42022](https://github.com/moby/moby/issues/42022); upstream fix in progress in [#52532](https://github.com/moby/moby/pull/52532)). An unauthenticated mirror avoids it — set `[auth] docker_anon_pull = true` to serve pulls without a login while still requiring auth on push (this is the Docker-specific switch; the general `anonymous_read` does not open `/v2/`). For pull-through caching of non-Docker-Hub registries, the containerd image store additionally tags mirror requests with the `?ns=` upstream namespace ([containerd hosts.md](https://github.com/containerd/containerd/blob/main/docs/hosts.md)). (#578)

## npm

| Feature | Status | Notes |
|---------|--------|-------|
| Package metadata (GET) | Full | JSON with all versions |
| Scoped packages `@scope/name` | Full | URL-encoded path |
| Tarball download | Full | SHA256 verified |
| Tarball URL rewriting | Full | Points to NORA, not upstream |
| Publish (`npm publish`) | Full | Immutable versions |
| Unpublish | — | Immutable; use quarantine/blocklist to disable a version |
| Dist-tags (`latest`, `next`) | Partial | Read from metadata, no explicit management |
| Search (`/-/v1/search`) | — | Not implemented |
| Audit (`bulk` npm7 / `audits/quick` npm6) | Full | Proxy repos: forwarded to upstream verbatim; internal-namespace names stripped/refused; anonymous-read eligible. Proxied packages only (no local advisory DB). (#597) |
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
| Conditional overwrite (`If-Match`) | Full | ETag-based, returns 200 on success |
| Create-only (`If-None-Match: *`) | Full | Returns 412 if resource exists |
| Directory listing | — | Not implemented |
| Immutability | Full | Default; re-upload returns 409 unless conditional headers used |

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
NORA serves both Terraform protocols against the same upstream: the **Registry Protocol**
(origin-registry, service-discovery based) and the **Network Mirror Protocol** (what
`network_mirror` speaks).

| Feature | Status | Notes |
|---------|--------|-------|
| Service discovery (`.well-known/terraform.json`) | Full | Registry protocol; points to NORA |
| Provider versions list | Full | TTL-cached |
| Provider download metadata | Full | `download_url` rewritten to NORA |
| Provider binary download | Full | Immutable cache |
| Module versions list | Full | TTL-cached |
| Module download | Full | `X-Terraform-Get` header pass-through |
| **Network mirror — `index.json`** | Full | Mirror protocol; list versions (#801) |
| **Network mirror — `{version}.json`** | Full | Mirror protocol; archives via NORA + `zh:` hash (#801) |
| Provider publish | — | Proxy-only (read) |

Client (network mirror — Terraform requires an `https:` URL, trailing slash):
`provider_installation { network_mirror { url = "https://nora.example.com/terraform/" } }`

**Limitations (accepted):**
- **Single upstream** — the `{hostname}` in a mirror request is validated but not routed;
  only the configured `terraform.proxy` upstream's providers resolve.
- **Mirror-mode integrity is weaker than registry mode** — in `network_mirror` mode
  Terraform does not run the origin-registry GPG check, and NORA does not itself verify
  `SHA256SUMS.sig`. Archives carry `zh:<sha256>` from upstream metadata (fail-closed: a
  platform without a resolvable shasum is omitted). Upgrade path: verify `SHA256SUMS.sig`
  against a pinned HashiCorp key at ingest.

## Ansible Galaxy (v3 API)

Caching proxy for galaxy.ansible.com. Collection tarballs are immutably cached.

| Feature | Status | Notes |
|---------|--------|-------|
| API discovery | Full | `/ansible/` and `/ansible/api/` |
| Collection list | Full | Short v3 and Pulp-style paths |
| Collection detail | Full | URL rewriting |
| Collection versions | Full | Paginated |
| Version detail | Full | Curation checks |
| Tarball download | Full | Immutable cache, both `/download/` and `/artifacts/` paths |
| Tarball curation | Full | Blocklist/allowlist, integrity verification |
| Collection publish | — | Proxy-only (read) |

Namespace and collection name validation follows Galaxy spec (`[a-z0-9_]+`).

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

## RPM (yum/dnf)

Hosted repositories with server-generated repodata (createrepo-style). Each
`/rpm/{repo}/` path is an independent repository; publishing or deleting a
package regenerates `repodata/` (repomd.xml + sha256-named
primary/filelists/other.xml.gz). Package headers are parsed server-side — no
`createrepo_c` needed on the client. No upstream proxy (hosted only).

| Feature | Status | Notes |
|---------|--------|-------|
| `repodata/repomd.xml` | Full | Regenerated on publish/delete, `Cache-Control: no-cache` |
| `primary.xml.gz` | Full | name/evr/arch, provides/requires/conflicts/obsoletes with flags, primary file subset, header-range |
| `filelists.xml.gz` | Full | All files with dir/ghost types |
| `other.xml.gz` | Full | Changelogs (last 10 per package, configurable) |
| Package publish (`PUT {repo}/{name}.rpm`) | Full | Header parsed and validated; invalid RPMs rejected |
| Package delete (`DELETE {repo}/{name}.rpm`) | Full | Repodata regenerated |
| Package download | Full | Byte-identical, sha256 pkgid in repodata |
| GPG-signed repodata (`repomd.xml.asc`) | Full | Signed on every regeneration; verify with `repo_gpgcheck=1`. Object-store backends (S3/GCS) require `signing.key_path` — without it signing is disabled with a startup warning |
| Public key (`repodata/repomd.xml.key`) | Full | Armored, for `gpgkey=`; key auto-generated at first boot |
| Package signatures (`gpgcheck=1`) | — | Packages are stored as uploaded; NORA signs metadata, not packages |
| Upstream proxy | — | Hosted only |
| sqlite metadata (`*_db`) | — | XML metadata only (all modern dnf/yum versions) |
| Delta RPMs (`prestodelta`) | — | Not generated |
| Module metadata (`modules.yaml`) | — | Not generated |

Publish: `curl -u user:pass -T pkg.rpm http://nora:4000/rpm/myrepo/pkg.rpm`

Client `.repo` file:

```ini
[nora-myrepo]
name=NORA myrepo
baseurl=http://nora:4000/rpm/myrepo
enabled=1
gpgcheck=0
repo_gpgcheck=1
gpgkey=http://nora:4000/rpm/myrepo/repodata/repomd.xml.key
```

`gpgcheck=0` stays: NORA signs the repository metadata, not the packages
themselves. With signing disabled (`signing.enabled = false`), also set
`repo_gpgcheck=0`.

## Debian (APT)

Hosted *flat* repositories with server-generated indexes. Each
`/deb/{repo}/` path is an independent repository; publishing or deleting a
package regenerates `Packages`, `Packages.gz`, and `Release` at the repo
root. Package control paragraphs are parsed server-side from the .deb
(ar → control.tar.{,gz,xz,zst}) — no `dpkg-scanpackages` needed. No
upstream proxy (hosted only).

| Feature | Status | Notes |
|---------|--------|-------|
| `Packages` / `Packages.gz` | Full | Verbatim control paragraphs + Filename/Size/MD5sum/SHA1/SHA256 |
| `Release` (flat repo) | Full | MD5Sum + SHA256 sections, `Cache-Control: no-cache` |
| Package publish (`PUT {repo}/{name}.deb`) | Full | Control parsed and validated; invalid debs rejected; decompression bombs bounded |
| Package delete (`DELETE {repo}/{name}.deb`) | Full | Indexes regenerated |
| Package download | Full | Byte-identical |
| `InRelease` (clearsigned) / `Release.gpg` (detached) | Full | Signed on every regeneration; verify via `signed-by` |
| Public key (`pubkey.gpg`) | Full | Armored, for the `signed-by` keyring; key auto-generated at first boot |
| `dists/` pool layout (suites/components) | — | Flat repositories only (`deb <url>/deb/{repo} ./`) |
| by-hash | — | Not applicable to flat repositories |
| Translations / Contents indexes | — | Not generated |
| Upstream proxy | — | Hosted only |

Publish: `curl -u user:pass -T pkg.deb http://nora:4000/deb/myrepo/pkg.deb`

Client setup:

```
curl -fsSL http://nora:4000/deb/myrepo/pubkey.gpg -o /etc/apt/keyrings/nora.asc
echo "deb [signed-by=/etc/apt/keyrings/nora.asc] http://nora:4000/deb/myrepo ./" \
  > /etc/apt/sources.list.d/nora.list
```

With signing disabled (`signing.enabled = false`), use
`deb [trusted=yes] http://nora:4000/deb/myrepo ./` instead.

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
| Rate limiting (429 + Retry-After) | Full | `tower_governor`, per-IP, documented in OpenAPI |
| 405 Method Not Allowed + Allow | Full | RFC 9110 §15.5.6, multi-method routes return Allow header |
| Prometheus metrics | Full | `/metrics` endpoint |
| Health check | Full | `/health` |
| Swagger/OpenAPI | Full | `/api-docs` |
| S3 backend | Full | AWS S3, Ceph RGW. Basic storage works on any S3-compatible; multi-replica write-serialization has a caveat — see note below. |
| GCS backend | Full | Native Google Cloud Storage (`storage.mode = "gcs"`): Workload Identity / service-account JSON / ambient credentials; endpoint override for emulators and Private Google Access. Same single-writer caveat as S3 for rpm/deb publishing (in-process publish lock). Hash-pinning (at-rest integrity verification) is unavailable on ALL object-store backends, not only S3. |
| Local filesystem backend | Full | Default, content-addressable |
| Activity log | Full | Recent push/pull in dashboard |
| Backup/restore | Full | CLI commands |
| Mirror CLI | Full | `nora mirror` for npm/pip/cargo/maven/docker |

### Storage backend notes

- **Multi-replica write-serialization needs conditional-write/CAS.** NORA's write lock
  (`publish_lock`) is safe under a **single writer** — one replica, or an RWO volume
  single-mounted so only one pod writes. Serializing concurrent writes across multiple
  replicas requires an object store with atomic conditional-write / compare-and-swap:
  AWS S3 and Ceph RGW provide it; **Garage** (no consensus layer) and **SeaweedFS**
  (immature) do not — on those, run single-writer. Not every "S3-compatible" backend is
  equivalent here.
