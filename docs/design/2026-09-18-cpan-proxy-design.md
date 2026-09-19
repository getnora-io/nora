# CPAN Proxy Registry — Design

## Overview

Add CPAN (Comprehensive Perl Archive Network) proxy support to NORA.
A caching proxy for www.cpan.org that serves Perl module distributions
to clients like `cpanm`, `cpan`, and `carton`.

## Registry Identity

- **RegistryType:** `Cpan` → `"cpan"`, mount point `/cpan/`, display `"CPAN"`
- **Storage prefix:** `cpan/`
- **Default upstream:** `https://www.cpan.org`
- **Default state:** disabled (ADR-7)
- **Type:** proxy-only (no hosted/publish)

## Configuration

New file `config/registry/cpan.rs`:

```rust
pub struct CpanConfig {
    pub enabled: bool,           // default: false
    pub proxy: Option<String>,   // default: Some("https://www.cpan.org")
    pub proxy_auth: Option<ProtectedString>,
    pub proxy_timeout: u64,      // default: 30
    pub metadata_ttl: i64,       // default: 300 (TTL for index, seconds)
    pub serve_stale: bool,       // default: true
}
```

Env vars: `NORA_CPAN_ENABLED`, `NORA_CPAN_PROXY`, `NORA_CPAN_PROXY_AUTH`,
`NORA_CPAN_PROXY_TIMEOUT`, `NORA_CPAN_METADATA_TTL`, `NORA_CPAN_SERVE_STALE`.

## API

### `GET /cpan/modules/02packages.details.txt.gz`

Proxy for the main CPAN package index.

- TTL-based caching (default 300s)
- Conditional revalidation via `etag`/`last-modified`
- Serve-stale fallback on upstream failure
- Curation check (blocklist/allowlist)

**Storage key:** `cpan/modules/02packages.details.txt.gz`

### `GET /cpan/authors/id/*path`

Proxy for distribution files (`.tar.gz`, etc.).

- Immutable caching (cached forever once downloaded)
- No TTL — distributions are content-addressed by path
- Curation check
- Digest quarantine
- Range request support

**Storage key:** `cpan/authors/id/{path}`

## Distribution grouping in the UI

CPAN stores every release in the author's directory and does not provide a
distribution-level directory. NORA derives the distribution name and version
from each cached archive filename so that, for example,
`Module-Build-XSUtil-0.18.tar.gz` and `Module-Build-XSUtil-0.19.tar.gz` appear as
one `Module-Build-XSUtil` entry with two versions.

The parser is a local, deterministic adaptation of the useful filename rules
from [`CPAN::DistnameInfo`](https://metacpan.org/pod/CPAN%3A%3ADistnameInfo):

- recognise `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tgz`, and `.zip` archives;
- remove the historical `-withoutworldwriteables` suffix and normalise a
  distribution name ending in `.pm`;
- prefer the rightmost plausible `-` separator, while retaining release
  suffixes such as `-TRIAL` as part of the version;
- support legacy `_` separators, `Dist.1.23`, and names with a directly
  attached version such as `Tk800.025`;
- recognise numeric and `v`-prefixed versions, plus historical alpha, beta,
  pre, rc, oct, and ye forms.

NORA does not fetch or parse `.meta` sidecars for grouping. Only archives that
have already passed through this proxy are listed, so the UI is a view of the
local cache rather than a complete upstream release history. Sidecars and
archive names for which no version can be inferred are omitted from the
author-level distribution list.

## Client Configuration

```bash
# cpanm
cpanm --from http://nora:4000/cpan Module::Name

# cpan
cpan> o conf urllist push http://nora:4000/cpan/
cpan> o conf commit
```

## ~20 Integration Touch Points

See ARCHITECTURE.md "Adding a New Registry" table.

## Out of Scope (v1)

- Retention/keep_last (follows gems/terraform/nuget pattern — not implemented)
- Hosted mode (publish to CPAN)
- Mirror CLI (`nora mirror cpan`)
- Full CPAN mirror (only `02packages.details.txt.gz` + `authors/id/`)
