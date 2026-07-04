---
title: NuGet
description: Caching proxy for the NuGet v3 API (also serves Chocolatey and PowerShell Gallery clients).
---

The NuGet registry provides a transparent caching proxy for [api.nuget.org](https://api.nuget.org). Service index URLs are rewritten to point through NORA, registration and version-list metadata is TTL-cached, and `.nupkg` / `.nuspec` files are immutably cached on first download. Chocolatey and PowerShell Gallery clients are supported via path aliases.

## Client Configuration

Add the NORA source with the .NET CLI:

```bash
dotnet nuget add source http://nora.example.com:4000/nuget/v3/index.json -n nora
```

Reference the source in a project's `NuGet.Config`:

```xml
<configuration>
  <packageSources>
    <add key="nora" value="http://nora.example.com:4000/nuget/v3/index.json" />
  </packageSources>
</configuration>
```

For Chocolatey clients:

```bash
choco source add -n nora -s http://nora.example.com:4000/chocolatey/v3/index.json
```

For PowerShell Gallery clients, use the `/pwsh/` alias:

```powershell
Register-PSRepository -Name nora `
  -SourceLocation http://nora.example.com:4000/pwsh/v3/index.json `
  -InstallationPolicy Trusted
```

## Upstream Proxy

By default, NORA proxies to the public NuGet API (`https://api.nuget.org`). To use a private feed (Azure Artifacts, Nexus, GitHub Packages):

```bash
export NORA_NUGET_PROXY=https://pkgs.dev.azure.com/myorg/_packaging/myfeed/nuget/v3/index.json
export NORA_NUGET_PROXY_AUTH=user:personalAccessToken
```

NORA rewrites all `@id` URLs in the service index response and in registration pages to route through itself, so clients always download through the proxy. When proxying a non-default feed, NORA auto-discovers the search and autocomplete service URLs from the upstream service index.

## Features

| Feature | Status | Notes |
|---------|--------|-------|
| Service index | Full | `@id` URLs rewritten through NORA |
| Package search | Full | Delegated to upstream search service |
| Autocomplete | Full | Delegated to upstream autocomplete service |
| Registration (metadata) | Full | TTL-cached with stale-while-revalidate |
| Flat container (version list) | Full | TTL-cached |
| `.nupkg` download | Full | Immutable cache on first download |
| `.nuspec` download | Full | Immutable cache on first download |
| Chocolatey clients | Full | `/chocolatey/` alias |
| PowerShell Gallery clients | Full | `/pwsh/` alias |
| Package push | -- | Proxy-only (read) |

**Environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `NORA_NUGET_ENABLED` | Enable NuGet registry | `false` |
| `NORA_NUGET_PROXY` | Upstream feed URL | `https://api.nuget.org` |
| `NORA_NUGET_PROXY_AUTH` | Upstream auth (`user:pass`) | *(none)* |
| `NORA_NUGET_PROXY_TIMEOUT` | Proxy timeout in seconds | `30` |
| `NORA_NUGET_METADATA_TIMEOUT` | Fast timeout for registration and version-list requests | `2` |
| `NORA_NUGET_METADATA_TTL` | Metadata cache TTL in seconds | `300` |
| `NORA_NUGET_REVALIDATE` | Revalidate stale metadata in the background | `true` |
| `NORA_NUGET_SERVE_STALE` | Serve cached metadata when upstream is unreachable | `true` |
| `NORA_NUGET_SEARCH_SERVICE` | Override upstream search endpoint | `https://azuresearch-usnc.nuget.org/query` |
| `NORA_NUGET_AUTOCOMPLETE` | Override upstream autocomplete endpoint | `https://azuresearch-usnc.nuget.org/autocomplete` |

**config.toml:**

```toml
[nuget]
enabled = true
proxy = "https://api.nuget.org"
# proxy_auth = "user:pass"
proxy_timeout = 30
metadata_timeout = 2
metadata_ttl = 300
revalidate = true
serve_stale = true
# search_service = "https://azuresearch-usnc.nuget.org/query"
# autocomplete = "https://azuresearch-usnc.nuget.org/autocomplete"
```

## Endpoints

All routes are also available under the `/chocolatey/` and `/pwsh/` path aliases.

| Path | Method | Description |
|------|--------|-------------|
| `/nuget/v3/index.json` | GET | Service index (`@id` URLs rewritten through NORA) |
| `/nuget/v3/query` | GET | Package search (proxied to upstream search service) |
| `/nuget/v3/autocomplete` | GET | Package ID autocomplete (proxied to upstream) |
| `/nuget/v3/registration/{id}/index.json` | GET | Registration leaf index (TTL-cached) |
| `/nuget/v3/registration/{id}/page/{lower}/{*upper}` | GET | Registration page (TTL-cached) |
| `/nuget/v3/flatcontainer/{*path}` | GET | Version list, `.nupkg`, and `.nuspec` (immutable files cached on first download) |

## Caching Behavior

- **Metadata** (service index, registration, version lists): TTL-cached for `NORA_NUGET_METADATA_TTL` seconds (default 300) with a fast upstream timeout of `NORA_NUGET_METADATA_TIMEOUT` seconds (default 2). Background revalidation runs when `NORA_NUGET_REVALIDATE=true`. Stale entries are served when upstream is unreachable and `NORA_NUGET_SERVE_STALE=true`.
- **Package files** (`.nupkg`, `.nuspec`): cached on first download with `Cache-Control: public, max-age=31536000, immutable`. Subsequent requests are served from local storage without contacting upstream.
- **Search and autocomplete**: not stored locally; every request is proxied live to the configured search service.

## Known Limitations

- Proxy-only: package push (`dotnet nuget push`) is not supported. Use the push command directly against NuGet.org or your private feed.
- Search and autocomplete results are delegated to the upstream search service and are not stored locally. If the upstream search service is unreachable, search requests return 502.
- When proxying a non-default feed, NORA discovers the search and autocomplete endpoints from the upstream service index. Feeds that do not advertise these resources in their service index will have search and autocomplete unavailable.
