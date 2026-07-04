---
title: Maven
description: Maven repository — proxy (multi-upstream) and host.
---

The Maven registry provides a proxy with multi-upstream fallback and hosted storage, mounted at `/maven2/`.

## Client Configuration

Add NORA as a mirror in `~/.m2/settings.xml`:

```xml
<settings>
  <mirrors>
    <mirror>
      <id>nora</id>
      <name>NORA Maven Proxy</name>
      <url>http://nora.example.com:4000/maven2/</url>
      <mirrorOf>central</mirrorOf>
    </mirror>
  </mirrors>
</settings>
```

To publish artifacts, add a `<distributionManagement>` section in your `pom.xml`:

```xml
<distributionManagement>
  <repository>
    <id>nora</id>
    <url>http://nora.example.com:4000/maven2/</url>
  </repository>
</distributionManagement>
```

## Upstream Proxy

NORA proxies to Maven Central by default. Multiple upstreams can be configured in `config.toml`; NORA tries each in declaration order and returns the first successful response.

```bash
export NORA_MAVEN_PROXIES=https://repo1.maven.org/maven2/
```

## Features

| Feature | Status | Notes |
|---------|--------|-------|
| Artifact download (GET) | Full | JARs, POMs, WARs, ZIPs |
| Checksum download (.md5 / .sha1 / .sha256) | Full | |
| Artifact upload (PUT) | Full | Auto-checksum generated on upload |
| maven-metadata.xml update on upload | Full | |
| Multi-upstream fallback | Full | First upstream to respond wins |
| Checksum verification | Full | Controlled by `checksum_verify` |
| Release immutability | Full | Re-upload returns 409 when `immutable_releases = true` |
| SNAPSHOT version management | -- | Latest timestamp returned; per-snapshot metadata not generated |
| maven-metadata.xml auto-generate on publish | -- | Upload the file explicitly |

**Environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `NORA_MAVEN_ENABLED` | Enable Maven registry | `true` |
| `NORA_MAVEN_PROXIES` | Comma-separated upstream URLs (TOML: `[[maven.proxies]]`) | `https://repo1.maven.org/maven2/` |
| `NORA_MAVEN_PROXY_TIMEOUT` | Upstream proxy timeout in seconds | `30` |
| `NORA_MAVEN_METADATA_TTL` | TTL for `maven-metadata.xml` and SNAPSHOT metadata in seconds | `300` |
| `NORA_MAVEN_CHECKSUM_VERIFY` | Verify artifact checksums against upstream | `true` |
| `NORA_MAVEN_IMMUTABLE_RELEASES` | Reject re-upload of release versions | `true` |

**config.toml:**

```toml
[maven]
enabled = true
proxy_timeout = 30
metadata_ttl = 300
checksum_verify = true
immutable_releases = true

[[maven.proxies]]
url = "https://repo1.maven.org/maven2/"
# auth = "user:password"
```

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/maven2/{*path}` | GET | Download artifact, checksum, or metadata |
| `/maven2/{*path}` | HEAD | Check artifact existence |
| `/maven2/{*path}` | PUT | Upload artifact (auto-checksum + maven-metadata update) |

## Caching Behavior

- **Release artifacts** (JARs, POMs, WARs): cached on first download and served from local storage on subsequent requests. Immutable release files are never re-fetched from upstream.
- **maven-metadata.xml and SNAPSHOT metadata**: TTL-based cache controlled by `metadata_ttl` (default 300 seconds). Re-fetched from upstream after expiry.

## Known Limitations

- `maven-metadata.xml` is not auto-generated when publishing artifacts directly to NORA. Upload the metadata file explicitly alongside the artifact.
- No SNAPSHOT version management: `-SNAPSHOT` paths resolve to the latest uploaded timestamp, but NORA does not generate or merge per-snapshot metadata files.
