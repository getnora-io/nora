---
title: Audit Log
description: Track all registry operations with structured JSONL audit logging
---

NORA records registry operations in a structured audit log. Each entry is a JSON object written to a single line (JSONL format).

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_AUDIT_LOG` | `file` | Output mode: `file`, `stdout`, `both`, or `off` |

```toml
# config.toml
[audit]
mode = "file"       # "file", "stdout", "both", "off"
```

**Modes:**

| Mode | Behavior |
|------|----------|
| `file` | Write to `{storage_path}/audit.jsonl` |
| `stdout` | Write to stderr (12-factor compatible, works with log aggregators) |
| `both` | Write to both file and stderr |
| `off` | Disable audit logging |

## Log format

Each line is a JSON object with these fields:

| Field | Type | Description |
|-------|------|-------------|
| `ts` | string | ISO 8601 timestamp (UTC) |
| `action` | string | `push`, `pull`, `delete`, `cache_hit`, `proxy_fetch`, `overwrite`, `retention-apply` |
| `actor` | string | Origin of the operation: `api` (HTTP request), `scheduler` (retention), or `cli` |
| `artifact` | string | Package name or image reference |
| `registry` | string | Registry type: `docker`, `npm`, `pypi`, `maven`, etc. |
| `detail` | string | Additional context (version, digest, size) |

### Example entries

```json
{"ts":"2026-05-18T10:30:45.123Z","action":"push","actor":"api","artifact":"myapp","registry":"docker","detail":"sha256:abc123"}
{"ts":"2026-05-18T10:31:02.456Z","action":"pull","actor":"api","artifact":"lodash","registry":"npm","detail":"4.17.21"}
{"ts":"2026-05-18T10:32:15.789Z","action":"delete","actor":"api","artifact":"old-image:v1","registry":"docker","detail":"manifest"}
{"ts":"2026-05-18T10:33:00.001Z","action":"cache_hit","actor":"api","artifact":"","registry":"maven","detail":""}
{"ts":"2026-05-18T10:33:05.200Z","action":"proxy_fetch","actor":"api","artifact":"","registry":"npm","detail":""}
{"ts":"2026-05-18T10:34:10.500Z","action":"overwrite","actor":"api","artifact":"libs/config.yaml","registry":"raw","detail":""}
```

**Action types:**

| Action | Description |
|--------|-------------|
| `push` | Client uploaded a new artifact |
| `pull` | Client downloaded an artifact from local storage |
| `delete` | Client deleted an artifact |
| `cache_hit` | Request served from local cache without contacting upstream |
| `proxy_fetch` | Artifact fetched from an upstream registry |
| `overwrite` | Existing artifact replaced (Raw registry) |
| `retention-apply` | Artifact removed by retention policy |

## File location

When using `file` or `both` mode, the audit log is written to:

```
{NORA_STORAGE_PATH}/audit.jsonl
```

Default: `data/audit.jsonl` (relative to the working directory).

The file is created automatically. Parent directories are created if they do not exist.

## Docker Compose example

```yaml
services:
  nora:
    image: ghcr.io/getnora-io/nora:0.9
    environment:
      NORA_AUDIT_LOG: both
      NORA_STORAGE_PATH: /data
    volumes:
      - nora-data:/data
```

Then tail the log:

```bash
docker exec nora tail -f /data/audit.jsonl | jq .
```

## Forwarding to a log aggregator

With `stdout` mode, audit entries go to stderr alongside regular logs. Use your container orchestrator's log driver to forward them:

```bash
# Filter audit entries from container logs
docker logs nora 2>&1 | grep '"action":' | jq .
```

For dedicated file-based forwarding (Filebeat, Promtail, Vector):

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    paths:
      - /data/audit.jsonl
    json.keys_under_root: true
    json.add_error_key: true
```

## Querying the audit log

```bash
# All pushes today
grep '"action":"push"' /data/audit.jsonl | jq .

# All Docker operations by user "admin"
jq -c 'select(.registry == "docker" and .actor == "admin")' /data/audit.jsonl

# Count operations per registry
jq -r '.registry' /data/audit.jsonl | sort | uniq -c | sort -rn
```

## See Also

- [Settings](/configuration/settings/) — `NORA_AUDIT_LOG` env var
- [Prometheus Metrics](/observability/prometheus-metrics/) — quantitative monitoring
