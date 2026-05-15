---
title: Raw
description: Simple file storage for arbitrary artifacts.
---

The Raw registry provides generic file storage via HTTP PUT/GET/DELETE. Use it for binaries, scripts, configuration files, or any artifact that does not fit another registry format.

## Client Configuration

Upload and download files with `curl`:

```bash
# Upload
curl -X PUT --data-binary @myfile.tar.gz http://nora.example.com:4000/raw/path/to/myfile.tar.gz

# Download
curl -O http://nora.example.com:4000/raw/path/to/myfile.tar.gz

# Check if file exists
curl -I http://nora.example.com:4000/raw/path/to/myfile.tar.gz

# Delete
curl -X DELETE http://nora.example.com:4000/raw/path/to/myfile.tar.gz
```

## Upstream Proxy

The Raw registry does not support upstream proxying. It is a direct storage backend only.

## Features

| Feature | Status | Notes |
|---------|--------|-------|
| Upload (PUT) | Full | Any file type |
| Download (GET) | Full | Content-Type by extension |
| Delete (DELETE) | Full | |
| Exists check (HEAD) | Full | Returns size + Content-Type |
| Max file size | Full | Configurable (default 100 MB) |
| Conditional overwrite (`If-Match`) | Full | ETag-based, returns 200 on success |
| Create-only (`If-None-Match: *`) | Full | Returns 412 if resource exists |
| Directory listing | -- | Not implemented |
| Immutability | Full | Default; re-upload returns 409 unless conditional headers used |

**Environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `NORA_RAW_ENABLED` | Enable Raw registry | `true` |
| `NORA_RAW_MAX_FILE_SIZE` | Max file size in bytes | `104857600` (100 MB) |
| `NORA_RAW_CACHE_CONTROL` | `Cache-Control` header for GET/HEAD responses | `no-cache` |

**config.toml:**

```toml
[raw]
enabled = true
max_file_size = 104857600
cache_control = "no-cache"
```

## Conditional Requests (RFC 9110)

Raw supports conditional PUT for safe create/update workflows:

```bash
# Create only if not exists (returns 412 if already present)
curl -X PUT -H "If-None-Match: *" --data-binary @file.txt http://nora:4000/raw/path/file.txt

# Overwrite only if ETag matches (returns 412 on mismatch)
ETAG=$(curl -sI http://nora:4000/raw/path/file.txt | grep -i etag | awk '{print $2}' | tr -d '\r')
curl -X PUT -H "If-Match: $ETAG" --data-binary @file-v2.txt http://nora:4000/raw/path/file.txt
```

## Known Limitations

- No directory listing -- you must know the exact file path.
- Files are immutable by default. Re-uploading the same path returns 409 unless conditional headers (`If-Match`, `If-None-Match`) are used.
- No upstream proxy support.
