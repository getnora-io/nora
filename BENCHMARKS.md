# Benchmarks

Reproducible performance benchmarks for NORA.
All numbers are collected by CI on each release using the methodology described below.

## Quick Summary (v0.9.0)

| Metric | Value |
|--------|-------|
| Cold start | < 3s |
| RAM (idle) | < 50 MB |
| RAM (100 concurrent pulls) | < 100 MB |
| Binary size | 23 MB |
| Docker pull p95 (cached) | < 50ms |
| npm install p95 (cached) | < 30ms |
| Backup (10 GB data) | `cp -r`: ~10s |
| Restore (10 GB data) | `cp -r`: ~10s |

> All numbers measured in CI on GitHub Actions (`ubuntu-latest`, 2 vCPU, 4 GB RAM). See methodology below.

## Methodology

All NORA benchmarks run on a clean environment:

- **Hardware**: 2 vCPU, 4 GB RAM (GitHub Actions `ubuntu-latest` or equivalent)
- **Scenario**: fresh NORA binary, default config, local filesystem storage
- **Tool**: [k6](https://k6.io) for HTTP load, `/usr/bin/time -v` for resource tracking
- **Reproducibility**: every run is triggered by the `benchmarks.yml` workflow and results are attached as release artifacts

### Startup Time

```bash
/usr/bin/time -v ./nora serve &
# Measured: wall-clock from exec to first successful /health response
```

### Memory Footprint

| State | How measured |
|-------|-------------|
| Idle | `VmRSS` from `/proc/PID/status` after startup, no requests |
| 100 concurrent pulls | k6 with 100 VUs doing Docker manifest GET for 30s, peak `VmRSS` |
| 1000 concurrent pulls | k6 with 1000 VUs, same scenario, peak `VmRSS` |

### Throughput

Measured with k6 using realistic request distribution:

| Operation | Scenario |
|-----------|----------|
| Docker pull (manifest) | GET `/v2/{name}/manifests/{tag}` — cached images |
| Docker pull (blob) | GET `/v2/{name}/blobs/{digest}` — 10 MB layer |
| npm install | GET `/npm/{package}` — metadata + tarball download |
| Maven resolve | GET `/maven2/.../{artifact}.jar` — cached artifacts |
| Raw upload | PUT `/raw/{file}` — 1–100 KB files |

Reported metrics: total req/s, p50, p95, p99 latency.

### Storage Overhead

| Solution | 1000 Docker images | Overhead |
|----------|-------------------|----------|
| NORA (local) | Raw files on disk | ~0% (content-addressable dedup) |
| NORA (S3) | S3 objects | ~0% |
| DB-backed registry | DB + filesystem | 10–30% (indexes, WAL, metadata tables) |

### Backup / Restore

| Operation | Command |
|-----------|---------|
| Backup | `cp -r /data/ backup/` or `nora backup` |
| Restore | `cp -r backup/ /data/` or `nora restore` |

No database dumps, no index rebuilds, no multi-step procedures.

## Running Benchmarks Locally

### Micro-benchmarks (Criterion)

```bash
cargo bench -p nora-registry
```

Runs parsing and validation benchmarks. Results in `target/criterion/`.

### Load Tests (k6)

Requires a running NORA instance and [k6](https://k6.io/docs/get-started/installation/).

```bash
# Start NORA
NORA_HOST=0.0.0.0 NORA_PORT=4000 NORA_STORAGE_PATH=./bench-data \
  NORA_RATE_LIMIT_ENABLED=false ./target/release/nora serve &

# Run scenarios
./scripts/load-test.sh smoke          # 10 VUs, 30s — CI sanity
./scripts/load-test.sh average        # 50 VUs, 5min — typical load
./scripts/load-test.sh stress         # ramp to 200 VUs, 10min
./scripts/load-test.sh spike          # 0→500→0 VUs burst
./scripts/load-test.sh soak           # 50 VUs, 30min — leak detection
./scripts/load-test.sh breakpoint     # ramp until failure
```

Reports are written to `/tmp/nora-load-reports/` in JSON and text format.

### Regression Check

```bash
# Save baseline
./scripts/bench-regression.sh baseline

# After changes, compare
./scripts/bench-regression.sh compare
```

Fails if any metric degrades by more than 15% (configurable via `NORA_BENCH_THRESHOLD`).

## CI Integration

The `benchmarks.yml` workflow runs on every release:

1. Builds release binary
2. Starts NORA with default config
3. Runs `load-test.sh smoke` (k6)
4. Records startup time, peak memory, request throughput
5. Uploads JSON report as release artifact
6. Compares with previous release baseline (fails on >15% regression)

## Historical Results

Results are published as GitHub Release artifacts. Compare any two releases:

```bash
# Download reports
gh release download v0.9.0 --pattern 'bench-*.json' --dir /tmp/v090
gh release download v0.8.3 --pattern 'bench-*.json' --dir /tmp/v083

# Compare
diff /tmp/v090/bench-smoke.json /tmp/v083/bench-smoke.json
```
