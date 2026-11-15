# Benchmarks

Reproducible performance figures for NORA.

> **Scope.** The figures below cover what CI measures today on each release:
> binary size, cold-start time, and idle memory, plus Criterion micro-benchmarks.
> Load-test figures — throughput, request latency, and memory under concurrent
> load — are **not yet measured**: the k6 load harness is not implemented (tracked
> in #693). The rows under "Targets" are goals, not measurements, until then.

## Measured (v1.4.0)

| Metric | Value |
|--------|-------|
| Binary size (`nora-linux-amd64`) | 23.4 MB |
| Cold start (process start to `/health` 200) | 55–90 ms |
| RAM (idle, 10 s after start) | about 15 MB (RSS) |

> The release binary of v1.4.0, three runs, empty local storage, `NORA_CURATION_MODE=off`, on a
> 20-core Linux 5.15 host. A store with packages starts later: the first start of 1.4.0 on a store
> with 3,000 Cargo crates writes their name records before it accepts requests, about 4 s on local
> disk and 2 s on S3; later starts skip it.
>
> Earlier figure, for comparison: v0.9.0 measured in CI on GitHub Actions (`ubuntu-latest`,
> 2 vCPU, 4 GB RAM) at under 3 s cold start, under 50 MB idle and about 23 MB of binary.

## Targets (not yet measured — see #693)

These need the k6 load harness, which does not exist yet:

| Metric | Target |
|--------|--------|
| RAM (100 concurrent pulls) | < 100 MB |
| Docker pull p95 (cached) | < 50 ms |
| npm install p95 (cached) | < 30 ms |

## Methodology

On each release, the `benchmarks.yml` workflow measures:

- **Cold start** — wall-clock from `nora serve` to the first successful `/health` response.
- **Idle memory** — `VmRSS` from `/proc/PID/status` after startup, with no requests.
- **Binary size** — `stat` of the stripped release binary.
- **Micro-benchmarks** — `cargo bench -p nora-registry` (parsing and validation).

Hardware: 2 vCPU, 4 GB RAM (GitHub Actions `ubuntu-latest` or equivalent). Results
are attached as release artifacts.

### Throughput and latency (planned — #693)

The intended k6 request distribution, once the harness lands:

| Operation | Scenario |
|-----------|----------|
| Docker pull (manifest) | GET `/v2/{name}/manifests/{tag}` — cached images |
| Docker pull (blob) | GET `/v2/{name}/blobs/{digest}` — 10 MB layer |
| npm install | GET `/npm/{package}` — metadata + tarball download |
| Maven resolve | GET `/maven2/.../{artifact}.jar` — cached artifacts |
| Raw upload | PUT `/raw/{file}` — 1–100 KB files |

Planned reported metrics: total req/s, p50, p95, p99 latency.

### Storage overhead

An architectural property, not a load measurement: NORA stores raw, content-addressable
files, so identical blobs are stored once.

| Solution | 1000 Docker images | Overhead |
|----------|-------------------|----------|
| NORA (local) | Raw files on disk | ~0% (content-addressable dedup) |
| NORA (S3) | S3 objects | ~0% |
| DB-backed registry | DB + filesystem | indexes, WAL, metadata tables |

### Backup / restore

NORA's data is plain files, so backup and restore are a file copy — no database dumps,
no index rebuilds, no multi-step procedures.

| Operation | Command |
|-----------|---------|
| Backup | `cp -r /data/ backup/` or `nora backup` |
| Restore | `cp -r backup/ /data/` or `nora restore` |

## Running benchmarks locally

### Micro-benchmarks (Criterion)

```bash
cargo bench -p nora-registry
```

Runs parsing and validation benchmarks. Results in `target/criterion/`.

### Load tests

The k6 load harness (`scripts/load-test.sh` scenarios and `scripts/bench-regression.sh`
regression check) is **not yet implemented** — see #693. Until it lands, there is no
local load-test command.

## CI integration

The `benchmarks.yml` workflow runs on each release:

1. Builds the release binary
2. Records binary size, cold-start time, and idle memory
3. Runs the Criterion micro-benchmarks
4. Uploads a JSON report as a release artifact

Load testing, throughput/latency measurement, and baseline regression comparison are
pending the harness in #693.

## Historical results

Release reports are published as GitHub Release artifacts:

```bash
gh release download <tag> --pattern 'bench-*.json' --dir /tmp/<tag>
```
