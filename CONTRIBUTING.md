# Contributing to NORA

Thank you for your interest in contributing to NORA!

## Developer Certificate of Origin (DCO)

By submitting a pull request, you agree to the [Developer Certificate of Origin](https://developercertificate.org/).
Your contribution will be licensed under the [MIT License](LICENSE).

You confirm that you have the right to submit the code and that it does not violate any third-party rights.

## Project Governance

NORA uses a **Benevolent Dictator** governance model:

- **Maintainer:** [@devitway](https://github.com/devitway) — final decisions on features, releases, and architecture
- **Contributors:** anyone who submits issues, PRs, or docs improvements
- **Decision process:** proposals via GitHub Issues → discussion → maintainer decision
- **Release authority:** maintainer only

### Roles and Responsibilities

| Role | Person | Responsibilities |
|------|--------|-----------------|
| Maintainer | @devitway | Code review, releases, roadmap, security response |
| Contributor | anyone | Issues, PRs, documentation, testing |
| Dependabot | automated | Dependency updates |

### Continuity

The GitHub organization [getnora-io](https://github.com/getnora-io) has multiple admin accounts to ensure project continuity. Source code is MIT-licensed, enabling anyone to fork and continue the project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/nora.git`
3. Create a branch: `git checkout -b feature/your-feature`

## Development Setup

### Prerequisites

- **Rust** stable (1.85+) — install via [rustup](https://rustup.rs/)
- **Docker** (optional) — for integration tests (docker push/pull)
- **Node.js** 18+ (optional) — for npm integration tests

### Build and Test

```bash
# Build
cargo build --package nora-registry

# Run unit tests (important: use --lib --bin to skip fuzz targets)
cargo test --lib --bin nora

# Run clippy (must pass with zero warnings)
cargo clippy --package nora-registry -- -D warnings

# Format check
cargo fmt --check
```

### Run Locally

```bash
# Start with defaults (port 4000, local storage in ./data/)
cargo run --bin nora -- serve

# Custom port and storage
NORA_PORT=5000 NORA_STORAGE_PATH=/tmp/nora-data cargo run --bin nora -- serve

# Test health
curl http://localhost:4000/health
```

### Integration / Smoke Tests

```bash
# Build release binary first
cargo build --release

# Run full smoke suite (starts NORA, tests all 7 protocols, stops)
bash tests/smoke.sh
```

### Fuzz Testing

```bash
# Install cargo-fuzz (one-time)
cargo install cargo-fuzz

# Run fuzz target (Ctrl+C to stop)
cargo +nightly fuzz run fuzz_validation -- -max_total_time=60
```

## Before Submitting a PR

```bash
cargo fmt --check
cargo clippy --package nora-registry -- -D warnings
cargo test --lib --bin nora
```

All three must pass. CI will enforce this.

## Code Style

- Run `cargo fmt` before committing
- Fix all `cargo clippy` warnings
- No `unwrap()` in production code (use proper error handling)
- Follow Rust naming conventions
- Keep functions short and focused
- Add tests for new functionality

## Pull Request Process

1. Branch from `main`, use descriptive branch names (`feat/`, `fix/`, `chore/`)
2. Update CHANGELOG.md if the change is user-facing
3. Add tests for new features or bug fixes
4. Ensure CI passes (fmt, clippy, test, security checks)
5. Keep PRs focused — one feature or fix per PR
6. PRs are squash-merged to keep a clean history

## Commit Messages

Use conventional commits:

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation
- `test:` adding or updating tests
- `security:` security improvements
- `chore:` maintenance

Example: `feat: add npm scoped package support`

## New Registry Checklist

When adding a new registry type (Docker, npm, Maven, etc.), ensure all of the following:

- [ ] Handler in `nora-registry/src/registry/`
- [ ] Health check endpoint
- [ ] Metrics (Prometheus)
- [ ] OpenAPI spec update
- [ ] Startup log line
- [ ] Dashboard UI tile
- [ ] Playwright e2e test
- [ ] CHANGELOG entry
- [ ] COMPAT.md update

## Reporting Issues

- Use GitHub Issues with the provided templates
- Include steps to reproduce
- Include NORA version (`nora --version`) and OS

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Community

- Telegram: [@getnora](https://t.me/getnora)
- GitHub Issues: [getnora-io/nora](https://github.com/getnora-io/nora/issues)
