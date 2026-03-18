# Contributing to NORA

Thank you for your interest in contributing to NORA!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/nora.git`
3. Create a branch: `git checkout -b feature/your-feature`

## Development Setup

```bash
# Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build --package nora-registry

# Run tests (important: always use --lib --bin nora to skip fuzz targets)
cargo test --lib --bin nora

# Run clippy
cargo clippy --package nora-registry -- -D warnings

# Format
cargo fmt

# Run locally
cargo run --bin nora -- serve
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
- Follow Rust naming conventions
- Keep functions short and focused
- Add tests for new functionality

## Pull Request Process

1. Update CHANGELOG.md if the change is user-facing
2. Add tests for new features or bug fixes
3. Ensure CI passes (fmt, clippy, test, security checks)
4. Keep PRs focused — one feature or fix per PR

## Commit Messages

Use conventional commits:

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation
- `test:` adding or updating tests
- `security:` security improvements
- `chore:` maintenance

Example: `feat: add npm scoped package support`

## Reporting Issues

- Use GitHub Issues with the provided templates
- Include steps to reproduce
- Include NORA version (`nora --version`) and OS

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Community

- Telegram: [@getnora](https://t.me/getnora)
- GitHub Issues: [getnora-io/nora](https://github.com/getnora-io/nora/issues)
