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
cargo build

# Run tests
cargo test

# Run locally
cargo run --bin nora -- serve
```

## Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy` and fix warnings
- Follow Rust naming conventions

## Pull Request Process

1. Update documentation if needed
2. Add tests for new features
3. Ensure all tests pass: `cargo test`
4. Ensure code is formatted: `cargo fmt --check`
5. Ensure no clippy warnings: `cargo clippy`

## Commit Messages

Use conventional commits:

- `feat:` - new feature
- `fix:` - bug fix
- `docs:` - documentation
- `style:` - formatting
- `refactor:` - code refactoring
- `test:` - adding tests
- `chore:` - maintenance

Example: `feat: add OAuth2 authentication`

## Reporting Issues

- Use GitHub Issues
- Include steps to reproduce
- Include NORA version and OS

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Contact

- Telegram: [@DevITWay](https://t.me/DevITWay)
- GitHub Issues: [getnora-io/nora](https://github.com/getnora-io/nora/issues)
