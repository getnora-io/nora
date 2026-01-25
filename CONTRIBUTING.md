# Contributing to NORA

Thanks for your interest in contributing to NORA!

## Getting Started

1. **Fork** the repository
2. **Clone** your fork:
   ```bash
   git clone https://github.com/your-username/nora.git
   cd nora
   ```
3. **Create a branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Prerequisites

- Rust 1.75+ (`rustup update`)
- Docker (for testing)
- Git

### Build

```bash
cargo build
```

### Run

```bash
cargo run --bin nora
```

### Test

```bash
cargo test
cargo clippy
cargo fmt --check
```

## Making Changes

1. **Write code** following Rust conventions
2. **Add tests** for new features
3. **Update docs** if needed
4. **Run checks**:
   ```bash
   cargo fmt
   cargo clippy -- -D warnings
   cargo test
   ```

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation
- `test:` - Tests
- `refactor:` - Code refactoring
- `chore:` - Maintenance

Example:
```bash
git commit -m "feat: add S3 storage migration"
```

## Pull Request Process

1. **Push** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Open a Pull Request** on GitHub

3. **Wait for review** - maintainers will review your PR

## Code Style

- Follow Rust conventions
- Use `cargo fmt` for formatting
- Pass `cargo clippy` with no warnings
- Write meaningful commit messages

## Questions?

- Open an [Issue](https://github.com/getnora-io/nora/issues)
- Ask in [Discussions](https://github.com/getnora-io/nora/discussions)
- Reach out on [Telegram](https://t.me/DevITWay)

---

Built with love by the NORA community
