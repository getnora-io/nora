# Claude Code Notes - NORA

## Project Info
- **Repo**: https://github.com/getnora-io/nora
- **Demo**: https://demo.getnora.io
- **Type**: Cloud-native artifact registry (Docker, npm, Maven, Cargo, PyPI)
- **Stack**: Rust + Axum

## Important Rules


## Self-Maintenance
- Если пользователь просит другой подход — добавь правило сюда
- Если видишь код нарушающий эти правила — исправь
- Если видишь опечатки — исправь
- Держи этот файл актуальным с реальным состоянием проекта
### Git & Commits
- **NO Co-Authored-By** in commits — never add this line
- **NO mention of Claude, AI, Anthropic** in commit messages — commits are from the developer only
- Use `self-hosted` runner for releases
- **Before EVERY commit**: `cargo fmt && cargo clippy -- -D warnings && cargo test --lib --bin nora`
- **NEVER** `cargo test` without `--lib --bin nora` — fuzz targets run forever and kill the server

### Code Editing — MANDATORY
- **NEVER** use `sed` to edit YAML, TOML, or JSON files via SSH. Fetch locally, Edit tool, scp back.
- **NEVER** overwrite files on ai-server via scp without checking `git diff` on server first.
- **NEVER** use Write tool on a file you have not Read in this session.
- **NEVER** rewrite a file fully when changing less than 20 lines — use Edit tool for surgical changes.
- **ALWAYS** fetch files from ai-server before editing (ai-server is source of truth, local copy may be stale).
- **ALWAYS** `git diff` on server before commit to verify changes are correct.
- Pre-commit hook on ai-server enforces: fmt, clippy, tests, YAML/TOML validation, rewrite blocker (>60%).

### Testing
- Unit tests: `cargo test --lib --bin nora` (103+ tests)
- E2E Playwright: `cd tests/e2e && NORA_URL=http://localhost:PORT npx playwright test` (23 tests)
- Smoke test: `bash tests/smoke.sh` (full scenario)
- **Every bug fix MUST include a regression test.**

## Code Patterns

### Rust: Error Handling
Используй `anyhow::Result` для application errors, `thiserror` для library errors:
```rust
use anyhow::{Context, Result};

pub async fn get_manifest(name: &str, reference: &str) -> Result<Manifest> {
    let path = storage_path(name, reference);
    let data = tokio::fs::read(&path)
        .await
        .context("failed to read manifest")?;
    Ok(serde_json::from_slice(&data)?)
}
```

### Rust: Handler Pattern (Axum)
```rust
async fn handle_push(
    State(state): State<AppState>,
    Path((name, reference)): Path<(String, String)>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    // ...
}
```

### Rust: Testing
Каждый баг-фикс — regression тест:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_manifest_not_found_returns_404() {
        // arrange, act, assert
    }
}
```

### Storage Layout
```
data/
  docker/          # Docker registry blobs + manifests
  npm/             # npm tarballs + metadata
  cargo/           # Cargo crates
  maven/           # Maven artifacts
  pypi/            # PyPI wheels + sdists
```

## Infrastructure

### VPS (demo.getnora.io)
- Container: `deploy-nora-1`
- Volume: `nora-data:/data`

### Self-hosted Runner
- Service: `actions.runner.getnora-io-nora.nora-builder`
- Build time: ~8 min (cold cache), ~3-5 min (warm)

## Git Workflow

### Release Process
1. Push to main triggers CI (fmt, clippy, test, deny, audit)
2. Create tag `v*` triggers release workflow
3. Self-hosted runner builds binary + Docker images (alpine, redos, astra)
4. Trivy scan, cosign signing, SBOM generation
5. GitHub Release with binary, signatures, SBOMs
6. Images pushed to ghcr.io/getnora-io/nora
