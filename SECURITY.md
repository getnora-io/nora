# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.9.x   | :white_check_mark: |
| < 0.9   | :x:                |

Only the latest minor release receives security patches.
Upgrade to the latest version for all fixes.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via:

1. **GitHub Private Vulnerability Reporting:** [Report a vulnerability](https://github.com/getnora-io/nora/security/advisories/new) (preferred)
2. **Email:** devitway@gmail.com
3. **Telegram:** [@devitway_pavel](https://t.me/devitway_pavel) (private message)

### What to Include

- Type of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Initial response:** within 48 hours
- **Status update:** within 7 days
- **Fix timeline:** depends on severity

### Severity Levels

| Severity | Description | Response |
|----------|-------------|----------|
| Critical | Remote code execution, auth bypass | Immediate fix |
| High | Data exposure, privilege escalation | Fix within 7 days |
| Medium | Limited impact vulnerabilities | Fix in next release |
| Low | Minor issues | Scheduled fix |

## Known Advisory Exclusions

The following RustSec advisories are excluded from `cargo audit` in CI
with documented rationale:

### RUSTSEC-2023-0071 — Marvin Attack (`rsa` crate)

| Field | Value |
|-------|-------|
| Advisory | [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) |
| Crate | `rsa` 0.9.x (transitive via `jsonwebtoken`) |
| Attack | Marvin Attack — timing side-channel on RSA PKCS#1 v1.5 **decryption** |
| NORA usage | JWT signature **verification** only (OIDC workload identity) |
| Applicable | **No** — NORA calls `rsa::verify`, never `rsa::decrypt` |
| Upstream fix | None available; `rsa` crate maintainers have not patched |

**Why RS256 is required:** GitHub Actions and GitLab CI OIDC providers sign
their workload identity tokens with RS256. NORA must verify these signatures
to support keyless CI/CD authentication. The `rsa` crate cannot be removed
from the dependency tree without breaking OIDC integration.

**Mitigations in place:**
- Algorithm whitelist per OIDC provider (`algorithms` config field)
- Default allowed algorithms: RS256, ES256 (EdDSA ready when providers adopt it)
- Symmetric algorithms (HS256/384/512) rejected globally
- `ed25519-dalek` already compiled in via `jsonwebtoken` `rust_crypto` feature

### RUSTSEC-2025-0119 — Unmaintained crate

Transitive dependency flagged as unmaintained. No fix available,
no security impact — the crate is functioning correctly.

## Security Best Practices

When deploying NORA:

1. **Enable authentication** - Set `NORA_AUTH_ENABLED=true`
2. **Use HTTPS** - Put NORA behind a reverse proxy with TLS
3. **Limit network access** - Use firewall rules
4. **Regular updates** - Keep NORA updated to latest version
5. **Secure credentials** - Use strong passwords, rotate tokens

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report valid vulnerabilities in our release notes and CHANGELOG, unless the reporter requests anonymity.

If you have previously reported a vulnerability and would like to be credited, please let us know.
