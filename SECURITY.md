# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via:

1. **Email:** devitway@gmail.com
2. **Telegram:** [@DevITWay](https://t.me/DevITWay) (private message)

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

## Security Best Practices

When deploying NORA:

1. **Enable authentication** - Set `NORA_AUTH_ENABLED=true`
2. **Use HTTPS** - Put NORA behind a reverse proxy with TLS
3. **Limit network access** - Use firewall rules
4. **Regular updates** - Keep NORA updated to latest version
5. **Secure credentials** - Use strong passwords, rotate tokens

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report valid vulnerabilities.
