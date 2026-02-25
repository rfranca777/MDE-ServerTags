# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.2.x   | ✅ Current release |
| 2.1.x   | ⚠️ Security fixes only |
| < 2.0   | ❌ Not supported   |

## Reporting a Vulnerability

If you discover a security vulnerability in MDE ServerTags, please **DO NOT** open a public GitHub issue.

### Responsible Disclosure

1. **Email**: Send details to **rafael.franca@live.com** with subject: `[SECURITY] MDE-ServerTags — <brief description>`
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
3. **Response**: You will receive an acknowledgment within **48 hours**
4. **Timeline**: We aim to release a fix within **7 days** for critical vulnerabilities

### What Qualifies as a Security Issue?

| Category | Example |
|----------|---------|
| ✅ Security Issue | Credential exposure in logs or output |
| ✅ Security Issue | OAuth token leak via API calls |
| ✅ Security Issue | Privilege escalation through script execution |
| ✅ Security Issue | Unintended data exposure to unauthorized parties |
| ❌ Not Security | Feature requests |
| ❌ Not Security | General bugs without security impact |
| ❌ Not Security | Documentation errors |

### Best Practices for Users

- **Never** commit `config.json` with real credentials to a repository
- Use **Azure Key Vault** or environment variables for secrets in production
- Run with **minimum required permissions** (`Machine.ReadWrite.All` only)
- Enable `reportOnly: true` mode before applying changes to production
- Rotate App Registration secrets regularly
- Review logs for unexpected API calls

## Acknowledgments

We appreciate security researchers who help keep MDE ServerTags and its users safe. Contributors who report valid vulnerabilities will be credited in the CHANGELOG (with permission).
