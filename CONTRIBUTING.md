# Contributing to MDE ServerTags

First off, thank you for considering contributing to MDE ServerTags! 🎉

## 🌟 How Can I Contribute?

### 🐛 Reporting Bugs

Before creating a bug report, please check the existing issues. When creating a bug report, include:

- **PowerShell version** (`$PSVersionTable.PSVersion`)
- **OS** (Windows Server version, or Linux distro)
- **MDE License** (P1, P2, Business)
- **Steps to reproduce** the issue
- **Expected vs actual behavior**
- **Log file output** (if applicable, remove sensitive data)

### 💡 Suggesting Features

Feature suggestions are welcome! Please:

1. Check if the feature was already requested in Issues
2. Open a new Issue with the `[Feature Request]` prefix
3. Describe the use case and expected behavior
4. Explain why this would be useful for the community

### 🔧 Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/my-new-feature
   ```
3. **Make your changes** following the coding standards below
4. **Test** your changes:
   ```powershell
   .\TEST-Lab-E2E.ps1 -Report
   ```
5. **Commit** with a clear message:
   ```bash
   git commit -m "feat: add support for custom tag prefixes"
   ```
6. **Push** and create a Pull Request

## 📝 Coding Standards

### PowerShell Style

- Use **PascalCase** for function names: `Get-ServerClassification`
- Use **camelCase** for local variables: `$serverList`
- Use **UPPER_SNAKE_CASE** for constants: `$MAX_RETRIES`
- Always use `[CmdletBinding()]` for advanced functions
- Include `-WhatIf` / `-Confirm` support for destructive operations
- Add comment-based help (`<# .SYNOPSIS #>`) to all public functions

### General Guidelines

- Keep functions focused — one function, one responsibility
- Log operations with timestamps (use `Write-Log` or `Write-Verbose`)
- Handle errors with `try/catch` and meaningful messages
- Never hardcode credentials, tenants, or subscription IDs
- Always support `reportOnly` mode for non-destructive testing

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Use |
|--------|-----|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation only |
| `refactor:` | Code change without fix/feature |
| `test:` | Test additions/changes |
| `chore:` | Build, CI, tooling |

## 🔒 Security

If you find a security vulnerability, **DO NOT** open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## 📜 License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

Thank you for helping make MDE ServerTags better! 🛡️
