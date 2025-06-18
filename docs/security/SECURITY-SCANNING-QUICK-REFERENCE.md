# Security Scanning Quick Reference

## 🚀 Quick Commands

```bash
# Install security tools (one-time setup)
make security-install

# Run quick security scan (2-3 minutes)
make security-scan-quick

# Run comprehensive security scan (5-10 minutes)
make security-scan

# Run specific checks from Makefile
make check-deps     # Dependency vulnerabilities only
make lint          # Code quality issues
```

## 📋 What Gets Scanned

### Quick Scan (`make security-scan-quick`)
- ✅ **Dependencies**: Known vulnerabilities (govulncheck)
- ✅ **Code Quality**: Static analysis (staticcheck)
- ✅ **Secrets**: Exposed credentials (gitleaks)

### Full Scan (`make security-scan`)
All of the above plus:
- ✅ **Container**: Dockerfile security (hadolint, trivy)
- ✅ **SAST**: Security patterns (gosec, semgrep)
- ✅ **Licenses**: Compliance check (go-licenses)

## 🛠️ Manual Tool Usage

```bash
# Individual tool commands (if installed)
govulncheck ./...                    # Go vulnerabilities
gosec -fmt text ./...                # Security issues
gitleaks detect --source .           # Secret scanning
staticcheck ./...                    # Static analysis
hadolint Dockerfile                  # Dockerfile linting
trivy fs .                          # Filesystem vulnerabilities
go-licenses check ./...             # License compliance
```

## 📊 Output Files

- `security-report.md` - Summary of all scans
- `license-report.txt` - Detailed license information
- Console output with color-coded results

## 🔧 Troubleshooting

```bash
# Check if tools are installed
which govulncheck gosec gitleaks

# Install missing Go tools
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
go install github.com/google/go-licenses@latest

# Install missing system tools (macOS)
brew install gitleaks hadolint trivy

# Install missing system tools (Linux)
# See tool-specific installation guides
```

## 🚨 Common Issues

| Issue | Solution |
|-------|----------|
| Script not found | Run from project root directory |
| Permission denied | Makefile handles this automatically |
| Tool not found | Run `make security-install` |
| Scan failures | Check output for specific issues |

## 📈 CI/CD Integration

Security scans run automatically on:
- Every push to `main` branch
- Every pull request
- Daily schedule (cron)

Check GitHub Actions tab for results.

## 🔒 Security Policies

- [Security Policy](../../SECURITY.md)
- [Security Architecture](../architecture/security.md)
- [Detailed Setup Guide](security-scanning-setup.md)