# Security Scanning Infrastructure Setup

This document describes the security scanning infrastructure implemented for the MVP Zero Trust Auth system, including local scanning capabilities and CI/CD integration.

## Overview

The security scanning infrastructure provides comprehensive security analysis through multiple scanning tools and methodologies:

- **Dependency Vulnerability Scanning**: Identifies known vulnerabilities in dependencies
- **Secret Detection**: Prevents accidental commit of sensitive information
- **Container Security**: Validates Docker container security
- **Static Application Security Testing (SAST)**: Identifies security issues in source code
- **License Compliance**: Ensures dependency licenses are compatible

## Local Security Scanning

### Quick Start

```bash
# Install security scanning tools
make security-install

# Run comprehensive security scan
make security-scan

# Run quick security scan (faster, skips some checks)
make security-scan-quick
```

### Makefile Targets

The following security-related targets are available in the Makefile:

| Target | Description |
|--------|-------------|
| `ensure-security-script` | Verifies security script exists and is executable |
| `security-scan` | Runs comprehensive security scan |
| `security-scan-quick` | Runs quick security scan (dependency + secrets only) |
| `security-install` | Installs required security scanning tools |

### Security Scanning Script

The main security scanning logic is implemented in `scripts/security-scan.sh`:

#### Features

1. **Tool Installation Management**
   - Automatic installation of Go-based security tools
   - Progress tracking with success/failure reporting
   - Graceful handling of installation failures

2. **Scanning Modes**
   - **Comprehensive Mode**: All security scans
   - **Quick Mode** (`--quick`): Only dependency and secret scans

3. **Security Scans Performed**

   **Dependency Vulnerability Scan**:
   - `govulncheck`: Go vulnerability database check
   - `staticcheck`: Static analysis for bugs and performance

   **Secret Detection**:
   - `gitleaks`: Detects secrets in git history

   **Container Security** (Full scan only):
   - `hadolint`: Dockerfile linting
   - `trivy`: Container vulnerability scanning

   **SAST** (Full scan only):
   - `gosec`: Go security checker
   - `semgrep`: Pattern-based static analysis

   **License Compliance** (Full scan only):
   - `go-licenses`: Go dependency license checker

4. **Output and Reporting**
   - Color-coded console output
   - Detailed scan summary
   - Security report generation (`security-report.md`)

### Implementation Details

#### DRY Principle Applied

The Makefile implementation follows the DRY principle:

```makefile
# Single source of truth for script verification
ensure-security-script: ## Ensure security script exists and is executable
	@if [ ! -f scripts/security-scan.sh ]; then \
		echo "❌ Security scan script not found at scripts/security-scan.sh"; \
		exit 1; \
	fi
	@chmod +x scripts/security-scan.sh

# All security targets depend on ensure-security-script
security-scan: ensure-security-script ## Run comprehensive security scan
	@echo "🔒 Running comprehensive security scan..."
	@./scripts/security-scan.sh || (echo "❌ Security scan failed" && exit 1)
	@echo "✅ Security scan completed"
```

#### Error Handling

The security scanning script includes comprehensive error handling:

```bash
# Track installation results
local failed_tools=()

# Install govulncheck
print_status "Installing govulncheck..."
if go install golang.org/x/vuln/cmd/govulncheck@latest; then
    print_success "govulncheck installed"
else
    failed_tools+=("govulncheck")
    print_warning "Failed to install govulncheck"
fi

# Report results
if [ ${#failed_tools[@]} -eq 0 ]; then
    print_success "All Go security tools installed successfully"
else
    print_warning "Some tools failed to install: ${failed_tools[*]}"
    print_status "You may need to install them manually or check your Go environment"
fi
```

## CI/CD Integration

### GitHub Actions Workflow

The security scanning is integrated into CI/CD through `.github/workflows/security.yml`:

#### Workflow Jobs

1. **dependency-scan**
   - Go vulnerability checking with govulncheck
   - Static analysis with staticcheck
   - Nancy dependency scanning
   - Gosec security scanning

2. **container-scan**
   - Trivy filesystem vulnerability scanning
   - Hadolint Dockerfile linting

3. **secret-scan**
   - Gitleaks secret detection with custom configuration

4. **license-check**
   - go-licenses for license compliance
   - Optional FOSSA integration

5. **sast**
   - CodeQL analysis for Go and JavaScript
   - Security-extended queries

### Security Configuration Files

#### Gitleaks Configuration (`.gitleaks.toml`)

Custom rules for secret detection:

```toml
# MVP Zero Trust Auth - Secret Detection
title = "MVP Zero Trust Auth - Secret Detection"

[extend]
useDefault = true

[[rules]]
description = "JWT Token"
id = "jwt"
regex = '''ey[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*\.[A-Za-z0-9._-]*'''
tags = ["key", "JWT"]

[allowlist]
description = "Allowlist for known safe patterns"
regexes = [
    '''development-secret-do-not-use-in-production''',
    '''demo-token-admin-123''',
    '''mvp_password''',
    '''mvp_user'''
]
```

#### Docker Security (`.dockerignore`)

Prevents sensitive files from being included in Docker builds:

```
# Security
*.pem
*.key
*.crt
secrets/
.env
.env.*

# Development
.git/
.github/
docs/
tests/
```

## Security Scan Output

### Console Output Example

```
🔒 Running comprehensive security scan...
[INFO] Starting security scan for MVP Zero Trust Auth...
[INFO] === Running Dependency Scan ===
[INFO] Running govulncheck...
[SUCCESS] govulncheck passed
[INFO] Running staticcheck...
[SUCCESS] staticcheck passed
[INFO] === Running Secret Scan ===
[INFO] Running gitleaks...
[SUCCESS] No secrets detected
[INFO] === Running Container Security Scan ===
[INFO] Running hadolint on Dockerfile...
[SUCCESS] Dockerfile linting passed
[INFO] === Running SAST Scan ===
[INFO] Running gosec...
[SUCCESS] gosec scan passed
[INFO] === Running License Check ===
[INFO] Checking Go module licenses...
[SUCCESS] License check passed
[SUCCESS] Security report generated: security-report.md

[SUCCESS] Security scan completed!

=========================================
           SECURITY SCAN SUMMARY         
=========================================
Mode: Comprehensive Scan
Scans performed:
  ✓ Dependency vulnerability scan
  ✓ Secret detection
  ✓ Container security scan
  ✓ Static application security testing
  ✓ License compliance check
=========================================

[INFO] Review the security-report.md file for detailed results
```

### Security Report

A `security-report.md` file is generated with:

- Scan timestamp
- Summary of scans performed
- Recommendations for addressing findings
- Next steps for security improvement

## Best Practices

### Running Security Scans

1. **During Development**
   ```bash
   # Quick scan during active development
   make security-scan-quick
   ```

2. **Before Commits**
   ```bash
   # Comprehensive scan before pushing code
   make security-scan
   ```

3. **CI/CD Pipeline**
   - Automatically runs on every push and PR
   - Blocks merge if critical issues found

### Tool Installation

Install all security tools locally:

```bash
# One-time setup
make security-install

# Verify installation
which govulncheck gosec staticcheck go-licenses
```

### Handling Findings

1. **Vulnerabilities**: Update dependencies immediately
2. **Secrets**: Rotate exposed credentials, update `.gitleaks.toml`
3. **Code Issues**: Fix security issues identified by SAST
4. **License Issues**: Review and ensure compliance

## Troubleshooting

### Common Issues

#### Security script not found

```bash
❌ Security scan script not found at scripts/security-scan.sh
```

**Solution**: Ensure you're in the project root directory

#### Tool installation failures

```bash
[WARNING] Some tools failed to install: gosec govulncheck
```

**Solution**: 
1. Check Go installation: `go version`
2. Ensure `$GOPATH/bin` is in PATH
3. Install manually if needed

#### Permission denied

```bash
permission denied: ./scripts/security-scan.sh
```

**Solution**: The Makefile automatically handles this, but you can manually run:
```bash
chmod +x scripts/security-scan.sh
```

## Future Enhancements

1. **Additional Scanners**
   - Integration with Snyk or Dependabot
   - OWASP dependency check
   - Infrastructure as Code scanning

2. **Reporting Improvements**
   - SARIF format support
   - HTML report generation
   - Trend analysis over time

3. **Automation**
   - Pre-commit hooks
   - Automated fix suggestions
   - Security baseline management

## References

- [govulncheck Documentation](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
- [Gosec - Go Security Checker](https://github.com/securego/gosec)
- [Gitleaks Documentation](https://github.com/gitleaks/gitleaks)
- [Trivy Scanner](https://github.com/aquasecurity/trivy)
- [Hadolint - Dockerfile Linter](https://github.com/hadolint/hadolint)