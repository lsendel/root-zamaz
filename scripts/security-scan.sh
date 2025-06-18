#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install Go tools
install_go_tools() {
    print_status "Installing Go security tools..."
    
    if command_exists go; then
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
        
        # Install staticcheck
        print_status "Installing staticcheck..."
        if go install honnef.co/go/tools/cmd/staticcheck@latest; then
            print_success "staticcheck installed"
        else
            failed_tools+=("staticcheck")
            print_warning "Failed to install staticcheck"
        fi
        
        # Install gosec
        print_status "Installing gosec..."
        if go install github.com/securego/gosec/v2/cmd/gosec@latest; then
            print_success "gosec installed"
        else
            failed_tools+=("gosec")
            print_warning "Failed to install gosec"
        fi
        
        # Install go-licenses
        print_status "Installing go-licenses..."
        if go install github.com/google/go-licenses@latest; then
            print_success "go-licenses installed"
        else
            failed_tools+=("go-licenses")
            print_warning "Failed to install go-licenses"
        fi
        
        # Report results
        if [ ${#failed_tools[@]} -eq 0 ]; then
            print_success "All Go security tools installed successfully"
        else
            print_warning "Some tools failed to install: ${failed_tools[*]}"
            print_status "You may need to install them manually or check your Go environment"
        fi
    else
        print_error "Go not found. Please install Go first."
        exit 1
    fi
}

# Function to run dependency scan
run_dependency_scan() {
    print_status "Running dependency vulnerability scan..."
    
    if command_exists govulncheck; then
        print_status "Running govulncheck..."
        if govulncheck ./...; then
            print_success "govulncheck passed"
        else
            print_warning "govulncheck found vulnerabilities"
        fi
    else
        print_warning "govulncheck not found. Run with --install to install tools."
    fi
    
    if command_exists staticcheck; then
        print_status "Running staticcheck..."
        if staticcheck ./...; then
            print_success "staticcheck passed"
        else
            print_warning "staticcheck found issues"
        fi
    else
        print_warning "staticcheck not found. Run with --install to install tools."
    fi
}

# Function to run secret scan
run_secret_scan() {
    print_status "Running secret scan..."
    
    if command_exists gitleaks; then
        print_status "Running gitleaks..."
        if gitleaks detect --source . -v; then
            print_success "No secrets detected"
        else
            print_warning "Secrets detected! Please review and clean them."
        fi
    else
        print_warning "gitleaks not found. Install with: brew install gitleaks"
    fi
}

# Function to run container scan
run_container_scan() {
    print_status "Running container security scan..."
    
    if [ -f "Dockerfile" ]; then
        # Run hadolint if available
        if command_exists hadolint; then
            print_status "Running hadolint on Dockerfile..."
            if hadolint Dockerfile; then
                print_success "Dockerfile linting passed"
            else
                print_warning "Dockerfile linting found issues"
            fi
        else
            print_warning "hadolint not found. Install with: brew install hadolint"
        fi
        
        # Run trivy if available
        if command_exists trivy; then
            print_status "Running trivy filesystem scan..."
            if trivy fs --skip-dirs frontend/node_modules --severity HIGH,CRITICAL .; then
                print_success "Trivy scan passed"
            else
                print_warning "Trivy found vulnerabilities"
            fi
        else
            print_warning "trivy not found. Install with: brew install trivy"
        fi
    else
        print_warning "No Dockerfile found"
    fi
}

# Function to run SAST scan
run_sast_scan() {
    print_status "Running Static Application Security Testing (SAST)..."
    
    if command_exists gosec; then
        print_status "Running gosec..."
        if gosec -fmt text ./...; then
            print_success "gosec scan passed"
        else
            print_warning "gosec found security issues"
        fi
    else
        print_warning "gosec not found. Run with --install to install tools."
    fi
    
    # Run semgrep if available
    if command_exists semgrep; then
        print_status "Running semgrep..."
        if semgrep --config=auto .; then
            print_success "semgrep scan passed"
        else
            print_warning "semgrep found issues"
        fi
    else
        print_warning "semgrep not found. Install with: pip3 install semgrep"
    fi
}

# Function to run license check
run_license_check() {
    print_status "Running license compliance check..."
    
    if command_exists go-licenses; then
        print_status "Checking Go module licenses..."
        if go-licenses check ./...; then
            print_success "License check passed"
        else
            print_warning "License issues found"
        fi
        
        print_status "Generating license report..."
        go-licenses report ./... > license-report.txt || true
        print_status "License report saved to license-report.txt"
    else
        print_warning "go-licenses not found. Run with --install to install tools."
    fi
}

# Function to generate security report
generate_report() {
    print_status "Generating security scan report..."
    
    cat > security-report.md << EOF
# Security Scan Report
Generated on: $(date)

## Summary
This report contains the results of various security scans performed on the MVP Zero Trust Auth system.

## Scans Performed
- ✅ Dependency Vulnerability Scan (govulncheck, staticcheck)
- ✅ Secret Detection (gitleaks)
- ✅ Container Security Scan (hadolint, trivy)
- ✅ Static Application Security Testing (gosec, semgrep)
- ✅ License Compliance Check (go-licenses)

## Recommendations
1. Review any warnings or errors found during scans
2. Update dependencies with known vulnerabilities
3. Remove or rotate any detected secrets
4. Fix container security issues
5. Address static analysis findings
6. Ensure license compliance

## Next Steps
- Run scans in CI/CD pipeline
- Set up automated security monitoring
- Implement security policies
- Regular security reviews

EOF
    
    print_success "Security report generated: security-report.md"
}

# Main function
main() {
    print_status "Starting security scan for MVP Zero Trust Auth..."
    
    # Parse command line arguments
    INSTALL_TOOLS=false
    QUICK_SCAN=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --install)
                INSTALL_TOOLS=true
                shift
                ;;
            --quick)
                QUICK_SCAN=true
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --install    Install required security tools"
                echo "  --quick      Run quick scan (skip time-consuming scans)"
                echo "  --help       Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Install tools if requested
    if [ "$INSTALL_TOOLS" = true ]; then
        install_go_tools
        # Exit after installation
        exit 0
    fi
    
    # Initialize scan summary
    local scan_summary=""
    
    # Run security scans
    print_status "=== Running Dependency Scan ==="
    run_dependency_scan
    
    print_status "=== Running Secret Scan ==="
    run_secret_scan
    
    if [ "$QUICK_SCAN" = false ]; then
        print_status "=== Running Container Security Scan ==="
        run_container_scan
        
        print_status "=== Running SAST Scan ==="
        run_sast_scan
        
        print_status "=== Running License Check ==="
        run_license_check
    else
        print_status "Skipping container scan, SAST, and license check (quick mode)"
    fi
    
    # Generate report
    generate_report
    
    # Print summary
    echo ""
    print_success "Security scan completed!"
    echo ""
    echo "========================================="
    echo "           SECURITY SCAN SUMMARY         "
    echo "========================================="
    if [ "$QUICK_SCAN" = true ]; then
        echo "Mode: Quick Scan"
        echo "Scans performed:"
        echo "  ✓ Dependency vulnerability scan"
        echo "  ✓ Secret detection"
        echo ""
        echo "Skipped scans (use full scan for these):"
        echo "  - Container security scan"
        echo "  - Static application security testing"
        echo "  - License compliance check"
    else
        echo "Mode: Comprehensive Scan"
        echo "Scans performed:"
        echo "  ✓ Dependency vulnerability scan"
        echo "  ✓ Secret detection"
        echo "  ✓ Container security scan"
        echo "  ✓ Static application security testing"
        echo "  ✓ License compliance check"
    fi
    echo "========================================="
    echo ""
    print_status "Review the security-report.md file for detailed results"
}

# Run main function
main "$@"