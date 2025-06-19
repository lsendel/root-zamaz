#!/bin/bash

# Kubernetes Configuration Validation Script
# Validates Kustomize and Helm configurations before deployment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT="development"
COMPONENT="all"
VERBOSE=false

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
KUBERNETES_DIR="$(dirname "$SCRIPT_DIR")"

function usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Validate Kubernetes configurations for Zamaz Platform

OPTIONS:
    -e, --environment    Environment to validate (development|staging|production) [default: development]
    -c, --component      Component to validate (zamaz|infrastructure|platform|all) [default: all]
    -v, --verbose        Enable verbose output
    -h, --help           Show this help message

EXAMPLES:
    $0 -e production -c zamaz
    $0 -e staging --verbose
    $0 --help

EOF
}

function log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "ERROR")
            echo -e "${RED}[$timestamp] ERROR: $message${NC}" >&2
            ;;
        "WARN")
            echo -e "${YELLOW}[$timestamp] WARN: $message${NC}" >&2
            ;;
        "INFO")
            echo -e "${GREEN}[$timestamp] INFO: $message${NC}"
            ;;
        "DEBUG")
            if [[ "$VERBOSE" == "true" ]]; then
                echo -e "${BLUE}[$timestamp] DEBUG: $message${NC}"
            fi
            ;;
    esac
}

function check_prerequisites() {
    log "INFO" "Checking validation prerequisites..."
    
    # Check if kubectl is installed
    if ! command -v kubectl &> /dev/null; then
        log "ERROR" "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check if kustomize is installed
    if ! command -v kustomize &> /dev/null; then
        log "ERROR" "kustomize is not installed or not in PATH"
        exit 1
    fi
    
    # Check if helm is installed (for infrastructure validation)
    if [[ "$COMPONENT" == "infrastructure" || "$COMPONENT" == "all" ]]; then
        if ! command -v helm &> /dev/null; then
            log "ERROR" "helm is not installed or not in PATH"
            exit 1
        fi
    fi
    
    # Check if kubeval is installed (optional but recommended)
    if command -v kubeval &> /dev/null; then
        log "DEBUG" "kubeval found, will use for schema validation"
    else
        log "WARN" "kubeval not found, skipping schema validation (install kubeval for better validation)"
    fi
    
    log "INFO" "Prerequisites check passed"
}

function validate_kustomize_config() {
    local overlay_dir=$1
    local name=$2
    
    log "INFO" "Validating Kustomize configuration: $name"
    
    if [[ ! -d "$overlay_dir" ]]; then
        log "ERROR" "Overlay directory not found: $overlay_dir"
        return 1
    fi
    
    if [[ ! -f "$overlay_dir/kustomization.yaml" ]]; then
        log "ERROR" "kustomization.yaml not found in: $overlay_dir"
        return 1
    fi
    
    # Test kustomize build
    log "DEBUG" "Testing kustomize build for $name"
    if ! kustomize build "$overlay_dir" > /tmp/kustomize-output-$name.yaml 2>/dev/null; then
        log "ERROR" "kustomize build failed for $name"
        return 1
    fi
    
    # Validate YAML syntax
    if ! kubectl apply --dry-run=client -f /tmp/kustomize-output-$name.yaml > /dev/null 2>&1; then
        log "ERROR" "YAML validation failed for $name"
        log "DEBUG" "Run 'kubectl apply --dry-run=client -f /tmp/kustomize-output-$name.yaml' for details"
        return 1
    fi
    
    # Schema validation with kubeval if available
    if command -v kubeval &> /dev/null; then
        if ! kubeval /tmp/kustomize-output-$name.yaml > /dev/null 2>&1; then
            log "WARN" "Schema validation warnings for $name (run 'kubeval /tmp/kustomize-output-$name.yaml' for details)"
        fi
    fi
    
    # Check for required labels
    if ! grep -q "app.kubernetes.io/name" /tmp/kustomize-output-$name.yaml; then
        log "WARN" "Missing standard label 'app.kubernetes.io/name' in $name"
    fi
    
    if ! grep -q "app.kubernetes.io/managed-by" /tmp/kustomize-output-$name.yaml; then
        log "WARN" "Missing standard label 'app.kubernetes.io/managed-by' in $name"
    fi
    
    # Check for security contexts in deployments
    if grep -q "kind: Deployment" /tmp/kustomize-output-$name.yaml; then
        if ! grep -q "securityContext" /tmp/kustomize-output-$name.yaml; then
            log "WARN" "Deployment in $name missing securityContext"
        fi
        
        if ! grep -q "runAsNonRoot: true" /tmp/kustomize-output-$name.yaml; then
            log "WARN" "Deployment in $name should set runAsNonRoot: true"
        fi
    fi
    
    # Check for resource limits
    if grep -q "kind: Deployment" /tmp/kustomize-output-$name.yaml; then
        if ! grep -q "resources:" /tmp/kustomize-output-$name.yaml; then
            log "WARN" "Deployment in $name missing resource limits"
        fi
    fi
    
    # Clean up
    rm -f /tmp/kustomize-output-$name.yaml
    
    log "INFO" "Kustomize validation passed for $name"
    return 0
}

function validate_helm_chart() {
    local chart_dir=$1
    local name=$2
    
    log "INFO" "Validating Helm chart: $name"
    
    if [[ ! -d "$chart_dir" ]]; then
        log "ERROR" "Chart directory not found: $chart_dir"
        return 1
    fi
    
    if [[ ! -f "$chart_dir/Chart.yaml" ]]; then
        log "ERROR" "Chart.yaml not found in: $chart_dir"
        return 1
    fi
    
    # Lint the chart
    log "DEBUG" "Linting Helm chart for $name"
    if ! helm lint "$chart_dir" > /tmp/helm-lint-$name.log 2>&1; then
        log "ERROR" "Helm lint failed for $name"
        log "DEBUG" "Lint output: $(cat /tmp/helm-lint-$name.log)"
        return 1
    fi
    
    # Template the chart
    log "DEBUG" "Templating Helm chart for $name"
    if ! helm template test-release "$chart_dir" > /tmp/helm-template-$name.yaml 2>/dev/null; then
        log "ERROR" "Helm template failed for $name"
        return 1
    fi
    
    # Validate YAML syntax
    if ! kubectl apply --dry-run=client -f /tmp/helm-template-$name.yaml > /dev/null 2>&1; then
        log "ERROR" "YAML validation failed for Helm chart $name"
        return 1
    fi
    
    # Schema validation with kubeval if available
    if command -v kubeval &> /dev/null; then
        if ! kubeval /tmp/helm-template-$name.yaml > /dev/null 2>&1; then
            log "WARN" "Schema validation warnings for Helm chart $name"
        fi
    fi
    
    # Clean up
    rm -f /tmp/helm-lint-$name.log /tmp/helm-template-$name.yaml
    
    log "INFO" "Helm chart validation passed for $name"
    return 0
}

function validate_zamaz() {
    local env=$1
    
    log "INFO" "Validating Zamaz application for environment: $env"
    
    local overlay_dir="$KUBERNETES_DIR/apps/zamaz/overlays/$env"
    
    if ! validate_kustomize_config "$overlay_dir" "zamaz-$env"; then
        return 1
    fi
    
    # Validate base configuration
    local base_dir="$KUBERNETES_DIR/apps/zamaz/base"
    if ! validate_kustomize_config "$base_dir" "zamaz-base"; then
        return 1
    fi
    
    log "INFO" "Zamaz validation completed successfully"
    return 0
}

function validate_infrastructure() {
    log "INFO" "Validating infrastructure components"
    
    local charts_dir="$KUBERNETES_DIR/../charts"
    local validation_failed=false
    
    # Validate each infrastructure chart
    for chart in istio-mesh observability spire-integration security-policies; do
        local chart_dir="$charts_dir/$chart"
        if [[ -d "$chart_dir" ]]; then
            if ! validate_helm_chart "$chart_dir" "$chart"; then
                validation_failed=true
            fi
        else
            log "WARN" "Chart directory not found: $chart_dir"
        fi
    done
    
    if [[ "$validation_failed" == "true" ]]; then
        return 1
    fi
    
    log "INFO" "Infrastructure validation completed successfully"
    return 0
}

function validate_platform() {
    log "INFO" "Validating platform components"
    
    local platform_dir="$KUBERNETES_DIR/platform"
    
    if [[ ! -d "$platform_dir" ]]; then
        log "WARN" "Platform directory not found: $platform_dir"
        return 0
    fi
    
    local validation_failed=false
    
    # Validate each platform component
    for component in namespaces network-policies rbac secrets; do
        local component_dir="$platform_dir/$component"
        if [[ -d "$component_dir" ]]; then
            if ! validate_kustomize_config "$component_dir" "platform-$component"; then
                validation_failed=true
            fi
        else
            log "DEBUG" "Platform component directory not found: $component_dir"
        fi
    done
    
    if [[ "$validation_failed" == "true" ]]; then
        return 1
    fi
    
    log "INFO" "Platform validation completed successfully"
    return 0
}

function check_naming_conventions() {
    log "INFO" "Checking naming conventions..."
    
    # Check for consistent naming patterns
    local issues_found=false
    
    # Check Zamaz configurations
    local zamaz_files=$(find "$KUBERNETES_DIR/apps/zamaz" -name "*.yaml" -type f)
    
    for file in $zamaz_files; do
        # Check for inconsistent naming
        if grep -q "name:.*zamaz.*api" "$file" && ! grep -q "zamaz-api" "$file"; then
            log "WARN" "Inconsistent naming in $file - should use 'zamaz-api' format"
            issues_found=true
        fi
        
        if grep -q "name:.*zamaz.*frontend" "$file" && ! grep -q "zamaz-frontend" "$file"; then
            log "WARN" "Inconsistent naming in $file - should use 'zamaz-frontend' format"
            issues_found=true
        fi
    done
    
    if [[ "$issues_found" == "false" ]]; then
        log "INFO" "Naming conventions check passed"
    else
        log "WARN" "Some naming convention issues found"
    fi
    
    return 0
}

function main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -c|--component)
                COMPONENT="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    log "INFO" "Starting validation for environment='$ENVIRONMENT', component='$COMPONENT'"
    
    # Check prerequisites
    check_prerequisites
    
    # Validation flags
    local validation_failed=false
    
    # Validate components based on selection
    case $COMPONENT in
        "zamaz")
            if ! validate_zamaz "$ENVIRONMENT"; then
                validation_failed=true
            fi
            ;;
        "infrastructure")
            if ! validate_infrastructure; then
                validation_failed=true
            fi
            ;;
        "platform")
            if ! validate_platform; then
                validation_failed=true
            fi
            ;;
        "all")
            if ! validate_platform; then
                validation_failed=true
            fi
            if ! validate_infrastructure; then
                validation_failed=true
            fi
            if ! validate_zamaz "$ENVIRONMENT"; then
                validation_failed=true
            fi
            ;;
    esac
    
    # Check naming conventions
    check_naming_conventions
    
    # Final result
    if [[ "$validation_failed" == "true" ]]; then
        log "ERROR" "Validation failed!"
        exit 1
    else
        log "INFO" "All validations passed successfully!"
        exit 0
    fi
}

main "$@"