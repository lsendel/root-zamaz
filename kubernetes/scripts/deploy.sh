#!/bin/bash

# Unified Kubernetes Deployment Script for Zamaz Platform
# This script replaces the complex Helm/Kustomize hybrid approach with a standardized deployment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT="development"
DRY_RUN=false
VERBOSE=false
NAMESPACE=""
COMPONENT="all"
VALIDATE=true

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
KUBERNETES_DIR="$(dirname "$SCRIPT_DIR")"

function usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy Zamaz Platform components to Kubernetes

OPTIONS:
    -e, --environment    Environment to deploy (development|staging|production) [default: development]
    -c, --component      Component to deploy (zamaz|infrastructure|platform|all) [default: all]
    -n, --namespace      Override namespace (optional)
    -d, --dry-run        Perform a dry run without applying changes
    -v, --verbose        Enable verbose output
    --skip-validation    Skip pre-deployment validation
    -h, --help           Show this help message

EXAMPLES:
    $0 -e development -c zamaz
    $0 -e production --dry-run
    $0 -e staging -v
    $0 --help

ENVIRONMENTS:
    development    Deploy to development environment with debug features
    staging        Deploy to staging environment for testing
    production     Deploy to production environment with full security

COMPONENTS:
    zamaz          Deploy only the Zamaz application (Kustomize)
    infrastructure Deploy infrastructure components (Helm)
    platform       Deploy platform-wide configurations
    all            Deploy all components (default)

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
    log "INFO" "Checking prerequisites..."
    
    # Check if kubectl is installed and configured
    if ! command -v kubectl &> /dev/null; then
        log "ERROR" "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check if kustomize is installed
    if ! command -v kustomize &> /dev/null; then
        log "ERROR" "kustomize is not installed or not in PATH"
        exit 1
    fi
    
    # Check if helm is installed (for infrastructure components)
    if [[ "$COMPONENT" == "infrastructure" || "$COMPONENT" == "all" ]]; then
        if ! command -v helm &> /dev/null; then
            log "ERROR" "helm is not installed or not in PATH (required for infrastructure components)"
            exit 1
        fi
    fi
    
    # Check kubectl connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log "ERROR" "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log "INFO" "Prerequisites check passed"
}

function validate_environment() {
    local env=$1
    
    case $env in
        "development"|"staging"|"production")
            log "DEBUG" "Environment '$env' is valid"
            ;;
        *)
            log "ERROR" "Invalid environment '$env'. Must be one of: development, staging, production"
            exit 1
            ;;
    esac
}

function validate_component() {
    local comp=$1
    
    case $comp in
        "zamaz"|"infrastructure"|"platform"|"all")
            log "DEBUG" "Component '$comp' is valid"
            ;;
        *)
            log "ERROR" "Invalid component '$comp'. Must be one of: zamaz, infrastructure, platform, all"
            exit 1
            ;;
    esac
}

function validate_configs() {
    if [[ "$VALIDATE" != "true" ]]; then
        log "INFO" "Skipping validation (--skip-validation flag provided)"
        return 0
    fi
    
    log "INFO" "Validating configurations..."
    
    local validation_script="$SCRIPT_DIR/validate.sh"
    if [[ -f "$validation_script" ]]; then
        if ! "$validation_script" -e "$ENVIRONMENT" -c "$COMPONENT"; then
            log "ERROR" "Configuration validation failed"
            exit 1
        fi
    else
        log "WARN" "Validation script not found at $validation_script, skipping validation"
    fi
    
    log "INFO" "Configuration validation passed"
}

function deploy_zamaz() {
    local env=$1
    local ns=${NAMESPACE:-"zamaz-$env"}
    
    if [[ "$env" == "production" ]]; then
        ns=${NAMESPACE:-"zamaz-prod"}
    elif [[ "$env" == "development" ]]; then
        ns=${NAMESPACE:-"zamaz-dev"}
    fi
    
    log "INFO" "Deploying Zamaz application to environment '$env' in namespace '$ns'..."
    
    local overlay_dir="$KUBERNETES_DIR/apps/zamaz/overlays/$env"
    
    if [[ ! -d "$overlay_dir" ]]; then
        log "ERROR" "Overlay directory not found: $overlay_dir"
        exit 1
    fi
    
    local kustomize_cmd="kustomize build $overlay_dir"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN: Would execute: $kustomize_cmd | kubectl apply -f -"
        $kustomize_cmd
    else
        log "DEBUG" "Executing: $kustomize_cmd | kubectl apply -f -"
        $kustomize_cmd | kubectl apply -f -
        
        # Wait for rollout to complete
        log "INFO" "Waiting for deployment rollout to complete..."
        kubectl rollout status deployment/$(echo "$env" | cut -c1-4)-zamaz-api-deployment -n "$ns" --timeout=300s
        kubectl rollout status deployment/$(echo "$env" | cut -c1-4)-zamaz-frontend-deployment -n "$ns" --timeout=300s
    fi
    
    log "INFO" "Zamaz application deployment completed"
}

function deploy_infrastructure() {
    local env=$1
    
    log "INFO" "Deploying infrastructure components for environment '$env'..."
    
    # Deploy SPIRE
    local spire_chart="$KUBERNETES_DIR/../charts/spire-integration"
    if [[ -d "$spire_chart" ]]; then
        log "INFO" "Deploying SPIRE integration..."
        local helm_cmd="helm upgrade --install spire-integration $spire_chart --namespace spire-system --create-namespace"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log "INFO" "DRY RUN: Would execute: $helm_cmd --dry-run"
            $helm_cmd --dry-run
        else
            $helm_cmd
        fi
    fi
    
    # Deploy Observability
    local obs_chart="$KUBERNETES_DIR/../charts/observability"
    if [[ -d "$obs_chart" ]]; then
        log "INFO" "Deploying observability stack..."
        local helm_cmd="helm upgrade --install observability $obs_chart --namespace observability --create-namespace"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log "INFO" "DRY RUN: Would execute: $helm_cmd --dry-run"
            $helm_cmd --dry-run
        else
            $helm_cmd
        fi
    fi
    
    # Deploy Istio Mesh
    local istio_chart="$KUBERNETES_DIR/../charts/istio-mesh"
    if [[ -d "$istio_chart" ]]; then
        log "INFO" "Deploying Istio service mesh..."
        local helm_cmd="helm upgrade --install istio-mesh $istio_chart --namespace istio-system --create-namespace"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log "INFO" "DRY RUN: Would execute: $helm_cmd --dry-run"
            $helm_cmd --dry-run
        else
            $helm_cmd
        fi
    fi
    
    log "INFO" "Infrastructure deployment completed"
}

function deploy_platform() {
    local env=$1
    
    log "INFO" "Deploying platform components for environment '$env'..."
    
    # Deploy platform-wide configurations using Kustomize
    local platform_dir="$KUBERNETES_DIR/platform"
    
    if [[ -d "$platform_dir" ]]; then
        for component in namespaces network-policies rbac secrets; do
            local component_dir="$platform_dir/$component"
            if [[ -d "$component_dir" ]]; then
                log "INFO" "Deploying platform component: $component"
                local kustomize_cmd="kustomize build $component_dir"
                
                if [[ "$DRY_RUN" == "true" ]]; then
                    log "INFO" "DRY RUN: Would execute: $kustomize_cmd | kubectl apply -f -"
                    $kustomize_cmd
                else
                    $kustomize_cmd | kubectl apply -f -
                fi
            fi
        done
    fi
    
    log "INFO" "Platform deployment completed"
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
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --skip-validation)
                VALIDATE=false
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
    
    # Validate inputs
    validate_environment "$ENVIRONMENT"
    validate_component "$COMPONENT"
    
    log "INFO" "Starting deployment with environment='$ENVIRONMENT', component='$COMPONENT'"
    
    # Check prerequisites
    check_prerequisites
    
    # Validate configurations
    validate_configs
    
    # Deploy components based on selection
    case $COMPONENT in
        "zamaz")
            deploy_zamaz "$ENVIRONMENT"
            ;;
        "infrastructure")
            deploy_infrastructure "$ENVIRONMENT"
            ;;
        "platform")
            deploy_platform "$ENVIRONMENT"
            ;;
        "all")
            deploy_platform "$ENVIRONMENT"
            deploy_infrastructure "$ENVIRONMENT"
            deploy_zamaz "$ENVIRONMENT"
            ;;
    esac
    
    log "INFO" "Deployment completed successfully!"
    
    # Show deployment status
    if [[ "$DRY_RUN" != "true" ]]; then
        log "INFO" "Deployment status:"
        if [[ "$COMPONENT" == "zamaz" || "$COMPONENT" == "all" ]]; then
            local ns=${NAMESPACE:-"zamaz-$ENVIRONMENT"}
            if [[ "$ENVIRONMENT" == "production" ]]; then
                ns=${NAMESPACE:-"zamaz-prod"}
            elif [[ "$ENVIRONMENT" == "development" ]]; then
                ns=${NAMESPACE:-"zamaz-dev"}
            fi
            kubectl get pods -n "$ns" -l "app.kubernetes.io/name=zamaz"
        fi
    fi
}

main "$@"