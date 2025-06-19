#!/bin/bash

# Kubernetes Environment Cleanup Script
# Safely removes Zamaz Platform deployments with confirmation

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT=""
COMPONENT="all"
FORCE=false
DRY_RUN=false
VERBOSE=false

function usage() {
    cat << EOF
Usage: $0 [OPTIONS] -e ENVIRONMENT

Clean up Zamaz Platform deployments from Kubernetes

OPTIONS:
    -e, --environment    Environment to clean up (development|staging|production) [REQUIRED]
    -c, --component      Component to clean up (zamaz|infrastructure|platform|all) [default: all]
    -f, --force          Skip confirmation prompts
    -d, --dry-run        Show what would be deleted without actually deleting
    -v, --verbose        Enable verbose output
    -h, --help           Show this help message

WARNING: This script will DELETE resources. Use with caution!

EXAMPLES:
    $0 -e development -c zamaz
    $0 -e staging --dry-run
    $0 -e production --force  # Use with extreme caution!

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

function confirm_action() {
    local action="$1"
    local env="$2"
    
    if [[ "$FORCE" == "true" ]]; then
        log "WARN" "Force mode enabled, skipping confirmation"
        return 0
    fi
    
    echo -e "${RED}WARNING: This will $action in environment '$env'${NC}"
    echo -e "${YELLOW}This action cannot be undone!${NC}"
    echo -n "Are you sure you want to continue? (type 'yes' to confirm): "
    read -r confirmation
    
    if [[ "$confirmation" != "yes" ]]; then
        log "INFO" "Operation cancelled by user"
        exit 0
    fi
    
    return 0
}

function cleanup_zamaz() {
    local env=$1
    local ns="zamaz-$env"
    
    if [[ "$env" == "production" ]]; then
        ns="zamaz-prod"
    elif [[ "$env" == "development" ]]; then
        ns="zamaz-dev"
    fi
    
    log "INFO" "Cleaning up Zamaz application in environment '$env' (namespace: $ns)"
    
    if ! kubectl get namespace "$ns" &> /dev/null; then
        log "WARN" "Namespace '$ns' does not exist, nothing to clean up"
        return 0
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN: Would delete namespace '$ns' and all its resources"
        kubectl get all -n "$ns" 2>/dev/null || true
        return 0
    fi
    
    confirm_action "delete all Zamaz resources in namespace '$ns'" "$env"
    
    # Scale down deployments gracefully first
    log "INFO" "Scaling down deployments..."
    kubectl scale deployment --all --replicas=0 -n "$ns" 2>/dev/null || true
    
    # Wait for pods to terminate gracefully
    log "INFO" "Waiting for pods to terminate gracefully..."
    kubectl wait --for=delete pods --all -n "$ns" --timeout=60s 2>/dev/null || true
    
    # Delete the namespace (this will delete all resources in it)
    log "INFO" "Deleting namespace '$ns'..."
    kubectl delete namespace "$ns" --timeout=300s
    
    log "INFO" "Zamaz cleanup completed for environment '$env'"
}

function cleanup_infrastructure() {
    log "INFO" "Cleaning up infrastructure components"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN: Would uninstall Helm releases for infrastructure"
        helm list --all-namespaces | grep -E "(spire-integration|observability|istio-mesh)" || true
        return 0
    fi
    
    confirm_action "uninstall infrastructure Helm releases" "cluster-wide"
    
    # Uninstall Helm releases
    local releases=("spire-integration" "observability" "istio-mesh")
    
    for release in "${releases[@]}"; do
        if helm list --all-namespaces | grep -q "$release"; then
            log "INFO" "Uninstalling Helm release: $release"
            helm uninstall "$release" --namespace "${release//-*/}-system" 2>/dev/null || true
        else
            log "DEBUG" "Helm release '$release' not found"
        fi
    done
    
    # Clean up namespaces
    local namespaces=("spire-system" "observability" "istio-system")
    
    for ns in "${namespaces[@]}"; do
        if kubectl get namespace "$ns" &> /dev/null; then
            log "INFO" "Deleting namespace: $ns"
            kubectl delete namespace "$ns" --timeout=300s || true
        fi
    done
    
    log "INFO" "Infrastructure cleanup completed"
}

function cleanup_platform() {
    log "INFO" "Cleaning up platform components"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN: Would delete platform-wide resources"
        kubectl get clusterroles,clusterrolebindings,networkpolicies --all-namespaces | grep zamaz || true
        return 0
    fi
    
    confirm_action "delete platform-wide resources (ClusterRoles, NetworkPolicies, etc.)" "cluster-wide"
    
    # Clean up cluster-wide resources
    log "INFO" "Cleaning up cluster-wide resources..."
    
    # Remove ClusterRoles and ClusterRoleBindings
    kubectl delete clusterroles,clusterrolebindings -l "app.kubernetes.io/part-of=zamaz-platform" 2>/dev/null || true
    
    # Remove any remaining NetworkPolicies in system namespaces
    kubectl delete networkpolicies -l "app.kubernetes.io/part-of=zamaz-platform" --all-namespaces 2>/dev/null || true
    
    log "INFO" "Platform cleanup completed"
}

function cleanup_persistent_volumes() {
    log "INFO" "Checking for persistent volumes to clean up..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN: Would check for PVs with zamaz labels"
        kubectl get pv -l "app.kubernetes.io/part-of=zamaz-platform" 2>/dev/null || true
        return 0
    fi
    
    # Check for any persistent volumes that might be left behind
    local pvs
    pvs=$(kubectl get pv -l "app.kubernetes.io/part-of=zamaz-platform" -o name 2>/dev/null || true)
    
    if [[ -n "$pvs" ]]; then
        log "WARN" "Found persistent volumes that may need manual cleanup:"
        kubectl get pv -l "app.kubernetes.io/part-of=zamaz-platform"
        
        echo -n "Do you want to delete these persistent volumes? (type 'yes' to confirm): "
        read -r pv_confirmation
        
        if [[ "$pv_confirmation" == "yes" ]]; then
            kubectl delete pv -l "app.kubernetes.io/part-of=zamaz-platform"
            log "INFO" "Persistent volumes deleted"
        else
            log "INFO" "Persistent volumes left for manual cleanup"
        fi
    else
        log "INFO" "No persistent volumes found for cleanup"
    fi
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
            -f|--force)
                FORCE=true
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
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
    
    # Validate required arguments
    if [[ -z "$ENVIRONMENT" ]]; then
        log "ERROR" "Environment is required (-e|--environment)"
        usage
        exit 1
    fi
    
    # Validate environment
    case $ENVIRONMENT in
        "development"|"staging"|"production")
            log "DEBUG" "Environment '$ENVIRONMENT' is valid"
            ;;
        *)
            log "ERROR" "Invalid environment '$ENVIRONMENT'. Must be one of: development, staging, production"
            exit 1
            ;;
    esac
    
    # Validate component
    case $COMPONENT in
        "zamaz"|"infrastructure"|"platform"|"all")
            log "DEBUG" "Component '$COMPONENT' is valid"
            ;;
        *)
            log "ERROR" "Invalid component '$COMPONENT'. Must be one of: zamaz, infrastructure, platform, all"
            exit 1
            ;;
    esac
    
    # Extra safety for production
    if [[ "$ENVIRONMENT" == "production" && "$FORCE" != "true" ]]; then
        echo -e "${RED}DANGER: You are about to clean up PRODUCTION environment!${NC}"
        echo -e "${YELLOW}This will DELETE production data and services!${NC}"
        echo -n "Type 'DELETE PRODUCTION' to confirm: "
        read -r prod_confirmation
        
        if [[ "$prod_confirmation" != "DELETE PRODUCTION" ]]; then
            log "INFO" "Production cleanup cancelled"
            exit 0
        fi
    fi
    
    log "INFO" "Starting cleanup with environment='$ENVIRONMENT', component='$COMPONENT'"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN MODE: No actual changes will be made"
    fi
    
    # Check kubectl connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log "ERROR" "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    # Clean up components based on selection
    case $COMPONENT in
        "zamaz")
            cleanup_zamaz "$ENVIRONMENT"
            ;;
        "infrastructure")
            cleanup_infrastructure
            ;;
        "platform")
            cleanup_platform
            ;;
        "all")
            cleanup_zamaz "$ENVIRONMENT"
            cleanup_infrastructure
            cleanup_platform
            cleanup_persistent_volumes
            ;;
    esac
    
    log "INFO" "Cleanup completed!"
    
    if [[ "$DRY_RUN" != "true" ]]; then
        log "INFO" "Remaining resources:"
        kubectl get namespaces | grep -E "(zamaz|spire|observability|istio)" || log "INFO" "No related namespaces found"
    fi
}

main "$@"