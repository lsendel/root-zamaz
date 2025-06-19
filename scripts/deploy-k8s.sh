#!/bin/bash

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT="${1:-staging}"
NAMESPACE="${2:-zamaz-${ENVIRONMENT}}"
TIMEOUT="${TIMEOUT:-300}"
DRY_RUN="${DRY_RUN:-false}"
KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

# Base directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
K8S_DIR="${PROJECT_ROOT}/kubernetes/apps/zamaz"

# Log functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_tools=()
    
    # Check required tools
    for tool in kubectl kustomize; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Please install missing tools before proceeding."
        exit 1
    fi
    
    # Check kubectl connection
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster. Please check your kubeconfig."
        exit 1
    fi
    
    # Check if environment overlay exists
    if [ ! -d "${K8S_DIR}/overlays/${ENVIRONMENT}" ]; then
        log_error "Environment overlay not found: ${K8S_DIR}/overlays/${ENVIRONMENT}"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Create namespace if it doesn't exist
create_namespace() {
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_info "Namespace $NAMESPACE already exists"
    else
        log_info "Creating namespace $NAMESPACE..."
        kubectl create namespace "$NAMESPACE"
        
        # Label namespace for environment
        kubectl label namespace "$NAMESPACE" \
            environment="$ENVIRONMENT" \
            managed-by="kustomize" \
            app="zamaz"
        
        log_success "Namespace $NAMESPACE created"
    fi
}

# Apply Kubernetes manifests using Kustomize
apply_manifests() {
    log_info "Building Kustomize manifests for $ENVIRONMENT..."
    
    local kustomize_output
    kustomize_output=$(cd "${K8S_DIR}/overlays/${ENVIRONMENT}" && kustomize build)
    
    if [ "$DRY_RUN" == "true" ]; then
        log_warning "DRY RUN MODE - Showing what would be applied:"
        echo "$kustomize_output"
        return 0
    fi
    
    log_info "Applying manifests to namespace $NAMESPACE..."
    echo "$kustomize_output" | kubectl apply -n "$NAMESPACE" -f -
    
    log_success "Manifests applied successfully"
}

# Wait for deployments to be ready
wait_for_deployments() {
    log_info "Waiting for deployments to be ready..."
    
    local deployments
    deployments=$(kubectl get deployments -n "$NAMESPACE" -o json | jq -r '.items[].metadata.name')
    
    for deployment in $deployments; do
        log_info "Waiting for deployment $deployment..."
        if kubectl rollout status deployment/"$deployment" -n "$NAMESPACE" --timeout="${TIMEOUT}s"; then
            log_success "Deployment $deployment is ready"
        else
            log_error "Deployment $deployment failed to become ready within ${TIMEOUT}s"
            return 1
        fi
    done
    
    log_success "All deployments are ready"
}

# Perform health checks
perform_health_checks() {
    log_info "Performing health checks..."
    
    # Check pod status
    local unhealthy_pods
    unhealthy_pods=$(kubectl get pods -n "$NAMESPACE" --field-selector=status.phase!=Running,status.phase!=Succeeded -o json | jq -r '.items[].metadata.name')
    
    if [ -n "$unhealthy_pods" ]; then
        log_warning "Unhealthy pods detected:"
        echo "$unhealthy_pods"
        
        # Show pod details
        for pod in $unhealthy_pods; do
            log_info "Pod $pod status:"
            kubectl describe pod "$pod" -n "$NAMESPACE" | tail -20
        done
        
        return 1
    fi
    
    # Check services
    local services
    services=$(kubectl get services -n "$NAMESPACE" -o json | jq -r '.items[].metadata.name')
    
    for service in $services; do
        local endpoints
        endpoints=$(kubectl get endpoints "$service" -n "$NAMESPACE" -o json | jq -r '.subsets[].addresses[]?.ip' 2>/dev/null)
        
        if [ -z "$endpoints" ]; then
            log_warning "Service $service has no endpoints"
        else
            log_success "Service $service has endpoints: $(echo "$endpoints" | tr '\n' ' ')"
        fi
    done
    
    log_success "Health checks completed"
}

# Show deployment summary
show_summary() {
    log_info "Deployment Summary for $ENVIRONMENT environment:"
    echo
    echo "Namespace: $NAMESPACE"
    echo "Deployments:"
    kubectl get deployments -n "$NAMESPACE" -o wide
    echo
    echo "Services:"
    kubectl get services -n "$NAMESPACE" -o wide
    echo
    echo "Pods:"
    kubectl get pods -n "$NAMESPACE" -o wide
    echo
}

# Rollback on failure
rollback() {
    log_error "Deployment failed, rolling back..."
    
    local deployments
    deployments=$(kubectl get deployments -n "$NAMESPACE" -o json | jq -r '.items[].metadata.name')
    
    for deployment in $deployments; do
        log_info "Rolling back deployment $deployment..."
        kubectl rollout undo deployment/"$deployment" -n "$NAMESPACE" || true
    done
    
    log_warning "Rollback completed. Please check the deployment status."
}

# Main deployment function
main() {
    log_info "Starting deployment to $ENVIRONMENT environment"
    
    # Trap errors and perform rollback
    trap 'rollback' ERR
    
    # Execute deployment steps
    check_prerequisites
    create_namespace
    apply_manifests
    
    if [ "$DRY_RUN" != "true" ]; then
        wait_for_deployments
        perform_health_checks
        show_summary
    fi
    
    # Remove error trap on success
    trap - ERR
    
    log_success "Deployment to $ENVIRONMENT completed successfully!"
}

# Show usage
usage() {
    cat << EOF
Usage: $0 [ENVIRONMENT] [NAMESPACE]

Deploy Kubernetes manifests using Kustomize

Arguments:
  ENVIRONMENT    Target environment (default: staging)
  NAMESPACE      Kubernetes namespace (default: zamaz-ENVIRONMENT)

Environment Variables:
  DRY_RUN        Set to 'true' to show what would be deployed without applying
  TIMEOUT        Timeout in seconds for deployment rollout (default: 300)
  KUBECONFIG     Path to kubeconfig file (default: ~/.kube/config)

Examples:
  # Deploy to staging
  $0 staging

  # Deploy to production
  $0 production

  # Dry run for production
  DRY_RUN=true $0 production

  # Deploy with custom timeout
  TIMEOUT=600 $0 production
EOF
}

# Parse arguments
case "${1:-}" in
    -h|--help|help)
        usage
        exit 0
        ;;
esac

# Run main function
main