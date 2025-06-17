#!/bin/bash

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
OUTPUT_DIR="${OUTPUT_DIR:-$HOME/.kube/configs}"
CLUSTER_NAME="${1:-}"
NAMESPACE="${2:-}"
SERVICE_ACCOUNT="${3:-default}"

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

# Show usage
usage() {
    cat << EOF
Usage: $0 [CLUSTER_NAME] [NAMESPACE] [SERVICE_ACCOUNT]

Export kubeconfig files for different environments and service accounts

Arguments:
  CLUSTER_NAME     Name of the cluster (required)
  NAMESPACE        Namespace to create kubeconfig for (required)
  SERVICE_ACCOUNT  Service account name (default: default)

Environment Variables:
  OUTPUT_DIR       Directory to save kubeconfig files (default: ~/.kube/configs)

Examples:
  # Export kubeconfig for staging environment
  $0 staging-cluster zamaz-staging zamaz-app

  # Export kubeconfig for production with custom service account
  $0 prod-cluster zamaz-production zamaz-admin

  # Export with custom output directory
  OUTPUT_DIR=/tmp/kubeconfigs $0 dev-cluster zamaz-dev
EOF
}

# Validate arguments
validate_args() {
    if [ -z "$CLUSTER_NAME" ] || [ -z "$NAMESPACE" ]; then
        log_error "Cluster name and namespace are required"
        echo
        usage
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed"
        exit 1
    fi
    
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Get cluster information
get_cluster_info() {
    log_info "Getting cluster information..."
    
    # Get current context
    CURRENT_CONTEXT=$(kubectl config current-context)
    
    # Get cluster server URL
    CLUSTER_SERVER=$(kubectl config view -o jsonpath="{.clusters[?(@.name==\"$CURRENT_CONTEXT\")].cluster.server}")
    
    if [ -z "$CLUSTER_SERVER" ]; then
        # Try alternative method
        CLUSTER_SERVER=$(kubectl cluster-info | grep "Kubernetes control plane" | awk '{print $NF}')
    fi
    
    # Get cluster CA certificate
    CLUSTER_CA=$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name==\"$CURRENT_CONTEXT\")].cluster.certificate-authority-data}")
    
    log_info "Cluster server: $CLUSTER_SERVER"
}

# Create service account if it doesn't exist
ensure_service_account() {
    log_info "Ensuring service account $SERVICE_ACCOUNT exists in namespace $NAMESPACE..."
    
    # Create namespace if it doesn't exist
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_info "Creating namespace $NAMESPACE..."
        kubectl create namespace "$NAMESPACE"
    fi
    
    # Create service account if it doesn't exist
    if ! kubectl get serviceaccount "$SERVICE_ACCOUNT" -n "$NAMESPACE" &> /dev/null; then
        log_info "Creating service account $SERVICE_ACCOUNT..."
        kubectl create serviceaccount "$SERVICE_ACCOUNT" -n "$NAMESPACE"
    fi
    
    # Create token for service account (for Kubernetes 1.24+)
    if kubectl version --short 2>/dev/null | grep -q "Server Version: v1.2[4-9]"; then
        log_info "Creating token for Kubernetes 1.24+..."
        
        # Check if secret already exists
        SECRET_NAME="${SERVICE_ACCOUNT}-token"
        if ! kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" &> /dev/null; then
            cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: ${SECRET_NAME}
  namespace: ${NAMESPACE}
  annotations:
    kubernetes.io/service-account.name: ${SERVICE_ACCOUNT}
type: kubernetes.io/service-account-token
EOF
        fi
        
        # Wait for token to be populated
        log_info "Waiting for token to be created..."
        for i in {1..30}; do
            if kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath='{.data.token}' 2>/dev/null | grep -q .; then
                break
            fi
            sleep 1
        done
    fi
    
    log_success "Service account ready"
}

# Get service account token
get_service_account_token() {
    log_info "Getting service account token..."
    
    # For Kubernetes 1.24+, use the manually created secret
    if kubectl version --short 2>/dev/null | grep -q "Server Version: v1.2[4-9]"; then
        SECRET_NAME="${SERVICE_ACCOUNT}-token"
        TOKEN=$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath='{.data.token}' | base64 -d)
    else
        # For older versions, get the auto-generated secret
        SECRET_NAME=$(kubectl get serviceaccount "$SERVICE_ACCOUNT" -n "$NAMESPACE" -o jsonpath='{.secrets[0].name}')
        TOKEN=$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath='{.data.token}' | base64 -d)
    fi
    
    if [ -z "$TOKEN" ]; then
        log_error "Failed to get service account token"
        exit 1
    fi
    
    log_success "Token retrieved"
}

# Create kubeconfig file
create_kubeconfig() {
    log_info "Creating kubeconfig file..."
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Generate kubeconfig filename
    KUBECONFIG_FILE="${OUTPUT_DIR}/kubeconfig-${CLUSTER_NAME}-${NAMESPACE}-${SERVICE_ACCOUNT}.yaml"
    
    # Create kubeconfig
    cat > "$KUBECONFIG_FILE" <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: ${CLUSTER_CA}
    server: ${CLUSTER_SERVER}
  name: ${CLUSTER_NAME}
contexts:
- context:
    cluster: ${CLUSTER_NAME}
    namespace: ${NAMESPACE}
    user: ${SERVICE_ACCOUNT}
  name: ${CLUSTER_NAME}-${NAMESPACE}-${SERVICE_ACCOUNT}
current-context: ${CLUSTER_NAME}-${NAMESPACE}-${SERVICE_ACCOUNT}
users:
- name: ${SERVICE_ACCOUNT}
  user:
    token: ${TOKEN}
EOF
    
    # Set appropriate permissions
    chmod 600 "$KUBECONFIG_FILE"
    
    log_success "Kubeconfig created: $KUBECONFIG_FILE"
}

# Test kubeconfig
test_kubeconfig() {
    log_info "Testing kubeconfig..."
    
    # Test connection
    if KUBECONFIG="$KUBECONFIG_FILE" kubectl get pods -n "$NAMESPACE" &> /dev/null; then
        log_success "Kubeconfig test successful"
    else
        log_warning "Kubeconfig test failed - this may be due to RBAC permissions"
    fi
}

# Create RBAC for the service account
create_rbac() {
    log_info "Creating RBAC for service account (optional)..."
    
    read -p "Do you want to create RBAC rules for this service account? (y/N) " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ${SERVICE_ACCOUNT}-role
  namespace: ${NAMESPACE}
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "secrets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${SERVICE_ACCOUNT}-rolebinding
  namespace: ${NAMESPACE}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ${SERVICE_ACCOUNT}-role
subjects:
- kind: ServiceAccount
  name: ${SERVICE_ACCOUNT}
  namespace: ${NAMESPACE}
EOF
        log_success "RBAC created"
    fi
}

# Show instructions
show_instructions() {
    cat << EOF

${GREEN}Kubeconfig exported successfully!${NC}

To use this kubeconfig:

1. Set the KUBECONFIG environment variable:
   export KUBECONFIG="$KUBECONFIG_FILE"

2. Or use it with kubectl directly:
   kubectl --kubeconfig="$KUBECONFIG_FILE" get pods

3. Or merge it with your existing kubeconfig:
   KUBECONFIG="$KUBECONFIG_FILE:~/.kube/config" kubectl config view --flatten > ~/.kube/config.new
   mv ~/.kube/config.new ~/.kube/config

4. To use as default context:
   kubectl config use-context ${CLUSTER_NAME}-${NAMESPACE}-${SERVICE_ACCOUNT}

EOF
}

# Main function
main() {
    case "${1:-}" in
        -h|--help|help)
            usage
            exit 0
            ;;
    esac
    
    validate_args
    check_prerequisites
    get_cluster_info
    ensure_service_account
    get_service_account_token
    create_kubeconfig
    test_kubeconfig
    create_rbac
    show_instructions
}

# Run main function
main "$@"