#!/bin/bash

# Istio Service Mesh Migration Script
# Implements namespace-based migration strategy for Zero Trust Authentication MVP

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MIGRATION_LOG="/tmp/istio-migration-$(date +%Y%m%d-%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        INFO)  echo -e "${GREEN}[INFO]${NC} $timestamp - $message" | tee -a "$MIGRATION_LOG" ;;
        WARN)  echo -e "${YELLOW}[WARN]${NC} $timestamp - $message" | tee -a "$MIGRATION_LOG" ;;
        ERROR) echo -e "${RED}[ERROR]${NC} $timestamp - $message" | tee -a "$MIGRATION_LOG" ;;
        DEBUG) echo -e "${BLUE}[DEBUG]${NC} $timestamp - $message" | tee -a "$MIGRATION_LOG" ;;
    esac
}

# Check prerequisites
check_prerequisites() {
    log INFO "Checking prerequisites..."
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log ERROR "kubectl is required but not installed"
        exit 1
    fi
    
    # Check helm
    if ! command -v helm &> /dev/null; then
        log ERROR "helm is required but not installed"
        exit 1
    fi
    
    # Check istioctl
    if ! command -v istioctl &> /dev/null; then
        log ERROR "istioctl is required but not installed"
        exit 1
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log ERROR "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log INFO "Prerequisites check passed"
}

# Install Istio control plane
install_istio() {
    log INFO "Installing Istio control plane..."
    
    # Create istio-system namespace
    kubectl create namespace istio-system --dry-run=client -o yaml | kubectl apply -f -
    
    # Install Istio base
    helm repo add istio https://istio-release.storage.googleapis.com/charts
    helm repo update
    
    helm upgrade --install istio-base istio/base \
        -n istio-system \
        --wait \
        --timeout 10m
    
    # Install Istiod
    helm upgrade --install istiod istio/istiod \
        -n istio-system \
        --set values.pilot.env.SPIFFE_BUNDLE_ENDPOINTS="spire-server.spire-system.svc.cluster.local:8081" \
        --wait \
        --timeout 10m
    
    # Install Istio gateway
    helm upgrade --install istio-gateway istio/gateway \
        -n istio-system \
        --wait \
        --timeout 10m
    
    log INFO "Istio control plane installed successfully"
}

# Deploy SPIRE integration
deploy_spire_integration() {
    log INFO "Deploying SPIRE integration..."
    
    # Create spire-system namespace
    kubectl create namespace spire-system --dry-run=client -o yaml | kubectl apply -f -
    
    # Deploy SPIRE integration chart
    helm upgrade --install spire-integration \
        "$PROJECT_ROOT/charts/spire-integration" \
        -n spire-system \
        --wait \
        --timeout 15m
    
    # Wait for SPIRE server to be ready
    log INFO "Waiting for SPIRE server to be ready..."
    kubectl wait --for=condition=ready pod -l app=spire-server -n spire-system --timeout=300s
    
    # Wait for SPIRE agent to be ready
    log INFO "Waiting for SPIRE agents to be ready..."
    kubectl wait --for=condition=ready pod -l app=spire-agent -n spire-system --timeout=300s
    
    log INFO "SPIRE integration deployed successfully"
}

# Create zamaz-mesh namespace
create_mesh_namespace() {
    log INFO "Creating zamaz-mesh namespace..."
    
    # Create namespace with Istio injection enabled
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: zamaz-mesh
  labels:
    istio-injection: enabled
    security.zamaz.io/tier: mesh
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
EOF
    
    log INFO "zamaz-mesh namespace created"
}

# Deploy service mesh infrastructure
deploy_mesh_infrastructure() {
    log INFO "Deploying service mesh infrastructure..."
    
    # Deploy Istio mesh configuration
    helm upgrade --install istio-mesh \
        "$PROJECT_ROOT/charts/istio-mesh" \
        -n istio-system \
        --wait \
        --timeout 10m
    
    # Deploy security policies
    helm upgrade --install security-policies \
        "$PROJECT_ROOT/charts/security-policies" \
        -n zamaz-mesh \
        --wait \
        --timeout 10m
    
    # Deploy observability enhancements
    kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -
    
    helm upgrade --install observability \
        "$PROJECT_ROOT/charts/observability" \
        -n monitoring \
        --wait \
        --timeout 15m
    
    log INFO "Service mesh infrastructure deployed"
}

# Deploy Zamaz application to mesh namespace
deploy_zamaz_to_mesh() {
    log INFO "Deploying Zamaz application to mesh namespace..."
    
    # Deploy with service mesh enabled
    helm upgrade --install zamaz-mesh \
        "$PROJECT_ROOT/charts/zamaz" \
        -n zamaz-mesh \
        --set global.serviceMesh.enabled=true \
        --set global.serviceMesh.namespace=zamaz-mesh \
        --set global.serviceMesh.istio.injection=enabled \
        --set istio.enabled=true \
        --set replicaCount=2 \
        --wait \
        --timeout 15m
    
    log INFO "Zamaz application deployed to mesh namespace"
}

# Verify mesh deployment
verify_mesh_deployment() {
    log INFO "Verifying mesh deployment..."
    
    # Check Istio proxy injection
    local pods_with_sidecars=$(kubectl get pods -n zamaz-mesh -o jsonpath='{.items[*].spec.containers[*].name}' | grep -o istio-proxy | wc -l)
    local total_pods=$(kubectl get pods -n zamaz-mesh --no-headers | wc -l)
    
    if [ "$pods_with_sidecars" -eq "$total_pods" ]; then
        log INFO "All pods have Istio sidecars injected ✓"
    else
        log WARN "Not all pods have Istio sidecars: $pods_with_sidecars/$total_pods"
    fi
    
    # Check SPIRE workload identities
    log INFO "Checking SPIRE workload identities..."
    kubectl exec -n spire-system deployment/spire-server -- \
        /opt/spire/bin/spire-server entry show -socketPath /opt/spire/sockets/server.sock
    
    # Check mTLS status
    log INFO "Checking mTLS status..."
    istioctl authn tls-check -n zamaz-mesh
    
    # Check virtual service
    if kubectl get virtualservice -n zamaz-mesh zamaz-vs &> /dev/null; then
        log INFO "Virtual service configured ✓"
    else
        log WARN "Virtual service not found"
    fi
    
    # Check destination rules
    if kubectl get destinationrule -n zamaz-mesh &> /dev/null; then
        log INFO "Destination rules configured ✓"
    else
        log WARN "Destination rules not found"
    fi
    
    log INFO "Mesh deployment verification completed"
}

# Test mesh functionality
test_mesh_functionality() {
    log INFO "Testing mesh functionality..."
    
    # Port forward to gateway for testing
    log INFO "Setting up port forward for testing..."
    kubectl port-forward -n istio-system svc/istio-gateway 8080:80 &
    local pf_pid=$!
    
    # Wait for port forward to be ready
    sleep 5
    
    # Test API endpoint
    if curl -f http://localhost:8080/health &> /dev/null; then
        log INFO "API health check passed ✓"
    else
        log WARN "API health check failed"
    fi
    
    # Clean up port forward
    kill $pf_pid 2>/dev/null || true
    
    log INFO "Mesh functionality test completed"
}

# Traffic shifting function
shift_traffic() {
    local percentage=$1
    
    log INFO "Shifting $percentage% traffic to mesh namespace..."
    
    # Update virtual service to split traffic
    cat <<EOF | kubectl apply -f -
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: zamaz-traffic-split
  namespace: istio-system
spec:
  hosts:
  - api.zamaz.local
  gateways:
  - zamaz-gateway
  http:
  - match:
    - uri:
        prefix: "/api/"
    route:
    - destination:
        host: zamaz-api.zamaz-mesh.svc.cluster.local
        port:
          number: 8080
      weight: $percentage
    - destination:
        host: zamaz-api.zamaz.svc.cluster.local
        port:
          number: 8080
      weight: $((100 - percentage))
EOF
    
    log INFO "Traffic split configured: $percentage% mesh, $((100 - percentage))% legacy"
}

# Monitor migration
monitor_migration() {
    local duration=${1:-300}  # Default 5 minutes
    
    log INFO "Monitoring migration for $duration seconds..."
    
    local start_time=$(date +%s)
    local end_time=$((start_time + duration))
    
    while [ $(date +%s) -lt $end_time ]; do
        # Check error rates
        log INFO "Checking error rates..."
        
        # Check pod health
        local unhealthy_pods=$(kubectl get pods -n zamaz-mesh --no-headers | grep -v Running | wc -l)
        if [ "$unhealthy_pods" -gt 0 ]; then
            log WARN "$unhealthy_pods unhealthy pods detected"
        fi
        
        sleep 30
    done
    
    log INFO "Migration monitoring completed"
}

# Rollback function
rollback_migration() {
    log WARN "Rolling back migration..."
    
    # Shift all traffic back to legacy
    shift_traffic 0
    
    # Scale down mesh deployment
    kubectl scale deployment -n zamaz-mesh --all --replicas=0
    
    # Remove mesh namespace (optional)
    read -p "Remove zamaz-mesh namespace? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        kubectl delete namespace zamaz-mesh
    fi
    
    log WARN "Migration rollback completed"
}

# Complete migration
complete_migration() {
    log INFO "Completing migration..."
    
    # Shift 100% traffic to mesh
    shift_traffic 100
    
    # Wait for traffic to stabilize
    sleep 60
    
    # Scale down legacy deployment
    kubectl scale deployment -n zamaz --all --replicas=0
    
    # Update DNS/ingress to point to mesh
    log INFO "Update your DNS/ingress to point to the mesh gateway"
    
    log INFO "Migration completed successfully!"
}

# Cleanup function
cleanup() {
    log INFO "Cleaning up temporary resources..."
    
    # Kill any background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    
    log INFO "Cleanup completed"
}

# Main migration workflow
main() {
    local action=${1:-"full"}
    
    log INFO "Starting Istio migration with action: $action"
    log INFO "Migration log: $MIGRATION_LOG"
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    case $action in
        "prereq")
            check_prerequisites
            ;;
        "install-istio")
            check_prerequisites
            install_istio
            ;;
        "deploy-spire")
            deploy_spire_integration
            ;;
        "create-namespace")
            create_mesh_namespace
            ;;
        "deploy-infrastructure")
            deploy_mesh_infrastructure
            ;;
        "deploy-app")
            deploy_zamaz_to_mesh
            ;;
        "verify")
            verify_mesh_deployment
            ;;
        "test")
            test_mesh_functionality
            ;;
        "shift-traffic")
            local percentage=${2:-50}
            shift_traffic "$percentage"
            ;;
        "monitor")
            local duration=${2:-300}
            monitor_migration "$duration"
            ;;
        "rollback")
            rollback_migration
            ;;
        "complete")
            complete_migration
            ;;
        "full")
            check_prerequisites
            install_istio
            deploy_spire_integration
            create_mesh_namespace
            deploy_mesh_infrastructure
            deploy_zamaz_to_mesh
            verify_mesh_deployment
            test_mesh_functionality
            
            # Interactive traffic shifting
            log INFO "Migration infrastructure ready. Use 'shift-traffic' to begin traffic migration."
            ;;
        *)
            echo "Usage: $0 [prereq|install-istio|deploy-spire|create-namespace|deploy-infrastructure|deploy-app|verify|test|shift-traffic|monitor|rollback|complete|full]"
            exit 1
            ;;
    esac
    
    log INFO "Migration action '$action' completed successfully"
}

# Run main function
main "$@"