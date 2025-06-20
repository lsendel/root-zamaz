#!/bin/bash

# Istio Service Mesh Setup Script for MVP Zero Trust Auth
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ISTIO_VERSION="${ISTIO_VERSION:-1.20.1}"
ISTIO_NAMESPACE="${ISTIO_NAMESPACE:-istio-system}"
MESH_NAMESPACE="${MESH_NAMESPACE:-zamaz}"
MESH_ID="${MESH_ID:-zamaz-mesh}"
CLUSTER_NAME="${CLUSTER_NAME:-zamaz-cluster}"
TRUST_DOMAIN="${TRUST_DOMAIN:-zamaz.cluster.local}"

log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        error "kubectl is required but not installed"
        exit 1
    fi
    
    # Check if we can connect to cluster
    if ! kubectl cluster-info &> /dev/null; then
        error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    # Check if istioctl is available
    if ! command -v istioctl &> /dev/null; then
        if [ -f "./istio-${ISTIO_VERSION}/bin/istioctl" ]; then
            export PATH="$PWD/istio-${ISTIO_VERSION}/bin:$PATH"
            log "Using local istioctl from istio-${ISTIO_VERSION}/bin/"
        else
            error "istioctl is required but not found"
            error "Please install istioctl or ensure istio-${ISTIO_VERSION}/bin/istioctl exists"
            exit 1
        fi
    fi
    
    success "Prerequisites check passed"
}

# Install Istio
install_istio() {
    log "Installing Istio ${ISTIO_VERSION}..."
    
    # Create istio-system namespace
    kubectl create namespace ${ISTIO_NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -
    
    # Install Istio with custom configuration
    if [ -f "istio/mesh-config.yaml" ]; then
        log "Installing Istio with custom mesh configuration..."
        istioctl install -f istio/mesh-config.yaml --skip-confirmation
    else
        log "Installing Istio with demo profile..."
        istioctl install --set values.defaultRevision=default --skip-confirmation
    fi
    
    # Verify installation
    kubectl wait --for=condition=Available deployment/istiod -n ${ISTIO_NAMESPACE} --timeout=300s
    
    success "Istio installation completed"
}

# Install Istio addons
install_addons() {
    log "Installing Istio observability addons..."
    
    # Use samples from istio installation
    if [ -d "istio-${ISTIO_VERSION}/samples/addons" ]; then
        ADDONS_DIR="istio-${ISTIO_VERSION}/samples/addons"
    else
        warn "Istio samples directory not found, skipping addons"
        return
    fi
    
    # Install Prometheus
    kubectl apply -f "${ADDONS_DIR}/prometheus.yaml"
    
    # Install Grafana
    kubectl apply -f "${ADDONS_DIR}/grafana.yaml"
    
    # Install Jaeger
    kubectl apply -f "${ADDONS_DIR}/jaeger.yaml"
    
    # Install Kiali
    kubectl apply -f "${ADDONS_DIR}/kiali.yaml"
    
    # Wait for addons to be ready
    log "Waiting for addons to be ready..."
    kubectl wait --for=condition=Available deployment/prometheus -n ${ISTIO_NAMESPACE} --timeout=300s || true
    kubectl wait --for=condition=Available deployment/grafana -n ${ISTIO_NAMESPACE} --timeout=300s || true
    kubectl wait --for=condition=Available deployment/jaeger -n ${ISTIO_NAMESPACE} --timeout=300s || true
    kubectl wait --for=condition=Available deployment/kiali -n ${ISTIO_NAMESPACE} --timeout=300s || true
    
    success "Istio addons installed"
}

# Setup namespaces
setup_namespaces() {
    log "Setting up namespaces for service mesh..."
    
    # Create zamaz namespace
    kubectl create namespace ${MESH_NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -
    
    # Enable automatic sidecar injection
    kubectl label namespace ${MESH_NAMESPACE} istio-injection=enabled --overwrite
    
    # Add mesh labels
    kubectl label namespace ${MESH_NAMESPACE} istio.io/mesh-id=${MESH_ID} --overwrite
    kubectl label namespace ${MESH_NAMESPACE} topology.istio.io/network=network1 --overwrite
    
    success "Namespaces configured for service mesh"
}

# Apply security policies
apply_security_policies() {
    log "Applying security policies..."
    
    if [ -d "istio/security" ]; then
        kubectl apply -f istio/security/
        
        # Wait for policies to be applied
        sleep 5
        
        success "Security policies applied"
    else
        warn "Security policies directory not found"
    fi
}

# Apply networking configuration
apply_networking() {
    log "Applying networking configuration..."
    
    if [ -d "istio/networking" ]; then
        kubectl apply -f istio/networking/
        success "Networking configuration applied"
    else
        warn "Networking configuration directory not found"
    fi
}

# Apply traffic management
apply_traffic_management() {
    log "Applying traffic management policies..."
    
    if [ -d "istio/traffic-management" ]; then
        kubectl apply -f istio/traffic-management/
        success "Traffic management policies applied"
    else
        warn "Traffic management directory not found"
    fi
}

# Apply observability configuration
apply_observability() {
    log "Applying observability configuration..."
    
    if [ -d "istio/observability" ]; then
        kubectl apply -f istio/observability/
        success "Observability configuration applied"
    else
        warn "Observability configuration directory not found"
    fi
}

# Verify installation
verify_installation() {
    log "Verifying Istio installation..."
    
    # Check Istio components
    if istioctl verify-install; then
        success "Istio installation verified"
    else
        error "Istio installation verification failed"
        return 1
    fi
    
    # Check proxy status
    log "Checking proxy status..."
    istioctl proxy-status
    
    # Check configuration
    log "Validating configuration..."
    istioctl analyze --all-namespaces
    
    success "Installation verification completed"
}

# Setup ingress
setup_ingress() {
    log "Setting up ingress configuration..."
    
    # Get ingress gateway external IP
    log "Waiting for ingress gateway external IP..."
    kubectl wait --for=condition=Available deployment/istio-ingressgateway -n ${ISTIO_NAMESPACE} --timeout=300s
    
    # Display ingress information
    INGRESS_HOST=$(kubectl get service istio-ingressgateway -n ${ISTIO_NAMESPACE} -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
    INGRESS_PORT=$(kubectl get service istio-ingressgateway -n ${ISTIO_NAMESPACE} -o jsonpath='{.spec.ports[?(@.name=="http2")].port}')
    SECURE_INGRESS_PORT=$(kubectl get service istio-ingressgateway -n ${ISTIO_NAMESPACE} -o jsonpath='{.spec.ports[?(@.name=="https")].port}')
    
    if [ -z "$INGRESS_HOST" ]; then
        INGRESS_HOST=$(kubectl get service istio-ingressgateway -n ${ISTIO_NAMESPACE} -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || echo "localhost")
    fi
    
    echo ""
    log "Ingress Gateway Information:"
    echo "  Host: ${INGRESS_HOST}"
    echo "  HTTP Port: ${INGRESS_PORT}"
    echo "  HTTPS Port: ${SECURE_INGRESS_PORT}"
    echo ""
    
    # Save ingress info to file
    cat > ingress-info.txt << EOF
# Istio Ingress Gateway Information
INGRESS_HOST=${INGRESS_HOST}
INGRESS_PORT=${INGRESS_PORT}
SECURE_INGRESS_PORT=${SECURE_INGRESS_PORT}

# URLs
HTTP_URL=http://${INGRESS_HOST}:${INGRESS_PORT}
HTTPS_URL=https://${INGRESS_HOST}:${SECURE_INGRESS_PORT}

# For local development, add to /etc/hosts:
# ${INGRESS_HOST} zamaz.local api.zamaz.local auth.zamaz.local
EOF
    
    success "Ingress configuration completed"
}

# Display dashboard information
show_dashboards() {
    log "Service mesh dashboards:"
    echo ""
    echo "  🔧 Kiali (Service Mesh Console):"
    echo "     kubectl port-forward -n ${ISTIO_NAMESPACE} svc/kiali 20001:20001"
    echo "     http://localhost:20001"
    echo ""
    echo "  📊 Grafana (Metrics Dashboard):"
    echo "     kubectl port-forward -n ${ISTIO_NAMESPACE} svc/grafana 3000:3000"
    echo "     http://localhost:3000"
    echo ""
    echo "  🔍 Jaeger (Distributed Tracing):"
    echo "     kubectl port-forward -n ${ISTIO_NAMESPACE} svc/jaeger 16686:16686"
    echo "     http://localhost:16686"
    echo ""
    echo "  📈 Prometheus (Metrics Collection):"
    echo "     kubectl port-forward -n ${ISTIO_NAMESPACE} svc/prometheus 9090:9090"
    echo "     http://localhost:9090"
    echo ""
}

# Generate certificates (for development)
generate_dev_certificates() {
    log "Generating development certificates..."
    
    mkdir -p certs
    
    # Generate root CA
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=zamaz-ca" \
        -keyout certs/ca-key.pem \
        -out certs/ca-cert.pem
    
    # Generate server certificate
    openssl req -new -newkey rsa:4096 -nodes \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=*.zamaz.local" \
        -keyout certs/server-key.pem \
        -out certs/server.csr
    
    # Sign server certificate
    openssl x509 -req -in certs/server.csr -CA certs/ca-cert.pem -CAkey certs/ca-key.pem \
        -CAcreateserial -out certs/server-cert.pem -days 365 \
        -extensions v3_req -extfile <(cat <<EOF
[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = *.zamaz.local
DNS.2 = zamaz.local
DNS.3 = api.zamaz.local
DNS.4 = auth.zamaz.local
DNS.5 = localhost
IP.1 = 127.0.0.1
EOF
)
    
    # Create TLS secret
    kubectl create secret tls zamaz-tls-secret \
        --cert=certs/server-cert.pem \
        --key=certs/server-key.pem \
        -n ${MESH_NAMESPACE} \
        --dry-run=client -o yaml | kubectl apply -f -
    
    rm certs/server.csr
    
    success "Development certificates generated and installed"
}

# Main execution
main() {
    log "Starting Istio service mesh setup for MVP Zero Trust Auth..."
    echo "Configuration:"
    echo "  Istio Version: ${ISTIO_VERSION}"
    echo "  Istio Namespace: ${ISTIO_NAMESPACE}"
    echo "  Mesh Namespace: ${MESH_NAMESPACE}"
    echo "  Mesh ID: ${MESH_ID}"
    echo "  Cluster Name: ${CLUSTER_NAME}"
    echo "  Trust Domain: ${TRUST_DOMAIN}"
    echo ""
    
    # Execute setup steps
    check_prerequisites
    install_istio
    install_addons
    setup_namespaces
    generate_dev_certificates
    apply_security_policies
    apply_networking
    apply_traffic_management
    apply_observability
    setup_ingress
    verify_installation
    
    echo ""
    success "Istio service mesh setup completed successfully!"
    echo ""
    log "Next steps:"
    echo "  1. Deploy your applications to the ${MESH_NAMESPACE} namespace"
    echo "  2. Applications will automatically get sidecar injection"
    echo "  3. Access the service mesh dashboards for monitoring"
    echo ""
    
    show_dashboards
    
    if [ -f "ingress-info.txt" ]; then
        echo ""
        log "Ingress information saved to: ingress-info.txt"
    fi
}

# Handle command line arguments
case "${1:-install}" in
    "install")
        main
        ;;
    "uninstall")
        log "Uninstalling Istio..."
        istioctl uninstall --purge -y
        kubectl delete namespace ${ISTIO_NAMESPACE} --ignore-not-found
        success "Istio uninstalled"
        ;;
    "verify")
        verify_installation
        ;;
    "dashboards")
        show_dashboards
        ;;
    "certs")
        generate_dev_certificates
        ;;
    *)
        echo "Usage: $0 [install|uninstall|verify|dashboards|certs]"
        echo ""
        echo "Commands:"
        echo "  install    - Install and configure Istio service mesh (default)"
        echo "  uninstall  - Remove Istio from the cluster"
        echo "  verify     - Verify Istio installation"
        echo "  dashboards - Show dashboard access information"
        echo "  certs      - Generate development certificates"
        exit 1
        ;;
esac