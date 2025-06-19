#!/bin/bash

# Migration Verification Script
# Comprehensive verification of Istio service mesh migration

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VERIFICATION_LOG="/tmp/verification-$(date +%Y%m%d-%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        INFO)  echo -e "${GREEN}[INFO]${NC} $timestamp - $message" | tee -a "$VERIFICATION_LOG" ;;
        WARN)  echo -e "${YELLOW}[WARN]${NC} $timestamp - $message" | tee -a "$VERIFICATION_LOG" ;;
        ERROR) echo -e "${RED}[ERROR]${NC} $timestamp - $message" | tee -a "$VERIFICATION_LOG" ;;
        DEBUG) echo -e "${BLUE}[DEBUG]${NC} $timestamp - $message" | tee -a "$VERIFICATION_LOG" ;;
        PASS)  echo -e "${GREEN}[PASS]${NC} $timestamp - $message" | tee -a "$VERIFICATION_LOG" ;;
        FAIL)  echo -e "${RED}[FAIL]${NC} $timestamp - $message" | tee -a "$VERIFICATION_LOG" ;;
    esac
}

# Test execution function
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log INFO "Running test: $test_name"
    
    if eval "$test_command" &>/dev/null; then
        log PASS "$test_name"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        log FAIL "$test_name"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# Verify Istio installation
verify_istio_installation() {
    log INFO "=== Verifying Istio Installation ==="
    
    run_test "Istio system namespace exists" \
        "kubectl get namespace istio-system"
    
    run_test "Istiod deployment is ready" \
        "kubectl get deployment istiod -n istio-system -o jsonpath='{.status.readyReplicas}' | grep -q '[1-9]'"
    
    run_test "Istio gateway is ready" \
        "kubectl get deployment -n istio-system -l istio=gateway -o jsonpath='{.items[*].status.readyReplicas}' | grep -q '[1-9]'"
    
    run_test "Istio proxy version check" \
        "istioctl version --remote"
}

# Verify SPIRE installation
verify_spire_installation() {
    log INFO "=== Verifying SPIRE Installation ==="
    
    run_test "SPIRE system namespace exists" \
        "kubectl get namespace spire-system"
    
    run_test "SPIRE server is ready" \
        "kubectl get statefulset spire-server -n spire-system -o jsonpath='{.status.readyReplicas}' | grep -q '1'"
    
    run_test "SPIRE agent daemonset is ready" \
        "kubectl get daemonset spire-agent -n spire-system -o jsonpath='{.status.numberReady}' | grep -q '[1-9]'"
    
    run_test "SPIRE server health check" \
        "kubectl exec -n spire-system statefulset/spire-server -- /opt/spire/bin/spire-server healthcheck"
    
    # Check registration entries
    local entries_count=$(kubectl exec -n spire-system statefulset/spire-server -- \
        /opt/spire/bin/spire-server entry show -socketPath /opt/spire/sockets/server.sock 2>/dev/null | grep "Entry ID" | wc -l)
    
    run_test "SPIRE registration entries exist" \
        "[ $entries_count -gt 0 ]"
}

# Verify mesh namespace
verify_mesh_namespace() {
    log INFO "=== Verifying Mesh Namespace ==="
    
    run_test "Mesh namespace exists" \
        "kubectl get namespace zamaz-mesh"
    
    run_test "Istio injection enabled" \
        "kubectl get namespace zamaz-mesh -o jsonpath='{.metadata.labels.istio-injection}' | grep -q 'enabled'"
    
    run_test "Pod security standards configured" \
        "kubectl get namespace zamaz-mesh -o jsonpath='{.metadata.labels}' | grep -q 'pod-security.kubernetes.io/enforce'"
}

# Verify application deployment
verify_application_deployment() {
    log INFO "=== Verifying Application Deployment ==="
    
    run_test "Zamaz API deployment exists" \
        "kubectl get deployment -n zamaz-mesh -l app=zamaz,component=api"
    
    run_test "Zamaz frontend deployment exists" \
        "kubectl get deployment -n zamaz-mesh -l app=zamaz,component=frontend"
    
    run_test "All pods are ready" \
        "kubectl wait --for=condition=ready pod -l app=zamaz -n zamaz-mesh --timeout=60s"
    
    # Check sidecar injection
    local api_containers=$(kubectl get pods -n zamaz-mesh -l app=zamaz,component=api -o jsonpath='{.items[0].spec.containers[*].name}')
    run_test "API pod has Istio sidecar" \
        "echo '$api_containers' | grep -q 'istio-proxy'"
    
    local frontend_containers=$(kubectl get pods -n zamaz-mesh -l app=zamaz,component=frontend -o jsonpath='{.items[0].spec.containers[*].name}')
    run_test "Frontend pod has Istio sidecar" \
        "echo '$frontend_containers' | grep -q 'istio-proxy'"
}

# Verify service mesh configuration
verify_service_mesh_config() {
    log INFO "=== Verifying Service Mesh Configuration ==="
    
    run_test "Gateway configuration exists" \
        "kubectl get gateway -n istio-system zamaz-gateway"
    
    run_test "VirtualService configuration exists" \
        "kubectl get virtualservice -n zamaz-mesh"
    
    run_test "DestinationRule configuration exists" \
        "kubectl get destinationrule -n zamaz-mesh"
    
    run_test "Istio configuration is valid" \
        "istioctl analyze -n zamaz-mesh"
}

# Verify security policies
verify_security_policies() {
    log INFO "=== Verifying Security Policies ==="
    
    run_test "PeerAuthentication policy exists" \
        "kubectl get peerauthentication -n zamaz-mesh"
    
    run_test "AuthorizationPolicy exists" \
        "kubectl get authorizationpolicy -n zamaz-mesh"
    
    run_test "NetworkPolicy exists" \
        "kubectl get networkpolicy -n zamaz-mesh"
    
    # Check mTLS status
    run_test "mTLS is properly configured" \
        "istioctl authn tls-check -n zamaz-mesh"
}

# Verify workload identities
verify_workload_identities() {
    log INFO "=== Verifying Workload Identities ==="
    
    # Get a pod name for testing
    local api_pod=$(kubectl get pods -n zamaz-mesh -l app=zamaz,component=api -o jsonpath='{.items[0].metadata.name}')
    
    if [ -n "$api_pod" ]; then
        run_test "SPIRE socket is mounted" \
            "kubectl exec -n zamaz-mesh $api_pod -c zamaz -- ls /run/spire/sockets/agent.sock"
        
        # Check certificate in Istio proxy
        run_test "Istio proxy has certificates" \
            "kubectl exec -n zamaz-mesh $api_pod -c istio-proxy -- ls /etc/ssl/certs/"
    else
        log WARN "No API pod found for identity verification"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Verify observability
verify_observability() {
    log INFO "=== Verifying Observability ==="
    
    # Check if monitoring namespace exists
    if kubectl get namespace monitoring &>/dev/null; then
        run_test "Prometheus is deployed" \
            "kubectl get deployment -n monitoring -l app=prometheus"
        
        run_test "Grafana is deployed" \
            "kubectl get deployment -n monitoring -l app=grafana"
        
        run_test "ServiceMonitor exists" \
            "kubectl get servicemonitor -n monitoring"
    else
        log WARN "Monitoring namespace not found, skipping observability checks"
    fi
    
    # Check telemetry configuration
    run_test "Telemetry configuration exists" \
        "kubectl get telemetry -n zamaz-mesh"
}

# Test connectivity
test_connectivity() {
    log INFO "=== Testing Connectivity ==="
    
    # Get service endpoints
    local api_service=$(kubectl get svc -n zamaz-mesh -l app=zamaz,component=api -o jsonpath='{.items[0].metadata.name}')
    local frontend_service=$(kubectl get svc -n zamaz-mesh -l app=zamaz,component=frontend -o jsonpath='{.items[0].metadata.name}')
    
    if [ -n "$api_service" ]; then
        run_test "API service is accessible" \
            "kubectl run test-pod --rm -i --restart=Never --image=curlimages/curl:latest -- curl -f http://$api_service.zamaz-mesh.svc.cluster.local:8080/health"
    fi
    
    if [ -n "$frontend_service" ]; then
        run_test "Frontend service is accessible" \
            "kubectl run test-pod --rm -i --restart=Never --image=curlimages/curl:latest -- curl -f http://$frontend_service.zamaz-mesh.svc.cluster.local:3000/health"
    fi
}

# Test traffic routing
test_traffic_routing() {
    log INFO "=== Testing Traffic Routing ==="
    
    # Check if gateway service exists
    local gateway_service=$(kubectl get svc -n istio-system -l istio=gateway -o jsonpath='{.items[0].metadata.name}')
    
    if [ -n "$gateway_service" ]; then
        # Port forward for testing
        log INFO "Setting up port forward for gateway testing..."
        kubectl port-forward -n istio-system svc/$gateway_service 8080:80 &
        local pf_pid=$!
        
        # Wait for port forward
        sleep 5
        
        # Test routing (this would need proper DNS/host headers in real scenario)
        run_test "Gateway is responding" \
            "curl -f http://localhost:8080 -H 'Host: api.zamaz.local' || curl -f http://localhost:8080"
        
        # Clean up
        kill $pf_pid 2>/dev/null || true
    else
        log WARN "Gateway service not found, skipping traffic routing test"
    fi
}

# Performance verification
verify_performance() {
    log INFO "=== Verifying Performance ==="
    
    # Check resource usage
    log INFO "Checking resource usage..."
    kubectl top pods -n zamaz-mesh --no-headers | while read line; do
        local pod_name=$(echo $line | awk '{print $1}')
        local cpu_usage=$(echo $line | awk '{print $2}')
        local memory_usage=$(echo $line | awk '{print $3}')
        
        log INFO "Pod $pod_name: CPU=$cpu_usage, Memory=$memory_usage"
    done
    
    # Check proxy resource usage
    run_test "Istio proxy resource usage is reasonable" \
        "kubectl top pods -n zamaz-mesh --containers | grep istio-proxy | awk '{if (\$3 ~ /[0-9]+m/ && \$3+0 < 200) print \"OK\"; else print \"HIGH\"}' | grep -q OK"
}

# Security verification
verify_security() {
    log INFO "=== Verifying Security ==="
    
    # Check that pods are running as non-root
    run_test "Pods run as non-root" \
        "kubectl get pods -n zamaz-mesh -o jsonpath='{.items[*].spec.securityContext.runAsNonRoot}' | grep -v false"
    
    # Check that pods have read-only filesystem
    run_test "Pods have read-only root filesystem" \
        "kubectl get pods -n zamaz-mesh -o jsonpath='{.items[*].spec.containers[?(@.name!=\"istio-proxy\")].securityContext.readOnlyRootFilesystem}' | grep -v false"
    
    # Check network policies are enforced
    local netpol_count=$(kubectl get networkpolicy -n zamaz-mesh --no-headers | wc -l)
    run_test "Network policies are configured" \
        "[ $netpol_count -gt 0 ]"
}

# Generate verification report
generate_report() {
    log INFO "=== Verification Report ==="
    
    echo "
===============================================
    ISTIO MIGRATION VERIFICATION REPORT
===============================================

Date: $(date)
Total Tests: $TOTAL_TESTS
Passed: $PASSED_TESTS
Failed: $FAILED_TESTS
Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%

" | tee -a "$VERIFICATION_LOG"

    if [ $FAILED_TESTS -eq 0 ]; then
        log PASS "All verification tests passed! ✅"
        echo "Migration verification: SUCCESS" >> "$VERIFICATION_LOG"
        return 0
    else
        log FAIL "$FAILED_TESTS tests failed. Please review the issues above."
        echo "Migration verification: FAILED" >> "$VERIFICATION_LOG"
        return 1
    fi
}

# Main verification function
main() {
    local scope=${1:-"all"}
    
    log INFO "Starting Istio migration verification (scope: $scope)"
    log INFO "Verification log: $VERIFICATION_LOG"
    
    case $scope in
        "istio")
            verify_istio_installation
            ;;
        "spire")
            verify_spire_installation
            ;;
        "app")
            verify_application_deployment
            ;;
        "security")
            verify_security_policies
            verify_workload_identities
            verify_security
            ;;
        "connectivity")
            test_connectivity
            test_traffic_routing
            ;;
        "performance")
            verify_performance
            ;;
        "observability")
            verify_observability
            ;;
        "all")
            verify_istio_installation
            verify_spire_installation
            verify_mesh_namespace
            verify_application_deployment
            verify_service_mesh_config
            verify_security_policies
            verify_workload_identities
            verify_observability
            test_connectivity
            test_traffic_routing
            verify_performance
            verify_security
            ;;
        *)
            echo "Usage: $0 [istio|spire|app|security|connectivity|performance|observability|all]"
            exit 1
            ;;
    esac
    
    generate_report
}

# Run verification
main "$@"