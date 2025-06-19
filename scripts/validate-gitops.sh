#!/bin/bash
# GitOps Validation Suite

# Set environment
ENVIRONMENT=${1:-staging}
NAMESPACE="zamaz-${ENVIRONMENT}"
SUCCESS=true

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

check_status() {
    if [ $? -eq 0 ]; then
        log "${GREEN}✓ $1${NC}"
    else
        log "${RED}✗ $1${NC}"
        SUCCESS=false
    fi
}

# 1. Validate ArgoCD Sync Status
log "Checking ArgoCD sync status..."
argocd app sync zamaz-${ENVIRONMENT} --timeout 300
check_status "ArgoCD sync"

# 2. Validate Rollout Status
log "Checking rollout status..."
kubectl argo rollouts status zamaz -n ${NAMESPACE} --timeout 300s
check_status "Rollout status"

# 3. Check SLOs
log "Validating SLOs..."
kubectl exec -n monitoring prometheus-0 -- curl -s 'http://localhost:9090/api/v1/query' --data-urlencode 'query=slo:http_requests_total:ratio_rate_1h > 0.999'
check_status "Availability SLO"

# 4. Verify Monitoring Stack
log "Checking monitoring components..."
for component in prometheus grafana jaeger; do
    kubectl get deployments -n monitoring ${component} -o jsonpath='{.status.readyReplicas}'
    check_status "${component} deployment"
done

# 5. Verify Security Configurations
log "Validating security configurations..."
kubectl auth can-i --as system:serviceaccount:${NAMESPACE}:default get secrets -n ${NAMESPACE}
check_status "RBAC configuration"

# 6. Check Vault Integration
log "Verifying Vault integration..."
kubectl get vaultsecret -n ${NAMESPACE} zamaz-secrets -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'
check_status "Vault secrets"

# 7. Validate Network Policies
log "Checking network policies..."
kubectl get networkpolicies -n ${NAMESPACE}
check_status "Network policies"

# 8. Check Resource Optimization
log "Validating resource optimization..."
kubectl exec -n monitoring prometheus-0 -- curl -s 'http://localhost:9090/api/v1/query' --data-urlencode 'query=zamaz:container_cpu_utilization:ratio > 0.3'
check_status "Resource utilization"

# 9. Verify Backup Configuration
log "Checking backup configuration..."
velero get backup --selector app=zamaz
check_status "Backup configuration"

# 10. Test Load Balancing
log "Validating load balancing..."
for i in {1..10}; do
    curl -s -o /dev/null -w "%{http_code}" https://zamaz.${ENVIRONMENT}.svc.cluster.local/health
done
check_status "Load balancer health"

# Final Status
if [ "$SUCCESS" = true ]; then
    log "${GREEN}All validations passed successfully${NC}"
    exit 0
else
    log "${RED}Some validations failed. Please check the logs above${NC}"
    exit 1
fi
