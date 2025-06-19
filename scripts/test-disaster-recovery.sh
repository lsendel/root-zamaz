#!/bin/bash

# Disaster Recovery Test Script

# Configuration
BACKUP_NAMESPACE="velero"
APP_NAMESPACE="zamaz-${ENVIRONMENT}"
RESTORE_NAMESPACE="zamaz-dr-test"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Logging function
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Check if backup exists
check_backup() {
    log "Checking latest backup..."
    LATEST_BACKUP=$(kubectl -n $BACKUP_NAMESPACE get backup -l app=zamaz -o jsonpath='{.items[0].metadata.name}')
    if [ -z "$LATEST_BACKUP" ]; then
        log "${RED}No backup found${NC}"
        exit 1
    fi
    log "${GREEN}Found backup: $LATEST_BACKUP${NC}"
}

# Create test namespace
create_test_namespace() {
    log "Creating test namespace..."
    kubectl create ns $RESTORE_NAMESPACE
    kubectl label namespace $RESTORE_NAMESPACE environment=dr-test
}

# Restore backup
restore_backup() {
    log "Starting backup restore..."
    velero restore create --from-backup $LATEST_BACKUP \
        --namespace-mappings $APP_NAMESPACE:$RESTORE_NAMESPACE \
        --include-namespaces $APP_NAMESPACE
}

# Validate restoration
validate_restore() {
    log "Validating restoration..."

    # Wait for pods to be ready
    kubectl wait --for=condition=ready pod -l app=zamaz -n $RESTORE_NAMESPACE --timeout=300s

    # Check critical components
    check_components=("deployment" "service" "configmap" "secret")
    for component in "${check_components[@]}"; do
        if kubectl get $component -n $RESTORE_NAMESPACE -l app=zamaz >/dev/null 2>&1; then
            log "${GREEN}✓ $component restored successfully${NC}"
        else
            log "${RED}✗ $component restoration failed${NC}"
            FAILED=1
        fi
    done

    # Validate application health
    HEALTH_CHECK=$(kubectl exec -n $RESTORE_NAMESPACE -l app=zamaz -- curl -s localhost:8080/health)
    if [[ $HEALTH_CHECK == *"ok"* ]]; then
        log "${GREEN}✓ Application health check passed${NC}"
    else
        log "${RED}✗ Application health check failed${NC}"
        FAILED=1
    fi
}

# Cleanup
cleanup() {
    log "Cleaning up test namespace..."
    kubectl delete namespace $RESTORE_NAMESPACE
}

# Main execution
main() {
    log "Starting disaster recovery test"
    check_backup
    create_test_namespace
    restore_backup
    validate_restore

    if [ "$FAILED" == "1" ]; then
        log "${RED}Disaster recovery test failed${NC}"
        exit 1
    else
        log "${GREEN}Disaster recovery test completed successfully${NC}"
        cleanup
    fi
}

main "$@"
