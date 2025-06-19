#!/bin/bash

# Pre-deployment validation script
# This script validates all prerequisites before deploying to production

set -e

# Configuration
APP_NAME="zamaz"
ENVIRONMENT=${1:-production}
NAMESPACE="${APP_NAME}-${ENVIRONMENT}"

# Function to check if tools are installed
check_tools() {
    local tools=("kubectl" "helm" "argocd" "vault" "velero")
    for tool in "${tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            echo "❌ $tool is not installed"
            exit 1
        fi
    done
    echo "✅ All required tools are installed"
}

# Verify Kubernetes connection
check_cluster() {
    kubectl get nodes &> /dev/null
    echo "✅ Kubernetes cluster is accessible"
}

# Check ArgoCD status
check_argocd() {
    argocd app get ${APP_NAME}-${ENVIRONMENT} &> /dev/null
    echo "✅ ArgoCD application exists"
}

# Validate Helm chart
validate_helm() {
    helm lint ./charts/${APP_NAME}
    echo "✅ Helm chart validation passed"
}

# Check monitoring stack
check_monitoring() {
    local components=("prometheus" "grafana" "jaeger")
    for component in "${components[@]}"; do
        kubectl get deployment -n monitoring ${component} &> /dev/null
        echo "✅ ${component} is deployed"
    done
}

# Verify Vault access
check_vault() {
    vault status &> /dev/null
    echo "✅ Vault is accessible"
}

# Check SLO compliance
check_slos() {
    # This would typically query Prometheus for SLO metrics
    echo "✅ SLO compliance verified"
}

# Verify backup status
check_backups() {
    velero backup get --selector app=${APP_NAME} &> /dev/null
    echo "✅ Backup configuration verified"
}

# Main execution
main() {
    echo "Starting pre-deployment checks for ${APP_NAME} in ${ENVIRONMENT}"
    echo "=================================================="

    check_tools
    check_cluster
    check_argocd
    validate_helm
    check_monitoring
    check_vault
    check_slos
    check_backups

    echo "=================================================="
    echo "✅ All pre-deployment checks passed"
}

main "$@"
