#!/bin/bash

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default environment if not set
ENVIRONMENT=${1:-staging}
DEPLOYMENT_TYPE=${2:-kubernetes}

echo "Deploying project to $ENVIRONMENT environment using $DEPLOYMENT_TYPE..."

case "$DEPLOYMENT_TYPE" in
    kubernetes|k8s)
        echo "Deploying to Kubernetes..."
        "${SCRIPT_DIR}/deploy-k8s.sh" "$ENVIRONMENT"
        ;;
    
    docker-compose)
        echo "Deploying with Docker Compose..."
        if [ "$ENVIRONMENT" == "production" ]; then
            echo "ERROR: Docker Compose deployment not recommended for production"
            exit 1
        fi
        
        # Build and start services
        docker-compose -f docker-compose.yml -f docker-compose.observability.yml up -d --build
        
        # Wait for services to be healthy
        echo "Waiting for services to be healthy..."
        sleep 10
        docker-compose ps
        ;;
    
    terraform)
        if [ -d "deployments/terraform/$ENVIRONMENT" ]; then
            echo "Deploying with Terraform..."
            (cd "deployments/terraform/$ENVIRONMENT" && terraform apply -auto-approve)
        else
            echo "ERROR: Terraform configuration not found for $ENVIRONMENT"
            exit 1
        fi
        ;;
    
    helm)
        if [ -d "deployments/helm" ]; then
            echo "Deploying with Helm..."
            helm upgrade --install zamaz-$ENVIRONMENT ./deployments/helm \
                --namespace zamaz-$ENVIRONMENT \
                --create-namespace \
                --values ./deployments/helm/values-$ENVIRONMENT.yaml
        else
            echo "ERROR: Helm chart not found"
            exit 1
        fi
        ;;
    
    *)
        echo "ERROR: Unknown deployment type: $DEPLOYMENT_TYPE"
        echo "Supported types: kubernetes (k8s), docker-compose, terraform, helm"
        exit 1
        ;;
esac

echo "Project deployment to $ENVIRONMENT complete."
