#!/bin/bash

# GitOps Test Suite
set -e

# Test Helm chart
echo "Testing Helm chart syntax and dependencies..."
helm lint charts/zamaz

# Test Kubernetes manifests
echo "Validating Kubernetes manifests..."
helm template charts/zamaz | kubectl apply --dry-run=client -f -

# Test ArgoCD configurations
echo "Validating ArgoCD configurations..."
argocd app diff zamaz --local charts/zamaz --dest-server https://kubernetes.default.svc

# Test progressive delivery configuration
echo "Validating Argo Rollouts configuration..."
kubectl argo rollouts lint charts/zamaz/templates/rollout.yaml

# Validate monitoring configurations
echo "Validating monitoring configurations..."
promtool check rules charts/zamaz/templates/prometheusrules.yaml

# Security compliance check
echo "Running security compliance checks..."
kubesec scan charts/zamaz/templates/deployment.yaml
kubesec scan charts/zamaz/templates/rollout.yaml

# Test backup configurations
echo "Validating backup configurations..."
velero backup describe --selector app=zamaz

# Test network policies
echo "Validating network policies..."
kubectl neat -f charts/zamaz/templates/networkpolicy.yaml

# Validate certificate configurations
echo "Validating TLS certificate configurations..."
kubectl cert-manager check api

# Report results
echo "All tests completed. Check above output for any errors."
