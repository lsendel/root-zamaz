# Kubernetes Resource Migration Guide

## Overview

This guide provides step-by-step instructions for migrating from the current hybrid Helm/Kustomize approach to the new standardized configuration management system.

## Migration Summary

### What's Changing
- **Eliminating Duplicates**: Removing duplicate resource definitions between Helm charts and Kustomize bases
- **Clear Tool Ownership**: Each component now has a single source of truth (either Helm or Kustomize)
- **Standardized Structure**: New directory structure with consistent naming conventions
- **Environment Separation**: Clean environment-specific overlays for development, staging, and production

### What's Staying
- **Helm Charts**: For infrastructure components (Istio, SPIRE, Observability)
- **Kustomize**: For application deployments (Zamaz) and environment-specific configurations
- **Current Functionality**: All existing features and security policies are preserved

## Pre-Migration Checklist

### 1. Backup Current State

```bash
# Create a backup of current deployments
kubectl get all,configmaps,secrets,networkpolicies,roles,rolebindings --all-namespaces -o yaml > backup-$(date +%Y%m%d-%H%M%S).yaml

# Backup Helm releases
helm list --all-namespaces > helm-releases-backup.txt
```

### 2. Validate Prerequisites

```bash
# Run the validation script
./kubernetes/scripts/validate.sh -e development -c all --verbose
```

### 3. Test New Configuration

```bash
# Test new configuration without applying
./kubernetes/scripts/deploy.sh -e development -c zamaz --dry-run
```

## Migration Steps

### Phase 1: Development Environment Migration

#### Step 1.1: Deploy New Zamaz Configuration

```bash
# Deploy new Zamaz configuration to development
./kubernetes/scripts/deploy.sh -e development -c zamaz
```

#### Step 1.2: Verify Deployment

```bash
# Check deployment status
kubectl get pods -n zamaz-dev
kubectl get services -n zamaz-dev
kubectl get networkpolicies -n zamaz-dev

# Test application functionality
curl -f http://$(kubectl get svc prod-zamaz-frontend-service -n zamaz-dev -o jsonpath='{.spec.clusterIP}'):3000/health
```

#### Step 1.3: Clean Up Old Resources

```bash
# Remove old duplicate resources (if any exist)
kubectl delete -f deployments/kubernetes/base/ --ignore-not-found=true

# Clean up old Helm chart deployment (if it exists)
helm uninstall zamaz -n zamaz --ignore-not-found
```

### Phase 2: Infrastructure Consolidation

#### Step 2.1: Update Infrastructure Components

```bash
# Deploy consolidated infrastructure
./kubernetes/scripts/deploy.sh -e development -c infrastructure
```

#### Step 2.2: Verify Infrastructure

```bash
# Check SPIRE deployment
kubectl get pods -n spire-system
kubectl logs -n spire-system deployment/spire-server

# Check Observability stack
kubectl get pods -n observability

# Check Istio mesh
kubectl get pods -n istio-system
```

### Phase 3: Staging Environment

#### Step 3.1: Create Staging Overlay

```bash
# Create staging-specific configuration
cp -r kubernetes/apps/zamaz/overlays/development kubernetes/apps/zamaz/overlays/staging

# Edit staging configuration
vim kubernetes/apps/zamaz/overlays/staging/kustomization.yaml
# Update:
# - namespace: zamaz-staging
# - namePrefix: staging-
# - image tags to staging versions
# - replica counts for staging load
```

#### Step 3.2: Deploy to Staging

```bash
# Deploy to staging
./kubernetes/scripts/deploy.sh -e staging -c all
```

### Phase 4: Production Migration

> **WARNING**: This phase affects production systems. Plan for maintenance window.

#### Step 4.1: Pre-Production Validation

```bash
# Validate production configuration
./kubernetes/scripts/validate.sh -e production -c all --verbose

# Dry-run production deployment
./kubernetes/scripts/deploy.sh -e production -c zamaz --dry-run
```

#### Step 4.2: Production Deployment

```bash
# During maintenance window:

# 1. Deploy new configuration alongside existing
./kubernetes/scripts/deploy.sh -e production -c zamaz

# 2. Verify new deployment
kubectl get pods -n zamaz-prod
kubectl rollout status deployment/prod-zamaz-api-deployment -n zamaz-prod
kubectl rollout status deployment/prod-zamaz-frontend-deployment -n zamaz-prod

# 3. Test application
# Run your production health checks here

# 4. Switch traffic (if using Istio/ingress)
# Update your ingress/gateway configuration to point to new services

# 5. Clean up old deployment
./kubernetes/scripts/cleanup.sh -e production -c zamaz --force
```

## Directory Mapping

### Old Structure → New Structure

```
OLD                                    NEW
├── charts/zamaz/                  →   [REMOVED - Consolidated into Kustomize]
├── charts/istio-mesh/             →   kubernetes/infrastructure/istio-mesh/
├── charts/observability/          →   kubernetes/infrastructure/observability/
├── charts/spire-integration/      →   kubernetes/infrastructure/spire-integration/
├── charts/security-policies/      →   kubernetes/platform/security-policies/
├── deployments/kubernetes/base/   →   kubernetes/apps/zamaz/base/
├── deployments/kubernetes/overlays/ → kubernetes/apps/zamaz/overlays/
└── [NEW]                          →   kubernetes/scripts/
```

## Resource Ownership Changes

| Resource Type | Old Ownership | New Ownership |
|---------------|---------------|---------------|
| Zamaz Deployment | Helm + Kustomize (Duplicate) | Kustomize Only |
| Zamaz ConfigMaps | Helm + Kustomize (Duplicate) | Kustomize Only |
| Zamaz NetworkPolicies | Multiple locations | Consolidated in Kustomize |
| Zamaz RBAC | Helm + Kustomize (Duplicate) | Kustomize Only |
| SPIRE Integration | Helm + Kustomize (Duplicate) | Helm Only |
| Observability | Helm | Helm (No Change) |
| Istio Mesh | Helm | Helm (No Change) |

## Validation Commands

### During Migration

```bash
# Validate configuration syntax
./kubernetes/scripts/validate.sh -e $ENVIRONMENT -c all

# Check for resource conflicts
kubectl get all --all-namespaces | grep zamaz

# Verify network policies
kubectl get networkpolicies --all-namespaces

# Check RBAC
kubectl get clusterroles,roles --all-namespaces | grep zamaz
```

### After Migration

```bash
# Application health checks
kubectl get pods -n zamaz-$ENVIRONMENT
kubectl logs -n zamaz-$ENVIRONMENT deployment/$(echo $ENVIRONMENT | cut -c1-4)-zamaz-api-deployment

# Service connectivity
kubectl exec -n zamaz-$ENVIRONMENT deployment/$(echo $ENVIRONMENT | cut -c1-4)-zamaz-api-deployment -- curl -f http://$(echo $ENVIRONMENT | cut -c1-4)-zamaz-frontend-service:3000/health

# Network policy verification
kubectl exec -n zamaz-$ENVIRONMENT deployment/$(echo $ENVIRONMENT | cut -c1-4)-zamaz-api-deployment -- nslookup postgres-service.postgres.svc.cluster.local
```

## Rollback Procedures

### If Migration Fails

#### Quick Rollback

```bash
# 1. Scale down new deployment
kubectl scale deployment --all --replicas=0 -n zamaz-$ENVIRONMENT

# 2. Restore from backup
kubectl apply -f backup-YYYYMMDD-HHMMSS.yaml

# 3. Verify old deployment
kubectl get pods --all-namespaces | grep zamaz
```

#### Complete Rollback

```bash
# Clean up new resources
./kubernetes/scripts/cleanup.sh -e $ENVIRONMENT -c zamaz --force

# Restore original Helm charts
helm install zamaz charts/zamaz/ -n zamaz

# Restore original Kustomize
kubectl apply -k deployments/kubernetes/overlays/$ENVIRONMENT/
```

## Troubleshooting

### Common Issues

#### 1. Resource Conflicts

```bash
# Symptom: "resource already exists" errors
# Solution: Clean up conflicting resources
kubectl delete deployment zamaz-api zamaz-frontend -n zamaz
kubectl delete service zamaz-api zamaz-frontend -n zamaz
```

#### 2. Network Policy Blocks

```bash
# Symptom: Pods can't communicate
# Solution: Check network policies
kubectl get networkpolicies -n zamaz-$ENVIRONMENT
kubectl describe networkpolicy zamaz-default-deny-all -n zamaz-$ENVIRONMENT
```

#### 3. RBAC Permission Errors

```bash
# Symptom: "forbidden" errors in logs
# Solution: Check service account permissions
kubectl get rolebindings -n zamaz-$ENVIRONMENT
kubectl describe role zamaz-api-role -n zamaz-$ENVIRONMENT
```

#### 4. Image Pull Errors

```bash
# Symptom: ImagePullBackOff
# Solution: Check image tags in kustomization.yaml
kubectl describe pod -n zamaz-$ENVIRONMENT | grep -A5 "Failed to pull image"
```

## Post-Migration Tasks

### 1. Update CI/CD Pipelines

- Update deployment scripts to use new `./kubernetes/scripts/deploy.sh`
- Update validation steps to use `./kubernetes/scripts/validate.sh`
- Update cleanup procedures to use `./kubernetes/scripts/cleanup.sh`

### 2. Update Documentation

- Update deployment runbooks
- Update troubleshooting guides
- Update team onboarding documentation

### 3. Team Training

- Conduct training sessions on new directory structure
- Update development workflows
- Share new deployment commands

### 4. Monitoring Updates

- Update monitoring dashboards for new resource names
- Update alerting rules for new namespaces
- Verify metrics collection from new deployments

## Success Criteria

### Migration is Complete When:

- [ ] All duplicate resources are eliminated
- [ ] Each component has single source of truth
- [ ] All environments deploy successfully with new scripts
- [ ] Application functionality is preserved
- [ ] Network policies work correctly
- [ ] RBAC permissions function properly
- [ ] Monitoring and observability work
- [ ] CI/CD pipelines are updated
- [ ] Team is trained on new procedures

### Performance Metrics:

- **Deployment Time**: Target 50% reduction in deployment complexity
- **Error Rate**: Reduce configuration-related errors by 80%
- **Resource Consistency**: 100% compliance with naming conventions
- **Maintenance Overhead**: 60% reduction in duplicate resource management

## Support

For assistance during migration:

1. **Validation Issues**: Run `./kubernetes/scripts/validate.sh --verbose` for detailed error information
2. **Deployment Problems**: Use `--dry-run` flag to test changes before applying
3. **Rollback Needed**: Follow rollback procedures above
4. **Team Questions**: Refer to `KUBERNETES_REFACTORING_PLAN.md` for architectural decisions

The migration transforms your Kubernetes management from a complex, duplicated system into a streamlined, maintainable platform that scales with your growing infrastructure needs.