# Kubernetes Resource Refactoring Plan

## Executive Summary
This document outlines our strategy to refactor the current hybrid Helm/Kustomize approach into a standardized, maintainable configuration management system that eliminates duplication and provides clear ownership of resources.

## Current State Analysis

### Identified Duplications
1. **Zamaz Application**: Defined in both `charts/zamaz/` and `deployments/kubernetes/base/`
2. **Network Policies**: Multiple definitions in Helm charts and Kustomize bases
3. **SPIRE Integration**: Overlapping configurations in both systems
4. **RBAC Resources**: ServiceAccounts and Roles duplicated across locations
5. **ConfigMaps**: Similar configurations with different values

### Issues Caused by Current Structure
- Resource naming conflicts
- Configuration drift between similar resources
- Unclear deployment ownership
- Maintenance overhead
- Potential for deployment conflicts

## Refactoring Strategy

### 1. Primary Tool Selection

#### Helm (Production & Templated Components)
- **Scope**: Third-party applications, complex templating needs, production deployments
- **Components**:
  - `istio-mesh/` - Complex service mesh configuration
  - `observability/` - Third-party monitoring stack (Prometheus, Grafana, Jaeger)
  - `spire-integration/` - Identity workload system requiring templating
  - Infrastructure components requiring environment-specific templating

#### Kustomize (Application Deployment & Environment Overlays)
- **Scope**: First-party applications, environment-specific patches, development workflows
- **Components**:
  - `zamaz/` - Main application deployment
  - Base configurations for development
  - Environment-specific overlays (dev, staging, prod)
  - Security policies (network policies, pod security)

### 2. New Directory Structure

```
kubernetes/
├── apps/                           # Application-specific configurations
│   ├── zamaz/                      # Main application
│   │   ├── base/                   # Base Kustomize configuration
│   │   ├── overlays/               # Environment-specific overlays
│   │   │   ├── development/
│   │   │   ├── staging/
│   │   │   └── production/
│   │   └── components/             # Reusable components
├── infrastructure/                 # Infrastructure components (Helm)
│   ├── istio-mesh/                # Service mesh
│   ├── observability/             # Monitoring stack
│   ├── spire-integration/         # Identity system
│   └── security-policies/         # Global security policies
├── platform/                      # Platform-wide configurations
│   ├── namespaces/                # Namespace definitions
│   ├── network-policies/          # Common network policies
│   ├── rbac/                      # Common RBAC resources
│   └── secrets/                   # External secrets configuration
└── scripts/                       # Deployment and management scripts
    ├── deploy.sh                  # Unified deployment script
    ├── validate.sh                # Configuration validation
    └── cleanup.sh                 # Environment cleanup
```

### 3. Migration Plan

#### Phase 1: Establish New Structure (Week 1)
1. Create new directory structure
2. Define standardized naming conventions
3. Create common base components
4. Implement validation scripts

#### Phase 2: Migrate Zamaz Application (Week 2)
1. Consolidate Zamaz deployment into Kustomize-only approach
2. Remove duplicate Helm chart
3. Create environment-specific overlays
4. Test deployment in development environment

#### Phase 3: Consolidate Infrastructure (Week 3)
1. Standardize infrastructure components on Helm
2. Merge duplicate network policies
3. Consolidate RBAC resources
4. Update SPIRE integration

#### Phase 4: Testing & Validation (Week 4)
1. Comprehensive testing across all environments
2. Documentation updates
3. Team training on new structure
4. Production deployment

### 4. Standardized Naming Conventions

#### Labels
```yaml
labels:
  app.kubernetes.io/name: zamaz
  app.kubernetes.io/instance: zamaz-prod
  app.kubernetes.io/version: "1.2.3"
  app.kubernetes.io/component: api
  app.kubernetes.io/part-of: zamaz-platform
  app.kubernetes.io/managed-by: kustomize
  environment: production
  team: platform-engineering
  project: zero-trust-auth
```

#### Resource Naming
- **Format**: `{app}-{component}-{resource-type}`
- **Examples**:
  - `zamaz-api-deployment`
  - `zamaz-frontend-service`
  - `zamaz-config-configmap`

### 5. Component Ownership Matrix

| Component | Tool | Reason | Owner |
|-----------|------|--------|-------|
| Zamaz App | Kustomize | First-party app, environment patches | Application Team |
| Istio Mesh | Helm | Complex templating, third-party | Platform Team |
| Observability | Helm | Third-party stack, complex config | Platform Team |
| SPIRE | Helm | Complex identity system | Security Team |
| Network Policies | Kustomize | Application-specific rules | Security Team |
| RBAC | Both | Common (Kustomize), Complex (Helm) | Security Team |

## Implementation Benefits

### Immediate Benefits
- **Elimination of Duplicates**: Remove 5 major duplication points
- **Clear Ownership**: Each resource has single source of truth
- **Reduced Complexity**: Simplified deployment workflows
- **Better Testing**: Isolated component testing possible

### Long-term Benefits
- **Improved Maintainability**: Single tool per component reduces cognitive load
- **Enhanced Consistency**: Standardized naming and labeling
- **Better GitOps**: Clear structure supports automated deployments
- **Reduced Risk**: Fewer conflicts, clearer rollback procedures

### Metrics for Success
- **Deployment Time**: Target 50% reduction in deployment complexity
- **Error Rate**: Reduce configuration-related errors by 80%
- **Team Velocity**: Faster onboarding and maintenance tasks
- **Resource Consistency**: 100% compliance with naming conventions

## Risk Mitigation

### Deployment Risks
- **Mitigation**: Phased migration with comprehensive testing
- **Rollback Plan**: Maintain current configurations until migration complete

### Learning Curve
- **Mitigation**: Team training sessions and documentation
- **Support**: Dedicated migration support team

### Configuration Loss
- **Mitigation**: Configuration comparison scripts
- **Validation**: Automated testing of migrated configurations

## Next Steps

1. **Approval**: Get stakeholder approval for refactoring plan
2. **Team Formation**: Assign migration team members
3. **Timeline**: Confirm 4-week migration timeline
4. **Kickoff**: Begin Phase 1 implementation

This refactoring will transform our Kubernetes management from a complex, duplicated system into a streamlined, maintainable platform that scales with our growing infrastructure needs.