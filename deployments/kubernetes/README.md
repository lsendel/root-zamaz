# Kubernetes Deployment Configuration

This directory contains Kubernetes manifests for deploying the Zamaz application using Kustomize.

## Directory Structure

```
kubernetes/
├── base/                    # Base Kubernetes manifests
│   ├── deployment.yaml      # Deployment configurations
│   ├── service.yaml         # Service definitions
│   ├── configmap.yaml       # ConfigMap for app configuration
│   ├── rbac.yaml           # RBAC configurations
│   ├── network-policy.yaml  # Network policies
│   └── kustomization.yaml   # Base Kustomization file
└── overlays/               # Environment-specific overlays
    ├── staging/
    │   ├── kustomization.yaml
    │   ├── deployment-patch.yaml
    │   └── configmap-patch.yaml
    └── production/
        ├── kustomization.yaml
        ├── deployment-patch.yaml
        ├── configmap-patch.yaml
        ├── hpa.yaml         # Horizontal Pod Autoscaler
        ├── pdb.yaml         # Pod Disruption Budget
        └── secrets.env      # Production secrets (DO NOT COMMIT)
```

## Deployment

### Prerequisites

- kubectl installed and configured
- kustomize installed (or kubectl 1.14+)
- Access to target Kubernetes cluster
- Docker images pushed to registry

### Deploy to Staging

```bash
# Using the deployment script (recommended)
./scripts/deploy-k8s.sh staging

# Or manually with kubectl
kubectl apply -k deployments/kubernetes/overlays/staging

# Dry run
DRY_RUN=true ./scripts/deploy-k8s.sh staging
```

### Deploy to Production

```bash
# First, ensure secrets.env is populated with production values
cd deployments/kubernetes/overlays/production
cp secrets.env.example secrets.env
# Edit secrets.env with actual production values

# Deploy
./scripts/deploy-k8s.sh production

# With custom timeout
TIMEOUT=600 ./scripts/deploy-k8s.sh production
```

## Configuration

### Base Configuration

The base configuration includes:
- **Deployments**: API and Frontend applications
- **Services**: ClusterIP services for internal communication
- **ConfigMaps**: Application configuration
- **RBAC**: Service accounts and roles
- **Network Policies**: Zero-trust network segmentation

### Environment Overlays

#### Staging
- Single replica for each component
- Debug logging enabled
- Lower resource limits
- Relaxed security policies

#### Production
- 3 replicas minimum
- Horizontal Pod Autoscaling (HPA)
- Pod Disruption Budgets (PDB)
- Anti-affinity rules for high availability
- Production-grade resource limits
- Strict network policies

## Customization

### Adding a New Environment

1. Create a new overlay directory:
```bash
mkdir -p deployments/kubernetes/overlays/dev
```

2. Create kustomization.yaml:
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: zamaz-dev

bases:
- ../../base

# Add patches and customizations
```

### Modifying Resources

Use Kustomize patches to modify resources:

```yaml
# deployment-patch.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zamaz-app
spec:
  replicas: 5
  template:
    spec:
      containers:
      - name: zamaz
        resources:
          limits:
            memory: "2Gi"
```

## Security Considerations

1. **Secrets Management**:
   - Never commit secrets.env files
   - Use Kubernetes secrets or external secret management
   - Consider using Sealed Secrets or External Secrets Operator

2. **Network Policies**:
   - Default deny-all policy is applied
   - Explicit allow rules for required communication
   - Separate policies for each component

3. **RBAC**:
   - Minimal permissions for service accounts
   - No cluster-wide permissions
   - Audit logging recommended

4. **Pod Security**:
   - Non-root user execution
   - Read-only root filesystem
   - No privilege escalation
   - Capabilities dropped

## Monitoring and Observability

The deployment includes:
- Prometheus metrics endpoint (port 9090)
- Health check endpoints (/health/live, /health/ready)
- Structured JSON logging
- Distributed tracing support

## Troubleshooting

### View deployment status
```bash
kubectl get all -n zamaz-staging
```

### Check pod logs
```bash
kubectl logs -n zamaz-staging deployment/zamaz-app
```

### Describe failing pods
```bash
kubectl describe pod -n zamaz-staging <pod-name>
```

### Test with port-forward
```bash
kubectl port-forward -n zamaz-staging service/zamaz-api 8080:80
```

### Export kubeconfig for service account
```bash
./scripts/export-kubeconfigs.sh staging-cluster zamaz-staging zamaz-app
```

## Rollback

In case of deployment failure:

```bash
# Automatic rollback (handled by deploy-k8s.sh)
# Or manual rollback
kubectl rollout undo deployment/zamaz-app -n zamaz-production
kubectl rollout undo deployment/zamaz-frontend -n zamaz-production
```