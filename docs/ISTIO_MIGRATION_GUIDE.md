# Istio Service Mesh Migration Guide

## Overview

This guide provides a comprehensive step-by-step approach for migrating the Zamaz Zero Trust Authentication MVP from standalone Envoy to a full Istio service mesh using a **namespace-based migration strategy**.

## Migration Strategy: Namespace-Based Approach

The namespace-based migration allows for:
- **Zero-downtime deployment** with parallel environments
- **Gradual traffic shifting** from legacy to mesh
- **Easy rollback** capabilities
- **Comprehensive testing** before full cutover

### Architecture Before Migration

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────┐
│   Load Balancer │───▶│     Envoy    │───▶│   Zamaz     │
│                 │    │   (Standalone)│    │ Application │
└─────────────────┘    └──────────────┘    └─────────────┘
                                                   │
                                           ┌───────┴───────┐
                                           │   Database    │
                                           │    Redis      │
                                           │    NATS       │
                                           └───────────────┘
```

### Architecture After Migration

```
┌─────────────────┐    ┌──────────────────┐    ┌────────────────┐
│   Load Balancer │───▶│  Istio Gateway   │───▶│ Zamaz + Envoy  │
│                 │    │                  │    │   Sidecars     │
└─────────────────┘    └──────────────────┘    └────────────────┘
                                │                       │
                        ┌───────┴───────┐       ┌───────┴───────┐
                        │ Virtual Service│       │ SPIRE Identity│
                        │Destination Rules│       │   mTLS Certs  │
                        └───────────────┘       └───────────────┘
```

## Prerequisites

### Required Tools

```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Install Istioctl
curl -L https://istio.io/downloadIstio | sh -
export PATH="$PATH:$PWD/istio-1.20.1/bin"
```

### Cluster Requirements

- Kubernetes 1.25+
- Minimum 4 vCPUs, 8GB RAM
- LoadBalancer support
- StorageClass for persistent volumes
- RBAC enabled

### Pre-Migration Checklist

- [ ] Backup current database
- [ ] Document current configuration
- [ ] Test disaster recovery procedures
- [ ] Prepare rollback plan
- [ ] Schedule maintenance window
- [ ] Notify stakeholders

## Migration Steps

### Phase 1: Infrastructure Setup

#### Step 1: Install Istio Control Plane

```bash
# Run prerequisite checks
./scripts/istio-migration.sh prereq

# Install Istio
./scripts/istio-migration.sh install-istio
```

This will:
- Create `istio-system` namespace
- Install Istio base components
- Install Istiod control plane
- Install Istio gateway

#### Step 2: Deploy SPIRE Integration

```bash
# Deploy SPIRE for workload identity
./scripts/istio-migration.sh deploy-spire
```

This will:
- Create `spire-system` namespace
- Deploy SPIRE server and agents
- Configure SPIRE-Istio integration
- Create initial workload identities

### Phase 2: Mesh Namespace Creation

#### Step 3: Create Mesh Namespace

```bash
# Create zamaz-mesh namespace with Istio injection
./scripts/istio-migration.sh create-namespace
```

This creates the `zamaz-mesh` namespace with:
- Istio sidecar injection enabled
- Pod Security Standards (restricted)
- Proper labels and annotations

#### Step 4: Deploy Mesh Infrastructure

```bash
# Deploy service mesh infrastructure
./scripts/istio-migration.sh deploy-infrastructure
```

This deploys:
- Istio Gateway and VirtualService
- DestinationRules with circuit breakers
- Security policies and authorization
- Enhanced observability stack

### Phase 3: Application Deployment

#### Step 5: Deploy Application to Mesh

```bash
# Deploy Zamaz to mesh namespace
./scripts/istio-migration.sh deploy-app
```

This will:
- Deploy Zamaz with Istio sidecars
- Configure service accounts with SPIRE identities
- Set up security policies
- Enable telemetry collection

#### Step 6: Verify Deployment

```bash
# Verify mesh deployment
./scripts/istio-migration.sh verify
```

This checks:
- Sidecar injection status
- SPIRE workload identities
- mTLS configuration
- Service mesh connectivity

### Phase 4: Traffic Migration

#### Step 7: Initial Testing

```bash
# Test mesh functionality
./scripts/istio-migration.sh test
```

#### Step 8: Gradual Traffic Shifting

Start with 10% traffic to test:

```bash
# Shift 10% traffic to mesh
./scripts/istio-migration.sh shift-traffic 10
```

Monitor for 30 minutes:

```bash
# Monitor migration
./scripts/istio-migration.sh monitor 1800
```

Gradually increase traffic:

```bash
# 25% traffic
./scripts/istio-migration.sh shift-traffic 25

# 50% traffic
./scripts/istio-migration.sh shift-traffic 50

# 75% traffic
./scripts/istio-migration.sh shift-traffic 75
```

#### Step 9: Complete Migration

When confident:

```bash
# Complete migration (100% traffic)
./scripts/istio-migration.sh complete
```

## Monitoring and Observability

### Key Metrics to Monitor

1. **Application Metrics**
   - Request rate and latency
   - Error rates (4xx, 5xx)
   - Database connection pool usage

2. **Service Mesh Metrics**
   - Sidecar resource usage
   - mTLS success rate
   - Circuit breaker status

3. **Security Metrics**
   - Authentication success/failure rates
   - SPIRE certificate renewals
   - Authorization policy violations

### Dashboards

Access the following dashboards:

```bash
# Grafana (admin/admin)
kubectl port-forward -n monitoring svc/grafana 3000:80

# Jaeger UI
kubectl port-forward -n monitoring svc/jaeger-query 16686:16686

# Kiali (if installed)
kubectl port-forward -n istio-system svc/kiali 20001:20001
```

### Key Dashboards

- **Zamaz Application Overview**: Application-specific metrics
- **Istio Service Mesh**: Service mesh performance
- **Security Dashboard**: Authentication and authorization metrics
- **SPIRE Dashboard**: Workload identity status

## Troubleshooting

### Common Issues

#### 1. Sidecar Not Injected

**Symptoms**: Pods start but no Istio proxy sidecar

**Solution**:
```bash
# Check namespace labels
kubectl get namespace zamaz-mesh --show-labels

# Ensure istio-injection=enabled
kubectl label namespace zamaz-mesh istio-injection=enabled --overwrite

# Restart pods
kubectl rollout restart deployment -n zamaz-mesh
```

#### 2. mTLS Connection Issues

**Symptoms**: Service-to-service communication fails

**Solution**:
```bash
# Check peer authentication
kubectl get peerauthentication -n zamaz-mesh

# Check destination rules
kubectl get destinationrule -n zamaz-mesh

# Debug with istioctl
istioctl proxy-config cluster <pod-name> -n zamaz-mesh
```

#### 3. SPIRE Identity Issues

**Symptoms**: Workloads cannot get SPIFFE identities

**Solution**:
```bash
# Check SPIRE server logs
kubectl logs -n spire-system deployment/spire-server

# Check registration entries
kubectl exec -n spire-system deployment/spire-server -- \
  /opt/spire/bin/spire-server entry show

# Verify agent connectivity
kubectl logs -n spire-system daemonset/spire-agent
```

#### 4. High Latency

**Symptoms**: Increased response times

**Investigation**:
```bash
# Check proxy stats
kubectl exec <pod-name> -c istio-proxy -n zamaz-mesh -- \
  curl localhost:15000/stats | grep circuit_breakers

# Check resource usage
kubectl top pods -n zamaz-mesh

# Review tracing
# Access Jaeger UI and examine traces
```

### Debug Commands

```bash
# Check Istio configuration
istioctl analyze -n zamaz-mesh

# Proxy configuration
istioctl proxy-config bootstrap <pod-name> -n zamaz-mesh

# Check certificates
istioctl proxy-config secret <pod-name> -n zamaz-mesh

# Network policies
kubectl describe networkpolicy -n zamaz-mesh
```

## Rollback Procedures

### Emergency Rollback

If critical issues occur:

```bash
# Emergency rollback
./scripts/istio-migration.sh rollback
```

This will:
1. Shift all traffic back to legacy namespace
2. Scale down mesh deployments
3. Preserve legacy environment

### Planned Rollback

For planned rollbacks:

1. **Gradual traffic shift back**:
   ```bash
   ./scripts/istio-migration.sh shift-traffic 50
   ./scripts/istio-migration.sh shift-traffic 25
   ./scripts/istio-migration.sh shift-traffic 0
   ```

2. **Scale down mesh environment**:
   ```bash
   kubectl scale deployment -n zamaz-mesh --all --replicas=0
   ```

3. **Clean up resources** (optional):
   ```bash
   helm uninstall zamaz-mesh -n zamaz-mesh
   kubectl delete namespace zamaz-mesh
   ```

## Security Considerations

### Network Security

- **Default Deny**: All network traffic denied by default
- **Least Privilege**: Services can only communicate as needed
- **mTLS Everywhere**: All service-to-service communication encrypted

### Identity and Access

- **SPIRE Integration**: Cryptographic workload identities
- **Zero Trust**: No implicit trust between services
- **Authorization Policies**: Fine-grained access control

### Compliance

- **Pod Security Standards**: Restricted security context
- **Network Policies**: Kubernetes-native network segmentation
- **Audit Logging**: Comprehensive security event logging

## Performance Optimization

### Sidecar Resources

Adjust sidecar resource limits based on load:

```yaml
# In values.yaml
istio:
  sidecar:
    resources:
      requests:
        cpu: 100m
        memory: 128Mi
      limits:
        cpu: 200m
        memory: 256Mi
```

### Circuit Breaker Tuning

```yaml
# Adjust circuit breaker settings
destinationRule:
  api:
    trafficPolicy:
      circuitBreaker:
        consecutiveGatewayErrors: 5
        consecutive5xxErrors: 5
        interval: 30s
        baseEjectionTime: 30s
        maxEjectionPercent: 50
```

### Connection Pool Optimization

```yaml
# Optimize connection pooling
destinationRule:
  api:
    trafficPolicy:
      connectionPool:
        tcp:
          maxConnections: 100
          connectTimeout: 30s
        http:
          http1MaxPendingRequests: 1000
          maxRequestsPerConnection: 10
```

## Post-Migration Tasks

1. **Update Documentation**
   - Service architecture diagrams
   - Troubleshooting runbooks
   - Security procedures

2. **Team Training**
   - Istio troubleshooting
   - Service mesh concepts
   - New monitoring tools

3. **Optimize Configuration**
   - Fine-tune resource limits
   - Adjust circuit breaker settings
   - Optimize observability collection

4. **Clean Up Legacy Resources**
   - Remove standalone Envoy
   - Clean up old monitoring
   - Archive legacy configuration

## Support and Resources

- **Istio Documentation**: https://istio.io/docs/
- **SPIRE Documentation**: https://spiffe.io/docs/
- **Prometheus Best Practices**: https://prometheus.io/docs/practices/
- **Kubernetes Security**: https://kubernetes.io/docs/concepts/security/

## Appendix

### Migration Checklist

#### Pre-Migration
- [ ] Prerequisites installed
- [ ] Cluster capacity verified
- [ ] Backup completed
- [ ] Team trained
- [ ] Rollback plan documented

#### Infrastructure Phase
- [ ] Istio control plane installed
- [ ] SPIRE integration deployed
- [ ] Mesh namespace created
- [ ] Security policies applied

#### Application Phase
- [ ] Application deployed to mesh
- [ ] Sidecar injection verified
- [ ] SPIRE identities configured
- [ ] Health checks passing

#### Traffic Migration
- [ ] Initial testing completed
- [ ] 10% traffic migrated
- [ ] 25% traffic migrated
- [ ] 50% traffic migrated
- [ ] 75% traffic migrated
- [ ] 100% traffic migrated

#### Post-Migration
- [ ] Legacy environment cleaned up
- [ ] Documentation updated
- [ ] Team training completed
- [ ] Performance optimized

### Emergency Contacts

- **Platform Team**: platform-team@company.com
- **Security Team**: security-team@company.com
- **On-Call**: +1-xxx-xxx-xxxx

---

*This migration guide is part of the Zamaz Zero Trust Authentication MVP documentation.*