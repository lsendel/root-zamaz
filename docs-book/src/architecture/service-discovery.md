# Service Discovery Architecture

## Overview

The Zamaz application implements a comprehensive service discovery system that works across multiple environments and service registry providers. This system ensures that frontend applications can dynamically discover and connect to backend services regardless of the deployment environment.

> **Note**: This is the modern, unified service discovery system that replaced legacy static configuration approaches. It provides automatic failover, health monitoring, and load balancing across multiple service registry providers.

## Architecture Components

### 1. Service Registry Interface

The core service registry interface provides a pluggable architecture:

```go
type ServiceRegistry interface {
    Register(ctx context.Context, service *Service) error
    Deregister(ctx context.Context, serviceID string) error
    Discover(ctx context.Context, serviceName string) ([]*Service, error)
    Watch(ctx context.Context, serviceName string) (<-chan ServiceEvent, error)
    Health() error
    Close() error
}
```

This interface allows for multiple backend implementations while providing a consistent API for service discovery operations.

### 2. Service Registry Implementations

#### Consul Registry
- **Location**: `pkg/discovery/consul.go`
- **Provider**: HashiCorp Consul
- **Features**:
  - Service registration and discovery
  - Health checking and automatic deregistration
  - Service watching for real-time updates
  - Load balancing with multiple strategies

#### Kubernetes Registry
- **Location**: `pkg/discovery/kubernetes.go`
- **Provider**: Kubernetes DNS
- **Features**:
  - Native Kubernetes service discovery via DNS
  - Headless service support for direct pod access
  - Integration with Kubernetes health checks
  - Automatic endpoint discovery

### 3. Frontend Service Discovery

The frontend implements intelligent service discovery in `frontend/src/config/service-discovery.ts`:

- **Auto-detects environment**: Kubernetes, Consul, or static configuration
- **Health monitoring**: Periodic health checks of discovered endpoints
- **Load balancing**: Round-robin, random, and least-connections strategies
- **Fallback mechanisms**: Graceful degradation when services are unavailable
- **Dynamic endpoint updates**: Real-time endpoint refreshing

## Service Discovery Flow

```typescript
// Detection Logic
if (isKubernetesEnvironment()) {
    // Use Kubernetes DNS resolution
    endpoints = getKubernetesEndpoints()
} else if (isConsulAvailable()) {
    // Use Consul service discovery
    endpoints = getConsulEndpoints()
} else {
    // Fall back to static configuration
    endpoints = getStaticEndpoints()
}
```

### Environment Detection

#### Kubernetes Environment
- Checks for `*.cluster.local` or `*.svc` in hostname
- Looks for Kubernetes environment variables (`VITE_KUBERNETES_SERVICE_HOST`)
- Detects mounted service account tokens

#### Consul Environment
- Checks for Consul host configuration (`VITE_CONSUL_HOST`)
- Validates Consul API availability
- Tests DNS resolution for `.service.consul` domains

#### Static/Development Environment
- Uses environment variables (`VITE_API_HOST`)
- Defaults to localhost for development
- Supports manual endpoint configuration

## Related Documentation

- **[Consul Integration](consul.md)** - Detailed Consul configuration
- **[Kubernetes DNS](kubernetes-dns.md)** - Kubernetes service discovery
- **[Service Mesh](service-mesh.md)** - Istio integration
- **[Load Balancing](../operations/performance.md)** - Performance optimization

## Configuration Examples

### Development Environment
```bash
VITE_API_HOST=localhost
VITE_API_PORT=3001
VITE_SERVICE_DISCOVERY_ENABLED=false
```

### Kubernetes Environment
```bash
VITE_K8S_NAMESPACE=zamaz
VITE_API_SERVICE_NAME=zamaz-api-service
VITE_SERVICE_DISCOVERY_ENABLED=true
VITE_CONSUL_ENABLED=true
```

### Consul Environment
```bash
VITE_CONSUL_HOST=consul.service.consul
VITE_CONSUL_API_URL=http://consul.consul.svc.cluster.local:8500
VITE_SERVICE_DISCOVERY_PROVIDER=consul
```

## Health Monitoring

### Frontend Health Checks
- `/health`: Basic container health
- `/ready`: Service dependency readiness
- Periodic API endpoint validation
- Service discovery endpoint monitoring

### Backend Integration
- Consul health check registration
- Kubernetes readiness/liveness probes
- Istio service mesh health validation
- Custom health check endpoints

## Load Balancing Strategies

### Round Robin (Default)
- Equal distribution across healthy endpoints
- Maintains endpoint index state
- Automatic failure detection and recovery

### Random
- Random endpoint selection
- Good for stateless services
- Reduces hot spotting

### Weighted
- Priority-based endpoint selection
- Supports service tiers (primary/secondary)
- Graceful traffic shaping

## Troubleshooting

### Common Issues

1. **DNS Resolution Failures**
   - Check Kubernetes DNS configuration
   - Verify service names and namespaces
   - Test with `nslookup` from pods

2. **Health Check Failures**
   - Validate endpoint URLs
   - Check network connectivity
   - Review timeout configurations

3. **Circuit Breaker Activation**
   - Monitor failure thresholds
   - Check backend service health
   - Review retry configurations

### Debugging Commands

```bash
# Test DNS resolution
kubectl exec -it <pod> -- nslookup zamaz-api-service.zamaz.svc.cluster.local

# Check service endpoints
kubectl get endpoints -n zamaz

# Monitor health checks
kubectl logs -n zamaz -l app=zamaz-frontend --tail=100

# Test API connectivity
kubectl exec -it <pod> -- wget -qO- http://zamaz-api-service.zamaz.svc.cluster.local:8080/health
```

## Security Considerations

### Network Policies
- Restrict service-to-service communication
- Namespace isolation
- Ingress/egress traffic controls

### mTLS with Istio
- Automatic certificate management
- Service-to-service encryption
- Identity-based authorization

### RBAC Configuration
- Service account permissions
- API server access controls
- Resource-specific permissions

This service discovery architecture provides a robust, scalable foundation for microservices communication across diverse deployment environments while maintaining high availability and observability.