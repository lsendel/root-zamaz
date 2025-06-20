# Service Discovery Architecture

## Overview

The Zamaz application implements a comprehensive service discovery system that works across multiple environments and service registry providers. This system ensures that frontend applications can dynamically discover and connect to backend services regardless of the deployment environment.

## Architecture Components

### 1. Service Registry Interface (`pkg/discovery/registry.go`)

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

### 2. Service Registry Implementations

#### Consul Registry (`pkg/discovery/consul.go`)
- Uses HashiCorp Consul for service registration and discovery
- Provides health checking and automatic deregistration
- Supports service watching for real-time updates
- Load balancing with multiple strategies

#### Kubernetes Registry (`pkg/discovery/kubernetes.go`)
- Native Kubernetes service discovery via DNS
- Headless service support for direct pod access
- Integration with Kubernetes health checks
- Automatic endpoint discovery

### 3. Frontend Service Discovery (`frontend/src/config/service-discovery.ts`)

The frontend implements intelligent service discovery that:

- **Auto-detects environment**: Kubernetes, Consul, or static configuration
- **Health monitoring**: Periodic health checks of discovered endpoints
- **Load balancing**: Round-robin, random, and least-connections strategies
- **Fallback mechanisms**: Graceful degradation when services are unavailable
- **Dynamic endpoint updates**: Real-time endpoint refreshing

## Frontend Service Discovery Flow

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

## Enhanced API Client (`frontend/src/services/api-enhanced.ts`)

The enhanced API client provides:

### Circuit Breaker Pattern
```typescript
class CircuitBreaker {
    private state: CLOSED | OPEN | HALF_OPEN
    private failureCount: number
    private lastFailureTime: number
    
    async execute<T>(fn: () => Promise<T>): Promise<T> {
        // Circuit breaker logic with failure tracking
        // Automatic recovery attempts after timeout
    }
}
```

### Retry Logic with Exponential Backoff
- Configurable retry attempts (default: 3)
- Exponential backoff delay calculation
- Conditional retry based on error type
- Alternative endpoint switching on retry

### Dynamic Endpoint Switching
- Real-time endpoint health monitoring
- Automatic failover to healthy endpoints
- Load balancing across available services
- Correlation ID tracking for distributed tracing

## Kubernetes Deployment Configuration

### Frontend Deployment (`k8s/frontend/deployment.yaml`)

Key service discovery features:

```yaml
env:
- name: VITE_K8S_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
- name: VITE_API_SERVICE_NAME
  value: "zamaz-api-service"
- name: VITE_SERVICE_DISCOVERY_ENABLED
  value: "true"
```

### Service Configuration (`k8s/frontend/service.yaml`)

Includes ConfigMaps for:
- Dynamic configuration injection
- Nginx proxy rules with service discovery
- Health check endpoints
- CORS and security headers

### Istio Integration (`k8s/frontend/ingress.yaml`)

Advanced traffic management:
- **VirtualService**: Intelligent routing with retry policies
- **DestinationRule**: Circuit breaker configuration at mesh level
- **Gateway**: TLS termination and security policies
- **EnvoyFilter**: Custom proxy behaviors

## Make Commands

The Makefile provides comprehensive service discovery management:

```bash
# Deploy frontend with service discovery
make k8s-frontend-deploy

# Check deployment status
make k8s-frontend-status

# Test service discovery functionality
make k8s-test-discovery

# Complete deployment pipeline
make k8s-frontend-complete
```

## Configuration Examples

### Development Environment (.env.local)
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
VITE_ENABLE_CIRCUIT_BREAKER=true
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

## Monitoring and Observability

### Correlation IDs
- Unique request tracking across services
- Distributed tracing support
- Error correlation and debugging

### Metrics Collection
- Service discovery success/failure rates
- Endpoint health check latencies
- Circuit breaker state transitions
- Load balancing distribution metrics

### Logging
- Service discovery events
- Health check results
- Endpoint switching decisions
- Error tracking with context

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

## Future Enhancements

### Planned Features
- Service mesh integration with Linkerd
- Advanced traffic shaping policies
- Multi-cluster service discovery
- Service dependency mapping
- Automated canary deployments

### Integration Roadmap
- HashiCorp Vault integration for secrets
- Prometheus metrics collection
- Grafana dashboard creation
- Alert manager configuration
- Jaeger distributed tracing

This service discovery architecture provides a robust, scalable foundation for microservices communication across diverse deployment environments while maintaining high availability and observability.