# Service Discovery Architecture

This document outlines the service discovery implementation for the MVP Zero Trust Auth system, providing both Consul and Kubernetes-native discovery patterns.

## Overview

The service discovery system is designed with a pluggable architecture that supports multiple backends:

- **Consul** - HashiCorp Consul for hybrid/multi-cloud deployments
- **Kubernetes** - Native K8s service discovery for cloud-native environments  
- **Memory** - In-memory registry for testing and development

## Architecture Components

### Core Interfaces

```go
// ServiceRegistry - Main discovery interface
type ServiceRegistry interface {
    Register(ctx context.Context, service *Service) error
    Deregister(ctx context.Context, serviceID string) error
    Discover(ctx context.Context, serviceName string) ([]*Service, error)
    Watch(ctx context.Context, serviceName string) (<-chan ServiceEvent, error)
    Health() error
    Close() error
}

// Service - Represents a discoverable service
type Service struct {
    ID          string
    Name        string
    Address     string
    Port        int
    Tags        []string
    Meta        map[string]string
    Health      HealthStatus
    Environment string
    Version     string
    Namespace   string
}
```

### Load Balancing Strategies

The system implements multiple load balancing algorithms:

- **Round Robin** - Even distribution across healthy instances
- **Weighted Round Robin** - Distribution based on instance weights
- **Random** - Random selection for simple load distribution
- **Consistent Hash** - Session affinity using client attributes
- **IP Hash** - Client IP-based routing for sticky sessions
- **Least Connections** - Route to instance with fewest active connections

## Implementation Details

### Consul Integration

**Features:**
- Service registration with health checks
- KV store for configuration management
- Service mesh integration via Consul Connect
- Multi-datacenter support
- Advanced health monitoring

**Configuration:**
```yaml
consul:
  address: "localhost:8500"
  datacenter: "dc1"
  health_check:
    interval: "10s"
    timeout: "3s"
    deregister_after: "60s"
```

**Health Checks:**
- HTTP endpoints (`/health`)
- TCP connectivity checks
- Custom script execution
- TTL-based checks

### Kubernetes Integration

**Features:**
- Native service discovery via K8s API
- Label selector-based service filtering
- Endpoint health monitoring
- Namespace isolation
- Automatic service registration

**Service Definition:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: zamaz-api-service
  namespace: zamaz
  labels:
    app.kubernetes.io/name: zamaz
    app.kubernetes.io/component: api
spec:
  type: ClusterIP
  ports:
  - name: http
    port: 8080
    targetPort: http
  selector:
    app.kubernetes.io/name: zamaz
    app.kubernetes.io/component: api
```

## Usage Examples

### Basic Service Registration

```go
// Initialize registry
registry, err := discovery.CreateFromEnvironment(logger)
if err != nil {
    log.Fatal(err)
}

// Register service
service := discovery.NewService("api-1", "zamaz-api", "127.0.0.1", 8080)
service.AddTag("environment=development")
service.AddMeta("version", "1.0.0")

err = registry.Register(ctx, service)
if err != nil {
    log.Fatal(err)
}
```

### Service Discovery

```go
// Discover services
services, err := registry.Discover(ctx, "zamaz-api")
if err != nil {
    log.Fatal(err)
}

// Load balance across instances
lb := loadbalancer.NewRoundRobinBalancer()
selected, err := lb.Select(services, &loadbalancer.Request{
    ClientIP: "192.168.1.100",
    Method:   "GET",
    Path:     "/api/users",
})
```

### Service Watching

```go
// Watch for service changes
eventChan, err := registry.Watch(ctx, "zamaz-api")
if err != nil {
    log.Fatal(err)
}

for event := range eventChan {
    switch event.Type {
    case discovery.EventServiceRegistered:
        log.Info("New service instance:", event.Service.ID)
    case discovery.EventServiceDeregistered:
        log.Info("Service instance removed:", event.Service.ID)
    case discovery.EventServiceHealthChange:
        log.Info("Health changed:", event.Service.ID, event.Service.Health)
    }
}
```

## Configuration

### Environment Variables

```bash
# Service Registry Provider
SERVICE_REGISTRY_PROVIDER=consul  # consul, kubernetes, memory

# Consul Configuration
CONSUL_ADDRESS=localhost:8500
CONSUL_DATACENTER=dc1
CONSUL_TOKEN=
CONSUL_NAMESPACE=

# Kubernetes Configuration  
K8S_IN_CLUSTER=true
K8S_NAMESPACE=zamaz
K8S_LABEL_SELECTOR=app.kubernetes.io/part-of=zamaz-platform

# Load Balancer Configuration
LB_STRATEGY=round_robin
LB_HEALTHY_ONLY=true
LB_MAX_RETRIES=3
LB_CIRCUIT_BREAKER=true
```

### Feature Flags

The system supports feature flags stored in Consul KV:

```bash
# Enable/disable features
mvp-zero-trust-auth/features/consul-discovery=true
mvp-zero-trust-auth/features/load-balancing=true
mvp-zero-trust-auth/features/circuit-breaker=true
mvp-zero-trust-auth/features/health-monitoring=true
```

## Deployment Patterns

### Development Setup

1. **Start Consul:**
   ```bash
   make consul-start
   ```

2. **Configure Services:**
   ```bash
   make consul-setup
   ```

3. **Verify Registration:**
   ```bash
   make consul-services
   ```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zamaz-api
spec:
  template:
    metadata:
      labels:
        app.kubernetes.io/name: zamaz
        app.kubernetes.io/component: api
    spec:
      containers:
      - name: api
        image: zamaz/api:latest
        env:
        - name: SERVICE_REGISTRY_PROVIDER
          value: "kubernetes"
        - name: K8S_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
```

### Multi-Registry Setup

```go
// Create multi-registry for hybrid environments
multiRegistry := discovery.NewMultiRegistry(logger)

// Add Consul for external services
consulRegistry, _ := discovery.NewConsulRegistry(consulConfig, logger)
multiRegistry.AddRegistry("consul", consulRegistry)

// Add Kubernetes for internal services
k8sRegistry, _ := discovery.NewKubernetesRegistry(k8sConfig, logger)
multiRegistry.AddRegistry("kubernetes", k8sRegistry)
multiRegistry.SetPrimary("kubernetes")
```

## Monitoring and Observability

### Health Checks

The system provides comprehensive health monitoring:

- **Service Health** - Individual service instance health
- **Registry Health** - Backend registry connectivity
- **Load Balancer Stats** - Distribution metrics and failure rates

### Metrics

Key metrics exposed via Prometheus:

```
# Service discovery metrics
service_registry_services_total{registry="consul",namespace="zamaz"}
service_registry_health_checks_total{status="passing"}
service_registry_discovery_duration_seconds

# Load balancer metrics  
load_balancer_requests_total{strategy="round_robin",backend="api-1"}
load_balancer_failures_total{strategy="round_robin",error="connection_refused"}
load_balancer_selection_duration_seconds
```

### Alerting

Recommended alerts:

- Service registration failures
- Health check failures exceeding threshold
- Load balancer backend unavailability
- Registry connectivity issues

## Security Considerations

### Service Authentication

- **Consul** - ACL tokens for API access
- **Kubernetes** - RBAC for service account permissions
- **mTLS** - Mutual TLS for service-to-service communication

### Network Security

- **Service Mesh** - Istio integration for traffic encryption
- **Network Policies** - K8s network policies for traffic isolation
- **Firewall Rules** - Consul agent communication security

## Best Practices

1. **Health Check Design**
   - Use lightweight health checks
   - Include dependency health in checks
   - Set appropriate timeouts and intervals

2. **Service Naming**
   - Use consistent naming conventions
   - Include environment and version tags
   - Namespace services appropriately

3. **Load Balancing**
   - Choose appropriate strategy for workload
   - Monitor backend health and performance
   - Implement circuit breakers for resilience

4. **Configuration Management**
   - Use feature flags for gradual rollouts
   - Store configuration in centralized KV store
   - Version configuration changes

## Troubleshooting

### Common Issues

**Service Not Discovered:**
- Check service registration status
- Verify health check configuration
- Validate label selectors (Kubernetes)

**Load Balancer Failures:**
- Monitor backend health status
- Check connection limits and timeouts
- Review circuit breaker settings

**Registry Connectivity:**
- Verify network connectivity to registry
- Check authentication/authorization
- Review TLS configuration

### Debugging Commands

```bash
# Check Consul services
make consul-services

# Verify Consul health
curl http://localhost:8500/v1/status/leader

# Check Kubernetes services
kubectl get services -n zamaz

# View service endpoints
kubectl get endpoints -n zamaz
```

This service discovery implementation provides a robust, scalable foundation for microservice communication in the MVP Zero Trust Auth system, supporting both cloud-native and hybrid deployment patterns.