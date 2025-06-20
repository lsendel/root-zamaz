# Istio Service Mesh Architecture

This document describes the Istio service mesh implementation for the MVP Zero Trust Auth system, providing secure service-to-service communication, traffic management, and comprehensive observability.

## Overview

The Istio service mesh provides a dedicated infrastructure layer for managing service-to-service communication, implementing zero trust security principles, and enabling advanced traffic management capabilities.

### Key Features

- **Zero Trust Security** - mTLS encryption for all service communication
- **Traffic Management** - Advanced routing, load balancing, and fault injection
- **Observability** - Distributed tracing, metrics collection, and access logging
- **Service Discovery** - Integration with Kubernetes and Consul service registries
- **Policy Enforcement** - Fine-grained authorization and rate limiting

## Architecture Components

### Control Plane (Istiod)

**Configuration:**
- **Replicas**: 2 (High Availability)
- **Resources**: 100m CPU / 128Mi Memory (requests), 500m CPU / 512Mi Memory (limits)
- **Auto-scaling**: HPA with 2-5 replicas based on CPU utilization

**Features:**
- Service discovery integration
- Certificate management via SPIRE
- Configuration distribution
- Workload registration

### Data Plane (Envoy Sidecars)

**Sidecar Configuration:**
- **Automatic injection** enabled for `zamaz` namespace
- **Resource allocation**: 10m CPU / 40Mi Memory (requests), 100m CPU / 128Mi Memory (limits)
- **Hold application start** until proxy is ready
- **Custom logging level**: Warning (production) / Debug (development)

### Gateways

#### Ingress Gateway
- **External traffic entry point** for web applications
- **TLS termination** with automatic certificate management
- **Load balancing** across multiple replicas (2-5 instances)
- **Multi-protocol support**: HTTP/HTTPS/TLS passthrough

#### Egress Gateway
- **Controlled external service access**
- **Security policy enforcement** for outbound traffic
- **External service registration** and monitoring

## Security Implementation

### Mutual TLS (mTLS)

**Configuration:**
```yaml
# Strict mTLS for all mesh traffic
spec:
  mtls:
    mode: STRICT
```

**Features:**
- **Automatic certificate rotation** via SPIRE integration
- **Trust domain**: `zamaz.cluster.local`
- **Certificate lifetime**: 1 hour with automatic renewal
- **Cross-cluster communication** support

### Authorization Policies

**Zero Trust Model:**
1. **Deny-all default policy** - No traffic allowed by default
2. **Explicit allow policies** - Granular permissions for specific routes
3. **Role-based access control** - JWT claims-based authorization
4. **Service-to-service policies** - Identity-based communication rules

**Policy Examples:**
```yaml
# Frontend to API communication
- from:
  - source:
      principals: ["cluster.local/ns/zamaz/sa/zamaz-frontend-sa"]
  to:
  - operation:
      methods: ["GET", "POST", "PUT", "DELETE"]
      paths: ["/api/*"]
```

### Request Authentication

**JWT Validation:**
- **Issuer**: `https://auth.zamaz.cluster.local`
- **JWKS endpoint**: Automatic key rotation support
- **Claims mapping**: Role-based authorization
- **Multiple providers**: Development and production issuers

## Traffic Management

### Virtual Services

**Frontend Routing:**
- **Health checks**: Direct routing with no retries
- **Static assets**: Long-term caching headers
- **API routes**: Retry policies and timeout configuration
- **Canary deployments**: Header and percentage-based routing

**API Routing:**
- **Authentication endpoints**: No retry to prevent lockouts
- **Admin APIs**: Extended timeouts and rate limiting
- **User APIs**: Standard retry and circuit breaker policies

### Destination Rules

**Load Balancing:**
- **API services**: `LEAST_CONN` for optimal distribution
- **Frontend services**: `ROUND_ROBIN` for simplicity
- **External services**: Custom connection pooling

**Circuit Breaker Configuration:**
```yaml
outlierDetection:
  consecutiveGatewayErrors: 5
  consecutive5xxErrors: 5
  interval: 30s
  baseEjectionTime: 30s
  maxEjectionPercent: 50
```

**Connection Pooling:**
- **TCP connections**: Max 100 per service
- **HTTP requests**: Max 50 pending, 100 concurrent
- **Keep-alive**: 7200s with 75s intervals

### Service Entries

**External Service Integration:**
- **Database services**: PostgreSQL and Redis external endpoints
- **API dependencies**: GitHub, Docker Registry, Google APIs
- **Observability**: Jaeger, Prometheus external services
- **Infrastructure**: DNS, NTP, Certificate authorities

## Observability

### Distributed Tracing

**Jaeger Integration:**
- **Sampling rate**: 1% (production), 10% (development)
- **Custom tags**: User ID, tenant ID, correlation ID
- **Span enrichment**: Request/response headers and metadata
- **Performance tracking**: End-to-end request flow

### Metrics Collection

**Prometheus Metrics:**
- **Request metrics**: Rate, latency, error rate
- **Service metrics**: Connection pools, circuit breaker status
- **Business metrics**: Authentication events, user actions
- **Custom labels**: Source/destination apps, API versions

**Key Metrics:**
```
istio_requests_total{source_app="frontend",destination_app="api"}
istio_request_duration_milliseconds_bucket{percentile="p99"}
istio_tcp_connections_opened_total
```

### Access Logging

**Structured JSON Format:**
```json
{
  "timestamp": "%START_TIME%",
  "method": "%REQ(:METHOD)%",
  "path": "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%",
  "response_code": "%RESPONSE_CODE%",
  "duration": "%DURATION%",
  "user_id": "%REQ(X-USER-ID)%",
  "correlation_id": "%REQ(X-CORRELATION-ID)%"
}
```

## Advanced Features

### EnvoyFilters

**Security Headers:**
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security: max-age=31536000`
- `X-XSS-Protection: 1; mode=block`

**Rate Limiting:**
- **Local rate limiting**: 100 requests per minute per IP
- **Token bucket algorithm**: Burst capability with sustained rate
- **Custom headers**: Rate limit status in responses

**CORS Configuration:**
- **Allowed origins**: Production and development domains
- **Methods**: GET, POST, PUT, DELETE, OPTIONS
- **Headers**: Authentication and custom business headers
- **Credentials**: Supported for authenticated requests

### Custom Telemetry

**Business Metrics:**
- **Authentication success/failure rates**
- **API endpoint usage patterns**
- **Error categorization**: Client vs server errors
- **Performance buckets**: Fast, medium, slow, very slow

**Custom Tags:**
```yaml
endpoint_type:
  value: |
    has(request.url_path) && (request.url_path | startsWith("/api/auth/")) ? "auth" :
    has(request.url_path) && (request.url_path | startsWith("/api/admin/")) ? "admin" :
    "user"
```

## Deployment Patterns

### Development Environment

**Configuration:**
- **Higher sampling**: 10% tracing for debugging
- **Permissive policies**: Easier development workflow
- **Local certificates**: Self-signed for testing
- **Debug logging**: Detailed request/response logs

**Setup Commands:**
```bash
# Install Istio with development profile
make istio-setup

# Generate development certificates
./scripts/istio-setup.sh certs

# Access dashboards
make istio-dashboards
```

### Production Environment

**High Availability:**
- **Multi-replica control plane**: 3+ Istiod instances
- **Gateway redundancy**: Multiple ingress/egress gateways
- **Cross-zone distribution**: Topology spread constraints
- **Automatic failover**: Health-based traffic routing

**Security Hardening:**
- **Strict mTLS**: No plaintext communication
- **Certificate rotation**: 1-hour certificate lifetime
- **Policy enforcement**: Deny-all default with explicit allows
- **Audit logging**: Complete request audit trail

### Canary Deployments

**Traffic Splitting:**
```yaml
# 95% stable, 5% canary
route:
- destination:
    host: zamaz-api-service
    subset: stable
  weight: 95
- destination:
    host: zamaz-api-service
    subset: canary
  weight: 5
```

**Header-based Routing:**
```yaml
# Route based on canary header
match:
- headers:
    canary:
      exact: "true"
route:
- destination:
    host: zamaz-api-service
    subset: canary
```

## Integration with External Systems

### SPIRE Integration

**Workload Identity:**
- **SPIFFE IDs**: Unique identity for each workload
- **X.509-SVID**: Short-lived certificates (1 hour)
- **Automatic rotation**: Seamless certificate renewal
- **Cross-cluster trust**: Federated identity across environments

### Consul Service Registry

**Hybrid Discovery:**
- **Kubernetes-native**: Internal service discovery
- **Consul integration**: External service registration
- **Multi-registry**: Consul + Kubernetes dual discovery
- **Health check sync**: Status propagation between systems

### Monitoring Stack

**Prometheus Integration:**
- **Service discovery**: Automatic endpoint discovery
- **Custom metrics**: Business and technical metrics
- **Alerting rules**: SLA/SLO monitoring
- **Dashboard integration**: Grafana visualization

**Jaeger Tracing:**
- **Distributed tracing**: End-to-end request flow
- **Performance analysis**: Latency breakdown
- **Dependency mapping**: Service interaction visualization
- **Error tracking**: Failure analysis and debugging

## Operations and Troubleshooting

### Common Commands

```bash
# Check mesh status
istioctl proxy-status

# Validate configuration
istioctl analyze --all-namespaces

# View proxy configuration
istioctl proxy-config cluster <pod-name>

# Debug networking
istioctl proxy-config listeners <pod-name>

# Certificate verification
istioctl proxy-config secret <pod-name>
```

### Performance Tuning

**Resource Optimization:**
- **Sidecar resources**: Right-sizing based on traffic
- **Control plane scaling**: CPU/memory optimization
- **Connection pooling**: Service-specific limits
- **Circuit breaker tuning**: Failure threshold adjustment

**Traffic Optimization:**
- **Keep-alive settings**: Persistent connection reuse
- **Compression**: Response compression for large payloads
- **Caching headers**: Static asset optimization
- **Retry policies**: Intelligent failure handling

### Troubleshooting Guide

**Common Issues:**

1. **mTLS Configuration**:
   - Verify PeerAuthentication policies
   - Check certificate validity
   - Validate trust domain configuration

2. **Traffic Routing**:
   - Analyze VirtualService rules
   - Check DestinationRule subsets
   - Verify service label selectors

3. **Authorization Failures**:
   - Review AuthorizationPolicy rules
   - Check JWT token validity
   - Validate service account permissions

4. **Performance Issues**:
   - Monitor connection pool metrics
   - Check circuit breaker status
   - Analyze request latency patterns

This Istio service mesh implementation provides a comprehensive, secure, and observable platform for the MVP Zero Trust Auth system, enabling advanced traffic management while maintaining strong security posture and operational visibility.