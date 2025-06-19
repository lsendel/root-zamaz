# Kubernetes Deployment with Zero Trust Authentication

This example demonstrates how to deploy the Zero Trust Authentication system on Kubernetes with proper RBAC, secrets management, observability, and scalability configurations.

## Features

- ✅ Complete Kubernetes deployment manifests
- ✅ RBAC and security policies
- ✅ Secret and ConfigMap management
- ✅ Service mesh integration (Istio)
- ✅ Horizontal Pod Autoscaling
- ✅ Ingress and Load Balancing
- ✅ Monitoring and Observability
- ✅ Database and Redis setup
- ✅ SPIRE workload identity

## Prerequisites

- Kubernetes cluster (1.25+)
- kubectl configured
- Helm 3.x
- Istio (optional, for service mesh)
- Prometheus & Grafana (for monitoring)

## Quick Start

```bash
# Clone and navigate to the example
git clone https://github.com/mvp/zerotrust-auth.git
cd zerotrust-auth/docs/examples/infrastructure/kubernetes

# Create namespace
kubectl create namespace zerotrust

# Apply configurations
kubectl apply -f namespace.yaml
kubectl apply -f secrets/
kubectl apply -f configs/
kubectl apply -f deployments/
kubectl apply -f services/
kubectl apply -f ingress/

# Verify deployment
kubectl get pods -n zerotrust
kubectl get services -n zerotrust
```

## Project Structure

```
kubernetes/
├── namespace.yaml
├── secrets/
│   ├── auth-secrets.yaml
│   ├── database-secrets.yaml
│   └── redis-secrets.yaml
├── configs/
│   ├── auth-config.yaml
│   ├── database-config.yaml
│   └── observability-config.yaml
├── deployments/
│   ├── auth-service.yaml
│   ├── database.yaml
│   ├── redis.yaml
│   └── frontend.yaml
├── services/
│   ├── auth-service.yaml
│   ├── database-service.yaml
│   └── redis-service.yaml
├── ingress/
│   ├── auth-ingress.yaml
│   └── app-ingress.yaml
├── rbac/
│   ├── service-accounts.yaml
│   ├── roles.yaml
│   └── role-bindings.yaml
├── monitoring/
│   ├── servicemonitor.yaml
│   ├── prometheusrule.yaml
│   └── grafana-dashboard.yaml
├── autoscaling/
│   └── hpa.yaml
├── istio/
│   ├── virtual-service.yaml
│   ├── destination-rule.yaml
│   └── gateway.yaml
├── spire/
│   ├── spire-server.yaml
│   ├── spire-agent.yaml
│   └── registration.yaml
└── helm/
    ├── Chart.yaml
    ├── values.yaml
    └── templates/
```

## Core Manifests

### Namespace

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: zerotrust
  labels:
    name: zerotrust
    istio-injection: enabled
    app.kubernetes.io/name: zerotrust
    app.kubernetes.io/version: "1.0.0"
---
apiVersion: v1
kind: LimitRange
metadata:
  name: zerotrust-limits
  namespace: zerotrust
spec:
  limits:
  - default:
      cpu: "500m"
      memory: "512Mi"
    defaultRequest:
      cpu: "100m"
      memory: "128Mi"
    type: Container
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: zerotrust-quota
  namespace: zerotrust
spec:
  hard:
    requests.cpu: "4"
    requests.memory: 8Gi
    limits.cpu: "8"
    limits.memory: 16Gi
    persistentvolumeclaims: "10"
    pods: "20"
    services: "10"
```

### Authentication Service Deployment

```yaml
# deployments/auth-service.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
  namespace: zerotrust
  labels:
    app: auth-service
    version: v1
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
      version: v1
  template:
    metadata:
      labels:
        app: auth-service
        version: v1
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: auth-service
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        fsGroup: 65534
      containers:
      - name: auth-service
        image: zerotrust/auth-service:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 8080
          name: http
          protocol: TCP
        - containerPort: 8443
          name: https
          protocol: TCP
        - containerPort: 9090
          name: metrics
          protocol: TCP
        env:
        - name: PORT
          value: "8080"
        - name: DB_HOST
          valueFrom:
            secretKeyRef:
              name: database-secrets
              key: host
        - name: DB_USER
          valueFrom:
            secretKeyRef:
              name: database-secrets
              key: username
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: database-secrets
              key: password
        - name: DB_NAME
          valueFrom:
            secretKeyRef:
              name: database-secrets
              key: database
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: redis-secrets
              key: url
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: jwt-secret
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: api-key
        envFrom:
        - configMapRef:
            name: auth-config
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        resources:
          requests:
            cpu: 200m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 512Mi
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
          readOnlyRootFilesystem: true
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: certs
          mountPath: /app/certs
          readOnly: true
      volumes:
      - name: tmp
        emptyDir: {}
      - name: certs
        secret:
          secretName: auth-tls-certs
      nodeSelector:
        kubernetes.io/os: linux
      tolerations:
      - key: "node-role.kubernetes.io/control-plane"
        operator: "Exists"
        effect: "NoSchedule"
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - auth-service
              topologyKey: kubernetes.io/hostname
```

### Service Configuration

```yaml
# services/auth-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: auth-service
  namespace: zerotrust
  labels:
    app: auth-service
    service: auth-service
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: nlb
    service.beta.kubernetes.io/aws-load-balancer-backend-protocol: tcp
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
    name: http
  - port: 443
    targetPort: 8443
    protocol: TCP
    name: https
  - port: 9090
    targetPort: 9090
    protocol: TCP
    name: metrics
  selector:
    app: auth-service
---
apiVersion: v1
kind: Service
metadata:
  name: auth-service-headless
  namespace: zerotrust
  labels:
    app: auth-service
spec:
  type: ClusterIP
  clusterIP: None
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
    name: http
  selector:
    app: auth-service
```

### ConfigMap

```yaml
# configs/auth-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-config
  namespace: zerotrust
data:
  LOG_LEVEL: "info"
  ENABLE_CORS: "true"
  CORS_ORIGINS: "https://app.example.com,https://admin.example.com"
  TOKEN_EXPIRY: "3600"
  REFRESH_TOKEN_EXPIRY: "604800"
  MFA_ENABLED: "true"
  RATE_LIMIT_ENABLED: "true"
  RATE_LIMIT_REQUESTS: "100"
  RATE_LIMIT_WINDOW: "60"
  OBSERVABILITY_ENABLED: "true"
  TRACING_ENABLED: "true"
  METRICS_ENABLED: "true"
  JAEGER_ENDPOINT: "http://jaeger-collector:14268/api/traces"
  PROMETHEUS_ENDPOINT: "http://prometheus:9090"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: database-config
  namespace: zerotrust
data:
  DB_MAX_CONNECTIONS: "20"
  DB_MAX_IDLE_CONNECTIONS: "5"
  DB_CONNECTION_MAX_LIFETIME: "300s"
  DB_SSL_MODE: "require"
  DB_TIMEZONE: "UTC"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: observability-config
  namespace: zerotrust
data:
  otel-config.yaml: |
    receivers:
      otlp:
        protocols:
          grpc:
            endpoint: 0.0.0.0:4317
          http:
            endpoint: 0.0.0.0:4318
    
    processors:
      batch:
        timeout: 1s
        send_batch_size: 1024
      memory_limiter:
        limit_mib: 512
    
    exporters:
      jaeger:
        endpoint: jaeger-collector:14250
        tls:
          insecure: true
      prometheus:
        endpoint: "0.0.0.0:8889"
    
    service:
      pipelines:
        traces:
          receivers: [otlp]
          processors: [memory_limiter, batch]
          exporters: [jaeger]
        metrics:
          receivers: [otlp]
          processors: [memory_limiter, batch]
          exporters: [prometheus]
```

### Secrets

```yaml
# secrets/auth-secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-secrets
  namespace: zerotrust
type: Opaque
data:
  jwt-secret: <base64-encoded-jwt-secret>
  api-key: <base64-encoded-api-key>
  encryption-key: <base64-encoded-encryption-key>
---
apiVersion: v1
kind: Secret
metadata:
  name: database-secrets
  namespace: zerotrust
type: Opaque
data:
  host: <base64-encoded-db-host>
  username: <base64-encoded-db-username>
  password: <base64-encoded-db-password>
  database: <base64-encoded-db-name>
---
apiVersion: v1
kind: Secret
metadata:
  name: redis-secrets
  namespace: zerotrust
type: Opaque
data:
  url: <base64-encoded-redis-url>
  password: <base64-encoded-redis-password>
```

### RBAC Configuration

```yaml
# rbac/service-accounts.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: auth-service
  namespace: zerotrust
  labels:
    app: auth-service
automountServiceAccountToken: true
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: zerotrust
  name: auth-service-role
rules:
- apiGroups: [""]
  resources: ["secrets", "configmaps"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: auth-service-binding
  namespace: zerotrust
subjects:
- kind: ServiceAccount
  name: auth-service
  namespace: zerotrust
roleRef:
  kind: Role
  name: auth-service-role
  apiGroup: rbac.authorization.k8s.io
```

### Ingress

```yaml
# ingress/auth-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auth-ingress
  namespace: zerotrust
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - auth.example.com
    secretName: auth-tls-cert
  rules:
  - host: auth.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: auth-service
            port:
              number: 80
```

### Horizontal Pod Autoscaler

```yaml
# autoscaling/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: auth-service-hpa
  namespace: zerotrust
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: auth-service
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
      - type: Pods
        value: 4
        periodSeconds: 15
      selectPolicy: Max
```

### Monitoring

```yaml
# monitoring/servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: auth-service-monitor
  namespace: zerotrust
  labels:
    app: auth-service
spec:
  selector:
    matchLabels:
      app: auth-service
  endpoints:
  - port: metrics
    path: /metrics
    interval: 30s
    scrapeTimeout: 10s
---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: auth-service-alerts
  namespace: zerotrust
  labels:
    app: auth-service
spec:
  groups:
  - name: auth-service
    rules:
    - alert: AuthServiceDown
      expr: up{job="auth-service"} == 0
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "Auth service is down"
        description: "Auth service has been down for more than 1 minute"
    
    - alert: AuthServiceHighErrorRate
      expr: rate(http_requests_total{job="auth-service",code=~"5.."}[5m]) > 0.1
      for: 2m
      labels:
        severity: warning
      annotations:
        summary: "High error rate in auth service"
        description: "Error rate is {{ $value }} errors per second"
    
    - alert: AuthServiceHighLatency
      expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job="auth-service"}[5m])) > 0.5
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High latency in auth service"
        description: "95th percentile latency is {{ $value }} seconds"
```

### Istio Service Mesh

```yaml
# istio/gateway.yaml
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: auth-gateway
  namespace: zerotrust
spec:
  selector:
    istio: ingressgateway
  servers:
  - port:
      number: 443
      name: https
      protocol: HTTPS
    tls:
      mode: SIMPLE
      credentialName: auth-tls-cert
    hosts:
    - auth.example.com
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - auth.example.com
    tls:
      httpsRedirect: true
---
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: auth-virtual-service
  namespace: zerotrust
spec:
  hosts:
  - auth.example.com
  gateways:
  - auth-gateway
  http:
  - match:
    - uri:
        prefix: /api/v1/health
    route:
    - destination:
        host: auth-service
        port:
          number: 80
    timeout: 5s
  - match:
    - uri:
        prefix: /api/v1/auth
    route:
    - destination:
        host: auth-service
        port:
          number: 80
    timeout: 30s
    retries:
      attempts: 3
      perTryTimeout: 10s
  - match:
    - uri:
        prefix: /
    route:
    - destination:
        host: auth-service
        port:
          number: 80
    timeout: 30s
---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: auth-destination-rule
  namespace: zerotrust
spec:
  host: auth-service
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 100
      http:
        http1MaxPendingRequests: 50
        maxRequestsPerConnection: 10
    loadBalancer:
      simple: LEAST_CONN
    outlierDetection:
      consecutiveErrors: 3
      interval: 30s
      baseEjectionTime: 30s
      maxEjectionPercent: 50
```

### SPIRE Integration

```yaml
# spire/spire-server.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: spire-server
  namespace: zerotrust
  labels:
    app: spire-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: spire-server
  template:
    metadata:
      labels:
        app: spire-server
    spec:
      serviceAccountName: spire-server
      containers:
      - name: spire-server
        image: ghcr.io/spiffe/spire-server:1.8.0
        args:
        - -config
        - /run/spire/config/server.conf
        ports:
        - containerPort: 8081
          name: grpc
        volumeMounts:
        - name: spire-config
          mountPath: /run/spire/config
          readOnly: true
        - name: spire-data
          mountPath: /run/spire/data
        livenessProbe:
          httpGet:
            path: /live
            port: 8080
          failureThreshold: 2
          initialDelaySeconds: 15
          periodSeconds: 60
          timeoutSeconds: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: spire-config
        configMap:
          name: spire-server
      - name: spire-data
        persistentVolumeClaim:
          claimName: spire-data
```

## Deployment Commands

### Initial Setup

```bash
# Create namespace and RBAC
kubectl apply -f namespace.yaml
kubectl apply -f rbac/

# Create secrets (update with your values first)
kubectl apply -f secrets/

# Create configurations
kubectl apply -f configs/

# Deploy services
kubectl apply -f deployments/
kubectl apply -f services/

# Setup ingress
kubectl apply -f ingress/

# Setup monitoring
kubectl apply -f monitoring/

# Setup autoscaling
kubectl apply -f autoscaling/
```

### Istio Setup (Optional)

```bash
# Install Istio
istioctl install --set values.defaultRevision=default

# Enable injection
kubectl label namespace zerotrust istio-injection=enabled

# Apply Istio configurations
kubectl apply -f istio/
```

### SPIRE Setup (Optional)

```bash
# Deploy SPIRE
kubectl apply -f spire/

# Register workloads
kubectl exec -n zerotrust spire-server-0 -- \
  spire-server entry create \
  -spiffeID spiffe://example.org/auth-service \
  -parentID spiffe://example.org/node \
  -selector k8s:ns:zerotrust \
  -selector k8s:sa:auth-service
```

## Helm Chart

### values.yaml

```yaml
# helm/values.yaml
global:
  imageRegistry: ""
  imagePullSecrets: []

replicaCount: 3

image:
  repository: zerotrust/auth-service
  tag: latest
  pullPolicy: Always

service:
  type: ClusterIP
  port: 80
  targetPort: 8080

ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
  - host: auth.example.com
    paths:
    - path: /
      pathType: Prefix
  tls:
  - secretName: auth-tls-cert
    hosts:
    - auth.example.com

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 200m
    memory: 256Mi

nodeSelector: {}
tolerations: []
affinity: {}

config:
  logLevel: "info"
  enableCors: true
  corsOrigins: "https://app.example.com"
  tokenExpiry: 3600
  mfaEnabled: true

secrets:
  jwtSecret: ""
  apiKey: ""
  encryptionKey: ""

database:
  host: ""
  username: ""
  password: ""
  database: ""

redis:
  url: ""
  password: ""

monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
  prometheusRule:
    enabled: true

istio:
  enabled: false
  gateway:
    enabled: true
  virtualService:
    enabled: true
  destinationRule:
    enabled: true

spire:
  enabled: false
```

### Installation

```bash
# Install with Helm
helm upgrade --install zerotrust ./helm \
  --namespace zerotrust \
  --create-namespace \
  --set config.corsOrigins="https://app.example.com" \
  --set secrets.jwtSecret="your-jwt-secret" \
  --set secrets.apiKey="your-api-key" \
  --set database.host="postgres.example.com" \
  --set database.username="zerotrust" \
  --set database.password="secure-password" \
  --set database.database="zerotrust_db"
```

## Operations

### Scaling

```bash
# Manual scaling
kubectl scale deployment auth-service --replicas=5 -n zerotrust

# Check autoscaler status
kubectl describe hpa auth-service-hpa -n zerotrust
```

### Rolling Updates

```bash
# Update image
kubectl set image deployment/auth-service auth-service=zerotrust/auth-service:v2.0.0 -n zerotrust

# Check rollout status
kubectl rollout status deployment/auth-service -n zerotrust

# Rollback if needed
kubectl rollout undo deployment/auth-service -n zerotrust
```

### Monitoring

```bash
# Check pod logs
kubectl logs -f deployment/auth-service -n zerotrust

# Check metrics
kubectl port-forward service/auth-service 9090:9090 -n zerotrust
curl http://localhost:9090/metrics

# Check health
kubectl port-forward service/auth-service 8080:80 -n zerotrust
curl http://localhost:8080/health
```

### Troubleshooting

```bash
# Check pod status
kubectl get pods -n zerotrust -o wide

# Describe problematic pod
kubectl describe pod <pod-name> -n zerotrust

# Check events
kubectl get events -n zerotrust --sort-by='.lastTimestamp'

# Check logs
kubectl logs <pod-name> -n zerotrust --previous

# Debug with temporary pod
kubectl run debug --image=nicolaka/netshoot -it --rm -n zerotrust
```

## Security Best Practices

1. **Pod Security**
   - Run as non-root user
   - Use read-only root filesystem
   - Drop all capabilities
   - Use security contexts

2. **Network Security**
   - Implement network policies
   - Use TLS for all communications
   - Restrict ingress/egress traffic

3. **Secrets Management**
   - Use external secret managers
   - Rotate secrets regularly
   - Encrypt secrets at rest

4. **RBAC**
   - Follow principle of least privilege
   - Use service accounts
   - Regular access reviews

For more examples and advanced patterns, see the [examples directory](../) and [main documentation](../../README.md).