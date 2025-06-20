# Claude Notes: Deployment & Infrastructure Architecture

> **Context**: Kubernetes deployments and infrastructure patterns  
> **Last Updated**: 2025-06-20  
> **Focus**: GitOps-driven Zero Trust infrastructure deployment

## 🚀 **Deployment Architecture Overview**

### **Infrastructure Philosophy**
- **GitOps-First**: All infrastructure changes through Git workflows
- **Zero Trust Network**: Service mesh with mutual TLS everywhere
- **Infrastructure as Code**: Declarative configuration management
- **Environment Parity**: Consistent deployment patterns across environments
- **Security by Default**: Pod security standards and network policies

### **Technology Stack**
- **Orchestration**: Kubernetes 1.28+ with containerd runtime
- **GitOps**: ArgoCD for continuous deployment automation
- **Service Mesh**: Istio for traffic management and security
- **Identity**: SPIRE/SPIFFE for workload identity management
- **Secrets**: External Secrets Operator with HashiCorp Vault
- **Monitoring**: Prometheus, Grafana, Jaeger, Loki stack

## 📁 **Directory Structure**

### **Deployment Organization**
```
deployments/
├── base/                  # Kustomize base configurations
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── configmap.yaml
│   └── secrets.yaml
├── overlays/             # Environment-specific overlays
│   ├── development/
│   ├── staging/
│   └── production/
├── istio/               # Service mesh configurations
│   ├── gateway.yaml
│   ├── virtual-service.yaml
│   ├── destination-rule.yaml
│   └── peer-authentication.yaml
├── security/            # Security policies
│   ├── network-policies.yaml
│   ├── pod-security-policy.yaml
│   └── rbac.yaml
└── monitoring/          # Observability stack
    ├── service-monitor.yaml
    ├── prometheus-rule.yaml
    └── grafana-dashboard.yaml
```

## 🛡️ **Security Architecture**

### **Zero Trust Implementation**
```yaml
# Network Policy - Deny All by Default
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
  namespace: zamaz-auth
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress

---
# Allow Specific Communication
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-auth-service
  namespace: zamaz-auth
spec:
  podSelector:
    matchLabels:
      app: auth-service
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: istio-system
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: postgres
    ports:
    - protocol: TCP
      port: 5432
```

### **Pod Security Standards**
```yaml
# Pod Security Policy
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: zamaz-auth-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  runAsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1000
        max: 65535
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
  readOnlyRootFilesystem: true
  allowedHostPaths: []
```

### **SPIRE Integration**
```yaml
# SPIRE Server Configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: spire-server-config
  namespace: spire-system
data:
  server.conf: |
    server {
      bind_address = "0.0.0.0"
      bind_port = "8081"
      socket_path = "/tmp/spire-server/private/api.sock"
      trust_domain = "zamaz.dev"
      data_dir = "/opt/spire/data"
      log_level = "INFO"
      ca_subject = {
        country = ["US"],
        organization = ["Zamaz"],
        common_name = "Zamaz Zero Trust CA",
      }
    }

    plugins {
      DataStore "sql" {
        plugin_data {
          database_type = "postgres"
          connection_string = "postgresql://spire:${POSTGRES_PASSWORD}@postgres:5432/spire"
        }
      }

      NodeAttestor "k8s_psat" {
        plugin_data {
          clusters = {
            "zamaz-cluster" = {
              service_account_allow_list = ["spire-system:spire-agent"]
            }
          }
        }
      }

      KeyManager "disk" {
        plugin_data {
          keys_path = "/opt/spire/data/keys"
        }
      }

      Notifier "k8sbundle" {
        plugin_data {
          namespace = "spire-system"
          config_map = "trust-bundle"
        }
      }
    }
```

## 🔄 **GitOps Workflow**

### **ArgoCD Application Configuration**
```yaml
# ArgoCD Application for Zero Trust Auth
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: zamaz-auth-dev
  namespace: argocd
  labels:
    environment: development
    component: authentication
spec:
  project: zamaz-platform
  source:
    repoURL: https://github.com/lsendel/root-zamaz
    targetRevision: main
    path: deployments/overlays/development
  destination:
    server: https://kubernetes.default.svc
    namespace: zamaz-auth-dev
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
      allowEmpty: false
    syncOptions:
    - CreateNamespace=true
    - PrunePropagationPolicy=foreground
    - PruneLast=true
    retry:
      limit: 5
      backoff:
        duration: 5s
        factor: 2
        maxDuration: 3m
  revisionHistoryLimit: 10

---
# Application Health Checks
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: zamaz-auth-dev
spec:
  # ... (source and destination config)
  ignoreDifferences:
  - group: apps
    kind: Deployment
    jsonPointers:
    - /spec/replicas
  - group: ""
    kind: Secret
    jsonPointers:
    - /data
  healthCheck:
    http:
      path: /health
      port: 8080
    initialDelaySeconds: 30
    periodSeconds: 10
    timeoutSeconds: 5
    successThreshold: 1
    failureThreshold: 3
```

### **Kustomize Overlay Pattern**
```yaml
# base/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

metadata:
  name: zamaz-auth-base

resources:
- namespace.yaml
- deployment.yaml
- service.yaml
- configmap.yaml
- service-account.yaml

commonLabels:
  app.kubernetes.io/name: zamaz-auth
  app.kubernetes.io/component: authentication
  app.kubernetes.io/part-of: zamaz-platform

images:
- name: zamaz-auth
  newTag: latest

---
# overlays/development/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: zamaz-auth-dev

resources:
- ../../base

commonLabels:
  environment: development

patchesStrategicMerge:
- deployment-patch.yaml
- service-patch.yaml

configMapGenerator:
- name: app-config
  envs:
  - config.env
  options:
    disableNameSuffixHash: true

images:
- name: zamaz-auth
  newTag: dev-latest
```

## 🏗️ **Application Deployment Patterns**

### **Zero Trust Authentication Service**
```yaml
# Authentication Service Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
  namespace: zamaz-auth
  labels:
    app: auth-service
    version: v1
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
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
        # SPIRE workload identity
        spire.io/workload-api-socket-dir: "/run/spire/sockets"
        # Istio sidecar injection
        sidecar.istio.io/inject: "true"
        # Prometheus metrics
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: auth-service
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
      containers:
      - name: auth-service
        image: zamaz-auth:latest
        imagePullPolicy: IfNotPresent
        ports:
        - name: http
          containerPort: 8080
          protocol: TCP
        - name: metrics
          containerPort: 9090
          protocol: TCP
        env:
        - name: PORT
          value: "8080"
        - name: METRICS_PORT
          value: "9090"
        - name: LOG_LEVEL
          value: "info"
        - name: DB_HOST
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: host
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: password
        # SPIRE socket volume
        volumeMounts:
        - name: spire-agent-socket
          mountPath: /run/spire/sockets
          readOnly: true
        # Application config
        - name: app-config
          mountPath: /etc/config
          readOnly: true
        # TLS certificates
        - name: tls-certs
          mountPath: /etc/tls
          readOnly: true
        livenessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: http
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      volumes:
      # SPIRE agent socket
      - name: spire-agent-socket
        hostPath:
          path: /run/spire/sockets
          type: Directory
      # Application configuration
      - name: app-config
        configMap:
          name: auth-service-config
      # TLS certificates for service mesh
      - name: tls-certs
        secret:
          secretName: auth-service-tls
      # DNS configuration
      dnsPolicy: ClusterFirst
      restartPolicy: Always
      terminationGracePeriodSeconds: 30
```

## 🕸️ **Istio Service Mesh Configuration**

### **Traffic Management**
```yaml
# Gateway Configuration
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: zamaz-auth-gateway
  namespace: zamaz-auth
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
      credentialName: zamaz-auth-tls
    hosts:
    - auth.zamaz.dev
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - auth.zamaz.dev
    tls:
      httpsRedirect: true

---
# Virtual Service for Routing
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: zamaz-auth-vs
  namespace: zamaz-auth
spec:
  hosts:
  - auth.zamaz.dev
  gateways:
  - zamaz-auth-gateway
  http:
  - match:
    - uri:
        prefix: "/api/v1/auth"
    route:
    - destination:
        host: auth-service
        port:
          number: 8080
      weight: 100
    fault:
      delay:
        percentage:
          value: 0.1
        fixedDelay: 5s
    retries:
      attempts: 3
      perTryTimeout: 2s
      retryOn: 5xx,reset,connect-failure,refused-stream
    timeout: 10s
  - match:
    - uri:
        prefix: "/"
    route:
    - destination:
        host: frontend-service
        port:
          number: 3000

---
# Destination Rule for Load Balancing
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: zamaz-auth-dr
  namespace: zamaz-auth
spec:
  host: auth-service
  trafficPolicy:
    loadBalancer:
      simple: LEAST_CONN
    connectionPool:
      tcp:
        maxConnections: 100
      http:
        http1MaxPendingRequests: 50
        http2MaxRequests: 100
        maxRequestsPerConnection: 10
        maxRetries: 3
        consecutiveGatewayErrors: 5
        interval: 30s
        baseEjectionTime: 30s
        maxEjectionPercent: 50
        minHealthPercent: 50
    outlierDetection:
      consecutiveGatewayErrors: 5
      interval: 30s
      baseEjectionTime: 30s
      maxEjectionPercent: 50
      minHealthPercent: 50
  subsets:
  - name: v1
    labels:
      version: v1
  - name: v2
    labels:
      version: v2
```

### **Security Policies**
```yaml
# Peer Authentication - Mutual TLS
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: zamaz-auth
spec:
  mtls:
    mode: STRICT

---
# Authorization Policy - Zero Trust
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: auth-service-authz
  namespace: zamaz-auth
spec:
  selector:
    matchLabels:
      app: auth-service
  rules:
  # Allow frontend to access auth endpoints
  - from:
    - source:
        principals: ["cluster.local/ns/zamaz-auth/sa/frontend-service"]
    to:
    - operation:
        methods: ["POST"]
        paths: ["/api/v1/auth/login", "/api/v1/auth/refresh"]
  # Allow internal services
  - from:
    - source:
        namespaces: ["zamaz-auth", "istio-system"]
    to:
    - operation:
        methods: ["GET"]
        paths: ["/health", "/ready", "/metrics"]
  # Deny all other traffic
  - {}

---
# Request Authentication - JWT Validation
apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: jwt-auth
  namespace: zamaz-auth
spec:
  selector:
    matchLabels:
      app: auth-service
  jwtRules:
  - issuer: "https://auth.zamaz.dev"
    jwksUri: "https://auth.zamaz.dev/.well-known/jwks.json"
    audiences:
    - "zamaz-platform"
    forwardOriginalToken: true
```

## 📊 **Monitoring & Observability**

### **Prometheus ServiceMonitor**
```yaml
# Service Monitor for Prometheus
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: auth-service-metrics
  namespace: zamaz-auth
  labels:
    app: auth-service
    release: prometheus
spec:
  selector:
    matchLabels:
      app: auth-service
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
    scrapeTimeout: 10s
  namespaceSelector:
    matchNames:
    - zamaz-auth

---
# Prometheus Rules for Alerting
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: auth-service-alerts
  namespace: zamaz-auth
  labels:
    app: auth-service
    release: prometheus
spec:
  groups:
  - name: auth-service.rules
    rules:
    - alert: AuthServiceDown
      expr: up{job="auth-service"} == 0
      for: 1m
      labels:
        severity: critical
        service: auth-service
      annotations:
        summary: "Auth service is down"
        description: "Auth service has been down for more than 1 minute"
    
    - alert: AuthServiceHighErrorRate
      expr: |
        (
          rate(http_requests_total{job="auth-service",status=~"5.."}[5m]) /
          rate(http_requests_total{job="auth-service"}[5m])
        ) > 0.05
      for: 5m
      labels:
        severity: warning
        service: auth-service
      annotations:
        summary: "High error rate in auth service"
        description: "Error rate is {{ $value | humanizePercentage }}"
    
    - alert: AuthServiceHighLatency
      expr: |
        histogram_quantile(0.95,
          rate(http_request_duration_seconds_bucket{job="auth-service"}[5m])
        ) > 0.5
      for: 5m
      labels:
        severity: warning
        service: auth-service
      annotations:
        summary: "High latency in auth service"
        description: "95th percentile latency is {{ $value }}s"
```

## 🔄 **Environment-Specific Configurations**

### **Development Environment**
```yaml
# overlays/development/deployment-patch.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: auth-service
        env:
        - name: LOG_LEVEL
          value: "debug"
        - name: ENABLE_PPROF
          value: "true"
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"

---
# Development-specific config
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-service-config
data:
  app.env: |
    ENVIRONMENT=development
    DEBUG_MODE=true
    CORS_ORIGINS=http://localhost:3000,http://localhost:5173
    SESSION_TIMEOUT=24h
    TOKEN_EXPIRY=1h
    REFRESH_TOKEN_EXPIRY=7d
```

### **Production Environment**
```yaml
# overlays/production/deployment-patch.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 5
  template:
    metadata:
      annotations:
        # Production-specific annotations
        cluster-autoscaler.kubernetes.io/safe-to-evict: "true"
    spec:
      # Production node selection
      nodeSelector:
        node-type: compute
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchLabels:
                  app: auth-service
              topologyKey: kubernetes.io/hostname
      containers:
      - name: auth-service
        env:
        - name: LOG_LEVEL
          value: "info"
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"

---
# Production HPA
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: auth-service-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: auth-service
  minReplicas: 3
  maxReplicas: 20
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
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 60
```

## 🚨 **Security Best Practices**

### **Secret Management**
- Use External Secrets Operator with HashiCorp Vault
- Rotate secrets regularly (automated process)
- Never commit secrets to Git repositories
- Use ServiceAccount tokens for workload identity
- Implement least privilege access principles

### **Network Security**
- Default deny-all network policies
- Explicit allow rules for required communication
- Service mesh mutual TLS everywhere
- Pod-to-pod encryption with SPIRE certificates
- Regular security policy audits

### **Container Security**
- Use distroless or minimal base images
- Run containers as non-root users
- Read-only root filesystems where possible
- Drop all Linux capabilities unless required
- Regular container image vulnerability scanning

## 📚 **Deployment Guidelines**

### **GitOps Workflow**
1. **Development**: Push changes to feature branch
2. **Testing**: CI/CD runs comprehensive tests
3. **Review**: Code review and security scanning
4. **Merge**: Merge to main branch triggers deployment
5. **Deploy**: ArgoCD automatically deploys to environments
6. **Monitor**: Observe deployment health and metrics

### **Emergency Procedures**
- **Rollback**: Use ArgoCD to rollback to previous version
- **Circuit Breaker**: Istio can redirect traffic during issues
- **Scaling**: HPA automatically scales based on demand
- **Incident Response**: Monitoring alerts trigger automated response

**Remember**: This infrastructure implements Zero Trust principles with defense in depth. Every component is secured, monitored, and follows the principle of least privilege access.