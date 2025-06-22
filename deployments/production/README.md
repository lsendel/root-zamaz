# Zero Trust Authentication Production Deployment Guide

> **Production Ready**: Complete deployment guide for Zero Trust Authentication system  
> **Last Updated**: 2025-06-22  
> **Environment**: Production with GitOps, monitoring, and security hardening

## 🎯 **Production Deployment Overview**

This guide provides comprehensive instructions for deploying the Zero Trust Authentication system to production with enterprise-grade security, monitoring, and operational practices.

## 📋 **Prerequisites**

### **Infrastructure Requirements**
- **Kubernetes Cluster**: v1.28+ with RBAC enabled
- **Container Runtime**: containerd or CRI-O
- **Storage**: Persistent volumes with backup capabilities
- **Networking**: LoadBalancer service support
- **DNS**: Proper domain configuration
- **Certificates**: Valid TLS certificates for all endpoints

### **External Dependencies**
- **HashiCorp Vault**: For secrets management
- **PostgreSQL**: Primary database (external or managed)
- **Redis**: Session storage and caching
- **Prometheus**: Metrics collection
- **Grafana**: Monitoring dashboards
- **ArgoCD**: GitOps deployment automation

### **Security Requirements**
- **SPIRE Server**: Workload identity management
- **OPA Gatekeeper**: Policy enforcement
- **Network Policies**: Kubernetes network segmentation
- **Pod Security Standards**: Enforced security policies
- **Image Scanning**: Container vulnerability assessment

## 🚀 **Quick Start Deployment**

### **1. Prepare Environment**
```bash
# Clone repository
git clone https://github.com/lsendel/root-zamaz.git
cd root-zamaz

# Verify cluster connectivity
kubectl cluster-info
kubectl get nodes

# Create production namespace
kubectl create namespace zero-trust-prod

# Label namespace for security policies
kubectl label namespace zero-trust-prod \
  security.zero-trust.io/tier=production \
  compliance.gdpr=enabled \
  compliance.sox=enabled
```

### **2. Deploy External Secrets Operator**
```bash
# Install External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm repo update

helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets-system \
  --create-namespace \
  --set installCRDs=true

# Configure Vault SecretStore
kubectl apply -f deployments/production/secrets/vault-secret-store.yaml
```

### **3. Deploy Production Configuration**
```bash
# Apply production manifests using Kustomize
kubectl apply -k deployments/production/

# Verify deployment status
kubectl get pods -n zero-trust-prod
kubectl get services -n zero-trust-prod
kubectl get ingress -n zero-trust-prod
```

### **4. Initialize Database Schema**
```bash
# Run database migrations
kubectl create job --from=cronjob/db-migration db-migration-init -n zero-trust-prod

# Verify migration completion
kubectl logs job/db-migration-init -n zero-trust-prod
```

### **5. Configure Monitoring**
```bash
# Deploy monitoring stack
kubectl apply -f deployments/production/monitoring/

# Access Grafana dashboard
kubectl port-forward svc/grafana 3000:3000 -n monitoring
# Navigate to http://localhost:3000
```

## 🔧 **Detailed Configuration**

### **Secrets Management**

#### **Vault Configuration**
```bash
# Create Vault policies for Zero Trust Auth
vault policy write zero-trust-auth - <<EOF
path "secret/data/zero-trust/*" {
  capabilities = ["read"]
}

path "database/creds/zero-trust-role" {
  capabilities = ["read"]
}
EOF

# Create Kubernetes auth role
vault write auth/kubernetes/role/zero-trust-auth \
  bound_service_account_names=external-secrets \
  bound_service_account_namespaces=zero-trust-prod \
  policies=zero-trust-auth \
  ttl=24h
```

#### **Secret Rotation Schedule**
```yaml
# Database credentials rotation (weekly)
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: database-credentials
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: database-credentials
    creationPolicy: Owner
  data:
  - secretKey: username
    remoteRef:
      key: database/creds/zero-trust-role
      property: username
  - secretKey: password
    remoteRef:
      key: database/creds/zero-trust-role
      property: password
```

### **Database Configuration**

#### **PostgreSQL High Availability**
```yaml
# PostgreSQL StatefulSet with read replicas
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: postgres-cluster
  namespace: zero-trust-prod
spec:
  instances: 3
  primaryUpdateStrategy: unsupervised
  
  postgresql:
    parameters:
      max_connections: "200"
      shared_buffers: "256MB"
      effective_cache_size: "1GB"
      work_mem: "4MB"
      maintenance_work_mem: "64MB"
      checkpoint_completion_target: "0.9"
      wal_buffers: "16MB"
      default_statistics_target: "100"
      
  bootstrap:
    initdb:
      database: zamaz_auth
      owner: zamaz_user
      secret:
        name: postgres-credentials
        
  monitoring:
    enabled: true
    
  backup:
    retentionPolicy: "30d"
    barmanObjectStore:
      destinationPath: "s3://zamaz-backups/postgresql"
      s3Credentials:
        accessKeyId:
          name: backup-credentials
          key: access-key-id
        secretAccessKey:
          name: backup-credentials
          key: secret-access-key
      wal:
        retention: "5d"
      data:
        retention: "30d"
```

#### **Database Migrations**
```yaml
# Database migration job
apiVersion: batch/v1
kind: Job
metadata:
  name: db-migration
  namespace: zero-trust-prod
spec:
  template:
    spec:
      containers:
      - name: migrate
        image: migrate/migrate:v4.16.2
        command:
        - migrate
        - -path
        - /migrations
        - -database
        - postgresql://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):5432/$(DB_NAME)?sslmode=require
        - up
        env:
        - name: DB_HOST
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: host
        - name: DB_USER
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: username
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: password
        - name: DB_NAME
          value: zamaz_auth
        volumeMounts:
        - name: migrations
          mountPath: /migrations
      volumes:
      - name: migrations
        configMap:
          name: db-migrations
      restartPolicy: OnFailure
```

### **Service Mesh Configuration**

#### **Istio Gateway and Virtual Service**
```yaml
# Production Gateway
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: zero-trust-gateway
  namespace: zero-trust-prod
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
      credentialName: zero-trust-tls-cert
    hosts:
    - auth.yourdomain.com
    - api.yourdomain.com
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - auth.yourdomain.com
    - api.yourdomain.com
    tls:
      httpsRedirect: true

---
# Traffic routing
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: zero-trust-routes
  namespace: zero-trust-prod
spec:
  hosts:
  - auth.yourdomain.com
  - api.yourdomain.com
  gateways:
  - zero-trust-gateway
  http:
  - match:
    - uri:
        prefix: "/api/v1/"
    route:
    - destination:
        host: backend-api
        port:
          number: 8080
    timeout: 30s
    retries:
      attempts: 3
      perTryTimeout: 10s
  - match:
    - uri:
        prefix: "/auth/"
    route:
    - destination:
        host: keycloak
        port:
          number: 8080
  - match:
    - uri:
        prefix: "/"
    route:
    - destination:
        host: frontend
        port:
          number: 3000
```

### **Monitoring and Alerting**

#### **Critical Alerts Configuration**
```yaml
# Production alert rules
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: zero-trust-critical-alerts
  namespace: zero-trust-prod
spec:
  groups:
  - name: zero-trust.critical
    rules:
    - alert: ServiceDown
      expr: up{job=~"backend-api|keycloak|opa"} == 0
      for: 1m
      labels:
        severity: critical
        team: platform
      annotations:
        summary: "Critical service {{ $labels.job }} is down"
        description: "Service {{ $labels.job }} has been down for more than 1 minute"
        runbook_url: "https://wiki.company.com/runbooks/service-down"
    
    - alert: HighAuthenticationErrorRate
      expr: |
        (
          sum(rate(http_requests_total{job="backend-api",endpoint="/api/v1/auth/login",status=~"4..|5.."}[5m])) /
          sum(rate(http_requests_total{job="backend-api",endpoint="/api/v1/auth/login"}[5m]))
        ) > 0.05
      for: 5m
      labels:
        severity: critical
        team: security
      annotations:
        summary: "High authentication error rate detected"
        description: "Authentication error rate is {{ $value | humanizePercentage }}"
    
    - alert: TrustLevelBypassAttempt
      expr: increase(trust_level_violations_total[5m]) > 0
      for: 0m
      labels:
        severity: critical
        team: security
      annotations:
        summary: "Trust level bypass attempt detected"
        description: "{{ $value }} trust level violations in the last 5 minutes"
    
    - alert: DatabaseConnectionPoolExhaustion
      expr: |
        (
          sum(pg_stat_database_numbackends) /
          sum(pg_settings_max_connections)
        ) > 0.9
      for: 2m
      labels:
        severity: warning
        team: platform
      annotations:
        summary: "Database connection pool near exhaustion"
        description: "Database connection usage is {{ $value | humanizePercentage }}"
```

#### **Grafana Dashboards**
```yaml
# Zero Trust monitoring dashboard
apiVersion: v1
kind: ConfigMap
metadata:
  name: zero-trust-dashboard
  namespace: monitoring
data:
  dashboard.json: |
    {
      "dashboard": {
        "title": "Zero Trust Authentication Production",
        "panels": [
          {
            "title": "Authentication Requests",
            "type": "stat",
            "targets": [
              {
                "expr": "sum(rate(http_requests_total{endpoint=\"/api/v1/auth/login\"}[5m]))"
              }
            ]
          },
          {
            "title": "Trust Level Distribution",
            "type": "piechart",
            "targets": [
              {
                "expr": "sum by (trust_level) (trust_level_distribution)"
              }
            ]
          },
          {
            "title": "Response Time P95",
            "type": "graph",
            "targets": [
              {
                "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))"
              }
            ]
          }
        ]
      }
    }
```

### **Backup and Disaster Recovery**

#### **Velero Backup Configuration**
```yaml
# Backup schedule
apiVersion: velero.io/v1
kind: Schedule
metadata:
  name: zero-trust-daily-backup
  namespace: velero
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  template:
    includedNamespaces:
    - zero-trust-prod
    excludedResources:
    - events
    - events.events.k8s.io
    storageLocation: default
    ttl: 720h0m0s  # 30 days
    snapshotVolumes: true
```

#### **Disaster Recovery Procedures**
```bash
# Database backup verification
kubectl exec -it postgres-cluster-1 -n zero-trust-prod -- \
  pg_dump -h localhost -U zamaz_user zamaz_auth | \
  gzip > /backup/zamaz_auth_$(date +%Y%m%d).sql.gz

# Application data backup
velero backup create manual-backup-$(date +%Y%m%d) \
  --include-namespaces zero-trust-prod \
  --wait

# Recovery test procedure
kubectl create namespace zero-trust-test
velero restore create test-restore \
  --from-backup manual-backup-$(date +%Y%m%d) \
  --namespace-mappings zero-trust-prod:zero-trust-test
```

## 🛡️ **Security Hardening**

### **Network Security**
```yaml
# Default deny network policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: zero-trust-prod
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress

---
# Allow specific communication
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-api-policy
  namespace: zero-trust-prod
spec:
  podSelector:
    matchLabels:
      app: backend-api
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
    - podSelector:
        matchLabels:
          app: postgresql
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
  name: zero-trust-psp
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
```

## 📊 **Performance Optimization**

### **Auto-scaling Configuration**
```yaml
# Horizontal Pod Autoscaler
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: backend-api-hpa
  namespace: zero-trust-prod
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: backend-api
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 60
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 70
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "100"
```

### **Resource Optimization**
```yaml
# Resource requests and limits
spec:
  containers:
  - name: backend-api
    resources:
      requests:
        memory: "512Mi"
        cpu: "500m"
      limits:
        memory: "1Gi"
        cpu: "1000m"
    
  - name: keycloak
    resources:
      requests:
        memory: "1Gi"
        cpu: "1000m"
      limits:
        memory: "2Gi"
        cpu: "2000m"
```

## 🔍 **Operational Procedures**

### **Health Checks**
```bash
# Service health verification
kubectl get pods -n zero-trust-prod
kubectl get services -n zero-trust-prod
kubectl describe deployment backend-api -n zero-trust-prod

# Application health endpoints
curl -k https://api.yourdomain.com/health
curl -k https://auth.yourdomain.com/auth/health-check

# Database connectivity
kubectl exec -it deployment/backend-api -n zero-trust-prod -- \
  sh -c 'nc -z $DB_HOST 5432 && echo "Database reachable"'
```

### **Log Management**
```bash
# View application logs
kubectl logs -f deployment/backend-api -n zero-trust-prod
kubectl logs -f deployment/keycloak -n zero-trust-prod

# Aggregate logs with Loki
curl -G -s "http://loki:3100/loki/api/v1/query_range" \
  --data-urlencode 'query={namespace="zero-trust-prod"}' \
  --data-urlencode 'start=2024-01-01T00:00:00Z' \
  --data-urlencode 'end=2024-01-01T23:59:59Z'
```

### **Performance Monitoring**
```bash
# Check resource usage
kubectl top pods -n zero-trust-prod
kubectl top nodes

# Query metrics
curl -s 'http://prometheus:9090/api/v1/query?query=up{namespace="zero-trust-prod"}'

# Load testing
k6 run tests/load/k6-load-test.js \
  --env API_BASE_URL=https://api.yourdomain.com
```

## 🚨 **Troubleshooting Guide**

### **Common Issues**

#### **Service Discovery Problems**
```bash
# Check DNS resolution
kubectl exec -it deployment/backend-api -n zero-trust-prod -- \
  nslookup keycloak.zero-trust-prod.svc.cluster.local

# Verify service endpoints
kubectl get endpoints -n zero-trust-prod
```

#### **Authentication Issues**
```bash
# Check JWT token validation
kubectl logs deployment/backend-api -n zero-trust-prod | grep "jwt"

# Verify Keycloak connectivity
kubectl exec -it deployment/backend-api -n zero-trust-prod -- \
  curl -v http://keycloak:8080/auth/realms/zamaz/.well-known/openid_configuration
```

#### **Database Connection Issues**
```bash
# Test database connectivity
kubectl exec -it postgres-cluster-1 -n zero-trust-prod -- \
  psql -U zamaz_user -d zamaz_auth -c "SELECT version();"

# Check connection pool status
kubectl exec -it deployment/backend-api -n zero-trust-prod -- \
  curl http://localhost:8080/metrics | grep -i pool
```

### **Emergency Procedures**

#### **Service Rollback**
```bash
# Rollback deployment
kubectl rollout undo deployment/backend-api -n zero-trust-prod

# Check rollout status
kubectl rollout status deployment/backend-api -n zero-trust-prod
```

#### **Scale Emergency Response**
```bash
# Emergency scale up
kubectl scale deployment backend-api --replicas=10 -n zero-trust-prod

# Traffic rerouting (if needed)
kubectl patch virtualservice zero-trust-routes -n zero-trust-prod \
  --type='json' -p='[{"op": "replace", "path": "/spec/http/0/route/0/weight", "value": 0}]'
```

## ✅ **Production Checklist**

### **Pre-Deployment**
- [ ] Infrastructure prerequisites met
- [ ] External dependencies configured
- [ ] Secrets properly configured in Vault
- [ ] Database migrations tested
- [ ] Security policies reviewed
- [ ] Monitoring dashboards configured
- [ ] Backup procedures tested
- [ ] Load testing completed
- [ ] Security scanning passed
- [ ] Documentation updated

### **Post-Deployment**
- [ ] All services running and healthy
- [ ] Authentication flows working
- [ ] Authorization policies enforced
- [ ] Monitoring alerts configured
- [ ] Backup schedules active
- [ ] Performance metrics within SLA
- [ ] Security policies enforced
- [ ] Compliance requirements met
- [ ] Team runbooks updated
- [ ] Incident response procedures tested

## 📚 **Additional Resources**

### **Documentation Links**
- [Zero Trust Architecture Guide](../docs/architecture.md)
- [Security Policies](security/README.md)
- [Monitoring Setup](monitoring/README.md)
- [Backup Procedures](backup/README.md)
- [API Documentation](../docs/api.md)

### **Runbooks**
- [Service Outage Response](runbooks/service-outage.md)
- [Security Incident Response](runbooks/security-incident.md)
- [Database Maintenance](runbooks/database-maintenance.md)
- [Scaling Procedures](runbooks/scaling.md)

### **Contact Information**
- **Platform Team**: platform@company.com
- **Security Team**: security@company.com
- **On-Call**: +1-555-ONCALL
- **Emergency Escalation**: emergency@company.com

---

**Production Support**: For production issues, follow the incident response procedures in the runbooks. All critical alerts are automatically routed to the on-call engineer.

**Security Notice**: This deployment implements Zero Trust principles. Any security concerns should be immediately reported to the security team.