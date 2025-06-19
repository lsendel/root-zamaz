# Zero Trust Authentication MVP - Production Deployment Manual

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Environment Setup](#environment-setup)
4. [First-Time Cluster Deployment](#first-time-cluster-deployment)
5. [Kubernetes Scaling & Load Balancing](#kubernetes-scaling--load-balancing)
6. [Service Discovery & Communication](#service-discovery--communication)
7. [CI/CD Strategy](#cicd-strategy)
8. [Multi-Cloud Deployment](#multi-cloud-deployment)
9. [Service Mesh with Envoy](#service-mesh-with-envoy)
10. [Monitoring & Observability](#monitoring--observability)
11. [Security Considerations](#security-considerations)
12. [Troubleshooting](#troubleshooting)

## Overview

This manual provides comprehensive guidance for deploying the Zero Trust Authentication MVP in production environments across multiple cloud providers and deployment scenarios.

### Architecture Overview
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Development   │───▶│     Staging     │───▶│   Production    │
│    (Local)      │    │   (Pre-prod)    │    │   (Multi-AZ)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Single Node    │    │   3-Node Cluster│    │  Multi-Cluster  │
│  Docker Compose │    │   Kubernetes    │    │   Service Mesh  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Prerequisites

### System Requirements
- **Minimum Resources (Development)**:
  - 4 vCPUs, 8GB RAM, 50GB SSD
  - Docker 20.10+, Docker Compose 2.0+
  
- **Recommended Resources (Production)**:
  - Control Plane: 3 nodes × (4 vCPUs, 8GB RAM, 100GB SSD)
  - Worker Nodes: 6+ nodes × (8 vCPUs, 16GB RAM, 200GB SSD)

### Software Dependencies
```bash
# Required tools
kubectl >= 1.25
helm >= 3.10
kustomize >= 4.5
istioctl >= 1.17 (for service mesh)
terraform >= 1.3 (for infrastructure)
```

### Access Requirements
- Kubernetes cluster admin access
- Container registry push/pull permissions
- Cloud provider credentials (AWS/GCP/Azure)
- SSL/TLS certificates for production domains

## Environment Setup

### 1. Development Environment
```bash
# Clone repository
git clone https://github.com/your-org/zero-trust-auth-mvp.git
cd zero-trust-auth-mvp

# Setup local development
make dev-up
make build
make test

# Verify services
curl http://localhost:8080/health
curl http://localhost:3000  # Grafana
curl http://localhost:9090  # Prometheus
```

### 2. Container Registry Setup
```bash
# Build and push images
docker build -t your-registry/zamaz-server:v1.0.0 .
docker build -f frontend/Dockerfile -t your-registry/zamaz-frontend:v1.0.0 ./frontend

docker push your-registry/zamaz-server:v1.0.0
docker push your-registry/zamaz-frontend:v1.0.0
```

## First-Time Cluster Deployment

### 1. Cluster Preparation

#### AWS EKS Setup
```bash
# Create EKS cluster with Terraform
cd infrastructure/terraform/aws

terraform init
terraform plan -var="environment=production"
terraform apply

# Configure kubectl
aws eks update-kubeconfig --region us-west-2 --name zamaz-prod-cluster
```

#### Google GKE Setup
```bash
# Create GKE cluster
gcloud container clusters create zamaz-prod \
  --region=us-central1 \
  --num-nodes=3 \
  --machine-type=e2-standard-4 \
  --enable-autoscaling \
  --min-nodes=3 \
  --max-nodes=10 \
  --enable-network-policy \
  --enable-ip-alias

# Get credentials
gcloud container clusters get-credentials zamaz-prod --region=us-central1
```

### 2. Namespace and RBAC Setup
```bash
# Create namespaces
kubectl create namespace zamaz-prod
kubectl create namespace zamaz-staging
kubectl create namespace zamaz-monitoring

# Apply RBAC
kubectl apply -f deployments/kubernetes/rbac/
```

### 3. Secrets Management
```bash
# Create TLS secrets
kubectl create secret tls zamaz-tls \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key \
  -n zamaz-prod

# Create database secrets
kubectl create secret generic zamaz-db-secret \
  --from-literal=username=zamaz_user \
  --from-literal=password=secure_random_password \
  --from-literal=database=zamaz_prod \
  -n zamaz-prod

# Create JWT secrets
kubectl create secret generic zamaz-jwt-secret \
  --from-literal=secret=your-super-secure-jwt-secret-key \
  -n zamaz-prod
```

### 4. Infrastructure Dependencies

#### PostgreSQL Database
```bash
# Option 1: Managed Database (Recommended)
# AWS RDS
aws rds create-db-instance \
  --db-instance-identifier zamaz-prod-db \
  --db-instance-class db.r5.large \
  --engine postgres \
  --master-username zamaz_admin \
  --master-user-password secure_password \
  --allocated-storage 100 \
  --vpc-security-group-ids sg-xxxxxxxxx

# Option 2: In-cluster PostgreSQL
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install postgresql bitnami/postgresql \
  --namespace zamaz-prod \
  --set auth.postgresPassword=secure_password \
  --set primary.persistence.size=100Gi
```

#### Redis Cache
```bash
# Managed Redis (Recommended)
# AWS ElastiCache
aws elasticache create-cache-cluster \
  --cache-cluster-id zamaz-prod-redis \
  --cache-node-type cache.r5.large \
  --engine redis \
  --num-cache-nodes 1

# In-cluster Redis
helm install redis bitnami/redis \
  --namespace zamaz-prod \
  --set auth.password=secure_redis_password \
  --set master.persistence.size=20Gi
```

### 5. Application Deployment
```bash
# Deploy with Kustomize
kubectl apply -k deployments/kubernetes/overlays/production

# Verify deployment
kubectl get pods -n zamaz-prod
kubectl get svc -n zamaz-prod
kubectl get ingress -n zamaz-prod
```

## Kubernetes Scaling & Load Balancing

### 1. Horizontal Pod Autoscaler (HPA)
```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: zamaz-app-hpa
  namespace: zamaz-prod
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: zamaz-app
  minReplicas: 3
  maxReplicas: 50
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
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
```

### 2. Vertical Pod Autoscaler (VPA)
```yaml
# vpa.yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: zamaz-app-vpa
  namespace: zamaz-prod
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: zamaz-app
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
    - containerName: zamaz
      maxAllowed:
        cpu: 2
        memory: 4Gi
      minAllowed:
        cpu: 100m
        memory: 128Mi
```

### 3. Cluster Autoscaler
```bash
# AWS EKS
kubectl apply -f https://raw.githubusercontent.com/kubernetes/autoscaler/master/cluster-autoscaler/cloudprovider/aws/examples/cluster-autoscaler-autodiscover.yaml

# Configure for your cluster
kubectl -n kube-system edit deployment.apps/cluster-autoscaler
# Add: --node-group-auto-discovery=asg:tag=k8s.io/cluster-autoscaler/enabled,k8s.io/cluster-autoscaler/zamaz-prod-cluster
```

### 4. Load Balancer Configuration

#### AWS Application Load Balancer
```yaml
# ingress-alb.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: zamaz-ingress
  namespace: zamaz-prod
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/ssl-redirect: '443'
    alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:us-west-2:123456789012:certificate/xxxxx
    alb.ingress.kubernetes.io/healthcheck-path: /health
    alb.ingress.kubernetes.io/healthcheck-interval-seconds: '30'
    alb.ingress.kubernetes.io/healthy-threshold-count: '2'
    alb.ingress.kubernetes.io/unhealthy-threshold-count: '3'
spec:
  rules:
  - host: api.zamaz.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: zamaz-api
            port:
              number: 8080
  - host: app.zamaz.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: zamaz-frontend
            port:
              number: 3000
```

#### GCP Global Load Balancer
```yaml
# ingress-gce.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: zamaz-ingress
  namespace: zamaz-prod
  annotations:
    kubernetes.io/ingress.class: gce
    kubernetes.io/ingress.global-static-ip-name: zamaz-global-ip
    networking.gke.io/managed-certificates: zamaz-ssl-cert
    kubernetes.io/ingress.allow-http: "false"
spec:
  rules:
  - host: api.zamaz.com
    http:
      paths:
      - path: /*
        pathType: ImplementationSpecific
        backend:
          service:
            name: zamaz-api
            port:
              number: 8080
```

## Service Discovery & Communication

### 1. Service Registration
Services are automatically registered in Kubernetes DNS:
```bash
# Internal service communication
zamaz-api.zamaz-prod.svc.cluster.local:8080
zamaz-frontend.zamaz-prod.svc.cluster.local:3000
postgresql.zamaz-prod.svc.cluster.local:5432
redis.zamaz-prod.svc.cluster.local:6379
```

### 2. Inter-Cluster Communication

#### Service Mesh Setup (Istio)
```bash
# Install Istio
istioctl install --set values.defaultRevision=default

# Enable sidecar injection
kubectl label namespace zamaz-prod istio-injection=enabled

# Apply service mesh configuration
kubectl apply -f deployments/istio/
```

#### Cross-Cluster Service Discovery
```yaml
# service-entry.yaml
apiVersion: networking.istio.io/v1beta1
kind: ServiceEntry
metadata:
  name: external-zamaz-service
  namespace: zamaz-prod
spec:
  hosts:
  - zamaz-api.staging.local
  ports:
  - number: 8080
    name: http
    protocol: HTTP
  location: MESH_EXTERNAL
  resolution: DNS
```

### 3. Multi-Cluster Communication Strategies

#### Option 1: VPN/VPC Peering
```bash
# AWS VPC Peering
aws ec2 create-vpc-peering-connection \
  --vpc-id vpc-12345678 \
  --peer-vpc-id vpc-87654321 \
  --peer-region us-east-1

# Accept peering connection
aws ec2 accept-vpc-peering-connection \
  --vpc-peering-connection-id pcx-xxxxxxxx
```

#### Option 2: Istio Multi-Cluster
```bash
# Install Istio on both clusters
# Cluster 1 (Primary)
istioctl install --set values.pilot.env.EXTERNAL_ISTIOD=true

# Cluster 2 (Remote)
istioctl install --set values.istiodRemote.enabled=true \
  --set values.pilot.env.EXTERNAL_ISTIOD=true \
  --set values.global.remotePilotAddress=<DISCOVERY_ADDRESS>
```

## CI/CD Strategy

### 1. Environment Progression
```
Developer → Feature Branch → Development → Staging → Pre-Production → Production
     ↓            ↓              ↓           ↓            ↓             ↓
  Local       Build & Test    Auto Deploy  Manual QA   Load Test   Blue/Green
```

### 2. GitOps Workflow (ArgoCD)
```yaml
# argocd-application.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: zamaz-production
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/your-org/zamaz-config
    targetRevision: HEAD
    path: overlays/production
  destination:
    server: https://kubernetes.default.svc
    namespace: zamaz-prod
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
    - CreateNamespace=true
    retry:
      limit: 5
      backoff:
        duration: 5s
        factor: 2
        maxDuration: 3m
```

### 3. GitHub Actions Pipeline
```yaml
# .github/workflows/deploy.yml
name: Deploy to Production
on:
  push:
    branches: [main]
    tags: ['v*']

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - uses: actions/setup-go@v3
      with:
        go-version: '1.21'
    - run: make test-coverage
    - run: make security-scan
    
  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Build and push Docker images
      run: |
        docker build -t ${{ secrets.REGISTRY }}/zamaz:${{ github.sha }} .
        docker push ${{ secrets.REGISTRY }}/zamaz:${{ github.sha }}
        
  deploy-staging:
    needs: build
    runs-on: ubuntu-latest
    environment: staging
    steps:
    - name: Deploy to staging
      run: |
        kustomize edit set image zamaz=${{ secrets.REGISTRY }}/zamaz:${{ github.sha }}
        kubectl apply -k overlays/staging
        
  deploy-production:
    needs: deploy-staging
    runs-on: ubuntu-latest
    environment: production
    if: startsWith(github.ref, 'refs/tags/v')
    steps:
    - name: Blue/Green deployment
      run: |
        # Blue/Green deployment script
        ./scripts/blue-green-deploy.sh ${{ github.sha }}
```

### 4. Deployment Strategies

#### Blue/Green Deployment
```bash
#!/bin/bash
# scripts/blue-green-deploy.sh

NEW_VERSION=$1
NAMESPACE="zamaz-prod"

# Deploy green environment
kubectl patch deployment zamaz-app-green -n $NAMESPACE \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"zamaz","image":"'$REGISTRY'/zamaz:'$NEW_VERSION'"}]}}}}'

# Wait for green to be ready
kubectl rollout status deployment/zamaz-app-green -n $NAMESPACE

# Health check green environment
kubectl exec deployment/zamaz-app-green -n $NAMESPACE -- curl -f http://localhost:8080/health

# Switch traffic to green
kubectl patch service zamaz-api -n $NAMESPACE \
  -p '{"spec":{"selector":{"version":"green"}}}'

# Monitor for 5 minutes
sleep 300

# If successful, update blue to new version
kubectl patch deployment zamaz-app-blue -n $NAMESPACE \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"zamaz","image":"'$REGISTRY'/zamaz:'$NEW_VERSION'"}]}}}}'
```

#### Canary Deployment with Flagger
```yaml
# canary.yaml
apiVersion: flagger.app/v1beta1
kind: Canary
metadata:
  name: zamaz-app
  namespace: zamaz-prod
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: zamaz-app
  progressDeadlineSeconds: 60
  service:
    port: 8080
  analysis:
    interval: 1m
    threshold: 10
    maxWeight: 50
    stepWeight: 5
    metrics:
    - name: request-success-rate
      threshold: 99
      interval: 1m
    - name: request-duration
      threshold: 500
      interval: 30s
```

## Multi-Cloud Deployment

### 1. AWS Deployment

#### Infrastructure as Code (Terraform)
```hcl
# infrastructure/terraform/aws/main.tf
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  
  name = "zamaz-prod-vpc"
  cidr = "10.0.0.0/16"
  
  azs             = ["us-west-2a", "us-west-2b", "us-west-2c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  
  enable_nat_gateway = true
  enable_vpn_gateway = true
  
  tags = {
    Environment = "production"
    Project     = "zamaz"
  }
}

module "eks" {
  source = "terraform-aws-modules/eks/aws"
  
  cluster_name    = "zamaz-prod"
  cluster_version = "1.27"
  
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  
  node_groups = {
    main = {
      desired_capacity = 3
      max_capacity     = 10
      min_capacity     = 3
      
      instance_types = ["m5.xlarge"]
      
      k8s_labels = {
        Environment = "production"
      }
    }
  }
}
```

#### AWS-Specific Services
```yaml
# aws-services.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-config
  namespace: zamaz-prod
data:
  AWS_REGION: "us-west-2"
  S3_BUCKET: "zamaz-prod-assets"
  SQS_QUEUE_URL: "https://sqs.us-west-2.amazonaws.com/123456789012/zamaz-notifications"
  
---
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets-manager
  namespace: zamaz-prod
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-west-2
      auth:
        jwt:
          serviceAccountRef:
            name: external-secrets-sa
```

### 2. Google Cloud Platform Deployment

#### GCP Infrastructure
```hcl
# infrastructure/terraform/gcp/main.tf
resource "google_container_cluster" "zamaz_prod" {
  name     = "zamaz-prod"
  location = "us-central1"
  
  remove_default_node_pool = true
  initial_node_count       = 1
  
  network    = google_compute_network.vpc.name
  subnetwork = google_compute_subnetwork.subnet.name
  
  networking_mode = "VPC_NATIVE"
  ip_allocation_policy {
    cluster_secondary_range_name  = "k8s-pod-range"
    services_secondary_range_name = "k8s-service-range"
  }
  
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
}

resource "google_container_node_pool" "zamaz_nodes" {
  name       = "zamaz-node-pool"
  location   = "us-central1"
  cluster    = google_container_cluster.zamaz_prod.name
  node_count = 3
  
  autoscaling {
    min_node_count = 3
    max_node_count = 10
  }
  
  node_config {
    preemptible  = false
    machine_type = "e2-standard-4"
    
    service_account = google_service_account.zamaz_sa.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }
}
```

### 3. Cross-Cloud Considerations

#### Network Connectivity
```bash
# Site-to-Site VPN between AWS and GCP
# AWS Customer Gateway
aws ec2 create-customer-gateway \
  --type ipsec.1 \
  --public-ip $GCP_VPN_IP \
  --bgp-asn 65000

# GCP VPN Gateway
gcloud compute vpn-gateways create aws-vpn-gateway \
  --network=zamaz-network \
  --region=us-central1
```

#### DNS and Service Discovery
```yaml
# external-dns.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-dns
  namespace: kube-system
spec:
  template:
    spec:
      containers:
      - name: external-dns
        image: k8s.gcr.io/external-dns/external-dns:v0.13.1
        args:
        - --source=service
        - --source=ingress
        - --domain-filter=zamaz.com
        - --provider=aws
        - --aws-zone-type=public
        - --registry=txt
        - --txt-owner-id=zamaz-prod
```

## Service Mesh with Envoy

### 1. Istio Service Mesh Setup
```bash
# Install Istio
curl -L https://istio.io/downloadIstio | sh -
istioctl install --set values.defaultRevision=default

# Enable automatic sidecar injection
kubectl label namespace zamaz-prod istio-injection=enabled
```

### 2. Envoy Configuration
```yaml
# envoy-filter.yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: zamaz-security-filter
  namespace: zamaz-prod
spec:
  configPatches:
  - applyTo: HTTP_FILTER
    match:
      context: SIDECAR_INBOUND
      listener:
        filterChain:
          filter:
            name: "envoy.filters.network.http_connection_manager"
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.filters.http.wasm
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
          config:
            name: "zamaz_auth_filter"
            root_id: "zamaz_auth"
            configuration:
              "@type": type.googleapis.com/google.protobuf.StringValue
              value: |
                {
                  "auth_service": "zamaz-api.zamaz-prod.svc.cluster.local:8080",
                  "auth_endpoint": "/auth/verify"
                }
```

### 3. Traffic Management
```yaml
# virtual-service.yaml
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: zamaz-api
  namespace: zamaz-prod
spec:
  hosts:
  - api.zamaz.com
  - zamaz-api.zamaz-prod.svc.cluster.local
  gateways:
  - zamaz-gateway
  http:
  - match:
    - uri:
        prefix: "/api/v1"
    route:
    - destination:
        host: zamaz-api.zamaz-prod.svc.cluster.local
        port:
          number: 8080
        subset: v1
    timeout: 30s
    retries:
      attempts: 3
      perTryTimeout: 10s
  - match:
    - uri:
        prefix: "/health"
    route:
    - destination:
        host: zamaz-api.zamaz-prod.svc.cluster.local
        port:
          number: 8080
    timeout: 5s
```

### 4. Security Policies
```yaml
# authorization-policy.yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: zamaz-api-authz
  namespace: zamaz-prod
spec:
  selector:
    matchLabels:
      app: zamaz-api
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/zamaz-prod/sa/zamaz-frontend"]
    to:
    - operation:
        methods: ["GET", "POST"]
        paths: ["/api/*"]
  - from:
    - source:
        principals: ["cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account"]
    to:
    - operation:
        methods: ["GET"]
        paths: ["/health", "/metrics"]
```

## Monitoring & Observability

### 1. Prometheus Configuration
```yaml
# prometheus-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: zamaz-monitoring
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s
    
    rule_files:
    - "/etc/prometheus/rules/*.yml"
    
    scrape_configs:
    - job_name: 'zamaz-api'
      kubernetes_sd_configs:
      - role: endpoints
        namespaces:
          names:
          - zamaz-prod
          - zamaz-staging
      relabel_configs:
      - source_labels: [__meta_kubernetes_service_name]
        action: keep
        regex: zamaz-api
      - source_labels: [__meta_kubernetes_endpoint_port_name]
        action: keep
        regex: metrics
    
    - job_name: 'kubernetes-pods'
      kubernetes_sd_configs:
      - role: pod
      relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
```

### 2. Grafana Dashboards
```yaml
# grafana-dashboard-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: zamaz-dashboard
  namespace: zamaz-monitoring
  labels:
    grafana_dashboard: "1"
data:
  zamaz-overview.json: |
    {
      "dashboard": {
        "title": "Zamaz Production Overview",
        "panels": [
          {
            "title": "Request Rate",
            "type": "graph",
            "targets": [
              {
                "expr": "sum(rate(http_requests_total{job=\"zamaz-api\"}[5m]))",
                "legendFormat": "Total RPS"
              }
            ]
          },
          {
            "title": "Error Rate",
            "type": "graph",
            "targets": [
              {
                "expr": "sum(rate(http_requests_total{job=\"zamaz-api\",status=~\"5..\"}[5m])) / sum(rate(http_requests_total{job=\"zamaz-api\"}[5m])) * 100",
                "legendFormat": "Error Rate %"
              }
            ]
          }
        ]
      }
    }
```

### 3. Alerting Rules
```yaml
# alerting-rules.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: zamaz-alert-rules
  namespace: zamaz-monitoring
data:
  zamaz.yml: |
    groups:
    - name: zamaz.rules
      rules:
      - alert: ZamazAPIHighErrorRate
        expr: (sum(rate(http_requests_total{job="zamaz-api",status=~"5.."}[5m])) / sum(rate(http_requests_total{job="zamaz-api"}[5m]))) * 100 > 5
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Zamaz API error rate is above 5%"
          description: "Error rate is {{ $value }}% for the last 5 minutes"
      
      - alert: ZamazAPIHighLatency
        expr: histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{job="zamaz-api"}[5m])) by (le)) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Zamaz API high latency"
          description: "95th percentile latency is {{ $value }}s"
      
      - alert: ZamazPodCrashLooping
        expr: rate(kube_pod_container_status_restarts_total{namespace="zamaz-prod"}[15m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Pod is crash looping"
          description: "Pod {{ $labels.pod }} in namespace {{ $labels.namespace }} is restarting"
```

## Security Considerations

### 1. Network Policies
```yaml
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: zamaz-api-netpol
  namespace: zamaz-prod
spec:
  podSelector:
    matchLabels:
      app: zamaz-api
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
          app: zamaz-frontend
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: zamaz-prod
    ports:
    - protocol: TCP
      port: 5432  # PostgreSQL
    - protocol: TCP
      port: 6379  # Redis
  - to: []  # Allow DNS
    ports:
    - protocol: UDP
      port: 53
```

### 2. Pod Security Standards
```yaml
# pod-security-policy.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: zamaz-psp
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
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
```

### 3. Secrets Management with External Secrets
```yaml
# external-secret.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: zamaz-secrets
  namespace: zamaz-prod
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: zamaz-app-secrets
    creationPolicy: Owner
  data:
  - secretKey: database-url
    remoteRef:
      key: zamaz/prod/database
      property: url
  - secretKey: jwt-secret
    remoteRef:
      key: zamaz/prod/auth
      property: jwt_secret
```

## Troubleshooting

### 1. Common Issues

#### Pod Startup Issues
```bash
# Check pod status
kubectl get pods -n zamaz-prod

# Describe pod for events
kubectl describe pod <pod-name> -n zamaz-prod

# Check logs
kubectl logs <pod-name> -n zamaz-prod -f

# Check previous container logs
kubectl logs <pod-name> -n zamaz-prod --previous
```

#### Database Connection Issues
```bash
# Test database connectivity
kubectl run --rm -it --restart=Never postgres-client \
  --image=postgres:15 \
  --namespace=zamaz-prod \
  -- psql -h postgresql.zamaz-prod.svc.cluster.local -U zamaz_user -d zamaz_prod

# Check service endpoints
kubectl get endpoints -n zamaz-prod
```

#### Load Balancer Issues
```bash
# Check ingress status
kubectl get ingress -n zamaz-prod
kubectl describe ingress zamaz-ingress -n zamaz-prod

# Check service status
kubectl get svc -n zamaz-prod
kubectl describe svc zamaz-api -n zamaz-prod
```

### 2. Performance Debugging
```bash
# Resource usage
kubectl top pods -n zamaz-prod
kubectl top nodes

# HPA status
kubectl get hpa -n zamaz-prod
kubectl describe hpa zamaz-app-hpa -n zamaz-prod

# Check metrics server
kubectl get --raw "/apis/metrics.k8s.io/v1beta1/pods"
```

### 3. Emergency Procedures

#### Rollback Deployment
```bash
# Check rollout history
kubectl rollout history deployment/zamaz-app -n zamaz-prod

# Rollback to previous version
kubectl rollout undo deployment/zamaz-app -n zamaz-prod

# Rollback to specific revision
kubectl rollout undo deployment/zamaz-app --to-revision=2 -n zamaz-prod
```

#### Scale Down/Up
```bash
# Emergency scale down
kubectl scale deployment zamaz-app --replicas=0 -n zamaz-prod

# Scale back up
kubectl scale deployment zamaz-app --replicas=3 -n zamaz-prod
```

#### Circuit Breaker
```bash
# Block all traffic (emergency)
kubectl patch service zamaz-api -n zamaz-prod \
  -p '{"spec":{"selector":{"app":"maintenance"}}}'

# Restore traffic
kubectl patch service zamaz-api -n zamaz-prod \
  -p '{"spec":{"selector":{"app":"zamaz-api"}}}'
```

## Next Steps

1. **Infrastructure Setup**: Start with Terraform to provision cloud resources
2. **Base Deployment**: Deploy to staging environment first
3. **Monitoring Setup**: Configure observability stack
4. **Security Hardening**: Implement network policies and security standards
5. **Load Testing**: Validate performance under load
6. **Disaster Recovery**: Set up backup and recovery procedures
7. **Documentation**: Create runbooks for operations team

For additional support, refer to:
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Istio Documentation](https://istio.io/latest/docs/)
- [Helm Charts Repository](https://artifacthub.io/)
- [Cloud Provider Specific Guides](https://cloud.google.com/kubernetes-engine/docs)