# Installation Guide

Complete installation guide for the Zamaz Zero Trust Platform across different environments.

## :package: Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 2 cores | 4+ cores |
| **Memory** | 4 GB RAM | 8+ GB RAM |
| **Storage** | 20 GB | 50+ GB |
| **OS** | Linux/macOS/Windows | Ubuntu 22.04+ |

### Required Tools

=== "Development"

    ```bash
    # Core development tools
    go version         # Go 1.22+
    node --version     # Node.js 20+
    docker --version   # Docker 24+
    make --version     # GNU Make 4+
    git --version      # Git 2.40+
    ```

=== "Production"

    ```bash
    # Kubernetes cluster tools
    kubectl version    # kubectl 1.28+
    helm version       # Helm 3.14+
    istioctl version   # Istio 1.20+
    
    # Optional but recommended
    k9s version        # Kubernetes UI
    stern --version    # Log tailing
    ```

## :rocket: Installation Methods

### Method 1: Development Environment

Perfect for local development and testing:

```bash
# 1. Clone repository
git clone https://github.com/zamaz/root-zamaz.git
cd root-zamaz

# 2. Setup development environment
make dev-setup

# 3. Start all services
make dev-up

# 4. Verify installation
make health-check
```

### Method 2: Docker Compose

Quick setup with Docker:

```bash
# 1. Clone and navigate
git clone https://github.com/zamaz/root-zamaz.git
cd root-zamaz

# 2. Configure environment
cp .env.example .env
# Edit .env with your configuration

# 3. Start services
docker-compose up -d

# 4. Check status
docker-compose ps
```

### Method 3: Kubernetes Production

Full production deployment:

```bash
# 1. Add Helm repository
helm repo add zamaz https://charts.zamaz.io
helm repo update

# 2. Create namespace
kubectl create namespace zamaz-system

# 3. Install with custom values
helm install zamaz-platform zamaz/zamaz \
  --namespace zamaz-system \
  --values values-production.yaml \
  --wait --timeout=10m

# 4. Verify deployment
kubectl get pods -n zamaz-system
```

### Method 4: GitOps with Argo CD

Automated GitOps deployment:

```bash
# 1. Install Argo CD
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# 2. Deploy Zamaz application
kubectl apply -f deployments/argocd/application.yaml

# 3. Access Argo CD UI
kubectl port-forward svc/argocd-server -n argocd 8080:443
```

## :gear: Configuration

### Environment Variables

Create `.env` file with required configuration:

```bash
# =============================================================================
# ZAMAZ ZERO TRUST PLATFORM CONFIGURATION
# =============================================================================

# Database Configuration
DATABASE_URL=postgres://zamaz:secure_password@localhost:5432/zamaz_db
DATABASE_MAX_CONNECTIONS=25
DATABASE_TIMEOUT=30s

# Redis Configuration  
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=secure_redis_password
REDIS_DB=0

# Authentication & Security
JWT_SECRET=your-super-secure-jwt-secret-key-min-32-chars
JWT_EXPIRY=24h
JWT_REFRESH_EXPIRY=168h  # 7 days

# Encryption
ENCRYPTION_KEY=32-character-encryption-key-here

# CORS Configuration
CORS_ALLOWED_ORIGINS=http://localhost:3000,https://app.zamaz.io
CORS_ALLOWED_METHODS=GET,POST,PUT,DELETE,OPTIONS
CORS_ALLOWED_HEADERS=Content-Type,Authorization

# Server Configuration
HTTP_PORT=8080
HTTP_HOST=0.0.0.0
HTTPS_PORT=8443
TLS_CERT_FILE=/etc/certs/tls.crt
TLS_KEY_FILE=/etc/certs/tls.key

# Feature Flags
ENABLE_AUTH=true
ENABLE_RATE_LIMITING=true
ENABLE_OBSERVABILITY=true
ENABLE_AUDIT_LOGGING=true

# Observability
PROMETHEUS_ENDPOINT=http://localhost:9090
JAEGER_ENDPOINT=http://localhost:14268/api/traces
LOKI_ENDPOINT=http://localhost:3100

# Service Discovery
CONSUL_ENDPOINT=http://localhost:8500
SERVICE_NAME=zamaz-auth
SERVICE_PORT=8080

# External Services
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=notifications@zamaz.io
SMTP_PASSWORD=smtp_app_password

# Development/Debug
LOG_LEVEL=info
DEBUG=false
ENVIRONMENT=production
```

### Kubernetes Values

For Helm deployments, customize `values-production.yaml`:

```yaml
# Global configuration
global:
  environment: production
  domain: zamaz.io
  tlsSecretName: zamaz-tls

# Application configuration
app:
  replicaCount: 3
  image:
    repository: zamaz/root-zamaz
    tag: "v1.0.0"
    pullPolicy: IfNotPresent
  
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: 1000m
      memory: 1Gi

# Database configuration
postgresql:
  enabled: true
  auth:
    database: zamaz_db
    username: zamaz
    existingSecret: zamaz-db-secret
  primary:
    persistence:
      size: 100Gi
      storageClass: fast-ssd

# Redis configuration
redis:
  enabled: true
  auth:
    enabled: true
    existingSecret: zamaz-redis-secret
  master:
    persistence:
      size: 50Gi

# Istio configuration
istio:
  enabled: true
  gateway:
    hosts:
      - zamaz.io
      - api.zamaz.io
```

## :shield: Security Setup

### TLS Certificates

Generate TLS certificates for secure communication:

```bash
# Development (self-signed)
make generate-certs

# Production (Let's Encrypt with cert-manager)
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@zamaz.io
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: istio
EOF
```

### Secrets Management

Create required Kubernetes secrets:

```bash
# Database credentials
kubectl create secret generic zamaz-db-secret \
  --from-literal=password='secure_db_password' \
  --namespace zamaz-system

# Application secrets
kubectl create secret generic zamaz-app-secrets \
  --from-literal=jwt-secret='your-jwt-secret-key' \
  --from-literal=encryption-key='32-char-encryption-key' \
  --namespace zamaz-system

# Redis credentials
kubectl create secret generic zamaz-redis-secret \
  --from-literal=password='secure_redis_password' \
  --namespace zamaz-system
```

## :white_check_mark: Verification

### Health Checks

Verify all components are running correctly:

```bash
# Check application health
curl http://localhost:8080/health

# Check authentication service
curl http://localhost:8081/health

# Check database connectivity
make db-ping

# Check all services (Docker Compose)
docker-compose ps

# Check Kubernetes deployment
kubectl get pods -n zamaz-system
kubectl get svc -n zamaz-system
kubectl get ingress -n zamaz-system
```

### Functional Tests

Run comprehensive tests to verify functionality:

```bash
# Unit tests
make test-go

# Integration tests  
make test-integration

# End-to-end tests
make test-e2e

# Load tests
make test-load
```

## :wrench: Troubleshooting

### Common Issues

!!! bug "Port Already in Use"
    
    **Problem**: Service fails to start due to port conflict
    
    **Solution**:
    ```bash
    # Find and kill process using port
    sudo lsof -ti:8080 | xargs kill -9
    
    # Or use different port
    export HTTP_PORT=8081
    ```

!!! bug "Database Connection Failed"
    
    **Problem**: Cannot connect to PostgreSQL
    
    **Solution**:
    ```bash
    # Check database is running
    docker-compose ps postgres
    
    # Check credentials
    psql $DATABASE_URL -c "SELECT 1;"
    
    # Reset database
    make db-reset
    ```

!!! bug "Permission Denied"
    
    **Problem**: Docker permission issues
    
    **Solution**:
    ```bash
    # Add user to docker group
    sudo usermod -aG docker $USER
    newgrp docker
    
    # Or use sudo
    sudo docker-compose up -d
    ```

### Log Analysis

View logs for debugging:

```bash
# Application logs
make logs

# Specific service logs
docker-compose logs auth-service

# Kubernetes logs
kubectl logs -f deployment/zamaz-auth -n zamaz-system

# Follow logs from multiple pods
stern zamaz -n zamaz-system
```

## :arrow_forward: Next Steps

After successful installation:

1. **[Quick Start Guide](quick-start.md)** - Get familiar with basic operations
2. **[Configuration Guide](configuration.md)** - Customize for your environment  
3. **[Security Setup](../security/README.md)** - Implement security best practices
4. **[API Documentation](../api/README.md)** - Integrate with your applications
5. **[Monitoring Setup](../architecture/observability.md)** - Enable comprehensive monitoring

## :sos: Getting Help

If you encounter issues:

- 📖 Check the [Troubleshooting Guide](../troubleshooting.md)
- 🐛 Search [GitHub Issues](https://github.com/zamaz/root-zamaz/issues)
- 💬 Ask in [GitHub Discussions](https://github.com/zamaz/root-zamaz/discussions)
- 📧 Contact support: support@zamaz.io