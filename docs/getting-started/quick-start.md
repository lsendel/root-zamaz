# Quick Start Guide

Get the Zamaz Zero Trust Platform running in your environment within minutes.

## Prerequisites

Before you begin, ensure you have the following installed:

=== "Development"
    
    - **Go 1.22+** - [Download Go](https://golang.org/dl/)
    - **Node.js 20+** - [Download Node.js](https://nodejs.org/)
    - **Docker** - [Install Docker](https://docs.docker.com/get-docker/)
    - **Make** - Usually pre-installed on Linux/macOS

=== "Production"
    
    - **Kubernetes 1.28+** - [Kubernetes Setup](https://kubernetes.io/docs/setup/)
    - **Helm 3.14+** - [Install Helm](https://helm.sh/docs/intro/install/)
    - **kubectl** - [Install kubectl](https://kubernetes.io/docs/tasks/tools/)

## Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/zamaz/root-zamaz.git
cd root-zamaz
```

### 2. Initial Setup

```bash
# Install dependencies and setup environment
make dev-setup

# Start all development services
make dev-up
```

This will start:

- **Authentication Server** on `http://localhost:8081`
- **Frontend Application** on `http://localhost:3000`  
- **API Gateway** on `http://localhost:8080`
- **PostgreSQL Database** on `localhost:5432`
- **Redis Cache** on `localhost:6379`

### 3. Verify Installation

```bash
# Check all services are running
make health-check

# Run tests
make test-all
```

### 4. Access the Platform

Open your browser and navigate to:

- **Frontend**: http://localhost:3000
- **API Documentation**: http://localhost:8080/swagger/
- **Health Check**: http://localhost:8080/health

## Production Deployment

### Kubernetes with Helm

```bash
# Add Helm repository
helm repo add zamaz https://charts.zamaz.io
helm repo update

# Install the platform
helm install zamaz-platform zamaz/zamaz \
  --namespace zamaz-system \
  --create-namespace \
  --values values-production.yaml
```

### GitOps Deployment

```bash
# Deploy Argo CD
kubectl apply -f deployments/argocd/

# Apply platform configuration
kubectl apply -f deployments/kubernetes/overlays/production/
```

## Docker Compose

For a complete local environment:

```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Database
DATABASE_URL=postgres://username:password@localhost:5432/zamaz
REDIS_URL=redis://localhost:6379

# Authentication
JWT_SECRET=your-jwt-secret-key
JWT_EXPIRY=24h

# Security
CORS_ALLOWED_ORIGINS=http://localhost:3000
ENABLE_AUTH=true

# Observability
PROMETHEUS_ENDPOINT=http://localhost:9090
JAEGER_ENDPOINT=http://localhost:14268
```

### Database Setup

```bash
# Run database migrations
make db-migrate

# Seed initial data
make db-seed
```

## Verification

### 1. Health Checks

```bash
# Check API health
curl http://localhost:8080/health

# Check authentication service
curl http://localhost:8081/health

# Check database connectivity
make db-ping
```

### 2. Authentication Test

```bash
# Register a new user
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com", 
    "password": "SecurePassword123!"
  }'

# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "SecurePassword123!"
  }'
```

## Next Steps

Now that you have Zamaz running:

1. **[Configure Authentication](../development/setup.md)** - Set up OAuth providers and security policies
2. **[Deploy to Production](../deployment/production.md)** - Production deployment guidelines  
3. **[Enable Observability](../architecture/observability.md)** - Set up monitoring and logging
4. **[API Integration](../api/README.md)** - Integrate with your applications

## Troubleshooting

### Common Issues

!!! bug "Port Already in Use"
    
    ```bash
    # Kill processes on required ports
    sudo lsof -ti:8080 | xargs kill -9
    sudo lsof -ti:3000 | xargs kill -9
    ```

!!! bug "Database Connection Failed"
    
    ```bash
    # Ensure PostgreSQL is running
    docker-compose up -d postgres
    
    # Check database logs
    docker-compose logs postgres
    ```

!!! bug "Frontend Build Failed"
    
    ```bash
    # Clean and reinstall dependencies
    cd frontend
    rm -rf node_modules package-lock.json
    npm install
    ```

### Getting Help

- 📖 Check the [Troubleshooting Guide](../troubleshooting.md)
- 🐛 Report issues on [GitHub](https://github.com/zamaz/root-zamaz/issues)
- 💬 Join our community discussions
- 📧 Contact support: support@zamaz.io