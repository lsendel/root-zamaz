# Zero Trust Authentication MVP

A comprehensive Zero Trust Authentication system built with Go, featuring microservices architecture, comprehensive observability, and modern security practices.

## 🌟 Features

### Core Authentication
- **JWT-based Authentication** with refresh tokens
- **Role-Based Access Control (RBAC)** using Casbin
- **Device Attestation** for Zero Trust verification
- **Multi-factor Authentication** ready
- **Session Management** with Redis caching

### Security & Zero Trust
- **SPIFFE/SPIRE Integration** for workload identity
- **Mutual TLS (mTLS)** support via Envoy proxy
- **Device Trust Verification** with configurable trust levels
- **Audit Logging** for all security events
- **Rate Limiting** and security headers

### Observability
- **Distributed Tracing** with Jaeger
- **Metrics Collection** with Prometheus
- **Structured Logging** with zerolog
- **Performance Monitoring** with OpenTelemetry
- **Business Metrics** tracking
- **Health Checks** and system monitoring

### Architecture
- **Microservices Ready** with clean architecture
- **API-First Design** with Swagger documentation
- **Event-Driven** with NATS messaging
- **Container Native** with Docker and Kubernetes support
- **Frontend Integration** with React TypeScript SPA

## 🚀 Quick Start

### Prerequisites
- Go 1.23+
- Docker & Docker Compose
- Node.js 18+ (for frontend)
- Make utility

### 1. Clone and Setup
```bash
git clone <repository-url>
cd root-zamaz
make dev-setup
```

### 2. Start Development Environment
```bash
# Start all infrastructure services
make dev-up

# In another terminal, start the frontend
make dev-frontend
```

### 3. Access Services
- **Frontend**: http://localhost:5175
- **API**: http://localhost:8080
- **Swagger UI**: http://localhost:8080/swagger/index.html
- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090
- **Jaeger**: http://localhost:16686

### 4. Default Login
```
Username: admin
Password: password
```

## 📖 Documentation

### Development
- [Development Setup](docs/development/setup.md)
- [Build System](examples/build-examples.md)
- [Testing Guide](docs/development/testing.md)
- [Contributing Guidelines](docs/development/contributing.md)

### API Documentation
- [Swagger UI](http://localhost:8080/swagger/index.html) (when running)
- [API Reference](docs/api/README.md)
- [Authentication Flow](docs/api/authentication.md)
- [Device Management](docs/api/devices.md)

### Deployment
- [Docker Deployment](docs/deployment/docker.md)
- [Kubernetes Deployment](docs/deployment/kubernetes.md)
- [Production Configuration](docs/deployment/production.md)
- [Security Hardening](docs/deployment/security.md)

### Architecture
- [System Architecture](docs/architecture/overview.md)
- [Security Model](docs/architecture/security.md)
- [Observability Design](docs/architecture/observability.md)
- [Zero Trust Implementation](docs/architecture/zero-trust.md)

## 🏗️ Architecture Overview

```mermaid
graph TB
    Client[Web Client/SPA] --> Envoy[Envoy Proxy]
    Envoy --> Auth[Auth Service]
    Auth --> DB[(PostgreSQL)]
    Auth --> Redis[(Redis Cache)]
    Auth --> NATS[NATS Messaging]
    
    subgraph "Zero Trust"
        SPIRE[SPIRE Server]
        Agent[SPIRE Agent]
        SPIRE --> Agent
    end
    
    subgraph "Observability"
        Jaeger[Jaeger Tracing]
        Prometheus[Prometheus Metrics]
        Grafana[Grafana Dashboards]
        Loki[Loki Logs]
    end
    
    Auth --> Jaeger
    Auth --> Prometheus
    Envoy --> Agent
```

## 🛠️ Development

### Available Commands
```bash
# Development
make dev-setup          # Initial setup
make dev-up             # Start infrastructure
make dev-down           # Stop infrastructure
make dev-frontend       # Start frontend dev server

# Building
make build              # Full build (backend + frontend + Docker)
make build-server       # Quick server build
make run-server         # Build and run server

# Testing
make test               # Run unit tests
make test-integration   # Run integration tests
make test-load          # Run load tests
make test-coverage      # Generate coverage report

# Quality
make lint               # Run linters
make fmt                # Format code
make security-scan      # Security scanning
make quality-check      # All quality checks

# Deployment
make deploy-local       # Deploy to local Kubernetes
make clean              # Clean up containers and volumes
```

### Project Structure
```
root-zamaz/
├── cmd/server/           # Main application entry point
├── pkg/                  # Core packages
│   ├── auth/            # Authentication & authorization
│   ├── handlers/        # HTTP handlers
│   ├── middleware/      # HTTP middleware
│   ├── models/          # Data models
│   ├── database/        # Database layer
│   ├── observability/   # Metrics, tracing, logging
│   └── config/          # Configuration management
├── frontend/            # React TypeScript SPA
├── deployments/         # Kubernetes manifests
├── envoy/              # Envoy proxy configuration
├── observability/      # Monitoring configuration
├── scripts/            # Build and deployment scripts
└── tests/              # Integration and E2E tests
```

## 🔒 Security Features

### Authentication & Authorization
- **JWT Tokens** with configurable expiration
- **Refresh Token** rotation
- **Role-Based Permissions** with Casbin
- **Device-Based Authentication**
- **Admin User Management**

### Zero Trust Implementation
- **Device Attestation** with trust levels
- **Workload Identity** via SPIFFE/SPIRE
- **Mutual TLS** for service-to-service communication
- **Certificate-Based Authentication**
- **Continuous Verification**

### Security Monitoring
- **Audit Logging** for all authentication events
- **Failed Login Tracking**
- **Device Registration Monitoring**
- **Permission Change Alerts**
- **Security Metrics** collection

## 📊 Observability Stack

### Metrics (Prometheus)
- **Business Metrics**: Login rates, device registrations
- **Performance Metrics**: Response times, throughput
- **Security Metrics**: Failed authentications, suspicious activities
- **System Metrics**: Resource usage, health status

### Tracing (Jaeger)
- **Request Tracing** across all services
- **Performance Analysis** with detailed spans
- **Error Tracking** with stack traces
- **Dependency Mapping**

### Logging (Loki)
- **Structured Logging** with zerolog
- **Centralized Log Aggregation**
- **Log Correlation** with trace IDs
- **Security Event Logging**

### Dashboards (Grafana)
- **Business KPIs**: User activity, system usage
- **Performance Monitoring**: Latency, errors, saturation
- **Security Dashboard**: Authentication events, threats
- **Infrastructure Health**: Service status, resource usage

## 🚀 Deployment Options

### Docker Compose (Development)
```bash
make dev-up  # Starts all services locally
```

### Docker (Production)
```bash
docker build -t mvp-auth:latest .
docker run -d -p 8080:8080 mvp-auth:latest
```

### Kubernetes (Production)
```bash
kubectl apply -k deployments/kubernetes/overlays/production/
```

### Local Binary
```bash
make build-server
./bin/server --config=configs/production.yaml
```

## 🧪 Testing

### Test Suites
- **Unit Tests**: `make test`
- **Integration Tests**: `make test-integration`
- **E2E Tests**: `npm run test:e2e` (in frontend/)
- **Load Tests**: `make test-load`
- **Security Tests**: `make security-scan`

### Test Coverage
- Target: 80% minimum coverage
- Check: `make check-coverage`
- Report: Generated at `coverage.html`

### E2E Testing
- **Playwright-based** browser testing
- **Multi-browser** support (Chrome, Firefox, Safari)
- **Visual Regression** testing with screenshots
- **Authentication Flows** testing

## 🔧 Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=postgres://user:pass@localhost:5432/mvp_db

# Redis
REDIS_URL=redis://localhost:6379

# JWT
JWT_SECRET=your-secret-key
JWT_EXPIRATION=24h

# Observability
JAEGER_ENDPOINT=http://localhost:14268/api/traces
PROMETHEUS_PORT=9000

# Security
CORS_ALLOWED_ORIGINS=http://localhost:5175
DISABLE_AUTH=false
```

### Configuration Files
- `configs/development.yaml` - Development settings
- `configs/production.yaml` - Production settings
- `configs/rbac_model.conf` - RBAC model definition
- `configs/rbac_policy.csv` - RBAC policies

## 🐛 Troubleshooting

### Common Issues

#### Database Connection Failed
```bash
# Check if PostgreSQL is running
make dev-up
docker ps | grep postgres

# Reset database
make db-reset
```

#### Frontend Build Errors
```bash
# Clean and reinstall dependencies
cd frontend
rm -rf node_modules package-lock.json
npm install
npm run build
```

#### Docker Build Issues
```bash
# Clean Docker cache
docker system prune -f
make clean
make build
```

#### Authentication Issues
```bash
# Check server logs
docker logs mvp-zero-trust-auth-envoy-1

# Verify JWT configuration
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'
```

### Debug Mode
```bash
# Enable debug logging
export LOG_LEVEL=debug
make run-server

# Enable SQL query logging
export DB_LOG_LEVEL=debug
```

## 🤝 Contributing

### Development Workflow
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Make changes and add tests
4. Run quality checks: `make quality-check`
5. Commit with conventional commits
6. Push and create a Pull Request

### Code Standards
- **Go**: Follow `go fmt` and `golangci-lint`
- **Frontend**: ESLint and Prettier configured
- **Git**: Conventional commit messages
- **Testing**: Minimum 80% coverage required

### Pull Request Process
1. Ensure all tests pass
2. Update documentation if needed
3. Add changelog entry
4. Request review from maintainers

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙋‍♂️ Support

### Documentation
- [API Documentation](http://localhost:8080/swagger/index.html)
- [Architecture Docs](docs/architecture/)
- [Deployment Guides](docs/deployment/)

### Community
- [Issues](https://github.com/your-org/mvp-zero-trust-auth/issues)
- [Discussions](https://github.com/your-org/mvp-zero-trust-auth/discussions)
- [Contributing Guide](docs/development/contributing.md)

### Commercial Support
For commercial support and enterprise features, contact: support@example.com

---

**Built with ❤️ for Zero Trust Security**