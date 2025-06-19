# Development Guide - MVP Zero Trust Authentication

This comprehensive guide provides everything developers need to contribute to, extend, or integrate with the MVP Zero Trust Authentication system. It covers architecture, development workflows, testing strategies, and deployment procedures.

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture Overview](#architecture-overview)
- [Development Environment](#development-environment)
- [Development Workflows](#development-workflows)
- [Testing Strategy](#testing-strategy)
- [SDK Development](#sdk-development)
- [API Documentation](#api-documentation)
- [Database Management](#database-management)
- [Monitoring & Observability](#monitoring--observability)
- [Security Guidelines](#security-guidelines)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [Contributing Guidelines](#contributing-guidelines)

## Quick Start

### Prerequisites

- **Go**: 1.23.8+ (with toolchain 1.23.10)
- **Node.js**: 18.20.4+ (see `.nvmrc`)
- **Docker**: 20.10+ with Docker Compose
- **Make**: For build automation
- **Git**: For version control

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/mvp/zerotrust-auth.git
cd zerotrust-auth

# Setup development environment
make dev-setup

# Start the development stack
make dev-up

# Verify installation
make dev-validate

# Run tests
make test-all

# Build everything
make build-all
```

### Quick Development Commands

```bash
# Development
make dev-up          # Start all services
make dev-down        # Stop all services
make dev-logs        # Follow all logs
make dev-frontend    # Start frontend dev server

# Testing
make test            # Run all tests
make test-integration # Run integration tests
make test-coverage   # Generate coverage reports

# Quality
make lint-all        # Run all linters
make security-scan   # Security vulnerability scan
make quality-gate    # Run quality checks

# Build
make build-all       # Build all components
make build-docker    # Build Docker images
```

## Architecture Overview

### System Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   API Gateway   │    │  Auth Service   │
│   (Vite/React)  │───▶│   (Envoy)      │───▶│   (Go/Fiber)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Monitoring    │    │    Message      │    │    Database     │
│ (Grafana/Prom)  │    │ Queue (NATS)    │    │ (PostgreSQL)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Caching       │    │   Identity      │    │    Logging      │
│   (Redis)       │    │  (SPIRE)        │    │   (Jaeger)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Key Design Principles

1. **Zero Trust Security**: Never trust, always verify
2. **Microservices**: Loosely coupled, independently deployable
3. **Observability First**: Comprehensive logging, metrics, and tracing
4. **API-First**: Well-defined interfaces and contracts
5. **Cloud Native**: Kubernetes-ready with service mesh support

### Directory Structure

```
root-zamaz/
├── cmd/                    # Application entrypoints
│   ├── server/            # Main auth server
│   └── ztcli/             # CLI tool
├── pkg/                   # Reusable packages
│   ├── auth/              # Authentication logic
│   ├── middleware/        # HTTP middleware
│   ├── observability/     # Logging, metrics, tracing
│   ├── messaging/         # NATS integration
│   └── sdk/               # SDK implementations
├── internal/              # Private application code
│   ├── handlers/          # HTTP handlers
│   ├── services/          # Business logic
│   └── models/            # Data models
├── frontend/              # Frontend application
├── deployments/           # Deployment configurations
├── tests/                 # Test suites
├── docs/                  # Documentation
└── scripts/               # Build and deployment scripts
```

## Development Environment

### Local Setup

The development environment uses Docker Compose to orchestrate all services:

```yaml
# docker-compose.yml (simplified)
services:
  auth-service:
    build: .
    ports: ["8080:8080"]
    depends_on: [postgres, redis, nats]
  
  postgres:
    image: postgres:15
    ports: ["5432:5432"]
  
  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]
  
  nats:
    image: nats:2.10-alpine
    ports: ["4222:4222"]
  
  # Observability stack
  prometheus: { ports: ["9090:9090"] }
  grafana: { ports: ["3000:3000"] }
  jaeger: { ports: ["16686:16686"] }
```

### Environment Variables

```bash
# Core Configuration
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=mvp_db
export DB_USER=mvp_user
export DB_PASSWORD=mvp_password

# Services
export NATS_URL=nats://localhost:4222
export REDIS_URL=redis://localhost:6379

# Security
export JWT_SECRET=your-jwt-secret
export API_KEY=your-api-key

# Development
export LOG_LEVEL=debug
export ENABLE_CORS=true
```

### Service URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| Auth API | http://localhost:8080 | API Key required |
| Frontend | http://localhost:3000 | - |
| Grafana | http://localhost:3000 | admin/admin |
| Prometheus | http://localhost:9090 | - |
| Jaeger | http://localhost:16686 | - |
| Postgres | localhost:5432 | mvp_user/mvp_password |
| Redis | localhost:6379 | - |
| NATS | localhost:4222 | - |

## Development Workflows

### Feature Development

```bash
# 1. Create feature branch
git checkout -b feature/new-authentication-method

# 2. Start development environment
make dev-up

# 3. Make changes and test iteratively
make test-go              # Run Go tests
make test-frontend        # Run frontend tests
make lint-all            # Check code quality

# 4. Run integration tests
make test-integration

# 5. Build and validate
make build-all
make quality-gate

# 6. Create pull request
git add .
git commit -m "feat: add new authentication method"
git push origin feature/new-authentication-method
```

### Code Quality Checks

```bash
# Comprehensive quality check
make quality-all

# Individual checks
make lint-go             # Go linting with golangci-lint
make lint-frontend       # Frontend linting with ESLint
make security-scan       # Security vulnerability scanning
make test-coverage       # Generate coverage reports
make deps-audit          # Dependency vulnerability check
```

### Database Migrations

```bash
# Create new migration
make db-migrate

# Reset database (development only)
make db-reset

# Backup database
make db-backup

# Restore database
make db-restore file=backup.sql
```

## Testing Strategy

### Test Pyramid

```
       ┌─────────────────────┐
       │    E2E Tests        │  ← Few, high-level integration tests
       │   (Playwright)      │
       └─────────────────────┘
     ┌───────────────────────────┐
     │   Integration Tests       │  ← API and component integration
     │   (Go + Jest)             │
     └───────────────────────────┘
   ┌─────────────────────────────────┐
   │      Unit Tests               │  ← Many, fast, isolated tests
   │   (Go test + Vitest)          │
   └─────────────────────────────────┘
```

### Running Tests

```bash
# All tests
make test-all

# By category
make test-go              # Go unit tests
make test-frontend        # Frontend unit tests  
make test-integration     # Integration tests
make test-e2e            # End-to-end tests
make test-load           # Load tests with k6

# With coverage
make test-coverage
make coverage-validate   # Enforce coverage thresholds

# Watch mode for development
make test-watch
```

### Test Configuration

**Go Tests:**
```go
// Example test structure
func TestAuthenticateUser(t *testing.T) {
    tests := []struct {
        name    string
        email   string
        password string
        want    *AuthResponse
        wantErr bool
    }{
        {
            name:     "valid credentials",
            email:    "user@example.com", 
            password: "validpassword",
            want:     &AuthResponse{Success: true},
            wantErr:  false,
        },
        // More test cases...
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

**Frontend Tests (Vitest):**
```typescript
// Example component test
describe('LoginForm', () => {
  test('submits valid credentials', async () => {
    const mockLogin = vi.fn()
    render(<LoginForm onLogin={mockLogin} />)
    
    await user.type(screen.getByLabelText(/email/i), 'user@example.com')
    await user.type(screen.getByLabelText(/password/i), 'password')
    await user.click(screen.getByRole('button', { name: /login/i }))
    
    expect(mockLogin).toHaveBeenCalledWith({
      email: 'user@example.com',
      password: 'password'
    })
  })
})
```

## SDK Development

### Go SDK

Location: `pkg/sdk/go/`

```go
// Example SDK usage
client, err := sdk.NewClient(sdk.Config{
    BaseURL: "https://auth.example.com",
    APIKey:  "your-api-key",
    Timeout: 30 * time.Second,
})

response, err := client.Authenticate(ctx, sdk.AuthenticationRequest{
    Email:    "user@example.com",
    Password: "password",
})
```

### JavaScript/TypeScript SDK

Location: `pkg/sdk/javascript/`

```typescript
// Example SDK usage
import { ZeroTrustClient } from '@mvp/zerotrust-sdk'

const client = new ZeroTrustClient({
  baseURL: 'https://auth.example.com',
  apiKey: 'your-api-key'
})

const response = await client.authenticate({
  email: 'user@example.com',
  password: 'password'
})
```

### Python SDK

Location: `pkg/sdk/python/`

```python
# Example SDK usage
from zerotrust_sdk import ZeroTrustClient

with ZeroTrustClient(
    base_url="https://auth.example.com",
    api_key="your-api-key"
) as client:
    response = client.authenticate("user@example.com", "password")
```

### SDK Development Commands

```bash
# Build all SDKs
make sdk-build-all

# Test SDKs
make sdk-test-all

# Generate SDK code
make dev-generate-all
```

## API Documentation

### API Endpoints

**Authentication:**
- `POST /api/v1/auth/login` - User authentication
- `POST /api/v1/auth/refresh` - Token refresh  
- `POST /api/v1/auth/logout` - User logout
- `POST /api/v1/auth/validate` - Token validation

**User Management:**
- `GET /api/v1/users/profile` - Get user profile
- `PUT /api/v1/users/profile` - Update user profile
- `GET /api/v1/admin/users` - List users (admin)
- `POST /api/v1/admin/users` - Create user (admin)

**System:**
- `GET /health` - Health check
- `GET /health/ready` - Readiness probe
- `GET /health/live` - Liveness probe
- `GET /metrics` - Prometheus metrics

### Request/Response Examples

**Login Request:**
```json
POST /api/v1/auth/login
{
  "email": "user@example.com",
  "password": "securepassword",
  "remember": true
}
```

**Login Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
  "expires_at": "2024-12-31T23:59:59Z",
  "token_type": "Bearer",
  "user": {
    "id": "user-123",
    "email": "user@example.com",
    "display_name": "John Doe",
    "roles": ["user"]
  },
  "trust_score": 0.95
}
```

### CLI Tool

```bash
# Authentication
ztcli auth login user@example.com
ztcli auth logout
ztcli auth refresh <refresh_token>

# Token operations
ztcli token validate <access_token>
ztcli token introspect <access_token>

# User management
ztcli user list
ztcli user create --email user@example.com --role admin
ztcli user show <user_id>

# System administration
ztcli system health
ztcli system status
ztcli system config

# Development utilities
ztcli dev generate-key
ztcli dev test-connection
ztcli dev generate-client --lang go
```

## Database Management

### Schema Management

```bash
# Run migrations
make db-migrate

# Create new migration
migrate create -ext sql -dir migrations -seq add_user_table

# Check migration status
migrate -path migrations -database "$DATABASE_URL" version
```

### Database Operations

```bash
# Development
make db-reset           # Reset to clean state
make db-seed            # Load test data

# Backup and restore
make db-backup
make db-restore file=backup.sql

# Performance
make db-optimize-dev    # Development optimizations
make db-benchmark       # Performance testing
make db-analyze         # Query analysis
```

### Schema Overview

```sql
-- Core tables
users              -- User accounts and profiles
user_sessions       -- Active user sessions  
refresh_tokens      -- Refresh token storage
audit_logs         -- Security audit trail
rate_limits        -- Rate limiting data
mfa_tokens         -- Multi-factor auth tokens

-- Indexes for performance
idx_users_email             -- Fast user lookup
idx_sessions_user_id        -- Session queries
idx_audit_logs_timestamp    -- Audit queries
idx_rate_limits_key         -- Rate limit checks
```

## Monitoring & Observability

### Metrics

Key metrics tracked:
- **Authentication**: Login success/failure rates, MFA usage
- **Performance**: Request latency, throughput, error rates
- **Security**: Failed login attempts, suspicious activity
- **System**: CPU, memory, database connections

### Logging

```go
// Structured logging example
logger.Info().
    Str("user_id", userID).
    Str("operation", "login").
    Float64("trust_score", trustScore).
    Dur("duration", duration).
    Msg("User authentication successful")
```

### Tracing

Distributed tracing with OpenTelemetry:

```go
// Tracing example
ctx, span := tracer.Start(ctx, "authenticate_user")
defer span.End()

span.SetAttributes(
    attribute.String("user.email", email),
    attribute.String("auth.method", "password"),
)
```

### Monitoring Commands

```bash
# Setup monitoring
make monitoring-setup

# Check status
make monitor-status

# View logs
make monitor-logs

# Access dashboards
open http://localhost:3000  # Grafana
open http://localhost:9090  # Prometheus  
open http://localhost:16686 # Jaeger
```

## Security Guidelines

### Authentication Security

1. **Password Requirements**
   - Minimum 8 characters
   - Must include uppercase, lowercase, number
   - No common passwords (dictionary check)
   - Regular password rotation prompts

2. **Token Security**
   - Short-lived access tokens (1 hour)
   - Longer refresh tokens (7 days)
   - Token rotation on refresh
   - Secure storage requirements

3. **Multi-Factor Authentication**
   - TOTP support (Google Authenticator)
   - SMS backup option
   - Recovery codes
   - Admin enforcement policies

### API Security

```go
// Rate limiting example
limiter := middleware.NewRateLimiter(middleware.Config{
    Max:      100,
    Duration: time.Minute,
    KeyFunc: func(c *fiber.Ctx) string {
        return c.IP() + ":" + c.Get("User-Agent")
    },
})
```

### Security Testing

```bash
# Security scans
make security-scan           # Vulnerability scanning
make security-audit          # Dependency audit
make security-install        # Install security tools

# Penetration testing
make test-security          # Security test suite
```

## Deployment

### Local Development

```bash
# Full development stack
make dev-up

# Individual services
docker-compose up postgres redis nats
go run cmd/server/main.go
```

### Docker Deployment

```bash
# Build images
make build-docker

# Deploy with compose
docker-compose -f docker-compose.prod.yml up -d
```

### Kubernetes Deployment

```bash
# Deploy to local cluster
make deploy-local

# Production deployment
kubectl apply -f deployments/kubernetes/
```

### Cloud Deployment

**AWS:**
```bash
# Using Terraform
cd deployments/terraform/aws
terraform init
terraform plan
terraform apply
```

**GCP:**
```bash
# Using Cloud Run
gcloud run deploy auth-service \
  --image gcr.io/project/auth-service \
  --platform managed \
  --region us-central1
```

## Troubleshooting

### Common Issues

**Database Connection Issues:**
```bash
# Check database connectivity
make db-health
psql -h localhost -U mvp_user -d mvp_db

# Reset database
make db-reset
```

**Service Discovery Issues:**
```bash
# Check service health
curl http://localhost:8080/health

# Check logs
make dev-logs
docker-compose logs auth-service
```

**Authentication Failures:**
```bash
# Test token validation
ztcli token validate <token>

# Check JWT secret
echo $JWT_SECRET

# Verify API key
curl -H "X-API-Key: $API_KEY" http://localhost:8080/health
```

### Debug Commands

```bash
# Enable debug logging
export LOG_LEVEL=debug
make dev-up

# Run with debugger
dlv debug cmd/server/main.go

# Profile performance
go tool pprof http://localhost:8080/debug/pprof/profile
```

### Log Analysis

```bash
# Filter logs by level
make dev-logs | grep ERROR

# Search for specific events  
make dev-logs | grep "authentication failed"

# Follow specific service
docker-compose logs -f auth-service
```

## Contributing Guidelines

### Code Standards

**Go Code:**
- Follow effective Go guidelines
- Use gofmt and goimports
- Write comprehensive tests
- Document public APIs

**Frontend Code:**
- Use TypeScript for type safety
- Follow React best practices
- Write component tests
- Use ESLint and Prettier

### Pull Request Process

1. **Create Feature Branch**
   ```bash
   git checkout -b feature/description
   ```

2. **Development**
   - Write code following standards
   - Add comprehensive tests
   - Update documentation

3. **Quality Checks**
   ```bash
   make quality-gate
   make test-all
   ```

4. **Pull Request**
   - Clear description of changes
   - Reference related issues
   - Include test results

### Code Review Checklist

- [ ] Code follows style guidelines
- [ ] Tests are comprehensive
- [ ] Documentation is updated
- [ ] Security considerations addressed
- [ ] Performance impact assessed
- [ ] Breaking changes documented

### Release Process

```bash
# Create release branch
git checkout -b release/v1.2.0

# Update version numbers
# Update CHANGELOG.md
# Create release tag
git tag -a v1.2.0 -m "Release v1.2.0"

# Push release
git push origin release/v1.2.0
git push origin v1.2.0
```

## Additional Resources

- [SDK Documentation](./sdk/) - Detailed SDK guides
- [Examples](./examples/) - Integration examples
- [CLI Documentation](./cli/) - CLI tool usage
- [API Reference](./api/) - Complete API documentation
- [Architecture Decision Records](./adr/) - Design decisions
- [Deployment Guides](./deployment/) - Platform-specific guides

For questions or support, please:
1. Check this documentation
2. Search existing issues
3. Create a new issue with detailed information
4. Join our community discussions

---

*This guide is continuously updated. Please refer to the latest version for current procedures.*