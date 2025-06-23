# Go Component System - 2025 Best Practices Demo

## 🎯 **Overview**

This demonstrates a comprehensive Go component system following 2025 best practices, inspired by Maven's component management approach. The system provides environment-ready templates for first-time setup with zero-trust authentication integration.

## 🏗️ **Architecture & Features**

### **Maven-Style Component Definitions**
```yaml
apiVersion: v1
kind: ComponentDefinition
metadata:
  name: "zerotrust-service"
  version: "1.0.0"
  description: "Zero Trust authentication service with modern Go practices"
  
spec:
  type: "service"
  module:
    name: "github.com/lsendel/zerotrust-service"
    goVersion: "1.21"
  dependencies:
    required:
      - name: "github.com/gin-gonic/gin"
        version: "v1.10.1"
```

### **Go 2025 Best Practices**
- ✅ **Structured Logging**: `log/slog` for modern logging
- ✅ **Context-Aware**: Context throughout the application
- ✅ **Graceful Shutdown**: Proper signal handling and cleanup
- ✅ **Health Checks**: Built-in health and readiness endpoints
- ✅ **Metrics**: Prometheus metrics integration
- ✅ **Configuration Management**: Environment-based config with validation
- ✅ **Security-First**: Security scanning and best practices built-in
- ✅ **Container Ready**: Multi-stage Dockerfiles with security
- ✅ **Observability**: Logging, metrics, and tracing ready

### **Environment-Ready From First Time**
- 🚀 **Zero Configuration**: Works out of the box
- 🔧 **Environment Variables**: Comprehensive .env support
- 🐳 **Docker Compose**: Complete service orchestration
- ☸️ **Kubernetes Ready**: Deployment manifests included
- 📊 **Monitoring Stack**: Prometheus, Grafana, Jaeger ready
- 🔐 **Security**: Keycloak integration with proper ports
- 🧪 **Testing**: Unit, integration, and E2E tests

## 📁 **Component Templates**

### **1. Component Definition Template**
```yaml
# File: templates/component.yaml
apiVersion: v1
kind: ComponentDefinition
metadata:
  name: "{{ .ComponentName }}"
  version: "{{ .Version }}"

spec:
  type: "{{ .ComponentType }}"
  module:
    name: "{{ .ModuleName }}"
    goVersion: "{{ .GoVersion }}"
  
  dependencies:
    required: [...]
  
  build:
    tags: [...]
    cgo:
      enabled: {{ .CgoEnabled }}
  
  runtime:
    environment: [...]
    health:
      endpoint: "{{ .HealthEndpoint }}"
      
  security:
    scan:
      enabled: {{ .SecurityScanEnabled }}
      tools: [...]
      
  observability:
    metrics:
      enabled: {{ .MetricsEnabled }}
    logging:
      format: "{{ .LogFormat }}"
    tracing:
      enabled: {{ .TracingEnabled }}
```

### **2. Main Application Template**
```go
// File: templates/main.go.tmpl
package main

import (
    "context"
    "log/slog"
    "net/http"
    "os/signal"
    "syscall"
    "time"
)

type Application struct {
    config *Config
    server *http.Server
    logger *slog.Logger
}

func (a *Application) Run(ctx context.Context) error {
    ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
    defer cancel()
    
    // Graceful shutdown with timeout
    shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer shutdownCancel()
    
    return a.server.Shutdown(shutdownCtx)
}
```

### **3. Dockerfile Template**
```dockerfile
# File: templates/dockerfile.tmpl
FROM golang:{{ .GoVersion }}-alpine AS builder

RUN adduser -D -s /bin/sh -u 1001 appuser
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED={{ .CgoEnabled }} go build \
    -ldflags="-w -s -X main.version={{ .Version }}" \
    -o {{ .BinaryName }} {{ .BuildPath }}

FROM alpine:{{ .AlpineVersion }} AS runtime
RUN apk add --no-cache ca-certificates tzdata curl
RUN adduser -D -s /bin/sh -u 1001 appuser

USER appuser
WORKDIR /app
COPY --from=builder --chown=appuser:appuser /build/{{ .BinaryName }} ./

HEALTHCHECK --interval={{ .HealthInterval }} \
    CMD curl -f http://localhost:${PORT}/health || exit 1

EXPOSE {{ .DefaultPort }}
ENTRYPOINT ["./{{ .BinaryName }}"]
```

## 🔧 **Component Generator**

### **Usage**
```bash
# Generate new component
./bin/component-generator \
    -config examples/zerotrust-service.yaml \
    -output /path/to/new-project \
    -templates ./templates \
    -verbose

# Output structure:
├── cmd/server/main.go       # Application entry point
├── internal/               # Private application code
├── pkg/                    # Public library code
├── api/                    # API definitions
├── configs/                # Configuration files
├── deployments/            # Kubernetes manifests
├── .github/workflows/      # CI/CD pipelines
├── go.mod                  # Go module definition
├── Dockerfile              # Container definition
├── docker-compose.yml      # Local development
├── README.md               # Documentation
└── component.yaml          # Component definition
```

## 🎮 **Live Demo: impl-zamaz**

### **Current Status**
```bash
# Application Health
$ curl http://localhost:8080/health
{
  "service": "impl-zamaz",
  "status": "healthy",
  "timestamp": "2025-06-22T22:49:51.455622672Z",
  "version": "1.0.0"
}

# Application Info
$ curl http://localhost:8080/info
{
  "name": "impl-zamaz Zero Trust Demo",
  "description": "Zero Trust authentication implementation",
  "features": [
    "JWT token validation",
    "Trust level authorization",
    "Device verification",
    "Risk assessment",
    "Continuous verification"
  ]
}

# Public API
$ curl http://localhost:8080/api/public
{
  "endpoint": "/api/public",
  "message": "This is public data accessible to authenticated users",
  "requirement": "Basic authentication demo"
}
```

### **Service Architecture**
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │    │    Keycloak     │    │   PostgreSQL    │
│   localhost:8080│────│ localhost:8082  │────│ localhost:5433  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                       ┌─────────────────┐
                       │     Redis       │
                       │ localhost:6380  │
                       └─────────────────┘
```

### **Configuration Management**
```bash
# Environment File: .env
APP_PORT=8080
KEYCLOAK_BASE_URL=http://localhost:8082
KEYCLOAK_REALM=zerotrust-test
POSTGRES_PORT=5433
REDIS_PORT=6380

# Docker Compose Integration
services:
  app:
    ports:
      - "${APP_PORT:-8080}:8080"
    environment:
      - KEYCLOAK_BASE_URL=http://keycloak:8080
      - REDIS_URL=redis://redis:6379
    env_file:
      - .env
```

## 🧪 **Testing Framework**

### **Automated Tests**
```bash
# Unit Tests
go test ./...

# Integration Tests  
go test -tags=integration ./...

# E2E Tests
go test -tags=e2e ./test/e2e/...

# Benchmarks
go test -bench=. -benchmem ./...

# Coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### **Quality Gates**
```bash
# Linting
golangci-lint run

# Security Scanning
gosec ./...

# Dependency Scanning
nancy sleuth

# Static Analysis
staticcheck ./...
```

## 🚀 **Production Readiness**

### **Security Features**
- 🔐 **Zero Trust Architecture**: Never trust, always verify
- 🛡️ **JWT Token Validation**: Secure authentication
- 📋 **Device Attestation**: Hardware-based verification
- 🎯 **Risk Assessment**: Continuous security evaluation
- 📊 **Audit Logging**: Complete compliance trail

### **Observability Stack**
- 📈 **Metrics**: Prometheus integration
- 📜 **Logging**: Structured JSON logging with slog
- 🔍 **Tracing**: Distributed tracing ready
- 🏥 **Health Checks**: Comprehensive health monitoring
- 📊 **Dashboards**: Grafana dashboard definitions

### **Deployment Options**
- 🐳 **Docker**: Multi-stage, security-hardened containers
- ☸️ **Kubernetes**: Complete K8s manifests
- 🌐 **Service Mesh**: Istio integration ready
- 🔄 **GitOps**: ArgoCD deployment automation

## 📚 **Best Practices Implemented**

### **Code Organization**
```
pkg/                    # Public APIs
├── auth/              # Authentication logic
├── client/            # Client implementations
├── config/            # Configuration management
├── middleware/        # HTTP middleware
├── types/             # Type definitions
└── zerotrust/         # Zero trust features

internal/              # Private code
├── cache/             # Cache implementations
├── testing/           # Test utilities
└── utils/             # Internal utilities

cmd/                   # Applications
└── server/            # Main server application

examples/              # Usage examples
├── basic/             # Simple examples
├── advanced/          # Complex scenarios
└── integrations/      # Framework integrations
```

### **Error Handling**
```go
// Structured error handling with context
func (c *Client) ValidateToken(ctx context.Context, token string) (*Claims, error) {
    if token == "" {
        return nil, fmt.Errorf("token is required")
    }
    
    claims, err := c.parseToken(token)
    if err != nil {
        return nil, fmt.Errorf("failed to parse token: %w", err)
    }
    
    return claims, nil
}
```

### **Configuration Management**
```go
// Environment-based configuration with validation
type Config struct {
    Port         int           `env:"PORT" envDefault:"8080"`
    LogLevel     string        `env:"LOG_LEVEL" envDefault:"info"`
    DatabaseURL  string        `env:"DATABASE_URL" envDefault:"postgres://localhost:5432/db"`
    RedisURL     string        `env:"REDIS_URL" envDefault:"redis://localhost:6379"`
}

func LoadConfig() (*Config, error) {
    cfg := &Config{}
    if err := env.Parse(cfg); err != nil {
        return nil, fmt.Errorf("failed to parse config: %w", err)
    }
    return cfg, nil
}
```

## 🎯 **Key Achievements**

✅ **Environment Ready First Time**: Complete setup with one command
✅ **Maven-Style Components**: Structured component definitions
✅ **Go 2025 Best Practices**: Modern patterns and approaches
✅ **Zero Trust Integration**: Security-first architecture
✅ **Production Ready**: Monitoring, logging, and deployment
✅ **Developer Experience**: Comprehensive tooling and automation
✅ **Quality Assurance**: Testing, linting, and security scanning
✅ **Documentation**: Complete guides and examples

## 🔮 **Future Enhancements**

1. **AI-Powered Generation**: LLM-assisted component creation
2. **Performance Optimization**: Auto-tuning and optimization
3. **Multi-Cloud Support**: AWS, GCP, Azure deployment templates
4. **Advanced Security**: SPIFFE/SPIRE integration
5. **Monitoring Enhancement**: Advanced observability features

---

**The system demonstrates a complete GitHub component repository workflow with practical implementation following Go 2025 best practices, providing an environment-ready solution from the first time.**