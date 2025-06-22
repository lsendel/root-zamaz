# Go Microservice Template - Zero Trust Architecture

> **Template**: Production-ready Go microservice with Zero Trust security  
> **Based On**: Zero Trust Authentication MVP patterns  
> **Version**: 1.0  
> **Last Updated**: 2025-06-21

## 🎯 **Template Overview**

This template provides a complete Go microservice foundation implementing Zero Trust security principles, modern development practices, and production-ready infrastructure patterns.

### **Key Features**
- **Zero Trust Security**: JWT authentication, device attestation, continuous verification
- **Domain-Driven Design**: Clean architecture with clear boundaries
- **Comprehensive Testing**: Unit, integration, and E2E testing strategies
- **Production Ready**: Observability, health checks, graceful shutdown
- **Modern Tooling**: Latest Go practices and dependency management

## 📁 **Directory Structure**

```
{service-name}/
├── cmd/
│   └── server/
│       └── main.go                    # Application entry point
├── internal/
│   ├── auth/                          # Authentication & authorization
│   │   ├── jwt.go
│   │   ├── middleware.go
│   │   └── trust_levels.go
│   ├── config/                        # Configuration management
│   │   └── config.go
│   ├── domain/                        # Business entities & logic
│   │   ├── models/
│   │   ├── services/
│   │   └── repositories/
│   ├── handlers/                      # HTTP handlers
│   │   └── rest/
│   ├── middleware/                    # HTTP middleware
│   │   ├── auth.go
│   │   ├── logging.go
│   │   ├── cors.go
│   │   └── recovery.go
│   ├── observability/                 # Metrics, logging, tracing
│   │   ├── metrics.go
│   │   ├── logger.go
│   │   └── tracing.go
│   └── infrastructure/                # External dependencies
│       ├── database/
│       ├── cache/
│       └── queue/
├── pkg/                               # Public API packages
│   ├── api/                          # API definitions
│   └── client/                       # Client SDK
├── deployments/                       # Kubernetes manifests
│   ├── base/
│   └── overlays/
├── scripts/                          # Build & deployment scripts
├── tests/                            # Test utilities
│   ├── integration/
│   ├── fixtures/
│   └── mocks/
├── docs/                             # Documentation
├── .env.template                     # Environment configuration template
├── .gitignore                        # Git ignore patterns
├── .golangci.yml                     # Go linting configuration
├── Dockerfile                        # Container definition
├── Makefile                          # Build automation
├── go.mod                           # Go module definition
├── go.sum                           # Go module checksums
└── README.md                        # Project documentation
```

## 🛠️ **Template Files**

### **Core Application (cmd/server/main.go)**
```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/gin-gonic/gin"
    "{service-name}/internal/config"
    "{service-name}/internal/handlers/rest"
    "{service-name}/internal/infrastructure/database"
    "{service-name}/internal/middleware"
    "{service-name}/internal/observability"
)

func main() {
    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        log.Fatalf("Failed to load configuration: %v", err)
    }

    // Initialize observability
    obs, err := observability.New(cfg.Observability)
    if err != nil {
        log.Fatalf("Failed to initialize observability: %v", err)
    }
    defer obs.Close()

    // Initialize database
    db, err := database.Connect(cfg.Database)
    if err != nil {
        obs.Logger.Fatal().Err(err).Msg("Failed to connect to database")
    }
    defer db.Close()

    // Initialize HTTP server
    router := setupRouter(cfg, obs, db)
    
    server := &http.Server{
        Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
        Handler:      router,
        ReadTimeout:  cfg.Server.ReadTimeout,
        WriteTimeout: cfg.Server.WriteTimeout,
        IdleTimeout:  cfg.Server.IdleTimeout,
    }

    // Start server in goroutine
    go func() {
        obs.Logger.Info().
            Int("port", cfg.Server.Port).
            Msg("Starting HTTP server")
        
        if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            obs.Logger.Fatal().Err(err).Msg("Failed to start server")
        }
    }()

    // Wait for interrupt signal
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    obs.Logger.Info().Msg("Shutting down server...")

    // Graceful shutdown with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := server.Shutdown(ctx); err != nil {
        obs.Logger.Fatal().Err(err).Msg("Server forced to shutdown")
    }

    obs.Logger.Info().Msg("Server exited")
}

func setupRouter(cfg *config.Config, obs *observability.Observability, db database.Database) *gin.Engine {
    if cfg.Environment == "production" {
        gin.SetMode(gin.ReleaseMode)
    }

    router := gin.New()

    // Global middleware
    router.Use(middleware.LoggingMiddleware(obs))
    router.Use(middleware.RecoveryMiddleware(obs))
    router.Use(middleware.CORSMiddleware(cfg.CORS))
    router.Use(middleware.SecurityHeaders())
    router.Use(middleware.RequestIDMiddleware())

    // Health check endpoints
    router.GET("/health", rest.HealthCheckHandler(db))
    router.GET("/ready", rest.ReadinessHandler(db))

    // Metrics endpoint
    router.GET("/metrics", gin.WrapH(obs.MetricsHandler()))

    // API routes with authentication
    api := router.Group("/api/v1")
    api.Use(middleware.AuthMiddleware(cfg.JWT))
    {
        // Add your API routes here
        api.GET("/profile", rest.GetProfileHandler())
        api.PUT("/profile", rest.UpdateProfileHandler())
    }

    return router
}
```

### **Configuration Management (internal/config/config.go)**
```go
package config

import (
    "fmt"
    "time"

    "github.com/spf13/viper"
)

type Config struct {
    Environment string         `mapstructure:"environment"`
    Server      ServerConfig   `mapstructure:"server"`
    Database    DatabaseConfig `mapstructure:"database"`
    Redis       RedisConfig    `mapstructure:"redis"`
    JWT         JWTConfig      `mapstructure:"jwt"`
    CORS        CORSConfig     `mapstructure:"cors"`
    Observability ObservabilityConfig `mapstructure:"observability"`
}

type ServerConfig struct {
    Port         int           `mapstructure:"port"`
    ReadTimeout  time.Duration `mapstructure:"read_timeout"`
    WriteTimeout time.Duration `mapstructure:"write_timeout"`
    IdleTimeout  time.Duration `mapstructure:"idle_timeout"`
}

type DatabaseConfig struct {
    Host     string `mapstructure:"host"`
    Port     int    `mapstructure:"port"`
    Database string `mapstructure:"database"`
    Username string `mapstructure:"username"`
    Password string `mapstructure:"password"`
    SSLMode  string `mapstructure:"ssl_mode"`
}

type RedisConfig struct {
    Host     string `mapstructure:"host"`
    Port     int    `mapstructure:"port"`
    Password string `mapstructure:"password"`
    Database int    `mapstructure:"database"`
}

type JWTConfig struct {
    Secret           string        `mapstructure:"secret"`
    ExpiryDuration   time.Duration `mapstructure:"expiry_duration"`
    RefreshDuration  time.Duration `mapstructure:"refresh_duration"`
    Issuer           string        `mapstructure:"issuer"`
    RequireHTTPS     bool          `mapstructure:"require_https"`
}

type CORSConfig struct {
    AllowedOrigins []string `mapstructure:"allowed_origins"`
    AllowedMethods []string `mapstructure:"allowed_methods"`
    AllowedHeaders []string `mapstructure:"allowed_headers"`
    AllowCredentials bool   `mapstructure:"allow_credentials"`
}

type ObservabilityConfig struct {
    ServiceName    string `mapstructure:"service_name"`
    ServiceVersion string `mapstructure:"service_version"`
    LogLevel       string `mapstructure:"log_level"`
    MetricsPort    int    `mapstructure:"metrics_port"`
    TracingEnabled bool   `mapstructure:"tracing_enabled"`
    TracingEndpoint string `mapstructure:"tracing_endpoint"`
}

// Load configuration from environment variables and config files
func Load() (*Config, error) {
    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath(".")
    viper.AddConfigPath("./configs")

    // Set environment variable prefix
    viper.SetEnvPrefix("{SERVICE_NAME}")
    viper.AutomaticEnv()

    // Set defaults
    setDefaults()

    if err := viper.ReadInConfig(); err != nil {
        if _, ok := err.(viper.ConfigFileNotFoundError); ok {
            // Config file not found; ignore error if desired
        } else {
            return nil, fmt.Errorf("error reading config file: %w", err)
        }
    }

    var config Config
    if err := viper.Unmarshal(&config); err != nil {
        return nil, fmt.Errorf("error unmarshaling config: %w", err)
    }

    return &config, nil
}

func setDefaults() {
    // Server defaults
    viper.SetDefault("server.port", 8080)
    viper.SetDefault("server.read_timeout", "30s")
    viper.SetDefault("server.write_timeout", "30s")
    viper.SetDefault("server.idle_timeout", "120s")

    // Database defaults
    viper.SetDefault("database.host", "localhost")
    viper.SetDefault("database.port", 5432)
    viper.SetDefault("database.ssl_mode", "disable")

    // Redis defaults
    viper.SetDefault("redis.host", "localhost")
    viper.SetDefault("redis.port", 6379)
    viper.SetDefault("redis.database", 0)

    // JWT defaults
    viper.SetDefault("jwt.expiry_duration", "1h")
    viper.SetDefault("jwt.refresh_duration", "24h")
    viper.SetDefault("jwt.require_https", true)

    // CORS defaults
    viper.SetDefault("cors.allowed_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
    viper.SetDefault("cors.allowed_headers", []string{"Authorization", "Content-Type", "X-Request-ID"})

    // Observability defaults
    viper.SetDefault("observability.log_level", "info")
    viper.SetDefault("observability.metrics_port", 9090)
    viper.SetDefault("observability.tracing_enabled", false)
}
```

### **Makefile Template**
```makefile
# Go Microservice Makefile Template
.PHONY: help dev build test lint clean docker run

# Configuration
SERVICE_NAME := {service-name}
VERSION := $(shell git describe --tags --always --dirty)
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GO_VERSION := $(shell go version | awk '{print $$3}')

# Build flags
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GoVersion=$(GO_VERSION)"

help: ## 📖 Show this help message
	@echo "🚀 $(SERVICE_NAME) - Go Microservice"
	@echo "=================================="
	@echo "📋 DEVELOPMENT:"
	@echo "  make dev          ⚡ Start development server with hot reload"
	@echo "  make build        🔨 Build the application"
	@echo "  make test         🧪 Run all tests"
	@echo "  make lint         🔍 Run linting and code quality checks"
	@echo ""
	@echo "🐳 DOCKER:"
	@echo "  make docker       📦 Build Docker image"
	@echo "  make run          🚀 Run with Docker Compose"
	@echo ""
	@echo "🧹 UTILITIES:"
	@echo "  make clean        🧹 Clean build artifacts"
	@echo "  make deps         📥 Download dependencies"

## Development Commands

dev: ## ⚡ Start development server with hot reload
	@echo "🚀 Starting development server..."
	air -c .air.toml

build: ## 🔨 Build the application
	@echo "🔨 Building $(SERVICE_NAME)..."
	go build $(LDFLAGS) -o bin/$(SERVICE_NAME) ./cmd/server

test: ## 🧪 Run all tests
	@echo "🧪 Running tests..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

test-integration: ## 🔗 Run integration tests
	@echo "🔗 Running integration tests..."
	go test -v -tags=integration ./tests/integration/...

lint: ## 🔍 Run linting and code quality checks
	@echo "🔍 Running linting..."
	golangci-lint run --config .golangci.yml
	@echo "📊 Running security scan..."
	gosec ./...

## Docker Commands

docker: ## 📦 Build Docker image
	@echo "📦 Building Docker image..."
	docker build -t $(SERVICE_NAME):$(VERSION) .
	docker tag $(SERVICE_NAME):$(VERSION) $(SERVICE_NAME):latest

run: ## 🚀 Run with Docker Compose
	@echo "🚀 Starting services with Docker Compose..."
	docker-compose up --build

## Utility Commands

clean: ## 🧹 Clean build artifacts
	@echo "🧹 Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	go clean

deps: ## 📥 Download dependencies
	@echo "📥 Downloading dependencies..."
	go mod download
	go mod tidy

## Database Commands

db-migrate: ## 🗃️ Run database migrations
	@echo "🗃️ Running database migrations..."
	migrate -path migrations -database "$(DATABASE_URL)" up

db-rollback: ## ↩️ Rollback last migration
	@echo "↩️ Rolling back last migration..."
	migrate -path migrations -database "$(DATABASE_URL)" down 1

## Deployment Commands

deploy-staging: ## 🚀 Deploy to staging
	@echo "🚀 Deploying to staging..."
	kubectl apply -k deployments/overlays/staging

deploy-prod: ## 🚀 Deploy to production
	@echo "🚀 Deploying to production..."
	kubectl apply -k deployments/overlays/production

## Monitoring Commands

logs: ## 📋 View application logs
	kubectl logs -l app=$(SERVICE_NAME) -f

status: ## 📊 Check service status
	@echo "📊 Service Status:"
	@curl -s http://localhost:8080/health | jq . || echo "Service not running"
	@echo ""
	@curl -s http://localhost:8080/ready | jq . || echo "Service not ready"
```

### **Environment Template (.env.template)**
```bash
# {SERVICE_NAME} Environment Configuration Template

# Application Environment
ENVIRONMENT=development
SERVICE_NAME={service-name}
SERVICE_VERSION=1.0.0

# Server Configuration
SERVER_PORT=8080
SERVER_READ_TIMEOUT=30s
SERVER_WRITE_TIMEOUT=30s
SERVER_IDLE_TIMEOUT=120s

# Database Configuration
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME={service-name}_db
DATABASE_USERNAME=postgres
DATABASE_PASSWORD=your_secure_password_here
DATABASE_SSL_MODE=disable
DATABASE_URL=postgresql://postgres:your_secure_password_here@localhost:5432/{service-name}_db?sslmode=disable

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DATABASE=0
REDIS_URL=redis://localhost:6379/0

# JWT Configuration
JWT_SECRET=your_jwt_secret_key_here_32_chars_min
JWT_EXPIRY_DURATION=1h
JWT_REFRESH_DURATION=24h
JWT_ISSUER={service-name}
JWT_REQUIRE_HTTPS=false

# CORS Configuration
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
CORS_ALLOWED_METHODS=GET,POST,PUT,DELETE,OPTIONS
CORS_ALLOWED_HEADERS=Authorization,Content-Type,X-Request-ID
CORS_ALLOW_CREDENTIALS=true

# Observability Configuration
OBSERVABILITY_LOG_LEVEL=info
OBSERVABILITY_METRICS_PORT=9090
OBSERVABILITY_TRACING_ENABLED=false
OBSERVABILITY_TRACING_ENDPOINT=http://localhost:14268/api/traces

# External Service URLs
API_BASE_URL=http://localhost:8080
FRONTEND_URL=http://localhost:3000

# Security Configuration
RATE_LIMIT_REQUESTS_PER_MINUTE=60
CSRF_SECRET=your_csrf_secret_here
ENCRYPTION_KEY=your_encryption_key_32_chars_here

# Monitoring & Health Checks
HEALTH_CHECK_INTERVAL=30s
READINESS_CHECK_TIMEOUT=5s
```

### **Docker Configuration**
```dockerfile
# Multi-stage Docker build
FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/server

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN adduser -D -s /bin/sh appuser

# Set working directory
WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/main .

# Copy configuration files
COPY --from=builder /app/configs ./configs

# Change ownership to appuser
RUN chown -R appuser:appuser /root/

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
CMD ["./main"]
```

## 📋 **Setup Instructions**

### **1. Initialize New Service**
```bash
# Create new service from template
mkdir my-new-service
cd my-new-service

# Copy template files (replace {service-name} with actual name)
# Initialize Go module
go mod init github.com/yourorg/my-new-service

# Install dependencies
go mod tidy

# Set up environment
cp .env.template .env
# Edit .env with your configuration
```

### **2. Configure Development Environment**
```bash
# Install development tools
go install github.com/cosmtrek/air@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# Set up database
make db-migrate

# Start development server
make dev
```

### **3. Customize for Your Use Case**
1. Replace `{service-name}` placeholders with your actual service name
2. Update `go.mod` with your module path
3. Implement your business logic in `internal/domain/`
4. Add your API endpoints in `internal/handlers/rest/`
5. Configure authentication and authorization rules
6. Set up your database schema and migrations

## 🔒 **Security Features Included**

- **JWT Authentication** with blacklisting and refresh tokens
- **Zero Trust Architecture** with continuous verification
- **Device Attestation** patterns for trust level management
- **Rate Limiting** and request validation
- **Secure Headers** middleware
- **Input Validation** and sanitization
- **Audit Logging** for compliance
- **CORS Configuration** for cross-origin security

## 🚀 **Production Readiness**

- **Graceful Shutdown** handling
- **Health Check Endpoints** for Kubernetes
- **Metrics Endpoint** for Prometheus
- **Structured Logging** with correlation IDs
- **Error Handling** with proper error codes
- **Configuration Management** with environment overrides
- **Container Security** with non-root user
- **Resource Limits** and timeouts

This template provides a solid foundation for building secure, scalable Go microservices following the patterns established in the Zero Trust Authentication MVP.