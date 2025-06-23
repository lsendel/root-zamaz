#!/bin/bash

# ==================================================
# Project Integration Generator
# ==================================================
# Generates integration scripts and documentation for external projects

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
COMPONENT_REGISTRY="github.com/lsendel/root-zamaz/libraries/go-keycloak-zerotrust"
REGISTRY_URL="ghcr.io/lsendel"

print_header() {
    echo -e "\n${CYAN}=================================================${NC}"
    echo -e "${CYAN}${BOLD}🔧 Project Integration Generator${NC}"
    echo -e "${CYAN}=================================================${NC}\n"
}

print_section() {
    echo -e "\n${BLUE}${BOLD}📋 $1${NC}"
    echo -e "${BLUE}$(printf '%.0s-' {1..50})${NC}\n"
}

print_step() {
    echo -e "${GREEN}🔸 $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

show_usage() {
    print_header
    
    echo -e "${CYAN}Usage: $0 <project_path> [options]${NC}\n"
    
    echo -e "${YELLOW}Arguments:${NC}"
    echo "  project_path            Path to target project directory"
    
    echo -e "\n${YELLOW}Options:${NC}"
    echo "  --framework <name>      Target framework (gin, echo, fiber, grpc)"
    echo "  --components <list>     Components to integrate (core,middleware,clients)"
    echo "  --template <name>       Project template (microservice, api-gateway, fullstack)"
    echo "  --deployment <type>     Deployment type (docker, kubernetes, standalone)"
    echo "  --help                  Show this help message"
    
    echo -e "\n${YELLOW}Examples:${NC}"
    echo "  $0 /path/to/project --framework gin --components core,middleware"
    echo "  $0 /path/to/project --template microservice --deployment kubernetes"
    echo "  $0 /path/to/project --framework echo --template api-gateway"
}

generate_integration_markdown() {
    local target_path="$1"
    local framework="${2:-gin}"
    local components="${3:-core,middleware}"
    local template="${4:-microservice}"
    local deployment="${5:-docker}"
    
    print_section "Generating Integration Documentation"
    
    local markdown_file="$target_path/ZEROTRUST_INTEGRATION.md"
    
    cat > "$markdown_file" << EOF
# 🛡️ Zero Trust Authentication Integration Guide

This guide helps you integrate the Go Keycloak Zero Trust library into your project.

**Generated**: $(date)  
**Target Framework**: $framework  
**Components**: $components  
**Template**: $template  
**Deployment**: $deployment

## 📋 Prerequisites

Before you begin, ensure you have:

- **Go 1.21+** installed ([Download Go](https://golang.org/dl/))
- **Docker** and **Docker Compose** installed ([Get Docker](https://docs.docker.com/get-docker/))
- **Git** for repository management
- **curl** for testing API endpoints

### Verify Prerequisites

\`\`\`bash
# Check Go version
go version

# Check Docker
docker --version
docker-compose --version

# Check other tools
git --version
curl --version
\`\`\`

## 🚀 Quick Integration

### Step 1: Install Components

Choose your preferred installation method:

#### Method 1: Go Modules (Recommended)
\`\`\`bash
# Initialize Go module if not already done
go mod init your-project-name

# Install core component
go get $COMPONENT_REGISTRY/components/core@v1.0.0

EOF

    # Add framework-specific installation
    if [[ "$components" == *"middleware"* ]]; then
        cat >> "$markdown_file" << EOF
# Install middleware component
go get $COMPONENT_REGISTRY/components/middleware@v1.0.0

EOF
    fi

    if [[ "$components" == *"clients"* ]]; then
        cat >> "$markdown_file" << EOF
# Install client SDKs
go get $COMPONENT_REGISTRY/components/clients@v1.0.0

EOF
    fi

    cat >> "$markdown_file" << EOF
# Install dependencies
go mod tidy
\`\`\`

#### Method 2: Using Integration Script
\`\`\`bash
# Download and run integration script
curl -sSL https://raw.githubusercontent.com/lsendel/root-zamaz/main/scripts/integrate.sh | bash -s -- \\
    --framework=$framework \\
    --components=$components \\
    --template=$template

# Or download manually
wget https://raw.githubusercontent.com/lsendel/root-zamaz/main/scripts/integrate.sh
chmod +x integrate.sh
./integrate.sh --framework=$framework --components=$components
\`\`\`

### Step 2: Environment Configuration

Create environment configuration:

\`\`\`bash
# Create .env file
cat > .env << 'ENVEOF'
# Keycloak Configuration
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=your-realm
KEYCLOAK_CLIENT_ID=your-client
KEYCLOAK_CLIENT_SECRET=your-secret

# Zero Trust Configuration
ZEROTRUST_TRUST_LEVEL_READ=25
ZEROTRUST_TRUST_LEVEL_WRITE=50
ZEROTRUST_TRUST_LEVEL_ADMIN=75
ZEROTRUST_TRUST_LEVEL_DELETE=90

# Cache Configuration
CACHE_TYPE=redis
CACHE_TTL=15m
REDIS_URL=redis://localhost:6379

# Database Configuration (for audit logging)
DATABASE_URL=postgres://user:password@localhost:5432/dbname

# Security Configuration
DEVICE_ATTESTATION_ENABLED=true
RISK_ASSESSMENT_ENABLED=true
CONTINUOUS_VERIFICATION=true
ENVEOF
\`\`\`

### Step 3: Framework Integration

EOF

    # Generate framework-specific integration code
    case $framework in
        gin)
            cat >> "$markdown_file" << 'EOF'
#### Gin Framework Integration

Create your main application file:

```go
// main.go
package main

import (
    "context"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/lsendel/root-zamaz/libraries/go-keycloak-zerotrust/components/core/zerotrust"
    "github.com/lsendel/root-zamaz/libraries/go-keycloak-zerotrust/components/middleware"
)

func main() {
    // Load configuration from environment
    config, err := zerotrust.LoadConfigFromEnv()
    if err != nil {
        log.Fatal("Failed to load configuration:", err)
    }

    // Create Zero Trust client
    client, err := zerotrust.NewKeycloakClient(config)
    if err != nil {
        log.Fatal("Failed to create Zero Trust client:", err)
    }
    defer client.Close()

    // Create Gin router
    r := gin.Default()

    // Add Zero Trust middleware
    middleware := zerotrust.NewGinMiddleware(client)

    // Health check endpoint (no authentication required)
    r.GET("/health", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
            "status": "healthy",
            "timestamp": time.Now().UTC(),
        })
    })

    // Protected API routes
    api := r.Group("/api")
    api.Use(middleware.Authenticate())
    {
        // Public data (trust level 25+)
        api.GET("/public", middleware.RequireTrustLevel(25), func(c *gin.Context) {
            claims := middleware.GetClaims(c)
            c.JSON(http.StatusOK, gin.H{
                "message": "This is public data",
                "user_id": claims.UserID,
                "trust_level": claims.TrustLevel,
            })
        })

        // Sensitive data (trust level 50+)
        api.GET("/sensitive", middleware.RequireTrustLevel(50), func(c *gin.Context) {
            claims := middleware.GetClaims(c)
            c.JSON(http.StatusOK, gin.H{
                "message": "This is sensitive data",
                "user_id": claims.UserID,
                "trust_level": claims.TrustLevel,
                "device_verified": claims.DeviceVerified,
            })
        })

        // Admin operations (trust level 75+)
        api.POST("/admin", middleware.RequireTrustLevel(75), func(c *gin.Context) {
            claims := middleware.GetClaims(c)
            c.JSON(http.StatusOK, gin.H{
                "message": "Admin operation completed",
                "user_id": claims.UserID,
                "trust_level": claims.TrustLevel,
                "timestamp": time.Now().UTC(),
            })
        })

        // Critical operations (trust level 90+ and device verification)
        api.DELETE("/critical", 
            middleware.RequireTrustLevel(90),
            middleware.RequireDeviceVerification(),
            func(c *gin.Context) {
                claims := middleware.GetClaims(c)
                c.JSON(http.StatusOK, gin.H{
                    "message": "Critical operation completed",
                    "user_id": claims.UserID,
                    "trust_level": claims.TrustLevel,
                    "device_verified": claims.DeviceVerified,
                    "risk_score": claims.RiskScore,
                })
            })
    }

    // Start server with graceful shutdown
    srv := &http.Server{
        Addr:    ":8080",
        Handler: r,
    }

    // Start server in a goroutine
    go func() {
        log.Println("🚀 Server starting on :8080")
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("Server failed to start: %v", err)
        }
    }()

    // Wait for interrupt signal to gracefully shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    log.Println("🛑 Server shutting down...")

    // Graceful shutdown with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    if err := srv.Shutdown(ctx); err != nil {
        log.Fatal("Server forced to shutdown:", err)
    }

    log.Println("✅ Server exited")
}
```

EOF
            ;;
        echo)
            cat >> "$markdown_file" << 'EOF'
#### Echo Framework Integration

Create your main application file:

```go
// main.go
package main

import (
    "context"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
    "github.com/lsendel/root-zamaz/libraries/go-keycloak-zerotrust/components/core/zerotrust"
    ztmiddleware "github.com/lsendel/root-zamaz/libraries/go-keycloak-zerotrust/components/middleware"
)

func main() {
    // Load configuration
    config, err := zerotrust.LoadConfigFromEnv()
    if err != nil {
        e.Logger.Fatal("Failed to load configuration:", err)
    }

    // Create Zero Trust client
    client, err := zerotrust.NewKeycloakClient(config)
    if err != nil {
        e.Logger.Fatal("Failed to create Zero Trust client:", err)
    }
    defer client.Close()

    // Create Echo instance
    e := echo.New()

    // Add standard middleware
    e.Use(middleware.Logger())
    e.Use(middleware.Recover())
    e.Use(middleware.CORS())

    // Add Zero Trust middleware
    ztmw := ztmiddleware.NewEchoMiddleware(client)

    // Health check
    e.GET("/health", func(c echo.Context) error {
        return c.JSON(http.StatusOK, map[string]interface{}{
            "status": "healthy",
            "timestamp": time.Now().UTC(),
        })
    })

    // Protected API routes
    api := e.Group("/api")
    api.Use(ztmw.Authenticate())

    // Public data endpoint
    api.GET("/public", func(c echo.Context) error {
        claims := ztmw.GetClaims(c)
        return c.JSON(http.StatusOK, map[string]interface{}{
            "message": "Public data",
            "user_id": claims.UserID,
            "trust_level": claims.TrustLevel,
        })
    }, ztmw.RequireTrustLevel(25))

    // Sensitive data endpoint
    api.GET("/sensitive", func(c echo.Context) error {
        claims := ztmw.GetClaims(c)
        return c.JSON(http.StatusOK, map[string]interface{}{
            "message": "Sensitive data",
            "user_id": claims.UserID,
            "trust_level": claims.TrustLevel,
            "device_verified": claims.DeviceVerified,
        })
    }, ztmw.RequireTrustLevel(50))

    // Start server with graceful shutdown
    go func() {
        if err := e.Start(":8080"); err != nil && err != http.ErrServerClosed {
            e.Logger.Fatal("Server startup failed:", err)
        }
    }()

    // Wait for interrupt signal
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
    <-quit

    // Graceful shutdown
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    if err := e.Shutdown(ctx); err != nil {
        e.Logger.Fatal(err)
    }
}
```

EOF
            ;;
        fiber)
            cat >> "$markdown_file" << 'EOF'
#### Fiber Framework Integration

```go
// main.go
package main

import (
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/cors"
    "github.com/gofiber/fiber/v2/middleware/logger"
    "github.com/lsendel/root-zamaz/libraries/go-keycloak-zerotrust/components/core/zerotrust"
    "github.com/lsendel/root-zamaz/libraries/go-keycloak-zerotrust/components/middleware"
)

func main() {
    // Load configuration
    config, err := zerotrust.LoadConfigFromEnv()
    if err != nil {
        log.Fatal("Failed to load configuration:", err)
    }

    // Create Zero Trust client
    client, err := zerotrust.NewKeycloakClient(config)
    if err != nil {
        log.Fatal("Failed to create Zero Trust client:", err)
    }
    defer client.Close()

    // Create Fiber app
    app := fiber.New(fiber.Config{
        ErrorHandler: func(c *fiber.Ctx, err error) error {
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
                "error": "Internal Server Error",
            })
        },
    })

    // Add middleware
    app.Use(logger.New())
    app.Use(cors.New())

    // Zero Trust middleware
    ztmw := middleware.NewFiberMiddleware(client)

    // Health check
    app.Get("/health", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "status": "healthy",
        })
    })

    // Protected API routes
    api := app.Group("/api")
    api.Use(ztmw.Authenticate())

    api.Get("/public", ztmw.RequireTrustLevel(25), func(c *fiber.Ctx) error {
        claims := ztmw.GetClaims(c)
        return c.JSON(fiber.Map{
            "message": "Public data",
            "user_id": claims.UserID,
            "trust_level": claims.TrustLevel,
        })
    })

    // Graceful shutdown
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)

    go func() {
        <-c
        log.Println("Gracefully shutting down...")
        _ = app.Shutdown()
    }()

    log.Println("🚀 Server starting on :8080")
    if err := app.Listen(":8080"); err != nil {
        log.Panic(err)
    }
}
```

EOF
            ;;
        grpc)
            cat >> "$markdown_file" << 'EOF'
#### gRPC Service Integration

```go
// main.go
package main

import (
    "log"
    "net"

    "google.golang.org/grpc"
    "github.com/lsendel/root-zamaz/libraries/go-keycloak-zerotrust/components/core/zerotrust"
    "github.com/lsendel/root-zamaz/libraries/go-keycloak-zerotrust/components/middleware"
)

func main() {
    // Load configuration
    config, err := zerotrust.LoadConfigFromEnv()
    if err != nil {
        log.Fatal("Failed to load configuration:", err)
    }

    // Create Zero Trust client
    client, err := zerotrust.NewKeycloakClient(config)
    if err != nil {
        log.Fatal("Failed to create Zero Trust client:", err)
    }
    defer client.Close()

    // Create gRPC interceptor
    interceptor := middleware.NewGRPCInterceptor(client)

    // Create gRPC server with Zero Trust interceptors
    s := grpc.NewServer(
        grpc.UnaryInterceptor(interceptor.UnaryInterceptor()),
        grpc.StreamInterceptor(interceptor.StreamInterceptor()),
    )

    // Register your gRPC services here
    // pb.RegisterYourServiceServer(s, &yourServiceImpl{})

    // Start server
    lis, err := net.Listen("tcp", ":9090")
    if err != nil {
        log.Fatalf("Failed to listen: %v", err)
    }

    log.Println("🚀 gRPC server starting on :9090")
    if err := s.Serve(lis); err != nil {
        log.Fatalf("Failed to serve: %v", err)
    }
}
```

EOF
            ;;
    esac

    # Add deployment section
    cat >> "$markdown_file" << EOF

### Step 4: Testing Your Integration

#### Get a Test Token
\`\`\`bash
# Get token from Keycloak
TOKEN=\$(curl -s -X POST "http://localhost:8080/realms/your-realm/protocol/openid-connect/token" \\
    -H "Content-Type: application/x-www-form-urlencoded" \\
    -d "grant_type=password" \\
    -d "client_id=your-client" \\
    -d "client_secret=your-secret" \\
    -d "username=testuser" \\
    -d "password=password" | jq -r '.access_token')

echo "Token: \$TOKEN"
\`\`\`

#### Test API Endpoints
\`\`\`bash
# Test health endpoint (no auth required)
curl http://localhost:8080/health

# Test public endpoint (trust level 25+)
curl -H "Authorization: Bearer \$TOKEN" http://localhost:8080/api/public

# Test sensitive endpoint (trust level 50+)
curl -H "Authorization: Bearer \$TOKEN" http://localhost:8080/api/sensitive

# Test admin endpoint (trust level 75+)
curl -X POST -H "Authorization: Bearer \$TOKEN" http://localhost:8080/api/admin
\`\`\`

## 🐳 Docker Deployment

EOF

    # Add Docker deployment based on deployment type
    if [[ "$deployment" == *"docker"* ]]; then
        cat >> "$markdown_file" << 'EOF'
### Dockerfile

```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/

# Copy binary from builder stage
COPY --from=builder /app/main .

# Copy configuration files
COPY --from=builder /app/.env.template .

EXPOSE 8080

CMD ["./main"]
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - KEYCLOAK_BASE_URL=http://keycloak:8080
      - KEYCLOAK_REALM=your-realm
      - KEYCLOAK_CLIENT_ID=your-client
      - KEYCLOAK_CLIENT_SECRET=your-secret
      - REDIS_URL=redis://redis:6379
      - DATABASE_URL=postgres://postgres:password@postgres:5432/app
    depends_on:
      - keycloak
      - redis
      - postgres
    restart: unless-stopped

  keycloak:
    image: quay.io/keycloak/keycloak:22.0.5
    command: start-dev
    environment:
      - KEYCLOAK_ADMIN=admin
      - KEYCLOAK_ADMIN_PASSWORD=admin
      - KC_DB=postgres
      - KC_DB_URL=jdbc:postgresql://postgres:5432/keycloak
      - KC_DB_USERNAME=postgres
      - KC_DB_PASSWORD=password
    ports:
      - "8081:8080"
    depends_on:
      - postgres
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    restart: unless-stopped

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=postgres
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
    restart: unless-stopped

volumes:
  postgres_data:
```

### Run with Docker Compose

```bash
# Start all services
docker-compose up -d

# Check logs
docker-compose logs -f app

# Stop services
docker-compose down
```

EOF
    fi

    # Add Kubernetes deployment if specified
    if [[ "$deployment" == *"kubernetes"* ]]; then
        cat >> "$markdown_file" << 'EOF'
## ☸️ Kubernetes Deployment

### Deployment Manifest

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zerotrust-app
  labels:
    app: zerotrust-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: zerotrust-app
  template:
    metadata:
      labels:
        app: zerotrust-app
    spec:
      containers:
      - name: app
        image: your-registry/zerotrust-app:latest
        ports:
        - containerPort: 8080
        env:
        - name: KEYCLOAK_BASE_URL
          value: "http://keycloak:8080"
        - name: KEYCLOAK_REALM
          value: "your-realm"
        - name: KEYCLOAK_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: zerotrust-secrets
              key: client-id
        - name: KEYCLOAK_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: zerotrust-secrets
              key: client-secret
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: zerotrust-app
spec:
  selector:
    app: zerotrust-app
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: LoadBalancer
```

### Secret Management

```yaml
# k8s/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: zerotrust-secrets
type: Opaque
stringData:
  client-id: "your-client-id"
  client-secret: "your-client-secret"
```

### Deploy to Kubernetes

```bash
# Apply secrets
kubectl apply -f k8s/secrets.yaml

# Apply deployment
kubectl apply -f k8s/deployment.yaml

# Check status
kubectl get pods -l app=zerotrust-app
kubectl logs -l app=zerotrust-app

# Get service URL
kubectl get svc zerotrust-app
```

EOF
    fi

    # Add development workflow
    cat >> "$markdown_file" << 'EOF'
## 🛠️ Development Workflow

### Makefile (Optional)

Create a Makefile for common tasks:

```makefile
# Makefile
.PHONY: build run test clean docker-build docker-run

# Go build
build:
	go build -o bin/app .

# Run locally
run:
	go run .

# Run tests
test:
	go test ./...

# Clean build artifacts
clean:
	rm -rf bin/

# Docker build
docker-build:
	docker build -t zerotrust-app .

# Docker run
docker-run: docker-build
	docker run --rm -p 8080:8080 --env-file .env zerotrust-app

# Development with hot reload (requires air)
dev:
	air

# Install development tools
tools:
	go install github.com/cosmtrek/air@latest
```

### Hot Reload Development

Install Air for hot reload during development:

```bash
# Install air
go install github.com/cosmtrek/air@latest

# Create .air.toml config
cat > .air.toml << 'AIREOF'
root = "."
testdata_dir = "testdata"
tmp_dir = "tmp"

[build]
  args_bin = []
  bin = "./tmp/main"
  cmd = "go build -o ./tmp/main ."
  delay = 1000
  exclude_dir = ["assets", "tmp", "vendor", "testdata"]
  exclude_file = []
  exclude_regex = ["_test.go"]
  exclude_unchanged = false
  follow_symlink = false
  full_bin = ""
  include_dir = []
  include_ext = ["go", "tpl", "tmpl", "html"]
  kill_delay = "0s"
  log = "build-errors.log"
  send_interrupt = false
  stop_on_root = false

[color]
  app = ""
  build = "yellow"
  main = "magenta"
  runner = "green"
  watcher = "cyan"

[log]
  time = false

[misc]
  clean_on_exit = false

[screen]
  clear_on_rebuild = false
AIREOF

# Start development server
make dev
```

## 🧪 Testing

### Unit Tests

```go
// main_test.go
package main

import (
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/gin-gonic/gin"
    "github.com/stretchr/testify/assert"
)

func TestHealthEndpoint(t *testing.T) {
    gin.SetMode(gin.TestMode)
    
    router := gin.Default()
    router.GET("/health", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"status": "healthy"})
    })

    w := httptest.NewRecorder()
    req, _ := http.NewRequest("GET", "/health", nil)
    router.ServeHTTP(w, req)

    assert.Equal(t, 200, w.Code)
    assert.Contains(t, w.Body.String(), "healthy")
}
```

### Integration Tests

```bash
# Run integration tests
go test -tags=integration ./...

# Run with coverage
go test -cover ./...
```

## 📚 Additional Resources

### Documentation
- [Zero Trust Architecture Guide](https://github.com/lsendel/root-zamaz/blob/main/docs/architecture.md)
- [API Reference](https://github.com/lsendel/root-zamaz/blob/main/docs/api-reference.md)
- [Security Best Practices](https://github.com/lsendel/root-zamaz/blob/main/docs/security.md)

### Examples
- [Complete Examples Repository](https://github.com/lsendel/root-zamaz/tree/main/examples)
- [Framework-Specific Examples](https://github.com/lsendel/root-zamaz/tree/main/examples/frameworks)

### Support
- [GitHub Issues](https://github.com/lsendel/root-zamaz/issues)
- [GitHub Discussions](https://github.com/lsendel/root-zamaz/discussions)
- [Component Registry](https://github.com/lsendel/root-zamaz/tree/main/registry)

## 🎯 Next Steps

1. **Customize Configuration**: Adjust trust levels and security policies for your use case
2. **Add Monitoring**: Integrate with your monitoring and observability stack
3. **Scale Deployment**: Configure for production load and high availability
4. **Security Hardening**: Review and implement additional security measures
5. **Team Training**: Familiarize your team with Zero Trust concepts and implementation

---

**🛡️ Congratulations!** You now have Zero Trust authentication integrated into your project. Your application is protected with modern, adaptive security that continuously verifies trust levels and device integrity.

EOF

    print_success "Integration documentation generated: $markdown_file"
}

generate_integration_script() {
    local target_path="$1"
    local framework="${2:-gin}"
    local components="${3:-core,middleware}"
    
    print_section "Generating Integration Script"
    
    local script_file="$target_path/integrate-zerotrust.sh"
    
    cat > "$script_file" << 'EOF'
#!/bin/bash

# ==================================================
# Zero Trust Integration Script
# ==================================================
# Automatically integrates Zero Trust components into your project

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() {
    echo -e "${GREEN}🔸 $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

echo -e "\n${BLUE}🛡️ Zero Trust Integration Script${NC}\n"

# Check prerequisites
print_step "Checking prerequisites..."

if ! command -v go &> /dev/null; then
    print_error "Go is not installed. Please install Go 1.21+"
    exit 1
fi

if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker"
    exit 1
fi

print_success "Prerequisites check passed"

# Initialize Go module if needed
print_step "Initializing Go module..."
if [ ! -f "go.mod" ]; then
    print_info "No go.mod found. Initializing..."
    read -p "Enter module name (e.g., github.com/yourorg/yourproject): " MODULE_NAME
    go mod init "$MODULE_NAME"
    print_success "Go module initialized"
else
    print_info "Using existing go.mod"
fi

# Install Zero Trust components
print_step "Installing Zero Trust components..."

EOF

    # Add component installation based on selected components
    if [[ "$components" == *"core"* ]]; then
        cat >> "$script_file" << 'EOF'
print_info "Installing core component..."
go get github.com/lsendel/root-zamaz/libraries/go-keycloak-zerotrust/components/core@v1.0.0

EOF
    fi

    if [[ "$components" == *"middleware"* ]]; then
        cat >> "$script_file" << 'EOF'
print_info "Installing middleware component..."
go get github.com/lsendel/root-zamaz/libraries/go-keycloak-zerotrust/components/middleware@v1.0.0

EOF
    fi

    # Add framework-specific dependencies
    case $framework in
        gin)
            cat >> "$script_file" << 'EOF'
print_info "Installing Gin framework..."
go get github.com/gin-gonic/gin@latest

EOF
            ;;
        echo)
            cat >> "$script_file" << 'EOF'
print_info "Installing Echo framework..."
go get github.com/labstack/echo/v4@latest

EOF
            ;;
        fiber)
            cat >> "$script_file" << 'EOF'
print_info "Installing Fiber framework..."
go get github.com/gofiber/fiber/v2@latest

EOF
            ;;
        grpc)
            cat >> "$script_file" << 'EOF'
print_info "Installing gRPC..."
go get google.golang.org/grpc@latest
go get google.golang.org/protobuf@latest

EOF
            ;;
    esac

    cat >> "$script_file" << 'EOF'
# Install common dependencies
go get github.com/golang-jwt/jwt/v5@latest
go get golang.org/x/crypto@latest

print_success "Components installed successfully"

# Tidy dependencies
print_step "Tidying Go modules..."
go mod tidy
print_success "Dependencies resolved"

# Create .env template if it doesn't exist
print_step "Creating environment configuration..."
if [ ! -f ".env" ]; then
    cat > .env.template << 'ENVEOF'
# Keycloak Configuration
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=your-realm
KEYCLOAK_CLIENT_ID=your-client
KEYCLOAK_CLIENT_SECRET=your-secret

# Zero Trust Configuration
ZEROTRUST_TRUST_LEVEL_READ=25
ZEROTRUST_TRUST_LEVEL_WRITE=50
ZEROTRUST_TRUST_LEVEL_ADMIN=75
ZEROTRUST_TRUST_LEVEL_DELETE=90

# Cache Configuration
CACHE_TYPE=redis
CACHE_TTL=15m
REDIS_URL=redis://localhost:6379

# Database Configuration
DATABASE_URL=postgres://user:password@localhost:5432/dbname

# Security Configuration
DEVICE_ATTESTATION_ENABLED=true
RISK_ASSESSMENT_ENABLED=true
CONTINUOUS_VERIFICATION=true
ENVEOF

    cp .env.template .env
    print_success "Environment configuration created (.env.template and .env)"
    print_info "Please update .env with your actual configuration values"
else
    print_info "Using existing .env file"
fi

# Create .gitignore if it doesn't exist
print_step "Creating .gitignore..."
if [ ! -f ".gitignore" ]; then
    cat > .gitignore << 'GITIGNOREEOF'
# Binaries for programs and plugins
*.exe
*.exe~
*.dll
*.so
*.dylib

# Test binary, built with `go test -c`
*.test

# Output of the go coverage tool
*.out

# Go workspace file
go.work

# Environment files
.env
.env.local
.env.*.local

# IDE files
.vscode/
.idea/
*.swp
*.swo

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Build artifacts
/bin/
/dist/
/tmp/
GITIGNOREEOF

    print_success ".gitignore created"
else
    print_info "Using existing .gitignore"
fi

print_success "Zero Trust integration completed!"

echo -e "\n${YELLOW}Next Steps:${NC}"
echo "1. Update .env with your Keycloak configuration"
echo "2. Review the generated ZEROTRUST_INTEGRATION.md guide"
echo "3. Run your application: go run ."
echo "4. Test the integration with the provided examples"

echo -e "\n${GREEN}🎉 Your project is now protected with Zero Trust authentication!${NC}"
EOF

    chmod +x "$script_file"
    print_success "Integration script generated: $script_file"
}

main() {
    if [[ $# -eq 0 ]]; then
        show_usage
        exit 1
    fi

    local target_path="$1"
    local framework="gin"
    local components="core,middleware"
    local template="microservice"
    local deployment="docker"

    # Parse arguments
    shift
    while [[ $# -gt 0 ]]; do
        case $1 in
            --framework)
                framework="$2"
                shift 2
                ;;
            --components)
                components="$2"
                shift 2
                ;;
            --template)
                template="$2"
                shift 2
                ;;
            --deployment)
                deployment="$2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Validate target path
    if [[ ! -d "$target_path" ]]; then
        print_error "Target path does not exist: $target_path"
        exit 1
    fi

    print_header
    print_info "Target Path: $target_path"
    print_info "Framework: $framework"
    print_info "Components: $components"
    print_info "Template: $template"
    print_info "Deployment: $deployment"

    # Generate integration files
    generate_integration_markdown "$target_path" "$framework" "$components" "$template" "$deployment"
    generate_integration_script "$target_path" "$framework" "$components"

    print_section "Integration Complete"
    print_success "Files generated in: $target_path"
    echo "  📝 ZEROTRUST_INTEGRATION.md - Complete integration guide"
    echo "  🚀 integrate-zerotrust.sh - Automated setup script"
    
    print_info "To start integration:"
    echo "  cd $target_path"
    echo "  ./integrate-zerotrust.sh"
    echo "  # Follow the ZEROTRUST_INTEGRATION.md guide"
}

# Run main function with all arguments
main "$@"