# Complete Zero Trust Implementation Guide for impl-zamaz Projects

> **🎯 Purpose**: Step-by-step guide to implement Zero Trust authentication in your `impl-zamaz` projects using reusable components from `root-zamaz`.

## 📋 **Table of Contents**

1. [Prerequisites & Setup](#1-prerequisites--setup)
2. [Infrastructure Components](#2-infrastructure-components)
3. [Library Components Overview](#3-library-components-overview)
4. [Installation Steps](#4-installation-steps)
5. [Application Implementation](#5-application-implementation)
6. [Testing & Verification](#6-testing--verification)
7. [Production Deployment](#7-production-deployment)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Prerequisites & Setup

### System Requirements

```bash
# Required software
- Docker & Docker Compose
- Go 1.21+
- jq (for JSON parsing in setup scripts)
- curl (for API testing)

# Verify installations
docker --version
go version
jq --version
curl --version
```

### Port Requirements

| Service | Port | Purpose |
|---------|------|---------|
| PostgreSQL | 5432 | Database for Keycloak |
| Keycloak | 8082 | Identity Provider |
| OPA | 8181 | Policy Engine |
| Redis | 6379 | Cache (optional) |
| Your App | 8080 | Zero Trust Application |
| Envoy | 10000 | Proxy (advanced) |

---

## 2. Infrastructure Components

### 🏗️ **Architecture Overview**

```mermaid
graph TB
    subgraph "Client Layer"
        WEB[Web Browser]
        MOBILE[Mobile App]
        API[API Client]
    end
    
    subgraph "Zero Trust Gateway"
        ENVOY[Envoy Proxy<br/>Port 10000]
    end
    
    subgraph "Authentication & Authorization"
        KEYCLOAK[Keycloak Identity Provider<br/>Port 8082]
        OPA[OPA Policy Engine<br/>Port 8181]
    end
    
    subgraph "Application Layer"
        APP[Your impl-zamaz App<br/>Port 8080]
        MIDDLEWARE[Root-zamaz Middleware]
    end
    
    subgraph "Data Layer"
        POSTGRES[PostgreSQL<br/>Port 5432]
        REDIS[Redis Cache<br/>Port 6379]
    end
    
    WEB --> ENVOY
    MOBILE --> ENVOY
    API --> ENVOY
    
    ENVOY --> APP
    APP --> MIDDLEWARE
    MIDDLEWARE --> KEYCLOAK
    MIDDLEWARE --> OPA
    
    KEYCLOAK --> POSTGRES
    APP --> REDIS
    
    style KEYCLOAK fill:#e1f5fe
    style OPA fill:#f3e5f5
    style APP fill:#e8f5e8
```

### 🔧 **Component Responsibilities**

| Component | Responsibility | Status |
|-----------|---------------|---------|
| **Keycloak** | User authentication, JWT token issuance, user management | ✅ Running |
| **OPA** | Authorization policies, trust level evaluation, business rules | ✅ Running |
| **PostgreSQL** | Persistent storage for user data and configurations | ✅ Running |
| **Redis** | Token caching, session storage, performance optimization | ✅ Running |
| **Envoy** | Request proxy, policy enforcement point, traffic management | 🔧 Optional |

---

## 3. Library Components Overview

### 📦 **Root-zamaz Reusable Components**

#### Core Client Library
```go
// Location: /pkg/client/keycloak_client.go
// Purpose: Complete Keycloak integration with Zero Trust features

type KeycloakClient interface {
    // Authentication
    ValidateToken(ctx context.Context, token string) (*ZeroTrustClaims, error)
    RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error)
    
    // User Management
    GetUserInfo(ctx context.Context, userID string) (*UserInfo, error)
    RegisterUser(ctx context.Context, req *UserRegistrationRequest) (*User, error)
    UpdateUserTrustLevel(ctx context.Context, req *TrustLevelUpdateRequest) error
    RevokeUserSessions(ctx context.Context, userID string) error
    
    // System
    Health(ctx context.Context) error
    GetMetrics(ctx context.Context) (*ClientMetrics, error)
    Close() error
}
```

#### Gin Middleware
```go
// Location: /middleware/gin/gin_middleware.go
// Purpose: Ready-to-use Gin middleware for Zero Trust

type Middleware struct {
    // Core authentication
    Authenticate() gin.HandlerFunc
    RequireAuth() gin.HandlerFunc
    
    // Role-based access control
    RequireRole(role string) gin.HandlerFunc
    RequireAnyRole(roles ...string) gin.HandlerFunc
    
    // Trust level enforcement
    RequireTrustLevel(minLevel int) gin.HandlerFunc
    RequireDeviceVerification() gin.HandlerFunc
    
    // Utility functions
    GetCurrentUser(c *gin.Context) *AuthenticatedUser
    CORS() gin.HandlerFunc
}
```

#### OPA Client
```go
// Location: /pkg/opa/client.go
// Purpose: Integration with Open Policy Agent for complex authorization

type OPAClient struct {
    // Authorization decisions
    Authorize(ctx context.Context, req AuthorizationRequest) (*AuthorizationResponse, error)
    HealthCheck(ctx context.Context) error
}

type AuthorizationRequest struct {
    JWT      string `json:"jwt_token"`
    Resource string `json:"resource"`
    Action   string `json:"action"`
    UserID   string `json:"user_id"`
    DeviceID string `json:"device_id"`
}
```

#### Configuration Types
```go
// Location: /pkg/types/types.go
// Purpose: Type definitions and configurations

type Config struct {
    BaseURL      string
    Realm        string
    ClientID     string
    ClientSecret string
    AdminUser    string
    AdminPass    string
    Timeout      time.Duration
    Cache        *CacheConfig
    ZeroTrust    *ZeroTrustConfig
}

type ZeroTrustClaims struct {
    UserID           string
    Email            string
    Roles            []string
    TrustLevel       int     // 0-100 scale
    DeviceID         string
    DeviceVerified   bool
    LastVerification string
    RiskScore        int
    LocationInfo     *LocationInfo
}
```

---

## 4. Installation Steps

### Step 1: Project Setup

```bash
# 1. Create your impl-zamaz project directory
mkdir my-zerotrust-app
cd my-zerotrust-app

# 2. Initialize Go module
go mod init my-zerotrust-app

# 3. Copy infrastructure files from root-zamaz
cp -r /path/to/root-zamaz/libraries/go-keycloak-zerotrust/docker-compose.simple.yml ./docker-compose.yml
cp -r /path/to/root-zamaz/libraries/go-keycloak-zerotrust/opa ./
cp -r /path/to/root-zamaz/libraries/go-keycloak-zerotrust/setup-keycloak-zerotrust.sh ./
```

### Step 2: Infrastructure Deployment

```bash
# 1. Start infrastructure services
docker-compose up -d postgres keycloak opa redis

# 2. Wait for services to be ready (about 60 seconds)
echo "Waiting for Keycloak to start..."
sleep 60

# 3. Initialize Keycloak with Zero Trust configuration
chmod +x setup-keycloak-zerotrust.sh
./setup-keycloak-zerotrust.sh

# 4. Verify all services are running
docker-compose ps
```

Expected output:
```
NAME                IMAGE                              STATUS
zerotrust-keycloak  quay.io/keycloak/keycloak:23.0    Up (healthy)
zerotrust-opa       openpolicyagent/opa:latest-envoy  Up (healthy)
zerotrust-postgres  postgres:15                       Up
zerotrust-redis     redis:7-alpine                    Up (healthy)
```

### Step 3: Environment Configuration

Create `.env` file:
```bash
# Keycloak Configuration
KEYCLOAK_URL=http://localhost:8082
KEYCLOAK_REALM=zerotrust-test
KEYCLOAK_CLIENT_ID=zerotrust-client
KEYCLOAK_CLIENT_SECRET=zerotrust-secret-12345
KEYCLOAK_ADMIN_USER=admin
KEYCLOAK_ADMIN_PASS=admin

# OPA Configuration
OPA_URL=http://localhost:8181

# Application Configuration
PORT=8080
GIN_MODE=debug

# Cache Configuration
REDIS_URL=redis://localhost:6379

# Database Configuration (for app data, not Keycloak)
DATABASE_URL=postgresql://app:password@localhost:5432/appdb
```

### Step 4: Go Dependencies

```bash
# Add root-zamaz library (replace with actual module path)
go mod edit -require github.com/yourorg/go-keycloak-zerotrust@latest

# Add required dependencies
go mod tidy

# If using local development, use replace directive
go mod edit -replace github.com/yourorg/go-keycloak-zerotrust=/path/to/root-zamaz/libraries/go-keycloak-zerotrust
```

---

## 5. Application Implementation

### Step 1: Basic Application Structure

```go
// main.go
package main

import (
    "context"
    "log"
    "net/http"
    "os"
    "time"

    "github.com/gin-gonic/gin"
    
    // Import root-zamaz components
    "github.com/yourorg/go-keycloak-zerotrust/pkg/client"
    "github.com/yourorg/go-keycloak-zerotrust/pkg/types"
    ginmiddleware "github.com/yourorg/go-keycloak-zerotrust/middleware/gin"
    "github.com/yourorg/go-keycloak-zerotrust/pkg/opa"
)

func main() {
    // Initialize Zero Trust configuration
    config := &types.Config{
        BaseURL:      getEnv("KEYCLOAK_URL", "http://localhost:8082"),
        Realm:        getEnv("KEYCLOAK_REALM", "zerotrust-test"),
        ClientID:     getEnv("KEYCLOAK_CLIENT_ID", "zerotrust-client"),
        ClientSecret: getEnv("KEYCLOAK_CLIENT_SECRET", "zerotrust-secret-12345"),
        AdminUser:    getEnv("KEYCLOAK_ADMIN_USER", "admin"),
        AdminPass:    getEnv("KEYCLOAK_ADMIN_PASS", "admin"),
        Timeout:      30 * time.Second,
        
        // Configure caching for performance
        Cache: &types.CacheConfig{
            Enabled:  true,
            Provider: "redis",
            RedisURL: getEnv("REDIS_URL", "redis://localhost:6379"),
            TTL:      30 * time.Minute,
            Prefix:   "zt:",
        },
        
        // Zero Trust security settings
        ZeroTrust: &types.ZeroTrustConfig{
            DefaultTrustLevel:       25,  // LOW trust by default
            DeviceAttestation:      false, // Simplified for demo
            RiskAssessment:         false, // Simplified for demo
            ContinuousVerification: false, // Simplified for demo
        },
    }

    // Create Keycloak client
    keycloakClient, err := client.NewKeycloakClient(config)
    if err != nil {
        log.Fatalf("Failed to create Keycloak client: %v", err)
    }
    defer keycloakClient.Close()

    // Create OPA client
    opaClient := opa.NewOPAClient(getEnv("OPA_URL", "http://localhost:8181"))

    // Test connections
    ctx := context.Background()
    if err := keycloakClient.Health(ctx); err != nil {
        log.Printf("Warning: Keycloak health check failed: %v", err)
    } else {
        log.Println("✅ Keycloak connection successful")
    }

    if err := opaClient.HealthCheck(ctx); err != nil {
        log.Printf("Warning: OPA health check failed: %v", err)
    } else {
        log.Println("✅ OPA connection successful")
    }

    // Setup Gin router with Zero Trust middleware
    router := setupRouter(keycloakClient, opaClient)

    // Start server
    port := getEnv("PORT", "8080")
    log.Printf("🚀 Starting Zero Trust application on port %s", port)
    if err := router.Run(":" + port); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}
```

### Step 2: Router Configuration with Zero Trust

```go
// router.go
func setupRouter(keycloakClient types.KeycloakClient, opaClient *opa.OPAClient) *gin.Engine {
    // Configure middleware
    middlewareConfig := &types.MiddlewareConfig{
        TokenHeader:    "Authorization",
        ContextUserKey: "user",
        SkipPaths:      []string{"/health", "/metrics", "/login", "/register"},
        RequestTimeout: 30 * time.Second,
        CorsEnabled:    true,
        CorsOrigins:    []string{"http://localhost:3000", "http://localhost:5173"},
    }

    // Create Zero Trust middleware
    authMiddleware := ginmiddleware.NewMiddleware(keycloakClient, middlewareConfig)

    router := gin.Default()

    // Apply CORS middleware
    router.Use(authMiddleware.CORS())

    // Public endpoints
    setupPublicRoutes(router, keycloakClient)

    // Protected endpoints with graduated trust levels
    setupProtectedRoutes(router, authMiddleware, opaClient)

    return router
}

func setupPublicRoutes(router *gin.Engine, keycloakClient types.KeycloakClient) {
    // Health check endpoint
    router.GET("/health", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
            "status": "healthy",
            "timestamp": time.Now().Unix(),
            "version": "1.0.0",
        })
    })

    // Metrics endpoint
    router.GET("/metrics", func(c *gin.Context) {
        ctx := c.Request.Context()
        metrics, err := keycloakClient.GetMetrics(ctx)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
            return
        }
        c.JSON(http.StatusOK, metrics)
    })

    // Authentication helper endpoint
    router.POST("/login", func(c *gin.Context) {
        var loginReq struct {
            Username string `json:"username" binding:"required"`
            Password string `json:"password" binding:"required"`
        }

        if err := c.ShouldBindJSON(&loginReq); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        // Return OAuth2 redirect URL for client
        c.JSON(http.StatusOK, gin.H{
            "message": "Use OAuth2 flow for authentication",
            "token_endpoint": "http://localhost:8082/realms/zerotrust-test/protocol/openid-connect/token",
            "auth_endpoint": "http://localhost:8082/realms/zerotrust-test/protocol/openid-connect/auth",
        })
    })
}

func setupProtectedRoutes(router *gin.Engine, authMiddleware *ginmiddleware.Middleware, opaClient *opa.OPAClient) {
    // Protected API group
    api := router.Group("/api")
    api.Use(authMiddleware.Authenticate())
    {
        // LOW trust level (25+) - Basic user operations
        api.GET("/profile", handleGetProfile(authMiddleware))
        api.GET("/dashboard", handleGetDashboard(authMiddleware))

        // MEDIUM trust level (50+) - Sensitive operations
        api.PUT("/profile", 
            authMiddleware.RequireTrustLevel(50),
            handleUpdateProfile(authMiddleware, opaClient))

        api.POST("/documents", 
            authMiddleware.RequireTrustLevel(50),
            handleCreateDocument(authMiddleware, opaClient))

        // HIGH trust level (75+) - Administrative operations
        api.GET("/admin/users", 
            authMiddleware.RequireRole("admin"),
            authMiddleware.RequireTrustLevel(75),
            handleAdminUsers(authMiddleware))

        api.POST("/admin/settings", 
            authMiddleware.RequireRole("admin"),
            authMiddleware.RequireTrustLevel(75),
            handleAdminSettings(authMiddleware))

        // FULL trust level (100+) - Critical operations
        api.POST("/financial/transfer",
            authMiddleware.RequireAnyRole("admin", "finance"),
            authMiddleware.RequireTrustLevel(100),
            authMiddleware.RequireDeviceVerification(),
            handleFinancialTransfer(authMiddleware, opaClient))
    }
}
```

### Step 3: Handler Implementation with OPA Integration

```go
// handlers.go
func handleGetProfile(authMiddleware *ginmiddleware.Middleware) gin.HandlerFunc {
    return func(c *gin.Context) {
        user := authMiddleware.GetCurrentUser(c)
        if user == nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
            return
        }

        c.JSON(http.StatusOK, gin.H{
            "user_id":     user.UserID,
            "email":       user.Email,
            "username":    user.Username,
            "trust_level": user.TrustLevel,
            "roles":       user.Roles,
            "device_verified": user.DeviceVerified,
        })
    }
}

func handleUpdateProfile(authMiddleware *ginmiddleware.Middleware, opaClient *opa.OPAClient) gin.HandlerFunc {
    return func(c *gin.Context) {
        user := authMiddleware.GetCurrentUser(c)
        
        // Check with OPA for business rules
        authzReq := opa.AuthorizationRequest{
            JWT:      c.GetHeader("Authorization"),
            Resource: "user_profile",
            Action:   "write",
            UserID:   user.UserID,
            DeviceID: user.DeviceID,
        }

        authzResp, err := opaClient.Authorize(c.Request.Context(), authzReq)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "authorization check failed"})
            return
        }

        if !authzResp.Result.Allow {
            c.JSON(http.StatusForbidden, gin.H{
                "error": "access denied by policy",
                "reasons": authzResp.Result.Reasons,
            })
            return
        }

        // Process the update
        var updateReq struct {
            FirstName string `json:"first_name"`
            LastName  string `json:"last_name"`
        }

        if err := c.ShouldBindJSON(&updateReq); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        c.JSON(http.StatusOK, gin.H{
            "message": "profile updated successfully",
            "trust_level": authzResp.Result.TrustLevel,
        })
    }
}

func handleFinancialTransfer(authMiddleware *ginmiddleware.Middleware, opaClient *opa.OPAClient) gin.HandlerFunc {
    return func(c *gin.Context) {
        user := authMiddleware.GetCurrentUser(c)

        // This is a critical operation - always check with OPA
        authzReq := opa.AuthorizationRequest{
            JWT:      c.GetHeader("Authorization"),
            Resource: "financial_data",
            Action:   "transact",
            UserID:   user.UserID,
            DeviceID: user.DeviceID,
        }

        authzResp, err := opaClient.Authorize(c.Request.Context(), authzReq)
        if err != nil || !authzResp.Result.Allow {
            c.JSON(http.StatusForbidden, gin.H{
                "error": "financial transaction denied",
                "reasons": authzResp.Result.Reasons,
            })
            return
        }

        // Process financial transfer (mock implementation)
        var transferReq struct {
            Amount      float64 `json:"amount" binding:"required"`
            ToAccount   string  `json:"to_account" binding:"required"`
            Description string  `json:"description"`
        }

        if err := c.ShouldBindJSON(&transferReq); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        c.JSON(http.StatusOK, gin.H{
            "message": "financial transfer authorized and processed",
            "transaction_id": "txn_" + fmt.Sprintf("%d", time.Now().Unix()),
            "amount": transferReq.Amount,
            "security_level": "FULL",
        })
    }
}
```

---

## 6. Testing & Verification

### Step 1: Start Your Application

```bash
# 1. Build and run your application
go mod tidy
go run main.go

# Expected output:
# ✅ Keycloak connection successful
# ✅ OPA connection successful
# 🚀 Starting Zero Trust application on port 8080
```

### Step 2: Test Authentication Flow

```bash
# 1. Health check
curl http://localhost:8080/health

# 2. Get JWT token using test user
TOKEN=$(curl -s -X POST "http://localhost:8082/realms/zerotrust-test/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=zerotrust-client" \
  -d "client_secret=zerotrust-secret-12345" \
  -d "username=testuser" \
  -d "password=password123" \
  | jq -r '.access_token')

echo "Token obtained: ${TOKEN:0:50}..."

# 3. Test protected endpoints
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/profile
curl -H "Authorization: Bearer $TOKEN" -X PUT http://localhost:8080/api/profile \
  -H "Content-Type: application/json" \
  -d '{"first_name": "Updated", "last_name": "Name"}'
```

### Step 3: Test Trust Levels

```bash
# Test different trust level requirements
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/admin/users
# Should succeed if user has admin role and trust level 75+

curl -H "Authorization: Bearer $TOKEN" -X POST http://localhost:8080/api/financial/transfer \
  -H "Content-Type: application/json" \
  -d '{"amount": 1000, "to_account": "123456", "description": "Test transfer"}'
# Should require trust level 100+ and device verification
```

### Step 4: Integration Test Script

Create `test-integration.sh`:
```bash
#!/bin/bash

echo "🧪 Running Zero Trust Integration Tests"

# Test 1: Health checks
echo "1. Testing health endpoints..."
curl -s http://localhost:8080/health | jq .
curl -s http://localhost:8181/health

# Test 2: Authentication
echo "2. Testing authentication..."
TOKEN=$(curl -s -X POST "http://localhost:8082/realms/zerotrust-test/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=zerotrust-client&client_secret=zerotrust-secret-12345&username=testuser&password=password123" \
  | jq -r '.access_token')

if [ "$TOKEN" != "null" ] && [ -n "$TOKEN" ]; then
    echo "✅ Authentication successful"
else
    echo "❌ Authentication failed"
    exit 1
fi

# Test 3: Protected endpoints
echo "3. Testing protected endpoints..."
PROFILE_RESP=$(curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/profile)
echo "Profile response: $PROFILE_RESP" | jq .

# Test 4: OPA integration
echo "4. Testing OPA integration..."
UPDATE_RESP=$(curl -s -H "Authorization: Bearer $TOKEN" -X PUT http://localhost:8080/api/profile \
  -H "Content-Type: application/json" \
  -d '{"first_name": "Test", "last_name": "User"}')
echo "Update response: $UPDATE_RESP" | jq .

echo "🎉 Integration tests completed"
```

---

## 7. Production Deployment

### Step 1: Production Configuration

Update `.env` for production:
```bash
# Production Keycloak
KEYCLOAK_URL=https://keycloak.yourdomain.com
KEYCLOAK_REALM=production
KEYCLOAK_CLIENT_SECRET=<secure-secret>

# Production OPA
OPA_URL=https://opa.yourdomain.com

# Enable full security features
ENABLE_DEVICE_ATTESTATION=true
ENABLE_RISK_ASSESSMENT=true
ENABLE_CONTINUOUS_VERIFICATION=true

# Production cache
REDIS_URL=redis://redis.yourdomain.com:6379
REDIS_PASSWORD=<secure-password>
```

### Step 2: Docker Production Build

Create `Dockerfile`:
```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o app .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/app .
EXPOSE 8080

CMD ["./app"]
```

### Step 3: Production Docker Compose

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  app:
    build: .
    environment:
      - KEYCLOAK_URL=https://keycloak.yourdomain.com
      - OPA_URL=https://opa.yourdomain.com
      - REDIS_URL=redis://redis:6379
      - GIN_MODE=release
    ports:
      - "8080:8080"
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD}
```

---

## 8. Troubleshooting

### Common Issues & Solutions

#### 1. Token Validation Fails
```bash
# Check Keycloak connectivity
curl -f http://localhost:8082/health

# Verify token format
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq .

# Check client configuration
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8082/admin/realms/zerotrust-test/clients"
```

#### 2. OPA Authorization Fails
```bash
# Test OPA directly
curl -X POST http://localhost:8181/v1/data/zero_trust/authz/allow \
  -H "Content-Type: application/json" \
  -d '{"input": {"jwt_token": "test", "resource": "user_profile", "action": "read", "trust_level": 50}}'

# Check OPA logs
docker logs zerotrust-opa
```

#### 3. High Latency Issues
```go
// Enable caching in production
Cache: &types.CacheConfig{
    Enabled:  true,
    Provider: "redis",
    RedisURL: "redis://redis:6379",
    TTL:      30 * time.Minute,
}
```

#### 4. Database Connection Issues
```bash
# Check PostgreSQL connectivity
docker exec -it zerotrust-postgres psql -U keycloak -d keycloak -c "SELECT 1;"

# Check Docker network
docker network ls
docker network inspect zerotrust-network
```

### Debug Mode

Enable debug logging:
```go
config.ZeroTrust.DebugMode = true
gin.SetMode(gin.DebugMode)
```

### Monitoring & Metrics

```bash
# Application metrics
curl http://localhost:8080/metrics

# Infrastructure metrics
docker stats
```

---

## 🎯 **Summary**

This guide provides a complete implementation of Zero Trust authentication using:

### ✅ **What You've Implemented**
- **Keycloak Integration**: Enterprise-grade identity provider
- **OPA Authorization**: Flexible policy-based access control  
- **Graduated Trust Levels**: 0-100 scale with automatic enforcement
- **Role-Based Access Control**: Fine-grained permissions
- **Caching Layer**: Redis for performance optimization
- **Comprehensive Testing**: Integration and unit tests

### 🔧 **Key Library Components Used**
- `pkg/client`: Complete Keycloak client with Zero Trust features
- `middleware/gin`: Ready-to-use Gin middleware
- `pkg/opa`: OPA integration for complex authorization
- `pkg/types`: Type definitions and configurations

### 🚀 **Production Ready Features**
- Health checks and monitoring
- Error handling and logging
- Security best practices
- Performance optimization
- Docker containerization
- Environment-based configuration

### 📈 **Next Steps**
1. **Enhance Security**: Enable device attestation and risk assessment
2. **Add Monitoring**: Implement comprehensive logging and alerting
3. **Scale Components**: Use Kubernetes for production deployment
4. **Custom Policies**: Extend OPA policies for business-specific rules

This implementation keeps your `impl-zamaz` project simple while leveraging the powerful, reusable components from `root-zamaz`.