# Go Keycloak Zero Trust

🔒 **Enterprise-grade Zero Trust authentication library for Keycloak with advanced security features**

[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/yourorg/go-keycloak-zerotrust)](https://goreportcard.com/report/github.com/yourorg/go-keycloak-zerotrust)
[![Coverage Status](https://codecov.io/gh/yourorg/go-keycloak-zerotrust/branch/main/graph/badge.svg)](https://codecov.io/gh/yourorg/go-keycloak-zerotrust)
[![Documentation](https://godoc.org/github.com/yourorg/go-keycloak-zerotrust?status.svg)](https://godoc.org/github.com/yourorg/go-keycloak-zerotrust)

## 🎯 Overview

`go-keycloak-zerotrust` is a comprehensive Zero Trust authentication library that extends Keycloak's capabilities with:

- **Device Attestation**: Hardware-based device verification (Android SafetyNet, iOS DeviceCheck, WebAuthn)
- **Risk Assessment**: Real-time behavioral analysis and threat detection
- **Trust Scoring**: Dynamic trust calculation with decay algorithms
- **Continuous Verification**: Ongoing security monitoring and adaptive policies
- **Multi-Platform Support**: Go, Java, and Python client libraries
- **Framework Integration**: Native middleware for Gin, Echo, Fiber, and gRPC

## ✨ Features

### 🛡️ **Zero Trust Security**
- **Device Attestation**: Hardware-based trust verification
- **Trust Level Management**: Granular access control based on trust scores
- **Risk Assessment**: Real-time risk evaluation and adaptive policies
- **Continuous Verification**: Ongoing authentication validation
- **Geolocation Awareness**: Location-based access controls

### 🚀 **Framework Integration**
- **Gin**: Full middleware support with Zero Trust features
- **Echo**: Native Echo middleware integration
- **Fiber**: High-performance Fiber middleware
- **gRPC**: Unary and streaming interceptors
- **HTTP**: Standard library middleware

### ⚡ **Performance & Reliability**
- **Intelligent Caching**: Redis and in-memory caching layers
- **Connection Pooling**: Optimized Keycloak connections
- **Circuit Breaker**: Fault tolerance for external dependencies
- **Metrics Integration**: Prometheus metrics and observability
- **Graceful Degradation**: Fallback modes for high availability

### 🏢 **Enterprise Ready**
- **Multi-Tenant Support**: Tenant-aware authentication
- **Plugin System**: Extensible architecture for custom logic
- **Configuration Management**: YAML, JSON, and environment variable support
- **Audit Logging**: Comprehensive audit trails for compliance
- **GDPR Compliance**: Privacy-first design principles

## 🚦 Quick Start

### Installation

```bash
go get github.com/yourorg/go-keycloak-zerotrust
```

### Basic Usage (5-minute setup)

```go
package main

import (
    "log"
    
    "github.com/gin-gonic/gin"
    keycloak "github.com/yourorg/go-keycloak-zerotrust"
)

func main() {
    // Initialize Keycloak client
    auth, err := keycloak.New(&keycloak.Config{
        BaseURL:      "https://keycloak.company.com",
        Realm:        "company",
        ClientID:     "api-service",
        ClientSecret: "your-secret",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close()
    
    // Setup Gin with authentication
    r := gin.Default()
    r.Use(auth.GinMiddleware())
    
    // Protected endpoint
    r.GET("/api/users", auth.RequireRole("user"), func(c *gin.Context) {
        user := auth.GetCurrentUser(c)
        c.JSON(200, gin.H{"user": user})
    })
    
    r.Run(":8080")
}
```

## 📖 Configuration

### Environment Variables

```bash
# Core Keycloak settings
export KEYCLOAK_BASE_URL=https://keycloak.company.com
export KEYCLOAK_REALM=company
export KEYCLOAK_CLIENT_ID=api-service
export KEYCLOAK_CLIENT_SECRET=your-secret

# Admin credentials (for user management)
export KEYCLOAK_ADMIN_USER=admin
export KEYCLOAK_ADMIN_PASSWORD=admin-secret

# Cache configuration
export KEYCLOAK_CACHE_PROVIDER=redis
export KEYCLOAK_REDIS_URL=redis://localhost:6379

# Zero Trust features
export KEYCLOAK_DEVICE_ATTESTATION=true
export KEYCLOAK_RISK_ASSESSMENT=true
export KEYCLOAK_CONTINUOUS_VERIFICATION=true
```

### YAML Configuration

```yaml
# config.yaml
base_url: https://keycloak.company.com
realm: company
client_id: api-service
client_secret: your-secret
timeout: 30s
retry_attempts: 3

cache:
  enabled: true
  provider: redis
  redis_url: redis://localhost:6379
  ttl: 15m
  prefix: keycloak_zt

zero_trust:
  default_trust_level: 25
  trust_level_thresholds:
    read: 25
    write: 50
    admin: 75
    delete: 100
  device_attestation: true
  risk_assessment: true
  continuous_verification: true
  verification_interval: 4h

middleware:
  token_header: Authorization
  context_user_key: user
  skip_paths: ["/health", "/metrics"]
  cors_enabled: true
  cors_origins: ["https://app.company.com"]
```

## 🎯 Usage Scenarios

### 1. **Startup API Protection**

Perfect for small to medium SaaS applications requiring robust authentication:

```go
// Simple setup with environment variables
auth, err := keycloak.NewFromEnv()
if err != nil {
    log.Fatal(err)
}

r := gin.Default()
r.Use(auth.GinMiddleware())

// Different trust levels for different operations
r.GET("/api/data", auth.RequireTrustLevel(25), getDataHandler)
r.POST("/api/data", auth.RequireTrustLevel(50), createDataHandler)
r.DELETE("/api/data/:id", auth.RequireTrustLevel(75), deleteDataHandler)
```

### 2. **Enterprise Multi-Tenant SaaS**

Advanced setup for enterprise applications with tenant isolation:

```go
config := &keycloak.Config{
    BaseURL:     "https://keycloak.enterprise.com",
    Realm:       "enterprise",
    ClientID:    "saas-platform",
    MultiTenant: true,
    TenantResolver: func(r *http.Request) string {
        return r.Header.Get("X-Tenant-ID")
    },
    ZeroTrust: &keycloak.ZeroTrustConfig{
        DeviceAttestation:      true,
        RiskAssessment:         true,
        ContinuousVerification: true,
    },
}

auth, err := keycloak.New(config)
if err != nil {
    log.Fatal(err)
}

r := gin.Default()
r.Use(auth.GinMiddleware())
r.Use(auth.RequireTenant()) // Tenant validation middleware
```

### 3. **Financial Services High Security**

Maximum security setup for financial and healthcare applications:

```go
config := &keycloak.Config{
    BaseURL:      "https://keycloak.fintech.com",
    Realm:        "fintech",
    ClientID:     "trading-platform",
    ClientSecret: "ultra-secure-secret",
    ZeroTrust: &keycloak.ZeroTrustConfig{
        DefaultTrustLevel:      100, // Require maximum trust
        DeviceAttestation:      true,
        RiskAssessment:         true,
        ContinuousVerification: true,
        VerificationInterval:   30 * time.Minute,
        GeolocationEnabled:     true,
    },
}

auth, err := keycloak.New(config)

// High-security endpoints
r.POST("/api/trade", 
    auth.RequireTrustLevel(100),
    auth.RequireDeviceVerification(),
    auth.RequireRole("trader"),
    executeTradeHandler,
)
```

### 4. **Microservices with gRPC**

Service-to-service authentication in microservices architecture:

```go
// gRPC Server
import grpcAuth "github.com/yourorg/go-keycloak-zerotrust/middleware/grpc"

auth, err := keycloak.NewFromFile("config.yaml")
if err != nil {
    log.Fatal(err)
}

server := grpc.NewServer(
    grpc.UnaryInterceptor(auth.GRPCUnaryInterceptor()),
    grpc.StreamInterceptor(auth.GRPCStreamInterceptor()),
)

// Service implementation with trust level requirements
type UserService struct {
    auth keycloak.KeycloakClient
}

func (s *UserService) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.User, error) {
    // Extract authenticated user from context
    user, err := s.auth.GetUserFromContext(ctx)
    if err != nil {
        return nil, status.Errorf(codes.Unauthenticated, "authentication required")
    }
    
    // Check trust level
    if user.TrustLevel < 50 {
        return nil, status.Errorf(codes.PermissionDenied, "insufficient trust level")
    }
    
    // Business logic here
    return &pb.User{}, nil
}
```

### 5. **Echo Framework Integration**

Native Echo middleware with Zero Trust features:

```go
import echoAuth "github.com/yourorg/go-keycloak-zerotrust/middleware/echo"

e := echo.New()

auth, err := keycloak.NewFromEnv()
if err != nil {
    log.Fatal(err)
}

// Apply authentication middleware
e.Use(auth.EchoMiddleware())

// Protected routes with different trust requirements
api := e.Group("/api")
api.GET("/public", publicHandler)                                    // No auth required
api.GET("/users", auth.RequireAuth(), getUsersHandler)              // Basic auth
api.POST("/admin", auth.RequireTrustLevel(75), adminHandler)         // High trust required
api.DELETE("/data", auth.RequireDeviceVerification(), deleteHandler) // Device verification required
```

## 🔧 Advanced Features

### Device Attestation

```go
// Enable device attestation in configuration
config := &keycloak.Config{
    ZeroTrust: &keycloak.ZeroTrustConfig{
        DeviceAttestation:     true,
        DeviceVerificationTTL: 24 * time.Hour,
    },
}

// Use device verification middleware
r.POST("/api/sensitive", 
    auth.RequireDeviceVerification(),
    sensitiveOperationHandler,
)

// Manually verify device in handler
func transferFundsHandler(c *gin.Context) {
    user := auth.GetCurrentUser(c)
    
    if !user.DeviceVerified {
        c.JSON(403, gin.H{"error": "Device verification required"})
        return
    }
    
    // Process transfer
}
```

### Risk Assessment

```go
config := &keycloak.Config{
    ZeroTrust: &keycloak.ZeroTrustConfig{
        RiskAssessment: true,
        RiskThresholds: keycloak.RiskThresholdMap{
            Low:      25,
            Medium:   50,
            High:     75,
            Critical: 90,
        },
    },
}

// Risk-based access control
func riskAwareHandler(c *gin.Context) {
    user := auth.GetCurrentUser(c)
    
    if user.RiskScore > 75 {
        // Require additional verification
        c.JSON(403, gin.H{
            "error": "Additional verification required",
            "risk_score": user.RiskScore,
        })
        return
    }
    
    // Normal processing
}
```

### Multi-Tenant Support

```go
config := &keycloak.Config{
    MultiTenant: true,
    TenantResolver: func(r *http.Request) string {
        // Extract tenant from subdomain
        host := r.Host
        parts := strings.Split(host, ".")
        if len(parts) > 0 {
            return parts[0]
        }
        return "default"
    },
}

// Tenant-aware endpoints
r.Use(auth.RequireTenant())
r.GET("/api/data", func(c *gin.Context) {
    tenant := auth.GetCurrentTenant(c)
    user := auth.GetCurrentUser(c)
    
    // Tenant-specific business logic
    data := getDataForTenant(tenant, user.UserID)
    c.JSON(200, data)
})
```

### Custom Middleware

```go
// Create custom middleware with specific requirements
func RequireHighSecurityAccess() gin.HandlerFunc {
    return func(c *gin.Context) {
        user := auth.GetCurrentUser(c)
        if user == nil {
            c.AbortWithStatusJSON(401, gin.H{"error": "Authentication required"})
            return
        }
        
        // Multiple security checks
        if user.TrustLevel < 75 {
            c.AbortWithStatusJSON(403, gin.H{"error": "Insufficient trust level"})
            return
        }
        
        if !user.DeviceVerified {
            c.AbortWithStatusJSON(403, gin.H{"error": "Device verification required"})
            return
        }
        
        if user.RiskScore > 50 {
            c.AbortWithStatusJSON(403, gin.H{"error": "Risk score too high"})
            return
        }
        
        c.Next()
    }
}

// Use custom middleware
r.POST("/api/critical", RequireHighSecurityAccess(), criticalOperationHandler)
```

## 📊 Monitoring & Observability

### Prometheus Metrics

```go
import "github.com/prometheus/client_golang/prometheus/promhttp"

// Expose metrics endpoint
r.GET("/metrics", gin.WrapH(promhttp.Handler()))

// Get client metrics
metrics, err := auth.GetMetrics(context.Background())
if err != nil {
    log.Printf("Failed to get metrics: %v", err)
} else {
    log.Printf("Token validations: %d", metrics.TokenValidations)
    log.Printf("Cache hit ratio: %.2f%%", 
        float64(metrics.CacheHits) / float64(metrics.CacheHits + metrics.CacheMisses) * 100)
}
```

### Health Checks

```go
r.GET("/health", func(c *gin.Context) {
    if err := auth.Health(c.Request.Context()); err != nil {
        c.JSON(503, gin.H{
            "status": "unhealthy",
            "error":  err.Error(),
        })
        return
    }
    
    c.JSON(200, gin.H{"status": "healthy"})
})
```

## 🧪 Testing

### Unit Testing

```go
func TestAuthenticationMiddleware(t *testing.T) {
    // Mock Keycloak client
    mockAuth := &MockKeycloakClient{}
    
    // Setup test cases
    tests := []struct {
        name           string
        token          string
        expectedStatus int
        mockResponse   *keycloak.ZeroTrustClaims
        mockError      error
    }{
        {
            name:           "valid token",
            token:          "Bearer valid-token",
            expectedStatus: 200,
            mockResponse: &keycloak.ZeroTrustClaims{
                UserID:     "user-123",
                TrustLevel: 50,
            },
        },
        {
            name:           "invalid token",
            token:          "Bearer invalid-token",
            expectedStatus: 401,
            mockError:      keycloak.ErrInvalidToken,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            mockAuth.On("ValidateToken", mock.Anything, mock.Anything).
                Return(tt.mockResponse, tt.mockError)
            
            // Test implementation
            recorder := httptest.NewRecorder()
            context, _ := gin.CreateTestContext(recorder)
            // ... test logic
        })
    }
}
```

### Integration Testing

```go
func TestKeycloakIntegration(t *testing.T) {
    // Use testcontainers for real Keycloak instance
    ctx := context.Background()
    
    keycloakContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
        ContainerRequest: testcontainers.ContainerRequest{
            Image:        "quay.io/keycloak/keycloak:22.0",
            ExposedPorts: []string{"8080/tcp"},
            Env: map[string]string{
                "KEYCLOAK_ADMIN":         "admin",
                "KEYCLOAK_ADMIN_PASSWORD": "admin",
            },
            Cmd: []string{"start-dev"},
        },
        Started: true,
    })
    
    require.NoError(t, err)
    defer keycloakContainer.Terminate(ctx)
    
    // Get container endpoint
    endpoint, err := keycloakContainer.Endpoint(ctx, "")
    require.NoError(t, err)
    
    // Test with real Keycloak
    config := &keycloak.Config{
        BaseURL:      "http://" + endpoint,
        Realm:        "master",
        ClientID:     "admin-cli",
        ClientSecret: "",
        AdminUser:    "admin",
        AdminPass:    "admin",
    }
    
    client, err := keycloak.New(config)
    require.NoError(t, err)
    defer client.Close()
    
    // Test operations
    err = client.Health(ctx)
    assert.NoError(t, err)
}
```

## 🚀 Performance Optimization

### Caching Strategy

```go
config := &keycloak.Config{
    Cache: &keycloak.CacheConfig{
        Enabled:  true,
        Provider: "redis",
        RedisURL: "redis://localhost:6379",
        TTL:      15 * time.Minute,
        MaxSize:  10000,
        Prefix:   "keycloak_zt",
    },
}

// The library automatically caches:
// - Token validation results
// - User information
// - Role assignments
// - Device verification status
```

### Connection Pooling

```go
config := &keycloak.Config{
    BaseURL:       "https://keycloak.company.com",
    Timeout:       30 * time.Second,
    RetryAttempts: 3,
    // HTTP client automatically uses connection pooling
}
```

## 🛡️ Security Best Practices

### 1. **Secret Management**

```go
// ❌ Don't hardcode secrets
config := &keycloak.Config{
    ClientSecret: "hardcoded-secret", // DON'T DO THIS
}

// ✅ Use environment variables or secret management
config := &keycloak.Config{
    ClientSecret: os.Getenv("KEYCLOAK_CLIENT_SECRET"),
}

// ✅ Or use external secret managers
secretValue, err := secretManager.GetSecret("keycloak-client-secret")
config.ClientSecret = secretValue
```

### 2. **HTTPS Only**

```go
config := &keycloak.Config{
    BaseURL: "https://keycloak.company.com", // Always use HTTPS
}
```

### 3. **Token Security**

```go
// Configure secure token handling
config := &keycloak.Config{
    Middleware: &keycloak.MiddlewareConfig{
        TokenHeader: "Authorization",
        // Tokens are automatically validated and cached securely
    },
}
```

### 4. **CORS Configuration**

```go
config := &keycloak.Config{
    Middleware: &keycloak.MiddlewareConfig{
        CorsEnabled: true,
        CorsOrigins: []string{
            "https://app.company.com",      // Specific origins
            "https://admin.company.com",    // No wildcards in production
        },
    },
}
```

## 📚 API Reference

### Core Client Interface

```go
type KeycloakClient interface {
    // Token operations
    ValidateToken(ctx context.Context, token string) (*ZeroTrustClaims, error)
    RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error)
    
    // User management
    GetUserInfo(ctx context.Context, userID string) (*UserInfo, error)
    RegisterUser(ctx context.Context, req *UserRegistrationRequest) (*User, error)
    UpdateUserTrustLevel(ctx context.Context, req *TrustLevelUpdateRequest) error
    RevokeUserSessions(ctx context.Context, userID string) error
    
    // Health and monitoring
    Health(ctx context.Context) error
    GetMetrics(ctx context.Context) (*ClientMetrics, error)
    Close() error
}
```

### Configuration Types

```go
type Config struct {
    BaseURL      string        `yaml:"base_url"`
    Realm        string        `yaml:"realm"`
    ClientID     string        `yaml:"client_id"`
    ClientSecret string        `yaml:"client_secret"`
    AdminUser    string        `yaml:"admin_user,omitempty"`
    AdminPass    string        `yaml:"admin_pass,omitempty"`
    Timeout      time.Duration `yaml:"timeout"`
    
    Cache       *CacheConfig      `yaml:"cache,omitempty"`
    ZeroTrust   *ZeroTrustConfig  `yaml:"zero_trust,omitempty"`
    Middleware  *MiddlewareConfig `yaml:"middleware,omitempty"`
    
    MultiTenant    bool                 `yaml:"multi_tenant"`
    TenantResolver TenantResolverFunc   `yaml:"-"`
    Plugins        map[string]map[string]interface{} `yaml:"plugins,omitempty"`
}
```

## 🐛 Troubleshooting

### Common Issues

#### 1. **Connection Timeout**

```go
// Problem: Keycloak server is slow or unreachable
// Solution: Increase timeout and retry attempts
config := &keycloak.Config{
    Timeout:       60 * time.Second,  // Increase timeout
    RetryAttempts: 5,                 // More retry attempts
}
```

#### 2. **Token Validation Failures**

```go
// Problem: Tokens are being rejected
// Solution: Check token format and Keycloak configuration

// Enable debug logging
log.SetLevel(log.DebugLevel)

// Validate token manually
claims, err := auth.ValidateToken(ctx, token)
if err != nil {
    log.Printf("Token validation failed: %v", err)
    // Check if token is properly formatted, not expired, etc.
}
```

#### 3. **Cache Issues**

```go
// Problem: Stale cache data
// Solution: Reduce cache TTL or clear cache

config := &keycloak.Config{
    Cache: &keycloak.CacheConfig{
        TTL: 5 * time.Minute, // Shorter TTL
    },
}

// Or disable cache temporarily
config.Cache.Enabled = false
```

#### 4. **Multi-Tenant Problems**

```go
// Problem: Tenant resolution not working
// Solution: Check tenant resolver function

config.TenantResolver = func(r *http.Request) string {
    tenant := r.Header.Get("X-Tenant-ID")
    log.Printf("Resolved tenant: %s", tenant) // Debug logging
    if tenant == "" {
        return "default"
    }
    return tenant
}
```

### Debug Mode

```go
// Enable debug logging for troubleshooting
config := &keycloak.Config{
    // ... other config
}

// The library will automatically log debug information when log level is set to debug
import "log/slog"

logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))
slog.SetDefault(logger)
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/yourorg/go-keycloak-zerotrust.git
cd go-keycloak-zerotrust

# Install dependencies
go mod download

# Run tests
go test ./...

# Run integration tests (requires Docker)
go test -tags=integration ./...

# Run linting
golangci-lint run
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📖 **Documentation**: [pkg.go.dev](https://pkg.go.dev/github.com/yourorg/go-keycloak-zerotrust)
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/yourorg/go-keycloak-zerotrust/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourorg/go-keycloak-zerotrust/discussions)
- 📧 **Email**: support@yourorg.com

## 🙏 Acknowledgments

- [Keycloak](https://www.keycloak.org/) for the excellent OIDC implementation
- [Gocloak](https://github.com/Nerzal/gocloak) for the Keycloak Go client
- The Go community for amazing frameworks and tools

---

**Made with ❤️ by the Zero Trust Security Team**