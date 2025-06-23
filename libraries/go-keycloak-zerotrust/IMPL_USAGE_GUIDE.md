# Implementation Guide: Using root-zamaz Zero Trust Components

> **Purpose**: This guide shows how to implement Zero Trust authentication in your `impl-zamaz` projects using reusable components from `root-zamaz`.

## 🎯 **Architecture Overview**

```mermaid
graph TB
    subgraph "impl-zamaz Project"
        APP[Your Application]
        CONFIG[Configuration]
        HANDLERS[HTTP Handlers]
    end
    
    subgraph "root-zamaz Reusable Components"
        CLIENT[Keycloak Client]
        MIDDLEWARE[Gin Middleware]
        OPA_CLIENT[OPA Client]
        TYPES[Types & Interfaces]
    end
    
    subgraph "Infrastructure Services"
        KEYCLOAK[Keycloak Identity Provider]
        OPA_SERVER[OPA Policy Engine]
        POSTGRES[PostgreSQL Database]
    end
    
    APP --> CLIENT
    APP --> MIDDLEWARE
    APP --> OPA_CLIENT
    CLIENT --> KEYCLOAK
    OPA_CLIENT --> OPA_SERVER
    KEYCLOAK --> POSTGRES
```

## 🚀 **Quick Start**

### Step 1: Import root-zamaz Components

```go
import (
    // Core client for Keycloak integration
    "github.com/yourorg/go-keycloak-zerotrust/pkg/client"
    
    // Type definitions
    "github.com/yourorg/go-keycloak-zerotrust/pkg/types"
    
    // Gin middleware
    ginmiddleware "github.com/yourorg/go-keycloak-zerotrust/middleware/gin"
    
    // OPA client for authorization
    "github.com/yourorg/go-keycloak-zerotrust/pkg/opa"
)
```

### Step 2: Configure Zero Trust Client

```go
config := &types.Config{
    BaseURL:      "http://localhost:8082",
    Realm:        "zerotrust-test",
    ClientID:     "zerotrust-client",
    ClientSecret: "zerotrust-secret-12345",
    AdminUser:    "admin",
    AdminPass:    "admin",
    Timeout:      30 * time.Second,
    
    // Configure caching
    Cache: &types.CacheConfig{
        Enabled:  true,
        Provider: "memory", // or "redis"
        TTL:      1 * time.Hour,
        MaxSize:  1000,
    },
    
    // Zero Trust policies
    ZeroTrust: &types.ZeroTrustConfig{
        DefaultTrustLevel:       25,  // LOW
        DeviceAttestation:      false, // Simplified
        RiskAssessment:         false, // Simplified
        ContinuousVerification: false, // Simplified
    },
}

// Create client using root-zamaz library
keycloakClient, err := client.NewKeycloakClient(config)
if err != nil {
    log.Fatalf("Failed to create client: %v", err)
}
defer keycloakClient.Close()
```

### Step 3: Setup Gin Middleware

```go
// Configure middleware
middlewareConfig := &types.MiddlewareConfig{
    TokenHeader:    "Authorization",
    ContextUserKey: "user",
    SkipPaths:      []string{"/health", "/login"},
    RequestTimeout: 30 * time.Second,
    CorsEnabled:    true,
    CorsOrigins:    []string{"http://localhost:3000"},
}

// Create middleware using root-zamaz components
authMiddleware := ginmiddleware.NewMiddleware(keycloakClient, middlewareConfig)

// Apply to Gin router
router := gin.Default()
router.Use(authMiddleware.CORS())
```

### Step 4: Protect Endpoints with Zero Trust

```go
// Public endpoints
router.GET("/health", healthHandler)

// Protected with basic authentication
protected := router.Group("/api")
protected.Use(authMiddleware.Authenticate())
{
    // LOW trust level (25+)
    protected.GET("/profile", profileHandler)
    
    // MEDIUM trust level (50+)
    protected.PUT("/profile", 
        authMiddleware.RequireTrustLevel(50), 
        updateProfileHandler)
    
    // HIGH trust level (75+) + admin role
    protected.GET("/admin/users", 
        authMiddleware.RequireRole("admin"),
        authMiddleware.RequireTrustLevel(75),
        adminUsersHandler)
    
    // FULL trust level (100+) + device verification
    protected.POST("/financial/transfer",
        authMiddleware.RequireRole("admin"),
        authMiddleware.RequireTrustLevel(100),
        authMiddleware.RequireDeviceVerification(),
        financialTransferHandler)
}
```

### Step 5: Integration with OPA

```go
// Initialize OPA client
opaClient := opa.NewOPAClient("http://localhost:8181")

// Use in handlers for complex authorization
func updateProfileHandler(c *gin.Context) {
    user := authMiddleware.GetCurrentUser(c)
    
    // Check with OPA for complex policies
    authzReq := opa.AuthorizationRequest{
        JWT:      c.GetHeader("Authorization"),
        Resource: "user_profile",
        Action:   "write",
        UserID:   user.UserID,
        DeviceID: user.DeviceID,
    }
    
    authzResp, err := opaClient.Authorize(c.Request.Context(), authzReq)
    if err != nil || !authzResp.Result.Allow {
        c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
        return
    }
    
    // Process the update...
    c.JSON(http.StatusOK, gin.H{"message": "profile updated"})
}
```

## 🏗️ **Directory Structure for impl-zamaz Projects**

```
impl-zamaz-project/
├── main.go                    # Your application entry point
├── handlers/                  # HTTP handlers
│   ├── auth.go
│   ├── profile.go
│   └── admin.go
├── config/                    # Configuration management
│   └── config.go
├── docker-compose.yml         # Infrastructure services
├── .env                       # Environment variables
└── go.mod                     # Dependencies (includes root-zamaz)

# Infrastructure (from root-zamaz)
├── opa/                       # OPA policies (from root-zamaz)
│   └── policies/
├── keycloak/                  # Keycloak configuration (from root-zamaz)
│   └── imports/
└── deployments/              # Kubernetes/Docker configs (from root-zamaz)
```

## 🔧 **Environment Configuration**

Create a `.env` file in your impl-zamaz project:

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
GIN_MODE=release

# Cache Configuration (optional)
REDIS_URL=redis://localhost:6379

# Database Configuration
DATABASE_URL=postgresql://keycloak:keycloak123@localhost:5432/keycloak
```

## 🐳 **Docker Compose Setup**

Use the provided `docker-compose.simple.yml` for development:

```yaml
# Copy from root-zamaz/libraries/go-keycloak-zerotrust/docker-compose.simple.yml
version: '3.8'

services:
  postgres:
    image: postgres:15
    # ... (database configuration)
    
  keycloak:
    image: quay.io/keycloak/keycloak:23.0
    # ... (identity provider configuration)
    
  opa:
    image: openpolicyagent/opa:latest-envoy
    # ... (policy engine configuration)
    
  app:
    build: .
    # ... (your application)
```

## 📊 **Trust Levels & Use Cases**

| Trust Level | Name | Requirements | Use Cases |
|-------------|------|--------------|-----------|
| 0-24 | NONE | No authentication | Public content |
| 25-49 | LOW | Basic JWT validation | User profile read |
| 50-74 | MEDIUM | Session verification | Profile updates, basic operations |
| 75-99 | HIGH | MFA + role verification | Admin operations, sensitive data |
| 100 | FULL | Hardware attestation + all above | Financial transactions, critical operations |

## 🔐 **Security Best Practices**

### 1. **Token Management**
```go
// Always validate tokens through the client
claims, err := keycloakClient.ValidateToken(ctx, token)
if err != nil {
    return handleAuthError(err)
}
```

### 2. **Trust Level Enforcement**
```go
// Use middleware for consistent enforcement
router.Use(authMiddleware.RequireTrustLevel(50))
```

### 3. **Role-Based Access Control**
```go
// Combine roles with trust levels
router.Use(authMiddleware.RequireRole("admin"))
router.Use(authMiddleware.RequireTrustLevel(75))
```

### 4. **OPA Policy Integration**
```go
// Use OPA for complex business logic
authzResp, err := opaClient.Authorize(ctx, authzReq)
if !authzResp.Result.Allow {
    return handleForbidden(authzResp.Result.Reasons)
}
```

## 🧪 **Testing Your Implementation**

### 1. **Start Infrastructure**
```bash
docker-compose up -d postgres keycloak opa
```

### 2. **Initialize Keycloak**
```bash
# Copy from root-zamaz
cp ../root-zamaz/libraries/go-keycloak-zerotrust/setup-keycloak-zerotrust.sh .
./setup-keycloak-zerotrust.sh
```

### 3. **Test Endpoints**
```bash
# Health check
curl http://localhost:8080/health

# Get token (use Keycloak admin console or direct API)
TOKEN=$(curl -X POST "http://localhost:8082/realms/zerotrust-test/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=zerotrust-client&client_secret=zerotrust-secret-12345&username=testuser&password=password123" \
  | jq -r '.access_token')

# Test protected endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/profile
```

## 🚀 **Production Deployment**

### 1. **Use External Services**
```yaml
# docker-compose.prod.yml
services:
  app:
    environment:
      - KEYCLOAK_URL=https://keycloak.yourdomain.com
      - OPA_URL=https://opa.yourdomain.com
      - REDIS_URL=redis://redis.yourdomain.com:6379
```

### 2. **Enable All Security Features**
```go
ZeroTrust: &types.ZeroTrustConfig{
    DefaultTrustLevel:       25,
    DeviceAttestation:      true,  // Enable for production
    RiskAssessment:         true,  // Enable for production
    ContinuousVerification: true,  // Enable for production
    VerificationInterval:   4 * time.Hour,
}
```

### 3. **Use Redis for Caching**
```go
Cache: &types.CacheConfig{
    Enabled:  true,
    Provider: "redis",
    RedisURL: "redis://redis:6379",
    TTL:      30 * time.Minute,
    Prefix:   "zt:",
}
```

## 🔄 **Migration from Custom Auth**

If you have existing authentication, follow these steps:

### 1. **Gradual Migration**
```go
// Support both old and new auth during transition
router.Use(func(c *gin.Context) {
    // Try new auth first
    if token := extractKeycloakToken(c); token != "" {
        if claims, err := keycloakClient.ValidateToken(ctx, token); err == nil {
            c.Set("user", createUserFromClaims(claims))
            c.Next()
            return
        }
    }
    
    // Fallback to old auth
    if user := validateOldAuth(c); user != nil {
        c.Set("user", user)
        c.Next()
        return
    }
    
    c.AbortWithStatus(http.StatusUnauthorized)
})
```

### 2. **User Migration**
```go
// Migrate existing users to Keycloak
func migrateUser(oldUser *OldUser) error {
    req := &types.UserRegistrationRequest{
        Username:   oldUser.Username,
        Email:      oldUser.Email,
        FirstName:  oldUser.FirstName,
        LastName:   oldUser.LastName,
        TrustLevel: calculateTrustLevel(oldUser),
        Attributes: map[string]string{
            "migrated_from": "old_system",
        },
    }
    
    _, err := keycloakClient.RegisterUser(ctx, req)
    return err
}
```

## 📚 **Additional Resources**

- **root-zamaz Documentation**: `/docs/` in the root-zamaz repository
- **Keycloak Setup Guide**: `setup-keycloak-zerotrust.sh`
- **OPA Policies**: `/opa/policies/` in root-zamaz
- **Example Implementation**: `example-implementation.go`
- **Docker Compose**: `docker-compose.simple.yml`

## 🆘 **Troubleshooting**

### Common Issues

1. **Token Validation Fails**
   ```bash
   # Check Keycloak connectivity
   curl http://localhost:8082/health
   ```

2. **OPA Authorization Fails**
   ```bash
   # Check OPA policies
   curl http://localhost:8181/v1/data/zero_trust/authz/allow
   ```

3. **High Latency**
   ```go
   // Enable caching
   Cache: &types.CacheConfig{Enabled: true}
   ```

### Debug Mode
```go
// Enable debug logging
config.ZeroTrust.DebugMode = true
```

This guide demonstrates how to keep your implementation simple in `impl-zamaz` while leveraging the powerful, reusable components from `root-zamaz`. The architecture separates concerns properly: infrastructure components are reusable, while business logic stays in your implementation projects.