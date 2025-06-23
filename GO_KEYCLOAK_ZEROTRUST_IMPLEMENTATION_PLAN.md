# 🔑 go-keycloak-zerotrust: 6-Week Implementation Plan

> **Project**: Extract Keycloak Zero Trust integration into production-ready library  
> **Timeline**: 6 weeks (42 days)  
> **Revenue Target**: $15-30K/month within 12 months  
> **Implementation Status**: Ready to Start  
> **Last Updated**: 2025-06-22

## 🎯 **Project Overview**

Extract and enhance the proven Keycloak OIDC integration from Root-Zamaz into a standalone, enterprise-grade Go library that enables Zero Trust authentication with minimal configuration.

### **📊 Key Metrics**
- **Current Codebase**: 866+ lines of production-tested code
- **Features**: OIDC integration, Zero Trust claims, device attestation, trust levels
- **Market Size**: 80% of Fortune 500 use Keycloak
- **Competitive Advantage**: Only Zero Trust + Keycloak library available

---

## 🔄 **Regular Usage Scenarios**

### **👨‍💻 Scenario 1: Startup API Protection**
**User**: Small SaaS startup with existing Keycloak  
**Goal**: Protect API endpoints with Zero Trust authentication  
**Flow**:
```go
// 5-minute integration
package main

import (
    "github.com/gin-gonic/gin"
    keycloak "github.com/yourorg/go-keycloak-zerotrust"
)

func main() {
    // Initialize Keycloak client
    auth, err := keycloak.New(&keycloak.Config{
        BaseURL:      "https://keycloak.company.com",
        Realm:        "company",
        ClientID:     "api-service",
        ClientSecret: "secret",
    })
    if err != nil {
        panic(err)
    }
    
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
**Expected Outcome**: API protected in 5 minutes with role-based access

### **🏢 Scenario 2: Enterprise Multi-Tenant SaaS**
**User**: Enterprise SaaS with multiple customer tenants  
**Goal**: Zero Trust authentication with tenant isolation  
**Flow**:
```go
// Multi-tenant configuration
func setupMultiTenant() {
    config := &keycloak.Config{
        BaseURL:     "https://keycloak.enterprise.com",
        MultiTenant: true,
        TenantResolver: func(r *http.Request) string {
            return r.Header.Get("X-Tenant-ID")
        },
    }
    
    auth, err := keycloak.New(config)
    if err != nil {
        panic(err)
    }
    
    r := gin.Default()
    
    // Tenant-aware middleware
    r.Use(auth.GinMiddleware())
    r.Use(auth.RequireTenant())
    
    // Different trust levels for different operations
    r.GET("/api/data", auth.RequireTrustLevel(25), getDataHandler)
    r.POST("/api/sensitive", auth.RequireTrustLevel(75), sensitiveHandler)
    r.DELETE("/api/admin", auth.RequireTrustLevel(100), adminHandler)
}
```
**Expected Outcome**: Tenant-isolated Zero Trust authentication

### **🛡️ Scenario 3: Financial Services High Security**
**User**: Fintech company requiring device attestation  
**Goal**: Hardware-based device verification for transactions  
**Flow**:
```go
// High-security financial application
func setupFinancialSecurity() {
    config := &keycloak.Config{
        BaseURL:           "https://keycloak.fintech.com",
        Realm:            "fintech",
        ClientID:         "trading-platform",
        DeviceAttestation: true,
        TrustLevels: keycloak.TrustLevels{
            ReadOperations:  25,  // Basic auth
            WriteOperations: 75,  // MFA + device
            Transactions:    100, // Hardware attestation
        },
    }
    
    auth, err := keycloak.New(config)
    if err != nil {
        panic(err)
    }
    
    r := gin.Default()
    r.Use(auth.GinMiddleware())
    
    // Read account balance - basic trust
    r.GET("/api/balance", auth.RequireTrustLevel(25), balanceHandler)
    
    // Transfer funds - high trust + device verification
    r.POST("/api/transfer", 
        auth.RequireTrustLevel(100),
        auth.RequireDeviceVerification(),
        transferHandler)
    
    // Admin operations - full attestation
    r.POST("/api/admin/*", 
        auth.RequireTrustLevel(100),
        auth.RequireDeviceVerification(),
        auth.RequireRole("admin"),
        adminHandler)
}
```
**Expected Outcome**: Hardware-attested device verification for critical operations

### **🔄 Scenario 4: Microservices Service-to-Service**
**User**: Large enterprise with microservices architecture  
**Goal**: Service mesh integration with workload identity  
**Flow**:
```go
// Service-to-service authentication
func setupServiceMesh() {
    config := &keycloak.Config{
        BaseURL:     "https://keycloak.internal.com",
        Realm:      "services",
        ServiceMesh: true,
        SPIRE: &keycloak.SPIREConfig{
            SocketPath:   "/run/spire/sockets/agent.sock",
            TrustDomain: "company.internal",
        },
    }
    
    auth, err := keycloak.New(config)
    if err != nil {
        panic(err)
    }
    
    // gRPC service with workload identity
    grpcServer := grpc.NewServer(
        grpc.StreamInterceptor(auth.GRPCStreamInterceptor()),
        grpc.UnaryInterceptor(auth.GRPCUnaryInterceptor()),
    )
    
    // HTTP service with mutual TLS
    httpServer := &http.Server{
        Addr:    ":8080",
        Handler: auth.HTTPMiddleware()(handler),
        TLSConfig: auth.GetTLSConfig(), // SPIRE-provided certs
    }
}
```
**Expected Outcome**: Zero Trust service mesh with workload identity

### **📱 Scenario 5: Mobile App Backend**
**User**: Mobile app company with native iOS/Android apps  
**Goal**: Mobile-optimized authentication with device binding  
**Flow**:
```go
// Mobile-optimized authentication
func setupMobileAuth() {
    config := &keycloak.Config{
        BaseURL:    "https://keycloak.mobileapp.com",
        Realm:     "mobile-users",
        ClientID:  "mobile-backend",
        Mobile: &keycloak.MobileConfig{
            DeviceBinding:     true,
            BiometricRequired: true,
            RefreshRotation:   true,
        },
    }
    
    auth, err := keycloak.New(config)
    if err != nil {
        panic(err)
    }
    
    r := gin.Default()
    r.Use(auth.GinMiddleware())
    
    // Device registration endpoint
    r.POST("/api/device/register", auth.DeviceRegistrationHandler())
    
    // Biometric verification required for sensitive data
    r.GET("/api/sensitive", 
        auth.RequireDeviceBinding(),
        auth.RequireBiometric(),
        sensitiveDataHandler)
    
    // Token refresh with rotation
    r.POST("/api/auth/refresh", auth.RefreshTokenHandler())
}
```
**Expected Outcome**: Mobile-optimized authentication with device binding

---

## 📅 **6-Week Implementation Timeline**

### **Week 1: Foundation & Architecture (Days 1-7)**

#### **🏗️ Day 1-2: Project Setup & Repository Structure**
```bash
# Create repository structure
mkdir -p go-keycloak-zerotrust/{cmd,pkg,internal,examples,docs,scripts,deployments}

# Initialize Go module
cd go-keycloak-zerotrust
go mod init github.com/yourorg/go-keycloak-zerotrust

# Create project structure
mkdir -p pkg/{client,middleware,config,types,plugins}
mkdir -p internal/{utils,testing,cache}
mkdir -p examples/{gin,echo,fiber,grpc,multi-tenant}
mkdir -p docs/{api,guides,examples}
mkdir -p scripts/{build,test,deploy}
mkdir -p deployments/{docker,kubernetes,helm}
```

**Project Structure**:
```
go-keycloak-zerotrust/
├── cmd/
│   ├── demo/                   # Demo application
│   └── migrate/                # Migration utilities
├── pkg/
│   ├── client/                 # Core Keycloak client
│   ├── middleware/             # Framework integrations
│   ├── config/                 # Configuration management
│   ├── types/                  # Type definitions
│   ├── auth/                   # Authentication logic
│   ├── zerotrust/             # Zero Trust features
│   └── plugins/               # Plugin system
├── internal/
│   ├── utils/                 # Internal utilities
│   ├── testing/               # Test helpers
│   └── cache/                 # Caching layer
├── examples/
│   ├── quickstart/            # 5-minute setup
│   ├── gin-basic/             # Gin integration
│   ├── echo-basic/            # Echo integration
│   ├── fiber-basic/           # Fiber integration
│   ├── grpc-service/          # gRPC integration
│   ├── multi-tenant/          # Multi-tenant setup
│   ├── high-security/         # Financial services example
│   └── mobile-backend/        # Mobile app backend
├── docs/
│   ├── quickstart.md          # 5-minute integration
│   ├── configuration.md       # Complete config reference
│   ├── zero-trust-guide.md    # Zero Trust implementation
│   ├── middleware-guide.md    # Framework integration
│   ├── deployment-guide.md    # Production deployment
│   └── migration-guide.md     # Migration from other auth
└── deployments/
    ├── docker/                # Docker configurations
    ├── kubernetes/            # K8s manifests
    └── helm/                  # Helm charts
```

#### **🔧 Day 3-4: Core Types & Interfaces**
Extract and enhance the core types from the current implementation:

```go
// pkg/types/types.go
package types

import (
    "context"
    "time"
    "github.com/golang-jwt/jwt/v5"
)

// KeycloakClient defines the core Keycloak operations
type KeycloakClient interface {
    ValidateToken(ctx context.Context, token string) (*ZeroTrustClaims, error)
    RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error)
    GetUserInfo(ctx context.Context, userID string) (*UserInfo, error)
    RegisterUser(ctx context.Context, req *UserRegistrationRequest) (*User, error)
    UpdateUserTrustLevel(ctx context.Context, req *TrustLevelUpdateRequest) error
    RevokeUserSessions(ctx context.Context, userID string) error
    Health(ctx context.Context) error
    Close() error
}

// ZeroTrustClaims represents JWT claims with Zero Trust attributes
type ZeroTrustClaims struct {
    // Standard OIDC claims
    UserID            string    `json:"sub"`
    Email             string    `json:"email"`
    PreferredUsername string    `json:"preferred_username"`
    GivenName         string    `json:"given_name"`
    FamilyName        string    `json:"family_name"`
    
    // Authorization claims
    Roles             []string  `json:"realm_access.roles"`
    Groups            []string  `json:"groups,omitempty"`
    
    // Zero Trust claims
    TrustLevel        int       `json:"trust_level"`
    DeviceID          string    `json:"device_id,omitempty"`
    DeviceVerified    bool      `json:"device_verified"`
    LastVerification  string    `json:"last_verification,omitempty"`
    RequiresDeviceAuth bool     `json:"requires_device_auth"`
    
    // Session information
    SessionState      string    `json:"session_state"`
    SessionTimeout    int       `json:"session_timeout,omitempty"`
    
    // Standard JWT claims
    jwt.RegisteredClaims
}

// Config represents the complete library configuration
type Config struct {
    // Keycloak connection
    BaseURL       string        `yaml:"base_url" json:"baseUrl"`
    Realm         string        `yaml:"realm" json:"realm"`
    ClientID      string        `yaml:"client_id" json:"clientId"`
    ClientSecret  string        `yaml:"client_secret" json:"clientSecret"`
    
    // Admin credentials (for user management)
    AdminUser     string        `yaml:"admin_user" json:"adminUser,omitempty"`
    AdminPass     string        `yaml:"admin_pass" json:"adminPass,omitempty"`
    
    // HTTP client configuration
    Timeout       time.Duration `yaml:"timeout" json:"timeout"`
    RetryAttempts int           `yaml:"retry_attempts" json:"retryAttempts"`
    
    // Caching configuration
    Cache         *CacheConfig  `yaml:"cache" json:"cache,omitempty"`
    
    // Zero Trust configuration
    ZeroTrust     *ZeroTrustConfig `yaml:"zero_trust" json:"zeroTrust,omitempty"`
    
    // Multi-tenant configuration
    MultiTenant   bool          `yaml:"multi_tenant" json:"multiTenant"`
    TenantResolver TenantResolverFunc `yaml:"-" json:"-"`
    
    // Framework-specific middleware config
    Middleware    *MiddlewareConfig `yaml:"middleware" json:"middleware,omitempty"`
}

// ZeroTrustConfig contains Zero Trust specific configuration
type ZeroTrustConfig struct {
    // Trust level configuration
    DefaultTrustLevel    int               `yaml:"default_trust_level" json:"defaultTrustLevel"`
    TrustLevelThresholds TrustLevelMap     `yaml:"trust_level_thresholds" json:"trustLevelThresholds"`
    
    // Device attestation
    DeviceAttestation    bool              `yaml:"device_attestation" json:"deviceAttestation"`
    DeviceVerificationTTL time.Duration    `yaml:"device_verification_ttl" json:"deviceVerificationTTL"`
    
    // Risk assessment
    RiskAssessment       bool              `yaml:"risk_assessment" json:"riskAssessment"`
    RiskThresholds       RiskThresholdMap  `yaml:"risk_thresholds" json:"riskThresholds"`
    
    // Continuous verification
    ContinuousVerification bool            `yaml:"continuous_verification" json:"continuousVerification"`
    VerificationInterval   time.Duration   `yaml:"verification_interval" json:"verificationInterval"`
}

// TrustLevelMap defines operation-specific trust level requirements
type TrustLevelMap struct {
    Read   int `yaml:"read" json:"read"`
    Write  int `yaml:"write" json:"write"`
    Admin  int `yaml:"admin" json:"admin"`
    Delete int `yaml:"delete" json:"delete"`
}

// TenantResolverFunc extracts tenant ID from HTTP request
type TenantResolverFunc func(r *http.Request) string

// Middleware configuration
type MiddlewareConfig struct {
    TokenHeader     string        `yaml:"token_header" json:"tokenHeader"`
    ContextUserKey  string        `yaml:"context_user_key" json:"contextUserKey"`
    SkipPaths       []string      `yaml:"skip_paths" json:"skipPaths"`
    RequestTimeout  time.Duration `yaml:"request_timeout" json:"requestTimeout"`
    ErrorHandler    ErrorHandlerFunc `yaml:"-" json:"-"`
}

// Error handling
type ErrorHandlerFunc func(ctx context.Context, err error) error

// User management types
type UserRegistrationRequest struct {
    Username   string            `json:"username" validate:"required,min=3,max=50"`
    Email      string            `json:"email" validate:"required,email"`
    FirstName  string            `json:"firstName" validate:"required,min=1,max=50"`
    LastName   string            `json:"lastName" validate:"required,min=1,max=50"`
    Password   string            `json:"password" validate:"required,min=8"`
    TrustLevel int               `json:"trustLevel" validate:"min=0,max=100"`
    DeviceID   string            `json:"deviceId,omitempty"`
    Attributes map[string]string `json:"attributes,omitempty"`
}

type TrustLevelUpdateRequest struct {
    UserID     string `json:"userId" validate:"required"`
    TrustLevel int    `json:"trustLevel" validate:"min=0,max=100"`
    Reason     string `json:"reason" validate:"required"`
    DeviceID   string `json:"deviceId,omitempty"`
    AdminID    string `json:"adminId" validate:"required"`
}

type User struct {
    ID       string            `json:"id"`
    Username string            `json:"username"`
    Email    string            `json:"email"`
    Enabled  bool              `json:"enabled"`
    Attributes map[string][]string `json:"attributes,omitempty"`
}

type TokenPair struct {
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token"`
    ExpiresIn    int       `json:"expires_in"`
    TokenType    string    `json:"token_type"`
    IssuedAt     time.Time `json:"issued_at"`
}

type UserInfo struct {
    UserID    string   `json:"sub"`
    Email     string   `json:"email"`
    Username  string   `json:"preferred_username"`
    FirstName string   `json:"given_name"`
    LastName  string   `json:"family_name"`
    Roles     []string `json:"roles"`
}
```

#### **⚙️ Day 5-7: Core Client Implementation**
Extract and enhance the Keycloak client:

```go
// pkg/client/keycloak_client.go
package client

import (
    "context"
    "fmt"
    "net/http"
    "strings"
    "sync"
    "time"
    
    "github.com/Nerzal/gocloak/v13"
    "github.com/golang-jwt/jwt/v5"
    
    "github.com/yourorg/go-keycloak-zerotrust/pkg/types"
    "github.com/yourorg/go-keycloak-zerotrust/internal/cache"
    "github.com/yourorg/go-keycloak-zerotrust/internal/utils"
)

// KeycloakClient implements the KeycloakClient interface
type KeycloakClient struct {
    client       *gocloak.GoCloak
    config       *types.Config
    adminToken   *gocloak.JWT
    tokenExpiry  time.Time
    tokenMutex   sync.RWMutex
    cache        cache.Cache
    httpClient   *http.Client
}

// New creates a new Keycloak client
func New(config *types.Config) (*KeycloakClient, error) {
    if err := config.Validate(); err != nil {
        return nil, fmt.Errorf("invalid configuration: %w", err)
    }
    
    // Create gocloak client with custom HTTP client
    httpClient := &http.Client{
        Timeout: config.Timeout,
        Transport: &http.Transport{
            MaxIdleConns:        100,
            MaxIdleConnsPerHost: 10,
            IdleConnTimeout:     90 * time.Second,
        },
    }
    
    goCloak := gocloak.NewClient(config.BaseURL, gocloak.SetHTTPClient(httpClient))
    
    client := &KeycloakClient{
        client:     goCloak,
        config:     config,
        httpClient: httpClient,
    }
    
    // Initialize cache if configured
    if config.Cache != nil {
        var err error
        client.cache, err = cache.New(config.Cache)
        if err != nil {
            return nil, fmt.Errorf("failed to initialize cache: %w", err)
        }
    }
    
    // Get initial admin token if credentials provided
    if config.AdminUser != "" && config.AdminPass != "" {
        if err := client.refreshAdminToken(); err != nil {
            return nil, fmt.Errorf("failed to get admin token: %w", err)
        }
    }
    
    return client, nil
}

// ValidateToken validates a JWT token using Keycloak token introspection
func (c *KeycloakClient) ValidateToken(ctx context.Context, accessToken string) (*types.ZeroTrustClaims, error) {
    if accessToken == "" {
        return nil, fmt.Errorf("access token cannot be empty")
    }
    
    // Remove Bearer prefix if present
    accessToken = strings.TrimPrefix(accessToken, "Bearer ")
    
    // Check cache first
    if c.cache != nil {
        if cached, err := c.cache.Get(ctx, "token:"+accessToken); err == nil {
            if claims, ok := cached.(*types.ZeroTrustClaims); ok {
                return claims, nil
            }
        }
    }
    
    // Introspect token with Keycloak
    rptResult, err := c.client.RetrospectToken(ctx, accessToken, c.config.ClientID, c.config.ClientSecret, c.config.Realm)
    if err != nil {
        return nil, fmt.Errorf("token introspection failed: %w", err)
    }
    
    if !*rptResult.Active {
        return nil, fmt.Errorf("token is not active")
    }
    
    // Get user info for additional claims
    userInfo, err := c.client.GetUserInfo(ctx, accessToken, c.config.Realm)
    if err != nil {
        return nil, fmt.Errorf("failed to get user info: %w", err)
    }
    
    // Parse JWT to extract all claims
    claims, err := c.parseJWTClaims(accessToken, userInfo)
    if err != nil {
        return nil, fmt.Errorf("failed to parse claims: %w", err)
    }
    
    // Apply Zero Trust enhancements
    c.enhanceWithZeroTrust(claims)
    
    // Cache the result if caching is enabled
    if c.cache != nil {
        ttl := time.Until(claims.ExpiresAt.Time)
        if ttl > 0 {
            c.cache.Set(ctx, "token:"+accessToken, claims, ttl)
        }
    }
    
    return claims, nil
}

// parseJWTClaims extracts claims from JWT token and user info
func (c *KeycloakClient) parseJWTClaims(accessToken string, userInfo map[string]interface{}) (*types.ZeroTrustClaims, error) {
    token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
        // We don't validate signature here since Keycloak already did introspection
        return []byte("dummy"), nil
    })
    
    if err != nil && !strings.Contains(err.Error(), "signature is invalid") {
        return nil, fmt.Errorf("failed to parse token: %w", err)
    }
    
    claims := &types.ZeroTrustClaims{}
    
    // Extract standard claims from user info
    utils.ExtractStringClaim(userInfo, "sub", &claims.UserID)
    utils.ExtractStringClaim(userInfo, "email", &claims.Email)
    utils.ExtractStringClaim(userInfo, "preferred_username", &claims.PreferredUsername)
    utils.ExtractStringClaim(userInfo, "given_name", &claims.GivenName)
    utils.ExtractStringClaim(userInfo, "family_name", &claims.FamilyName)
    
    // Extract JWT-specific claims
    if jwtClaims, ok := token.Claims.(jwt.MapClaims); ok {
        c.extractZeroTrustClaims(jwtClaims, claims)
        c.extractStandardJWTClaims(jwtClaims, claims)
    }
    
    return claims, nil
}

// extractZeroTrustClaims extracts Zero Trust specific claims
func (c *KeycloakClient) extractZeroTrustClaims(jwtClaims jwt.MapClaims, claims *types.ZeroTrustClaims) {
    // Extract trust level
    if trustLevel := utils.ExtractIntClaim(jwtClaims, "trust_level"); trustLevel != 0 {
        claims.TrustLevel = trustLevel
    } else {
        claims.TrustLevel = c.config.ZeroTrust.DefaultTrustLevel
    }
    
    // Extract device information
    claims.DeviceID = utils.ExtractStringClaimDefault(jwtClaims, "device_id", "")
    claims.DeviceVerified = utils.ExtractBoolClaim(jwtClaims, "device_verified")
    claims.LastVerification = utils.ExtractStringClaimDefault(jwtClaims, "last_verification", "")
    claims.RequiresDeviceAuth = utils.ExtractBoolClaim(jwtClaims, "requires_device_auth")
    
    // Extract session information
    claims.SessionState = utils.ExtractStringClaimDefault(jwtClaims, "session_state", "")
    claims.SessionTimeout = utils.ExtractIntClaim(jwtClaims, "session_timeout")
    
    // Extract roles from realm_access
    if realmAccess, ok := jwtClaims["realm_access"].(map[string]interface{}); ok {
        if rolesInterface, ok := realmAccess["roles"].([]interface{}); ok {
            for _, role := range rolesInterface {
                if roleStr, ok := role.(string); ok {
                    claims.Roles = append(claims.Roles, roleStr)
                }
            }
        }
    }
}

// extractStandardJWTClaims extracts standard JWT claims
func (c *KeycloakClient) extractStandardJWTClaims(jwtClaims jwt.MapClaims, claims *types.ZeroTrustClaims) {
    if exp, ok := jwtClaims["exp"].(float64); ok {
        claims.ExpiresAt = jwt.NewNumericDate(time.Unix(int64(exp), 0))
    }
    if iat, ok := jwtClaims["iat"].(float64); ok {
        claims.IssuedAt = jwt.NewNumericDate(time.Unix(int64(iat), 0))
    }
    if iss, ok := jwtClaims["iss"].(string); ok {
        claims.Issuer = iss
    }
    if aud, ok := jwtClaims["aud"].(string); ok {
        claims.Audience = jwt.ClaimStrings{aud}
    }
}

// enhanceWithZeroTrust applies Zero Trust enhancements to claims
func (c *KeycloakClient) enhanceWithZeroTrust(claims *types.ZeroTrustClaims) {
    if c.config.ZeroTrust == nil {
        return
    }
    
    // Verify device verification is recent if required
    if c.config.ZeroTrust.DeviceAttestation && claims.DeviceID != "" {
        if claims.LastVerification != "" {
            if lastVerif, err := time.Parse(time.RFC3339, claims.LastVerification); err == nil {
                if time.Since(lastVerif) > c.config.ZeroTrust.DeviceVerificationTTL {
                    claims.DeviceVerified = false
                }
            }
        }
    }
    
    // Apply risk assessment if enabled
    if c.config.ZeroTrust.RiskAssessment {
        // Implement risk scoring logic
        c.assessRisk(claims)
    }
}

// refreshAdminToken gets a fresh admin token from Keycloak
func (c *KeycloakClient) refreshAdminToken() error {
    c.tokenMutex.Lock()
    defer c.tokenMutex.Unlock()
    
    ctx, cancel := context.WithTimeout(context.Background(), c.config.Timeout)
    defer cancel()
    
    token, err := c.client.LoginAdmin(ctx, c.config.AdminUser, c.config.AdminPass, "master")
    if err != nil {
        return fmt.Errorf("admin login failed: %w", err)
    }
    
    c.adminToken = token
    c.tokenExpiry = time.Now().Add(time.Duration(token.ExpiresIn-60) * time.Second)
    
    return nil
}

// ensureValidAdminToken ensures we have a valid admin token
func (c *KeycloakClient) ensureValidAdminToken() error {
    c.tokenMutex.RLock()
    needsRefresh := c.adminToken == nil || time.Now().After(c.tokenExpiry)
    c.tokenMutex.RUnlock()
    
    if needsRefresh {
        return c.refreshAdminToken()
    }
    
    return nil
}

// Health checks Keycloak connectivity
func (c *KeycloakClient) Health(ctx context.Context) error {
    _, err := c.client.GetRealm(ctx, c.adminToken.AccessToken, c.config.Realm)
    if err != nil {
        return fmt.Errorf("keycloak health check failed: %w", err)
    }
    return nil
}

// Close cleans up the client
func (c *KeycloakClient) Close() error {
    if c.cache != nil {
        c.cache.Close()
    }
    
    c.tokenMutex.Lock()
    defer c.tokenMutex.Unlock()
    
    c.adminToken = nil
    c.config.ClientSecret = ""
    
    return nil
}

// RegisterUser creates a new user in Keycloak with Zero Trust attributes
func (c *KeycloakClient) RegisterUser(ctx context.Context, req *types.UserRegistrationRequest) (*types.User, error) {
    if err := c.ensureValidAdminToken(); err != nil {
        return nil, err
    }
    
    // Implementation follows the existing code pattern...
    // [Full implementation extracted from current keycloak.go]
    
    return nil, nil // Placeholder
}

// Additional methods following the same pattern...
// UpdateUserTrustLevel, RevokeUserSessions, GetUserInfo, RefreshToken
```

### **Week 2: Middleware & Framework Integration (Days 8-14)**

#### **🔌 Day 8-10: Universal Middleware Layer**
Create framework-agnostic middleware that can be adapted to any Go web framework:

```go
// pkg/middleware/core.go
package middleware

import (
    "context"
    "net/http"
    "time"
    
    "github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// AuthMiddleware provides universal authentication middleware
type AuthMiddleware struct {
    client types.KeycloakClient
    config *types.MiddlewareConfig
}

// New creates a new authentication middleware
func New(client types.KeycloakClient, config *types.MiddlewareConfig) *AuthMiddleware {
    if config == nil {
        config = DefaultMiddlewareConfig()
    }
    
    return &AuthMiddleware{
        client: client,
        config: config,
    }
}

// HTTPMiddleware returns standard HTTP middleware
func (m *AuthMiddleware) HTTPMiddleware() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if m.shouldSkipPath(r.URL.Path) {
                next.ServeHTTP(w, r)
                return
            }
            
            token := m.extractToken(r)
            if token == "" {
                m.handleError(w, r, ErrMissingToken)
                return
            }
            
            ctx, cancel := context.WithTimeout(r.Context(), m.config.RequestTimeout)
            defer cancel()
            
            claims, err := m.client.ValidateToken(ctx, token)
            if err != nil {
                m.handleError(w, r, err)
                return
            }
            
            // Add user to context
            ctx = context.WithValue(r.Context(), m.config.ContextUserKey, claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

#### **🚀 Day 11-12: Gin Integration**
```go
// pkg/middleware/gin.go
package middleware

import (
    "context"
    "net/http"
    "time"
    
    "github.com/gin-gonic/gin"
    "github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// GinMiddleware creates Gin-specific middleware
func (m *AuthMiddleware) GinMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        if m.shouldSkipPath(c.Request.URL.Path) {
            c.Next()
            return
        }
        
        token := m.extractToken(c.Request)
        if token == "" {
            m.respondUnauthorized(c, "Missing or invalid authorization header")
            return
        }
        
        ctx, cancel := context.WithTimeout(c.Request.Context(), m.config.RequestTimeout)
        defer cancel()
        
        claims, err := m.client.ValidateToken(ctx, token)
        if err != nil {
            m.respondUnauthorized(c, "Invalid or expired token")
            return
        }
        
        // Create authenticated user object
        user := &types.AuthenticatedUser{
            UserID:           claims.UserID,
            Email:            claims.Email,
            Username:         claims.PreferredUsername,
            FirstName:        claims.GivenName,
            LastName:         claims.FamilyName,
            Roles:            claims.Roles,
            TrustLevel:       claims.TrustLevel,
            DeviceID:         claims.DeviceID,
            LastVerification: claims.LastVerification,
            SessionState:     claims.SessionState,
        }
        
        if claims.ExpiresAt != nil {
            user.ExpiresAt = claims.ExpiresAt.Time
        }
        
        // Store in Gin context
        c.Set(m.config.ContextUserKey, user)
        c.Set("claims", claims)
        c.Set("user_id", user.UserID)
        c.Set("trust_level", user.TrustLevel)
        
        c.Next()
    }
}

// RequireRole creates Gin middleware for role checking
func (m *AuthMiddleware) RequireRole(roles ...string) gin.HandlerFunc {
    return func(c *gin.Context) {
        user := GetCurrentUser(c)
        if user == nil {
            m.respondForbidden(c, "Authentication required")
            return
        }
        
        if !hasAnyRole(user.Roles, roles) {
            m.respondForbidden(c, "Insufficient privileges")
            return
        }
        
        c.Next()
    }
}

// RequireTrustLevel creates Gin middleware for trust level checking
func (m *AuthMiddleware) RequireTrustLevel(minLevel int) gin.HandlerFunc {
    return func(c *gin.Context) {
        user := GetCurrentUser(c)
        if user == nil {
            m.respondForbidden(c, "Authentication required")
            return
        }
        
        if user.TrustLevel < minLevel {
            m.respondForbidden(c, map[string]interface{}{
                "error":          "Insufficient trust level",
                "required_level": minLevel,
                "current_level":  user.TrustLevel,
                "improvement_suggestions": getTrustLevelSuggestions(user.TrustLevel, minLevel),
            })
            return
        }
        
        c.Next()
    }
}

// RequireDeviceVerification creates Gin middleware for device verification
func (m *AuthMiddleware) RequireDeviceVerification() gin.HandlerFunc {
    return func(c *gin.Context) {
        user := GetCurrentUser(c)
        if user == nil {
            m.respondForbidden(c, "Authentication required")
            return
        }
        
        if user.DeviceID == "" {
            m.respondForbidden(c, map[string]interface{}{
                "error": "Device verification required",
                "instructions": "Please register your device to access this resource",
            })
            return
        }
        
        // Check if device verification is recent
        if user.LastVerification != "" {
            if lastVerif, err := time.Parse(time.RFC3339, user.LastVerification); err == nil {
                if time.Since(lastVerif) > 24*time.Hour {
                    m.respondForbidden(c, map[string]interface{}{
                        "error": "Device re-verification required",
                        "last_verified": user.LastVerification,
                        "instructions": "Please re-verify your device to continue",
                    })
                    return
                }
            }
        }
        
        c.Next()
    }
}

// Helper functions
func GetCurrentUser(c *gin.Context) *types.AuthenticatedUser {
    if user, exists := c.Get("user"); exists {
        if authUser, ok := user.(*types.AuthenticatedUser); ok {
            return authUser
        }
    }
    return nil
}

func (m *AuthMiddleware) respondUnauthorized(c *gin.Context, message interface{}) {
    c.Header("WWW-Authenticate", "Bearer")
    c.JSON(http.StatusUnauthorized, gin.H{
        "error":     "Unauthorized",
        "message":   message,
        "timestamp": time.Now().Unix(),
    })
    c.Abort()
}

func (m *AuthMiddleware) respondForbidden(c *gin.Context, message interface{}) {
    c.JSON(http.StatusForbidden, gin.H{
        "error":     "Forbidden",
        "message":   message,
        "timestamp": time.Now().Unix(),
    })
    c.Abort()
}
```

#### **📡 Day 13-14: Echo, Fiber, and gRPC Integrations**
Create similar middleware implementations for other popular frameworks:

```go
// pkg/middleware/echo.go - Echo integration
// pkg/middleware/fiber.go - Fiber integration  
// pkg/middleware/grpc.go - gRPC interceptors
```

### **Week 3: Zero Trust Features & Device Management (Days 15-21)**

#### **🛡️ Day 15-17: Trust Level Management**
```go
// pkg/zerotrust/trust_manager.go
package zerotrust

import (
    "context"
    "fmt"
    "time"
    
    "github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// TrustManager handles trust level assessment and management
type TrustManager struct {
    client types.KeycloakClient
    config *types.ZeroTrustConfig
}

// AssessTrustLevel calculates dynamic trust level based on context
func (tm *TrustManager) AssessTrustLevel(ctx context.Context, userID string, context *TrustContext) (int, error) {
    baseTrustLevel, err := tm.getStoredTrustLevel(ctx, userID)
    if err != nil {
        return 0, err
    }
    
    // Apply dynamic adjustments
    adjustments := tm.calculateAdjustments(context)
    finalLevel := baseTrustLevel + adjustments
    
    // Ensure within bounds
    if finalLevel < 0 {
        finalLevel = 0
    }
    if finalLevel > 100 {
        finalLevel = 100
    }
    
    return finalLevel, nil
}

// calculateAdjustments applies contextual trust adjustments
func (tm *TrustManager) calculateAdjustments(context *TrustContext) int {
    adjustments := 0
    
    // Device verification bonus
    if context.DeviceVerified {
        adjustments += 20
    }
    
    // MFA bonus
    if context.MFAVerified {
        adjustments += 15
    }
    
    // Time-based adjustments
    if context.LoginTime.IsZero() || time.Since(context.LoginTime) > 8*time.Hour {
        adjustments -= 10 // Reduce trust for old sessions
    }
    
    // Location-based adjustments
    if context.SuspiciousLocation {
        adjustments -= 25
    }
    
    // Behavioral analysis
    if context.UnusualBehavior {
        adjustments -= 15
    }
    
    return adjustments
}

type TrustContext struct {
    DeviceVerified      bool
    MFAVerified         bool
    LoginTime           time.Time
    SuspiciousLocation  bool
    UnusualBehavior     bool
    IPAddress           string
    UserAgent           string
    GeolocationData     *GeolocationData
}

type GeolocationData struct {
    Country string
    Region  string
    City    string
    ISP     string
}
```

#### **📱 Day 18-19: Device Attestation**
```go
// pkg/zerotrust/device_manager.go
package zerotrust

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "time"
    
    "github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// DeviceManager handles device registration and verification
type DeviceManager struct {
    client types.KeycloakClient
    config *types.ZeroTrustConfig
}

// RegisterDevice registers a new device for a user
func (dm *DeviceManager) RegisterDevice(ctx context.Context, req *DeviceRegistrationRequest) (*DeviceInfo, error) {
    // Generate unique device ID
    deviceID, err := dm.generateDeviceID(req.DeviceFingerprint)
    if err != nil {
        return nil, fmt.Errorf("failed to generate device ID: %w", err)
    }
    
    // Create device attestation record
    attestation := &DeviceAttestation{
        DeviceID:          deviceID,
        UserID:           req.UserID,
        DeviceFingerprint: req.DeviceFingerprint,
        PublicKey:        req.PublicKey,
        AttestationData:  req.AttestationData,
        TrustLevel:       calculateDeviceTrustLevel(req),
        RegisteredAt:     time.Now(),
        LastSeenAt:       time.Now(),
    }
    
    // Store device information
    if err := dm.storeDeviceAttestation(ctx, attestation); err != nil {
        return nil, fmt.Errorf("failed to store device attestation: %w", err)
    }
    
    // Update user's device list
    if err := dm.updateUserDevices(ctx, req.UserID, deviceID); err != nil {
        return nil, fmt.Errorf("failed to update user devices: %w", err)
    }
    
    return &DeviceInfo{
        DeviceID:   deviceID,
        TrustLevel: attestation.TrustLevel,
        Status:     "registered",
    }, nil
}

// VerifyDevice verifies a device's current attestation
func (dm *DeviceManager) VerifyDevice(ctx context.Context, deviceID string, challenge []byte) (*DeviceVerificationResult, error) {
    // Get device attestation
    attestation, err := dm.getDeviceAttestation(ctx, deviceID)
    if err != nil {
        return nil, fmt.Errorf("device not found: %w", err)
    }
    
    // Verify challenge signature
    if err := dm.verifyChallengeSignature(challenge, attestation.PublicKey); err != nil {
        return nil, fmt.Errorf("challenge verification failed: %w", err)
    }
    
    // Update last seen time
    attestation.LastSeenAt = time.Now()
    if err := dm.updateDeviceAttestation(ctx, attestation); err != nil {
        return nil, fmt.Errorf("failed to update device attestation: %w", err)
    }
    
    return &DeviceVerificationResult{
        Verified:   true,
        TrustLevel: attestation.TrustLevel,
        LastSeen:   attestation.LastSeenAt,
    }, nil
}

type DeviceRegistrationRequest struct {
    UserID            string `json:"userId"`
    DeviceFingerprint string `json:"deviceFingerprint"`
    PublicKey         []byte `json:"publicKey"`
    AttestationData   []byte `json:"attestationData"`
    DeviceInfo        *DeviceInfo `json:"deviceInfo"`
}

type DeviceAttestation struct {
    DeviceID          string    `json:"deviceId"`
    UserID           string    `json:"userId"`
    DeviceFingerprint string    `json:"deviceFingerprint"`
    PublicKey        []byte    `json:"publicKey"`
    AttestationData  []byte    `json:"attestationData"`
    TrustLevel       int       `json:"trustLevel"`
    RegisteredAt     time.Time `json:"registeredAt"`
    LastSeenAt       time.Time `json:"lastSeenAt"`
}

type DeviceInfo struct {
    DeviceID   string `json:"deviceId"`
    TrustLevel int    `json:"trustLevel"`
    Status     string `json:"status"`
}

type DeviceVerificationResult struct {
    Verified   bool      `json:"verified"`
    TrustLevel int       `json:"trustLevel"`
    LastSeen   time.Time `json:"lastSeen"`
}
```

#### **🔄 Day 20-21: Continuous Verification**
```go
// pkg/zerotrust/continuous_verifier.go
package zerotrust

import (
    "context"
    "log"
    "time"
    
    "github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// ContinuousVerifier performs ongoing verification of user sessions
type ContinuousVerifier struct {
    client      types.KeycloakClient
    trustMgr    *TrustManager
    deviceMgr   *DeviceManager
    config      *types.ZeroTrustConfig
    stopChan    chan struct{}
}

// Start begins continuous verification process
func (cv *ContinuousVerifier) Start(ctx context.Context) error {
    if !cv.config.ContinuousVerification {
        return nil
    }
    
    ticker := time.NewTicker(cv.config.VerificationInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-cv.stopChan:
            return nil
        case <-ticker.C:
            cv.performVerificationCycle(ctx)
        }
    }
}

// performVerificationCycle runs a verification cycle for all active sessions
func (cv *ContinuousVerifier) performVerificationCycle(ctx context.Context) {
    activeSessions, err := cv.getActiveSessions(ctx)
    if err != nil {
        log.Printf("Failed to get active sessions: %v", err)
        return
    }
    
    for _, session := range activeSessions {
        go cv.verifySession(ctx, session)
    }
}

// verifySession verifies an individual session
func (cv *ContinuousVerifier) verifySession(ctx context.Context, session *SessionInfo) {
    // Check session age
    if time.Since(session.StartTime) > 24*time.Hour {
        cv.flagSessionForReauth(ctx, session, "session_too_old")
        return
    }
    
    // Verify device if required
    if session.DeviceID != "" {
        deviceStatus, err := cv.deviceMgr.GetDeviceStatus(ctx, session.DeviceID)
        if err != nil || !deviceStatus.Trusted {
            cv.flagSessionForReauth(ctx, session, "device_verification_failed")
            return
        }
    }
    
    // Check for suspicious activity
    if cv.detectSuspiciousActivity(ctx, session) {
        cv.flagSessionForReauth(ctx, session, "suspicious_activity")
        return
    }
    
    // Update trust level based on current context
    trustContext := cv.buildTrustContext(session)
    newTrustLevel, err := cv.trustMgr.AssessTrustLevel(ctx, session.UserID, trustContext)
    if err != nil {
        log.Printf("Failed to assess trust level for session %s: %v", session.SessionID, err)
        return
    }
    
    // If trust level dropped significantly, require re-authentication
    if newTrustLevel < session.TrustLevel-20 {
        cv.flagSessionForReauth(ctx, session, "trust_level_dropped")
    }
}

type SessionInfo struct {
    SessionID   string    `json:"sessionId"`
    UserID      string    `json:"userId"`
    DeviceID    string    `json:"deviceId"`
    TrustLevel  int       `json:"trustLevel"`
    StartTime   time.Time `json:"startTime"`
    LastActivity time.Time `json:"lastActivity"`
    IPAddress   string    `json:"ipAddress"`
    UserAgent   string    `json:"userAgent"`
}
```

### **Week 4: Configuration & Plugin System (Days 22-28)**

#### **⚙️ Day 22-24: Advanced Configuration Management**
```go
// pkg/config/config.go
package config

import (
    "fmt"
    "os"
    "strings"
    "time"
    
    "gopkg.in/yaml.v3"
    "github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// ConfigManager handles configuration loading and validation
type ConfigManager struct {
    config *types.Config
}

// LoadFromFile loads configuration from YAML file
func LoadFromFile(path string) (*types.Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read config file: %w", err)
    }
    
    config := DefaultConfig()
    if err := yaml.Unmarshal(data, config); err != nil {
        return nil, fmt.Errorf("failed to parse config: %w", err)
    }
    
    if err := config.Validate(); err != nil {
        return nil, fmt.Errorf("invalid configuration: %w", err)
    }
    
    return config, nil
}

// LoadFromEnv loads configuration from environment variables
func LoadFromEnv() (*types.Config, error) {
    config := DefaultConfig()
    
    // Core Keycloak settings
    if val := os.Getenv("KEYCLOAK_BASE_URL"); val != "" {
        config.BaseURL = val
    }
    if val := os.Getenv("KEYCLOAK_REALM"); val != "" {
        config.Realm = val
    }
    if val := os.Getenv("KEYCLOAK_CLIENT_ID"); val != "" {
        config.ClientID = val
    }
    if val := os.Getenv("KEYCLOAK_CLIENT_SECRET"); val != "" {
        config.ClientSecret = val
    }
    
    // Admin credentials
    if val := os.Getenv("KEYCLOAK_ADMIN_USER"); val != "" {
        config.AdminUser = val
    }
    if val := os.Getenv("KEYCLOAK_ADMIN_PASS"); val != "" {
        config.AdminPass = val
    }
    
    // Zero Trust settings
    if val := os.Getenv("ZERO_TRUST_ENABLED"); val == "true" {
        if config.ZeroTrust == nil {
            config.ZeroTrust = DefaultZeroTrustConfig()
        }
    }
    
    // Multi-tenant settings
    if val := os.Getenv("MULTI_TENANT_ENABLED"); val == "true" {
        config.MultiTenant = true
    }
    
    if err := config.Validate(); err != nil {
        return nil, fmt.Errorf("invalid configuration: %w", err)
    }
    
    return config, nil
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *types.Config {
    return &types.Config{
        Timeout:       30 * time.Second,
        RetryAttempts: 3,
        Cache:         DefaultCacheConfig(),
        ZeroTrust:     DefaultZeroTrustConfig(),
        Middleware:    DefaultMiddlewareConfig(),
    }
}

// DefaultZeroTrustConfig returns default Zero Trust configuration
func DefaultZeroTrustConfig() *types.ZeroTrustConfig {
    return &types.ZeroTrustConfig{
        DefaultTrustLevel: 25,
        TrustLevelThresholds: types.TrustLevelMap{
            Read:   25,
            Write:  50,
            Admin:  75,
            Delete: 100,
        },
        DeviceAttestation:       true,
        DeviceVerificationTTL:   24 * time.Hour,
        RiskAssessment:          true,
        ContinuousVerification:  true,
        VerificationInterval:    15 * time.Minute,
    }
}

// Configuration validation
func (c *types.Config) Validate() error {
    if c.BaseURL == "" {
        return fmt.Errorf("base_url is required")
    }
    if c.Realm == "" {
        return fmt.Errorf("realm is required")
    }
    if c.ClientID == "" {
        return fmt.Errorf("client_id is required")
    }
    if c.ClientSecret == "" {
        return fmt.Errorf("client_secret is required")
    }
    
    if c.Timeout <= 0 {
        return fmt.Errorf("timeout must be positive")
    }
    
    if c.RetryAttempts < 0 {
        return fmt.Errorf("retry_attempts cannot be negative")
    }
    
    // Validate Zero Trust configuration
    if c.ZeroTrust != nil {
        if err := c.ZeroTrust.Validate(); err != nil {
            return fmt.Errorf("zero_trust config invalid: %w", err)
        }
    }
    
    return nil
}
```

#### **🔌 Day 25-26: Plugin System**
```go
// pkg/plugins/plugin_manager.go
package plugins

import (
    "context"
    "fmt"
    "sync"
    
    "github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// PluginManager manages authentication plugins
type PluginManager struct {
    plugins map[string]Plugin
    mutex   sync.RWMutex
}

// Plugin defines the plugin interface
type Plugin interface {
    Name() string
    Version() string
    Initialize(config map[string]interface{}) error
    Cleanup() error
    Health() PluginHealth
}

// AuthenticationPlugin enhances authentication flow
type AuthenticationPlugin interface {
    Plugin
    PreAuthentication(ctx context.Context, request *AuthRequest) (*AuthRequest, error)
    PostAuthentication(ctx context.Context, response *AuthResponse) (*AuthResponse, error)
    OnAuthenticationFailure(ctx context.Context, error error) error
}

// TrustAssessmentPlugin provides custom trust level assessment
type TrustAssessmentPlugin interface {
    Plugin
    AssessTrust(ctx context.Context, context *TrustAssessmentContext) (int, error)
    GetTrustFactors() []TrustFactor
}

// DeviceAttestationPlugin provides custom device verification
type DeviceAttestationPlugin interface {
    Plugin
    AttestDevice(ctx context.Context, request *DeviceAttestationRequest) (*DeviceAttestationResponse, error)
    VerifyDevice(ctx context.Context, deviceID string, challenge []byte) (*DeviceVerificationResponse, error)
}

// Built-in plugins

// RiskAssessmentPlugin provides risk-based trust assessment
type RiskAssessmentPlugin struct {
    config *RiskAssessmentConfig
}

func (r *RiskAssessmentPlugin) Name() string { return "risk-assessment" }
func (r *RiskAssessmentPlugin) Version() string { return "1.0.0" }

func (r *RiskAssessmentPlugin) AssessTrust(ctx context.Context, context *TrustAssessmentContext) (int, error) {
    baseTrust := context.BaseTrustLevel
    adjustments := 0
    
    // IP reputation check
    if r.isIPSuspicious(context.IPAddress) {
        adjustments -= 30
    }
    
    // Geolocation analysis
    if r.isLocationUnusual(context.UserID, context.Location) {
        adjustments -= 20
    }
    
    // Time-based analysis
    if r.isUnusualTimeAccess(context.UserID, context.AccessTime) {
        adjustments -= 10
    }
    
    // Behavioral analysis
    if r.isBehaviorUnusual(context.UserID, context.BehaviorMetrics) {
        adjustments -= 15
    }
    
    finalTrust := baseTrust + adjustments
    if finalTrust < 0 {
        finalTrust = 0
    }
    if finalTrust > 100 {
        finalTrust = 100
    }
    
    return finalTrust, nil
}

// Hardware attestation plugin for high-security environments
type HardwareAttestationPlugin struct {
    config *HardwareAttestationConfig
}

func (h *HardwareAttestationPlugin) AttestDevice(ctx context.Context, request *DeviceAttestationRequest) (*DeviceAttestationResponse, error) {
    // TPM-based attestation
    if h.config.RequireTPM {
        if err := h.verifyTPMAttestation(request.TPMData); err != nil {
            return &DeviceAttestationResponse{
                Success: false,
                Reason:  "TPM verification failed",
            }, err
        }
    }
    
    // Hardware security module verification
    if h.config.RequireHSM {
        if err := h.verifyHSMAttestation(request.HSMData); err != nil {
            return &DeviceAttestationResponse{
                Success: false,
                Reason:  "HSM verification failed",
            }, err
        }
    }
    
    return &DeviceAttestationResponse{
        Success:    true,
        TrustLevel: 100, // Hardware attestation grants maximum trust
        DeviceID:   request.DeviceID,
    }, nil
}
```

#### **📋 Day 27-28: Documentation Templates & Examples**
Create comprehensive documentation and example applications for each scenario.

### **Week 5: Testing & Integration (Days 29-35)**

#### **🧪 Day 29-31: Comprehensive Testing Suite**
```go
// pkg/client/keycloak_client_test.go
package client

import (
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/testcontainers/testcontainers-go"
    "github.com/testcontainers/testcontainers-go/modules/compose"
    
    "github.com/yourorg/go-keycloak-zerotrust/pkg/types"
    "github.com/yourorg/go-keycloak-zerotrust/internal/testing"
)

// Integration tests with real Keycloak instance
func TestKeycloakClient_Integration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration tests in short mode")
    }
    
    // Start Keycloak using testcontainers
    compose := testcontainers.NewLocalDockerCompose([]string{"../../deployments/docker/docker-compose.test.yml"}, "keycloak-test")
    execError := compose.WithCommand([]string{"up", "-d"}).Invoke()
    require.NoError(t, execError.Error)
    
    defer func() {
        execError := compose.Down()
        require.NoError(t, execError.Error)
    }()
    
    // Wait for Keycloak to be ready
    time.Sleep(30 * time.Second)
    
    // Create test client
    config := &types.Config{
        BaseURL:      "http://localhost:8080",
        Realm:        "test-realm",
        ClientID:     "test-client",
        ClientSecret: "test-secret",
        AdminUser:    "admin",
        AdminPass:    "admin123",
        Timeout:      10 * time.Second,
    }
    
    client, err := New(config)
    require.NoError(t, err)
    defer client.Close()
    
    t.Run("Health Check", func(t *testing.T) {
        ctx := context.Background()
        err := client.Health(ctx)
        assert.NoError(t, err)
    })
    
    t.Run("User Registration", func(t *testing.T) {
        ctx := context.Background()
        req := &types.UserRegistrationRequest{
            Username:   "testuser",
            Email:      "test@example.com",
            FirstName:  "Test",
            LastName:   "User",
            Password:   "password123",
            TrustLevel: 50,
            DeviceID:   "test-device-001",
        }
        
        user, err := client.RegisterUser(ctx, req)
        assert.NoError(t, err)
        assert.NotNil(t, user)
        assert.Equal(t, req.Username, *user.Username)
    })
}

// Unit tests with mocked dependencies
func TestKeycloakClient_ValidateToken(t *testing.T) {
    tests := []struct {
        name          string
        token         string
        setupMocks    func(*testing.MockGocloak)
        expectedClaims *types.ZeroTrustClaims
        expectedError string
    }{
        {
            name:  "valid token with zero trust claims",
            token: "valid.jwt.token",
            setupMocks: func(mock *testing.MockGocloak) {
                mock.On("RetrospectToken", mock.Anything, mock.Anything).Return(&gocloak.RetrospecTokenResult{
                    Active: gocloak.BoolP(true),
                }, nil)
                mock.On("GetUserInfo", mock.Anything, mock.Anything).Return(map[string]interface{}{
                    "sub":                "user-123",
                    "email":              "test@example.com",
                    "preferred_username": "testuser",
                }, nil)
            },
            expectedClaims: &types.ZeroTrustClaims{
                UserID:   "user-123",
                Email:    "test@example.com",
                Username: "testuser",
            },
        },
        {
            name:          "empty token",
            token:         "",
            expectedError: "access token cannot be empty",
        },
        {
            name:  "inactive token",
            token: "inactive.jwt.token",
            setupMocks: func(mock *testing.MockGocloak) {
                mock.On("RetrospectToken", mock.Anything, mock.Anything).Return(&gocloak.RetrospecTokenResult{
                    Active: gocloak.BoolP(false),
                }, nil)
            },
            expectedError: "token is not active",
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            mockGocloak := &testing.MockGocloak{}
            if tt.setupMocks != nil {
                tt.setupMocks(mockGocloak)
            }
            
            client := &KeycloakClient{
                client: mockGocloak,
                config: &types.Config{
                    ZeroTrust: &types.ZeroTrustConfig{
                        DefaultTrustLevel: 25,
                    },
                },
            }
            
            ctx := context.Background()
            claims, err := client.ValidateToken(ctx, tt.token)
            
            if tt.expectedError != "" {
                assert.Error(t, err)
                assert.Contains(t, err.Error(), tt.expectedError)
                assert.Nil(t, claims)
            } else {
                assert.NoError(t, err)
                assert.NotNil(t, claims)
                if tt.expectedClaims != nil {
                    assert.Equal(t, tt.expectedClaims.UserID, claims.UserID)
                    assert.Equal(t, tt.expectedClaims.Email, claims.Email)
                }
            }
            
            mockGocloak.AssertExpectations(t)
        })
    }
}

// Benchmark tests
func BenchmarkKeycloakClient_ValidateToken(b *testing.B) {
    client := setupBenchmarkClient(b)
    ctx := context.Background()
    token := getBenchmarkToken(b)
    
    b.ResetTimer()
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            _, err := client.ValidateToken(ctx, token)
            if err != nil {
                b.Fatal(err)
            }
        }
    })
}
```

#### **🔄 Day 32-33: Contract Testing**
```go
// pkg/middleware/contract_test.go
package middleware

import (
    "testing"
    
    "github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// ContractTestSuite defines the contract that all middleware implementations must satisfy
type ContractTestSuite struct {
    CreateMiddleware func(*types.Config) (types.Middleware, error)
}

// TestMiddlewareContract tests that middleware implementations satisfy the contract
func (suite *ContractTestSuite) TestMiddlewareContract(t *testing.T) {
    config := &types.Config{
        BaseURL:      "http://localhost:8080",
        Realm:        "test",
        ClientID:     "test-client",
        ClientSecret: "secret",
    }
    
    middleware, err := suite.CreateMiddleware(config)
    require.NoError(t, err)
    
    t.Run("Authentication", func(t *testing.T) {
        suite.testAuthentication(t, middleware)
    })
    
    t.Run("Authorization", func(t *testing.T) {
        suite.testAuthorization(t, middleware)
    })
    
    t.Run("TrustLevel", func(t *testing.T) {
        suite.testTrustLevel(t, middleware)
    })
}

// Test all framework integrations against the same contract
func TestGinMiddlewareContract(t *testing.T) {
    suite := &ContractTestSuite{
        CreateMiddleware: func(config *types.Config) (types.Middleware, error) {
            client, err := client.New(config)
            if err != nil {
                return nil, err
            }
            return NewGinMiddleware(client, nil), nil
        },
    }
    suite.TestMiddlewareContract(t)
}

func TestEchoMiddlewareContract(t *testing.T) {
    suite := &ContractTestSuite{
        CreateMiddleware: func(config *types.Config) (types.Middleware, error) {
            client, err := client.New(config)
            if err != nil {
                return nil, err
            }
            return NewEchoMiddleware(client, nil), nil
        },
    }
    suite.TestMiddlewareContract(t)
}
```

#### **📊 Day 34-35: Performance & Load Testing**
```go
// tests/performance/load_test.go
package performance

import (
    "context"
    "sync"
    "testing"
    "time"
    
    "github.com/yourorg/go-keycloak-zerotrust/pkg/client"
    "github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// LoadTest simulates realistic production load
func TestKeycloakClient_LoadTest(t *testing.T) {
    if !*loadTest {
        t.Skip("Load testing disabled. Use -load flag to enable.")
    }
    
    config := &types.Config{
        BaseURL:      getTestKeycloakURL(),
        Realm:        "load-test",
        ClientID:     "load-test-client",
        ClientSecret: getTestClientSecret(),
        Timeout:      5 * time.Second,
        Cache: &types.CacheConfig{
            Enabled: true,
            TTL:     5 * time.Minute,
        },
    }
    
    client, err := client.New(config)
    require.NoError(t, err)
    defer client.Close()
    
    // Test parameters
    numWorkers := 100
    requestsPerWorker := 1000
    testDuration := 5 * time.Minute
    
    t.Logf("Starting load test: %d workers, %d requests per worker, %v duration", 
           numWorkers, requestsPerWorker, testDuration)
    
    // Create test tokens
    testTokens := generateTestTokens(t, numWorkers*requestsPerWorker)
    
    // Metrics collection
    var (
        successCount int64
        errorCount   int64
        totalLatency time.Duration
        mutex        sync.Mutex
    )
    
    // Start workers
    var wg sync.WaitGroup
    ctx, cancel := context.WithTimeout(context.Background(), testDuration)
    defer cancel()
    
    startTime := time.Now()
    
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func(workerID int) {
            defer wg.Done()
            
            for j := 0; j < requestsPerWorker; j++ {
                if ctx.Err() != nil {
                    return
                }
                
                tokenIndex := workerID*requestsPerWorker + j
                token := testTokens[tokenIndex%len(testTokens)]
                
                reqStart := time.Now()
                _, err := client.ValidateToken(ctx, token)
                reqDuration := time.Since(reqStart)
                
                mutex.Lock()
                if err != nil {
                    errorCount++
                } else {
                    successCount++
                }
                totalLatency += reqDuration
                mutex.Unlock()
            }
        }(i)
    }
    
    wg.Wait()
    totalDuration := time.Since(startTime)
    
    // Calculate metrics
    totalRequests := successCount + errorCount
    avgLatency := totalLatency / time.Duration(totalRequests)
    rps := float64(totalRequests) / totalDuration.Seconds()
    errorRate := float64(errorCount) / float64(totalRequests) * 100
    
    t.Logf("Load test results:")
    t.Logf("  Total requests: %d", totalRequests)
    t.Logf("  Successful: %d", successCount)
    t.Logf("  Errors: %d", errorCount)
    t.Logf("  Error rate: %.2f%%", errorRate)
    t.Logf("  Average latency: %v", avgLatency)
    t.Logf("  Requests per second: %.2f", rps)
    t.Logf("  Total duration: %v", totalDuration)
    
    // Assert performance requirements
    assert.Less(t, errorRate, 1.0, "Error rate should be less than 1%")
    assert.Less(t, avgLatency, 100*time.Millisecond, "Average latency should be less than 100ms")
    assert.Greater(t, rps, 1000.0, "Should handle at least 1000 requests per second")
}
```

### **Week 6: Documentation, Examples & Release (Days 36-42)**

#### **📚 Day 36-38: Comprehensive Documentation**
Create complete documentation including:

1. **Quick Start Guide** (5-minute integration)
2. **Configuration Reference** (all options documented)
3. **Framework Integration Guides** (Gin, Echo, Fiber, gRPC)
4. **Zero Trust Implementation Guide** (trust levels, device attestation)
5. **Production Deployment Guide** (Docker, Kubernetes, performance tuning)
6. **Migration Guide** (from other auth libraries)
7. **Plugin Development Guide** (custom plugins)
8. **Troubleshooting Guide** (common issues and solutions)

#### **💻 Day 39-40: Example Applications**
Create production-ready examples for each usage scenario:

1. **quickstart/** - 5-minute Gin integration
2. **gin-basic/** - Basic Gin web application with roles
3. **echo-basic/** - Echo framework integration
4. **fiber-basic/** - Fiber framework integration
5. **grpc-service/** - gRPC microservice with workload identity
6. **multi-tenant/** - Multi-tenant SaaS application
7. **high-security/** - Financial services with device attestation
8. **mobile-backend/** - Mobile app backend with device binding

#### **🚀 Day 41-42: Release Preparation**
1. **Final Testing** - Complete test suite execution
2. **Security Audit** - Third-party security review
3. **Performance Validation** - Load testing and optimization
4. **Documentation Review** - Technical writing review
5. **Release Notes** - Feature documentation and migration guide
6. **GitHub Release** - Tagged release with binaries
7. **Go Module Publishing** - Available via `go get`

---

## 📊 **Implementation Checklist**

### **Week 1: Foundation ✅**
- [ ] Repository setup and project structure
- [ ] Core types and interfaces defined
- [ ] Basic Keycloak client implementation
- [ ] Configuration management system
- [ ] Initial test framework

### **Week 2: Middleware ✅**
- [ ] Universal middleware layer
- [ ] Gin integration with all features
- [ ] Echo framework integration
- [ ] Fiber framework integration
- [ ] gRPC interceptors implementation

### **Week 3: Zero Trust ✅**
- [ ] Trust level management system
- [ ] Device attestation framework
- [ ] Continuous verification engine
- [ ] Risk assessment algorithms
- [ ] Context-aware trust decisions

### **Week 4: Configuration & Plugins ✅**
- [ ] Advanced configuration management
- [ ] Plugin system architecture
- [ ] Built-in plugin implementations
- [ ] Configuration validation
- [ ] Environment variable support

### **Week 5: Testing ✅**
- [ ] Unit test suite (>95% coverage)
- [ ] Integration tests with real Keycloak
- [ ] Contract tests for all middleware
- [ ] Performance and load testing
- [ ] Security penetration testing

### **Week 6: Documentation & Release ✅**
- [ ] Complete documentation suite
- [ ] Example applications for all scenarios
- [ ] Migration tools and guides
- [ ] Release preparation and publishing
- [ ] Community feedback collection

---

## 🎯 **Success Criteria**

### **Technical Metrics**
- **Performance**: <50ms token validation latency
- **Reliability**: 99.9% uptime in production tests
- **Security**: Zero critical vulnerabilities
- **Coverage**: >95% test coverage
- **Documentation**: 100% API documentation

### **Business Metrics**
- **GitHub Stars**: 500+ within 30 days of release
- **Downloads**: 1,000+ monthly downloads within 60 days
- **Enterprise Inquiries**: 10+ within 90 days
- **Community**: 25+ contributors within 120 days

### **Quality Metrics**
- **Issue Response**: <24 hours for critical issues
- **Documentation Score**: >4.5/5 user satisfaction
- **Integration Time**: <30 minutes for basic setup
- **Migration Time**: <2 hours from other auth libraries

This comprehensive 6-week implementation plan will deliver a production-ready, enterprise-grade Keycloak Zero Trust library that can immediately generate revenue through enterprise licensing while building a strong open source community.