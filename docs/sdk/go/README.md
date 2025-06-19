# Go SDK for MVP Zero Trust Authentication

The Go SDK provides a comprehensive, type-safe interface for integrating with the MVP Zero Trust Authentication system. It includes client libraries, middleware, utilities, and examples for easy integration into Go applications.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Authentication](#authentication)
- [Middleware Integration](#middleware-integration)
- [Token Management](#token-management)
- [User Management](#user-management)
- [Error Handling](#error-handling)
- [Utilities](#utilities)
- [Examples](#examples)
- [API Reference](#api-reference)

## Installation

```bash
go get mvp.local/pkg/sdk/go
```

## Quick Start

### Basic Client Setup

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "mvp.local/pkg/sdk/go"
)

func main() {
    // Initialize the client
    client, err := sdk.NewClient(sdk.Config{
        BaseURL: "https://auth.example.com",
        APIKey:  "your-api-key",
        Timeout: 30 * time.Second,
        Debug:   true,
    })
    if err != nil {
        log.Fatal("Failed to create client:", err)
    }
    defer client.Close()

    // Test connection
    ctx := context.Background()
    if err := client.HealthCheck(ctx); err != nil {
        log.Fatal("Health check failed:", err)
    }

    fmt.Println("✅ Connected to Zero Trust Auth service!")
}
```

## Authentication

### User Login

```go
func authenticateUser(client *sdk.Client) {
    ctx := context.Background()

    // Authenticate user
    response, err := client.Authenticate(ctx, sdk.AuthenticationRequest{
        Email:    "user@example.com",
        Password: "secure-password",
        Remember: true,
    })
    if err != nil {
        log.Fatal("Authentication failed:", err)
    }

    if response.RequiresMFA {
        fmt.Printf("MFA required. Challenge: %s\n", response.MFAChallenge)
        // Handle MFA flow here
        return
    }

    fmt.Printf("✅ Authentication successful!\n")
    fmt.Printf("Access Token: %s\n", response.AccessToken)
    fmt.Printf("User: %s (%s)\n", response.User.DisplayName, response.User.Email)
    fmt.Printf("Trust Score: %.2f\n", response.TrustScore)
    fmt.Printf("Expires At: %s\n", response.ExpiresAt)
}
```

### Token Validation

```go
func validateToken(client *sdk.Client, token string) {
    ctx := context.Background()

    response, err := client.ValidateToken(ctx, sdk.TokenValidationRequest{
        Token:          token,
        RequiredScopes: []string{"read:profile", "write:profile"},
        Audience:       "api.example.com",
    })
    if err != nil {
        log.Printf("Token validation failed: %v", err)
        return
    }

    if !response.Valid {
        log.Println("❌ Token is invalid")
        return
    }

    fmt.Printf("✅ Token is valid!\n")
    fmt.Printf("User ID: %s\n", response.Claims.Subject)
    fmt.Printf("Email: %s\n", response.Claims.Email)
    fmt.Printf("Roles: %v\n", response.Claims.Roles)
    fmt.Printf("Trust Score: %.2f\n", response.TrustScore)
}
```

### Token Refresh

```go
func refreshToken(client *sdk.Client, refreshToken string) {
    ctx := context.Background()

    response, err := client.RefreshToken(ctx, sdk.RefreshTokenRequest{
        RefreshToken: refreshToken,
    })
    if err != nil {
        log.Fatal("Token refresh failed:", err)
    }

    fmt.Printf("✅ Token refreshed successfully!\n")
    fmt.Printf("New Access Token: %s\n", response.AccessToken)
    fmt.Printf("Expires At: %s\n", response.ExpiresAt)
}
```

## Middleware Integration

### Fiber Framework Integration

```go
package main

import (
    "log"

    "github.com/gofiber/fiber/v2"
    "mvp.local/pkg/sdk/go"
)

func main() {
    // Initialize SDK client
    client, err := sdk.NewClient(sdk.Config{
        BaseURL: "https://auth.example.com",
        APIKey:  "your-api-key",
    })
    if err != nil {
        log.Fatal(err)
    }

    app := fiber.New()

    // Public routes
    app.Get("/health", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{"status": "ok"})
    })

    // Protected routes with authentication middleware
    api := app.Group("/api/v1")
    api.Use(fiberAuthMiddleware(client))

    // Routes that require authentication
    api.Get("/profile", getProfile)
    api.Put("/profile", updateProfile)

    // Routes that require specific roles
    admin := api.Group("/admin")
    admin.Use(fiberRoleMiddleware(client, "admin"))
    admin.Get("/users", listUsers)

    log.Fatal(app.Listen(":8080"))
}

func fiberAuthMiddleware(client *sdk.Client) fiber.Handler {
    return func(c *fiber.Ctx) error {
        token := extractToken(c)
        if token == "" {
            return c.Status(401).JSON(fiber.Map{
                "error": "Authentication required",
            })
        }

        response, err := client.ValidateToken(c.Context(), sdk.TokenValidationRequest{
            Token: token,
        })
        if err != nil || !response.Valid {
            return c.Status(401).JSON(fiber.Map{
                "error": "Invalid token",
            })
        }

        // Store claims in context
        c.Locals("claims", response.Claims)
        c.Locals("user_id", response.Claims.Subject)

        return c.Next()
    }
}

func fiberRoleMiddleware(client *sdk.Client, requiredRole string) fiber.Handler {
    return func(c *fiber.Ctx) error {
        claims := c.Locals("claims").(*sdk.Claims)
        
        hasRole := false
        for _, role := range claims.Roles {
            if role == requiredRole {
                hasRole = true
                break
            }
        }

        if !hasRole {
            return c.Status(403).JSON(fiber.Map{
                "error": "Insufficient permissions",
            })
        }

        return c.Next()
    }
}

func extractToken(c *fiber.Ctx) string {
    auth := c.Get("Authorization")
    if auth == "" {
        return ""
    }
    
    if len(auth) > 7 && auth[:7] == "Bearer " {
        return auth[7:]
    }
    
    return ""
}
```

### Standard HTTP Integration

```go
package main

import (
    "log"
    "net/http"

    "mvp.local/pkg/sdk/go"
)

func main() {
    // Initialize SDK client
    client, err := sdk.NewClient(sdk.Config{
        BaseURL: "https://auth.example.com",
        APIKey:  "your-api-key",
    })
    if err != nil {
        log.Fatal(err)
    }

    // Create authentication middleware
    authMiddleware := sdk.AuthMiddleware(sdk.MiddlewareConfig{
        Client: client,
        RequiredRoles: []string{"user"},
        SkipPaths: []string{"/health", "/login"},
    })

    // Set up routes
    mux := http.NewServeMux()
    
    // Public routes
    mux.HandleFunc("/health", healthHandler)
    mux.HandleFunc("/login", loginHandler)

    // Protected routes
    mux.Handle("/api/", authMiddleware(http.HandlerFunc(apiHandler)))
    mux.Handle("/admin/", sdk.RequireRoles(client, "admin")(http.HandlerFunc(adminHandler)))

    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.Write([]byte(`{"status": "ok"}`))
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
    // Get claims from context
    claims, ok := sdk.GetClaimsFromContext(r.Context())
    if !ok {
        http.Error(w, "No authentication claims found", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.Write([]byte(fmt.Sprintf(`{"user_id": "%s", "email": "%s"}`, 
        claims.Subject, claims.Email)))
}
```

## Token Management

### Token Utilities

```go
func demonstrateTokenUtils() {
    utils := sdk.NewUtils()

    // Check if token is expired
    expiresAt := time.Now().Add(time.Hour)
    isExpired := utils.Token.IsTokenExpired(expiresAt)
    fmt.Printf("Token expired: %t\n", isExpired)

    // Check if token is expiring soon (within 5 minutes)
    expiringSoon := utils.Token.IsTokenExpiringSoon(expiresAt, 5*time.Minute)
    fmt.Printf("Token expiring soon: %t\n", expiringSoon)

    // Generate OAuth state parameter
    state, err := utils.Token.GenerateState()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("OAuth state: %s\n", state)

    // Generate PKCE code verifier and challenge
    verifier, err := utils.Token.GenerateCodeVerifier()
    if err != nil {
        log.Fatal(err)
    }
    challenge := utils.Token.GenerateCodeChallenge(verifier)
    fmt.Printf("PKCE verifier: %s\n", verifier)
    fmt.Printf("PKCE challenge: %s\n", challenge)
}
```

### OAuth Flow Implementation

```go
func oauthFlow() {
    utils := sdk.NewUtils()

    // Generate OAuth state and PKCE parameters
    state, _ := utils.Token.GenerateState()
    verifier, _ := utils.Token.GenerateCodeVerifier()
    challenge := utils.Token.GenerateCodeChallenge(verifier)

    // Build authorization URL
    authURL, err := utils.URL.BuildAuthURLWithPKCE(
        "https://auth.example.com",
        "your-client-id",
        "https://app.example.com/callback",
        state,
        challenge,
        []string{"read:profile", "write:profile"},
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Authorization URL: %s\n", authURL)

    // In your callback handler
    callbackURL := "https://app.example.com/callback?code=abc123&state=" + state
    code, returnedState, err := utils.URL.ExtractAuthCode(callbackURL)
    if err != nil {
        log.Fatal(err)
    }

    if returnedState != state {
        log.Fatal("State mismatch - possible CSRF attack")
    }

    fmt.Printf("Authorization code: %s\n", code)
    // Exchange code for tokens using your OAuth client
}
```

## User Management

### Get User Profile

```go
func getUserProfile(client *sdk.Client, token string) {
    ctx := context.Background()

    user, err := client.GetUserProfile(ctx, token)
    if err != nil {
        log.Fatal("Failed to get user profile:", err)
    }

    fmt.Printf("User Profile:\n")
    fmt.Printf("  ID: %s\n", user.ID)
    fmt.Printf("  Email: %s\n", user.Email)
    fmt.Printf("  Name: %s %s\n", user.FirstName, user.LastName)
    fmt.Printf("  Display Name: %s\n", user.DisplayName)
    fmt.Printf("  Roles: %v\n", user.Roles)
    fmt.Printf("  Trust Score: %.2f\n", user.TrustScore)
    fmt.Printf("  Active: %t\n", user.IsActive)
    fmt.Printf("  Verified: %t\n", user.IsVerified)
    fmt.Printf("  MFA Enabled: %t\n", user.MFAEnabled)
}
```

### Update User Profile

```go
func updateUserProfile(client *sdk.Client, token string) {
    ctx := context.Background()

    updatedUser, err := client.UpdateUserProfile(ctx, token, sdk.User{
        FirstName:   "John",
        LastName:    "Doe",
        DisplayName: "John Doe",
        Metadata: map[string]interface{}{
            "department": "Engineering",
            "location":   "San Francisco",
        },
    })
    if err != nil {
        log.Fatal("Failed to update user profile:", err)
    }

    fmt.Printf("✅ Profile updated successfully!\n")
    fmt.Printf("Updated Name: %s\n", updatedUser.DisplayName)
}
```

## Error Handling

### Structured Error Handling

```go
func handleErrors(client *sdk.Client) {
    ctx := context.Background()
    utils := sdk.NewUtils()

    _, err := client.Authenticate(ctx, sdk.AuthenticationRequest{
        Email:    "invalid@example.com",
        Password: "wrong-password",
    })

    if err != nil {
        // Check if it's an API error
        if apiErr, ok := err.(*sdk.APIError); ok {
            fmt.Printf("API Error - Code: %s\n", apiErr.Code)
            fmt.Printf("Message: %s\n", apiErr.Message)
            fmt.Printf("Details: %s\n", apiErr.Details)
            fmt.Printf("Trace ID: %s\n", apiErr.TraceID)

            // Check error type
            if utils.Error.IsAuthenticationError(err) {
                fmt.Println("This is an authentication error")
            }

            if utils.Error.IsRetryableError(err) {
                fmt.Println("This error can be retried")
            }
        } else {
            fmt.Printf("Other error: %v\n", err)
        }
    }
}
```

### Retry Logic Example

```go
func authenticateWithRetry(client *sdk.Client, maxRetries int) (*sdk.AuthenticationResponse, error) {
    utils := sdk.NewUtils()
    ctx := context.Background()

    request := sdk.AuthenticationRequest{
        Email:    "user@example.com",
        Password: "password",
    }

    var lastErr error
    for attempt := 0; attempt < maxRetries; attempt++ {
        response, err := client.Authenticate(ctx, request)
        if err == nil {
            return response, nil
        }

        lastErr = err

        // Don't retry authentication errors
        if utils.Error.IsAuthenticationError(err) {
            break
        }

        // Only retry if error is retryable
        if !utils.Error.IsRetryableError(err) {
            break
        }

        // Wait before retrying
        time.Sleep(time.Duration(attempt+1) * time.Second)
    }

    return nil, fmt.Errorf("authentication failed after %d attempts: %w", maxRetries, lastErr)
}
```

## Utilities

### Security Utilities

```go
func demonstrateSecurityUtils() {
    utils := sdk.NewUtils()

    // Email validation and sanitization
    email := "  USER@EXAMPLE.COM  "
    sanitized := utils.Security.SanitizeEmail(email)
    isValid := utils.Security.ValidateEmail(sanitized)
    fmt.Printf("Sanitized email: %s (valid: %t)\n", sanitized, isValid)

    // Password hashing (client-side)
    password := "user-password"
    hashedPassword := utils.Security.HashPassword(password)
    fmt.Printf("Hashed password: %s\n", hashedPassword)

    // Device fingerprinting
    userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
    ip := "192.168.1.100"
    fingerprint := utils.Security.GenerateFingerprint(userAgent, ip, "additional-data")
    fmt.Printf("Device fingerprint: %s\n", fingerprint)
}
```

### Cache Utilities

```go
func demonstrateCacheUtils() {
    utils := sdk.NewUtils()

    userID := "user-123"

    // Generate cache keys
    tokenKey := utils.Cache.GenerateTokenCacheKey(userID)
    refreshKey := utils.Cache.GenerateRefreshTokenCacheKey(userID)
    sessionKey := utils.Cache.GenerateSessionCacheKey("session-456")

    fmt.Printf("Token cache key: %s\n", tokenKey)
    fmt.Printf("Refresh token cache key: %s\n", refreshKey)
    fmt.Printf("Session cache key: %s\n", sessionKey)

    // Use with your cache implementation
    // cache.Set(tokenKey, accessToken, expiration)
    // cache.Set(refreshKey, refreshToken, refreshExpiration)
}
```

## Complete Examples

### Web Application with Authentication

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "time"

    "mvp.local/pkg/sdk/go"
)

type App struct {
    client *sdk.Client
}

func main() {
    // Initialize the app
    app := &App{}
    
    var err error
    app.client, err = sdk.NewClient(sdk.Config{
        BaseURL: "https://auth.example.com",
        APIKey:  "your-api-key",
        Timeout: 30 * time.Second,
    })
    if err != nil {
        log.Fatal("Failed to create client:", err)
    }

    // Set up routes
    http.HandleFunc("/login", app.loginHandler)
    http.HandleFunc("/logout", app.logoutHandler)
    http.HandleFunc("/refresh", app.refreshHandler)
    http.HandleFunc("/profile", app.authenticatedHandler(app.profileHandler))
    http.HandleFunc("/admin", app.roleHandler("admin", app.adminHandler))

    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func (app *App) loginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var request sdk.AuthenticationRequest
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    response, err := app.client.Authenticate(r.Context(), request)
    if err != nil {
        http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func (app *App) authenticatedHandler(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        token := extractBearerToken(r)
        if token == "" {
            http.Error(w, "Authentication required", http.StatusUnauthorized)
            return
        }

        response, err := app.client.ValidateToken(r.Context(), sdk.TokenValidationRequest{
            Token: token,
        })
        if err != nil || !response.Valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        // Add claims to request context
        ctx := context.WithValue(r.Context(), "claims", response.Claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    }
}

func (app *App) roleHandler(requiredRole string, next http.HandlerFunc) http.HandlerFunc {
    return app.authenticatedHandler(func(w http.ResponseWriter, r *http.Request) {
        claims := r.Context().Value("claims").(*sdk.Claims)
        
        hasRole := false
        for _, role := range claims.Roles {
            if role == requiredRole {
                hasRole = true
                break
            }
        }

        if !hasRole {
            http.Error(w, "Insufficient permissions", http.StatusForbidden)
            return
        }

        next.ServeHTTP(w, r)
    })
}

func extractBearerToken(r *http.Request) string {
    auth := r.Header.Get("Authorization")
    if auth == "" {
        return ""
    }
    
    if len(auth) > 7 && auth[:7] == "Bearer " {
        return auth[7:]
    }
    
    return ""
}
```

## API Reference

### Client Configuration

```go
type Config struct {
    BaseURL                string        // Required: Base URL of the auth service
    APIKey                 string        // Required: API key for authentication
    Timeout                time.Duration // Request timeout (default: 30s)
    MaxRetries             int           // Max retry attempts (default: 3)
    RetryDelay             time.Duration // Delay between retries (default: 1s)
    InsecureSkipVerify     bool          // Skip TLS verification (dev only)
    UserAgent              string        // Custom user agent
    Debug                  bool          // Enable debug logging
}
```

### Authentication Methods

```go
// Authenticate user with email/password
func (c *Client) Authenticate(ctx context.Context, req AuthenticationRequest) (*AuthenticationResponse, error)

// Validate an access token
func (c *Client) ValidateToken(ctx context.Context, req TokenValidationRequest) (*TokenValidationResponse, error)

// Refresh an access token
func (c *Client) RefreshToken(ctx context.Context, req RefreshTokenRequest) (*AuthenticationResponse, error)

// Logout user session
func (c *Client) Logout(ctx context.Context, req LogoutRequest) error

// Check service health
func (c *Client) HealthCheck(ctx context.Context) error
```

### User Management Methods

```go
// Get user profile
func (c *Client) GetUserProfile(ctx context.Context, token string) (*User, error)

// Update user profile
func (c *Client) UpdateUserProfile(ctx context.Context, token string, user User) (*User, error)
```

### Middleware Functions

```go
// General authentication middleware
func AuthMiddleware(config MiddlewareConfig) func(http.Handler) http.Handler

// Require specific roles
func RequireRoles(client *Client, roles ...string) func(http.Handler) http.Handler

// Require specific scopes
func RequireScopes(client *Client, scopes ...string) func(http.Handler) http.Handler

// Extract claims from context
func GetClaimsFromContext(ctx context.Context) (*Claims, bool)

// Extract user ID from context
func GetUserIDFromContext(ctx context.Context) (string, bool)
```

For more detailed API documentation, see the [complete API reference](./api-reference.md).