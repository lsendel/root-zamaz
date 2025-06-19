# Go Fiber Integration with Zero Trust Authentication

This example demonstrates how to integrate Zero Trust Authentication into a Go web application using the Fiber v2 framework. It showcases middleware-based authentication, role-based access control, and best practices for secure API development.

## Features

- ✅ Fiber v2 middleware integration
- ✅ JWT token validation
- ✅ Role-based access control (RBAC)
- ✅ Scope-based permissions
- ✅ Rate limiting and security headers
- ✅ Structured logging with zerolog
- ✅ OpenTelemetry observability
- ✅ Graceful shutdown
- ✅ Health checks and metrics

## Prerequisites

- Go 1.23.8+
- Zero Trust Auth service running
- Basic Go and Fiber knowledge

## Quick Start

```bash
# Initialize Go module
go mod init zerotrust-fiber-example
cd zerotrust-fiber-example

# Install dependencies
go get github.com/gofiber/fiber/v2
go get mvp.local/pkg/sdk/go
go get github.com/gofiber/fiber/v2/middleware/cors
go get github.com/gofiber/fiber/v2/middleware/helmet
go get github.com/gofiber/fiber/v2/middleware/limiter
go get github.com/gofiber/fiber/v2/middleware/logger
go get github.com/gofiber/fiber/v2/middleware/recover

# Copy example files (see below)
# Run the application
go run main.go
```

## Project Structure

```
zerotrust-fiber-example/
├── main.go
├── go.mod
├── go.sum
├── config/
│   └── config.go
├── middleware/
│   ├── auth.go
│   ├── cors.go
│   └── security.go
├── handlers/
│   ├── auth.go
│   ├── users.go
│   └── health.go
├── models/
│   └── responses.go
├── services/
│   └── auth.go
└── utils/
    ├── logger.go
    └── errors.go
```

## Core Implementation

### Main Application

```go
// main.go
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"mvp.local/pkg/sdk/go"

	"zerotrust-fiber-example/config"
	"zerotrust-fiber-example/handlers"
	"zerotrust-fiber-example/middleware"
	"zerotrust-fiber-example/services"
	"zerotrust-fiber-example/utils"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize logger
	logger := utils.NewLogger(cfg.LogLevel)

	// Initialize Zero Trust SDK client
	client, err := sdk.NewClient(sdk.Config{
		BaseURL: cfg.ZeroTrust.BaseURL,
		APIKey:  cfg.ZeroTrust.APIKey,
		Timeout: cfg.ZeroTrust.Timeout,
		Debug:   cfg.Debug,
	})
	if err != nil {
		log.Fatal("Failed to create Zero Trust client:", err)
	}
	defer client.Close()

	// Initialize services
	authService := services.NewAuthService(client, logger)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService, logger)
	userHandler := handlers.NewUserHandler(authService, logger)
	healthHandler := handlers.NewHealthHandler(client, logger)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:      "Zero Trust Fiber Example",
		ServerHeader: "Fiber",
		ErrorHandler: errorHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	})

	// Security middleware
	app.Use(helmet.New(helmet.Config{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "DENY",
		HSTSMaxAge:            31536000,
		HSTSIncludeSubdomains: true,
		CSPReportOnly:         false,
		CSP:                   "default-src 'self'",
	}))

	app.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.CORS.AllowedOrigins,
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Requested-With",
		AllowCredentials: true,
		MaxAge:           86400,
	}))

	// Rate limiting
	app.Use(limiter.New(limiter.Config{
		Max:        100,
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(429).JSON(fiber.Map{
				"error": "Rate limit exceeded",
			})
		},
	}))

	// Logging middleware
	app.Use(logger.New(logger.Config{
		Format: "${time} ${method} ${path} ${status} ${latency} ${ip} ${ua}\n",
	}))

	// Recovery middleware
	app.Use(recover.New(recover.Config{
		EnableStackTrace: cfg.Debug,
	}))

	// Initialize auth middleware
	authMiddleware := middleware.NewAuthMiddleware(authService)

	// Public routes
	public := app.Group("/api/v1")
	public.Post("/auth/login", authHandler.Login)
	public.Post("/auth/refresh", authHandler.Refresh)
	public.Get("/health", healthHandler.Health)
	public.Get("/health/ready", healthHandler.Ready)
	public.Get("/health/live", healthHandler.Live)

	// Protected routes
	protected := app.Group("/api/v1")
	protected.Use(authMiddleware.Authenticate())

	// User routes
	users := protected.Group("/users")
	users.Get("/profile", userHandler.GetProfile)
	users.Put("/profile", userHandler.UpdateProfile)
	users.Post("/logout", authHandler.Logout)

	// Admin routes
	admin := protected.Group("/admin")
	admin.Use(authMiddleware.RequireRoles("admin"))
	admin.Get("/users", userHandler.ListUsers)
	admin.Post("/users", userHandler.CreateUser)
	admin.Get("/users/:id", userHandler.GetUser)
	admin.Put("/users/:id", userHandler.UpdateUser)
	admin.Delete("/users/:id", userHandler.DeleteUser)

	// Super admin routes
	superAdmin := protected.Group("/super-admin")
	superAdmin.Use(authMiddleware.RequireRoles("super-admin"))
	superAdmin.Get("/system/stats", handlers.GetSystemStats)

	// Start server
	go func() {
		logger.Info().
			Str("port", cfg.Server.Port).
			Msg("Starting server")

		if err := app.Listen(":" + cfg.Server.Port); err != nil {
			logger.Fatal().Err(err).Msg("Failed to start server")
		}
	}()

	// Graceful shutdown
	gracefulShutdown(app, logger)
}

func errorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	message := "Internal Server Error"

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
		message = e.Message
	}

	return c.Status(code).JSON(fiber.Map{
		"error":   message,
		"code":    code,
		"path":    c.Path(),
		"method":  c.Method(),
		"time":    time.Now().Unix(),
	})
}

func gracefulShutdown(app *fiber.App, logger utils.Logger) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	<-c
	logger.Info().Msg("Gracefully shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := app.ShutdownWithContext(ctx); err != nil {
		logger.Error().Err(err).Msg("Server forced to shutdown")
	}

	logger.Info().Msg("Server exited")
}
```

### Authentication Middleware

```go
// middleware/auth.go
package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"mvp.local/pkg/sdk/go"

	"zerotrust-fiber-example/services"
	"zerotrust-fiber-example/utils"
)

type AuthMiddleware struct {
	authService *services.AuthService
	logger      utils.Logger
}

func NewAuthMiddleware(authService *services.AuthService) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
		logger:      utils.NewLogger("info"),
	}
}

// Authenticate validates JWT tokens and sets user context
func (m *AuthMiddleware) Authenticate() fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := m.extractToken(c)
		if token == "" {
			return c.Status(401).JSON(fiber.Map{
				"error": "Authentication required",
				"code":  "MISSING_TOKEN",
			})
		}

		claims, err := m.authService.ValidateToken(c.Context(), token)
		if err != nil {
			m.logger.Error().
				Err(err).
				Str("ip", c.IP()).
				Str("user_agent", c.Get("User-Agent")).
				Msg("Token validation failed")

			return c.Status(401).JSON(fiber.Map{
				"error": "Invalid token",
				"code":  "INVALID_TOKEN",
			})
		}

		// Store claims in context
		c.Locals("claims", claims)
		c.Locals("user_id", claims.Subject)
		c.Locals("user_email", claims.Email)
		c.Locals("user_roles", claims.Roles)

		m.logger.Debug().
			Str("user_id", claims.Subject).
			Str("email", claims.Email).
			Strs("roles", claims.Roles).
			Str("path", c.Path()).
			Msg("User authenticated")

		return c.Next()
	}
}

// RequireRoles ensures user has at least one of the required roles
func (m *AuthMiddleware) RequireRoles(requiredRoles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims := m.getClaimsFromContext(c)
		if claims == nil {
			return c.Status(401).JSON(fiber.Map{
				"error": "Authentication required",
				"code":  "MISSING_AUTH",
			})
		}

		hasRole := false
		for _, userRole := range claims.Roles {
			for _, requiredRole := range requiredRoles {
				if userRole == requiredRole {
					hasRole = true
					break
				}
			}
			if hasRole {
				break
			}
		}

		if !hasRole {
			m.logger.Warn().
				Str("user_id", claims.Subject).
				Strs("user_roles", claims.Roles).
				Strs("required_roles", requiredRoles).
				Str("path", c.Path()).
				Msg("Access denied - insufficient roles")

			return c.Status(403).JSON(fiber.Map{
				"error":          "Insufficient permissions",
				"code":           "INSUFFICIENT_ROLES",
				"required_roles": requiredRoles,
				"user_roles":     claims.Roles,
			})
		}

		return c.Next()
	}
}

// RequireScopes ensures user has all required scopes
func (m *AuthMiddleware) RequireScopes(requiredScopes ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims := m.getClaimsFromContext(c)
		if claims == nil {
			return c.Status(401).JSON(fiber.Map{
				"error": "Authentication required",
				"code":  "MISSING_AUTH",
			})
		}

		userScopes := claims.Permissions
		for _, requiredScope := range requiredScopes {
			found := false
			for _, userScope := range userScopes {
				if userScope == requiredScope {
					found = true
					break
				}
			}
			if !found {
				m.logger.Warn().
					Str("user_id", claims.Subject).
					Strs("user_scopes", userScopes).
					Strs("required_scopes", requiredScopes).
					Str("path", c.Path()).
					Msg("Access denied - insufficient scopes")

				return c.Status(403).JSON(fiber.Map{
					"error":           "Insufficient permissions",
					"code":            "INSUFFICIENT_SCOPES",
					"required_scopes": requiredScopes,
					"user_scopes":     userScopes,
				})
			}
		}

		return c.Next()
	}
}

// extractToken extracts JWT token from Authorization header
func (m *AuthMiddleware) extractToken(c *fiber.Ctx) string {
	auth := c.Get("Authorization")
	if auth == "" {
		return ""
	}

	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}

	return ""
}

// getClaimsFromContext retrieves claims from fiber context
func (m *AuthMiddleware) getClaimsFromContext(c *fiber.Ctx) *sdk.Claims {
	claims := c.Locals("claims")
	if claims == nil {
		return nil
	}

	if c, ok := claims.(*sdk.Claims); ok {
		return c
	}

	return nil
}

// GetUserID extracts user ID from context
func GetUserID(c *fiber.Ctx) string {
	if userID := c.Locals("user_id"); userID != nil {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	return ""
}

// GetUserEmail extracts user email from context
func GetUserEmail(c *fiber.Ctx) string {
	if email := c.Locals("user_email"); email != nil {
		if e, ok := email.(string); ok {
			return e
		}
	}
	return ""
}

// GetUserRoles extracts user roles from context
func GetUserRoles(c *fiber.Ctx) []string {
	if roles := c.Locals("user_roles"); roles != nil {
		if r, ok := roles.([]string); ok {
			return r
		}
	}
	return []string{}
}
```

### Authentication Service

```go
// services/auth.go
package services

import (
	"context"
	"fmt"

	"mvp.local/pkg/sdk/go"

	"zerotrust-fiber-example/utils"
)

type AuthService struct {
	client *sdk.Client
	logger utils.Logger
}

func NewAuthService(client *sdk.Client, logger utils.Logger) *AuthService {
	return &AuthService{
		client: client,
		logger: logger,
	}
}

func (s *AuthService) Login(ctx context.Context, email, password string) (*sdk.AuthenticationResponse, error) {
	s.logger.Info().
		Str("email", email).
		Msg("User login attempt")

	response, err := s.client.Authenticate(ctx, sdk.AuthenticationRequest{
		Email:    email,
		Password: password,
		Remember: true,
	})

	if err != nil {
		s.logger.Error().
			Err(err).
			Str("email", email).
			Msg("Login failed")
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	s.logger.Info().
		Str("email", email).
		Str("user_id", response.User.ID).
		Bool("requires_mfa", response.RequiresMFA).
		Msg("Login successful")

	return response, nil
}

func (s *AuthService) ValidateToken(ctx context.Context, token string) (*sdk.Claims, error) {
	response, err := s.client.ValidateToken(ctx, sdk.TokenValidationRequest{
		Token: token,
	})

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if !response.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	return response.Claims, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*sdk.AuthenticationResponse, error) {
	s.logger.Info().Msg("Token refresh attempt")

	response, err := s.client.RefreshToken(ctx, sdk.RefreshTokenRequest{
		RefreshToken: refreshToken,
	})

	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("Token refresh failed")
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	s.logger.Info().
		Str("user_id", response.User.ID).
		Msg("Token refresh successful")

	return response, nil
}

func (s *AuthService) Logout(ctx context.Context, token string) error {
	s.logger.Info().Msg("User logout")

	err := s.client.Logout(ctx, sdk.LogoutRequest{
		Token:      token,
		Everywhere: false,
	})

	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("Logout failed")
		return fmt.Errorf("logout failed: %w", err)
	}

	s.logger.Info().Msg("Logout successful")
	return nil
}

func (s *AuthService) GetUserProfile(ctx context.Context, token string) (*sdk.User, error) {
	user, err := s.client.GetUserProfile(ctx, token)
	if err != nil {
		s.logger.Error().
			Err(err).
			Msg("Failed to get user profile")
		return nil, fmt.Errorf("failed to get user profile: %w", err)
	}

	return user, nil
}
```

### Authentication Handlers

```go
// handlers/auth.go
package handlers

import (
	"github.com/gofiber/fiber/v2"

	"zerotrust-fiber-example/middleware"
	"zerotrust-fiber-example/models"
	"zerotrust-fiber-example/services"
	"zerotrust-fiber-example/utils"
)

type AuthHandler struct {
	authService *services.AuthService
	logger      utils.Logger
}

func NewAuthHandler(authService *services.AuthService, logger utils.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		logger:      logger,
	}
}

func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var req models.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body",
			"code":  "INVALID_REQUEST",
		})
	}

	// Validate request
	if req.Email == "" || req.Password == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Email and password are required",
			"code":  "MISSING_CREDENTIALS",
		})
	}

	response, err := h.authService.Login(c.Context(), req.Email, req.Password)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{
			"error": "Authentication failed",
			"code":  "AUTH_FAILED",
		})
	}

	if response.RequiresMFA {
		return c.JSON(fiber.Map{
			"requires_mfa":   true,
			"mfa_challenge":  response.MFAChallenge,
			"partial_token":  response.PartialToken,
		})
	}

	return c.JSON(models.LoginResponse{
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,
		ExpiresAt:    response.ExpiresAt,
		TokenType:    "Bearer",
		User: models.UserInfo{
			ID:          response.User.ID,
			Email:       response.User.Email,
			FirstName:   response.User.FirstName,
			LastName:    response.User.LastName,
			DisplayName: response.User.DisplayName,
			Roles:       response.User.Roles,
			IsActive:    response.User.IsActive,
			IsVerified:  response.User.IsVerified,
		},
		TrustScore: response.TrustScore,
	})
}

func (h *AuthHandler) Refresh(c *fiber.Ctx) error {
	var req models.RefreshRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid request body",
			"code":  "INVALID_REQUEST",
		})
	}

	if req.RefreshToken == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Refresh token is required",
			"code":  "MISSING_REFRESH_TOKEN",
		})
	}

	response, err := h.authService.RefreshToken(c.Context(), req.RefreshToken)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{
			"error": "Token refresh failed",
			"code":  "REFRESH_FAILED",
		})
	}

	return c.JSON(models.RefreshResponse{
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,
		ExpiresAt:    response.ExpiresAt,
		TokenType:    "Bearer",
	})
}

func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	token := c.Get("Authorization")
	if token != "" && len(token) > 7 {
		token = token[7:] // Remove "Bearer " prefix
	}

	if token == "" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Token is required",
			"code":  "MISSING_TOKEN",
		})
	}

	err := h.authService.Logout(c.Context(), token)
	if err != nil {
		h.logger.Error().Err(err).Msg("Logout failed")
		// Don't return error to client, logout should always succeed from client perspective
	}

	return c.JSON(fiber.Map{
		"message": "Logout successful",
	})
}
```

### Response Models

```go
// models/responses.go
package models

import "time"

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
	MFA      string `json:"mfa,omitempty"`
	Remember bool   `json:"remember,omitempty"`
}

type LoginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
	User         UserInfo  `json:"user"`
	TrustScore   float64   `json:"trust_score"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type RefreshResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

type UserInfo struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	FirstName   string   `json:"first_name"`
	LastName    string   `json:"last_name"`
	DisplayName string   `json:"display_name"`
	Roles       []string `json:"roles"`
	IsActive    bool     `json:"is_active"`
	IsVerified  bool     `json:"is_verified"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Details string `json:"details,omitempty"`
	TraceID string `json:"trace_id,omitempty"`
}
```

### Configuration

```go
// config/config.go
package config

import (
	"os"
	"time"
)

type Config struct {
	Server struct {
		Port string
		Host string
	}
	ZeroTrust struct {
		BaseURL string
		APIKey  string
		Timeout time.Duration
	}
	CORS struct {
		AllowedOrigins []string
	}
	LogLevel string
	Debug    bool
}

func Load() *Config {
	cfg := &Config{}

	// Server configuration
	cfg.Server.Port = getEnv("PORT", "8080")
	cfg.Server.Host = getEnv("HOST", "localhost")

	// Zero Trust configuration
	cfg.ZeroTrust.BaseURL = getEnv("ZEROTRUST_BASE_URL", "http://localhost:8080")
	cfg.ZeroTrust.APIKey = getEnv("ZEROTRUST_API_KEY", "dev-api-key")
	cfg.ZeroTrust.Timeout = 30 * time.Second

	// CORS configuration
	cfg.CORS.AllowedOrigins = []string{
		getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:3001"),
	}

	// Logging
	cfg.LogLevel = getEnv("LOG_LEVEL", "info")
	cfg.Debug = getEnv("DEBUG", "false") == "true"

	return cfg
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
```

## Usage Examples

### Client Integration

```bash
# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'

# Access protected endpoint
curl -X GET http://localhost:8080/api/v1/users/profile \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."

# Admin endpoint
curl -X GET http://localhost:8080/api/v1/admin/users \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."

# Refresh token
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"eyJhbGciOiJSUzI1NiIs..."}'

# Logout
curl -X POST http://localhost:8080/api/v1/users/logout \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
```

## Environment Configuration

```bash
# .env
PORT=8080
HOST=localhost

# Zero Trust Auth service
ZEROTRUST_BASE_URL=https://auth.example.com
ZEROTRUST_API_KEY=your-api-key

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001

# Logging
LOG_LEVEL=info
DEBUG=false
```

## Testing

```go
// handlers/auth_test.go
package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"zerotrust-fiber-example/handlers"
	"zerotrust-fiber-example/models"
)

func TestLoginHandler(t *testing.T) {
	// Create test app
	app := fiber.New()
	
	// Mock auth service
	mockAuthService := &MockAuthService{}
	
	// Setup handler
	handler := handlers.NewAuthHandler(mockAuthService, nil)
	app.Post("/login", handler.Login)

	// Test successful login
	t.Run("successful login", func(t *testing.T) {
		loginReq := models.LoginRequest{
			Email:    "test@example.com",
			Password: "password123",
		}
		
		reqBody, _ := json.Marshal(loginReq)
		req := httptest.NewRequest("POST", "/login", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")

		mockAuthService.On("Login", mock.Anything, "test@example.com", "password123").
			Return(&sdk.AuthenticationResponse{
				AccessToken:  "mock-access-token",
				RefreshToken: "mock-refresh-token",
				RequiresMFA:  false,
			}, nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})
}
```

## Docker Deployment

```dockerfile
# Dockerfile
FROM golang:1.23.8-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/main .
EXPOSE 8080

CMD ["./main"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  zerotrust-fiber-app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - ZEROTRUST_BASE_URL=http://auth-service:8080
      - ZEROTRUST_API_KEY=your-api-key
      - LOG_LEVEL=info
    depends_on:
      - auth-service
    networks:
      - zerotrust-network

networks:
  zerotrust-network:
    external: true
```

## Best Practices

1. **Security**
   - Always validate tokens on protected routes
   - Use HTTPS in production
   - Implement rate limiting
   - Sanitize user inputs
   - Use security headers

2. **Performance**
   - Cache token validation results
   - Use connection pooling
   - Implement graceful shutdown
   - Monitor response times

3. **Error Handling**
   - Return consistent error responses
   - Log security events
   - Don't leak sensitive information
   - Implement circuit breakers

4. **Observability**
   - Add structured logging
   - Implement health checks
   - Use distributed tracing
   - Monitor key metrics

## Troubleshooting

### Common Issues

1. **Token Validation Fails**
   - Check token format
   - Verify API key
   - Check service connectivity

2. **CORS Issues**
   - Configure allowed origins
   - Set proper headers
   - Handle preflight requests

3. **Performance Issues**
   - Enable token caching
   - Optimize middleware order
   - Monitor resource usage

For more examples and advanced patterns, see the [examples directory](../) and [SDK documentation](../../sdk/).