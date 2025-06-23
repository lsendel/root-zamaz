// Package fiber provides Fiber framework middleware for Keycloak Zero Trust authentication
package fiber

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// Middleware provides Fiber-specific middleware functions
type Middleware struct {
	client types.KeycloakClient
	config *types.MiddlewareConfig
}

// NewMiddleware creates a new Fiber middleware instance
func NewMiddleware(client types.KeycloakClient, config *types.MiddlewareConfig) *Middleware {
	if config == nil {
		config = &types.MiddlewareConfig{
			TokenHeader:    "Authorization",
			ContextUserKey: "user",
			SkipPaths:      []string{"/health", "/metrics"},
			RequestTimeout: 30 * time.Second,
		}
	}
	
	return &Middleware{
		client: client,
		config: config,
	}
}

// Authenticate provides basic authentication middleware
func (m *Middleware) Authenticate() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Skip authentication for configured paths
		if m.shouldSkipPath(c.Path()) {
			return c.Next()
		}

		// Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), m.config.RequestTimeout)
		defer cancel()

		// Extract token from header
		token := m.extractToken(c)
		if token == "" {
			return m.handleAuthError(c, types.ErrMissingToken)
		}

		// Validate token
		claims, err := m.client.ValidateToken(ctx, token)
		if err != nil {
			return m.handleAuthError(c, err)
		}

		// Create authenticated user and set in context
		user := m.createAuthenticatedUser(claims)
		c.Locals(m.config.ContextUserKey, user)

		return c.Next()
	}
}

// RequireAuth ensures the request is authenticated (alias for Authenticate for clarity)
func (m *Middleware) RequireAuth() fiber.Handler {
	return m.Authenticate()
}

// RequireRole requires the user to have a specific role
func (m *Middleware) RequireRole(requiredRole string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := m.GetCurrentUser(c)
		if user == nil {
			return m.handleAuthError(c, types.ErrMissingToken)
		}

		// Check if user has the required role
		hasRole := false
		for _, role := range user.Roles {
			if role == requiredRole {
				hasRole = true
				break
			}
		}

		if !hasRole {
			return m.handleAuthError(c, types.ErrInsufficientRole)
		}

		return c.Next()
	}
}

// RequireAnyRole requires the user to have at least one of the specified roles
func (m *Middleware) RequireAnyRole(roles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := m.GetCurrentUser(c)
		if user == nil {
			return m.handleAuthError(c, types.ErrMissingToken)
		}

		// Check if user has any of the required roles
		hasRole := false
		for _, userRole := range user.Roles {
			for _, requiredRole := range roles {
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
			return m.handleAuthError(c, types.ErrInsufficientRole)
		}

		return c.Next()
	}
}

// RequireTrustLevel requires a minimum trust level
func (m *Middleware) RequireTrustLevel(minTrustLevel int) fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := m.GetCurrentUser(c)
		if user == nil {
			return m.handleAuthError(c, types.ErrMissingToken)
		}

		if user.TrustLevel < minTrustLevel {
			return m.handleAuthError(c, &types.AuthError{
				Code:    types.ErrCodeInsufficientTrust,
				Message: "insufficient trust level",
				Details: "required: " + strconv.Itoa(minTrustLevel) + ", current: " + strconv.Itoa(user.TrustLevel),
			})
		}

		return c.Next()
	}
}

// RequireDeviceVerification requires device verification
func (m *Middleware) RequireDeviceVerification() fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := m.GetCurrentUser(c)
		if user == nil {
			return m.handleAuthError(c, types.ErrMissingToken)
		}

		if !user.DeviceVerified {
			return m.handleAuthError(c, types.ErrDeviceNotVerified)
		}

		return c.Next()
	}
}

// RequireTenant ensures multi-tenant context is valid
func (m *Middleware) RequireTenant() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// This would be implemented based on the tenant resolver configuration
		// For now, it's a placeholder that sets tenant info in context
		
		// In a real implementation, this would:
		// 1. Extract tenant ID using the configured TenantResolver
		// 2. Validate tenant access for the authenticated user
		// 3. Set tenant context for downstream handlers
		
		c.Locals("tenant", "default") // Placeholder
		return c.Next()
	}
}

// CORS provides CORS middleware if enabled
func (m *Middleware) CORS() fiber.Handler {
	if !m.config.CorsEnabled {
		return func(c *fiber.Ctx) error {
			return c.Next()
		}
	}

	return func(c *fiber.Ctx) error {
		origin := c.Get("Origin")
		
		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range m.config.CorsOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			c.Set("Access-Control-Allow-Origin", origin)
			c.Set("Access-Control-Allow-Credentials", "true")
			c.Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
			c.Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, PATCH")
		}

		if c.Method() == "OPTIONS" {
			return c.SendStatus(fiber.StatusNoContent)
		}

		return c.Next()
	}
}

// RateLimiter provides rate limiting middleware for Fiber
func (m *Middleware) RateLimiter(max int, window time.Duration) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// This is a simplified rate limiter implementation
		// In production, you would use Redis or a more sophisticated implementation
		
		// For now, just pass through
		// TODO: Implement proper rate limiting with configurable backends
		return c.Next()
	}
}

// RequestID adds a unique request ID to each request
func (m *Middleware) RequestID() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Check if request ID already exists
		requestID := c.Get("X-Request-ID")
		if requestID == "" {
			// Generate a simple request ID (in production, use proper UUID)
			requestID = generateRequestID()
			c.Set("X-Request-ID", requestID)
		}
		
		// Store in locals for access in handlers
		c.Locals("request_id", requestID)
		
		return c.Next()
	}
}

// GetCurrentUser retrieves the authenticated user from context
func (m *Middleware) GetCurrentUser(c *fiber.Ctx) *types.AuthenticatedUser {
	user := c.Locals(m.config.ContextUserKey)
	if user == nil {
		return nil
	}

	authUser, ok := user.(*types.AuthenticatedUser)
	if !ok {
		return nil
	}

	return authUser
}

// GetCurrentTenant retrieves the current tenant from context
func (m *Middleware) GetCurrentTenant(c *fiber.Ctx) string {
	tenant := c.Locals("tenant")
	if tenant == nil {
		return ""
	}

	tenantStr, ok := tenant.(string)
	if !ok {
		return ""
	}

	return tenantStr
}

// GetRequestID retrieves the request ID from context
func (m *Middleware) GetRequestID(c *fiber.Ctx) string {
	requestID := c.Locals("request_id")
	if requestID == nil {
		return ""
	}

	requestIDStr, ok := requestID.(string)
	if !ok {
		return ""
	}

	return requestIDStr
}

// Helper methods

// shouldSkipPath checks if the path should skip authentication
func (m *Middleware) shouldSkipPath(path string) bool {
	for _, skipPath := range m.config.SkipPaths {
		if path == skipPath || strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// extractToken extracts the JWT token from the request
func (m *Middleware) extractToken(c *fiber.Ctx) string {
	// Try header first
	authHeader := c.Get(m.config.TokenHeader)
	if authHeader != "" {
		// Remove "Bearer " prefix if present
		if strings.HasPrefix(authHeader, "Bearer ") {
			return strings.TrimPrefix(authHeader, "Bearer ")
		}
		return authHeader
	}

	// Try query parameter as fallback
	token := c.Query("token")
	if token != "" {
		return token
	}

	// Try cookie as last resort
	cookie := c.Cookies("access_token")
	if cookie != "" {
		return cookie
	}

	return ""
}

// createAuthenticatedUser creates an AuthenticatedUser from claims
func (m *Middleware) createAuthenticatedUser(claims *types.ZeroTrustClaims) *types.AuthenticatedUser {
	user := &types.AuthenticatedUser{
		UserID:           claims.UserID,
		Email:            claims.Email,
		Username:         claims.PreferredUsername,
		FirstName:        claims.GivenName,
		LastName:         claims.FamilyName,
		Roles:            claims.Roles,
		TrustLevel:       claims.TrustLevel,
		DeviceID:         claims.DeviceID,
		DeviceVerified:   claims.DeviceVerified,
		LastVerification: claims.LastVerification,
		SessionState:     claims.SessionState,
		RiskScore:        claims.RiskScore,
		LocationInfo:     claims.LocationInfo,
	}

	// Set expiration time
	if claims.ExpiresAt != nil {
		user.ExpiresAt = claims.ExpiresAt.Time
	}

	return user
}

// handleAuthError handles authentication errors consistently
func (m *Middleware) handleAuthError(c *fiber.Ctx, err error) error {
	// If a custom error handler is configured, use it
	if m.config.ErrorHandler != nil {
		if handledErr := m.config.ErrorHandler(context.Background(), err); handledErr != nil {
			err = handledErr
		}
	}

	// Determine HTTP status code based on error type
	var statusCode int
	var response fiber.Map

	if authErr, ok := err.(*types.AuthError); ok {
		switch authErr.Code {
		case types.ErrCodeUnauthorized, types.ErrCodeInvalidToken, types.ErrCodeExpiredToken:
			statusCode = fiber.StatusUnauthorized
		case types.ErrCodeForbidden, types.ErrCodeInsufficientTrust, types.ErrCodeInsufficientRole, types.ErrCodeDeviceNotVerified:
			statusCode = fiber.StatusForbidden
		case types.ErrCodeConnectionError, types.ErrCodeConfigurationError:
			statusCode = fiber.StatusInternalServerError
		default:
			statusCode = fiber.StatusUnauthorized
		}

		response = fiber.Map{
			"error": fiber.Map{
				"code":    authErr.Code,
				"message": authErr.Message,
			},
		}

		if authErr.Details != "" {
			response["error"].(fiber.Map)["details"] = authErr.Details
		}
	} else {
		// Generic error
		statusCode = fiber.StatusUnauthorized
		response = fiber.Map{
			"error": fiber.Map{
				"code":    "AUTHENTICATION_ERROR",
				"message": err.Error(),
			},
		}
	}

	return c.Status(statusCode).JSON(response)
}

// generateRequestID generates a simple request ID
func generateRequestID() string {
	// Simple implementation - in production use proper UUID
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

// FiberMiddleware creates a new Fiber middleware instance from the client
func FiberMiddleware(client types.KeycloakClient, config ...*types.MiddlewareConfig) *Middleware {
	var cfg *types.MiddlewareConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	return NewMiddleware(client, cfg)
}