// Package gin provides Gin framework middleware for Keycloak Zero Trust authentication
package gin

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// Middleware provides Gin-specific middleware functions
type Middleware struct {
	client types.KeycloakClient
	config *types.MiddlewareConfig
}

// NewMiddleware creates a new Gin middleware instance
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
func (m *Middleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip authentication for configured paths
		if m.shouldSkipPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Create context with timeout
		ctx, cancel := context.WithTimeout(c.Request.Context(), m.config.RequestTimeout)
		defer cancel()

		// Extract token from header
		token := m.extractToken(c)
		if token == "" {
			m.handleAuthError(c, types.ErrMissingToken)
			return
		}

		// Validate token
		claims, err := m.client.ValidateToken(ctx, token)
		if err != nil {
			m.handleAuthError(c, err)
			return
		}

		// Create authenticated user and set in context
		user := m.createAuthenticatedUser(claims)
		c.Set(m.config.ContextUserKey, user)

		c.Next()
	}
}

// RequireAuth ensures the request is authenticated (alias for Authenticate for clarity)
func (m *Middleware) RequireAuth() gin.HandlerFunc {
	return m.Authenticate()
}

// RequireRole requires the user to have a specific role
func (m *Middleware) RequireRole(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get(m.config.ContextUserKey)
		if !exists {
			m.handleAuthError(c, types.ErrMissingToken)
			return
		}

		authUser, ok := user.(*types.AuthenticatedUser)
		if !ok {
			m.handleAuthError(c, types.ErrInvalidToken)
			return
		}

		// Check if user has the required role
		hasRole := false
		for _, role := range authUser.Roles {
			if role == requiredRole {
				hasRole = true
				break
			}
		}

		if !hasRole {
			m.handleAuthError(c, types.ErrInsufficientRole)
			return
		}

		c.Next()
	}
}

// RequireAnyRole requires the user to have at least one of the specified roles
func (m *Middleware) RequireAnyRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get(m.config.ContextUserKey)
		if !exists {
			m.handleAuthError(c, types.ErrMissingToken)
			return
		}

		authUser, ok := user.(*types.AuthenticatedUser)
		if !ok {
			m.handleAuthError(c, types.ErrInvalidToken)
			return
		}

		// Check if user has any of the required roles
		hasRole := false
		for _, userRole := range authUser.Roles {
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
			m.handleAuthError(c, types.ErrInsufficientRole)
			return
		}

		c.Next()
	}
}

// RequireTrustLevel requires a minimum trust level
func (m *Middleware) RequireTrustLevel(minTrustLevel int) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get(m.config.ContextUserKey)
		if !exists {
			m.handleAuthError(c, types.ErrMissingToken)
			return
		}

		authUser, ok := user.(*types.AuthenticatedUser)
		if !ok {
			m.handleAuthError(c, types.ErrInvalidToken)
			return
		}

		if authUser.TrustLevel < minTrustLevel {
			m.handleAuthError(c, &types.AuthError{
				Code:    types.ErrCodeInsufficientTrust,
				Message: "insufficient trust level",
				Details: "required: " + strconv.Itoa(minTrustLevel) + ", current: " + strconv.Itoa(authUser.TrustLevel),
			})
			return
		}

		c.Next()
	}
}

// RequireDeviceVerification requires device verification
func (m *Middleware) RequireDeviceVerification() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get(m.config.ContextUserKey)
		if !exists {
			m.handleAuthError(c, types.ErrMissingToken)
			return
		}

		authUser, ok := user.(*types.AuthenticatedUser)
		if !ok {
			m.handleAuthError(c, types.ErrInvalidToken)
			return
		}

		if !authUser.DeviceVerified {
			m.handleAuthError(c, types.ErrDeviceNotVerified)
			return
		}

		c.Next()
	}
}

// RequireTenant ensures multi-tenant context is valid
func (m *Middleware) RequireTenant() gin.HandlerFunc {
	return func(c *gin.Context) {
		// This would be implemented based on the tenant resolver configuration
		// For now, it's a placeholder that sets tenant info in context
		
		// In a real implementation, this would:
		// 1. Extract tenant ID using the configured TenantResolver
		// 2. Validate tenant access for the authenticated user
		// 3. Set tenant context for downstream handlers
		
		c.Set("tenant", "default") // Placeholder
		c.Next()
	}
}

// CORS provides CORS middleware if enabled
func (m *Middleware) CORS() gin.HandlerFunc {
	if !m.config.CorsEnabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range m.config.CorsOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, PATCH")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// GetCurrentUser retrieves the authenticated user from context
func (m *Middleware) GetCurrentUser(c *gin.Context) *types.AuthenticatedUser {
	user, exists := c.Get(m.config.ContextUserKey)
	if !exists {
		return nil
	}

	authUser, ok := user.(*types.AuthenticatedUser)
	if !ok {
		return nil
	}

	return authUser
}

// GetCurrentTenant retrieves the current tenant from context
func (m *Middleware) GetCurrentTenant(c *gin.Context) string {
	tenant, exists := c.Get("tenant")
	if !exists {
		return ""
	}

	tenantStr, ok := tenant.(string)
	if !ok {
		return ""
	}

	return tenantStr
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
func (m *Middleware) extractToken(c *gin.Context) string {
	// Try header first
	authHeader := c.GetHeader(m.config.TokenHeader)
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
	cookie, err := c.Cookie("access_token")
	if err == nil && cookie != "" {
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
func (m *Middleware) handleAuthError(c *gin.Context, err error) {
	// If a custom error handler is configured, use it
	if m.config.ErrorHandler != nil {
		if handledErr := m.config.ErrorHandler(c.Request.Context(), err); handledErr != nil {
			err = handledErr
		}
	}

	// Determine HTTP status code based on error type
	var statusCode int
	var response gin.H

	if authErr, ok := err.(*types.AuthError); ok {
		switch authErr.Code {
		case types.ErrCodeUnauthorized, types.ErrCodeInvalidToken, types.ErrCodeExpiredToken:
			statusCode = http.StatusUnauthorized
		case types.ErrCodeForbidden, types.ErrCodeInsufficientTrust, types.ErrCodeInsufficientRole, types.ErrCodeDeviceNotVerified:
			statusCode = http.StatusForbidden
		case types.ErrCodeConnectionError, types.ErrCodeConfigurationError:
			statusCode = http.StatusInternalServerError
		default:
			statusCode = http.StatusUnauthorized
		}

		response = gin.H{
			"error": gin.H{
				"code":    authErr.Code,
				"message": authErr.Message,
			},
		}

		if authErr.Details != "" {
			response["error"].(gin.H)["details"] = authErr.Details
		}
	} else {
		// Generic error
		statusCode = http.StatusUnauthorized
		response = gin.H{
			"error": gin.H{
				"code":    "AUTHENTICATION_ERROR",
				"message": err.Error(),
			},
		}
	}

	c.AbortWithStatusJSON(statusCode, response)
}

// Extension methods for the main client

// GinMiddleware creates a new Gin middleware instance from the client
func GinMiddleware(client types.KeycloakClient, config ...*types.MiddlewareConfig) *Middleware {
	var cfg *types.MiddlewareConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	return NewMiddleware(client, cfg)
}