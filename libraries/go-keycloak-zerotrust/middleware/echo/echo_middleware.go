// Package echo provides Echo framework middleware for Keycloak Zero Trust authentication
package echo

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// Middleware provides Echo-specific middleware functions
type Middleware struct {
	client types.KeycloakClient
	config *types.MiddlewareConfig
}

// NewMiddleware creates a new Echo middleware instance
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
func (m *Middleware) Authenticate() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Skip authentication for configured paths
			if m.shouldSkipPath(c.Request().URL.Path) {
				return next(c)
			}

			// Create context with timeout
			ctx, cancel := context.WithTimeout(c.Request().Context(), m.config.RequestTimeout)
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
			c.Set(m.config.ContextUserKey, user)

			return next(c)
		}
	}
}

// RequireAuth ensures the request is authenticated (alias for Authenticate for clarity)
func (m *Middleware) RequireAuth() echo.MiddlewareFunc {
	return m.Authenticate()
}

// RequireRole requires the user to have a specific role
func (m *Middleware) RequireRole(requiredRole string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
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

			return next(c)
		}
	}
}

// RequireAnyRole requires the user to have at least one of the specified roles
func (m *Middleware) RequireAnyRole(roles ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
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

			return next(c)
		}
	}
}

// RequireTrustLevel requires a minimum trust level
func (m *Middleware) RequireTrustLevel(minTrustLevel int) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
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

			return next(c)
		}
	}
}

// RequireDeviceVerification requires device verification
func (m *Middleware) RequireDeviceVerification() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user := m.GetCurrentUser(c)
			if user == nil {
				return m.handleAuthError(c, types.ErrMissingToken)
			}

			if !user.DeviceVerified {
				return m.handleAuthError(c, types.ErrDeviceNotVerified)
			}

			return next(c)
		}
	}
}

// RequireTenant ensures multi-tenant context is valid
func (m *Middleware) RequireTenant() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// This would be implemented based on the tenant resolver configuration
			// For now, it's a placeholder that sets tenant info in context
			
			// In a real implementation, this would:
			// 1. Extract tenant ID using the configured TenantResolver
			// 2. Validate tenant access for the authenticated user
			// 3. Set tenant context for downstream handlers
			
			c.Set("tenant", "default") // Placeholder
			return next(c)
		}
	}
}

// CORS provides CORS middleware if enabled
func (m *Middleware) CORS() echo.MiddlewareFunc {
	if !m.config.CorsEnabled {
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return next
		}
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			res := c.Response()
			origin := req.Header.Get("Origin")
			
			// Check if origin is allowed
			allowed := false
			for _, allowedOrigin := range m.config.CorsOrigins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}

			if allowed {
				res.Header().Set("Access-Control-Allow-Origin", origin)
				res.Header().Set("Access-Control-Allow-Credentials", "true")
				res.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
				res.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, PATCH")
			}

			if req.Method == "OPTIONS" {
				return c.NoContent(http.StatusNoContent)
			}

			return next(c)
		}
	}
}

// GetCurrentUser retrieves the authenticated user from context
func (m *Middleware) GetCurrentUser(c echo.Context) *types.AuthenticatedUser {
	user := c.Get(m.config.ContextUserKey)
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
func (m *Middleware) GetCurrentTenant(c echo.Context) string {
	tenant := c.Get("tenant")
	if tenant == nil {
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
func (m *Middleware) extractToken(c echo.Context) string {
	req := c.Request()
	
	// Try header first
	authHeader := req.Header.Get(m.config.TokenHeader)
	if authHeader != "" {
		// Remove "Bearer " prefix if present
		if strings.HasPrefix(authHeader, "Bearer ") {
			return strings.TrimPrefix(authHeader, "Bearer ")
		}
		return authHeader
	}

	// Try query parameter as fallback
	token := c.QueryParam("token")
	if token != "" {
		return token
	}

	// Try cookie as last resort
	cookie, err := c.Cookie("access_token")
	if err == nil && cookie.Value != "" {
		return cookie.Value
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
func (m *Middleware) handleAuthError(c echo.Context, err error) error {
	// If a custom error handler is configured, use it
	if m.config.ErrorHandler != nil {
		if handledErr := m.config.ErrorHandler(c.Request().Context(), err); handledErr != nil {
			err = handledErr
		}
	}

	// Determine HTTP status code based on error type
	var statusCode int
	var response map[string]interface{}

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

		response = map[string]interface{}{
			"error": map[string]interface{}{
				"code":    authErr.Code,
				"message": authErr.Message,
			},
		}

		if authErr.Details != "" {
			response["error"].(map[string]interface{})["details"] = authErr.Details
		}
	} else {
		// Generic error
		statusCode = http.StatusUnauthorized
		response = map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "AUTHENTICATION_ERROR",
				"message": err.Error(),
			},
		}
	}

	return c.JSON(statusCode, response)
}

// EchoMiddleware creates a new Echo middleware instance from the client
func EchoMiddleware(client types.KeycloakClient, config ...*types.MiddlewareConfig) *Middleware {
	var cfg *types.MiddlewareConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	return NewMiddleware(client, cfg)
}