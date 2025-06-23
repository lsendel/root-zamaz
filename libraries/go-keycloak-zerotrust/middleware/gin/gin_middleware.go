// Package gin provides Gin framework middleware for Keycloak Zero Trust authentication
package gin

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/middleware/common"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// Middleware provides Gin-specific middleware functions
type Middleware struct {
	client types.KeycloakClient
	config *types.MiddlewareConfig
	
	// Shared utilities for common functionality
	tokenExtractor     *common.TokenExtractor
	userFactory        *common.UserFactory
	pathMatcher        *common.PathMatcher
	roleValidator      *common.RoleValidator
	trustValidator     *common.TrustLevelValidator
	errorHandler       common.FrameworkErrorHandler
	auditLogger        *common.SecurityAuditLogger
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
	
	// Initialize shared utilities
	return &Middleware{
		client:         client,
		config:         config,
		tokenExtractor: common.NewTokenExtractor(config.TokenHeader),
		userFactory:    common.NewUserFactory(),
		pathMatcher:    common.NewPathMatcher(config.SkipPaths),
		roleValidator:  common.NewRoleValidator(),
		trustValidator: common.NewTrustLevelValidator(),
		errorHandler:   common.NewFrameworkErrorHandler(config.ErrorHandler),
		auditLogger:    common.NewSecurityAuditLogger(true), // Enable audit logging
	}
}

// Authenticate provides basic authentication middleware
func (m *Middleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip authentication for configured paths using shared path matcher
		if m.pathMatcher.ShouldSkip(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Create context with timeout
		ctx, cancel := context.WithTimeout(c.Request.Context(), m.config.RequestTimeout)
		defer cancel()

		// Extract token using shared extractor
		token := m.tokenExtractor.ExtractFromGinContext(c)
		if token == "" {
			m.handleAuthError(c, types.ErrMissingToken)
			return
		}

		// Validate token
		claims, err := m.client.ValidateToken(ctx, token)
		if err != nil {
			m.auditLogger.LogAuthenticationFailure(ctx, "token_validation_failed", map[string]interface{}{
				"error": err.Error(),
				"path":  c.Request.URL.Path,
			})
			m.handleAuthError(c, err)
			return
		}

		// Validate claims and create authenticated user using shared factory
		if err := m.userFactory.ValidateUserClaims(claims); err != nil {
			m.auditLogger.LogAuthenticationFailure(ctx, "invalid_claims", map[string]interface{}{
				"error": err.Error(),
				"user_id": claims.UserID,
			})
			m.handleAuthError(c, err)
			return
		}

		user := m.userFactory.CreateAuthenticatedUser(claims)
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
		user := m.GetCurrentUser(c)
		if user == nil {
			m.handleAuthError(c, types.ErrMissingToken)
			return
		}

		// Use shared role validator for optimized O(1) lookup
		if !m.roleValidator.HasRole(user, requiredRole) {
			m.auditLogger.LogAuthorizationFailure(c.Request.Context(), user.UserID, "role", requiredRole, map[string]interface{}{
				"required_role": requiredRole,
				"user_roles":    user.Roles,
				"path":          c.Request.URL.Path,
			})
			m.handleAuthError(c, types.ErrInsufficientRole)
			return
		}

		c.Next()
	}
}

// RequireAnyRole requires the user to have at least one of the specified roles
func (m *Middleware) RequireAnyRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := m.GetCurrentUser(c)
		if user == nil {
			m.handleAuthError(c, types.ErrMissingToken)
			return
		}

		// Use shared role validator for optimized lookup
		if !m.roleValidator.HasAnyRole(user, roles) {
			m.auditLogger.LogAuthorizationFailure(c.Request.Context(), user.UserID, "roles", strings.Join(roles, ","), map[string]interface{}{
				"required_roles": roles,
				"user_roles":     user.Roles,
				"path":           c.Request.URL.Path,
			})
			m.handleAuthError(c, types.ErrInsufficientRole)
			return
		}

		c.Next()
	}
}

// RequireTrustLevel requires a minimum trust level
func (m *Middleware) RequireTrustLevel(minTrustLevel int) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := m.GetCurrentUser(c)
		if user == nil {
			m.handleAuthError(c, types.ErrMissingToken)
			return
		}

		// Use shared trust level validator
		if !m.trustValidator.ValidateTrustLevel(user, minTrustLevel) {
			m.auditLogger.LogAuthorizationFailure(c.Request.Context(), user.UserID, "trust_level", strconv.Itoa(minTrustLevel), map[string]interface{}{
				"required_trust_level": minTrustLevel,
				"current_trust_level":  user.TrustLevel,
				"trust_category":       m.trustValidator.GetTrustLevelCategory(user.TrustLevel),
				"path":                 c.Request.URL.Path,
			})
			m.handleAuthError(c, &types.AuthError{
				Code:    types.ErrCodeInsufficientTrust,
				Message: "insufficient trust level",
				Details: "required: " + strconv.Itoa(minTrustLevel) + ", current: " + strconv.Itoa(user.TrustLevel),
			})
			return
		}

		c.Next()
	}
}

// RequireDeviceVerification requires device verification
func (m *Middleware) RequireDeviceVerification() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := m.GetCurrentUser(c)
		if user == nil {
			m.handleAuthError(c, types.ErrMissingToken)
			return
		}

		// Use shared trust level validator for device verification
		if !m.trustValidator.ValidateDeviceVerification(user, true) {
			m.auditLogger.LogAuthorizationFailure(c.Request.Context(), user.UserID, "device_verification", "required", map[string]interface{}{
				"device_id":       user.DeviceID,
				"device_verified": user.DeviceVerified,
				"path":            c.Request.URL.Path,
			})
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

// Note: shouldSkipPath, extractToken, and createAuthenticatedUser methods
// have been replaced with shared utilities in pkg/middleware/common/

// handleAuthError handles authentication errors consistently using shared error handler
func (m *Middleware) handleAuthError(c *gin.Context, err error) {
	// Use shared error handler to create standardized error response
	errorResp := m.errorHandler.HandleAuthError(c.Request.Context(), err)
	
	// Add request ID if available
	if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
		errorResp.WithRequestID(requestID)
	}
	
	// Use framework-specific error handler
	m.errorHandler.HandleGinError(c, errorResp)
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