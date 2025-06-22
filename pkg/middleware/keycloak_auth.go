// Package middleware provides Gin middleware for Zero Trust authentication with Keycloak
package middleware

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"your-project/pkg/auth"
)

// KeycloakAuthMiddleware provides Zero Trust authentication middleware using Keycloak
type KeycloakAuthMiddleware struct {
	keycloak *auth.KeycloakAuthenticator
	config   *AuthMiddlewareConfig
}

// AuthMiddlewareConfig configures the authentication middleware
type AuthMiddlewareConfig struct {
	SkipPaths       []string      `json:"skipPaths"`       // Paths that don't require authentication
	TokenHeader     string        `json:"tokenHeader"`     // Header name for JWT token (default: Authorization)
	ContextUserKey  string        `json:"contextUserKey"`  // Context key for user info (default: user)
	RequestTimeout  time.Duration `json:"requestTimeout"`  // Timeout for Keycloak requests
	CacheEnabled    bool          `json:"cacheEnabled"`    // Enable token validation caching
	CacheTTL        time.Duration `json:"cacheTTL"`        // Cache TTL for valid tokens
}

// AuthenticatedUser represents an authenticated user in the request context
type AuthenticatedUser struct {
	UserID           string    `json:"userId"`
	Email            string    `json:"email"`
	Username         string    `json:"username"`
	FirstName        string    `json:"firstName"`
	LastName         string    `json:"lastName"`
	Roles            []string  `json:"roles"`
	TrustLevel       int       `json:"trustLevel"`
	DeviceID         string    `json:"deviceId,omitempty"`
	LastVerification string    `json:"lastVerification,omitempty"`
	SessionState     string    `json:"sessionState"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

// NewKeycloakAuthMiddleware creates a new Keycloak authentication middleware
func NewKeycloakAuthMiddleware(keycloak *auth.KeycloakAuthenticator, config *AuthMiddlewareConfig) *KeycloakAuthMiddleware {
	if config == nil {
		config = &AuthMiddlewareConfig{
			TokenHeader:    "Authorization",
			ContextUserKey: "user",
			RequestTimeout: 5 * time.Second,
			CacheEnabled:   true,
			CacheTTL:       5 * time.Minute,
		}
	}

	// Set defaults
	if config.TokenHeader == "" {
		config.TokenHeader = "Authorization"
	}
	if config.ContextUserKey == "" {
		config.ContextUserKey = "user"
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 5 * time.Second
	}

	return &KeycloakAuthMiddleware{
		keycloak: keycloak,
		config:   config,
	}
}

// Authenticate creates a Gin middleware function for JWT authentication
func (m *KeycloakAuthMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if path should be skipped
		if m.shouldSkipPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Extract token from header
		token := m.extractToken(c)
		if token == "" {
			m.respondUnauthorized(c, "Missing or invalid authorization header")
			return
		}

		// Create context with timeout for Keycloak requests
		ctx, cancel := context.WithTimeout(c.Request.Context(), m.config.RequestTimeout)
		defer cancel()

		// Validate token with Keycloak
		claims, err := m.keycloak.ValidateToken(ctx, token)
		if err != nil {
			m.respondUnauthorized(c, "Invalid or expired token")
			return
		}

		// Create authenticated user object
		user := &AuthenticatedUser{
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

		// Store user in context
		c.Set(m.config.ContextUserKey, user)
		c.Set("user_id", user.UserID)
		c.Set("user_email", user.Email)
		c.Set("user_roles", user.Roles)
		c.Set("trust_level", user.TrustLevel)
		c.Set("device_id", user.DeviceID)
		c.Set("session_state", user.SessionState)

		c.Next()
	}
}

// RequireRole creates middleware that requires specific roles
func (m *KeycloakAuthMiddleware) RequireRole(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := m.getUserFromContext(c)
		if user == nil {
			m.respondForbidden(c, "Authentication required")
			return
		}

		// Check if user has any of the required roles
		if !m.hasAnyRole(user.Roles, requiredRoles) {
			m.respondForbidden(c, "Insufficient privileges")
			return
		}

		c.Next()
	}
}

// RequireTrustLevel creates middleware that requires minimum trust level
func (m *KeycloakAuthMiddleware) RequireTrustLevel(minTrustLevel int) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := m.getUserFromContext(c)
		if user == nil {
			m.respondForbidden(c, "Authentication required")
			return
		}

		if user.TrustLevel < minTrustLevel {
			m.respondForbidden(c, map[string]interface{}{
				"error":           "Insufficient trust level",
				"required_level":  minTrustLevel,
				"current_level":   user.TrustLevel,
				"trust_message":   m.getTrustLevelMessage(user.TrustLevel, minTrustLevel),
			})
			return
		}

		c.Next()
	}
}

// RequireDeviceVerification creates middleware that requires verified device
func (m *KeycloakAuthMiddleware) RequireDeviceVerification() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := m.getUserFromContext(c)
		if user == nil {
			m.respondForbidden(c, "Authentication required")
			return
		}

		if user.DeviceID == "" {
			m.respondForbidden(c, "Device verification required")
			return
		}

		// Check if device verification is recent (within last 24 hours)
		if user.LastVerification != "" {
			if lastVerif, err := time.Parse(time.RFC3339, user.LastVerification); err == nil {
				if time.Since(lastVerif) > 24*time.Hour {
					m.respondForbidden(c, "Device re-verification required")
					return
				}
			}
		}

		c.Next()
	}
}

// extractToken extracts JWT token from request header
func (m *KeycloakAuthMiddleware) extractToken(c *gin.Context) string {
	authHeader := c.GetHeader(m.config.TokenHeader)
	if authHeader == "" {
		return ""
	}

	// Handle Bearer token format
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Return raw token if no Bearer prefix
	return authHeader
}

// shouldSkipPath checks if the current path should skip authentication
func (m *KeycloakAuthMiddleware) shouldSkipPath(path string) bool {
	for _, skipPath := range m.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// getUserFromContext retrieves authenticated user from Gin context
func (m *KeycloakAuthMiddleware) getUserFromContext(c *gin.Context) *AuthenticatedUser {
	if user, exists := c.Get(m.config.ContextUserKey); exists {
		if authUser, ok := user.(*AuthenticatedUser); ok {
			return authUser
		}
	}
	return nil
}

// hasAnyRole checks if user has any of the required roles
func (m *KeycloakAuthMiddleware) hasAnyRole(userRoles, requiredRoles []string) bool {
	for _, required := range requiredRoles {
		for _, userRole := range userRoles {
			if userRole == required {
				return true
			}
		}
	}
	return false
}

// getTrustLevelMessage returns a user-friendly message about trust levels
func (m *KeycloakAuthMiddleware) getTrustLevelMessage(current, required int) string {
	switch {
	case required >= 100:
		return "Full trust verification required (hardware attestation, MFA, verified device)"
	case required >= 75:
		return "High trust verification required (MFA and verified device)"
	case required >= 50:
		return "Medium trust verification required (verified device or recent authentication)"
	case required >= 25:
		return "Low trust verification required (basic authentication)"
	default:
		return "No specific trust requirements"
	}
}

// respondUnauthorized sends a 401 Unauthorized response
func (m *KeycloakAuthMiddleware) respondUnauthorized(c *gin.Context, message interface{}) {
	c.Header("WWW-Authenticate", "Bearer")
	c.JSON(http.StatusUnauthorized, gin.H{
		"error":     "Unauthorized",
		"message":   message,
		"timestamp": time.Now().Unix(),
	})
	c.Abort()
}

// respondForbidden sends a 403 Forbidden response
func (m *KeycloakAuthMiddleware) respondForbidden(c *gin.Context, message interface{}) {
	c.JSON(http.StatusForbidden, gin.H{
		"error":     "Forbidden",
		"message":   message,
		"timestamp": time.Now().Unix(),
	})
	c.Abort()
}

// GetCurrentUser is a helper function to get current user from context
func GetCurrentUser(c *gin.Context) *AuthenticatedUser {
	if user, exists := c.Get("user"); exists {
		if authUser, ok := user.(*AuthenticatedUser); ok {
			return authUser
		}
	}
	return nil
}

// GetUserID is a helper function to get current user ID from context
func GetUserID(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	return ""
}

// GetUserTrustLevel is a helper function to get current user trust level from context
func GetUserTrustLevel(c *gin.Context) int {
	if trustLevel, exists := c.Get("trust_level"); exists {
		if level, ok := trustLevel.(int); ok {
			return level
		}
	}
	return 0
}

// HasRole is a helper function to check if current user has a specific role
func HasRole(c *gin.Context, role string) bool {
	if roles, exists := c.Get("user_roles"); exists {
		if userRoles, ok := roles.([]string); ok {
			for _, userRole := range userRoles {
				if userRole == role {
					return true
				}
			}
		}
	}
	return false
}

// IsAdmin is a helper function to check if current user is an admin
func IsAdmin(c *gin.Context) bool {
	return HasRole(c, "admin")
}

// IsManager is a helper function to check if current user is a manager
func IsManager(c *gin.Context) bool {
	return HasRole(c, "manager") || HasRole(c, "admin")
}

// AuthInfo provides authentication information endpoint
func (m *KeycloakAuthMiddleware) AuthInfo() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := m.getUserFromContext(c)
		if user == nil {
			m.respondUnauthorized(c, "Authentication required")
			return
		}

		// Return safe user information (no sensitive data)
		c.JSON(http.StatusOK, gin.H{
			"user_id":     user.UserID,
			"email":       user.Email,
			"username":    user.Username,
			"first_name":  user.FirstName,
			"last_name":   user.LastName,
			"roles":       user.Roles,
			"trust_level": user.TrustLevel,
			"device_id":   user.DeviceID,
			"expires_at":  user.ExpiresAt.Unix(),
			"is_admin":    m.hasAnyRole(user.Roles, []string{"admin"}),
			"is_manager":  m.hasAnyRole(user.Roles, []string{"admin", "manager"}),
		})
	}
}

// TrustLevelInfo provides trust level information and requirements
func (m *KeycloakAuthMiddleware) TrustLevelInfo() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := m.getUserFromContext(c)
		if user == nil {
			m.respondUnauthorized(c, "Authentication required")
			return
		}

		// Get trust level name
		var trustLevelName string
		switch {
		case user.TrustLevel >= 100:
			trustLevelName = "FULL"
		case user.TrustLevel >= 75:
			trustLevelName = "HIGH"
		case user.TrustLevel >= 50:
			trustLevelName = "MEDIUM"
		case user.TrustLevel >= 25:
			trustLevelName = "LOW"
		default:
			trustLevelName = "NONE"
		}

		c.JSON(http.StatusOK, gin.H{
			"trust_level":      user.TrustLevel,
			"trust_level_name": trustLevelName,
			"device_verified":  user.DeviceID != "",
			"last_verification": user.LastVerification,
			"improvements": gin.H{
				"for_medium": "Verify your device or complete recent authentication",
				"for_high":   "Enable MFA and verify your device",
				"for_full":   "Complete hardware attestation, MFA, and device verification",
			},
		})
	}
}