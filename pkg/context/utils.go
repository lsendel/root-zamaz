// Package context provides utilities for extracting data from HTTP context
package context

import (
	"github.com/gofiber/fiber/v2"
	"mvp.local/pkg/auth"
)

// GetUserID extracts user ID from fiber context with fallback to JWT claims
func GetUserID(c *fiber.Ctx) string {
	// Try from locals first (set by auth middleware)
	if userID := c.Locals("user_id"); userID != nil {
		if id, ok := userID.(string); ok && id != "" {
			return id
		}
	}

	// Fallback to JWT claims
	if claims := c.Locals("jwt_claims"); claims != nil {
		if jwtClaims, ok := claims.(*auth.JWTClaims); ok {
			return jwtClaims.UserID
		}
	}

	return ""
}

// GetTenantID extracts tenant ID from context
func GetTenantID(c *fiber.Ctx) string {
	if tenantID := c.Locals("tenant_id"); tenantID != nil {
		if id, ok := tenantID.(string); ok {
			return id
		}
	}
	return ""
}

// GetUserRoles extracts user roles from context
func GetUserRoles(c *fiber.Ctx) []string {
	if roles := c.Locals("roles"); roles != nil {
		if roleSlice, ok := roles.([]string); ok {
			return roleSlice
		}
	}
	return []string{}
}

// GetUserPermissions extracts user permissions from context
func GetUserPermissions(c *fiber.Ctx) []string {
	if permissions := c.Locals("permissions"); permissions != nil {
		if permSlice, ok := permissions.([]string); ok {
			return permSlice
		}
	}
	return []string{}
}

// MustGetUserID gets user ID or panics (for cases where auth is required)
func MustGetUserID(c *fiber.Ctx) string {
	userID := GetUserID(c)
	if userID == "" {
		panic("user ID not found in context")
	}
	return userID
}

// GetRequestID extracts request ID from context
func GetRequestID(c *fiber.Ctx) string {
	if id := c.Get("X-Request-ID"); id != "" {
		return id
	}
	if id := c.Get("X-Correlation-ID"); id != "" {
		return id
	}
	if id := c.Locals("request_id"); id != nil {
		if idStr, ok := id.(string); ok {
			return idStr
		}
	}
	return ""
}

// GetClientIP extracts client IP from context
func GetClientIP(c *fiber.Ctx) string {
	return c.IP()
}

// GetUserAgent extracts user agent from context
func GetUserAgent(c *fiber.Ctx) string {
	return c.Get("User-Agent")
}

// GetJWTClaims extracts JWT claims from context
func GetJWTClaims(c *fiber.Ctx) *auth.JWTClaims {
	if claims := c.Locals("jwt_claims"); claims != nil {
		if jwtClaims, ok := claims.(*auth.JWTClaims); ok {
			return jwtClaims
		}
	}
	return nil
}

// IsAuthenticated checks if the user is authenticated
func IsAuthenticated(c *fiber.Ctx) bool {
	return GetUserID(c) != ""
}

// HasRole checks if the user has a specific role
func HasRole(c *fiber.Ctx, role string) bool {
	roles := GetUserRoles(c)
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasPermission checks if the user has a specific permission
func HasPermission(c *fiber.Ctx, permission string) bool {
	permissions := GetUserPermissions(c)
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}
