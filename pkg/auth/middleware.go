// Package auth provides authentication and authorization middleware for the MVP Zero Trust Auth system.
// It includes JWT validation, role-based access control, and audit logging.
package auth

import (
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"mvp.local/pkg/config"
	"mvp.local/pkg/errors"
	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
)

// AuthMiddleware provides JWT authentication middleware
type AuthMiddleware struct {
	jwtService   JWTServiceInterface
	authzService AuthorizationInterface
	db           *gorm.DB
	obs          *observability.Observability
	config       *config.Config
}

// AuthMiddlewareInterface defines the contract for authentication middleware
type AuthMiddlewareInterface interface {
	RequireAuth() fiber.Handler
	RequirePermission(resource, action string) fiber.Handler
	RequireRole(role string) fiber.Handler
	RequireAdminRole() fiber.Handler
	OptionalAuth() fiber.Handler
	AuditMiddleware() fiber.Handler
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(
	jwtService JWTServiceInterface,
	authzService AuthorizationInterface,
	db *gorm.DB,
	obs *observability.Observability,
	config *config.Config,
) *AuthMiddleware {
	return &AuthMiddleware{
		jwtService:   jwtService,
		authzService: authzService,
		db:           db,
		obs:          obs,
		config:       config,
	}
}

// RequireAuth middleware that requires valid JWT authentication
func (a *AuthMiddleware) RequireAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {

		// Extract token from header
		authHeader := c.Get("Authorization")
		tokenString, err := ExtractTokenFromHeader(authHeader)
		if err != nil {
			return a.sendUnauthorized(c, err.Error())
		}

		// Validate token
		claims, err := a.jwtService.ValidateToken(tokenString)
		if err != nil {
			return a.sendUnauthorized(c, "Invalid token")
		}

		// Check if user still exists and is active
		var user models.User
		if err := a.db.First(&user, claims.UserID).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return a.sendUnauthorized(c, "User not found")
			}
			return a.sendInternalError(c, "Database error")
		}

		if !user.IsActive {
			return a.sendUnauthorized(c, "User account is disabled")
		}

		// Store user information in context
		c.Locals("user_id", claims.UserID)
		c.Locals("user", &user)
		c.Locals("username", claims.Username)
		c.Locals("email", claims.Email)
		c.Locals("roles", claims.Roles)
		c.Locals("permissions", claims.Permissions)
		c.Locals("device_id", claims.DeviceID)
		c.Locals("trust_level", claims.TrustLevel)
		c.Locals("jwt_claims", claims)

		return c.Next()
	}
}

// RequirePermission middleware that requires specific permission
func (a *AuthMiddleware) RequirePermission(resource, action string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// First check authentication
		if err := a.RequireAuth()(c); err != nil {
			return err
		}

		userID := c.Locals("user_id").(string)

		// Check permission
		allowed, err := a.authzService.Enforce(userID, resource, action)
		if err != nil {
			a.logAuthEvent(c, userID, "permission_check_error", false, err.Error())
			return a.sendInternalError(c, "Authorization check failed")
		}

		if !allowed {
			a.logAuthEvent(c, userID, "permission_denied", false, "Insufficient permissions")
			return a.sendForbidden(c, "Insufficient permissions")
		}

		a.logAuthEvent(c, userID, "permission_granted", true, "")
		return c.Next()
	}
}

// RequireRole middleware that requires specific role
func (a *AuthMiddleware) RequireRole(role string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// First check authentication
		if err := a.RequireAuth()(c); err != nil {
			return err
		}

		userID := c.Locals("user_id").(string)
		roles := c.Locals("roles").([]string)

		// Check if user has the required role
		hasRole := false
		for _, userRole := range roles {
			if userRole == role {
				hasRole = true
				break
			}
		}

		if !hasRole {
			a.logAuthEvent(c, userID, "role_denied", false, "Required role: "+role)
			return a.sendForbidden(c, "Required role not found")
		}

		a.logAuthEvent(c, userID, "role_granted", true, "Role: "+role)
		return c.Next()
	}
}

// RequireAdminRole middleware that requires admin role
func (a *AuthMiddleware) RequireAdminRole() fiber.Handler {
	return a.RequireRole("admin")
}

// OptionalAuth middleware that optionally authenticates if token is present
func (a *AuthMiddleware) OptionalAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Next()
		}

		tokenString, err := ExtractTokenFromHeader(authHeader)
		if err != nil {
			return c.Next()
		}

		claims, err := a.jwtService.ValidateToken(tokenString)
		if err != nil {
			return c.Next()
		}

		// Check if user exists and is active
		var user models.User
		if err := a.db.First(&user, claims.UserID).Error; err != nil {
			return c.Next()
		}

		if !user.IsActive {
			return c.Next()
		}

		// Store user information in context
		c.Locals("user_id", claims.UserID)
		c.Locals("user", &user)
		c.Locals("username", claims.Username)
		c.Locals("email", claims.Email)
		c.Locals("roles", claims.Roles)
		c.Locals("permissions", claims.Permissions)
		c.Locals("device_id", claims.DeviceID)
		c.Locals("trust_level", claims.TrustLevel)
		c.Locals("jwt_claims", claims)

		return c.Next()
	}
}

// AuditMiddleware logs authentication and authorization events
func (a *AuthMiddleware) AuditMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		// Execute the request
		err := c.Next()

		// Log the request
		userID := ""
		if uid := c.Locals("user_id"); uid != nil {
			userID = uid.(string)
		}

		action := c.Method() + " " + c.Path()
		success := err == nil && c.Response().StatusCode() < 400

		details := map[string]interface{}{
			"method":      c.Method(),
			"path":        c.Path(),
			"status_code": c.Response().StatusCode(),
			"duration_ms": time.Since(start).Milliseconds(),
		}

		detailsJSON, _ := json.Marshal(details)

		var userIDPtr *uuid.UUID
		if userID != "" {
			if parsed, err := uuid.Parse(userID); err == nil {
				userIDPtr = &parsed
			}
		}

		auditLog := models.AuditLog{
			UserID:    userIDPtr,
			Action:    action,
			Resource:  "api",
			Details:   string(detailsJSON),
			IPAddress: c.IP(),
			UserAgent: c.Get("User-Agent"),
			RequestID: c.Get("X-Correlation-ID"),
			Success:   success,
		}

		if err != nil {
			auditLog.ErrorMsg = err.Error()
		}

		// Save audit log (non-blocking)
		go func() {
			if err := a.db.Create(&auditLog).Error; err != nil {
				if a.obs != nil {
					a.obs.Logger.Error().Err(err).Msg("Failed to save audit log")
				}
			}
		}()

		return err
	}
}

// Helper methods

func (a *AuthMiddleware) sendUnauthorized(c *fiber.Ctx, message string) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"error":   "Unauthorized",
		"message": message,
	})
}

func (a *AuthMiddleware) sendForbidden(c *fiber.Ctx, message string) error {
	return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
		"error":   "Forbidden",
		"message": message,
	})
}

func (a *AuthMiddleware) sendInternalError(c *fiber.Ctx, message string) error {
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"error":   "Internal Server Error",
		"message": message,
	})
}

func (a *AuthMiddleware) logAuthEvent(c *fiber.Ctx, userID string, event string, success bool, details string) {
	var userIDPtr *uuid.UUID
	if userID != "" {
		if parsed, err := uuid.Parse(userID); err == nil {
			userIDPtr = &parsed
		}
	}

	auditLog := models.AuditLog{
		UserID:    userIDPtr,
		Action:    event,
		Resource:  "auth",
		Details:   details,
		IPAddress: c.IP(),
		UserAgent: c.Get("User-Agent"),
		RequestID: c.Get("X-Correlation-ID"),
		Success:   success,
	}

	// Save audit log (non-blocking)
	go func() {
		if err := a.db.Create(&auditLog).Error; err != nil {
			if a.obs != nil {
				a.obs.Logger.Error().Err(err).Msg("Failed to save auth audit log")
			}
		}
	}()
}

// GetCurrentUser is a helper function to get the current authenticated user
func GetCurrentUser(c *fiber.Ctx) (*models.User, error) {
	user := c.Locals("user")
	if user == nil {
		return nil, errors.Unauthorized("No authenticated user")
	}

	u, ok := user.(*models.User)
	if !ok {
		return nil, errors.Internal("Invalid user data in context")
	}

	return u, nil
}

// GetCurrentUserID is a helper function to get the current authenticated user ID
func GetCurrentUserID(c *fiber.Ctx) (string, error) {
	userID := c.Locals("user_id")
	if userID == nil {
		return "", errors.Unauthorized("No authenticated user")
	}

	uid, ok := userID.(string)
	if !ok {
		return "", errors.Internal("Invalid user ID in context")
	}

	return uid, nil
}

// GetCurrentUserRoles is a helper function to get the current user's roles
func GetCurrentUserRoles(c *fiber.Ctx) ([]string, error) {
	roles := c.Locals("roles")
	if roles == nil {
		return nil, errors.Unauthorized("No authenticated user")
	}

	r, ok := roles.([]string)
	if !ok {
		return nil, errors.Internal("Invalid roles data in context")
	}

	return r, nil
}

// GetCurrentUserPermissions is a helper function to get the current user's permissions
func GetCurrentUserPermissions(c *fiber.Ctx) ([]string, error) {
	permissions := c.Locals("permissions")
	if permissions == nil {
		return nil, errors.Unauthorized("No authenticated user")
	}

	p, ok := permissions.([]string)
	if !ok {
		return nil, errors.Internal("Invalid permissions data in context")
	}

	return p, nil
}

// GetJWTClaims is a helper function to get the JWT claims
func GetJWTClaims(c *fiber.Ctx) (*JWTClaims, error) {
	claims := c.Locals("jwt_claims")
	if claims == nil {
		return nil, errors.Unauthorized("No JWT claims")
	}

	jwtClaims, ok := claims.(*JWTClaims)
	if !ok {
		return nil, errors.Internal("Invalid JWT claims in context")
	}

	return jwtClaims, nil
}
