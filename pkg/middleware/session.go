// Package middleware provides session management middleware for Fiber applications.
package middleware

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"mvp.local/pkg/errors"
	"mvp.local/pkg/session"
)

// SessionMiddlewareConfig holds configuration for session middleware
type SessionMiddlewareConfig struct {
	SessionManager   *session.SessionManager
	CookieName       string        `default:"session_id"`
	CookiePath       string        `default:"/"`
	CookieDomain     string        `default:""`
	CookieSecure     bool          `default:"true"`
	CookieHTTPOnly   bool          `default:"true"`
	CookieSameSite   string        `default:"Strict"`
	CookieExpiration time.Duration `default:"24h"`

	// Behavior
	RequireSession bool `default:"false"` // Whether to require a valid session
	AutoRefresh    bool `default:"true"`  // Automatically refresh sessions near expiration

	// Error handling
	RedirectOnError string // URL to redirect to on session errors
	ErrorResponse   func(c *fiber.Ctx, err error) error
}

// DefaultSessionMiddlewareConfig returns default session middleware configuration
func DefaultSessionMiddlewareConfig() SessionMiddlewareConfig {
	return SessionMiddlewareConfig{
		CookieName:       "session_id",
		CookiePath:       "/",
		CookieDomain:     "",
		CookieSecure:     true,
		CookieHTTPOnly:   true,
		CookieSameSite:   "Strict",
		CookieExpiration: 24 * time.Hour,
		RequireSession:   false,
		AutoRefresh:      true,
	}
}

// SessionMiddleware creates session management middleware
func SessionMiddleware(sessionManager *session.SessionManager, config ...SessionMiddlewareConfig) fiber.Handler {
	cfg := DefaultSessionMiddlewareConfig()
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg.SessionManager = sessionManager

	return func(c *fiber.Ctx) error {
		// Get session ID from cookie
		sessionID := c.Cookies(cfg.CookieName)

		if sessionID == "" {
			// No session cookie
			if cfg.RequireSession {
				return handleSessionError(c, cfg, errors.Unauthorized("Session required"))
			}
			return c.Next()
		}

		// Get session data
		sessionData, err := cfg.SessionManager.GetSession(c.Context(), sessionID)
		if err != nil {
			// Clear invalid session cookie
			clearSessionCookie(c, cfg)

			if cfg.RequireSession {
				return handleSessionError(c, cfg, err)
			}
			return c.Next()
		}

		// Auto-refresh session if configured and needed
		if cfg.AutoRefresh {
			refreshedSession, err := cfg.SessionManager.RefreshSession(c.Context(), sessionID)
			if err != nil {
				// Log refresh error but don't fail the request
				// In production, you might want to log this
			} else if refreshedSession != nil {
				sessionData = refreshedSession
			}
		}

		// Update last activity and IP if changed
		currentIP := c.IP()
		if sessionData.IPAddress != currentIP {
			sessionData.IPAddress = currentIP
			sessionData.LastActivity = time.Now()

			// Update session in Redis
			if err := cfg.SessionManager.UpdateSession(c.Context(), sessionID, *sessionData); err != nil {
				// Log error but don't fail the request
			}
		}

		// Store session data in context
		c.Locals("session", sessionData)
		c.Locals("session_id", sessionID)
		c.Locals("user_id", sessionData.UserID)

		if sessionData.TenantID != "" {
			c.Locals("tenant_id", sessionData.TenantID)
		}

		return c.Next()
	}
}

// RequireSessionMiddleware creates middleware that requires a valid session
func RequireSessionMiddleware(sessionManager *session.SessionManager, config ...SessionMiddlewareConfig) fiber.Handler {
	cfg := DefaultSessionMiddlewareConfig()
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg.RequireSession = true
	cfg.SessionManager = sessionManager

	return SessionMiddleware(sessionManager, cfg)
}

// CreateSessionHandler creates a new session for a user
func CreateSessionHandler(sessionManager *session.SessionManager, config ...SessionMiddlewareConfig) func(c *fiber.Ctx, userID string, sessionData session.SessionData) error {
	cfg := DefaultSessionMiddlewareConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	return func(c *fiber.Ctx, userID string, sessionData session.SessionData) error {
		// Add request context to session data
		sessionData.IPAddress = c.IP()
		sessionData.UserAgent = c.Get("User-Agent")

		// Create session
		createdSession, err := sessionManager.CreateSession(c.Context(), userID, sessionData)
		if err != nil {
			return err
		}

		// Set session cookie
		setSessionCookie(c, cfg, createdSession.SessionID)

		// Store session data in context for this request
		c.Locals("session", createdSession)
		c.Locals("session_id", createdSession.SessionID)
		c.Locals("user_id", userID)

		if createdSession.TenantID != "" {
			c.Locals("tenant_id", createdSession.TenantID)
		}

		return nil
	}
}

// DestroySessionHandler destroys the current session
func DestroySessionHandler(sessionManager *session.SessionManager, config ...SessionMiddlewareConfig) func(c *fiber.Ctx) error {
	cfg := DefaultSessionMiddlewareConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	return func(c *fiber.Ctx) error {
		// Get session ID from cookie
		sessionID := c.Cookies(cfg.CookieName)
		if sessionID == "" {
			// No session to destroy
			return nil
		}

		// Delete session from Redis
		if err := sessionManager.DeleteSession(c.Context(), sessionID); err != nil {
			// Log error but still clear cookie
		}

		// Clear session cookie
		clearSessionCookie(c, cfg)

		// Clear context
		c.Locals("session", nil)
		c.Locals("session_id", nil)
		c.Locals("user_id", nil)
		c.Locals("tenant_id", nil)

		return nil
	}
}

// GetSessionFromContext retrieves session data from Fiber context
func GetSessionFromContext(c *fiber.Ctx) (*session.SessionData, bool) {
	if sessionData := c.Locals("session"); sessionData != nil {
		if session, ok := sessionData.(*session.SessionData); ok {
			return session, true
		}
	}
	return nil, false
}

// GetUserIDFromContext retrieves user ID from Fiber context
func GetUserIDFromContext(c *fiber.Ctx) string {
	if userID := c.Locals("user_id"); userID != nil {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	return ""
}

// GetTenantIDFromContext retrieves tenant ID from Fiber context
func GetTenantIDFromContext(c *fiber.Ctx) string {
	if tenantID := c.Locals("tenant_id"); tenantID != nil {
		if id, ok := tenantID.(string); ok {
			return id
		}
	}
	return ""
}

// Helper functions

func setSessionCookie(c *fiber.Ctx, cfg SessionMiddlewareConfig, sessionID string) {
	cookie := &fiber.Cookie{
		Name:     cfg.CookieName,
		Value:    sessionID,
		Path:     cfg.CookiePath,
		Domain:   cfg.CookieDomain,
		Expires:  time.Now().Add(cfg.CookieExpiration),
		Secure:   cfg.CookieSecure,
		HTTPOnly: cfg.CookieHTTPOnly,
		SameSite: cfg.CookieSameSite,
	}
	c.Cookie(cookie)
}

func clearSessionCookie(c *fiber.Ctx, cfg SessionMiddlewareConfig) {
	cookie := &fiber.Cookie{
		Name:     cfg.CookieName,
		Value:    "",
		Path:     cfg.CookiePath,
		Domain:   cfg.CookieDomain,
		Expires:  time.Now().Add(-24 * time.Hour), // Expire in the past
		Secure:   cfg.CookieSecure,
		HTTPOnly: cfg.CookieHTTPOnly,
		SameSite: cfg.CookieSameSite,
	}
	c.Cookie(cookie)
}

func handleSessionError(c *fiber.Ctx, cfg SessionMiddlewareConfig, err error) error {
	if cfg.ErrorResponse != nil {
		return cfg.ErrorResponse(c, err)
	}

	if cfg.RedirectOnError != "" {
		return c.Redirect(cfg.RedirectOnError)
	}

	// Default error handling - check if it's an AppError and return appropriate status
	if appErr, ok := err.(*errors.AppError); ok {
		switch appErr.Code {
		case errors.CodeUnauthorized, errors.CodeAuthentication:
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "Unauthorized",
				"message": appErr.Message,
			})
		case errors.CodeForbidden, errors.CodeAuthorization:
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   "Forbidden",
				"message": appErr.Message,
			})
		default:
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   "Internal Server Error",
				"message": "An error occurred",
			})
		}
	}

	// For non-AppError, return unauthorized by default for session errors
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"error":   "Unauthorized",
		"message": "Session required",
	})
}
