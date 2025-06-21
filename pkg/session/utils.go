// Package session provides session management utilities
package session

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"mvp.local/pkg/config"
	"mvp.local/pkg/observability"
)

// SessionCreator provides utilities for creating user sessions
type SessionCreator struct {
	sessionManager *SessionManager
	config         *config.Config
	obs            *observability.Observability
}

// SessionParams represents parameters for creating a session
type SessionParams struct {
	UserID      string
	Email       string
	Username    string
	Roles       []string
	Permissions []string
	IPAddress   string
	UserAgent   string
	DeviceID    string
	TenantID    string
	Metadata    map[string]interface{}
}

// NewSessionCreator creates a new session creator
func NewSessionCreator(sm *SessionManager, cfg *config.Config, obs *observability.Observability) *SessionCreator {
	return &SessionCreator{
		sessionManager: sm,
		config:         cfg,
		obs:            obs,
	}
}

// CreateUserSession creates a new user session with standardized data
func (sc *SessionCreator) CreateUserSession(c *fiber.Ctx, params SessionParams) (*SessionData, error) {
	if sc.sessionManager == nil {
		return nil, nil // No error if session manager not available
	}

	sessionData := SessionData{
		UserID:      params.UserID,
		Email:       params.Email,
		Username:    params.Username,
		Roles:       params.Roles,
		Permissions: params.Permissions,
		TenantID:    params.TenantID,
		IPAddress:   params.IPAddress,
		UserAgent:   params.UserAgent,
		DeviceID:    params.DeviceID,
		IsActive:    true,
		Metadata:    params.Metadata,
	}

	createdSession, err := sc.sessionManager.CreateSession(c.Context(), params.UserID, sessionData)
	if err != nil {
		sc.obs.Logger.Error().Err(err).Str("user_id", params.UserID).Msg("Failed to create session")
		return nil, err
	}

	// Set secure session cookie
	sc.setSessionCookie(c, createdSession.SessionID, createdSession.ExpiresAt)

	sc.obs.Logger.Info().
		Str("user_id", params.UserID).
		Str("session_id", createdSession.SessionID).
		Msg("Session created successfully")

	return createdSession, nil
}

// RefreshUserSession refreshes an existing session
func (sc *SessionCreator) RefreshUserSession(c *fiber.Ctx, sessionID string) (*SessionData, error) {
	if sc.sessionManager == nil {
		return nil, nil
	}

	refreshedSession, err := sc.sessionManager.RefreshSession(c.Context(), sessionID)
	if err != nil {
		sc.obs.Logger.Error().Err(err).Str("session_id", sessionID).Msg("Failed to refresh session")
		return nil, err
	}

	// Update session cookie with new expiration
	sc.setSessionCookie(c, refreshedSession.SessionID, refreshedSession.ExpiresAt)

	sc.obs.Logger.Info().
		Str("session_id", sessionID).
		Str("user_id", refreshedSession.UserID).
		Msg("Session refreshed successfully")

	return refreshedSession, nil
}

// DestroyUserSession destroys a user session
func (sc *SessionCreator) DestroyUserSession(c *fiber.Ctx, sessionID string) error {
	if sc.sessionManager == nil {
		return nil
	}

	err := sc.sessionManager.DeleteSession(c.Context(), sessionID)
	if err != nil {
		sc.obs.Logger.Error().Err(err).Str("session_id", sessionID).Msg("Failed to destroy session")
		return err
	}

	// Clear session cookie
	sc.clearSessionCookie(c)

	sc.obs.Logger.Info().
		Str("session_id", sessionID).
		Msg("Session destroyed successfully")

	return nil
}

// setSessionCookie sets a secure session cookie
func (sc *SessionCreator) setSessionCookie(c *fiber.Ctx, sessionID string, expiresAt time.Time) {
	c.Cookie(&fiber.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Expires:  expiresAt,
		HTTPOnly: true,
		Secure:   sc.isSecure(),
		SameSite: sc.getSameSite(),
		Path:     "/",
	})
}

// clearSessionCookie clears the session cookie
func (sc *SessionCreator) clearSessionCookie(c *fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     "session_id",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		Secure:   sc.isSecure(),
		SameSite: sc.getSameSite(),
		Path:     "/",
	})
}

// isSecure determines if cookies should be secure based on TLS configuration
func (sc *SessionCreator) isSecure() bool {
	if sc.config != nil && sc.config.HTTP.TLS.Enabled {
		return true
	}
	return false
}

// getSameSite returns the SameSite cookie attribute
func (sc *SessionCreator) getSameSite() string {
	return "Strict"
}

// GetSessionFromCookie extracts session data from request cookie
func (sc *SessionCreator) GetSessionFromCookie(c *fiber.Ctx) (*SessionData, error) {
	if sc.sessionManager == nil {
		return nil, nil
	}

	sessionID := c.Cookies("session_id")
	if sessionID == "" {
		return nil, nil
	}

	return sc.sessionManager.GetSession(c.Context(), sessionID)
}
