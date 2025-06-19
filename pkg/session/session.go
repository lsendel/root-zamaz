// Package session provides Redis-based session management for the MVP Zero Trust Auth system.
package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"mvp.local/pkg/errors"
)

// SessionConfig holds configuration for session management
type SessionConfig struct {
	KeyPrefix         string        `default:"session"`
	DefaultExpiration time.Duration `default:"24h"`
	MaxSessions       int           `default:"5"`     // Max concurrent sessions per user
	RefreshThreshold  time.Duration `default:"6h"`   // Refresh session if less than this time remaining
	SecureCookies     bool          `default:"true"`
	SameSite          string        `default:"Strict"`
	HttpOnly          bool          `default:"true"`
}

// DefaultSessionConfig returns default session configuration
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		KeyPrefix:         "session",
		DefaultExpiration: 24 * time.Hour,
		MaxSessions:       5,
		RefreshThreshold:  6 * time.Hour,
		SecureCookies:     true,
		SameSite:          "Strict",
		HttpOnly:          true,
	}
}

// SessionData represents session information stored in Redis
type SessionData struct {
	SessionID    string                 `json:"session_id"`
	UserID       string                 `json:"user_id"`
	Email        string                 `json:"email,omitempty"`
	Username     string                 `json:"username,omitempty"`
	Roles        []string               `json:"roles,omitempty"`
	Permissions  []string               `json:"permissions,omitempty"`
	TenantID     string                 `json:"tenant_id,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	LastActivity time.Time              `json:"last_activity"`
	ExpiresAt    time.Time              `json:"expires_at"`
	IPAddress    string                 `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	DeviceID     string                 `json:"device_id,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	IsActive     bool                   `json:"is_active"`
}

// SessionManager handles session operations
type SessionManager struct {
	redis  *redis.Client
	config SessionConfig
}

// NewSessionManager creates a new session manager
func NewSessionManager(redisClient *redis.Client, config ...SessionConfig) *SessionManager {
	cfg := DefaultSessionConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	return &SessionManager{
		redis:  redisClient,
		config: cfg,
	}
}

// CreateSession creates a new session for a user
func (sm *SessionManager) CreateSession(ctx context.Context, userID string, sessionData SessionData) (*SessionData, error) {
	if sm.redis == nil {
		return nil, errors.Internal("Redis client not available")
	}

	// Generate session ID
	sessionID := uuid.New().String()
	now := time.Now()

	// Populate session data
	sessionData.SessionID = sessionID
	sessionData.UserID = userID
	sessionData.CreatedAt = now
	sessionData.LastActivity = now
	sessionData.ExpiresAt = now.Add(sm.config.DefaultExpiration)
	sessionData.IsActive = true

	if sessionData.Metadata == nil {
		sessionData.Metadata = make(map[string]interface{})
	}

	// Check if user has too many active sessions
	activeSessions, err := sm.GetUserSessions(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to check user sessions")
	}

	if len(activeSessions) >= sm.config.MaxSessions {
		// Remove oldest session
		if err := sm.cleanupOldestSession(ctx, userID, activeSessions); err != nil {
			return nil, errors.Wrap(err, errors.CodeInternal, "Failed to cleanup old sessions")
		}
	}

	// Store session data
	sessionKey := sm.getSessionKey(sessionID)
	userSessionsKey := sm.getUserSessionsKey(userID)

	// Use pipeline for atomic operations
	pipe := sm.redis.Pipeline()

	// Serialize session data
	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to serialize session data")
	}

	// Store session
	pipe.Set(ctx, sessionKey, sessionJSON, sm.config.DefaultExpiration)

	// Add to user sessions set
	pipe.SAdd(ctx, userSessionsKey, sessionID)
	pipe.Expire(ctx, userSessionsKey, sm.config.DefaultExpiration)

	// Execute pipeline
	_, err = pipe.Exec(ctx)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to create session")
	}

	return &sessionData, nil
}

// GetSession retrieves session data by session ID
func (sm *SessionManager) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	if sm.redis == nil {
		return nil, errors.Internal("Redis client not available")
	}

	sessionKey := sm.getSessionKey(sessionID)
	sessionJSON, err := sm.redis.Get(ctx, sessionKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.NotFound("Session not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to get session")
	}

	var sessionData SessionData
	if err := json.Unmarshal([]byte(sessionJSON), &sessionData); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to deserialize session data")
	}

	// Check if session is expired
	if time.Now().After(sessionData.ExpiresAt) {
		// Clean up expired session
		sm.DeleteSession(ctx, sessionID)
		return nil, errors.NotFound("Session expired")
	}

	return &sessionData, nil
}

// UpdateSession updates session data
func (sm *SessionManager) UpdateSession(ctx context.Context, sessionID string, sessionData SessionData) error {
	if sm.redis == nil {
		return errors.Internal("Redis client not available")
	}

	// Update last activity
	sessionData.LastActivity = time.Now()

	sessionKey := sm.getSessionKey(sessionID)

	// Serialize session data
	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to serialize session data")
	}

	// Calculate remaining TTL
	ttl := time.Until(sessionData.ExpiresAt)
	if ttl <= 0 {
		return errors.NotFound("Session expired")
	}

	// Store updated session
	if err := sm.redis.Set(ctx, sessionKey, sessionJSON, ttl).Err(); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to update session")
	}

	return nil
}

// RefreshSession extends session expiration
func (sm *SessionManager) RefreshSession(ctx context.Context, sessionID string) (*SessionData, error) {
	sessionData, err := sm.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	// Check if refresh is needed
	timeUntilExpiry := time.Until(sessionData.ExpiresAt)
	if timeUntilExpiry > sm.config.RefreshThreshold {
		// No need to refresh yet
		return sessionData, nil
	}

	// Extend expiration
	sessionData.ExpiresAt = time.Now().Add(sm.config.DefaultExpiration)
	sessionData.LastActivity = time.Now()

	if err := sm.UpdateSession(ctx, sessionID, *sessionData); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to refresh session")
	}

	// Update Redis expiration
	sessionKey := sm.getSessionKey(sessionID)
	if err := sm.redis.Expire(ctx, sessionKey, sm.config.DefaultExpiration).Err(); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to update session expiration")
	}

	return sessionData, nil
}

// DeleteSession removes a session
func (sm *SessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	if sm.redis == nil {
		return errors.Internal("Redis client not available")
	}

	// Get session to find user ID
	sessionData, err := sm.GetSession(ctx, sessionID)
	if err != nil {
		// Session doesn't exist, consider it deleted
		return nil
	}

	sessionKey := sm.getSessionKey(sessionID)
	userSessionsKey := sm.getUserSessionsKey(sessionData.UserID)

	// Use pipeline for atomic operations
	pipe := sm.redis.Pipeline()

	// Remove session data
	pipe.Del(ctx, sessionKey)

	// Remove from user sessions set
	pipe.SRem(ctx, userSessionsKey, sessionID)

	// Execute pipeline
	_, err = pipe.Exec(ctx)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to delete session")
	}

	return nil
}

// GetUserSessions returns all active sessions for a user
func (sm *SessionManager) GetUserSessions(ctx context.Context, userID string) ([]SessionData, error) {
	if sm.redis == nil {
		return nil, errors.Internal("Redis client not available")
	}

	userSessionsKey := sm.getUserSessionsKey(userID)
	sessionIDs, err := sm.redis.SMembers(ctx, userSessionsKey).Result()
	if err != nil {
		if err == redis.Nil {
			return []SessionData{}, nil
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to get user sessions")
	}

	var sessions []SessionData
	for _, sessionID := range sessionIDs {
		sessionData, err := sm.GetSession(ctx, sessionID)
		if err != nil {
			// Session might be expired, remove from set
			sm.redis.SRem(ctx, userSessionsKey, sessionID)
			continue
		}
		sessions = append(sessions, *sessionData)
	}

	return sessions, nil
}

// DeleteUserSessions removes all sessions for a user
func (sm *SessionManager) DeleteUserSessions(ctx context.Context, userID string) error {
	sessions, err := sm.GetUserSessions(ctx, userID)
	if err != nil {
		return err
	}

	for _, session := range sessions {
		if err := sm.DeleteSession(ctx, session.SessionID); err != nil {
			return err
		}
	}

	return nil
}

// CleanupExpiredSessions removes expired sessions (should be run periodically)
func (sm *SessionManager) CleanupExpiredSessions(ctx context.Context) error {
	if sm.redis == nil {
		return errors.Internal("Redis client not available")
	}

	// This is a simple implementation - in production you might want to use Redis SCAN
	// to iterate through keys more efficiently
	pattern := sm.config.KeyPrefix + ":*"
	keys, err := sm.redis.Keys(ctx, pattern).Result()
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to get session keys")
	}

	var expiredKeys []string
	for _, key := range keys {
		ttl := sm.redis.TTL(ctx, key).Val()
		if ttl == -1 { // Key exists but has no expiration
			expiredKeys = append(expiredKeys, key)
		}
	}

	if len(expiredKeys) > 0 {
		if err := sm.redis.Del(ctx, expiredKeys...).Err(); err != nil {
			return errors.Wrap(err, errors.CodeInternal, "Failed to cleanup expired sessions")
		}
	}

	return nil
}

// GetSessionStats returns session statistics
func (sm *SessionManager) GetSessionStats(ctx context.Context) (map[string]interface{}, error) {
	if sm.redis == nil {
		return nil, errors.Internal("Redis client not available")
	}

	pattern := sm.config.KeyPrefix + ":*"
	keys, err := sm.redis.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to get session keys")
	}

	totalSessions := len(keys)
	activeSessions := 0

	// Count active sessions (this is expensive - consider using different approach in production)
	for _, key := range keys {
		ttl := sm.redis.TTL(ctx, key).Val()
		if ttl > 0 {
			activeSessions++
		}
	}

	return map[string]interface{}{
		"total_sessions":  totalSessions,
		"active_sessions": activeSessions,
		"expired_sessions": totalSessions - activeSessions,
	}, nil
}

// Helper methods

func (sm *SessionManager) getSessionKey(sessionID string) string {
	return fmt.Sprintf("%s:%s", sm.config.KeyPrefix, sessionID)
}

func (sm *SessionManager) getUserSessionsKey(userID string) string {
	return fmt.Sprintf("%s:user:%s", sm.config.KeyPrefix, userID)
}

func (sm *SessionManager) cleanupOldestSession(ctx context.Context, userID string, sessions []SessionData) error {
	if len(sessions) == 0 {
		return nil
	}

	// Find oldest session
	oldestSession := sessions[0]
	for _, session := range sessions[1:] {
		if session.CreatedAt.Before(oldestSession.CreatedAt) {
			oldestSession = session
		}
	}

	return sm.DeleteSession(ctx, oldestSession.SessionID)
}