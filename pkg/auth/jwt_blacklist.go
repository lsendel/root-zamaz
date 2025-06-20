// Package auth provides JWT blacklist functionality for the MVP Zero Trust Auth system.
// This allows blacklisting of JWT tokens to immediately revoke access.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"mvp.local/pkg/cache"
	"mvp.local/pkg/errors"
)

// JWTBlacklist manages revoked/blacklisted JWT tokens
type JWTBlacklist struct {
	cache cache.Cache
}

// BlacklistEntry represents a blacklisted token entry
type BlacklistEntry struct {
	TokenHash string    `json:"token_hash"`
	UserID    string    `json:"user_id"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Blacklist reasons
const (
	BlacklistReasonLogout         = "logout"
	BlacklistReasonSecurityBreach = "security_breach"
	BlacklistReasonPasswordChange = "password_change"
	BlacklistReasonAdminRevoke    = "admin_revoke"
	BlacklistReasonSuspended      = "user_suspended"
)

// Cache key constants for JWT blacklist
const (
	BlacklistKeyPrefix  = "jwt_blacklist:"
	UserBlacklistPrefix = "user_blacklist:"
)

// NewJWTBlacklist creates a new JWT blacklist service
func NewJWTBlacklist(cache cache.Cache) *JWTBlacklist {
	return &JWTBlacklist{
		cache: cache,
	}
}

// BlacklistToken adds a token to the blacklist
func (jb *JWTBlacklist) BlacklistToken(ctx context.Context, tokenString, userID, reason string, expiresAt time.Time) error {
	if jb.cache == nil {
		return errors.Internal("Cache not available for JWT blacklist")
	}

	// Create hash of token to avoid storing the actual token
	tokenHash := jb.hashToken(tokenString)

	entry := BlacklistEntry{
		TokenHash: tokenHash,
		UserID:    userID,
		Reason:    reason,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	// Calculate TTL based on token expiration
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Token already expired, no need to blacklist
		return nil
	}

	blacklistKey := jb.getBlacklistKey(tokenHash)

	// Store the blacklist entry with JSON serialization
	if err := jb.cache.Set(ctx, blacklistKey, entry, ttl); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to blacklist token")
	}

	// Also store in user-specific blacklist for bulk operations
	userBlacklistKey := jb.getUserBlacklistKey(userID)
	if err := jb.cache.SAdd(ctx, userBlacklistKey, tokenHash); err != nil {
		// Log error but don't fail the operation
		// The main blacklist entry is what matters for token validation
	}

	return nil
}

// IsTokenBlacklisted checks if a token is blacklisted
func (jb *JWTBlacklist) IsTokenBlacklisted(ctx context.Context, tokenString string) (bool, error) {
	if jb.cache == nil {
		// If cache is not available, assume token is not blacklisted
		// This ensures the system continues to work even without cache
		return false, nil
	}

	tokenHash := jb.hashToken(tokenString)
	blacklistKey := jb.getBlacklistKey(tokenHash)

	// Check if token exists in blacklist
	exists, err := jb.cache.Exists(ctx, blacklistKey)
	if err != nil {
		// Log error but don't fail authentication
		// Return false to avoid breaking auth if cache is temporarily unavailable
		return false, nil
	}

	return exists, nil
}

// BlacklistUserTokens blacklists all tokens for a specific user
func (jb *JWTBlacklist) BlacklistUserTokens(ctx context.Context, userID, reason string, maxTokenExpiry time.Time) error {
	if jb.cache == nil {
		return errors.Internal("Cache not available for JWT blacklist")
	}

	// Create a user-wide blacklist entry that affects all tokens for this user
	// This is useful for password changes, account suspension, etc.
	userBlacklistKey := jb.getUserBlacklistKey(userID)

	entry := BlacklistEntry{
		TokenHash: "", // Empty for user-wide blacklist
		UserID:    userID,
		Reason:    reason,
		CreatedAt: time.Now(),
		ExpiresAt: maxTokenExpiry,
	}

	// Calculate TTL based on maximum token expiration
	ttl := time.Until(maxTokenExpiry)
	if ttl <= 0 {
		ttl = 24 * time.Hour // Default fallback
	}

	if err := jb.cache.Set(ctx, userBlacklistKey, entry, ttl); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to blacklist user tokens")
	}

	return nil
}

// IsUserTokensBlacklisted checks if all tokens for a user are blacklisted
func (jb *JWTBlacklist) IsUserTokensBlacklisted(ctx context.Context, userID string) (bool, error) {
	if jb.cache == nil {
		return false, nil
	}

	userBlacklistKey := jb.getUserBlacklistKey(userID)

	exists, err := jb.cache.Exists(ctx, userBlacklistKey)
	if err != nil {
		return false, nil
	}

	return exists, nil
}

// CleanupExpiredEntries removes expired blacklist entries (called periodically)
func (jb *JWTBlacklist) CleanupExpiredEntries(ctx context.Context) error {
	if jb.cache == nil {
		return nil
	}

	// Get all blacklist keys
	pattern := BlacklistKeyPrefix + "*"
	keys, err := jb.cache.Keys(ctx, pattern)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to get blacklist keys")
	}

	// Check TTL for each key and remove expired ones
	for _, key := range keys {
		ttl, err := jb.cache.TTL(ctx, key)
		if err != nil {
			continue
		}

		// Remove keys with no TTL or expired
		if ttl <= 0 {
			_ = jb.cache.Delete(ctx, key)
		}
	}

	// Also cleanup user blacklist keys
	userPattern := UserBlacklistPrefix + "*"
	userKeys, err := jb.cache.Keys(ctx, userPattern)
	if err == nil {
		for _, key := range userKeys {
			ttl, err := jb.cache.TTL(ctx, key)
			if err != nil {
				continue
			}

			if ttl <= 0 {
				_ = jb.cache.Delete(ctx, key)
			}
		}
	}

	return nil
}

// GetBlacklistStats returns statistics about blacklisted tokens
func (jb *JWTBlacklist) GetBlacklistStats(ctx context.Context) (map[string]interface{}, error) {
	if jb.cache == nil {
		return map[string]interface{}{
			"total_blacklisted_tokens": 0,
			"blacklisted_users":        0,
		}, nil
	}

	// Count blacklisted tokens
	tokenPattern := BlacklistKeyPrefix + "*"
	tokenKeys, err := jb.cache.Keys(ctx, tokenPattern)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to get blacklist statistics")
	}

	// Count blacklisted users
	userPattern := UserBlacklistPrefix + "*"
	userKeys, err := jb.cache.Keys(ctx, userPattern)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to get user blacklist statistics")
	}

	return map[string]interface{}{
		"total_blacklisted_tokens": len(tokenKeys),
		"blacklisted_users":        len(userKeys),
	}, nil
}

// Helper methods

// hashToken creates a SHA-256 hash of the token for secure storage
func (jb *JWTBlacklist) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// getBlacklistKey returns the cache key for a blacklisted token
func (jb *JWTBlacklist) getBlacklistKey(tokenHash string) string {
	return fmt.Sprintf("%s%s", BlacklistKeyPrefix, tokenHash)
}

// getUserBlacklistKey returns the cache key for user-wide blacklist
func (jb *JWTBlacklist) getUserBlacklistKey(userID string) string {
	return fmt.Sprintf("%s%s", UserBlacklistPrefix, userID)
}
