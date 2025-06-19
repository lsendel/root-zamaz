// Package cache provides repository-level caching for database queries in the MVP Zero Trust Auth system.
// This implements a cache-aside pattern for frequently accessed database entities.
package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"mvp.local/pkg/models"
)

// RepositoryCache provides caching for database repositories
type RepositoryCache struct {
	cache Cache
}

// Cache key prefixes for different entity types
const (
	UserCachePrefix            = "repo:user:"
	UserByEmailCachePrefix     = "repo:user_email:"
	UserByUsernameCachePrefix  = "repo:user_username:"
	RoleCachePrefix            = "repo:role:"
	PermissionCachePrefix      = "repo:permission:"
	DeviceAttestationPrefix    = "repo:device:"
	LoginAttemptCachePrefix    = "repo:login_attempt:"
	RepositoryCacheTTL         = 10 * time.Minute // TTL for repository cache entries
)

// NewRepositoryCache creates a new repository cache
func NewRepositoryCache(cache Cache) *RepositoryCache {
	return &RepositoryCache{
		cache: cache,
	}
}

// User caching methods

// SetUser caches a user by ID
func (rc *RepositoryCache) SetUser(ctx context.Context, user *models.User) error {
	if rc.cache == nil || user == nil {
		return nil
	}

	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}

	// Cache by ID
	userKey := UserCachePrefix + user.ID.String()
	_ = rc.cache.Set(ctx, userKey, userJSON, RepositoryCacheTTL)

	// Cache by email for fast email lookups
	emailKey := UserByEmailCachePrefix + user.Email
	_ = rc.cache.Set(ctx, emailKey, userJSON, RepositoryCacheTTL)

	// Cache by username for fast username lookups
	usernameKey := UserByUsernameCachePrefix + user.Username
	_ = rc.cache.Set(ctx, usernameKey, userJSON, RepositoryCacheTTL)

	return nil
}

// GetUser retrieves a user by ID from cache
func (rc *RepositoryCache) GetUser(ctx context.Context, userID string) (*models.User, error) {
	if rc.cache == nil {
		return nil, fmt.Errorf("cache not available")
	}

	userKey := UserCachePrefix + userID
	cached, err := rc.cache.Get(ctx, userKey)
	if err != nil {
		return nil, err
	}

	var user models.User
	if err := json.Unmarshal(cached, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by email from cache
func (rc *RepositoryCache) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	if rc.cache == nil {
		return nil, fmt.Errorf("cache not available")
	}

	emailKey := UserByEmailCachePrefix + email
	cached, err := rc.cache.Get(ctx, emailKey)
	if err != nil {
		return nil, err
	}

	var user models.User
	if err := json.Unmarshal(cached, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUserByUsername retrieves a user by username from cache
func (rc *RepositoryCache) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	if rc.cache == nil {
		return nil, fmt.Errorf("cache not available")
	}

	usernameKey := UserByUsernameCachePrefix + username
	cached, err := rc.cache.Get(ctx, usernameKey)
	if err != nil {
		return nil, err
	}

	var user models.User
	if err := json.Unmarshal(cached, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

// InvalidateUser removes user from all cache entries
func (rc *RepositoryCache) InvalidateUser(ctx context.Context, user *models.User) error {
	if rc.cache == nil || user == nil {
		return nil
	}

	// Remove all user cache entries
	userKey := UserCachePrefix + user.ID.String()
	emailKey := UserByEmailCachePrefix + user.Email
	usernameKey := UserByUsernameCachePrefix + user.Username

	_ = rc.cache.Delete(ctx, userKey)
	_ = rc.cache.Delete(ctx, emailKey)
	_ = rc.cache.Delete(ctx, usernameKey)

	return nil
}

// Role caching methods

// SetRole caches a role by ID
func (rc *RepositoryCache) SetRole(ctx context.Context, role *models.Role) error {
	if rc.cache == nil || role == nil {
		return nil
	}

	roleJSON, err := json.Marshal(role)
	if err != nil {
		return err
	}

	roleKey := fmt.Sprintf("%s%d", RoleCachePrefix, role.ID)
	return rc.cache.Set(ctx, roleKey, roleJSON, RepositoryCacheTTL)
}

// GetRole retrieves a role by ID from cache
func (rc *RepositoryCache) GetRole(ctx context.Context, roleID int64) (*models.Role, error) {
	if rc.cache == nil {
		return nil, fmt.Errorf("cache not available")
	}

	roleKey := fmt.Sprintf("%s%d", RoleCachePrefix, roleID)
	cached, err := rc.cache.Get(ctx, roleKey)
	if err != nil {
		return nil, err
	}

	var role models.Role
	if err := json.Unmarshal(cached, &role); err != nil {
		return nil, err
	}

	return &role, nil
}

// InvalidateRole removes role from cache
func (rc *RepositoryCache) InvalidateRole(ctx context.Context, roleID int64) error {
	if rc.cache == nil {
		return nil
	}

	roleKey := fmt.Sprintf("%s%d", RoleCachePrefix, roleID)
	return rc.cache.Delete(ctx, roleKey)
}

// Permission caching methods

// SetPermission caches a permission by ID
func (rc *RepositoryCache) SetPermission(ctx context.Context, permission *models.Permission) error {
	if rc.cache == nil || permission == nil {
		return nil
	}

	permissionJSON, err := json.Marshal(permission)
	if err != nil {
		return err
	}

	permissionKey := fmt.Sprintf("%s%d", PermissionCachePrefix, permission.ID)
	return rc.cache.Set(ctx, permissionKey, permissionJSON, RepositoryCacheTTL)
}

// GetPermission retrieves a permission by ID from cache
func (rc *RepositoryCache) GetPermission(ctx context.Context, permissionID int64) (*models.Permission, error) {
	if rc.cache == nil {
		return nil, fmt.Errorf("cache not available")
	}

	permissionKey := fmt.Sprintf("%s%d", PermissionCachePrefix, permissionID)
	cached, err := rc.cache.Get(ctx, permissionKey)
	if err != nil {
		return nil, err
	}

	var permission models.Permission
	if err := json.Unmarshal(cached, &permission); err != nil {
		return nil, err
	}

	return &permission, nil
}

// InvalidatePermission removes permission from cache
func (rc *RepositoryCache) InvalidatePermission(ctx context.Context, permissionID int64) error {
	if rc.cache == nil {
		return nil
	}

	permissionKey := fmt.Sprintf("%s%d", PermissionCachePrefix, permissionID)
	return rc.cache.Delete(ctx, permissionKey)
}

// Device Attestation caching methods

// SetDeviceAttestation caches a device attestation by ID
func (rc *RepositoryCache) SetDeviceAttestation(ctx context.Context, device *models.DeviceAttestation) error {
	if rc.cache == nil || device == nil {
		return nil
	}

	deviceJSON, err := json.Marshal(device)
	if err != nil {
		return err
	}

	deviceKey := DeviceAttestationPrefix + device.ID.String()
	return rc.cache.Set(ctx, deviceKey, deviceJSON, RepositoryCacheTTL)
}

// GetDeviceAttestation retrieves a device attestation by ID from cache
func (rc *RepositoryCache) GetDeviceAttestation(ctx context.Context, deviceID string) (*models.DeviceAttestation, error) {
	if rc.cache == nil {
		return nil, fmt.Errorf("cache not available")
	}

	deviceKey := DeviceAttestationPrefix + deviceID
	cached, err := rc.cache.Get(ctx, deviceKey)
	if err != nil {
		return nil, err
	}

	var device models.DeviceAttestation
	if err := json.Unmarshal(cached, &device); err != nil {
		return nil, err
	}

	return &device, nil
}

// InvalidateDeviceAttestation removes device attestation from cache
func (rc *RepositoryCache) InvalidateDeviceAttestation(ctx context.Context, deviceID string) error {
	if rc.cache == nil {
		return nil
	}

	deviceKey := DeviceAttestationPrefix + deviceID
	return rc.cache.Delete(ctx, deviceKey)
}

// Login attempt caching for rate limiting

// SetRecentLoginAttempts caches recent login attempts for a given identifier (IP or username)
func (rc *RepositoryCache) SetRecentLoginAttempts(ctx context.Context, identifier string, attempts []models.LoginAttempt, ttl time.Duration) error {
	if rc.cache == nil {
		return nil
	}

	attemptsJSON, err := json.Marshal(attempts)
	if err != nil {
		return err
	}

	attemptKey := LoginAttemptCachePrefix + identifier
	return rc.cache.Set(ctx, attemptKey, attemptsJSON, ttl)
}

// GetRecentLoginAttempts retrieves recent login attempts from cache
func (rc *RepositoryCache) GetRecentLoginAttempts(ctx context.Context, identifier string) ([]models.LoginAttempt, error) {
	if rc.cache == nil {
		return nil, fmt.Errorf("cache not available")
	}

	attemptKey := LoginAttemptCachePrefix + identifier
	cached, err := rc.cache.Get(ctx, attemptKey)
	if err != nil {
		return nil, err
	}

	var attempts []models.LoginAttempt
	if err := json.Unmarshal(cached, &attempts); err != nil {
		return nil, err
	}

	return attempts, nil
}

// InvalidateLoginAttempts removes login attempts from cache
func (rc *RepositoryCache) InvalidateLoginAttempts(ctx context.Context, identifier string) error {
	if rc.cache == nil {
		return nil
	}

	attemptKey := LoginAttemptCachePrefix + identifier
	return rc.cache.Delete(ctx, attemptKey)
}

// Bulk operations

// InvalidateAllUserCache clears all user-related cache entries
func (rc *RepositoryCache) InvalidateAllUserCache(ctx context.Context) error {
	if rc.cache == nil {
		return nil
	}

	patterns := []string{
		UserCachePrefix + "*",
		UserByEmailCachePrefix + "*",
		UserByUsernameCachePrefix + "*",
	}

	for _, pattern := range patterns {
		if keys, err := rc.cache.Keys(ctx, pattern); err == nil {
			for _, key := range keys {
				_ = rc.cache.Delete(ctx, key)
			}
		}
	}

	return nil
}

// InvalidateAllCache clears all repository cache entries
func (rc *RepositoryCache) InvalidateAllCache(ctx context.Context) error {
	if rc.cache == nil {
		return nil
	}

	patterns := []string{
		UserCachePrefix + "*",
		UserByEmailCachePrefix + "*",
		UserByUsernameCachePrefix + "*",
		RoleCachePrefix + "*",
		PermissionCachePrefix + "*",
		DeviceAttestationPrefix + "*",
		LoginAttemptCachePrefix + "*",
	}

	for _, pattern := range patterns {
		if keys, err := rc.cache.Keys(ctx, pattern); err == nil {
			for _, key := range keys {
				_ = rc.cache.Delete(ctx, key)
			}
		}
	}

	return nil
}

// GetCacheStats returns cache statistics for repository entries
func (rc *RepositoryCache) GetCacheStats(ctx context.Context) (map[string]interface{}, error) {
	if rc.cache == nil {
		return map[string]interface{}{
			"users":              0,
			"roles":              0,
			"permissions":        0,
			"device_attestations": 0,
			"login_attempts":     0,
		}, nil
	}

	stats := make(map[string]interface{})

	// Count each type of cached entity
	patterns := map[string]string{
		"users":               UserCachePrefix + "*",
		"user_emails":         UserByEmailCachePrefix + "*",
		"user_usernames":      UserByUsernameCachePrefix + "*",
		"roles":               RoleCachePrefix + "*",
		"permissions":         PermissionCachePrefix + "*",
		"device_attestations": DeviceAttestationPrefix + "*",
		"login_attempts":      LoginAttemptCachePrefix + "*",
	}

	for name, pattern := range patterns {
		if keys, err := rc.cache.Keys(ctx, pattern); err == nil {
			stats[name] = len(keys)
		} else {
			stats[name] = 0
		}
	}

	return stats, nil
}