// Package blacklist provides token blacklisting implementations for JWT revocation.
package blacklist

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Blacklist interface for token blacklisting implementations
type Blacklist interface {
	Add(ctx context.Context, jti, reason string, expiresAt time.Time) error
	IsBlacklisted(ctx context.Context, tokenString string) (bool, error)
	Remove(ctx context.Context, jti string) error
	Cleanup(ctx context.Context) error
	GetStats(ctx context.Context) (*Stats, error)
}

// BlacklistEntry represents a blacklisted token entry
type BlacklistEntry struct {
	JTI       string    `json:"jti"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	UserID    string    `json:"user_id,omitempty"`
}

// Stats represents blacklist statistics
type Stats struct {
	TotalEntries   int64     `json:"total_entries"`
	ExpiredEntries int64     `json:"expired_entries"`
	ActiveEntries  int64     `json:"active_entries"`
	LastCleanup    time.Time `json:"last_cleanup"`
	MemoryUsage    int64     `json:"memory_usage_bytes,omitempty"`
}

// MemoryBlacklist implements in-memory token blacklisting
type MemoryBlacklist struct {
	mu         sync.RWMutex
	entries    map[string]*BlacklistEntry
	lastCleanup time.Time
	cleanupInterval time.Duration
}

// NewMemoryBlacklist creates a new in-memory blacklist
func NewMemoryBlacklist() *MemoryBlacklist {
	return &MemoryBlacklist{
		entries:         make(map[string]*BlacklistEntry),
		lastCleanup:     time.Now(),
		cleanupInterval: 1 * time.Hour, // Clean up every hour
	}
}

// Add adds a token to the blacklist
func (mb *MemoryBlacklist) Add(ctx context.Context, jti, reason string, expiresAt time.Time) error {
	if jti == "" {
		return fmt.Errorf("JTI cannot be empty")
	}
	if reason == "" {
		return fmt.Errorf("reason cannot be empty")
	}

	mb.mu.Lock()
	defer mb.mu.Unlock()

	entry := &BlacklistEntry{
		JTI:       jti,
		Reason:    reason,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	mb.entries[jti] = entry

	// Auto-cleanup if needed
	if time.Since(mb.lastCleanup) > mb.cleanupInterval {
		go mb.autoCleanup()
	}

	return nil
}

// IsBlacklisted checks if a token is blacklisted
func (mb *MemoryBlacklist) IsBlacklisted(ctx context.Context, tokenString string) (bool, error) {
	jti, err := extractJTI(tokenString)
	if err != nil {
		return false, fmt.Errorf("failed to extract JTI: %w", err)
	}

	mb.mu.RLock()
	defer mb.mu.RUnlock()

	entry, exists := mb.entries[jti]
	if !exists {
		return false, nil
	}

	// Check if entry has expired
	if time.Now().After(entry.ExpiresAt) {
		// Remove expired entry
		delete(mb.entries, jti)
		return false, nil
	}

	return true, nil
}

// Remove removes a token from the blacklist
func (mb *MemoryBlacklist) Remove(ctx context.Context, jti string) error {
	if jti == "" {
		return fmt.Errorf("JTI cannot be empty")
	}

	mb.mu.Lock()
	defer mb.mu.Unlock()

	delete(mb.entries, jti)
	return nil
}

// Cleanup removes expired entries from the blacklist
func (mb *MemoryBlacklist) Cleanup(ctx context.Context) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	now := time.Now()
	expiredCount := 0

	for jti, entry := range mb.entries {
		if now.After(entry.ExpiresAt) {
			delete(mb.entries, jti)
			expiredCount++
		}
	}

	mb.lastCleanup = now
	return nil
}

// autoCleanup performs automatic cleanup in a goroutine
func (mb *MemoryBlacklist) autoCleanup() {
	mb.Cleanup(context.Background())
}

// GetStats returns blacklist statistics
func (mb *MemoryBlacklist) GetStats(ctx context.Context) (*Stats, error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	now := time.Now()
	activeEntries := int64(0)
	expiredEntries := int64(0)

	for _, entry := range mb.entries {
		if now.After(entry.ExpiresAt) {
			expiredEntries++
		} else {
			activeEntries++
		}
	}

	// Estimate memory usage
	memoryUsage := int64(len(mb.entries)) * 200 // Rough estimate: 200 bytes per entry

	return &Stats{
		TotalEntries:   activeEntries + expiredEntries,
		ExpiredEntries: expiredEntries,
		ActiveEntries:  activeEntries,
		LastCleanup:    mb.lastCleanup,
		MemoryUsage:    memoryUsage,
	}, nil
}

// RedisBlacklist implements Redis-based token blacklisting
type RedisBlacklist struct {
	client RedisClient
	prefix string
}

// RedisClient interface for Redis operations
type RedisClient interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Del(ctx context.Context, keys ...string) error
	Exists(ctx context.Context, keys ...string) (int64, error)
	Keys(ctx context.Context, pattern string) ([]string, error)
	TTL(ctx context.Context, key string) (time.Duration, error)
}

// NewRedisBlacklist creates a new Redis-based blacklist
func NewRedisBlacklist(client RedisClient, prefix string) *RedisBlacklist {
	if prefix == "" {
		prefix = "jwt:blacklist"
	}

	return &RedisBlacklist{
		client: client,
		prefix: prefix,
	}
}

// Add adds a token to the Redis blacklist
func (rb *RedisBlacklist) Add(ctx context.Context, jti, reason string, expiresAt time.Time) error {
	if jti == "" {
		return fmt.Errorf("JTI cannot be empty")
	}
	if reason == "" {
		return fmt.Errorf("reason cannot be empty")
	}

	key := rb.getKey(jti)
	entry := &BlacklistEntry{
		JTI:       jti,
		Reason:    reason,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal blacklist entry: %w", err)
	}

	// Set with expiration based on token expiry
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return fmt.Errorf("token already expired")
	}

	return rb.client.Set(ctx, key, entryJSON, ttl)
}

// IsBlacklisted checks if a token is blacklisted in Redis
func (rb *RedisBlacklist) IsBlacklisted(ctx context.Context, tokenString string) (bool, error) {
	jti, err := extractJTI(tokenString)
	if err != nil {
		return false, fmt.Errorf("failed to extract JTI: %w", err)
	}

	key := rb.getKey(jti)
	exists, err := rb.client.Exists(ctx, key)
	if err != nil {
		return false, fmt.Errorf("failed to check Redis: %w", err)
	}

	return exists > 0, nil
}

// Remove removes a token from the Redis blacklist
func (rb *RedisBlacklist) Remove(ctx context.Context, jti string) error {
	if jti == "" {
		return fmt.Errorf("JTI cannot be empty")
	}

	key := rb.getKey(jti)
	return rb.client.Del(ctx, key)
}

// Cleanup removes expired entries (Redis handles this automatically via TTL)
func (rb *RedisBlacklist) Cleanup(ctx context.Context) error {
	// Redis automatically removes expired keys, but we can force cleanup
	// by checking for keys with negative TTL and removing them
	pattern := rb.prefix + ":*"
	keys, err := rb.client.Keys(ctx, pattern)
	if err != nil {
		return fmt.Errorf("failed to get keys: %w", err)
	}

	expiredKeys := []string{}
	for _, key := range keys {
		ttl, err := rb.client.TTL(ctx, key)
		if err != nil {
			continue
		}
		if ttl < 0 {
			expiredKeys = append(expiredKeys, key)
		}
	}

	if len(expiredKeys) > 0 {
		return rb.client.Del(ctx, expiredKeys...)
	}

	return nil
}

// GetStats returns blacklist statistics from Redis
func (rb *RedisBlacklist) GetStats(ctx context.Context) (*Stats, error) {
	pattern := rb.prefix + ":*"
	keys, err := rb.client.Keys(ctx, pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to get keys: %w", err)
	}

	activeEntries := int64(0)
	expiredEntries := int64(0)

	for _, key := range keys {
		ttl, err := rb.client.TTL(ctx, key)
		if err != nil {
			continue
		}
		if ttl > 0 {
			activeEntries++
		} else {
			expiredEntries++
		}
	}

	return &Stats{
		TotalEntries:   activeEntries + expiredEntries,
		ExpiredEntries: expiredEntries,
		ActiveEntries:  activeEntries,
		LastCleanup:    time.Now(), // Redis cleanup is continuous
	}, nil
}

// getKey generates a Redis key for a JTI
func (rb *RedisBlacklist) getKey(jti string) string {
	return fmt.Sprintf("%s:%s", rb.prefix, jti)
}

// HybridBlacklist combines memory and Redis blacklists for high performance
type HybridBlacklist struct {
	memory      *MemoryBlacklist
	redis       *RedisBlacklist
	syncEnabled bool
}

// NewHybridBlacklist creates a hybrid blacklist with both memory and Redis
func NewHybridBlacklist(redisClient RedisClient, prefix string) *HybridBlacklist {
	return &HybridBlacklist{
		memory:      NewMemoryBlacklist(),
		redis:       NewRedisBlacklist(redisClient, prefix),
		syncEnabled: true,
	}
}

// Add adds a token to both memory and Redis blacklists
func (hb *HybridBlacklist) Add(ctx context.Context, jti, reason string, expiresAt time.Time) error {
	// Add to memory first (fast)
	if err := hb.memory.Add(ctx, jti, reason, expiresAt); err != nil {
		return err
	}

	// Add to Redis for persistence (may be slower)
	if hb.syncEnabled {
		if err := hb.redis.Add(ctx, jti, reason, expiresAt); err != nil {
			// Log error but don't fail - memory blacklist is still active
			// In production, you'd want proper logging here
			return fmt.Errorf("failed to sync to Redis: %w", err)
		}
	}

	return nil
}

// IsBlacklisted checks memory first, then Redis if not found
func (hb *HybridBlacklist) IsBlacklisted(ctx context.Context, tokenString string) (bool, error) {
	// Check memory first (fastest)
	blacklisted, err := hb.memory.IsBlacklisted(ctx, tokenString)
	if err != nil {
		return false, err
	}
	if blacklisted {
		return true, nil
	}

	// Check Redis if not in memory
	if hb.syncEnabled {
		return hb.redis.IsBlacklisted(ctx, tokenString)
	}

	return false, nil
}

// Remove removes from both memory and Redis
func (hb *HybridBlacklist) Remove(ctx context.Context, jti string) error {
	// Remove from memory
	if err := hb.memory.Remove(ctx, jti); err != nil {
		return err
	}

	// Remove from Redis
	if hb.syncEnabled {
		return hb.redis.Remove(ctx, jti)
	}

	return nil
}

// Cleanup cleans up both memory and Redis
func (hb *HybridBlacklist) Cleanup(ctx context.Context) error {
	// Cleanup memory
	if err := hb.memory.Cleanup(ctx); err != nil {
		return err
	}

	// Cleanup Redis
	if hb.syncEnabled {
		return hb.redis.Cleanup(ctx)
	}

	return nil
}

// GetStats returns combined statistics
func (hb *HybridBlacklist) GetStats(ctx context.Context) (*Stats, error) {
	memStats, err := hb.memory.GetStats(ctx)
	if err != nil {
		return nil, err
	}

	if !hb.syncEnabled {
		return memStats, nil
	}

	redisStats, err := hb.redis.GetStats(ctx)
	if err != nil {
		// Return memory stats if Redis fails
		return memStats, nil
	}

	// Combine stats (Redis is authoritative for total counts)
	return &Stats{
		TotalEntries:   redisStats.TotalEntries,
		ExpiredEntries: redisStats.ExpiredEntries,
		ActiveEntries:  redisStats.ActiveEntries,
		LastCleanup:    memStats.LastCleanup,
		MemoryUsage:    memStats.MemoryUsage,
	}, nil
}

// Helper function to extract JTI from token
func extractJTI(tokenString string) (string, error) {
	if tokenString == "" {
		return "", fmt.Errorf("token string cannot be empty")
	}

	// Remove Bearer prefix if present
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// We don't validate signature here, just extract claims
		return []byte("dummy"), nil
	})

	if err != nil && !strings.Contains(err.Error(), "signature is invalid") {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if jti, exists := claims["jti"]; exists {
			if jtiStr, ok := jti.(string); ok {
				return jtiStr, nil
			}
		}
	}

	return "", fmt.Errorf("JTI not found in token")
}