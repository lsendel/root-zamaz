// Package cache provides Redis-backed caching implementation for the MVP Zero Trust Auth system
package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"mvp.local/pkg/config"
	"mvp.local/pkg/observability"
)

// Cache defines the interface for caching operations
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
	Keys(ctx context.Context, pattern string) ([]string, error)
	FlushAll(ctx context.Context) error
	TTL(ctx context.Context, key string) (time.Duration, error)

	// Batch operations
	MGet(ctx context.Context, keys []string) (map[string][]byte, error)
	MSet(ctx context.Context, pairs map[string]interface{}, expiration time.Duration) error

	// Hash operations
	HGet(ctx context.Context, key, field string) ([]byte, error)
	HSet(ctx context.Context, key, field string, value interface{}) error
	HGetAll(ctx context.Context, key string) (map[string]string, error)

	// List operations
	LPush(ctx context.Context, key string, values ...interface{}) error
	RPop(ctx context.Context, key string) ([]byte, error)
	LRange(ctx context.Context, key string, start, stop int64) ([]string, error)

	// Set operations
	SAdd(ctx context.Context, key string, members ...interface{}) error
	SMembers(ctx context.Context, key string) ([]string, error)
	SIsMember(ctx context.Context, key string, member interface{}) (bool, error)

	// Utility
	Ping(ctx context.Context) error
	Info(ctx context.Context) (map[string]interface{}, error)
	Stats() CacheStats
}

// CacheStats provides cache performance statistics
type CacheStats struct {
	Hits        int64                  `json:"hits"`
	Misses      int64                  `json:"misses"`
	HitRatio    float64                `json:"hit_ratio"`
	Keys        int64                  `json:"keys"`
	Memory      map[string]interface{} `json:"memory"`
	Connections map[string]interface{} `json:"connections"`
	LastUpdate  time.Time              `json:"last_update"`
}

// RedisCache implements the Cache interface using Redis
type RedisCache struct {
	client *redis.Client
	config *config.RedisConfig
	obs    *observability.Observability

	// Key prefix for this cache instance
	keyPrefix string

	// Default expiration
	defaultExpiration time.Duration

	// Statistics
	stats CacheStats
}

// NewRedisCache creates a new Redis cache instance
func NewRedisCache(
	client *redis.Client,
	config *config.RedisConfig,
	obs *observability.Observability,
	keyPrefix string,
) *RedisCache {
	if keyPrefix == "" {
		keyPrefix = "mvp_auth"
	}

	return &RedisCache{
		client:            client,
		config:            config,
		obs:               obs,
		keyPrefix:         keyPrefix,
		defaultExpiration: 1 * time.Hour,
		stats: CacheStats{
			LastUpdate: time.Now(),
		},
	}
}

// Get retrieves a value from cache
func (rc *RedisCache) Get(ctx context.Context, key string) ([]byte, error) {
	fullKey := rc.buildKey(key)

	start := time.Now()
	result, err := rc.client.Get(ctx, fullKey).Bytes()
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("get", duration, err == nil)

	if err == redis.Nil {
		rc.stats.Misses++
		return nil, ErrCacheMiss
	}

	if err != nil {
		rc.obs.Logger.Error().
			Err(err).
			Str("key", key).
			Dur("duration", duration).
			Msg("Cache get operation failed")
		return nil, fmt.Errorf("cache get failed: %w", err)
	}

	rc.stats.Hits++
	rc.obs.Logger.Debug().
		Str("key", key).
		Dur("duration", duration).
		Msg("Cache hit")

	return result, nil
}

// Set stores a value in cache
func (rc *RedisCache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	fullKey := rc.buildKey(key)

	if expiration == 0 {
		expiration = rc.defaultExpiration
	}

	// Serialize value
	data, err := rc.serialize(value)
	if err != nil {
		return fmt.Errorf("failed to serialize value: %w", err)
	}

	start := time.Now()
	err = rc.client.Set(ctx, fullKey, data, expiration).Err()
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("set", duration, err == nil)

	if err != nil {
		rc.obs.Logger.Error().
			Err(err).
			Str("key", key).
			Dur("duration", duration).
			Dur("expiration", expiration).
			Msg("Cache set operation failed")
		return fmt.Errorf("cache set failed: %w", err)
	}

	rc.obs.Logger.Debug().
		Str("key", key).
		Dur("duration", duration).
		Dur("expiration", expiration).
		Msg("Cache set successful")

	return nil
}

// Delete removes a key from cache
func (rc *RedisCache) Delete(ctx context.Context, key string) error {
	fullKey := rc.buildKey(key)

	start := time.Now()
	err := rc.client.Del(ctx, fullKey).Err()
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("delete", duration, err == nil)

	if err != nil {
		rc.obs.Logger.Error().
			Err(err).
			Str("key", key).
			Dur("duration", duration).
			Msg("Cache delete operation failed")
		return fmt.Errorf("cache delete failed: %w", err)
	}

	return nil
}

// Exists checks if a key exists in cache
func (rc *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	fullKey := rc.buildKey(key)

	start := time.Now()
	count, err := rc.client.Exists(ctx, fullKey).Result()
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("exists", duration, err == nil)

	if err != nil {
		return false, fmt.Errorf("cache exists check failed: %w", err)
	}

	return count > 0, nil
}

// Keys returns all keys matching a pattern
func (rc *RedisCache) Keys(ctx context.Context, pattern string) ([]string, error) {
	fullPattern := rc.buildKey(pattern)

	start := time.Now()

	// Use SCAN instead of KEYS for better performance
	var keys []string
	iter := rc.client.Scan(ctx, 0, fullPattern, 0).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		// Remove prefix for returned keys
		if strings.HasPrefix(key, rc.keyPrefix+":") {
			keys = append(keys, key[len(rc.keyPrefix)+1:])
		}
	}

	duration := time.Since(start)
	err := iter.Err()

	// Record metrics
	rc.recordOperation("keys", duration, err == nil)

	if err != nil {
		return nil, fmt.Errorf("cache keys scan failed: %w", err)
	}

	return keys, nil
}

// FlushAll removes all keys from the cache
func (rc *RedisCache) FlushAll(ctx context.Context) error {
	start := time.Now()
	err := rc.client.FlushDB(ctx).Err()
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("flush_all", duration, err == nil)

	if err != nil {
		rc.obs.Logger.Error().
			Err(err).
			Dur("duration", duration).
			Msg("Cache flush all operation failed")
		return fmt.Errorf("cache flush all failed: %w", err)
	}

	rc.obs.Logger.Info().
		Dur("duration", duration).
		Msg("Cache flushed successfully")

	return nil
}

// TTL returns the time to live for a key
func (rc *RedisCache) TTL(ctx context.Context, key string) (time.Duration, error) {
	fullKey := rc.buildKey(key)

	start := time.Now()
	ttl, err := rc.client.TTL(ctx, fullKey).Result()
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("ttl", duration, err == nil)

	if err != nil {
		return 0, fmt.Errorf("cache TTL check failed: %w", err)
	}

	return ttl, nil
}

// Batch operations

// MGet retrieves multiple values
func (rc *RedisCache) MGet(ctx context.Context, keys []string) (map[string][]byte, error) {
	if len(keys) == 0 {
		return make(map[string][]byte), nil
	}

	fullKeys := make([]string, len(keys))
	for i, key := range keys {
		fullKeys[i] = rc.buildKey(key)
	}

	start := time.Now()
	values, err := rc.client.MGet(ctx, fullKeys...).Result()
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("mget", duration, err == nil)

	if err != nil {
		return nil, fmt.Errorf("cache mget failed: %w", err)
	}

	result := make(map[string][]byte)
	for i, value := range values {
		if value != nil {
			if strVal, ok := value.(string); ok {
				result[keys[i]] = []byte(strVal)
				rc.stats.Hits++
			}
		} else {
			rc.stats.Misses++
		}
	}

	return result, nil
}

// MSet sets multiple key-value pairs
func (rc *RedisCache) MSet(ctx context.Context, pairs map[string]interface{}, expiration time.Duration) error {
	if len(pairs) == 0 {
		return nil
	}

	if expiration == 0 {
		expiration = rc.defaultExpiration
	}

	pipe := rc.client.Pipeline()

	for key, value := range pairs {
		fullKey := rc.buildKey(key)
		data, err := rc.serialize(value)
		if err != nil {
			return fmt.Errorf("failed to serialize value for key %s: %w", key, err)
		}
		pipe.Set(ctx, fullKey, data, expiration)
	}

	start := time.Now()
	_, err := pipe.Exec(ctx)
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("mset", duration, err == nil)

	if err != nil {
		return fmt.Errorf("cache mset failed: %w", err)
	}

	return nil
}

// Hash operations

// HGet gets a field from a hash
func (rc *RedisCache) HGet(ctx context.Context, key, field string) ([]byte, error) {
	fullKey := rc.buildKey(key)

	start := time.Now()
	result, err := rc.client.HGet(ctx, fullKey, field).Bytes()
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("hget", duration, err == nil)

	if err == redis.Nil {
		return nil, ErrCacheMiss
	}

	if err != nil {
		return nil, fmt.Errorf("cache hget failed: %w", err)
	}

	return result, nil
}

// HSet sets a field in a hash
func (rc *RedisCache) HSet(ctx context.Context, key, field string, value interface{}) error {
	fullKey := rc.buildKey(key)

	data, err := rc.serialize(value)
	if err != nil {
		return fmt.Errorf("failed to serialize value: %w", err)
	}

	start := time.Now()
	err = rc.client.HSet(ctx, fullKey, field, data).Err()
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("hset", duration, err == nil)

	if err != nil {
		return fmt.Errorf("cache hset failed: %w", err)
	}

	return nil
}

// HGetAll gets all fields from a hash
func (rc *RedisCache) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	fullKey := rc.buildKey(key)

	start := time.Now()
	result, err := rc.client.HGetAll(ctx, fullKey).Result()
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("hgetall", duration, err == nil)

	if err != nil {
		return nil, fmt.Errorf("cache hgetall failed: %w", err)
	}

	return result, nil
}

// List operations

// LPush pushes values to the left of a list
func (rc *RedisCache) LPush(ctx context.Context, key string, values ...interface{}) error {
	fullKey := rc.buildKey(key)

	start := time.Now()
	err := rc.client.LPush(ctx, fullKey, values...).Err()
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("lpush", duration, err == nil)

	if err != nil {
		return fmt.Errorf("cache lpush failed: %w", err)
	}

	return nil
}

// RPop pops a value from the right of a list
func (rc *RedisCache) RPop(ctx context.Context, key string) ([]byte, error) {
	fullKey := rc.buildKey(key)

	start := time.Now()
	result, err := rc.client.RPop(ctx, fullKey).Bytes()
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("rpop", duration, err == nil)

	if err == redis.Nil {
		return nil, ErrCacheMiss
	}

	if err != nil {
		return nil, fmt.Errorf("cache rpop failed: %w", err)
	}

	return result, nil
}

// LRange gets a range of values from a list
func (rc *RedisCache) LRange(ctx context.Context, key string, start, stop int64) ([]string, error) {
	fullKey := rc.buildKey(key)

	startTime := time.Now()
	result, err := rc.client.LRange(ctx, fullKey, start, stop).Result()
	duration := time.Since(startTime)

	// Record metrics
	rc.recordOperation("lrange", duration, err == nil)

	if err != nil {
		return nil, fmt.Errorf("cache lrange failed: %w", err)
	}

	return result, nil
}

// Set operations

// SAdd adds members to a set
func (rc *RedisCache) SAdd(ctx context.Context, key string, members ...interface{}) error {
	fullKey := rc.buildKey(key)

	start := time.Now()
	err := rc.client.SAdd(ctx, fullKey, members...).Err()
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("sadd", duration, err == nil)

	if err != nil {
		return fmt.Errorf("cache sadd failed: %w", err)
	}

	return nil
}

// SMembers gets all members of a set
func (rc *RedisCache) SMembers(ctx context.Context, key string) ([]string, error) {
	fullKey := rc.buildKey(key)

	start := time.Now()
	result, err := rc.client.SMembers(ctx, fullKey).Result()
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("smembers", duration, err == nil)

	if err != nil {
		return nil, fmt.Errorf("cache smembers failed: %w", err)
	}

	return result, nil
}

// SIsMember checks if a value is a member of a set
func (rc *RedisCache) SIsMember(ctx context.Context, key string, member interface{}) (bool, error) {
	fullKey := rc.buildKey(key)

	start := time.Now()
	result, err := rc.client.SIsMember(ctx, fullKey, member).Result()
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("sismember", duration, err == nil)

	if err != nil {
		return false, fmt.Errorf("cache sismember failed: %w", err)
	}

	return result, nil
}

// Utility methods

// Ping tests the connection to Redis
func (rc *RedisCache) Ping(ctx context.Context) error {
	start := time.Now()
	err := rc.client.Ping(ctx).Err()
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("ping", duration, err == nil)

	if err != nil {
		return fmt.Errorf("cache ping failed: %w", err)
	}

	return nil
}

// Info returns Redis server information
func (rc *RedisCache) Info(ctx context.Context) (map[string]interface{}, error) {
	start := time.Now()
	info, err := rc.client.Info(ctx).Result()
	duration := time.Since(start)

	// Record metrics
	rc.recordOperation("info", duration, err == nil)

	if err != nil {
		return nil, fmt.Errorf("cache info failed: %w", err)
	}

	// Parse info string into map
	result := make(map[string]interface{})
	lines := strings.Split(info, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	return result, nil
}

// Stats returns cache performance statistics
func (rc *RedisCache) Stats() CacheStats {
	rc.stats.LastUpdate = time.Now()

	// Calculate hit ratio
	total := rc.stats.Hits + rc.stats.Misses
	if total > 0 {
		rc.stats.HitRatio = float64(rc.stats.Hits) / float64(total)
	}

	// Get current key count
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if dbSize, err := rc.client.DBSize(ctx).Result(); err == nil {
		rc.stats.Keys = dbSize
	}

	// Get memory info
	if info, err := rc.Info(ctx); err == nil {
		rc.stats.Memory = info
	}

	return rc.stats
}

// Helper methods

// buildKey creates a full key with prefix
func (rc *RedisCache) buildKey(key string) string {
	return fmt.Sprintf("%s:%s", rc.keyPrefix, key)
}

// serialize converts a value to bytes for storage
func (rc *RedisCache) serialize(value interface{}) ([]byte, error) {
	switch v := value.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, bool:
		return json.Marshal(v)
	default:
		return json.Marshal(v)
	}
}

// recordOperation records metrics for cache operations
func (rc *RedisCache) recordOperation(operation string, duration time.Duration, success bool) {
	if rc.obs == nil {
		return
	}

	// TODO: Implement proper metrics recording using OpenTelemetry
	// For now, just log the operation for observability
	rc.obs.Logger.Debug().
		Str("operation", operation).
		Bool("success", success).
		Dur("duration", duration).
		Msg("Cache operation completed")
}

// Error definitions
var (
	ErrCacheMiss = fmt.Errorf("cache miss")
)
