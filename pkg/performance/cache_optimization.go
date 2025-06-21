package performance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"mvp.local/pkg/common/errors"
)

// CacheOptimizer provides performance optimizations for caching operations
type CacheOptimizer struct {
	redisClient *redis.Client
	logger      zerolog.Logger
}

// NewCacheOptimizer creates a new cache optimizer
func NewCacheOptimizer(redisClient *redis.Client, logger zerolog.Logger) *CacheOptimizer {
	return &CacheOptimizer{
		redisClient: redisClient,
		logger:      logger,
	}
}

// CacheOptions defines caching behavior options
type CacheOptions struct {
	TTL                  time.Duration
	Namespace            string
	UseCompression       bool
	StaleWhileRevalidate time.Duration
}

// DefaultCacheOptions returns sensible defaults for caching
func DefaultCacheOptions() CacheOptions {
	return CacheOptions{
		TTL:                  5 * time.Minute,
		Namespace:            "zamaz",
		UseCompression:       true,
		StaleWhileRevalidate: 30 * time.Second,
	}
}

// GetWithFallback retrieves data from cache with fallback to data source
func (c *CacheOptimizer) GetWithFallback(
	ctx context.Context,
	key string,
	options CacheOptions,
	fallback func() (interface{}, error),
) (interface{}, error) {
	// Build namespaced key
	namespacedKey := c.buildKey(options.Namespace, key)

	// Try to get from cache first
	cached, err := c.redisClient.Get(ctx, namespacedKey).Result()
	if err == nil {
		// Cache hit - deserialize and return
		var data interface{}
		if err := json.Unmarshal([]byte(cached), &data); err != nil {
			c.logger.Warn().Err(err).Str("key", namespacedKey).Msg("Cache deserialization failed")
		} else {
			c.logger.Debug().Str("key", namespacedKey).Msg("Cache hit")
			return data, nil
		}
	} else if err != redis.Nil {
		// Cache error (not miss)
		c.logger.Error().Err(err).Str("key", namespacedKey).Msg("Cache get error")
	}

	// Cache miss or error - call fallback
	c.logger.Debug().Str("key", namespacedKey).Msg("Cache miss - calling fallback")
	data, err := fallback()
	if err != nil {
		return nil, errors.NewExternalError("data_source", 0, err)
	}

	// Cache the result asynchronously to avoid blocking
	go c.setAsync(ctx, namespacedKey, data, options.TTL)

	return data, nil
}

// setAsync sets cache value asynchronously
func (c *CacheOptimizer) setAsync(ctx context.Context, key string, data interface{}, ttl time.Duration) {
	// Serialize data
	serialized, err := json.Marshal(data)
	if err != nil {
		c.logger.Error().Err(err).Str("key", key).Msg("Cache serialization failed")
		return
	}

	// Set in cache
	if err := c.redisClient.Set(ctx, key, serialized, ttl).Err(); err != nil {
		c.logger.Error().Err(err).Str("key", key).Msg("Cache set failed")
	} else {
		c.logger.Debug().Str("key", key).Dur("ttl", ttl).Msg("Cache set success")
	}
}

// InvalidatePattern invalidates cache entries matching a pattern
func (c *CacheOptimizer) InvalidatePattern(ctx context.Context, namespace, pattern string) error {
	fullPattern := c.buildKey(namespace, pattern)

	// Use SCAN instead of KEYS for better performance
	iter := c.redisClient.Scan(ctx, 0, fullPattern, 0).Iterator()
	keys := make([]string, 0)

	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}

	if err := iter.Err(); err != nil {
		return errors.NewExternalError("redis", 0, err)
	}

	if len(keys) > 0 {
		// Delete in batches to avoid blocking
		const batchSize = 100
		for i := 0; i < len(keys); i += batchSize {
			end := i + batchSize
			if end > len(keys) {
				end = len(keys)
			}

			batch := keys[i:end]
			if err := c.redisClient.Del(ctx, batch...).Err(); err != nil {
				c.logger.Error().Err(err).Int("batch_size", len(batch)).Msg("Cache batch delete failed")
			} else {
				c.logger.Debug().Int("deleted", len(batch)).Msg("Cache batch deleted")
			}
		}
	}

	return nil
}

// WarmupCache pre-loads frequently accessed data into cache
func (c *CacheOptimizer) WarmupCache(ctx context.Context, warmupFunctions map[string]func() (interface{}, error)) error {
	c.logger.Info().Int("functions", len(warmupFunctions)).Msg("Starting cache warmup")

	options := DefaultCacheOptions()
	options.TTL = 30 * time.Minute // Longer TTL for warmup data

	for key, fn := range warmupFunctions {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			_, err := c.GetWithFallback(ctx, key, options, fn)
			if err != nil {
				c.logger.Error().Err(err).Str("key", key).Msg("Cache warmup failed for key")
				// Continue with other keys
			}
		}
	}

	c.logger.Info().Msg("Cache warmup completed")
	return nil
}

// GetCacheStats returns cache performance statistics
func (c *CacheOptimizer) GetCacheStats(ctx context.Context) (map[string]interface{}, error) {
	info, err := c.redisClient.Info(ctx, "stats").Result()
	if err != nil {
		return nil, errors.NewExternalError("redis", 0, err)
	}

	// Parse Redis INFO output
	stats := make(map[string]interface{})
	// Add basic parsing of Redis stats here
	stats["raw_info"] = info

	// Add custom metrics
	dbSize, err := c.redisClient.DBSize(ctx).Result()
	if err == nil {
		stats["total_keys"] = dbSize
	}

	return stats, nil
}

// buildKey creates a namespaced cache key
func (c *CacheOptimizer) buildKey(namespace, key string) string {
	return fmt.Sprintf("%s:%s", namespace, key)
}

// CleanupExpiredKeys performs cleanup of expired keys (called periodically)
func (c *CacheOptimizer) CleanupExpiredKeys(ctx context.Context, namespace string) error {
	pattern := c.buildKey(namespace, "*")

	// Use SCAN to iterate through keys
	iter := c.redisClient.Scan(ctx, 0, pattern, 100).Iterator()
	expiredCount := 0

	for iter.Next(ctx) {
		key := iter.Val()

		// Check TTL
		ttl, err := c.redisClient.TTL(ctx, key).Result()
		if err != nil {
			continue
		}

		// If TTL is very short (< 1 second), consider for immediate cleanup
		if ttl < time.Second && ttl > 0 {
			c.redisClient.Del(ctx, key)
			expiredCount++
		}
	}

	if expiredCount > 0 {
		c.logger.Debug().Int("expired_keys", expiredCount).Msg("Cleaned up expired cache keys")
	}

	return iter.Err()
}
