package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/allegro/bigcache/v3"
	"github.com/redis/go-redis/v9"
)

// CacheConfig holds configuration for CacheLayer
// TTL is the expiration duration for cached entries.
// MaxSize sets the maximum in-memory cache size in MB.
// EvictionPolicy is reserved for future use.
type CacheConfig struct {
	TTL            time.Duration
	MaxSize        int64
	EvictionPolicy string
}

// CacheLayer combines in-memory caching with Redis for persistence.
type CacheLayer struct {
	Redis    *redis.Client
	InMemory *bigcache.BigCache
	Config   CacheConfig
}

// NewCacheLayer creates a new CacheLayer instance.
func NewCacheLayer(client *redis.Client, cfg CacheConfig) (*CacheLayer, error) {
	if cfg.TTL == 0 {
		cfg.TTL = time.Hour
	}

	bcConfig := bigcache.DefaultConfig(cfg.TTL)
	if cfg.MaxSize > 0 {
		bcConfig.HardMaxCacheSize = int(cfg.MaxSize)
	}

	bc, err := bigcache.NewBigCache(bcConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create bigcache: %w", err)
	}

	return &CacheLayer{
		Redis:    client,
		InMemory: bc,
		Config:   cfg,
	}, nil
}

// Get retrieves a value from cache.
func (cl *CacheLayer) Get(ctx context.Context, key string) ([]byte, error) {
	if cl.InMemory != nil {
		if data, err := cl.InMemory.Get(key); err == nil {
			return data, nil
		}
	}

	if cl.Redis == nil {
		return nil, fmt.Errorf("cache miss")
	}

	data, err := cl.Redis.Get(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	if cl.InMemory != nil {
		_ = cl.InMemory.Set(key, data)
	}
	return data, nil
}

// Set stores a value in cache and Redis.
func (cl *CacheLayer) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	// Convert value to bytes
	var data []byte
	switch v := value.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("unsupported value type: %T", value)
	}

	// Use provided expiration or fall back to config TTL
	ttl := expiration
	if ttl == 0 {
		ttl = cl.Config.TTL
	}
	if cl.InMemory != nil {
		if err := cl.InMemory.Set(key, data); err != nil {
			return err
		}
	}

	if cl.Redis != nil {
		return cl.Redis.Set(ctx, key, data, ttl).Err()
	}
	return nil
}

// Delete removes a key from cache and Redis.
func (cl *CacheLayer) Delete(ctx context.Context, key string) error {
	if cl.InMemory != nil {
		cl.InMemory.Delete(key)
	}
	if cl.Redis != nil {
		return cl.Redis.Del(ctx, key).Err()
	}
	return nil
}

// Exists checks if a key exists in cache or Redis.
func (cl *CacheLayer) Exists(ctx context.Context, key string) (bool, error) {
	// Check in-memory cache first
	if cl.InMemory != nil {
		if _, err := cl.InMemory.Get(key); err == nil {
			return true, nil
		}
	}

	// Check Redis
	if cl.Redis != nil {
		exists, err := cl.Redis.Exists(ctx, key).Result()
		return exists > 0, err
	}

	return false, nil
}

// Stub implementations for Cache interface compliance
// These methods delegate to Redis when available

func (cl *CacheLayer) Keys(ctx context.Context, pattern string) ([]string, error) {
	if cl.Redis != nil {
		return cl.Redis.Keys(ctx, pattern).Result()
	}
	return []string{}, nil
}

func (cl *CacheLayer) FlushAll(ctx context.Context) error {
	if cl.InMemory != nil {
		cl.InMemory.Reset()
	}
	if cl.Redis != nil {
		return cl.Redis.FlushAll(ctx).Err()
	}
	return nil
}

func (cl *CacheLayer) TTL(ctx context.Context, key string) (time.Duration, error) {
	if cl.Redis != nil {
		return cl.Redis.TTL(ctx, key).Result()
	}
	return 0, nil
}

func (cl *CacheLayer) MGet(ctx context.Context, keys []string) (map[string][]byte, error) {
	result := make(map[string][]byte)
	if cl.Redis != nil {
		vals, err := cl.Redis.MGet(ctx, keys...).Result()
		if err != nil {
			return nil, err
		}
		for i, val := range vals {
			if val != nil {
				if str, ok := val.(string); ok {
					result[keys[i]] = []byte(str)
				}
			}
		}
	}
	return result, nil
}

func (cl *CacheLayer) MSet(ctx context.Context, pairs map[string]interface{}, expiration time.Duration) error {
	if cl.Redis != nil {
		pipe := cl.Redis.Pipeline()
		for key, value := range pairs {
			pipe.Set(ctx, key, value, expiration)
		}
		_, err := pipe.Exec(ctx)
		return err
	}
	return nil
}

func (cl *CacheLayer) HGet(ctx context.Context, key, field string) ([]byte, error) {
	if cl.Redis != nil {
		val, err := cl.Redis.HGet(ctx, key, field).Result()
		return []byte(val), err
	}
	return nil, fmt.Errorf("Redis not available")
}

func (cl *CacheLayer) HSet(ctx context.Context, key, field string, value interface{}) error {
	if cl.Redis != nil {
		return cl.Redis.HSet(ctx, key, field, value).Err()
	}
	return nil
}

func (cl *CacheLayer) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	if cl.Redis != nil {
		return cl.Redis.HGetAll(ctx, key).Result()
	}
	return make(map[string]string), nil
}

func (cl *CacheLayer) LPush(ctx context.Context, key string, values ...interface{}) error {
	if cl.Redis != nil {
		return cl.Redis.LPush(ctx, key, values...).Err()
	}
	return nil
}

func (cl *CacheLayer) RPop(ctx context.Context, key string) ([]byte, error) {
	if cl.Redis != nil {
		val, err := cl.Redis.RPop(ctx, key).Result()
		return []byte(val), err
	}
	return nil, fmt.Errorf("Redis not available")
}

func (cl *CacheLayer) LRange(ctx context.Context, key string, start, stop int64) ([]string, error) {
	if cl.Redis != nil {
		return cl.Redis.LRange(ctx, key, start, stop).Result()
	}
	return []string{}, nil
}

func (cl *CacheLayer) SAdd(ctx context.Context, key string, members ...interface{}) error {
	if cl.Redis != nil {
		return cl.Redis.SAdd(ctx, key, members...).Err()
	}
	return nil
}

func (cl *CacheLayer) SMembers(ctx context.Context, key string) ([]string, error) {
	if cl.Redis != nil {
		return cl.Redis.SMembers(ctx, key).Result()
	}
	return []string{}, nil
}

func (cl *CacheLayer) SIsMember(ctx context.Context, key string, member interface{}) (bool, error) {
	if cl.Redis != nil {
		return cl.Redis.SIsMember(ctx, key, member).Result()
	}
	return false, nil
}

func (cl *CacheLayer) Ping(ctx context.Context) error {
	if cl.Redis != nil {
		return cl.Redis.Ping(ctx).Err()
	}
	return nil
}

func (cl *CacheLayer) Info(ctx context.Context) (map[string]interface{}, error) {
	info := make(map[string]interface{})
	if cl.Redis != nil {
		redisInfo, err := cl.Redis.Info(ctx).Result()
		if err != nil {
			return nil, err
		}
		info["redis"] = redisInfo
	}
	if cl.InMemory != nil {
		info["bigcache_stats"] = cl.InMemory.Stats()
	}
	return info, nil
}

func (cl *CacheLayer) Stats() CacheStats {
	stats := CacheStats{}
	if cl.InMemory != nil {
		bcStats := cl.InMemory.Stats()
		stats.Hits = bcStats.Hits
		stats.Misses = bcStats.Misses
	}
	return stats
}
