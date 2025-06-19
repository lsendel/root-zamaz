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
func (cl *CacheLayer) Set(ctx context.Context, key string, value []byte) error {
	if cl.InMemory != nil {
		if err := cl.InMemory.Set(key, value); err != nil {
			return err
		}
	}

	if cl.Redis != nil {
		return cl.Redis.Set(ctx, key, value, cl.Config.TTL).Err()
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
