// Package client provides caching implementations for the Keycloak Zero Trust library
package client

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// Memory Cache Implementation

// newMemoryCache creates a new in-memory cache
func newMemoryCache(maxSize int) Cache {
	return &memoryCache{
		data:    make(map[string]cacheItem),
		maxSize: maxSize,
	}
}

// Get retrieves a value from memory cache
func (m *memoryCache) Get(ctx context.Context, key string) (string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	item, exists := m.data[key]
	if !exists {
		return "", nil // Key not found
	}

	// Check if expired
	if time.Now().After(item.expiresAt) {
		// Remove expired item
		delete(m.data, key)
		return "", nil
	}

	return item.value, nil
}

// Set stores a value in memory cache
func (m *memoryCache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check cache size limit
	if len(m.data) >= m.maxSize {
		// Simple LRU: remove oldest entries
		m.evictOldest()
	}

	m.data[key] = cacheItem{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}

	return nil
}

// Delete removes a value from memory cache
func (m *memoryCache) Delete(ctx context.Context, key string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.data, key)
	return nil
}

// Close cleans up the memory cache
func (m *memoryCache) Close() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Clear all data
	for k := range m.data {
		delete(m.data, k)
	}

	return nil
}

// evictOldest removes the oldest entries when cache is full
func (m *memoryCache) evictOldest() {
	if len(m.data) == 0 {
		return
	}

	// Find and remove expired items first
	now := time.Now()
	expiredKeys := make([]string, 0)
	for key, item := range m.data {
		if now.After(item.expiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	// Remove expired items
	for _, key := range expiredKeys {
		delete(m.data, key)
	}

	// If still at capacity, remove some items (simple eviction)
	if len(m.data) >= m.maxSize {
		removeCount := m.maxSize / 4 // Remove 25% of items
		count := 0
		for key := range m.data {
			if count >= removeCount {
				break
			}
			delete(m.data, key)
			count++
		}
	}
}

// Redis Cache Implementation

// newRedisCache creates a new Redis cache
func newRedisCache(redisURL, prefix string) (Cache, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}

	client := redis.NewClient(opt)
	
	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &redisCache{
		client: client,
		prefix: prefix,
	}, nil
}

// Get retrieves a value from Redis cache
func (r *redisCache) Get(ctx context.Context, key string) (string, error) {
	fullKey := r.getFullKey(key)
	value, err := r.client.Get(ctx, fullKey).Result()
	if err != nil {
		if err == redis.Nil {
			return "", nil // Key not found
		}
		return "", err
	}
	return value, nil
}

// Set stores a value in Redis cache
func (r *redisCache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	fullKey := r.getFullKey(key)
	return r.client.Set(ctx, fullKey, value, ttl).Err()
}

// Delete removes a value from Redis cache
func (r *redisCache) Delete(ctx context.Context, key string) error {
	fullKey := r.getFullKey(key)
	return r.client.Del(ctx, fullKey).Err()
}

// Close closes the Redis connection
func (r *redisCache) Close() error {
	return r.client.Close()
}

// getFullKey returns the full cache key with prefix
func (r *redisCache) getFullKey(key string) string {
	if r.prefix == "" {
		return key
	}
	return r.prefix + ":" + key
}