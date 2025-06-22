package security

import (
	"context"
	"sync"
	"time"
	
	"mvp.local/pkg/cache"
	"mvp.local/pkg/errors"
	"mvp.local/pkg/observability"
)

// ReplayProtector provides protection against replay attacks with automatic TTL-based cleanup
type ReplayProtector struct {
	cache        cache.Cache
	replayWindow time.Duration
	obs          *observability.Observability
	
	// In-memory fallback with automatic cleanup
	mu           sync.RWMutex
	seen         map[string]time.Time
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
	
	// Metrics
	metrics struct {
		cacheHits     uint64
		cacheMisses   uint64
		memoryHits    uint64
		memoryMisses  uint64
		cleanupRuns   uint64
		itemsCleaned  uint64
	}
}

// NewReplayProtector creates a new replay protector with automatic cleanup
func NewReplayProtector(cache cache.Cache, replayWindow time.Duration, obs *observability.Observability) *ReplayProtector {
	rp := &ReplayProtector{
		cache:        cache,
		replayWindow: replayWindow,
		obs:          obs,
		seen:         make(map[string]time.Time),
		stopCleanup:  make(chan struct{}),
	}
	
	// Start automatic cleanup for in-memory cache
	rp.startCleanupRoutine()
	
	return rp
}

// CheckAndStore checks if a key has been seen within the replay window and stores it if not
func (rp *ReplayProtector) CheckAndStore(ctx context.Context, key string) error {
	if rp.replayWindow <= 0 {
		return nil // Replay protection disabled
	}
	
	// Try cache-based protection first
	if rp.cache != nil {
		exists, err := rp.checkCacheReplay(ctx, key)
		if err == nil {
			if exists {
				rp.metrics.cacheHits++
				return errors.Authentication("replay attack detected")
			}
			rp.metrics.cacheMisses++
			return nil
		}
		// Fall through to in-memory protection if cache fails
		rp.logCacheError(err)
	}
	
	// Use in-memory protection as fallback
	return rp.checkMemoryReplay(key)
}

// checkCacheReplay checks and stores in distributed cache
func (rp *ReplayProtector) checkCacheReplay(ctx context.Context, key string) (bool, error) {
	cacheKey := ReplayCachePrefix + key
	
	// Check existence
	exists, err := rp.cache.Exists(ctx, cacheKey)
	if err != nil {
		return false, err
	}
	
	if exists {
		return true, nil
	}
	
	// Store with TTL
	err = rp.cache.Set(ctx, cacheKey, []byte("1"), rp.replayWindow)
	if err != nil {
		return false, err
	}
	
	return false, nil
}

// checkMemoryReplay checks and stores in memory with manual cleanup
func (rp *ReplayProtector) checkMemoryReplay(key string) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	
	now := time.Now()
	
	// Check if key exists and is still within replay window
	if timestamp, found := rp.seen[key]; found {
		if now.Sub(timestamp) < rp.replayWindow {
			rp.metrics.memoryHits++
			return errors.Authentication("replay attack detected")
		}
		// Key expired, will be cleaned up by routine
	}
	
	// Store new key
	rp.seen[key] = now
	rp.metrics.memoryMisses++
	
	return nil
}

// startCleanupRoutine starts the automatic cleanup routine for in-memory cache
func (rp *ReplayProtector) startCleanupRoutine() {
	// Run cleanup every minute or replay window / 10, whichever is smaller
	cleanupInterval := time.Minute
	if rp.replayWindow/10 < cleanupInterval {
		cleanupInterval = rp.replayWindow / 10
	}
	
	rp.cleanupTicker = time.NewTicker(cleanupInterval)
	
	go func() {
		for {
			select {
			case <-rp.cleanupTicker.C:
				rp.cleanupExpiredEntries()
			case <-rp.stopCleanup:
				rp.cleanupTicker.Stop()
				return
			}
		}
	}()
}

// cleanupExpiredEntries removes expired entries from in-memory cache
func (rp *ReplayProtector) cleanupExpiredEntries() {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	
	now := time.Now()
	expired := 0
	
	for key, timestamp := range rp.seen {
		if now.Sub(timestamp) > rp.replayWindow {
			delete(rp.seen, key)
			expired++
		}
	}
	
	rp.metrics.cleanupRuns++
	rp.metrics.itemsCleaned += uint64(expired)
	
	if rp.obs != nil && expired > 0 {
		rp.obs.Logger.Debug().
			Int("expired_entries", expired).
			Int("remaining_entries", len(rp.seen)).
			Msg("Cleaned up expired replay protection entries")
	}
}

// Stop stops the replay protector and cleans up resources
func (rp *ReplayProtector) Stop() {
	close(rp.stopCleanup)
	
	// Clear all entries
	rp.mu.Lock()
	rp.seen = make(map[string]time.Time)
	rp.mu.Unlock()
}

// GetMetrics returns current metrics
func (rp *ReplayProtector) GetMetrics() map[string]interface{} {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	
	return map[string]interface{}{
		"cache_hits":      rp.metrics.cacheHits,
		"cache_misses":    rp.metrics.cacheMisses,
		"memory_hits":     rp.metrics.memoryHits,
		"memory_misses":   rp.metrics.memoryMisses,
		"cleanup_runs":    rp.metrics.cleanupRuns,
		"items_cleaned":   rp.metrics.itemsCleaned,
		"memory_entries":  len(rp.seen),
		"replay_window":   rp.replayWindow.String(),
		"cache_available": rp.cache != nil,
	}
}

// ClearAll clears all replay protection entries
func (rp *ReplayProtector) ClearAll(ctx context.Context) error {
	// Clear cache entries
	if rp.cache != nil {
		pattern := ReplayCachePrefix + "*"
		if keys, err := rp.cache.Keys(ctx, pattern); err == nil {
			for _, key := range keys {
				_ = rp.cache.Delete(ctx, key)
			}
		}
	}
	
	// Clear memory entries
	rp.mu.Lock()
	rp.seen = make(map[string]time.Time)
	rp.mu.Unlock()
	
	return nil
}

// logCacheError logs cache errors for monitoring
func (rp *ReplayProtector) logCacheError(err error) {
	if rp.obs != nil {
		rp.obs.Logger.Warn().
			Err(err).
			Msg("Cache error in replay protection, falling back to memory")
	}
}