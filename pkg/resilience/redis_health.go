package resilience

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	
	"github.com/go-redis/redis/v8"
	"mvp.local/pkg/errors"
	"mvp.local/pkg/observability"
)

// RedisHealthChecker provides health checking and circuit breaking for Redis
type RedisHealthChecker struct {
	client          *redis.Client
	obs             *observability.Observability
	circuitBreaker  *CircuitBreaker
	healthCheckInterval time.Duration
	
	// Health status
	healthy         atomic.Bool
	lastHealthCheck time.Time
	mu              sync.RWMutex
	
	// Metrics
	metrics struct {
		healthChecks      uint64
		healthChecksFailed uint64
		circuitOpens      uint64
		reconnectAttempts uint64
	}
	
	// Control
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// RedisHealthConfig contains configuration for Redis health checking
type RedisHealthConfig struct {
	HealthCheckInterval time.Duration
	CircuitBreakerConfig CircuitBreakerConfig
	EnableAutoRecovery  bool
}

// DefaultRedisHealthConfig returns sensible defaults
func DefaultRedisHealthConfig() RedisHealthConfig {
	return RedisHealthConfig{
		HealthCheckInterval: 10 * time.Second,
		CircuitBreakerConfig: CircuitBreakerConfig{
			MaxFailures:      3,
			ResetTimeout:     30 * time.Second,
			HalfOpenMaxCalls: 3,
		},
		EnableAutoRecovery: true,
	}
}

// NewRedisHealthChecker creates a new Redis health checker
func NewRedisHealthChecker(client *redis.Client, config RedisHealthConfig, obs *observability.Observability) *RedisHealthChecker {
	rhc := &RedisHealthChecker{
		client:              client,
		obs:                 obs,
		healthCheckInterval: config.HealthCheckInterval,
		stopChan:           make(chan struct{}),
	}
	
	// Create circuit breaker
	rhc.circuitBreaker = NewCircuitBreaker(
		"redis",
		config.CircuitBreakerConfig,
		obs,
	)
	
	// Set initial health status
	rhc.checkHealthOnce(context.Background())
	
	// Start health check routine if auto-recovery is enabled
	if config.EnableAutoRecovery {
		rhc.startHealthCheckRoutine()
	}
	
	return rhc
}

// Execute wraps Redis operations with circuit breaker protection
func (rhc *RedisHealthChecker) Execute(ctx context.Context, operation func() error) error {
	// Quick health check
	if !rhc.IsHealthy() {
		return errors.ServiceUnavailable("Redis is currently unavailable")
	}
	
	// Execute with circuit breaker
	return rhc.circuitBreaker.Execute(ctx, func() error {
		// Set a reasonable timeout for Redis operations
		opCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		
		// Monitor operation context
		done := make(chan error, 1)
		go func() {
			done <- operation()
		}()
		
		select {
		case err := <-done:
			if err != nil {
				// Mark unhealthy on operation failure
				rhc.markUnhealthy(err)
			}
			return err
		case <-opCtx.Done():
			// Timeout - mark unhealthy
			rhc.markUnhealthy(opCtx.Err())
			return errors.Timeout("Redis operation timed out")
		}
	})
}

// IsHealthy returns the current health status
func (rhc *RedisHealthChecker) IsHealthy() bool {
	return rhc.healthy.Load()
}

// GetHealthStatus returns detailed health status
func (rhc *RedisHealthChecker) GetHealthStatus() map[string]interface{} {
	rhc.mu.RLock()
	defer rhc.mu.RUnlock()
	
	return map[string]interface{}{
		"healthy":            rhc.healthy.Load(),
		"last_health_check":  rhc.lastHealthCheck.Format(time.RFC3339),
		"circuit_state":      rhc.circuitBreaker.State().String(),
		"health_checks":      atomic.LoadUint64(&rhc.metrics.healthChecks),
		"health_checks_failed": atomic.LoadUint64(&rhc.metrics.healthChecksFailed),
		"circuit_opens":      atomic.LoadUint64(&rhc.metrics.circuitOpens),
		"reconnect_attempts": atomic.LoadUint64(&rhc.metrics.reconnectAttempts),
	}
}

// checkHealthOnce performs a single health check
func (rhc *RedisHealthChecker) checkHealthOnce(ctx context.Context) bool {
	atomic.AddUint64(&rhc.metrics.healthChecks, 1)
	
	// Perform ping with timeout
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	
	err := rhc.client.Ping(pingCtx).Err()
	
	rhc.mu.Lock()
	rhc.lastHealthCheck = time.Now()
	rhc.mu.Unlock()
	
	if err != nil {
		atomic.AddUint64(&rhc.metrics.healthChecksFailed, 1)
		rhc.markUnhealthy(err)
		return false
	}
	
	rhc.markHealthy()
	return true
}

// markHealthy marks Redis as healthy
func (rhc *RedisHealthChecker) markHealthy() {
	wasUnhealthy := !rhc.healthy.Swap(true)
	
	if wasUnhealthy && rhc.obs != nil {
		rhc.obs.Logger.Info().
			Msg("Redis connection restored")
	}
}

// markUnhealthy marks Redis as unhealthy
func (rhc *RedisHealthChecker) markUnhealthy(err error) {
	wasHealthy := rhc.healthy.Swap(false)
	
	if wasHealthy {
		atomic.AddUint64(&rhc.metrics.circuitOpens, 1)
		
		if rhc.obs != nil {
			rhc.obs.Logger.Error().
				Err(err).
				Msg("Redis connection lost")
		}
	}
}

// startHealthCheckRoutine starts the background health check routine
func (rhc *RedisHealthChecker) startHealthCheckRoutine() {
	rhc.wg.Add(1)
	go func() {
		defer rhc.wg.Done()
		
		ticker := time.NewTicker(rhc.healthCheckInterval)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				if !rhc.checkHealthOnce(context.Background()) {
					// If unhealthy, try reconnection
					rhc.attemptReconnection()
				}
			case <-rhc.stopChan:
				return
			}
		}
	}()
}

// attemptReconnection tries to reconnect to Redis
func (rhc *RedisHealthChecker) attemptReconnection() {
	atomic.AddUint64(&rhc.metrics.reconnectAttempts, 1)
	
	// Use exponential backoff for reconnection attempts
	backoff := time.Second
	maxBackoff := time.Minute
	
	for i := 0; i < 3; i++ {
		select {
		case <-rhc.stopChan:
			return
		case <-time.After(backoff):
			if rhc.checkHealthOnce(context.Background()) {
				if rhc.obs != nil {
					rhc.obs.Logger.Info().
						Int("attempt", i+1).
						Msg("Redis reconnection successful")
				}
				return
			}
			
			// Exponential backoff
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
	
	if rhc.obs != nil {
		rhc.obs.Logger.Error().
			Msg("Failed to reconnect to Redis after multiple attempts")
	}
}

// Stop stops the health checker
func (rhc *RedisHealthChecker) Stop() {
	close(rhc.stopChan)
	rhc.wg.Wait()
}

// WrapRedisClient wraps a Redis client with health checking and circuit breaking
func WrapRedisClient(client *redis.Client, config RedisHealthConfig, obs *observability.Observability) *HealthCheckedRedisClient {
	healthChecker := NewRedisHealthChecker(client, config, obs)
	
	return &HealthCheckedRedisClient{
		Client:        client,
		healthChecker: healthChecker,
	}
}

// HealthCheckedRedisClient wraps redis.Client with health checking
type HealthCheckedRedisClient struct {
	*redis.Client
	healthChecker *RedisHealthChecker
}

// Get wraps the Get command with health checking
func (c *HealthCheckedRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	cmd := redis.NewStringCmd(ctx)
	
	err := c.healthChecker.Execute(ctx, func() error {
		result := c.Client.Get(ctx, key)
		cmd = result
		return result.Err()
	})
	
	if err != nil && err != redis.Nil {
		cmd.SetErr(err)
	}
	
	return cmd
}

// Set wraps the Set command with health checking
func (c *HealthCheckedRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(ctx)
	
	err := c.healthChecker.Execute(ctx, func() error {
		result := c.Client.Set(ctx, key, value, expiration)
		cmd = result
		return result.Err()
	})
	
	if err != nil {
		cmd.SetErr(err)
	}
	
	return cmd
}

// HealthStatus returns the health status of the Redis connection
func (c *HealthCheckedRedisClient) HealthStatus() map[string]interface{} {
	return c.healthChecker.GetHealthStatus()
}

// IsHealthy returns whether Redis is healthy
func (c *HealthCheckedRedisClient) IsHealthy() bool {
	return c.healthChecker.IsHealthy()
}

// Stop stops the health checker
func (c *HealthCheckedRedisClient) Stop() {
	c.healthChecker.Stop()
}