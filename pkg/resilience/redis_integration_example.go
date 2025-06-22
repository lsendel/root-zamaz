package resilience

import (
	"context"
	"fmt"
	"time"
	
	"github.com/go-redis/redis/v8"
	"mvp.local/pkg/config"
	"mvp.local/pkg/observability"
)

// Example of how to integrate Redis with health checking and circuit breaker

// CreateHealthCheckedRedisClient creates a Redis client with health checking and circuit breaker
func CreateHealthCheckedRedisClient(cfg *config.RedisConfig, obs *observability.Observability) (*HealthCheckedRedisClient, error) {
	// Create standard Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:         cfg.RedisAddr(),
		Password:     cfg.Password,
		DB:           cfg.Database,
		PoolSize:     cfg.PoolSize,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		
		// Connection pool settings for better resilience
		MinIdleConns:    cfg.PoolSize / 4,
		MaxRetries:      3,
		MinRetryBackoff: 8 * time.Millisecond,
		MaxRetryBackoff: 512 * time.Millisecond,
		
		// Connection lifecycle
		MaxConnAge:  30 * time.Minute,
		PoolTimeout: cfg.ReadTimeout + time.Second,
		IdleTimeout: 5 * time.Minute,
		
		// Hooks for monitoring
		OnConnect: func(ctx context.Context, cn *redis.Conn) error {
			if obs != nil {
				obs.Logger.Debug().
					Str("addr", cn.String()).
					Msg("Redis connection established")
			}
			return nil
		},
	})
	
	// Test initial connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := redisClient.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}
	
	// Configure health checking
	healthConfig := RedisHealthConfig{
		HealthCheckInterval: 10 * time.Second,
		CircuitBreakerConfig: CircuitBreakerConfig{
			MaxFailures:      3,
			ResetTimeout:     30 * time.Second,
			HalfOpenMaxCalls: 3,
			SuccessThreshold: 2,
		},
		EnableAutoRecovery: true,
	}
	
	// Wrap with health checking
	healthCheckedClient := WrapRedisClient(redisClient, healthConfig, obs)
	
	if obs != nil {
		obs.Logger.Info().
			Str("addr", cfg.RedisAddr()).
			Int("pool_size", cfg.PoolSize).
			Bool("health_check_enabled", true).
			Msg("Redis client initialized with health checking")
	}
	
	return healthCheckedClient, nil
}

// Example usage in main.go:
/*
func setupRedis(cfg *config.Config, obs *observability.Observability) (*resilience.HealthCheckedRedisClient, error) {
	if cfg.Redis.Host == "" {
		obs.Logger.Info().Msg("Redis not configured, skipping initialization")
		return nil, nil
	}
	
	redisClient, err := resilience.CreateHealthCheckedRedisClient(&cfg.Redis, obs)
	if err != nil {
		obs.Logger.Warn().
			Err(err).
			Msg("Failed to initialize Redis, continuing without caching")
		return nil, nil
	}
	
	// Register health check endpoint
	http.HandleFunc("/health/redis", func(w http.ResponseWriter, r *http.Request) {
		status := redisClient.HealthStatus()
		
		if redisClient.IsHealthy() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		
		json.NewEncoder(w).Encode(status)
	})
	
	return redisClient, nil
}

// Using the health-checked client:
func someService(redisClient *resilience.HealthCheckedRedisClient) {
	ctx := context.Background()
	
	// Set operation - automatically protected by circuit breaker
	err := redisClient.Set(ctx, "key", "value", time.Hour).Err()
	if err != nil {
		if errors.Is(err, resilience.ErrServiceUnavailable) {
			// Redis is down, use fallback logic
			log.Warn("Redis unavailable, using in-memory cache")
			return
		}
		// Handle other errors
	}
	
	// Get operation - automatically protected by circuit breaker
	val, err := redisClient.Get(ctx, "key").Result()
	if err == redis.Nil {
		// Key doesn't exist
	} else if err != nil {
		// Handle error (circuit breaker will handle Redis failures)
	}
}
*/

// RedisMetricsCollector collects metrics from health-checked Redis clients
type RedisMetricsCollector struct {
	clients map[string]*HealthCheckedRedisClient
}

// NewRedisMetricsCollector creates a new metrics collector
func NewRedisMetricsCollector() *RedisMetricsCollector {
	return &RedisMetricsCollector{
		clients: make(map[string]*HealthCheckedRedisClient),
	}
}

// Register registers a Redis client for metrics collection
func (c *RedisMetricsCollector) Register(name string, client *HealthCheckedRedisClient) {
	c.clients[name] = client
}

// CollectMetrics collects metrics from all registered clients
func (c *RedisMetricsCollector) CollectMetrics() map[string]interface{} {
	metrics := make(map[string]interface{})
	
	for name, client := range c.clients {
		metrics[name] = client.HealthStatus()
	}
	
	return metrics
}