// Package resilience provides circuit breaker management and monitoring.
package resilience

import (
	"context"
	"fmt"
	"sync"
	"time"

	"mvp.local/pkg/observability"
)

// CircuitBreakerManager manages multiple circuit breakers
type CircuitBreakerManager struct {
	breakers map[string]*CircuitBreaker
	mutex    sync.RWMutex
	obs      *observability.Observability
}

// NewCircuitBreakerManager creates a new circuit breaker manager
func NewCircuitBreakerManager(obs *observability.Observability) *CircuitBreakerManager {
	return &CircuitBreakerManager{
		breakers: make(map[string]*CircuitBreaker),
		obs:      obs,
	}
}

// GetOrCreate gets an existing circuit breaker or creates a new one
func (m *CircuitBreakerManager) GetOrCreate(name string, config ...CircuitBreakerConfig) *CircuitBreaker {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if cb, exists := m.breakers[name]; exists {
		return cb
	}

	// Create new circuit breaker with provided config or default
	var cfg CircuitBreakerConfig
	if len(config) > 0 {
		cfg = config[0]
	} else {
		cfg = DefaultCircuitBreakerConfig(name)
	}

	// Ensure name is set
	cfg.Name = name

	cb := NewCircuitBreaker(cfg, m.obs)
	m.breakers[name] = cb

	if m.obs != nil {
		m.obs.Logger.Info().
			Str("circuit_breaker", name).
			Int("max_failures", cfg.MaxFailures).
			Dur("timeout", cfg.Timeout).
			Int("max_requests", cfg.MaxRequests).
			Msg("Created new circuit breaker")
	}

	return cb
}

// Get retrieves a circuit breaker by name
func (m *CircuitBreakerManager) Get(name string) (*CircuitBreaker, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	cb, exists := m.breakers[name]
	return cb, exists
}

// Remove removes a circuit breaker
func (m *CircuitBreakerManager) Remove(name string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.breakers, name)

	if m.obs != nil {
		m.obs.Logger.Info().
			Str("circuit_breaker", name).
			Msg("Removed circuit breaker")
	}
}

// List returns all circuit breaker names
func (m *CircuitBreakerManager) List() []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	names := make([]string, 0, len(m.breakers))
	for name := range m.breakers {
		names = append(names, name)
	}

	return names
}

// GetAllMetrics returns metrics for all circuit breakers
func (m *CircuitBreakerManager) GetAllMetrics() map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	metrics := make(map[string]interface{})
	for name, cb := range m.breakers {
		metrics[name] = cb.GetMetrics()
	}

	return metrics
}

// ResetAll resets all circuit breakers
func (m *CircuitBreakerManager) ResetAll() {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, cb := range m.breakers {
		cb.Reset()
	}

	if m.obs != nil {
		m.obs.Logger.Info().Msg("Reset all circuit breakers")
	}
}

// ExecuteWithBreaker executes a function with circuit breaker protection
func (m *CircuitBreakerManager) ExecuteWithBreaker(
	ctx context.Context,
	breakerName string,
	fn func(ctx context.Context) error,
	config ...CircuitBreakerConfig,
) error {
	cb := m.GetOrCreate(breakerName, config...)
	return cb.Execute(ctx, fn)
}

// MonitorHealth starts a background goroutine to monitor circuit breaker health
func (m *CircuitBreakerManager) MonitorHealth(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.performHealthChecks(ctx)
		}
	}
}

// performHealthChecks runs readiness checks for circuit breakers that have them configured
func (m *CircuitBreakerManager) performHealthChecks(ctx context.Context) {
	m.mutex.RLock()
	breakers := make([]*CircuitBreaker, 0, len(m.breakers))
	for _, cb := range m.breakers {
		breakers = append(breakers, cb)
	}
	m.mutex.RUnlock()

	for _, cb := range breakers {
		if cb.config.ReadinessCheck != nil && cb.GetState() == StateOpen {
			m.checkBreakerHealth(ctx, cb)
		}
	}
}

// checkBreakerHealth performs a readiness check for a single circuit breaker
func (m *CircuitBreakerManager) checkBreakerHealth(ctx context.Context, cb *CircuitBreaker) {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := cb.config.ReadinessCheck(checkCtx)

	if err == nil && cb.GetState() == StateOpen {
		// Service appears to be healthy, move to half-open
		cb.mutex.Lock()
		if cb.state == StateOpen && time.Since(cb.lastFailTime) >= cb.config.Timeout {
			cb.setState(StateHalfOpen)
			cb.requests = 0
		}
		cb.mutex.Unlock()

		if m.obs != nil {
			m.obs.Logger.Info().
				Str("circuit_breaker", cb.config.Name).
				Msg("Readiness check passed, moving to half-open")
		}
	} else if err != nil {
		if m.obs != nil {
			m.obs.Logger.Debug().
				Str("circuit_breaker", cb.config.Name).
				Err(err).
				Msg("Readiness check failed")
		}
	}
}

// Predefined circuit breaker configurations for common services
var (
	// DatabaseConfig is optimized for database operations
	DatabaseConfig = CircuitBreakerConfig{
		MaxFailures:    3, // Fail fast for database issues
		Timeout:        10 * time.Second,
		MaxRequests:    2,   // Conservative testing
		ReadinessCheck: nil, // Will be set by database package
	}

	// CacheConfig is more tolerant since cache is often optional
	CacheConfig = CircuitBreakerConfig{
		MaxFailures:    5, // More tolerant of cache failures
		Timeout:        5 * time.Second,
		MaxRequests:    3,
		ReadinessCheck: nil, // Will be set by cache package
	}

	// MessagingConfig for NATS and other messaging systems
	MessagingConfig = CircuitBreakerConfig{
		MaxFailures:    4,
		Timeout:        15 * time.Second,
		MaxRequests:    2,
		ReadinessCheck: nil, // Will be set by messaging package
	}

	// ObservabilityConfig for tracing and metrics
	ObservabilityConfig = CircuitBreakerConfig{
		MaxFailures:    10, // Very tolerant - observability shouldn't break app
		Timeout:        30 * time.Second,
		MaxRequests:    5,
		ReadinessCheck: nil,
	}

	// ExternalAPIConfig for external HTTP services
	ExternalAPIConfig = CircuitBreakerConfig{
		MaxFailures:    3,
		Timeout:        20 * time.Second,
		MaxRequests:    2,
		ReadinessCheck: nil,
	}
)

// CreateDatabaseBreaker creates a circuit breaker optimized for database operations
func (m *CircuitBreakerManager) CreateDatabaseBreaker(name string, readinessCheck func(ctx context.Context) error) *CircuitBreaker {
	config := DatabaseConfig
	config.Name = name
	config.ReadinessCheck = readinessCheck

	return m.GetOrCreate(name, config)
}

// CreateCacheBreaker creates a circuit breaker optimized for cache operations
func (m *CircuitBreakerManager) CreateCacheBreaker(name string, readinessCheck func(ctx context.Context) error) *CircuitBreaker {
	config := CacheConfig
	config.Name = name
	config.ReadinessCheck = readinessCheck

	return m.GetOrCreate(name, config)
}

// CreateMessagingBreaker creates a circuit breaker optimized for messaging operations
func (m *CircuitBreakerManager) CreateMessagingBreaker(name string, readinessCheck func(ctx context.Context) error) *CircuitBreaker {
	config := MessagingConfig
	config.Name = name
	config.ReadinessCheck = readinessCheck

	return m.GetOrCreate(name, config)
}

// CreateObservabilityBreaker creates a circuit breaker optimized for observability operations
func (m *CircuitBreakerManager) CreateObservabilityBreaker(name string, readinessCheck func(ctx context.Context) error) *CircuitBreaker {
	config := ObservabilityConfig
	config.Name = name
	config.ReadinessCheck = readinessCheck

	return m.GetOrCreate(name, config)
}

// Global circuit breaker manager instance
var (
	globalManager     *CircuitBreakerManager
	globalManagerOnce sync.Once
)

// GetGlobalManager returns the global circuit breaker manager
func GetGlobalManager(obs *observability.Observability) *CircuitBreakerManager {
	globalManagerOnce.Do(func() {
		globalManager = NewCircuitBreakerManager(obs)
	})
	return globalManager
}

// Helper functions for common operations

// WithDatabaseBreaker wraps a database operation with circuit breaker protection
func WithDatabaseBreaker(ctx context.Context, obs *observability.Observability, name string, fn func(ctx context.Context) error) error {
	manager := GetGlobalManager(obs)
	return manager.ExecuteWithBreaker(ctx, fmt.Sprintf("db-%s", name), fn, DatabaseConfig)
}

// WithCacheBreaker wraps a cache operation with circuit breaker protection
func WithCacheBreaker(ctx context.Context, obs *observability.Observability, name string, fn func(ctx context.Context) error) error {
	manager := GetGlobalManager(obs)
	return manager.ExecuteWithBreaker(ctx, fmt.Sprintf("cache-%s", name), fn, CacheConfig)
}

// WithMessagingBreaker wraps a messaging operation with circuit breaker protection
func WithMessagingBreaker(ctx context.Context, obs *observability.Observability, name string, fn func(ctx context.Context) error) error {
	manager := GetGlobalManager(obs)
	return manager.ExecuteWithBreaker(ctx, fmt.Sprintf("messaging-%s", name), fn, MessagingConfig)
}
