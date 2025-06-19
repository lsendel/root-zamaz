// Package resilience provides circuit breaker and resilience patterns for the MVP Zero Trust Auth system.
// It includes circuit breakers, retry logic, timeout handling, and graceful degradation patterns.
package resilience

import (
	"context"
	"errors"
	"sync"
	"time"

	"mvp.local/pkg/observability"
)

// CircuitBreakerState represents the current state of a circuit breaker
type CircuitBreakerState int

const (
	// StateClosed - circuit breaker is closed, allowing requests through
	StateClosed CircuitBreakerState = iota
	// StateOpen - circuit breaker is open, failing fast
	StateOpen
	// StateHalfOpen - circuit breaker is testing if service has recovered
	StateHalfOpen
)

// String returns the string representation of the circuit breaker state
func (s CircuitBreakerState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF_OPEN"
	default:
		return "UNKNOWN"
	}
}

// CircuitBreakerConfig holds configuration for a circuit breaker
type CircuitBreakerConfig struct {
	// Name of the circuit breaker for logging and metrics
	Name string
	
	// MaxFailures before opening the circuit
	MaxFailures int
	
	// Timeout before attempting to close the circuit from open state
	Timeout time.Duration
	
	// MaxRequests allowed when in half-open state
	MaxRequests int
	
	// ReadinessCheck function to test if service is ready
	ReadinessCheck func(ctx context.Context) error
	
	// OnStateChange callback when state changes
	OnStateChange func(name string, from, to CircuitBreakerState)
}

// DefaultCircuitBreakerConfig returns default configuration
func DefaultCircuitBreakerConfig(name string) CircuitBreakerConfig {
	return CircuitBreakerConfig{
		Name:           name,
		MaxFailures:    5,
		Timeout:        30 * time.Second,
		MaxRequests:    3,
		ReadinessCheck: nil,
		OnStateChange:  nil,
	}
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	config       CircuitBreakerConfig
	state        CircuitBreakerState
	failures     int
	successes    int
	requests     int
	lastFailTime time.Time
	mutex        sync.RWMutex
	obs          *observability.Observability
}

// CircuitBreakerError represents an error when circuit breaker is open
type CircuitBreakerError struct {
	Name    string
	State   CircuitBreakerState
	Message string
}

func (e *CircuitBreakerError) Error() string {
	return e.Message
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config CircuitBreakerConfig, obs *observability.Observability) *CircuitBreaker {
	if config.Name == "" {
		config.Name = "unnamed"
	}
	
	cb := &CircuitBreaker{
		config: config,
		state:  StateClosed,
		obs:    obs,
	}
	
	return cb
}

// Execute runs the given function with circuit breaker protection
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func(ctx context.Context) error) error {
	// Check if we can proceed
	if err := cb.beforeRequest(ctx); err != nil {
		return err
	}
	
	// Execute the function
	err := fn(ctx)
	
	// Record the result
	cb.afterRequest(err)
	
	return err
}

// beforeRequest checks if the request should be allowed
func (cb *CircuitBreaker) beforeRequest(ctx context.Context) error {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	
	switch cb.state {
	case StateClosed:
		// Allow request
		return nil
		
	case StateOpen:
		// Check if timeout has passed
		if time.Since(cb.lastFailTime) >= cb.config.Timeout {
			cb.setState(StateHalfOpen)
			cb.requests = 0
			return nil
		}
		
		// Circuit is still open
		return &CircuitBreakerError{
			Name:    cb.config.Name,
			State:   StateOpen,
			Message: "circuit breaker is open",
		}
		
	case StateHalfOpen:
		// Allow limited requests
		if cb.requests >= cb.config.MaxRequests {
			return &CircuitBreakerError{
				Name:    cb.config.Name,
				State:   StateHalfOpen,
				Message: "circuit breaker is half-open with max requests reached",
			}
		}
		
		cb.requests++
		return nil
		
	default:
		return &CircuitBreakerError{
			Name:    cb.config.Name,
			State:   cb.state,
			Message: "circuit breaker is in unknown state",
		}
	}
}

// afterRequest records the result of a request
func (cb *CircuitBreaker) afterRequest(err error) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	
	if err != nil {
		cb.onFailure()
	} else {
		cb.onSuccess()
	}
}

// onFailure handles a failed request
func (cb *CircuitBreaker) onFailure() {
	cb.failures++
	cb.lastFailTime = time.Now()
	
	// Log failure
	if cb.obs != nil {
		cb.obs.Logger.Warn().
			Str("circuit_breaker", cb.config.Name).
			Int("failures", cb.failures).
			Str("state", cb.state.String()).
			Msg("Circuit breaker recorded failure")
	}
	
	switch cb.state {
	case StateClosed:
		if cb.failures >= cb.config.MaxFailures {
			cb.setState(StateOpen)
		}
		
	case StateHalfOpen:
		cb.setState(StateOpen)
	}
}

// onSuccess handles a successful request
func (cb *CircuitBreaker) onSuccess() {
	cb.successes++
	
	switch cb.state {
	case StateHalfOpen:
		if cb.successes >= cb.config.MaxRequests {
			cb.setState(StateClosed)
		}
	}
}

// setState changes the circuit breaker state
func (cb *CircuitBreaker) setState(newState CircuitBreakerState) {
	oldState := cb.state
	cb.state = newState
	
	// Reset counters based on new state
	switch newState {
	case StateClosed:
		cb.failures = 0
		cb.successes = 0
		cb.requests = 0
		
	case StateOpen:
		cb.successes = 0
		cb.requests = 0
		
	case StateHalfOpen:
		cb.successes = 0
		cb.requests = 0
	}
	
	// Log state change
	if cb.obs != nil {
		cb.obs.Logger.Info().
			Str("circuit_breaker", cb.config.Name).
			Str("from_state", oldState.String()).
			Str("to_state", newState.String()).
			Msg("Circuit breaker state changed")
	}
	
	// Call state change callback
	if cb.config.OnStateChange != nil {
		cb.config.OnStateChange(cb.config.Name, oldState, newState)
	}
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state
}

// GetMetrics returns current metrics for the circuit breaker
func (cb *CircuitBreaker) GetMetrics() map[string]interface{} {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	
	return map[string]interface{}{
		"name":           cb.config.Name,
		"state":          cb.state.String(),
		"failures":       cb.failures,
		"successes":      cb.successes,
		"requests":       cb.requests,
		"last_fail_time": cb.lastFailTime,
		"max_failures":   cb.config.MaxFailures,
		"timeout":        cb.config.Timeout,
		"max_requests":   cb.config.MaxRequests,
	}
}

// ForceOpen forces the circuit breaker to open state
func (cb *CircuitBreaker) ForceOpen() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	cb.setState(StateOpen)
}

// ForceClose forces the circuit breaker to closed state
func (cb *CircuitBreaker) ForceClose() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	cb.setState(StateClosed)
}

// Reset resets the circuit breaker to initial state
func (cb *CircuitBreaker) Reset() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	cb.setState(StateClosed)
}

// IsFailureError determines if an error should be counted as a failure
func IsFailureError(err error) bool {
	if err == nil {
		return false
	}
	
	// Don't count context cancellation as failure
	if errors.Is(err, context.Canceled) {
		return false
	}
	
	// Don't count deadline exceeded as failure (might be expected)
	if errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	
	// Don't count circuit breaker errors as additional failures
	var cbErr *CircuitBreakerError
	if errors.As(err, &cbErr) {
		return false
	}
	
	return true
}