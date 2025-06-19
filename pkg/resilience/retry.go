// Package resilience provides retry logic and timeout handling for resilient operations.
package resilience

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"time"

	"mvp.local/pkg/observability"
)

// RetryPolicy defines how retries should be performed
type RetryPolicy struct {
	// MaxAttempts is the maximum number of retry attempts
	MaxAttempts int

	// InitialDelay is the delay before the first retry
	InitialDelay time.Duration

	// MaxDelay is the maximum delay between retries
	MaxDelay time.Duration

	// BackoffMultiplier for exponential backoff
	BackoffMultiplier float64

	// Jitter adds randomness to prevent thundering herd
	Jitter bool

	// RetryableErrors function to determine if an error is retryable
	RetryableErrors func(error) bool
}

// DefaultRetryPolicy returns a sensible default retry policy
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:       3,
		InitialDelay:      100 * time.Millisecond,
		MaxDelay:          5 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            true,
		RetryableErrors:   DefaultRetryableErrors,
	}
}

// DatabaseRetryPolicy is optimized for database operations
func DatabaseRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:       3,
		InitialDelay:      50 * time.Millisecond,
		MaxDelay:          2 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            true,
		RetryableErrors:   DatabaseRetryableErrors,
	}
}

// CacheRetryPolicy is optimized for cache operations
func CacheRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:       2,
		InitialDelay:      25 * time.Millisecond,
		MaxDelay:          500 * time.Millisecond,
		BackoffMultiplier: 2.0,
		Jitter:            true,
		RetryableErrors:   CacheRetryableErrors,
	}
}

// MessagingRetryPolicy is optimized for messaging operations
func MessagingRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:       4,
		InitialDelay:      100 * time.Millisecond,
		MaxDelay:          10 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            true,
		RetryableErrors:   MessagingRetryableErrors,
	}
}

// ExternalAPIRetryPolicy is optimized for external API calls
func ExternalAPIRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:       3,
		InitialDelay:      500 * time.Millisecond,
		MaxDelay:          30 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            true,
		RetryableErrors:   ExternalAPIRetryableErrors,
	}
}

// RetryResult contains information about the retry execution
type RetryResult struct {
	Attempts   int
	TotalDelay time.Duration
	LastError  error
	Success    bool
	StartTime  time.Time
	EndTime    time.Time
}

// Retryer provides retry functionality with circuit breaker integration
type Retryer struct {
	policy RetryPolicy
	obs    *observability.Observability
}

// NewRetryer creates a new retryer with the given policy
func NewRetryer(policy RetryPolicy, obs *observability.Observability) *Retryer {
	return &Retryer{
		policy: policy,
		obs:    obs,
	}
}

// Execute runs the given function with retry logic
func (r *Retryer) Execute(ctx context.Context, name string, fn func(ctx context.Context) error) (*RetryResult, error) {
	result := &RetryResult{
		StartTime: time.Now(),
	}

	var lastError error

	for attempt := 1; attempt <= r.policy.MaxAttempts; attempt++ {
		result.Attempts = attempt

		// Create context with timeout for this attempt
		attemptCtx := ctx
		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			// Use remaining time for attempt
			remaining := time.Until(deadline)
			if remaining <= 0 {
				lastError = context.DeadlineExceeded
				break
			}
		}

		// Execute the function
		err := fn(attemptCtx)

		// Log attempt
		if r.obs != nil {
			if err != nil {
				r.obs.Logger.Debug().
					Str("operation", name).
					Int("attempt", attempt).
					Int("max_attempts", r.policy.MaxAttempts).
					Err(err).
					Msg("Retry attempt failed")
			} else {
				r.obs.Logger.Debug().
					Str("operation", name).
					Int("attempt", attempt).
					Msg("Retry attempt succeeded")
			}
		}

		if err == nil {
			// Success!
			result.Success = true
			result.EndTime = time.Now()
			return result, nil
		}

		lastError = err

		// Check if error is retryable
		if r.policy.RetryableErrors != nil && !r.policy.RetryableErrors(err) {
			// Error is not retryable, stop immediately
			if r.obs != nil {
				r.obs.Logger.Debug().
					Str("operation", name).
					Err(err).
					Msg("Error is not retryable, stopping retries")
			}
			break
		}

		// Don't delay after the last attempt
		if attempt < r.policy.MaxAttempts {
			delay := r.calculateDelay(attempt)
			result.TotalDelay += delay

			// Sleep with context cancellation support
			select {
			case <-ctx.Done():
				lastError = ctx.Err()
				goto done
			case <-time.After(delay):
				// Continue to next attempt
			}
		}
	}

done:
	result.LastError = lastError
	result.EndTime = time.Now()

	// Log final result
	if r.obs != nil {
		r.obs.Logger.Warn().
			Str("operation", name).
			Int("attempts", result.Attempts).
			Dur("total_delay", result.TotalDelay).
			Err(lastError).
			Msg("All retry attempts failed")
	}

	return result, lastError
}

// calculateDelay calculates the delay for the given attempt
func (r *Retryer) calculateDelay(attempt int) time.Duration {
	delay := float64(r.policy.InitialDelay)

	// Apply exponential backoff
	if attempt > 1 {
		delay = delay * math.Pow(r.policy.BackoffMultiplier, float64(attempt-1))
	}

	// Apply jitter to prevent thundering herd
	if r.policy.Jitter {
		jitter := delay * 0.1 * (2*rand.Float64() - 1) // ±10% jitter
		delay += jitter
	}

	// Cap at max delay
	if delay > float64(r.policy.MaxDelay) {
		delay = float64(r.policy.MaxDelay)
	}

	// Ensure minimum delay
	if delay < float64(r.policy.InitialDelay) {
		delay = float64(r.policy.InitialDelay)
	}

	return time.Duration(delay)
}

// Timeout configuration for different operation types
type TimeoutConfig struct {
	// Operation timeout for the entire operation
	Operation time.Duration

	// Individual attempt timeout
	Attempt time.Duration

	// Connection timeout for network operations
	Connection time.Duration

	// Read timeout for read operations
	Read time.Duration

	// Write timeout for write operations
	Write time.Duration
}

// Default timeout configurations
var (
	DatabaseTimeouts = TimeoutConfig{
		Operation:  30 * time.Second,
		Attempt:    10 * time.Second,
		Connection: 5 * time.Second,
		Read:       15 * time.Second,
		Write:      10 * time.Second,
	}

	CacheTimeouts = TimeoutConfig{
		Operation:  5 * time.Second,
		Attempt:    2 * time.Second,
		Connection: 1 * time.Second,
		Read:       3 * time.Second,
		Write:      2 * time.Second,
	}

	MessagingTimeouts = TimeoutConfig{
		Operation:  20 * time.Second,
		Attempt:    10 * time.Second,
		Connection: 5 * time.Second,
		Read:       10 * time.Second,
		Write:      10 * time.Second,
	}

	ExternalAPITimeouts = TimeoutConfig{
		Operation:  60 * time.Second,
		Attempt:    30 * time.Second,
		Connection: 10 * time.Second,
		Read:       45 * time.Second,
		Write:      15 * time.Second,
	}
)

// WithTimeout creates a context with timeout
func WithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

// WithOperationTimeout creates a context with operation-level timeout
func WithOperationTimeout(ctx context.Context, config TimeoutConfig) (context.Context, context.CancelFunc) {
	return WithTimeout(ctx, config.Operation)
}

// WithAttemptTimeout creates a context with attempt-level timeout
func WithAttemptTimeout(ctx context.Context, config TimeoutConfig) (context.Context, context.CancelFunc) {
	return WithTimeout(ctx, config.Attempt)
}

// ExecuteWithRetry is a convenience function that combines retry logic with circuit breaker
func ExecuteWithRetry(
	ctx context.Context,
	obs *observability.Observability,
	name string,
	policy RetryPolicy,
	fn func(ctx context.Context) error,
) error {
	retryer := NewRetryer(policy, obs)
	_, err := retryer.Execute(ctx, name, fn)
	return err
}

// ExecuteWithRetryAndBreaker combines retry logic with circuit breaker protection
func ExecuteWithRetryAndBreaker(
	ctx context.Context,
	obs *observability.Observability,
	name string,
	policy RetryPolicy,
	breakerConfig CircuitBreakerConfig,
	fn func(ctx context.Context) error,
) error {
	manager := GetGlobalManager(obs)

	return manager.ExecuteWithBreaker(ctx, name, func(ctx context.Context) error {
		return ExecuteWithRetry(ctx, obs, name, policy, fn)
	}, breakerConfig)
}

// Helper functions for common retry patterns

// RetryDatabase wraps a database operation with retry logic and circuit breaker
func RetryDatabase(ctx context.Context, obs *observability.Observability, name string, fn func(ctx context.Context) error) error {
	ctx, cancel := WithOperationTimeout(ctx, DatabaseTimeouts)
	defer cancel()

	return ExecuteWithRetryAndBreaker(ctx, obs, fmt.Sprintf("db-%s", name), DatabaseRetryPolicy(), DatabaseConfig, fn)
}

// RetryCache wraps a cache operation with retry logic and circuit breaker
func RetryCache(ctx context.Context, obs *observability.Observability, name string, fn func(ctx context.Context) error) error {
	ctx, cancel := WithOperationTimeout(ctx, CacheTimeouts)
	defer cancel()

	return ExecuteWithRetryAndBreaker(ctx, obs, fmt.Sprintf("cache-%s", name), CacheRetryPolicy(), CacheConfig, fn)
}

// RetryMessaging wraps a messaging operation with retry logic and circuit breaker
func RetryMessaging(ctx context.Context, obs *observability.Observability, name string, fn func(ctx context.Context) error) error {
	ctx, cancel := WithOperationTimeout(ctx, MessagingTimeouts)
	defer cancel()

	return ExecuteWithRetryAndBreaker(ctx, obs, fmt.Sprintf("messaging-%s", name), MessagingRetryPolicy(), MessagingConfig, fn)
}

// RetryExternalAPI wraps an external API call with retry logic and circuit breaker
func RetryExternalAPI(ctx context.Context, obs *observability.Observability, name string, fn func(ctx context.Context) error) error {
	ctx, cancel := WithOperationTimeout(ctx, ExternalAPITimeouts)
	defer cancel()

	return ExecuteWithRetryAndBreaker(ctx, obs, fmt.Sprintf("api-%s", name), ExternalAPIRetryPolicy(), ExternalAPIConfig, fn)
}

// Default retry error functions

// DefaultRetryableErrors determines if an error should be retried for general operations
func DefaultRetryableErrors(err error) bool {
	if err == nil {
		return false
	}

	// Don't retry context cancellation or deadline exceeded
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Don't retry circuit breaker errors
	var cbErr *CircuitBreakerError
	if errors.As(err, &cbErr) {
		return false
	}

	// Retry most other errors
	return true
}

// DatabaseRetryableErrors determines if a database error should be retried
func DatabaseRetryableErrors(err error) bool {
	if err == nil {
		return false
	}

	// Don't retry context errors
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Don't retry circuit breaker errors
	var cbErr *CircuitBreakerError
	if errors.As(err, &cbErr) {
		return false
	}

	errStr := err.Error()

	// Retry connection errors
	if containsAny(errStr, []string{
		"connection refused",
		"connection reset",
		"connection timeout",
		"network is unreachable",
		"no route to host",
		"temporary failure",
		"too many connections",
	}) {
		return true
	}

	// Don't retry constraint violations or syntax errors
	if containsAny(errStr, []string{
		"unique constraint",
		"foreign key constraint",
		"check constraint",
		"syntax error",
		"invalid input",
		"permission denied",
		"authentication failed",
	}) {
		return false
	}

	// Retry most other database errors
	return true
}

// CacheRetryableErrors determines if a cache error should be retried
func CacheRetryableErrors(err error) bool {
	if err == nil {
		return false
	}

	// Don't retry context errors
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Don't retry circuit breaker errors
	var cbErr *CircuitBreakerError
	if errors.As(err, &cbErr) {
		return false
	}

	errStr := err.Error()

	// Retry connection and network errors
	if containsAny(errStr, []string{
		"connection refused",
		"connection reset",
		"connection timeout",
		"network error",
		"timeout",
		"temporary failure",
		"redis: nil",
		"EOF",
	}) {
		return true
	}

	// Don't retry authentication or permission errors
	if containsAny(errStr, []string{
		"authentication failed",
		"permission denied",
		"invalid credentials",
	}) {
		return false
	}

	// Retry most other cache errors (cache should be tolerant)
	return true
}

// MessagingRetryableErrors determines if a messaging error should be retried
func MessagingRetryableErrors(err error) bool {
	if err == nil {
		return false
	}

	// Don't retry context errors
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Don't retry circuit breaker errors
	var cbErr *CircuitBreakerError
	if errors.As(err, &cbErr) {
		return false
	}

	errStr := err.Error()

	// Retry connection and network errors
	if containsAny(errStr, []string{
		"connection refused",
		"connection closed",
		"connection timeout",
		"network error",
		"nats: timeout",
		"nats: connection closed",
		"nats: no servers available",
		"temporary failure",
	}) {
		return true
	}

	// Don't retry authentication or authorization errors
	if containsAny(errStr, []string{
		"authentication timeout",
		"authorization violation",
		"permission denied",
		"invalid subject",
		"invalid queue group",
	}) {
		return false
	}

	// Retry most other messaging errors
	return true
}

// ExternalAPIRetryableErrors determines if an external API error should be retried
func ExternalAPIRetryableErrors(err error) bool {
	if err == nil {
		return false
	}

	// Don't retry context errors
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Don't retry circuit breaker errors
	var cbErr *CircuitBreakerError
	if errors.As(err, &cbErr) {
		return false
	}

	errStr := err.Error()

	// Retry network and connection errors
	if containsAny(errStr, []string{
		"connection refused",
		"connection reset",
		"connection timeout",
		"network error",
		"timeout",
		"temporary failure",
		"service unavailable",
		"bad gateway",
		"gateway timeout",
		"too many requests",
	}) {
		return true
	}

	// Don't retry client errors (4xx)
	if containsAny(errStr, []string{
		"400 Bad Request",
		"401 Unauthorized",
		"403 Forbidden",
		"404 Not Found",
		"405 Method Not Allowed",
		"406 Not Acceptable",
		"409 Conflict",
		"410 Gone",
		"422 Unprocessable Entity",
	}) {
		return false
	}

	// Retry server errors (5xx) except for some specific ones
	if containsAny(errStr, []string{
		"500 Internal Server Error",
		"502 Bad Gateway",
		"503 Service Unavailable",
		"504 Gateway Timeout",
	}) {
		return true
	}

	// Default to retry for unknown errors
	return true
}

// containsAny checks if the string contains any of the substrings
func containsAny(s string, substrings []string) bool {
	for _, substring := range substrings {
		if len(s) >= len(substring) {
			for i := 0; i <= len(s)-len(substring); i++ {
				if s[i:i+len(substring)] == substring {
					return true
				}
			}
		}
	}
	return false
}
