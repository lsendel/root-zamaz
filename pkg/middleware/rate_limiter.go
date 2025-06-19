// Package middleware provides rate limiting functionality with Redis backend support.
package middleware

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"mvp.local/pkg/errors"
	"mvp.local/pkg/observability"
)

// RateLimiterConfig holds configuration for rate limiting
type RateLimiterConfig struct {
	// Rate limiting settings
	RequestsPerMinute int           `default:"60"`
	RequestsPerHour   int           `default:"1000"`
	BurstLimit        int           `default:"10"`
	WindowSize        time.Duration `default:"1m"`

	// Key generation
	KeyPrefix    string `default:"rate_limit"`
	IncludeIP    bool   `default:"true"`
	IncludeUser  bool   `default:"true"`
	IncludeRoute bool   `default:"false"`

	// Response customization
	SkipSuccessfulRequests bool `default:"false"`
	SkipFailedRequests     bool `default:"false"`

	// Headers
	IncludeHeaders bool   `default:"true"`
	HeaderPrefix   string `default:"X-RateLimit"`

	// Special handling
	WhitelistIPs   []string
	WhitelistUsers []string
	BlacklistIPs   []string

	// Fallback when Redis is unavailable
	AllowOnRedisFailure bool `default:"true"`
}

// DefaultRateLimiterConfig returns default rate limiter configuration
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		RequestsPerMinute:      60,
		RequestsPerHour:        1000,
		BurstLimit:             10,
		WindowSize:             time.Minute,
		KeyPrefix:              "rate_limit",
		IncludeIP:              true,
		IncludeUser:            true,
		IncludeRoute:           false,
		SkipSuccessfulRequests: false,
		SkipFailedRequests:     false,
		IncludeHeaders:         true,
		HeaderPrefix:           "X-RateLimit",
		WhitelistIPs:           []string{},
		WhitelistUsers:         []string{},
		BlacklistIPs:           []string{},
		AllowOnRedisFailure:    true,
	}
}

// RateLimiter represents a rate limiter instance
type RateLimiter struct {
	config      RateLimiterConfig
	redisClient *redis.Client
	obs         *observability.Observability
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(redisClient *redis.Client, obs *observability.Observability, config ...RateLimiterConfig) *RateLimiter {
	cfg := DefaultRateLimiterConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	return &RateLimiter{
		config:      cfg,
		redisClient: redisClient,
		obs:         obs,
	}
}

// RateLimitMiddleware creates rate limiting middleware
func (rl *RateLimiter) RateLimitMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Skip if Redis is not available and fallback is allowed
		if rl.redisClient == nil {
			if rl.config.AllowOnRedisFailure {
				rl.obs.Logger.Warn().Msg("Rate limiting skipped: Redis not available")
				return c.Next()
			}
			return errors.Unavailable("Rate limiting service unavailable")
		}

		// Generate rate limit key
		key := rl.generateKey(c)

		// Check blacklist
		if rl.isBlacklisted(c) {
			rl.obs.Logger.Warn().
				Str("ip", c.IP()).
				Str("key", key).
				Msg("Request blocked: IP blacklisted")

			return errors.RateLimit("Access denied").
				WithContext("reason", "blacklisted").
				WithContext("ip", c.IP())
		}

		// Check whitelist
		if rl.isWhitelisted(c) {
			return c.Next()
		}

		// Check rate limit
		allowed, remaining, resetTime, err := rl.checkRateLimit(c.Context(), key)
		if err != nil {
			rl.obs.Logger.Error().
				Err(err).
				Str("key", key).
				Msg("Rate limit check failed")

			if rl.config.AllowOnRedisFailure {
				return c.Next()
			}
			return errors.Internal("Rate limiting service error")
		}

		// Add rate limit headers
		if rl.config.IncludeHeaders {
			rl.addRateLimitHeaders(c, remaining, resetTime)
		}

		// Check if rate limited
		if !allowed {
			rl.obs.Logger.Warn().
				Str("ip", c.IP()).
				Str("key", key).
				Int("remaining", remaining).
				Time("reset_time", resetTime).
				Msg("Request rate limited")

			// Add Retry-After header
			retryAfter := int(time.Until(resetTime).Seconds())
			if retryAfter < 0 {
				retryAfter = 60 // Default to 1 minute
			}
			c.Set("Retry-After", strconv.Itoa(retryAfter))

			return errors.RateLimit("Rate limit exceeded").
				WithContext("limit", rl.config.RequestsPerMinute).
				WithContext("window", rl.config.WindowSize.String()).
				WithContext("retry_after", retryAfter)
		}

		return c.Next()
	}
}

// generateKey generates a rate limiting key based on configuration
func (rl *RateLimiter) generateKey(c *fiber.Ctx) string {
	parts := []string{rl.config.KeyPrefix}

	if rl.config.IncludeIP {
		parts = append(parts, "ip", c.IP())
	}

	if rl.config.IncludeUser {
		userID := getUserID(c)
		if userID != "" {
			parts = append(parts, "user", userID)
		}
	}

	if rl.config.IncludeRoute {
		parts = append(parts, "route", c.Route().Path)
	}

	// Add time window
	window := time.Now().Truncate(rl.config.WindowSize).Unix()
	parts = append(parts, "window", strconv.FormatInt(window, 10))

	return joinStringSlice(parts, ":")
}

// checkRateLimit checks if the request is within rate limits
func (rl *RateLimiter) checkRateLimit(ctx context.Context, key string) (allowed bool, remaining int, resetTime time.Time, err error) {
	// Use Redis pipeline for atomic operations
	pipe := rl.redisClient.Pipeline()

	// Increment counter
	incr := pipe.Incr(ctx, key)

	// Set expiration if this is a new key
	pipe.Expire(ctx, key, rl.config.WindowSize)

	// Execute pipeline
	_, err = pipe.Exec(ctx)
	if err != nil {
		return false, 0, time.Time{}, fmt.Errorf("failed to execute rate limit check: %w", err)
	}

	// Get current count
	count, err := incr.Result()
	if err != nil {
		return false, 0, time.Time{}, fmt.Errorf("failed to get rate limit count: %w", err)
	}

	// Calculate remaining requests
	remaining = rl.config.RequestsPerMinute - int(count)
	if remaining < 0 {
		remaining = 0
	}

	// Calculate reset time
	resetTime = time.Now().Truncate(rl.config.WindowSize).Add(rl.config.WindowSize)

	// Check if request is allowed
	allowed = count <= int64(rl.config.RequestsPerMinute)

	return allowed, remaining, resetTime, nil
}

// addRateLimitHeaders adds rate limit information to response headers
func (rl *RateLimiter) addRateLimitHeaders(c *fiber.Ctx, remaining int, resetTime time.Time) {
	prefix := rl.config.HeaderPrefix

	c.Set(prefix+"-Limit", strconv.Itoa(rl.config.RequestsPerMinute))
	c.Set(prefix+"-Remaining", strconv.Itoa(remaining))
	c.Set(prefix+"-Reset", strconv.FormatInt(resetTime.Unix(), 10))
	c.Set(prefix+"-Window", rl.config.WindowSize.String())
}

// isWhitelisted checks if the request should be whitelisted
func (rl *RateLimiter) isWhitelisted(c *fiber.Ctx) bool {
	ip := c.IP()
	userID := getUserID(c)

	// Check IP whitelist
	for _, whiteIP := range rl.config.WhitelistIPs {
		if ip == whiteIP {
			return true
		}
	}

	// Check user whitelist
	if userID != "" {
		for _, whiteUser := range rl.config.WhitelistUsers {
			if userID == whiteUser {
				return true
			}
		}
	}

	return false
}

// isBlacklisted checks if the request should be blacklisted
func (rl *RateLimiter) isBlacklisted(c *fiber.Ctx) bool {
	ip := c.IP()

	// Check IP blacklist
	for _, blackIP := range rl.config.BlacklistIPs {
		if ip == blackIP {
			return true
		}
	}

	return false
}

// getUserID extracts user ID from request context
func getUserID(c *fiber.Ctx) string {
	// Try to get from locals (set by auth middleware)
	if userID := c.Locals("user_id"); userID != nil {
		if id, ok := userID.(string); ok {
			return id
		}
	}

	// Try to get from JWT claims
	if claims := c.Locals("claims"); claims != nil {
		if claimsMap, ok := claims.(map[string]interface{}); ok {
			if sub, exists := claimsMap["sub"]; exists {
				if subStr, ok := sub.(string); ok {
					return subStr
				}
			}
		}
	}

	return ""
}

// joinStringSlice joins a string slice with a separator
func joinStringSlice(slice []string, sep string) string {
	if len(slice) == 0 {
		return ""
	}

	result := slice[0]
	for i := 1; i < len(slice); i++ {
		result += sep + slice[i]
	}
	return result
}

// PerRouteRateLimiter creates route-specific rate limiting
func (rl *RateLimiter) PerRouteRateLimiter(requestsPerMinute int) fiber.Handler {
	// Create a copy of config with route-specific settings
	config := rl.config
	config.RequestsPerMinute = requestsPerMinute
	config.IncludeRoute = true

	routeLimiter := &RateLimiter{
		config:      config,
		redisClient: rl.redisClient,
		obs:         rl.obs,
	}

	return routeLimiter.RateLimitMiddleware()
}

// PerUserRateLimiter creates user-specific rate limiting
func (rl *RateLimiter) PerUserRateLimiter(requestsPerMinute int) fiber.Handler {
	// Create a copy of config with user-specific settings
	config := rl.config
	config.RequestsPerMinute = requestsPerMinute
	config.IncludeUser = true
	config.IncludeIP = false // Focus on user, not IP

	userLimiter := &RateLimiter{
		config:      config,
		redisClient: rl.redisClient,
		obs:         rl.obs,
	}

	return userLimiter.RateLimitMiddleware()
}

// GetRateLimitStatus returns current rate limit status for debugging
func (rl *RateLimiter) GetRateLimitStatus(ctx context.Context, c *fiber.Ctx) (map[string]interface{}, error) {
	key := rl.generateKey(c)

	// Get current count
	count, err := rl.redisClient.Get(ctx, key).Int()
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("failed to get rate limit status: %w", err)
	}

	// Get TTL
	ttl, err := rl.redisClient.TTL(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get rate limit TTL: %w", err)
	}

	remaining := rl.config.RequestsPerMinute - count
	if remaining < 0 {
		remaining = 0
	}

	return map[string]interface{}{
		"key":             key,
		"limit":           rl.config.RequestsPerMinute,
		"current":         count,
		"remaining":       remaining,
		"window_size":     rl.config.WindowSize.String(),
		"reset_time":      time.Now().Add(ttl).Unix(),
		"is_rate_limited": count >= rl.config.RequestsPerMinute,
	}, nil
}
