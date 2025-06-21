package middleware

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"

	"mvp.local/pkg/common/errors"
	"mvp.local/pkg/observability"
)

// EnhancedErrorMiddleware creates a middleware that integrates with the standardized error handling system
func EnhancedErrorMiddleware(errorHandler *errors.Handler, obs *observability.Observability, logger zerolog.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Execute the next handler
		err := c.Next()
		if err != nil {
			// Record error metrics
			obs.RecordErrorMetric(err, c.Path(), c.Method())

			// Log the error with request context
			logger.Error().
				Err(err).
				Str("path", c.Path()).
				Str("method", c.Method()).
				Str("ip", c.IP()).
				Interface("request_id", c.Locals("requestId")).
				Interface("user_id", c.Locals("userId")).
				Msg("Request error")

			// Handle the error using the standardized error handler
			return errorHandler.HandleError(c, err)
		}

		return nil
	}
}

// RequestIDMiddleware adds a unique request ID to each request
func RequestIDMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Generate request ID
		requestID := generateRequestID()

		// Set in context
		c.Locals("requestId", requestID)

		// Add to response headers
		c.Set("X-Request-ID", requestID)

		return c.Next()
	}
}

// generateRequestID creates a unique request identifier
func generateRequestID() string {
	// Use a combination of timestamp and random string for uniqueness
	return fmt.Sprintf("req_%d_%s", time.Now().UnixNano(), generateRandomString(8))
}

// generateRandomString generates a random alphanumeric string
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
