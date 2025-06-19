// Package middleware provides error handling middleware for structured error responses.
package middleware

import (
	"runtime/debug"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"mvp.local/pkg/errors"
	"mvp.local/pkg/observability"
)

// Context key for storing database transaction
type contextKey string

const (
	TransactionContextKey contextKey = "db_transaction"
)

// ErrorResponse represents the structure of error responses sent to clients
type ErrorResponse struct {
	Error     *errors.AppError `json:"error"`
	Success   bool             `json:"success"`
	Timestamp time.Time        `json:"timestamp"`
	RequestID string           `json:"request_id,omitempty"`
	Path      string           `json:"path"`
	Method    string           `json:"method"`
}

// ErrorHandlerConfig holds configuration for error handling middleware
type ErrorHandlerConfig struct {
	IncludeStackTrace bool
	LogErrors         bool
	SanitizeErrors    bool // Remove sensitive information from error responses
}

// DefaultErrorHandlerConfig returns default error handler configuration
func DefaultErrorHandlerConfig() ErrorHandlerConfig {
	return ErrorHandlerConfig{
		IncludeStackTrace: false,
		LogErrors:         true,
		SanitizeErrors:    true,
	}
}

// ErrorHandlerMiddleware creates a new error handling middleware
func ErrorHandlerMiddleware(obs *observability.Observability, config ...ErrorHandlerConfig) fiber.ErrorHandler {
	cfg := DefaultErrorHandlerConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	return func(c *fiber.Ctx, err error) error {
		// Get request ID from context
		requestID := c.Get("X-Request-ID")
		if requestID == "" {
			requestID = c.Get("X-Correlation-ID")
		}

		// Convert error to AppError if it isn't already
		var appErr *errors.AppError
		if ae, ok := err.(*errors.AppError); ok {
			appErr = ae
		} else if fiberErr, ok := err.(*fiber.Error); ok {
			appErr = convertFiberError(fiberErr)
		} else {
			appErr = errors.Internal("An unexpected error occurred")
			if cfg.IncludeStackTrace {
				appErr = appErr.WithDetails(err.Error())
			}
		}

		// Add request context to error
		if requestID != "" {
			appErr = appErr.WithRequest(requestID)
		}

		// Determine HTTP status code
		statusCode := getHTTPStatusCode(appErr.Code)

		// Log error if configured
		if cfg.LogErrors {
			logError(obs, c, appErr, statusCode)
		}

		// Sanitize error for response if configured
		if cfg.SanitizeErrors {
			appErr = sanitizeError(appErr, statusCode)
		}

		// Create error response
		response := ErrorResponse{
			Error:     appErr,
			Success:   false,
			Timestamp: time.Now(),
			RequestID: requestID,
			Path:      c.Path(),
			Method:    c.Method(),
		}

		// Set appropriate headers
		if appErr.Code == errors.CodeRateLimit {
			c.Set("Retry-After", "60")
		}

		return c.Status(statusCode).JSON(response)
	}
}

// convertFiberError converts a Fiber error to AppError
func convertFiberError(fiberErr *fiber.Error) *errors.AppError {
	code := getErrorCodeFromStatus(fiberErr.Code)
	return errors.NewAppError(code, fiberErr.Message)
}

// StatusCodeMapping represents bidirectional mapping between error codes and HTTP status codes
type StatusCodeMapping struct {
	ErrorCode  errors.ErrorCode
	HTTPStatus int
}

// statusCodeMappings defines the mapping between error codes and HTTP status codes
var statusCodeMappings = []StatusCodeMapping{
	{errors.CodeValidation, fiber.StatusBadRequest},
	{errors.CodeAuthentication, fiber.StatusUnauthorized},
	{errors.CodeUnauthorized, fiber.StatusUnauthorized},
	{errors.CodeAuthorization, fiber.StatusForbidden},
	{errors.CodeForbidden, fiber.StatusForbidden},
	{errors.CodeNotFound, fiber.StatusNotFound},
	{errors.CodeConflict, fiber.StatusConflict},
	{errors.CodeTimeout, fiber.StatusRequestTimeout},
	{errors.CodeUnavailable, fiber.StatusServiceUnavailable},
	{errors.CodeRateLimit, fiber.StatusTooManyRequests},
	{errors.CodeInternal, fiber.StatusInternalServerError},
}

var (
	errorToHTTPMap = make(map[errors.ErrorCode]int)
	httpToErrorMap = make(map[int]errors.ErrorCode)
)

func init() {
	for _, mapping := range statusCodeMappings {
		errorToHTTPMap[mapping.ErrorCode] = mapping.HTTPStatus
		httpToErrorMap[mapping.HTTPStatus] = mapping.ErrorCode
	}
}

// getHTTPStatusCode maps error codes to HTTP status codes
func getHTTPStatusCode(code errors.ErrorCode) int {
	if status, exists := errorToHTTPMap[code]; exists {
		return status
	}
	return fiber.StatusInternalServerError
}

// getErrorCodeFromStatus maps HTTP status codes to error codes
func getErrorCodeFromStatus(status int) errors.ErrorCode {
	if code, exists := httpToErrorMap[status]; exists {
		return code
	}
	return errors.CodeInternal
}

// logError logs the error with appropriate level and context
func logError(obs *observability.Observability, c *fiber.Ctx, appErr *errors.AppError, statusCode int) {
	logEvent := obs.Logger.Error().
		Str("error_code", string(appErr.Code)).
		Str("error_message", appErr.Message).
		Int("status_code", statusCode).
		Str("method", c.Method()).
		Str("path", c.Path()).
		Str("user_agent", c.Get("User-Agent")).
		Str("remote_ip", c.IP())

	if appErr.RequestID != "" {
		logEvent = logEvent.Str("request_id", appErr.RequestID)
	}

	if appErr.TenantID != "" {
		logEvent = logEvent.Str("tenant_id", appErr.TenantID)
	}

	if appErr.Details != "" {
		logEvent = logEvent.Str("details", appErr.Details)
	}

	if appErr.Context != nil && len(appErr.Context) > 0 {
		logEvent = logEvent.Interface("context", appErr.Context)
	}

	if appErr.Cause != nil {
		logEvent = logEvent.Err(appErr.Cause)
	}

	// Log at different levels based on error severity
	switch appErr.Code {
	case errors.CodeInternal:
		logEvent.Msg("Internal server error")
	case errors.CodeTimeout, errors.CodeUnavailable:
		logEvent.Msg("Service error")
	case errors.CodeAuthentication, errors.CodeAuthorization:
		logEvent.Msg("Security error")
	case errors.CodeValidation:
		obs.Logger.Warn().
			Str("error_code", string(appErr.Code)).
			Str("path", c.Path()).
			Str("method", c.Method()).
			Msg("Validation error")
		return
	default:
		logEvent.Msg("Application error")
	}
}

// sanitizeError removes sensitive information from errors before sending to client
func sanitizeError(appErr *errors.AppError, statusCode int) *errors.AppError {
	// For internal server errors, don't expose internal details
	if statusCode >= 500 {
		sanitized := &errors.AppError{
			Code:      appErr.Code,
			Message:   "An internal error occurred",
			RequestID: appErr.RequestID,
			TenantID:  appErr.TenantID,
		}
		
		// Only include details in development/staging
		// This would typically check an environment variable
		// For now, we'll keep it simple
		return sanitized
	}

	// For client errors, sanitize context to remove potentially sensitive data
	sanitizedContext := make(map[string]interface{})
	for key, value := range appErr.Context {
		// Only include safe context keys
		switch key {
		case "field", "resource", "operation", "limit", "count":
			sanitizedContext[key] = value
		}
	}

	return &errors.AppError{
		Code:      appErr.Code,
		Message:   appErr.Message,
		Details:   appErr.Details,
		Context:   sanitizedContext,
		RequestID: appErr.RequestID,
		TenantID:  appErr.TenantID,
	}
}

// SetTransactionInContext stores a database transaction in the fiber context
func SetTransactionInContext(c *fiber.Ctx, tx *gorm.DB) {
	c.Locals(string(TransactionContextKey), tx)
}

// GetTransactionFromContext retrieves a database transaction from the fiber context
func GetTransactionFromContext(c *fiber.Ctx) *gorm.DB {
	if tx := c.Locals(string(TransactionContextKey)); tx != nil {
		if gormTx, ok := tx.(*gorm.DB); ok {
			return gormTx
		}
	}
	return nil
}

// RecoveryMiddleware creates a panic recovery middleware that converts panics to errors
func RecoveryMiddleware(obs *observability.Observability) fiber.Handler {
	return func(c *fiber.Ctx) error {
		defer func() {
			if r := recover(); r != nil {
				// Check if there's an active transaction and roll it back
				if tx := GetTransactionFromContext(c); tx != nil {
					// Use a defer to handle any panics during rollback
					func() {
						defer func() {
							if rollbackPanic := recover(); rollbackPanic != nil {
								obs.Logger.Error().
									Interface("panic", r).
									Interface("rollback_panic", rollbackPanic).
									Msg("Panic occurred during transaction rollback")
							}
						}()
						
						if err := tx.Rollback().Error; err != nil {
							obs.Logger.Error().
								Err(err).
								Interface("panic", r).
								Msg("Failed to rollback transaction during panic recovery")
						} else {
							obs.Logger.Warn().
								Interface("panic", r).
								Msg("Transaction rolled back due to panic")
						}
					}()
				}

				// Log the panic with additional context
				obs.Logger.Error().
					Interface("panic", r).
					Str("method", c.Method()).
					Str("path", c.Path()).
					Str("user_agent", c.Get("User-Agent")).
					Str("remote_ip", c.IP()).
					Bytes("stack_trace", debug.Stack()).
					Msg("Panic recovered")

				// Set error status and response
				c.Status(fiber.StatusInternalServerError)
				response := ErrorResponse{
					Error:     &errors.AppError{
						Code:    errors.CodeInternal,
						Message: "An unexpected error occurred",
						Details: "System panic recovered",
						Context: map[string]interface{}{
							"panic": true,
						},
					},
					Success:   false,
					Timestamp: time.Now(),
					RequestID: c.Get("X-Request-ID"),
					Path:      c.Path(),
					Method:    c.Method(),
				}
				c.JSON(response)
			}
		}()

		return c.Next()
	}
}