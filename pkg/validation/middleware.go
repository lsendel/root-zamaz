// Package validation provides validation middleware for automatic request validation.
package validation

import (
	"reflect"

	"github.com/gofiber/fiber/v2"
	"mvp.local/pkg/observability"
)

// ValidationMiddleware provides request validation functionality
type ValidationMiddleware struct {
	validator *Validator
	obs       *observability.Observability
}

// ValidationConfig holds configuration for validation middleware
type ValidationConfig struct {
	// SkipValidation allows certain paths to skip validation
	SkipPaths []string

	// ValidateHeaders enables header validation
	ValidateHeaders bool

	// ValidateQuery enables query parameter validation
	ValidateQuery bool

	// LogValidationErrors enables logging of validation errors
	LogValidationErrors bool
}

// DefaultValidationConfig returns default validation configuration
func DefaultValidationConfig() ValidationConfig {
	return ValidationConfig{
		SkipPaths: []string{
			"/health",
			"/metrics",
			"/swagger",
		},
		ValidateHeaders:     false,
		ValidateQuery:       false,
		LogValidationErrors: true,
	}
}

// NewValidationMiddleware creates a new validation middleware
func NewValidationMiddleware(obs *observability.Observability, config ...ValidationConfig) *ValidationMiddleware {
	// Configuration will be used for future enhancements
	_ = DefaultValidationConfig()
	if len(config) > 0 {
		_ = config[0]
	}

	return &ValidationMiddleware{
		validator: NewValidator(),
		obs:       obs,
	}
}

// ValidateRequest returns a middleware that validates request body against a struct
func (vm *ValidationMiddleware) ValidateRequest(requestType interface{}) fiber.Handler {
	// Get the reflect type of the request struct
	structType := reflect.TypeOf(requestType)
	if structType.Kind() == reflect.Ptr {
		structType = structType.Elem()
	}

	return func(c *fiber.Ctx) error {
		// Skip validation for certain methods
		if c.Method() == "GET" || c.Method() == "DELETE" {
			return c.Next()
		}

		// Create a new instance of the request struct
		requestValue := reflect.New(structType).Interface()

		// Parse the request body
		if err := c.BodyParser(requestValue); err != nil {
			vm.logValidationError(c, "body_parse_error", err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   "Bad Request",
				"message": "Invalid request body format",
				"details": err.Error(),
			})
		}

		// Validate the request struct
		if err := vm.validator.ValidateStruct(requestValue); err != nil {
			vm.logValidationError(c, "validation_error", err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   "Validation Error",
				"message": "Request validation failed",
				"details": err.Error(),
			})
		}

		// Store the validated request in context for handlers to use
		c.Locals("validatedRequest", requestValue)

		return c.Next()
	}
}

// ValidationMiddleware returns a general validation middleware
func (vm *ValidationMiddleware) ValidationMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Add validation context information
		c.Locals("validator", vm.validator)
		return c.Next()
	}
}

// GetValidatedRequest retrieves the validated request from context
func GetValidatedRequest(c *fiber.Ctx) interface{} {
	return c.Locals("validatedRequest")
}

// GetValidator retrieves the validator from context
func GetValidator(c *fiber.Ctx) *Validator {
	if validator, ok := c.Locals("validator").(*Validator); ok {
		return validator
	}
	return nil
}

// ValidateQueryParams validates query parameters against a struct
func (vm *ValidationMiddleware) ValidateQueryParams(paramsType interface{}) fiber.Handler {
	structType := reflect.TypeOf(paramsType)
	if structType.Kind() == reflect.Ptr {
		structType = structType.Elem()
	}

	return func(c *fiber.Ctx) error {
		// Create a new instance of the params struct
		paramsValue := reflect.New(structType).Interface()

		// Parse query parameters into the struct
		if err := c.QueryParser(paramsValue); err != nil {
			vm.logValidationError(c, "query_parse_error", err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   "Bad Request",
				"message": "Invalid query parameters",
				"details": err.Error(),
			})
		}

		// Validate the params struct
		if err := vm.validator.ValidateStruct(paramsValue); err != nil {
			vm.logValidationError(c, "query_validation_error", err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   "Validation Error",
				"message": "Query parameter validation failed",
				"details": err.Error(),
			})
		}

		// Store validated params in context
		c.Locals("validatedQueryParams", paramsValue)

		return c.Next()
	}
}

// GetValidatedQueryParams retrieves validated query parameters from context
func GetValidatedQueryParams(c *fiber.Ctx) interface{} {
	return c.Locals("validatedQueryParams")
}

// logValidationError logs validation errors for monitoring
func (vm *ValidationMiddleware) logValidationError(c *fiber.Ctx, errorType string, err error) {
	if vm.obs != nil {
		vm.obs.Logger.Warn().
			Str("error_type", errorType).
			Str("method", c.Method()).
			Str("path", c.Path()).
			Str("user_agent", c.Get("User-Agent")).
			Str("remote_ip", c.IP()).
			Err(err).
			Msg("Request validation failed")
	}
}

// shouldSkipPath checks if a path should skip validation
func shouldSkipPath(path string, skipPaths []string) bool {
	for _, skipPath := range skipPaths {
		if path == skipPath {
			return true
		}
	}
	return false
}
