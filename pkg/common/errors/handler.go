package errors

import (
	"errors"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

// Handler provides centralized error handling for HTTP responses
type Handler struct {
	logger zerolog.Logger
}

// NewHandler creates a new error handler
func NewHandler(logger zerolog.Logger) *Handler {
	return &Handler{
		logger: logger,
	}
}

// HandleError processes an error and returns appropriate HTTP response
func (h *Handler) HandleError(c *fiber.Ctx, err error) error {
	if err == nil {
		return nil
	}

	// Extract request context for logging
	requestID := c.Locals("requestId")
	userID := c.Locals("userId")

	// Log the error with context
	logEvent := h.logger.Error().
		Err(err).
		Str("path", c.Path()).
		Str("method", c.Method()).
		Interface("request_id", requestID).
		Interface("user_id", userID)

	// Handle different error types
	switch e := err.(type) {
	case *AppError:
		return h.handleAppError(c, e, logEvent)
	case *ValidationError:
		return h.handleValidationError(c, e, logEvent)
	case *DatabaseError:
		return h.handleDatabaseError(c, e, logEvent)
	case *ExternalError:
		return h.handleExternalError(c, e, logEvent)
	default:
		return h.handleGenericError(c, err, logEvent)
	}
}

// handleAppError handles AppError types
func (h *Handler) handleAppError(c *fiber.Ctx, err *AppError, logEvent *zerolog.Event) error {
	logEvent.
		Str("error_code", string(err.Code)).
		Str("error_message", err.Message).
		Interface("error_details", err.Details).
		Msg("Application error")

	response := fiber.Map{
		"error": fiber.Map{
			"code":    err.Code,
			"message": err.Message,
		},
		"request_id": c.Locals("requestId"),
	}

	if err.Details != nil && len(err.Details) > 0 {
		response["error"].(fiber.Map)["details"] = err.Details
	}

	return c.Status(err.HTTPStatus).JSON(response)
}

// handleValidationError handles ValidationError types
func (h *Handler) handleValidationError(c *fiber.Ctx, err *ValidationError, logEvent *zerolog.Event) error {
	logEvent.
		Str("error_code", string(err.Code)).
		Str("error_message", err.Message).
		Interface("validation_fields", err.Fields).
		Msg("Validation error")

	response := fiber.Map{
		"error": fiber.Map{
			"code":    err.Code,
			"message": err.Message,
		},
		"request_id": c.Locals("requestId"),
	}

	if err.Fields != nil && len(err.Fields) > 0 {
		response["error"].(fiber.Map)["fields"] = err.Fields
	}

	return c.Status(err.HTTPStatus).JSON(response)
}

// handleDatabaseError handles DatabaseError types
func (h *Handler) handleDatabaseError(c *fiber.Ctx, err *DatabaseError, logEvent *zerolog.Event) error {
	logEvent.
		Str("error_code", string(err.Code)).
		Str("error_message", err.Message).
		Str("db_operation", err.Operation).
		Str("db_table", err.Table).
		Msg("Database error")

	// Don't expose internal database details to client
	response := fiber.Map{
		"error": fiber.Map{
			"code":    err.Code,
			"message": "A database error occurred",
		},
		"request_id": c.Locals("requestId"),
	}

	return c.Status(err.HTTPStatus).JSON(response)
}

// handleExternalError handles ExternalError types
func (h *Handler) handleExternalError(c *fiber.Ctx, err *ExternalError, logEvent *zerolog.Event) error {
	logEvent.
		Str("error_code", string(err.Code)).
		Str("error_message", err.Message).
		Str("external_service", err.Service).
		Int("external_status_code", err.StatusCode).
		Msg("External service error")

	response := fiber.Map{
		"error": fiber.Map{
			"code":    err.Code,
			"message": fmt.Sprintf("External service %s is temporarily unavailable", err.Service),
		},
		"request_id": c.Locals("requestId"),
	}

	return c.Status(err.HTTPStatus).JSON(response)
}

// handleGenericError handles unknown error types
func (h *Handler) handleGenericError(c *fiber.Ctx, err error, logEvent *zerolog.Event) error {
	// Check for common GORM errors
	if errors.Is(err, gorm.ErrRecordNotFound) {
		notFoundErr := NewNotFoundError("Resource")
		return h.handleAppError(c, notFoundErr, logEvent)
	}

	// Log as internal error
	logEvent.Msg("Unhandled error")

	// Return generic internal error to client
	internalErr := NewInternalError("An unexpected error occurred", err)
	return h.handleAppError(c, internalErr, logEvent)
}

// HandleValidationError is a convenience method for validation errors
func (h *Handler) HandleValidationError(c *fiber.Ctx, message string, fields map[string]string) error {
	err := NewValidationError(message, fields)
	return h.HandleError(c, err)
}

// HandleNotFoundError is a convenience method for not found errors
func (h *Handler) HandleNotFoundError(c *fiber.Ctx, resource string) error {
	err := NewNotFoundError(resource)
	return h.HandleError(c, err)
}

// HandleUnauthorizedError is a convenience method for unauthorized errors
func (h *Handler) HandleUnauthorizedError(c *fiber.Ctx, message string) error {
	err := NewUnauthorizedError(message)
	return h.HandleError(c, err)
}

// HandleForbiddenError is a convenience method for forbidden errors
func (h *Handler) HandleForbiddenError(c *fiber.Ctx, message string) error {
	err := NewForbiddenError(message)
	return h.HandleError(c, err)
}

// HandleDatabaseError is a convenience method for database errors
func (h *Handler) HandleDatabaseError(c *fiber.Ctx, operation, table string, cause error) error {
	err := NewDatabaseError(operation, table, cause)
	return h.HandleError(c, err)
}

// HandleExternalError is a convenience method for external service errors
func (h *Handler) HandleExternalError(c *fiber.Ctx, service string, statusCode int, cause error) error {
	err := NewExternalError(service, statusCode, cause)
	return h.HandleError(c, err)
}

// ErrorResponse represents a standardized error response structure
type ErrorResponse struct {
	Error struct {
		Code    ErrorCode              `json:"code"`
		Message string                 `json:"message"`
		Details map[string]interface{} `json:"details,omitempty"`
		Fields  map[string]string      `json:"fields,omitempty"`
	} `json:"error"`
	RequestID interface{} `json:"request_id,omitempty"`
}
