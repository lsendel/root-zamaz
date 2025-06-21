package errors

import (
	"fmt"
	"net/http"
)

// ErrorCode represents standardized error codes
type ErrorCode string

const (
	CodeValidation   ErrorCode = "VALIDATION_ERROR"
	CodeNotFound     ErrorCode = "NOT_FOUND"
	CodeUnauthorized ErrorCode = "UNAUTHORIZED"
	CodeForbidden    ErrorCode = "FORBIDDEN"
	CodeConflict     ErrorCode = "CONFLICT"
	CodeInternal     ErrorCode = "INTERNAL_ERROR"
	CodeDatabase     ErrorCode = "DATABASE_ERROR"
	CodeExternal     ErrorCode = "EXTERNAL_SERVICE_ERROR"
	CodeRateLimit    ErrorCode = "RATE_LIMIT_EXCEEDED"
	CodeMaintenance  ErrorCode = "MAINTENANCE_MODE"
)

// AppError represents a standardized application error
type AppError struct {
	Code       ErrorCode              `json:"code"`
	Message    string                 `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	Cause      error                  `json:"-"`
	HTTPStatus int                    `json:"-"`
}

func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Cause
}

// ValidationError represents validation-specific errors
type ValidationError struct {
	*AppError
	Fields map[string]string `json:"fields,omitempty"`
}

// DatabaseError represents database-specific errors
type DatabaseError struct {
	*AppError
	Operation string `json:"operation,omitempty"`
	Table     string `json:"table,omitempty"`
}

// ExternalError represents external service errors
type ExternalError struct {
	*AppError
	Service    string `json:"service,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
}

// NewValidationError creates a new validation error
func NewValidationError(message string, fields map[string]string) *ValidationError {
	details := make(map[string]interface{})
	if fields != nil {
		details["fields"] = fields
	}

	return &ValidationError{
		AppError: &AppError{
			Code:       CodeValidation,
			Message:    message,
			Details:    details,
			HTTPStatus: http.StatusBadRequest,
		},
		Fields: fields,
	}
}

// NewNotFoundError creates a new not found error
func NewNotFoundError(resource string) *AppError {
	return &AppError{
		Code:       CodeNotFound,
		Message:    fmt.Sprintf("%s not found", resource),
		HTTPStatus: http.StatusNotFound,
	}
}

// NewUnauthorizedError creates a new unauthorized error
func NewUnauthorizedError(message string) *AppError {
	if message == "" {
		message = "Authentication required"
	}
	return &AppError{
		Code:       CodeUnauthorized,
		Message:    message,
		HTTPStatus: http.StatusUnauthorized,
	}
}

// NewForbiddenError creates a new forbidden error
func NewForbiddenError(message string) *AppError {
	if message == "" {
		message = "Access denied"
	}
	return &AppError{
		Code:       CodeForbidden,
		Message:    message,
		HTTPStatus: http.StatusForbidden,
	}
}

// NewConflictError creates a new conflict error
func NewConflictError(resource string, details map[string]interface{}) *AppError {
	return &AppError{
		Code:       CodeConflict,
		Message:    fmt.Sprintf("%s already exists", resource),
		Details:    details,
		HTTPStatus: http.StatusConflict,
	}
}

// NewDatabaseError creates a new database error
func NewDatabaseError(operation, table string, cause error) *DatabaseError {
	return &DatabaseError{
		AppError: &AppError{
			Code:       CodeDatabase,
			Message:    fmt.Sprintf("Database operation failed: %s", operation),
			Cause:      cause,
			HTTPStatus: http.StatusInternalServerError,
		},
		Operation: operation,
		Table:     table,
	}
}

// NewExternalError creates a new external service error
func NewExternalError(service string, statusCode int, cause error) *ExternalError {
	return &ExternalError{
		AppError: &AppError{
			Code:       CodeExternal,
			Message:    fmt.Sprintf("External service error: %s", service),
			Cause:      cause,
			HTTPStatus: http.StatusBadGateway,
		},
		Service:    service,
		StatusCode: statusCode,
	}
}

// NewInternalError creates a new internal server error
func NewInternalError(message string, cause error) *AppError {
	if message == "" {
		message = "Internal server error"
	}
	return &AppError{
		Code:       CodeInternal,
		Message:    message,
		Cause:      cause,
		HTTPStatus: http.StatusInternalServerError,
	}
}

// NewRateLimitError creates a new rate limit error
func NewRateLimitError(limit int, window string) *AppError {
	details := map[string]interface{}{
		"limit":  limit,
		"window": window,
	}
	return &AppError{
		Code:       CodeRateLimit,
		Message:    "Rate limit exceeded",
		Details:    details,
		HTTPStatus: http.StatusTooManyRequests,
	}
}

// Wrap wraps an existing error with additional context
func Wrap(err error, code ErrorCode, message string) *AppError {
	if err == nil {
		return nil
	}

	// If it's already an AppError, wrap it
	if appErr, ok := err.(*AppError); ok {
		return &AppError{
			Code:       code,
			Message:    message,
			Cause:      appErr,
			HTTPStatus: appErr.HTTPStatus,
		}
	}

	return &AppError{
		Code:       code,
		Message:    message,
		Cause:      err,
		HTTPStatus: http.StatusInternalServerError,
	}
}
