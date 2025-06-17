// Package errors provides consistent error handling patterns and utilities
// for the MVP Zero Trust Auth system. It includes structured error types,
// error wrapping utilities, and standardized error codes.
package errors

import (
	"errors"
	"fmt"
)

// ErrorCode represents a standardized error classification
type ErrorCode string

const (
	// Core error codes for different failure categories
	CodeInternal      ErrorCode = "INTERNAL_ERROR"
	CodeValidation    ErrorCode = "VALIDATION_ERROR" 
	CodeAuthentication ErrorCode = "AUTHENTICATION_ERROR"
	CodeAuthorization ErrorCode = "AUTHORIZATION_ERROR"
	CodeNotFound      ErrorCode = "NOT_FOUND"
	CodeConflict      ErrorCode = "CONFLICT"
	CodeTimeout       ErrorCode = "TIMEOUT"
	CodeUnavailable   ErrorCode = "SERVICE_UNAVAILABLE"
	CodeRateLimit     ErrorCode = "RATE_LIMIT_EXCEEDED"
)

// AppError represents a structured application error with context
type AppError struct {
	Code      ErrorCode              `json:"code"`
	Message   string                 `json:"message"`
	Details   string                 `json:"details,omitempty"`
	Cause     error                  `json:"-"`
	Context   map[string]interface{} `json:"context,omitempty"`
	TenantID  string                 `json:"tenant_id,omitempty"`
	RequestID string                 `json:"request_id,omitempty"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause for error chain traversal
func (e *AppError) Unwrap() error {
	return e.Cause
}

// Is implements error matching for errors.Is()
func (e *AppError) Is(target error) bool {
	if target == nil {
		return false
	}
	
	if appErr, ok := target.(*AppError); ok {
		return e.Code == appErr.Code
	}
	
	return false
}

// NewAppError creates a new structured application error
func NewAppError(code ErrorCode, message string) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Context: make(map[string]interface{}),
	}
}

// Wrap wraps an existing error with additional context
func Wrap(err error, code ErrorCode, message string) *AppError {
	if err == nil {
		return nil
	}
	
	// If it's already an AppError, preserve the original code but update message
	if appErr, ok := err.(*AppError); ok {
		return &AppError{
			Code:      appErr.Code, // Keep original code
			Message:   message,
			Details:   appErr.Message, // Move original message to details
			Cause:     appErr.Cause,
			Context:   appErr.Context,
			TenantID:  appErr.TenantID,
			RequestID: appErr.RequestID,
		}
	}
	
	return &AppError{
		Code:    code,
		Message: message,
		Cause:   err,
		Context: make(map[string]interface{}),
	}
}

// WithContext adds context information to an error
func (e *AppError) WithContext(key string, value interface{}) *AppError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// WithTenant adds tenant context to an error
func (e *AppError) WithTenant(tenantID string) *AppError {
	e.TenantID = tenantID
	return e
}

// WithRequest adds request context to an error
func (e *AppError) WithRequest(requestID string) *AppError {
	e.RequestID = requestID
	return e
}

// WithDetails adds additional details to an error
func (e *AppError) WithDetails(details string) *AppError {
	e.Details = details
	return e
}

// Common error constructors for frequently used error types

// Internal creates an internal server error
func Internal(message string) *AppError {
	return NewAppError(CodeInternal, message)
}

// Validation creates a validation error
func Validation(message string) *AppError {
	return NewAppError(CodeValidation, message)
}

// Authentication creates an authentication error
func Authentication(message string) *AppError {
	return NewAppError(CodeAuthentication, message)
}

// Authorization creates an authorization error  
func Authorization(message string) *AppError {
	return NewAppError(CodeAuthorization, message)
}

// NotFound creates a not found error
func NotFound(message string) *AppError {
	return NewAppError(CodeNotFound, message)
}

// Conflict creates a conflict error
func Conflict(message string) *AppError {
	return NewAppError(CodeConflict, message)
}

// Timeout creates a timeout error
func Timeout(message string) *AppError {
	return NewAppError(CodeTimeout, message)
}

// Unavailable creates a service unavailable error
func Unavailable(message string) *AppError {
	return NewAppError(CodeUnavailable, message)
}

// RateLimit creates a rate limit error
func RateLimit(message string) *AppError {
	return NewAppError(CodeRateLimit, message)
}

// IsCode checks if an error has a specific error code
func IsCode(err error, code ErrorCode) bool {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code == code
	}
	return false
}

// GetCode extracts the error code from an error, returns CodeInternal for non-AppErrors
func GetCode(err error) ErrorCode {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code
	}
	return CodeInternal
}

// GetContext extracts context from an error
func GetContext(err error) map[string]interface{} {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Context
	}
	return nil
}