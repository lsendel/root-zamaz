package errors

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAppError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *AppError
		expected string
	}{
		{
			name: "error without cause",
			err: &AppError{
				Code:    CodeValidation,
				Message: "invalid input",
			},
			expected: "VALIDATION_ERROR: invalid input",
		},
		{
			name: "error with cause",
			err: &AppError{
				Code:    CodeInternal,
				Message: "database operation failed",
				Cause:   errors.New("connection timeout"),
			},
			expected: "INTERNAL_ERROR: database operation failed (caused by: connection timeout)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestAppError_Unwrap(t *testing.T) {
	cause := errors.New("original error")
	err := &AppError{
		Code:    CodeInternal,
		Message: "wrapped error",
		Cause:   cause,
	}

	assert.Equal(t, cause, err.Unwrap())
}

func TestAppError_Is(t *testing.T) {
	err1 := &AppError{Code: CodeValidation, Message: "test"}
	err2 := &AppError{Code: CodeValidation, Message: "different message"}
	err3 := &AppError{Code: CodeInternal, Message: "test"}

	assert.True(t, err1.Is(err2), "errors with same code should match")
	assert.False(t, err1.Is(err3), "errors with different codes should not match")
	assert.False(t, err1.Is(nil), "error should not match nil")
	assert.False(t, err1.Is(errors.New("standard error")), "AppError should not match standard error")
}

func TestWrap(t *testing.T) {
	t.Run("wrap nil error", func(t *testing.T) {
		result := Wrap(nil, CodeInternal, "test")
		assert.Nil(t, result)
	})

	t.Run("wrap standard error", func(t *testing.T) {
		originalErr := errors.New("original error")
		wrapped := Wrap(originalErr, CodeInternal, "wrapped message")

		assert.Equal(t, CodeInternal, wrapped.Code)
		assert.Equal(t, "wrapped message", wrapped.Message)
		assert.Equal(t, originalErr, wrapped.Cause)
	})

	t.Run("wrap AppError", func(t *testing.T) {
		originalErr := &AppError{
			Code:    CodeValidation,
			Message: "original message",
			Context: map[string]interface{}{"key": "value"},
		}
		wrapped := Wrap(originalErr, CodeInternal, "wrapped message")

		assert.Equal(t, CodeValidation, wrapped.Code) // Should preserve original code
		assert.Equal(t, "wrapped message", wrapped.Message)
		assert.Equal(t, "original message", wrapped.Details)
		assert.Equal(t, originalErr.Cause, wrapped.Cause)
		assert.Equal(t, originalErr.Context, wrapped.Context)
	})
}

func TestAppError_WithContext(t *testing.T) {
	err := NewAppError(CodeValidation, "test error")

	result := err.WithContext("user_id", "123").WithContext("action", "create")

	assert.Equal(t, "123", result.Context["user_id"])
	assert.Equal(t, "create", result.Context["action"])
}

func TestAppError_WithTenant(t *testing.T) {
	err := NewAppError(CodeValidation, "test error")
	result := err.WithTenant("tenant-123")

	assert.Equal(t, "tenant-123", result.TenantID)
}

func TestAppError_WithRequest(t *testing.T) {
	err := NewAppError(CodeValidation, "test error")
	result := err.WithRequest("req-456")

	assert.Equal(t, "req-456", result.RequestID)
}

func TestAppError_WithDetails(t *testing.T) {
	err := NewAppError(CodeValidation, "test error")
	result := err.WithDetails("additional details")

	assert.Equal(t, "additional details", result.Details)
}

func TestErrorConstructors(t *testing.T) {
	tests := []struct {
		name    string
		fn      func(string) *AppError
		code    ErrorCode
		message string
	}{
		{"Internal", Internal, CodeInternal, "internal error"},
		{"Validation", Validation, CodeValidation, "validation error"},
		{"Authentication", Authentication, CodeAuthentication, "auth error"},
		{"Authorization", Authorization, CodeAuthorization, "authz error"},
		{"NotFound", NotFound, CodeNotFound, "not found"},
		{"Conflict", Conflict, CodeConflict, "conflict"},
		{"Timeout", Timeout, CodeTimeout, "timeout"},
		{"Unavailable", Unavailable, CodeUnavailable, "unavailable"},
		{"RateLimit", RateLimit, CodeRateLimit, "rate limit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn(tt.message)
			assert.Equal(t, tt.code, err.Code)
			assert.Equal(t, tt.message, err.Message)
		})
	}
}

func TestIsCode(t *testing.T) {
	appErr := NewAppError(CodeValidation, "test")
	stdErr := errors.New("standard error")

	assert.True(t, IsCode(appErr, CodeValidation))
	assert.False(t, IsCode(appErr, CodeInternal))
	assert.False(t, IsCode(stdErr, CodeValidation))
	assert.False(t, IsCode(nil, CodeValidation))
}

func TestGetCode(t *testing.T) {
	appErr := NewAppError(CodeValidation, "test")
	stdErr := errors.New("standard error")

	assert.Equal(t, CodeValidation, GetCode(appErr))
	assert.Equal(t, CodeInternal, GetCode(stdErr))
	assert.Equal(t, CodeInternal, GetCode(nil))
}

func TestGetContext(t *testing.T) {
	appErr := NewAppError(CodeValidation, "test").WithContext("key", "value")
	stdErr := errors.New("standard error")

	context := GetContext(appErr)
	assert.NotNil(t, context)
	assert.Equal(t, "value", context["key"])

	assert.Nil(t, GetContext(stdErr))
	assert.Nil(t, GetContext(nil))
}

func TestErrorChaining(t *testing.T) {
	// Test that errors.Is and errors.As work correctly
	originalErr := errors.New("original")
	wrappedErr := Wrap(originalErr, CodeInternal, "wrapped")

	// Test errors.Is
	assert.True(t, errors.Is(wrappedErr, originalErr))

	// Test errors.As
	var appErr *AppError
	assert.True(t, errors.As(wrappedErr, &appErr))
	assert.Equal(t, CodeInternal, appErr.Code)
}

func TestErrorFormatting(t *testing.T) {
	err := NewAppError(CodeValidation, "test error").
		WithTenant("tenant-123").
		WithRequest("req-456").
		WithContext("field", "email").
		WithDetails("email format is invalid")

	// Test that error includes relevant information
	errorStr := err.Error()
	assert.Contains(t, errorStr, "VALIDATION_ERROR")
	assert.Contains(t, errorStr, "test error")

	// Test that all fields are properly set
	assert.Equal(t, "tenant-123", err.TenantID)
	assert.Equal(t, "req-456", err.RequestID)
	assert.Equal(t, "email format is invalid", err.Details)
	assert.Equal(t, "email", err.Context["field"])
}

func ExampleAppError() {
	// Create a validation error with context
	err := Validation("Invalid email format").
		WithTenant("tenant-123").
		WithRequest("req-456").
		WithContext("field", "email").
		WithContext("value", "invalid-email").
		WithDetails("Email must contain @ symbol")

	fmt.Println("Error:", err.Error())
	fmt.Println("Code:", err.Code)
	fmt.Println("Tenant:", err.TenantID)
	fmt.Println("Request:", err.RequestID)

	// Output:
	// Error: VALIDATION_ERROR: Invalid email format
	// Code: VALIDATION_ERROR
	// Tenant: tenant-123
	// Request: req-456
}

func ExampleWrap() {
	// Wrap a database error with application context
	dbErr := errors.New("connection timeout")
	appErr := Wrap(dbErr, CodeUnavailable, "Database connection failed").
		WithTenant("tenant-123").
		WithContext("operation", "user_lookup")

	fmt.Println("Error:", appErr.Error())
	fmt.Println("Is timeout:", errors.Is(appErr, dbErr))

	// Output:
	// Error: SERVICE_UNAVAILABLE: Database connection failed (caused by: connection timeout)
	// Is timeout: true
}
