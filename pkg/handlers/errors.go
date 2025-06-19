// Package handlers provides error handling utilities for consistent error responses.
package handlers

import (
	"github.com/gofiber/fiber/v2"
	"mvp.local/pkg/auth"
	"mvp.local/pkg/errors"
)

// Error message constants for consistent error responses
const (
	ErrMsgInvalidRequestBody    = "Invalid request body"
	ErrMsgNotAuthenticated      = "Not authenticated"
	ErrMsgInsufficientPerms     = "Insufficient permissions"
	ErrMsgDatabaseError         = "Database operation failed"
	ErrMsgInternalError         = "An unexpected error occurred"
	ErrMsgUserNotFound          = "User not found"
	ErrMsgResourceNotFound      = "Resource not found"
	ErrMsgInvalidCredentials    = "Invalid credentials"
	ErrMsgAccountDisabled       = "Account is disabled"
	ErrMsgAccountLocked         = "Account is temporarily locked"
	ErrMsgUserAlreadyExists     = "User already exists"
	ErrMsgRoleNotFound          = "Role not found"
	ErrMsgPermissionNotFound    = "Permission not found"
	ErrMsgDeviceNotFound        = "Device not found"
	ErrMsgDeviceAlreadyExists   = "Device already exists"
	ErrMsgInvalidDeviceID       = "Invalid device ID"
	ErrMsgInvalidUserID         = "Invalid user ID"
	ErrMsgInvalidRoleID         = "Invalid role ID"
	ErrMsgInvalidPermissionID   = "Invalid permission ID"
	ErrMsgCannotDeleteOwnUser   = "Cannot delete your own user account"
	ErrMsgCannotDeleteSystemRole = "Cannot delete system roles"
)

// ErrorContext holds common context information for error responses
type ErrorContext struct {
	RequestID string
	UserID    string
	TenantID  string
	Path      string
	Method    string
	IP        string
	UserAgent string
}

// GetErrorContext extracts common context information from the request
func GetErrorContext(c *fiber.Ctx) ErrorContext {
	ctx := ErrorContext{
		Path:      c.Path(),
		Method:    c.Method(),
		IP:        c.IP(),
		UserAgent: c.Get("User-Agent"),
	}

	// Extract request ID from headers
	ctx.RequestID = c.Get("X-Correlation-ID")
	if ctx.RequestID == "" {
		ctx.RequestID = c.Get("X-Request-ID")
	}

	// Extract user ID from authentication context if available
	if user, err := auth.GetCurrentUser(c); err == nil {
		ctx.UserID = user.ID.String()
	} else if userID, err := auth.GetCurrentUserID(c); err == nil {
		ctx.UserID = userID
	}

	// Extract tenant ID if available (for future multi-tenant support)
	ctx.TenantID = c.Get("X-Tenant-ID")

	return ctx
}

// HandleValidationError creates a standardized validation error response
func HandleValidationError(c *fiber.Ctx, err error) error {
	ctx := GetErrorContext(c)
	
	appErr := errors.ValidationWithDetails(ErrMsgInvalidRequestBody, map[string]interface{}{
		"details": err.Error(),
	}).WithRequest(ctx.RequestID)

	if ctx.UserID != "" {
		appErr = appErr.WithContext("user_id", ctx.UserID).
			WithContext("path", ctx.Path).
			WithContext("method", ctx.Method)
	}

	return appErr
}

// HandleAuthenticationError creates a standardized authentication error response
func HandleAuthenticationError(c *fiber.Ctx, message string) error {
	ctx := GetErrorContext(c)
	
	if message == "" {
		message = ErrMsgNotAuthenticated
	}

	appErr := errors.Authentication(message).WithRequest(ctx.RequestID)
	
	if ctx.UserID != "" {
		appErr = appErr.WithContext("user_id", ctx.UserID).
			WithContext("path", ctx.Path).
			WithContext("method", ctx.Method)
	}

	return appErr
}

// HandleAuthorizationError creates a standardized authorization error response
func HandleAuthorizationError(c *fiber.Ctx, message string) error {
	ctx := GetErrorContext(c)
	
	if message == "" {
		message = ErrMsgInsufficientPerms
	}

	appErr := errors.Authorization(message).WithRequest(ctx.RequestID)
	
	if ctx.UserID != "" {
		appErr = appErr.WithContext("user_id", ctx.UserID).
			WithContext("path", ctx.Path).
			WithContext("method", ctx.Method)
	}

	return appErr
}

// HandleDatabaseError creates a standardized database error response
func HandleDatabaseError(c *fiber.Ctx, err error, operation string) error {
	ctx := GetErrorContext(c)
	
	appErr := errors.Internal(ErrMsgDatabaseError).
		WithRequest(ctx.RequestID).
		WithDetails(err.Error()).
		WithContext("operation", operation).
		WithContext("path", ctx.Path).
		WithContext("method", ctx.Method)

	if ctx.UserID != "" {
		appErr = appErr.WithContext("user_id", ctx.UserID).
			WithContext("operation", operation).
			WithContext("path", ctx.Path).
			WithContext("method", ctx.Method)
	}

	return appErr
}

// HandleNotFoundError creates a standardized not found error response
func HandleNotFoundError(c *fiber.Ctx, resource string) error {
	ctx := GetErrorContext(c)
	
	message := ErrMsgResourceNotFound
	if resource != "" {
		switch resource {
		case "user":
			message = ErrMsgUserNotFound
		case "role":
			message = ErrMsgRoleNotFound
		case "permission":
			message = ErrMsgPermissionNotFound
		case "device":
			message = ErrMsgDeviceNotFound
		}
	}

	appErr := errors.NotFound(message).WithRequest(ctx.RequestID)
	
	if ctx.UserID != "" {
		appErr = appErr.WithContext("user_id", ctx.UserID).
			WithContext("resource", resource).
			WithContext("path", ctx.Path).
			WithContext("method", ctx.Method)
	}

	return appErr
}

// HandleConflictError creates a standardized conflict error response
func HandleConflictError(c *fiber.Ctx, resource string) error {
	ctx := GetErrorContext(c)
	
	message := "Resource already exists"
	if resource != "" {
		switch resource {
		case "user":
			message = ErrMsgUserAlreadyExists
		case "device":
			message = ErrMsgDeviceAlreadyExists
		}
	}

	appErr := errors.Conflict(message).WithRequest(ctx.RequestID)
	
	if ctx.UserID != "" {
		appErr = appErr.WithContext("user_id", ctx.UserID).
			WithContext("resource", resource).
			WithContext("path", ctx.Path).
			WithContext("method", ctx.Method)
	}

	return appErr
}

// HandleInternalError creates a standardized internal server error response
func HandleInternalError(c *fiber.Ctx, err error, operation string) error {
	ctx := GetErrorContext(c)
	
	appErr := errors.Internal(ErrMsgInternalError).
		WithRequest(ctx.RequestID)

	if err != nil {
		appErr = appErr.WithDetails(err.Error())
	}

	appErr = appErr.WithContext("path", ctx.Path).
		WithContext("method", ctx.Method)
	
	if operation != "" {
		appErr = appErr.WithContext("operation", operation)
	}
	
	if ctx.UserID != "" {
		appErr = appErr.WithContext("user_id", ctx.UserID)
	}

	return appErr
}

// HandleBusinessLogicError creates a standardized business logic error response
func HandleBusinessLogicError(c *fiber.Ctx, message string, code errors.ErrorCode) error {
	ctx := GetErrorContext(c)
	
	appErr := errors.NewAppError(code, message).WithRequest(ctx.RequestID)
	
	if ctx.UserID != "" {
		appErr = appErr.WithContext("user_id", ctx.UserID).
			WithContext("path", ctx.Path).
			WithContext("method", ctx.Method)
	}

	return appErr
}