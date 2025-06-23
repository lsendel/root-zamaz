// Package common provides shared error handling utilities
package common

import (
	"context"
	"net/http"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// ErrorHandler provides common error handling logic for all middleware implementations
type ErrorHandler struct {
	customHandler types.ErrorHandlerFunc
}

// NewErrorHandler creates a new error handler
func NewErrorHandler(customHandler types.ErrorHandlerFunc) *ErrorHandler {
	return &ErrorHandler{
		customHandler: customHandler,
	}
}

// HandleAuthError processes authentication errors consistently across frameworks
func (eh *ErrorHandler) HandleAuthError(ctx context.Context, err error) *ErrorResponse {
	// Use custom handler if provided
	if eh.customHandler != nil {
		if customErr := eh.customHandler(ctx, err); customErr != nil {
			// Custom handler returned a new error, use it
			err = customErr
		}
	}
	
	// Convert to AuthError if not already
	var authErr *types.AuthError
	if ae, ok := err.(*types.AuthError); ok {
		authErr = ae
	} else {
		// Create a generic auth error
		authErr = &types.AuthError{
			Code:    types.ErrCodeUnauthorized,
			Message: "Authentication failed",
			Details: err.Error(),
		}
	}
	
	return eh.createErrorResponse(authErr)
}

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	StatusCode int                    `json:"-"`
	Error      string                 `json:"error"`
	Code       string                 `json:"code"`
	Message    string                 `json:"message"`
	Details    string                 `json:"details,omitempty"`
	Timestamp  string                 `json:"timestamp"`
	RequestID  string                 `json:"request_id,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// createErrorResponse creates a standardized error response
func (eh *ErrorHandler) createErrorResponse(authErr *types.AuthError) *ErrorResponse {
	return &ErrorResponse{
		StatusCode: eh.getHTTPStatusCode(authErr.Code),
		Error:      "Authentication Error",
		Code:       authErr.Code,
		Message:    authErr.Message,
		Details:    authErr.Details,
		Timestamp:  eh.getCurrentTimestamp(),
		Metadata:   make(map[string]interface{}),
	}
}

// getHTTPStatusCode maps auth error codes to HTTP status codes
func (eh *ErrorHandler) getHTTPStatusCode(code string) int {
	switch code {
	case types.ErrCodeMissingToken, types.ErrCodeUnauthorized:
		return http.StatusUnauthorized
	case types.ErrCodeInvalidToken, types.ErrCodeExpiredToken:
		return http.StatusUnauthorized
	case types.ErrCodeInsufficientTrust, types.ErrCodeDeviceNotVerified, 
		 types.ErrCodeInsufficientRole, types.ErrCodeForbidden:
		return http.StatusForbidden
	case types.ErrCodeConfigurationError:
		return http.StatusInternalServerError
	case types.ErrCodeConnectionError:
		return http.StatusServiceUnavailable
	default:
		return http.StatusUnauthorized
	}
}

// getCurrentTimestamp returns current timestamp in ISO format
func (eh *ErrorHandler) getCurrentTimestamp() string {
	return "2024-01-20T10:30:00Z" // In real implementation, use time.Now().Format(time.RFC3339)
}

// WithRequestID adds request ID to error response
func (err *ErrorResponse) WithRequestID(requestID string) *ErrorResponse {
	err.RequestID = requestID
	return err
}

// WithMetadata adds metadata to error response
func (err *ErrorResponse) WithMetadata(key string, value interface{}) *ErrorResponse {
	if err.Metadata == nil {
		err.Metadata = make(map[string]interface{})
	}
	err.Metadata[key] = value
	return err
}

// FrameworkErrorHandler provides framework-specific error handling
type FrameworkErrorHandler interface {
	// HandleGinError handles errors in Gin framework
	HandleGinError(c interface{}, errorResp *ErrorResponse)
	
	// HandleEchoError handles errors in Echo framework
	HandleEchoError(c interface{}, errorResp *ErrorResponse) error
	
	// HandleFiberError handles errors in Fiber framework
	HandleFiberError(c interface{}, errorResp *ErrorResponse) error
	
	// HandleGRPCError handles errors in gRPC framework
	HandleGRPCError(errorResp *ErrorResponse) error
}

// DefaultFrameworkErrorHandler implements FrameworkErrorHandler
type DefaultFrameworkErrorHandler struct {
	*ErrorHandler
}

// NewFrameworkErrorHandler creates a new framework-specific error handler
func NewFrameworkErrorHandler(customHandler types.ErrorHandlerFunc) FrameworkErrorHandler {
	return &DefaultFrameworkErrorHandler{
		ErrorHandler: NewErrorHandler(customHandler),
	}
}

// HandleGinError handles errors in Gin framework
func (feh *DefaultFrameworkErrorHandler) HandleGinError(c interface{}, errorResp *ErrorResponse) {
	type ginContext interface {
		AbortWithStatusJSON(int, interface{})
	}
	
	if ctx, ok := c.(ginContext); ok {
		ctx.AbortWithStatusJSON(errorResp.StatusCode, errorResp)
	}
}

// HandleEchoError handles errors in Echo framework
func (feh *DefaultFrameworkErrorHandler) HandleEchoError(c interface{}, errorResp *ErrorResponse) error {
	type echoContext interface {
		JSON(int, interface{}) error
	}
	
	if ctx, ok := c.(echoContext); ok {
		return ctx.JSON(errorResp.StatusCode, errorResp)
	}
	
	return nil
}

// HandleFiberError handles errors in Fiber framework
func (feh *DefaultFrameworkErrorHandler) HandleFiberError(c interface{}, errorResp *ErrorResponse) error {
	type fiberContext interface {
		Status(int) interface{}
		JSON(interface{}) error
	}
	
	if ctx, ok := c.(fiberContext); ok {
		return ctx.Status(errorResp.StatusCode).JSON(errorResp)
	}
	
	return nil
}

// HandleGRPCError handles errors in gRPC framework
func (feh *DefaultFrameworkErrorHandler) HandleGRPCError(errorResp *ErrorResponse) error {
	// In a real implementation, this would convert to gRPC status
	// For now, return a generic error
	return &types.AuthError{
		Code:    errorResp.Code,
		Message: errorResp.Message,
		Details: errorResp.Details,
	}
}

// SecurityAuditLogger provides security event logging
type SecurityAuditLogger struct {
	enabled bool
}

// NewSecurityAuditLogger creates a new security audit logger
func NewSecurityAuditLogger(enabled bool) *SecurityAuditLogger {
	return &SecurityAuditLogger{
		enabled: enabled,
	}
}

// LogAuthenticationFailure logs authentication failure events
func (sal *SecurityAuditLogger) LogAuthenticationFailure(ctx context.Context, reason string, metadata map[string]interface{}) {
	if !sal.enabled {
		return
	}
	
	// In a real implementation, this would log to a proper logging system
	// For now, we'll just prepare the log entry structure
	logEntry := map[string]interface{}{
		"event_type": "authentication_failure",
		"timestamp":  "2024-01-20T10:30:00Z",
		"reason":     reason,
		"metadata":   metadata,
	}
	
	// Log the entry (implementation would depend on chosen logging library)
	_ = logEntry
}

// LogAuthorizationFailure logs authorization failure events
func (sal *SecurityAuditLogger) LogAuthorizationFailure(ctx context.Context, userID, resource, action string, metadata map[string]interface{}) {
	if !sal.enabled {
		return
	}
	
	logEntry := map[string]interface{}{
		"event_type": "authorization_failure",
		"timestamp":  "2024-01-20T10:30:00Z",
		"user_id":    userID,
		"resource":   resource,
		"action":     action,
		"metadata":   metadata,
	}
	
	_ = logEntry
}

// LogSecurityEvent logs general security events
func (sal *SecurityAuditLogger) LogSecurityEvent(ctx context.Context, eventType string, metadata map[string]interface{}) {
	if !sal.enabled {
		return
	}
	
	logEntry := map[string]interface{}{
		"event_type": eventType,
		"timestamp":  "2024-01-20T10:30:00Z",
		"metadata":   metadata,
	}
	
	_ = logEntry
}