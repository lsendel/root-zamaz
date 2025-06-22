package auth

import (
	"context"
	"fmt"
	
	"mvp.local/pkg/errors"
	"mvp.local/pkg/observability"
)

// SecureErrorHandler provides secure error messages while logging detailed information
type SecureErrorHandler struct {
	obs *observability.Observability
}

// NewSecureErrorHandler creates a new secure error handler
func NewSecureErrorHandler(obs *observability.Observability) *SecureErrorHandler {
	return &SecureErrorHandler{
		obs: obs,
	}
}

// PermissionDeniedError creates a secure permission denied error
// It returns a generic error to the client while logging detailed information
func (h *SecureErrorHandler) PermissionDeniedError(ctx context.Context, userID, action, resource string) error {
	// Log detailed information for internal debugging and audit
	if h.obs != nil {
		h.obs.Logger.Warn().
			Str("user_id", userID).
			Str("action", action).
			Str("resource", resource).
			Str("request_id", getRequestID(ctx)).
			Msg("Permission denied for user")
	}
	
	// Return generic error message that doesn't expose internal details
	return errors.Forbidden("Permission denied for the requested operation")
}

// AuthenticationFailedError creates a secure authentication error
func (h *SecureErrorHandler) AuthenticationFailedError(ctx context.Context, username, reason string) error {
	// Log detailed information
	if h.obs != nil {
		h.obs.Logger.Warn().
			Str("username", username).
			Str("reason", reason).
			Str("request_id", getRequestID(ctx)).
			Msg("Authentication failed")
	}
	
	// Return generic error
	return errors.Unauthorized("Authentication failed")
}

// ResourceNotFoundError creates a secure not found error
func (h *SecureErrorHandler) ResourceNotFoundError(ctx context.Context, resourceType, resourceID string) error {
	// Log detailed information
	if h.obs != nil {
		h.obs.Logger.Debug().
			Str("resource_type", resourceType).
			Str("resource_id", resourceID).
			Str("request_id", getRequestID(ctx)).
			Msg("Resource not found")
	}
	
	// Return generic error
	return errors.NotFound("Requested resource not found")
}

// InvalidOperationError creates a secure validation error
func (h *SecureErrorHandler) InvalidOperationError(ctx context.Context, operation, details string) error {
	// Log detailed information
	if h.obs != nil {
		h.obs.Logger.Warn().
			Str("operation", operation).
			Str("details", details).
			Str("request_id", getRequestID(ctx)).
			Msg("Invalid operation attempted")
	}
	
	// Return generic error
	return errors.Validation("Invalid operation")
}

// SecurityEventError logs a security event and returns a generic error
func (h *SecureErrorHandler) SecurityEventError(ctx context.Context, eventType, userID, details string) error {
	// Log as security event with high priority
	if h.obs != nil {
		h.obs.Logger.Error().
			Str("event_type", eventType).
			Str("user_id", userID).
			Str("details", details).
			Str("request_id", getRequestID(ctx)).
			Msg("Security event detected")
	}
	
	// Return generic error
	return errors.Forbidden("Security policy violation")
}

// getRequestID extracts request ID from context
func getRequestID(ctx context.Context) string {
	if ctx == nil {
		return "unknown"
	}
	
	// Try common request ID keys
	if reqID, ok := ctx.Value("request_id").(string); ok {
		return reqID
	}
	if reqID, ok := ctx.Value("requestID").(string); ok {
		return reqID
	}
	if reqID, ok := ctx.Value("X-Request-ID").(string); ok {
		return reqID
	}
	
	return "unknown"
}

// ErrorCode represents standardized error codes for consistent error handling
type ErrorCode string

const (
	// Client errors (4xx)
	ErrCodeAuthenticationRequired ErrorCode = "AUTH_REQUIRED"
	ErrCodePermissionDenied      ErrorCode = "PERMISSION_DENIED"
	ErrCodeResourceNotFound      ErrorCode = "RESOURCE_NOT_FOUND"
	ErrCodeInvalidRequest        ErrorCode = "INVALID_REQUEST"
	ErrCodeRateLimitExceeded     ErrorCode = "RATE_LIMIT_EXCEEDED"
	
	// Security errors
	ErrCodeSecurityViolation     ErrorCode = "SECURITY_VIOLATION"
	ErrCodeAccountLocked         ErrorCode = "ACCOUNT_LOCKED"
	ErrCodeSessionExpired        ErrorCode = "SESSION_EXPIRED"
	ErrCodeInvalidCredentials    ErrorCode = "INVALID_CREDENTIALS"
	ErrCodeTrustLevelInsufficient ErrorCode = "TRUST_LEVEL_INSUFFICIENT"
)

// StandardError represents a standardized error response
type StandardError struct {
	Code      ErrorCode `json:"code"`
	Message   string    `json:"message"`
	RequestID string    `json:"request_id,omitempty"`
}

// CreateStandardError creates a standardized error response
func (h *SecureErrorHandler) CreateStandardError(ctx context.Context, code ErrorCode, publicMessage string) *StandardError {
	return &StandardError{
		Code:      code,
		Message:   publicMessage,
		RequestID: getRequestID(ctx),
	}
}

// LogAndReturnError logs detailed error information and returns a secure error
func (h *SecureErrorHandler) LogAndReturnError(ctx context.Context, err error, code ErrorCode, publicMessage string, details map[string]interface{}) error {
	if h.obs != nil {
		logger := h.obs.Logger.Error().
			Err(err).
			Str("error_code", string(code)).
			Str("request_id", getRequestID(ctx))
		
		// Add all details to the log
		for key, value := range details {
			logger = logger.Interface(key, value)
		}
		
		logger.Msg("Error occurred during operation")
	}
	
	// Return generic public message
	switch code {
	case ErrCodeAuthenticationRequired, ErrCodeInvalidCredentials, ErrCodeSessionExpired:
		return errors.Unauthorized(publicMessage)
	case ErrCodePermissionDenied, ErrCodeSecurityViolation, ErrCodeAccountLocked, ErrCodeTrustLevelInsufficient:
		return errors.Forbidden(publicMessage)
	case ErrCodeResourceNotFound:
		return errors.NotFound(publicMessage)
	case ErrCodeInvalidRequest:
		return errors.Validation(publicMessage)
	case ErrCodeRateLimitExceeded:
		return errors.RateLimited(publicMessage)
	default:
		return errors.Internal("An error occurred")
	}
}