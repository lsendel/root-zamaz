package sdk

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// MiddlewareConfig holds configuration for authentication middleware
type MiddlewareConfig struct {
	// Client is the SDK client for token validation
	Client *Client

	// RequiredScopes are the scopes required for access
	RequiredScopes []string

	// RequiredRoles are the roles required for access
	RequiredRoles []string

	// SkipPaths are paths that skip authentication
	SkipPaths []string

	// ErrorHandler handles authentication errors
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

	// SuccessHandler is called after successful authentication
	SuccessHandler func(w http.ResponseWriter, r *http.Request, claims *Claims)

	// ContextKey is the key used to store claims in request context
	ContextKey string
}

// AuthMiddleware returns HTTP middleware for Zero Trust authentication
func AuthMiddleware(config MiddlewareConfig) func(http.Handler) http.Handler {
	if config.ContextKey == "" {
		config.ContextKey = "auth_claims"
	}

	if config.ErrorHandler == nil {
		config.ErrorHandler = defaultErrorHandler
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path should skip authentication
			for _, skipPath := range config.SkipPaths {
				if strings.HasPrefix(r.URL.Path, skipPath) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Extract token from Authorization header
			token := extractTokenFromHeader(r)
			if token == "" {
				config.ErrorHandler(w, r, &APIError{
					Code:    "MISSING_TOKEN",
					Message: "Authorization token is required",
				})
				return
			}

			// Validate token
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()

			validationResp, err := config.Client.ValidateToken(ctx, TokenValidationRequest{
				Token:          token,
				RequiredScopes: config.RequiredScopes,
			})
			if err != nil {
				config.ErrorHandler(w, r, err)
				return
			}

			if !validationResp.Valid {
				config.ErrorHandler(w, r, &APIError{
					Code:    "INVALID_TOKEN",
					Message: "Token is invalid or expired",
				})
				return
			}

			// Check required roles
			if len(config.RequiredRoles) > 0 {
				if !hasRequiredRoles(validationResp.Roles, config.RequiredRoles) {
					config.ErrorHandler(w, r, &APIError{
						Code:    "INSUFFICIENT_PERMISSIONS",
						Message: "User does not have required roles",
					})
					return
				}
			}

			// Store claims in context
			ctx = context.WithValue(r.Context(), config.ContextKey, validationResp.Claims)
			r = r.WithContext(ctx)

			// Call success handler if provided
			if config.SuccessHandler != nil {
				config.SuccessHandler(w, r, validationResp.Claims)
			}

			// Continue to next handler
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRoles returns middleware that requires specific roles
func RequireRoles(client *Client, roles ...string) func(http.Handler) http.Handler {
	return AuthMiddleware(MiddlewareConfig{
		Client:        client,
		RequiredRoles: roles,
	})
}

// RequireScopes returns middleware that requires specific scopes
func RequireScopes(client *Client, scopes ...string) func(http.Handler) http.Handler {
	return AuthMiddleware(MiddlewareConfig{
		Client:         client,
		RequiredScopes: scopes,
	})
}

// GetClaimsFromContext extracts authentication claims from request context
func GetClaimsFromContext(ctx context.Context) (*Claims, bool) {
	return GetClaimsFromContextWithKey(ctx, "auth_claims")
}

// GetClaimsFromContextWithKey extracts authentication claims from request context with custom key
func GetClaimsFromContextWithKey(ctx context.Context, key string) (*Claims, bool) {
	claims, ok := ctx.Value(key).(*Claims)
	return claims, ok
}

// GetUserIDFromContext extracts user ID from request context
func GetUserIDFromContext(ctx context.Context) (string, bool) {
	claims, ok := GetClaimsFromContext(ctx)
	if !ok {
		return "", false
	}
	return claims.Subject, true
}

// extractTokenFromHeader extracts Bearer token from Authorization header
func extractTokenFromHeader(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}

// hasRequiredRoles checks if user has all required roles
func hasRequiredRoles(userRoles, requiredRoles []string) bool {
	roleMap := make(map[string]bool)
	for _, role := range userRoles {
		roleMap[role] = true
	}

	for _, required := range requiredRoles {
		if !roleMap[required] {
			return false
		}
	}

	return true
}

// defaultErrorHandler is the default error handler for authentication failures
func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")

	status := http.StatusUnauthorized
	message := "Authentication failed"

	if apiErr, ok := err.(*APIError); ok {
		switch apiErr.Code {
		case "MISSING_TOKEN":
			status = http.StatusUnauthorized
		case "INVALID_TOKEN":
			status = http.StatusUnauthorized
		case "INSUFFICIENT_PERMISSIONS":
			status = http.StatusForbidden
		default:
			status = http.StatusInternalServerError
		}
		message = apiErr.Message
	}

	w.WriteHeader(status)
	w.Write([]byte(`{"error":"` + message + `"}`))
}
