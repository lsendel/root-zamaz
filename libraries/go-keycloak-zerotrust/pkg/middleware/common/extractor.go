// Package common provides shared utilities for middleware implementations
package common

import (
	"net/http"
	"strings"
)

// TokenExtractor provides common token extraction logic for all middleware implementations
type TokenExtractor struct {
	TokenHeader string
}

// NewTokenExtractor creates a new token extractor with the specified header
func NewTokenExtractor(tokenHeader string) *TokenExtractor {
	if tokenHeader == "" {
		tokenHeader = "Authorization"
	}
	return &TokenExtractor{
		TokenHeader: tokenHeader,
	}
}

// ExtractFromHTTPRequest extracts token from HTTP request using multiple fallback methods
func (te *TokenExtractor) ExtractFromHTTPRequest(r *http.Request) string {
	// Method 1: Extract from Authorization header
	if token := te.extractFromAuthHeader(r); token != "" {
		return token
	}
	
	// Method 2: Extract from query parameter
	if token := te.extractFromQuery(r); token != "" {
		return token
	}
	
	// Method 3: Extract from cookie
	if token := te.extractFromCookie(r); token != "" {
		return token
	}
	
	return ""
}

// ExtractFromHeader extracts token from any header
func (te *TokenExtractor) ExtractFromHeader(headerValue string) string {
	if headerValue == "" {
		return ""
	}
	
	// Support both "Bearer token" and "token" formats
	if strings.HasPrefix(headerValue, "Bearer ") {
		return strings.TrimPrefix(headerValue, "Bearer ")
	}
	
	return headerValue
}

// ExtractFromQueryParam extracts token from query parameter
func (te *TokenExtractor) ExtractFromQueryParam(queryValue string) string {
	return strings.TrimSpace(queryValue)
}

// ExtractFromCookie extracts token from cookie value
func (te *TokenExtractor) ExtractFromCookie(cookieValue string) string {
	return strings.TrimSpace(cookieValue)
}

// extractFromAuthHeader extracts token from Authorization header
func (te *TokenExtractor) extractFromAuthHeader(r *http.Request) string {
	authHeader := r.Header.Get(te.TokenHeader)
	return te.ExtractFromHeader(authHeader)
}

// extractFromQuery extracts token from query parameters
func (te *TokenExtractor) extractFromQuery(r *http.Request) string {
	// Try common query parameter names
	queryParams := []string{"token", "access_token", "auth_token", "jwt"}
	
	for _, param := range queryParams {
		if token := r.URL.Query().Get(param); token != "" {
			return te.ExtractFromQueryParam(token)
		}
	}
	
	return ""
}

// extractFromCookie extracts token from cookies
func (te *TokenExtractor) extractFromCookie(r *http.Request) string {
	// Try common cookie names
	cookieNames := []string{"token", "access_token", "auth_token", "jwt"}
	
	for _, name := range cookieNames {
		if cookie, err := r.Cookie(name); err == nil {
			return te.ExtractFromCookie(cookie.Value)
		}
	}
	
	return ""
}

// FrameworkTokenExtractor provides framework-specific extraction methods
type FrameworkTokenExtractor interface {
	// ExtractFromGinContext extracts token from Gin context
	ExtractFromGinContext(c interface{}) string
	
	// ExtractFromEchoContext extracts token from Echo context
	ExtractFromEchoContext(c interface{}) string
	
	// ExtractFromFiberContext extracts token from Fiber context
	ExtractFromFiberContext(c interface{}) string
	
	// ExtractFromGRPCMetadata extracts token from gRPC metadata
	ExtractFromGRPCMetadata(md interface{}) string
}

// DefaultFrameworkExtractor implements FrameworkTokenExtractor
type DefaultFrameworkExtractor struct {
	*TokenExtractor
}

// NewFrameworkExtractor creates a new framework-specific token extractor
func NewFrameworkExtractor(tokenHeader string) FrameworkTokenExtractor {
	return &DefaultFrameworkExtractor{
		TokenExtractor: NewTokenExtractor(tokenHeader),
	}
}

// ExtractFromGinContext extracts token from Gin context
func (fe *DefaultFrameworkExtractor) ExtractFromGinContext(c interface{}) string {
	// Import gin only when needed to avoid dependency issues
	type ginContext interface {
		GetHeader(string) string
		Query(string) string
		Cookie(string) (string, error)
	}
	
	if ctx, ok := c.(ginContext); ok {
		// Try header first
		if token := fe.ExtractFromHeader(ctx.GetHeader(fe.TokenHeader)); token != "" {
			return token
		}
		
		// Try query parameters
		queryParams := []string{"token", "access_token", "auth_token", "jwt"}
		for _, param := range queryParams {
			if token := fe.ExtractFromQueryParam(ctx.Query(param)); token != "" {
				return token
			}
		}
		
		// Try cookies
		cookieNames := []string{"token", "access_token", "auth_token", "jwt"}
		for _, name := range cookieNames {
			if cookie, err := ctx.Cookie(name); err == nil {
				return fe.ExtractFromCookie(cookie)
			}
		}
	}
	
	return ""
}

// ExtractFromEchoContext extracts token from Echo context
func (fe *DefaultFrameworkExtractor) ExtractFromEchoContext(c interface{}) string {
	type echoContext interface {
		Request() *http.Request
	}
	
	if ctx, ok := c.(echoContext); ok {
		return fe.ExtractFromHTTPRequest(ctx.Request())
	}
	
	return ""
}

// ExtractFromFiberContext extracts token from Fiber context
func (fe *DefaultFrameworkExtractor) ExtractFromFiberContext(c interface{}) string {
	type fiberContext interface {
		Get(string) string
		Query(string) string
		Cookies(string) string
	}
	
	if ctx, ok := c.(fiberContext); ok {
		// Try header first
		if token := fe.ExtractFromHeader(ctx.Get(fe.TokenHeader)); token != "" {
			return token
		}
		
		// Try query parameters
		queryParams := []string{"token", "access_token", "auth_token", "jwt"}
		for _, param := range queryParams {
			if token := fe.ExtractFromQueryParam(ctx.Query(param)); token != "" {
				return token
			}
		}
		
		// Try cookies
		cookieNames := []string{"token", "access_token", "auth_token", "jwt"}
		for _, name := range cookieNames {
			if token := fe.ExtractFromCookie(ctx.Cookies(name)); token != "" {
				return token
			}
		}
	}
	
	return ""
}

// ExtractFromGRPCMetadata extracts token from gRPC metadata
func (fe *DefaultFrameworkExtractor) ExtractFromGRPCMetadata(md interface{}) string {
	type metadata interface {
		Get(string) []string
	}
	
	if meta, ok := md.(metadata); ok {
		// Try authorization header
		if values := meta.Get("authorization"); len(values) > 0 {
			return fe.ExtractFromHeader(values[0])
		}
		
		// Try token header
		if values := meta.Get("token"); len(values) > 0 {
			return fe.ExtractFromHeader(values[0])
		}
	}
	
	return ""
}