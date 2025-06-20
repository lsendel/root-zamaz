package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"

	"mvp.local/pkg/errors"
	"mvp.local/pkg/security"
)

// RequestSigningMiddleware validates request signatures using the enhanced security system
func RequestSigningMiddleware(manager *security.RequestSigningManager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Skip validation if request signing is disabled
		if manager == nil || !manager.IsEnabled() {
			return c.Next()
		}

		// Convert fasthttp.Request to http.Request for the validator
		httpReq, err := convertFastHTTPToHTTP(c.Request())
		if err != nil {
			return errors.Internal("failed to convert request for signature validation").WithDetails(err.Error())
		}

		// Validate the request signature
		if err := manager.ValidateRequest(httpReq); err != nil {
			return errors.Unauthorized("request signature validation failed").WithDetails(err.Error())
		}

		return c.Next()
	}
}

// RequestSigningMiddlewareWithConfig creates middleware with optional configuration
type RequestSigningConfig struct {
	// SkipPaths contains paths that should skip signature validation
	SkipPaths []string

	// SkipMethods contains HTTP methods that should skip signature validation
	SkipMethods []string

	// OnError is called when signature validation fails (optional)
	OnError func(c *fiber.Ctx, err error) error
}

// RequestSigningMiddlewareWithConfig creates request signing middleware with configuration
func RequestSigningMiddlewareWithConfig(manager *security.RequestSigningManager, config RequestSigningConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Skip validation if request signing is disabled
		if manager == nil || !manager.IsEnabled() {
			return c.Next()
		}

		// Check if path should be skipped
		path := c.Path()
		for _, skipPath := range config.SkipPaths {
			if strings.HasPrefix(path, skipPath) {
				return c.Next()
			}
		}

		// Check if method should be skipped
		method := c.Method()
		for _, skipMethod := range config.SkipMethods {
			if strings.EqualFold(method, skipMethod) {
				return c.Next()
			}
		}

		// Convert fasthttp.Request to http.Request for the validator
		httpReq, err := convertFastHTTPToHTTP(c.Request())
		if err != nil {
			err = errors.Internal("failed to convert request for signature validation").WithDetails(err.Error())
			if config.OnError != nil {
				return config.OnError(c, err)
			}
			return err
		}

		// Validate the request signature
		if err := manager.ValidateRequest(httpReq); err != nil {
			if config.OnError != nil {
				return config.OnError(c, err)
			}
			return errors.Unauthorized("request signature validation failed").WithDetails(err.Error())
		}

		return c.Next()
	}
}

// Legacy middleware for backward compatibility
func RequestSigningMiddlewareValidator(validator *security.SignatureValidator) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Convert fasthttp.Request to http.Request for the validator
		httpReq, err := convertFastHTTPToHTTP(c.Request())
		if err != nil {
			return errors.Internal("failed to convert request for signature validation").WithDetails(err.Error())
		}

		if err := validator.Validate(httpReq); err != nil {
			return errors.Unauthorized("invalid request signature").WithDetails(err.Error())
		}
		return c.Next()
	}
}

// convertFastHTTPToHTTP converts a fasthttp.Request to http.Request with enhanced body handling
func convertFastHTTPToHTTP(fhReq *fasthttp.Request) (*http.Request, error) {
	// Parse URL
	uri := fhReq.URI()
	reqURL, err := url.Parse(string(uri.FullURI()))
	if err != nil {
		return nil, err
	}

	// Create http.Request
	httpReq := &http.Request{
		Method: string(fhReq.Header.Method()),
		URL:    reqURL,
		Header: make(http.Header),
	}

	// Copy headers
	fhReq.Header.VisitAll(func(key, value []byte) {
		httpReq.Header.Add(string(key), string(value))
	})

	// Set Host header
	if host := fhReq.Header.Host(); len(host) > 0 {
		httpReq.Host = string(host)
	} else if httpReq.URL.Host != "" {
		httpReq.Host = httpReq.URL.Host
	}

	// Set content length if available
	if contentLength := fhReq.Header.ContentLength(); contentLength > 0 {
		httpReq.ContentLength = int64(contentLength)
	}

	// Note: Remote address not available in fasthttp.Request

	return httpReq, nil
}
