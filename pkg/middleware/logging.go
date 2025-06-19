// Package middleware provides request/response logging functionality with structured logging support.
package middleware

import (
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"mvp.local/pkg/observability"
)

// LoggingConfig holds configuration for logging middleware
type LoggingConfig struct {
	// Request logging
	LogRequests       bool `default:"true"`
	LogRequestHeaders bool `default:"false"`
	LogRequestBody    bool `default:"false"`
	MaxBodySize       int  `default:"1024"` // Maximum body size to log in bytes

	// Response logging
	LogResponses       bool `default:"true"`
	LogResponseHeaders bool `default:"false"`
	LogResponseBody    bool `default:"false"`
	
	// Performance logging
	LogSlowRequests    bool          `default:"true"`
	SlowRequestThreshold time.Duration `default:"1s"`

	// Security logging
	LogFailedRequests  bool `default:"true"`
	LogSuspiciousRequests bool `default:"true"`

	// Filtering
	SkipPaths         []string // Paths to skip logging (e.g., /health, /metrics)
	SkipMethods       []string // Methods to skip
	SensitiveHeaders  []string // Headers to redact
	SensitiveParams   []string // Query parameters to redact
	
	// Privacy
	RedactSensitiveData bool `default:"true"`
	LogClientIP         bool `default:"true"`
	LogUserAgent        bool `default:"true"`
}

// DefaultLoggingConfig returns default logging configuration
func DefaultLoggingConfig() LoggingConfig {
	return LoggingConfig{
		LogRequests:           true,
		LogRequestHeaders:     false,
		LogRequestBody:        false,
		MaxBodySize:           1024,
		LogResponses:          true,
		LogResponseHeaders:    false,
		LogResponseBody:       false,
		LogSlowRequests:       true,
		SlowRequestThreshold:  time.Second,
		LogFailedRequests:     true,
		LogSuspiciousRequests: true,
		SkipPaths: []string{
			"/health",
			"/metrics",
			"/favicon.ico",
		},
		SkipMethods: []string{},
		SensitiveHeaders: []string{
			"authorization",
			"cookie",
			"set-cookie",
			"x-api-key",
			"x-auth-token",
		},
		SensitiveParams: []string{
			"password",
			"token",
			"secret",
			"key",
		},
		RedactSensitiveData: true,
		LogClientIP:         true,
		LogUserAgent:        true,
	}
}

// RequestLogEntry represents a structured log entry for requests
type RequestLogEntry struct {
	RequestID     string                 `json:"request_id,omitempty"`
	Method        string                 `json:"method"`
	Path          string                 `json:"path"`
	Query         string                 `json:"query,omitempty"`
	ClientIP      string                 `json:"client_ip,omitempty"`
	UserAgent     string                 `json:"user_agent,omitempty"`
	ContentLength int64                  `json:"content_length,omitempty"`
	Headers       map[string]string      `json:"headers,omitempty"`
	Body          string                 `json:"body,omitempty"`
	UserID        string                 `json:"user_id,omitempty"`
	TenantID      string                 `json:"tenant_id,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// ResponseLogEntry represents a structured log entry for responses
type ResponseLogEntry struct {
	RequestID     string                 `json:"request_id,omitempty"`
	StatusCode    int                    `json:"status_code"`
	ContentLength int64                  `json:"content_length,omitempty"`
	Duration      time.Duration          `json:"duration"`
	Headers       map[string]string      `json:"headers,omitempty"`
	Body          string                 `json:"body,omitempty"`
	Error         string                 `json:"error,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// LoggingMiddleware creates a new request/response logging middleware
func LoggingMiddleware(obs *observability.Observability, config ...LoggingConfig) fiber.Handler {
	cfg := DefaultLoggingConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	return func(c *fiber.Ctx) error {
		// Skip if path is in skip list
		if shouldSkipPath(c.Path(), cfg.SkipPaths) {
			return c.Next()
		}

		// Skip if method is in skip list
		if shouldSkipMethod(c.Method(), cfg.SkipMethods) {
			return c.Next()
		}

		start := time.Now()
		
		// Get request ID
		requestID := getRequestID(c)

		// Log request if enabled
		if cfg.LogRequests {
			logRequest(obs, c, cfg, requestID)
		}

		// Capture response body if needed
		// Execute next handlers
		if err := c.Next(); err != nil {
			// Log error response
			if cfg.LogFailedRequests {
				logErrorResponse(obs, c, cfg, requestID, start, err)
			}
			return err
		}
		
		// For now, we'll skip response body logging due to Fiber limitations
		// TODO: Implement response body capture using Fiber's built-in mechanisms
		var responseBody []byte

		duration := time.Since(start)

		// Log response if enabled
		if cfg.LogResponses {
			logResponse(obs, c, cfg, requestID, duration, responseBody)
		}

		// Log slow requests if enabled
		if cfg.LogSlowRequests && duration > cfg.SlowRequestThreshold {
			logSlowRequest(obs, c, requestID, duration)
		}

		// Log suspicious requests if enabled
		if cfg.LogSuspiciousRequests {
			if isSuspiciousRequest(c) {
				logSuspiciousRequest(obs, c, requestID)
			}
		}

		return nil
	}
}

// logRequest logs incoming request details
func logRequest(obs *observability.Observability, c *fiber.Ctx, cfg LoggingConfig, requestID string) {
	entry := RequestLogEntry{
		RequestID:     requestID,
		Method:        c.Method(),
		Path:          c.Path(),
		Query:         sanitizeQuery(c.OriginalURL(), cfg),
		ContentLength: int64(len(c.Body())),
		Timestamp:     time.Now(),
	}

	// Add client IP if enabled
	if cfg.LogClientIP {
		entry.ClientIP = c.IP()
	}

	// Add user agent if enabled
	if cfg.LogUserAgent {
		entry.UserAgent = c.Get("User-Agent")
	}

	// Add headers if enabled
	if cfg.LogRequestHeaders {
		entry.Headers = sanitizeHeaders(convertHeadersToStringMap(c.GetReqHeaders()), cfg)
	}

	// Add body if enabled and within size limit
	if cfg.LogRequestBody && len(c.Body()) > 0 && len(c.Body()) <= cfg.MaxBodySize {
		if isJSONContent(c.Get("Content-Type")) {
			entry.Body = sanitizeBody(string(c.Body()), cfg)
		}
	}

	// Add user context if available
	if userID := getUserIDFromContext(c); userID != "" {
		entry.UserID = userID
	}

	// Add tenant context if available
	if tenantID := getTenantIDFromContext(c); tenantID != "" {
		entry.TenantID = tenantID
	}

	obs.Logger.Info().
		Interface("request", entry).
		Msg("HTTP request")
}

// logResponse logs outgoing response details
func logResponse(obs *observability.Observability, c *fiber.Ctx, cfg LoggingConfig, requestID string, duration time.Duration, responseBody []byte) {
	entry := ResponseLogEntry{
		RequestID:     requestID,
		StatusCode:    c.Response().StatusCode(),
		ContentLength: int64(len(c.Response().Body())),
		Duration:      duration,
		Timestamp:     time.Now(),
	}

	// Add headers if enabled
	if cfg.LogResponseHeaders {
		entry.Headers = sanitizeResponseHeaders(convertHeadersToStringMap(c.GetRespHeaders()), cfg)
	}

	// Add body if enabled and available
	if cfg.LogResponseBody && len(responseBody) > 0 && len(responseBody) <= cfg.MaxBodySize {
		if isJSONContent(c.Get("Content-Type")) {
			entry.Body = sanitizeBody(string(responseBody), cfg)
		}
	}

	// Choose log level based on status code
	logEvent := obs.Logger.Info()
	if entry.StatusCode >= 400 && entry.StatusCode < 500 {
		logEvent = obs.Logger.Warn()
	} else if entry.StatusCode >= 500 {
		logEvent = obs.Logger.Error()
	}

	logEvent.
		Interface("response", entry).
		Msg("HTTP response")
}

// logErrorResponse logs error responses
func logErrorResponse(obs *observability.Observability, c *fiber.Ctx, cfg LoggingConfig, requestID string, start time.Time, err error) {
	entry := ResponseLogEntry{
		RequestID:  requestID,
		StatusCode: c.Response().StatusCode(),
		Duration:   time.Since(start),
		Error:      err.Error(),
		Timestamp:  time.Now(),
	}

	obs.Logger.Error().
		Interface("response", entry).
		Msg("HTTP error response")
}

// logSlowRequest logs requests that exceed the slow threshold
func logSlowRequest(obs *observability.Observability, c *fiber.Ctx, requestID string, duration time.Duration) {
	obs.Logger.Warn().
		Str("request_id", requestID).
		Str("method", c.Method()).
		Str("path", c.Path()).
		Dur("duration", duration).
		Msg("Slow request detected")
}

// logSuspiciousRequest logs potentially suspicious requests
func logSuspiciousRequest(obs *observability.Observability, c *fiber.Ctx, requestID string) {
	obs.Logger.Warn().
		Str("request_id", requestID).
		Str("method", c.Method()).
		Str("path", c.Path()).
		Str("client_ip", c.IP()).
		Str("user_agent", c.Get("User-Agent")).
		Msg("Suspicious request detected")
}

// Helper functions

// getRequestID extracts request ID from context
func getRequestID(c *fiber.Ctx) string {
	if id := c.Get("X-Request-ID"); id != "" {
		return id
	}
	if id := c.Get("X-Correlation-ID"); id != "" {
		return id
	}
	if id := c.Locals("request_id"); id != nil {
		if idStr, ok := id.(string); ok {
			return idStr
		}
	}
	return ""
}

// getUserIDFromContext extracts user ID from context
func getUserIDFromContext(c *fiber.Ctx) string {
	if userID := c.Locals("user_id"); userID != nil {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	return ""
}

// getTenantIDFromContext extracts tenant ID from context
func getTenantIDFromContext(c *fiber.Ctx) string {
	if tenantID := c.Locals("tenant_id"); tenantID != nil {
		if id, ok := tenantID.(string); ok {
			return id
		}
	}
	return ""
}

// shouldSkipPath checks if a path should be skipped
func shouldSkipPath(path string, skipPaths []string) bool {
	for _, skipPath := range skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// shouldSkipMethod checks if a method should be skipped
func shouldSkipMethod(method string, skipMethods []string) bool {
	for _, skipMethod := range skipMethods {
		if strings.EqualFold(method, skipMethod) {
			return true
		}
	}
	return false
}

// convertHeadersToStringMap converts map[string][]string to map[string]string
func convertHeadersToStringMap(headers map[string][]string) map[string]string {
	result := make(map[string]string)
	for key, values := range headers {
		if len(values) > 0 {
			// Join multiple values with comma (HTTP standard)
			result[key] = strings.Join(values, ", ")
		}
	}
	return result
}

// sanitizeHeaders removes or redacts sensitive headers
func sanitizeHeaders(headers map[string]string, cfg LoggingConfig) map[string]string {
	if !cfg.RedactSensitiveData {
		return headers
	}

	sanitized := make(map[string]string)
	for key, value := range headers {
		if isSensitiveHeader(key, cfg.SensitiveHeaders) {
			sanitized[key] = "[REDACTED]"
		} else {
			sanitized[key] = value
		}
	}
	return sanitized
}

// sanitizeResponseHeaders removes or redacts sensitive response headers
func sanitizeResponseHeaders(headers map[string]string, cfg LoggingConfig) map[string]string {
	return sanitizeHeaders(headers, cfg) // Use same logic as request headers
}

// sanitizeQuery removes or redacts sensitive query parameters
func sanitizeQuery(url string, cfg LoggingConfig) string {
	if !cfg.RedactSensitiveData {
		return url
	}

	// Simple redaction - in production, you might want more sophisticated parsing
	for _, param := range cfg.SensitiveParams {
		if strings.Contains(url, param+"=") {
			return strings.ReplaceAll(url, param+"=", param+"=[REDACTED]")
		}
	}
	return url
}

// sanitizeBody removes or redacts sensitive data from request/response body
func sanitizeBody(body string, cfg LoggingConfig) string {
	if !cfg.RedactSensitiveData {
		return body
	}

	// Simple redaction for JSON - in production, you might want JSON parsing
	for _, field := range cfg.SensitiveParams {
		pattern := fmt.Sprintf(`"%s"\s*:\s*"[^"]*"`, field)
		replacement := fmt.Sprintf(`"%s": "[REDACTED]"`, field)
		body = strings.ReplaceAll(body, pattern, replacement)
	}
	return body
}

// isSensitiveHeader checks if a header is considered sensitive
func isSensitiveHeader(header string, sensitiveHeaders []string) bool {
	headerLower := strings.ToLower(header)
	for _, sensitive := range sensitiveHeaders {
		if headerLower == strings.ToLower(sensitive) {
			return true
		}
	}
	return false
}

// isJSONContent checks if content type is JSON
func isJSONContent(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "application/json")
}

// isSuspiciousRequest checks if a request might be suspicious
func isSuspiciousRequest(c *fiber.Ctx) bool {
	userAgent := strings.ToLower(c.Get("User-Agent"))
	
	// Check for suspicious user agents
	suspiciousAgents := []string{
		"sqlmap",
		"nikto",
		"nessus",
		"burp",
		"zap",
		"masscan",
		"nmap",
	}
	
	for _, agent := range suspiciousAgents {
		if strings.Contains(userAgent, agent) {
			return true
		}
	}

	// Check for suspicious paths
	path := strings.ToLower(c.Path())
	suspiciousPaths := []string{
		"../",
		"..\\",
		"/etc/passwd",
		"/proc/",
		"wp-admin",
		"phpmyadmin",
		".env",
		"config.php",
	}
	
	for _, suspPath := range suspiciousPaths {
		if strings.Contains(path, suspPath) {
			return true
		}
	}

	return false
}