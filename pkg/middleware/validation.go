// Package middleware provides HTTP middleware components for request validation and sanitization.
package middleware

import (
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"strings"
	"unicode"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

// ValidationConfig holds configuration for validation middleware
type ValidationConfig struct {
	MaxBodySize       int64 `default:"1048576"` // 1MB default
	MaxJSONDepth      int   `default:"10"`
	StripHTML         bool  `default:"true"`
	TrimWhitespace    bool  `default:"true"`
	ValidateUTF8      bool  `default:"true"`
	MaxStringLength   int   `default:"1000"`
	AllowedMimeTypes  []string
	BlockedPatterns   []string
	SanitizeFields    []string
}

// DefaultValidationConfig returns default validation configuration
func DefaultValidationConfig() ValidationConfig {
	return ValidationConfig{
		MaxBodySize:     1048576, // 1MB
		MaxJSONDepth:    10,
		StripHTML:       true,
		TrimWhitespace:  true,
		ValidateUTF8:    true,
		MaxStringLength: 1000,
		AllowedMimeTypes: []string{
			"application/json",
			"application/x-www-form-urlencoded",
			"multipart/form-data",
		},
		BlockedPatterns: []string{
			`<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>`,
			`javascript:`,
			`vbscript:`,
			`on\w+\s*=`,
			`expression\s*\(`,
		},
		SanitizeFields: []string{
			"username", "email", "name", "title", "description",
		},
	}
}

var (
	validator = validator.New()
	
	// Common patterns for validation
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	phoneRegex    = regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	alphanumRegex = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	
	// Security patterns
	sqlInjectionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(union|select|insert|delete|update|drop|create|alter|exec|execute)`),
		regexp.MustCompile(`(?i)(\b(and|or)\b.*=)|(\b(and|or)\b.*\b(like|in)\b)`),
		regexp.MustCompile(`(?i)(--|#|\/\*|\*\/)`),
	}
	
	xssPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>`),
		regexp.MustCompile(`(?i)javascript:`),
		regexp.MustCompile(`(?i)vbscript:`),
		regexp.MustCompile(`(?i)on\w+\s*=`),
		regexp.MustCompile(`(?i)expression\s*\(`),
	}
)

// ValidationMiddleware creates a new validation middleware
func ValidationMiddleware(config ...ValidationConfig) fiber.Handler {
	cfg := DefaultValidationConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	return func(c *fiber.Ctx) error {
		// Check content length
		if c.Request().Header.ContentLength() > cfg.MaxBodySize {
			return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{
				"error":   "Request Entity Too Large",
				"message": fmt.Sprintf("Request body too large. Maximum size is %d bytes", cfg.MaxBodySize),
			})
		}

		// Check content type for JSON requests
		contentType := string(c.Request().Header.ContentType())
		if strings.Contains(contentType, "application/json") {
			if !isAllowedMimeType(contentType, cfg.AllowedMimeTypes) {
				return c.Status(fiber.StatusUnsupportedMediaType).JSON(fiber.Map{
					"error":   "Unsupported Media Type",
					"message": "Content type not allowed",
				})
			}

			// Validate and sanitize JSON body
			if err := validateJSONBody(c, cfg); err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":   "Invalid Request Body",
					"message": err.Error(),
				})
			}
		}

		// Validate and sanitize query parameters
		if err := validateQueryParams(c, cfg); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   "Invalid Query Parameters",
				"message": err.Error(),
			})
		}

		// Validate and sanitize headers
		if err := validateHeaders(c, cfg); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   "Invalid Headers",
				"message": err.Error(),
			})
		}

		return c.Next()
	}
}

// validateJSONBody validates and sanitizes JSON request body
func validateJSONBody(c *fiber.Ctx, cfg ValidationConfig) error {
	body := c.Body()
	if len(body) == 0 {
		return nil
	}

	// Parse JSON to check structure and depth
	var jsonData interface{}
	if err := json.Unmarshal(body, &jsonData); err != nil {
		return fmt.Errorf("invalid JSON format: %v", err)
	}

	// Check JSON depth
	if depth := getJSONDepth(jsonData); depth > cfg.MaxJSONDepth {
		return fmt.Errorf("JSON depth exceeds maximum allowed depth of %d", cfg.MaxJSONDepth)
	}

	// Sanitize JSON data
	sanitized := sanitizeJSONData(jsonData, cfg)
	
	// Check for security patterns
	if err := checkSecurityPatterns(sanitized, cfg); err != nil {
		return err
	}

	// Update the body with sanitized data
	sanitizedBody, err := json.Marshal(sanitized)
	if err != nil {
		return fmt.Errorf("failed to marshal sanitized data: %v", err)
	}

	c.Request().SetBody(sanitizedBody)
	return nil
}

// validateQueryParams validates and sanitizes query parameters
func validateQueryParams(c *fiber.Ctx, cfg ValidationConfig) error {
	queries := c.Queries()
	for key, value := range queries {
		// Validate UTF-8
		if cfg.ValidateUTF8 && !isValidUTF8(value) {
			return fmt.Errorf("invalid UTF-8 in query parameter: %s", key)
		}

		// Check string length
		if len(value) > cfg.MaxStringLength {
			return fmt.Errorf("query parameter %s exceeds maximum length", key)
		}

		// Check for security patterns
		if containsSecurityPatterns(value) {
			return fmt.Errorf("query parameter %s contains potentially malicious content", key)
		}

		// Sanitize value
		sanitized := sanitizeString(value, cfg)
		c.Request().URI().QueryArgs().Set(key, sanitized)
	}

	return nil
}

// validateHeaders validates request headers
func validateHeaders(c *fiber.Ctx, cfg ValidationConfig) error {
	// Check User-Agent
	userAgent := c.Get("User-Agent")
	if userAgent != "" {
		if cfg.ValidateUTF8 && !isValidUTF8(userAgent) {
			return fmt.Errorf("invalid UTF-8 in User-Agent header")
		}
		if containsSecurityPatterns(userAgent) {
			return fmt.Errorf("User-Agent header contains potentially malicious content")
		}
	}

	// Check Referer
	referer := c.Get("Referer")
	if referer != "" {
		if cfg.ValidateUTF8 && !isValidUTF8(referer) {
			return fmt.Errorf("invalid UTF-8 in Referer header")
		}
		if containsSecurityPatterns(referer) {
			return fmt.Errorf("Referer header contains potentially malicious content")
		}
	}

	return nil
}

// sanitizeJSONData recursively sanitizes JSON data
func sanitizeJSONData(data interface{}, cfg ValidationConfig) interface{} {
	switch v := data.(type) {
	case string:
		return sanitizeString(v, cfg)
	case map[string]interface{}:
		sanitized := make(map[string]interface{})
		for key, value := range v {
			sanitizedKey := sanitizeString(key, cfg)
			sanitized[sanitizedKey] = sanitizeJSONData(value, cfg)
		}
		return sanitized
	case []interface{}:
		sanitized := make([]interface{}, len(v))
		for i, value := range v {
			sanitized[i] = sanitizeJSONData(value, cfg)
		}
		return sanitized
	default:
		return v
	}
}

// sanitizeString sanitizes a string value
func sanitizeString(s string, cfg ValidationConfig) string {
	// Trim whitespace
	if cfg.TrimWhitespace {
		s = strings.TrimSpace(s)
	}

	// Strip HTML
	if cfg.StripHTML {
		s = html.EscapeString(s)
	}

	// Remove control characters
	s = removeControlChars(s)

	return s
}

// getJSONDepth calculates the maximum depth of a JSON structure
func getJSONDepth(data interface{}) int {
	switch v := data.(type) {
	case map[string]interface{}:
		maxDepth := 0
		for _, value := range v {
			depth := getJSONDepth(value)
			if depth > maxDepth {
				maxDepth = depth
			}
		}
		return maxDepth + 1
	case []interface{}:
		maxDepth := 0
		for _, value := range v {
			depth := getJSONDepth(value)
			if depth > maxDepth {
				maxDepth = depth
			}
		}
		return maxDepth + 1
	default:
		return 1
	}
}

// checkSecurityPatterns checks for security patterns in data
func checkSecurityPatterns(data interface{}, cfg ValidationConfig) error {
	switch v := data.(type) {
	case string:
		if containsSecurityPatterns(v) {
			return fmt.Errorf("content contains potentially malicious patterns")
		}
	case map[string]interface{}:
		for key, value := range v {
			if containsSecurityPatterns(key) {
				return fmt.Errorf("field name contains potentially malicious patterns")
			}
			if err := checkSecurityPatterns(value, cfg); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, value := range v {
			if err := checkSecurityPatterns(value, cfg); err != nil {
				return err
			}
		}
	}
	return nil
}

// containsSecurityPatterns checks if a string contains security patterns
func containsSecurityPatterns(s string) bool {
	// Check SQL injection patterns
	for _, pattern := range sqlInjectionPatterns {
		if pattern.MatchString(s) {
			return true
		}
	}

	// Check XSS patterns
	for _, pattern := range xssPatterns {
		if pattern.MatchString(s) {
			return true
		}
	}

	return false
}

// isValidUTF8 checks if a string is valid UTF-8
func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == unicode.ReplacementChar {
			return false
		}
	}
	return true
}

// removeControlChars removes control characters from a string
func removeControlChars(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return -1
		}
		return r
	}, s)
}

// isAllowedMimeType checks if a content type is allowed
func isAllowedMimeType(contentType string, allowed []string) bool {
	for _, allowedType := range allowed {
		if strings.Contains(contentType, allowedType) {
			return true
		}
	}
	return false
}

// StructValidationMiddleware validates struct fields using validator tags
func StructValidationMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// This would be used in handlers to validate specific structs
		// For now, just pass through
		return c.Next()
	}
}

// ValidateStruct validates a struct using validator tags
func ValidateStruct(s interface{}) error {
	return validator.Struct(s)
}

// ValidateEmail validates an email address
func ValidateEmail(email string) bool {
	return emailRegex.MatchString(email)
}

// ValidatePhone validates a phone number
func ValidatePhone(phone string) bool {
	return phoneRegex.MatchString(phone)
}

// ValidateAlphanumeric validates that a string contains only alphanumeric characters
func ValidateAlphanumeric(s string) bool {
	return alphanumRegex.MatchString(s)
}