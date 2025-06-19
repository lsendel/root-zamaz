// Package validation provides validation utilities and helper functions.
package validation

import (
	"regexp"
	"strings"
)

// Common validation patterns
var (
	// EmailPattern is a regex pattern for basic email validation
	EmailPattern = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	// UsernamePattern allows alphanumeric characters, underscores, and hyphens
	UsernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_\-]{3,50}$`)

	// DeviceIDPattern for device identification
	DeviceIDPattern = regexp.MustCompile(`^[a-zA-Z0-9\-]{8,64}$`)

	// SPIFFEIDPattern for SPIFFE ID validation
	SPIFFEIDPattern = regexp.MustCompile(`^spiffe://[a-zA-Z0-9\-\.]+(/[a-zA-Z0-9\-\._/]*)?$`)

	// StrongPasswordPattern for basic validation (actual complexity checked in functions)
	StrongPasswordPattern = regexp.MustCompile(`^.{8,}$`)
)

// ValidateEmail checks if an email address is valid
func ValidateEmail(email string) bool {
	return EmailPattern.MatchString(email)
}

// ValidateUsername checks if a username follows the required format
func ValidateUsername(username string) bool {
	return UsernamePattern.MatchString(username)
}

// ValidateDeviceID checks if a device ID follows the required format
func ValidateDeviceID(deviceID string) bool {
	return DeviceIDPattern.MatchString(deviceID)
}

// ValidateSPIFFEID checks if a SPIFFE ID is valid
func ValidateSPIFFEID(spiffeID string) bool {
	return SPIFFEIDPattern.MatchString(spiffeID)
}

// ValidateStrongPassword checks if a password meets complexity requirements
func ValidateStrongPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	// Check for at least one uppercase letter
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)

	// Check for at least one lowercase letter
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)

	// Check for at least one digit
	hasDigit := regexp.MustCompile(`\d`).MatchString(password)

	// Check for at least one special character
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password)

	return hasUpper && hasLower && hasDigit && hasSpecial
}

// ValidateTrustLevel checks if a trust level is within valid range
func ValidateTrustLevel(level int) bool {
	return level >= 0 && level <= 100
}

// SanitizeInput removes potentially dangerous characters from input
func SanitizeInput(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Trim whitespace
	input = strings.TrimSpace(input)

	return input
}

// NormalizeEmail converts email to lowercase and trims whitespace
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// NormalizeUsername converts username to lowercase and trims whitespace
func NormalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// IsValidIPAddress checks if a string is a valid IP address
func IsValidIPAddress(ip string) bool {
	// Simple IPv4 pattern
	ipv4Pattern := regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	if ipv4Pattern.MatchString(ip) {
		return true
	}

	// Simple IPv6 pattern (basic check)
	ipv6Pattern := regexp.MustCompile(`^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$`)
	return ipv6Pattern.MatchString(ip)
}

// ValidatePasswordComplexity provides detailed password validation
func ValidatePasswordComplexity(password string) []string {
	var errors []string

	if len(password) < 8 {
		errors = append(errors, "Password must be at least 8 characters long")
	}

	if len(password) > 128 {
		errors = append(errors, "Password must be at most 128 characters long")
	}

	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	if !hasUpper {
		errors = append(errors, "Password must contain at least one uppercase letter")
	}

	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	if !hasLower {
		errors = append(errors, "Password must contain at least one lowercase letter")
	}

	hasDigit := regexp.MustCompile(`\d`).MatchString(password)
	if !hasDigit {
		errors = append(errors, "Password must contain at least one digit")
	}

	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password)
	if !hasSpecial {
		errors = append(errors, "Password must contain at least one special character")
	}

	// Check for common weak patterns
	if strings.Contains(strings.ToLower(password), "password") {
		errors = append(errors, "Password cannot contain the word 'password'")
	}

	if regexp.MustCompile(`^(.)\1{3,}`).MatchString(password) {
		errors = append(errors, "Password cannot contain more than 3 consecutive identical characters")
	}

	return errors
}

// ValidateFieldLength checks if a string field is within specified length limits
func ValidateFieldLength(field string, min, max int) bool {
	length := len(field)
	return length >= min && length <= max
}

// IsAlphanumeric checks if a string contains only alphanumeric characters
func IsAlphanumeric(s string) bool {
	pattern := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	return pattern.MatchString(s)
}

// IsAlphanumericWithHyphens checks if a string contains only alphanumeric characters and hyphens
func IsAlphanumericWithHyphens(s string) bool {
	pattern := regexp.MustCompile(`^[a-zA-Z0-9\-]+$`)
	return pattern.MatchString(s)
}

// ValidateRequiredFields checks if all required fields are non-empty
func ValidateRequiredFields(fields map[string]string) []string {
	var missing []string

	for fieldName, value := range fields {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, fieldName)
		}
	}

	return missing
}
