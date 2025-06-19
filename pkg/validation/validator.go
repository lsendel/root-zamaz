// Package validation provides comprehensive input validation for the MVP Zero Trust Auth system.
// It includes request validation middleware, custom validators, and structured error formatting.
package validation

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"mvp.local/pkg/errors"
)

// Validator holds the validator instance and custom validation rules
type Validator struct {
	validator *validator.Validate
}

// ValidationError represents a field validation error
type ValidationError struct {
	Field   string `json:"field"`
	Tag     string `json:"tag"`
	Value   string `json:"value"`
	Message string `json:"message"`
}

// NewValidator creates a new validator instance with custom rules
func NewValidator() *Validator {
	validate := validator.New()

	// Register custom tag name function for better field names
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	// Register custom validation rules
	registerCustomValidators(validate)

	return &Validator{
		validator: validate,
	}
}

// ValidateStruct validates a struct and returns structured validation errors
func (v *Validator) ValidateStruct(s interface{}) error {
	err := v.validator.Struct(s)
	if err == nil {
		return nil
	}

	var validationErrors []ValidationError

	// Handle validation errors
	if validatorErrors, ok := err.(validator.ValidationErrors); ok {
		for _, validatorErr := range validatorErrors {
			validationErrors = append(validationErrors, ValidationError{
				Field:   validatorErr.Field(),
				Tag:     validatorErr.Tag(),
				Value:   fmt.Sprintf("%v", validatorErr.Value()),
				Message: getErrorMessage(validatorErr),
			})
		}
	}

	// Create structured validation error
	return errors.ValidationWithDetails("Validation failed", map[string]interface{}{
		"errors": validationErrors,
		"count":  len(validationErrors),
	})
}

// registerCustomValidators registers custom validation rules
func registerCustomValidators(validate *validator.Validate) {
	// UUID validation
	validate.RegisterValidation("uuid", validateUUID)

	// Strong password validation
	validate.RegisterValidation("strong_password", validateStrongPassword)

	// Device ID format validation
	validate.RegisterValidation("device_id", validateDeviceID)

	// SPIFFE ID validation
	validate.RegisterValidation("spiffe_id", validateSPIFFEID)

	// Username format validation
	validate.RegisterValidation("username", validateUsername)

	// Trust level validation
	validate.RegisterValidation("trust_level", validateTrustLevel)
}

// validateUUID validates that a string is a valid UUID
func validateUUID(fl validator.FieldLevel) bool {
	_, err := uuid.Parse(fl.Field().String())
	return err == nil
}

// validateStrongPassword validates password complexity
func validateStrongPassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	// Minimum 8 characters
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

// validateDeviceID validates device ID format
func validateDeviceID(fl validator.FieldLevel) bool {
	deviceID := fl.Field().String()

	// Device ID should be alphanumeric with hyphens, 8-64 characters
	pattern := `^[a-zA-Z0-9\-]{8,64}$`
	matched, _ := regexp.MatchString(pattern, deviceID)
	return matched
}

// validateSPIFFEID validates SPIFFE ID format
func validateSPIFFEID(fl validator.FieldLevel) bool {
	spiffeID := fl.Field().String()

	// SPIFFE ID format: spiffe://trust-domain/path
	pattern := `^spiffe://[a-zA-Z0-9\-\.]+(/[a-zA-Z0-9\-\._/]*)?$`
	matched, _ := regexp.MatchString(pattern, spiffeID)
	return matched
}

// validateUsername validates username format
func validateUsername(fl validator.FieldLevel) bool {
	username := fl.Field().String()

	// Username: alphanumeric, underscore, hyphen, 3-50 characters
	pattern := `^[a-zA-Z0-9_\-]{3,50}$`
	matched, _ := regexp.MatchString(pattern, username)
	return matched
}

// validateTrustLevel validates trust level range
func validateTrustLevel(fl validator.FieldLevel) bool {
	trustLevel := fl.Field().Int()
	return trustLevel >= 0 && trustLevel <= 100
}

// getErrorMessage returns a human-readable error message for validation errors
func getErrorMessage(err validator.FieldError) string {
	switch err.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", err.Field())
	case "email":
		return fmt.Sprintf("%s must be a valid email address", err.Field())
	case "min":
		return fmt.Sprintf("%s must be at least %s characters", err.Field(), err.Param())
	case "max":
		return fmt.Sprintf("%s must be at most %s characters", err.Field(), err.Param())
	case "len":
		return fmt.Sprintf("%s must be exactly %s characters", err.Field(), err.Param())
	case "uuid":
		return fmt.Sprintf("%s must be a valid UUID", err.Field())
	case "strong_password":
		return fmt.Sprintf("%s must contain at least one uppercase letter, one lowercase letter, one digit, and one special character", err.Field())
	case "device_id":
		return fmt.Sprintf("%s must be alphanumeric with hyphens, 8-64 characters", err.Field())
	case "spiffe_id":
		return fmt.Sprintf("%s must be a valid SPIFFE ID format", err.Field())
	case "username":
		return fmt.Sprintf("%s must be alphanumeric with underscores/hyphens, 3-50 characters", err.Field())
	case "trust_level":
		return fmt.Sprintf("%s must be between 0 and 100", err.Field())
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", err.Field(), err.Param())
	case "alphanum":
		return fmt.Sprintf("%s must contain only alphanumeric characters", err.Field())
	default:
		return fmt.Sprintf("%s is invalid", err.Field())
	}
}
