// Package security provides password policy validation for the MVP Zero Trust Auth system.
package security

import (
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
	"mvp.local/pkg/errors"
)

// PasswordPolicy defines password complexity requirements
type PasswordPolicy struct {
	MinLength        int
	MaxLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumbers   bool
	RequireSymbols   bool
	ForbidCommon     bool
	ForbidUserInfo   bool
}

// DefaultPasswordPolicy returns the default password policy
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:        12,
		MaxLength:        128,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumbers:   true,
		RequireSymbols:   true,
		ForbidCommon:     true,
		ForbidUserInfo:   true,
	}
}

// ValidationResult contains password validation results
type ValidationResult struct {
	IsValid bool
	Errors  []string
	Score   int // 0-100, strength score
}

// Common weak passwords (subset for demonstration)
var commonPasswords = map[string]bool{
	"password":    true,
	"123456":      true,
	"12345678":    true,
	"qwerty":      true,
	"abc123":      true,
	"password123": true,
	"admin":       true,
	"letmein":     true,
	"welcome":     true,
	"monkey":      true,
	"dragon":      true,
	"princess":    true,
	"sunshine":    true,
	"football":    true,
	"iloveyou":    true,
	"trustno1":    true,
	"password1":   true,
	"welcome123":  true,
	"admin123":    true,
	"changeme":    true,
}

// ValidatePassword validates a password against the policy
func ValidatePassword(password string, policy PasswordPolicy, userInfo ...string) (*ValidationResult, error) {
	result := &ValidationResult{
		IsValid: true,
		Errors:  []string{},
		Score:   0,
	}

	// Check length
	if len(password) < policy.MinLength {
		result.IsValid = false
		result.Errors = append(result.Errors, "Password is too short")
	}
	if len(password) > policy.MaxLength {
		result.IsValid = false
		result.Errors = append(result.Errors, "Password is too long")
	}

	// Check character requirements
	hasUpper, hasLower, hasNumber, hasSymbol := analyzePassword(password)

	if policy.RequireUppercase && !hasUpper {
		result.IsValid = false
		result.Errors = append(result.Errors, "Password must contain at least one uppercase letter")
	}

	if policy.RequireLowercase && !hasLower {
		result.IsValid = false
		result.Errors = append(result.Errors, "Password must contain at least one lowercase letter")
	}

	if policy.RequireNumbers && !hasNumber {
		result.IsValid = false
		result.Errors = append(result.Errors, "Password must contain at least one number")
	}

	if policy.RequireSymbols && !hasSymbol {
		result.IsValid = false
		result.Errors = append(result.Errors, "Password must contain at least one special character")
	}

	// Check against common passwords
	if policy.ForbidCommon {
		if commonPasswords[strings.ToLower(password)] {
			result.IsValid = false
			result.Errors = append(result.Errors, "Password is too common")
		}
	}

	// Check against user information
	if policy.ForbidUserInfo && len(userInfo) > 0 {
		for _, info := range userInfo {
			if info != "" && len(info) >= 3 {
				if containsSubstring(strings.ToLower(password), strings.ToLower(info)) {
					result.IsValid = false
					result.Errors = append(result.Errors, "Password cannot contain user information")
					break
				}
			}
		}
	}

	// Check for sequential characters
	if hasSequentialChars(password) {
		result.Errors = append(result.Errors, "Password should not contain sequential characters")
		// This is a warning, not a hard failure
	}

	// Check for repeated characters
	if hasRepeatedChars(password) {
		result.Errors = append(result.Errors, "Password should not contain repeated character patterns")
		// This is a warning, not a hard failure
	}

	// Calculate strength score
	result.Score = calculatePasswordScore(password, hasUpper, hasLower, hasNumber, hasSymbol)

	return result, nil
}

// analyzePassword analyzes password character composition
func analyzePassword(password string) (hasUpper, hasLower, hasNumber, hasSymbol bool) {
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSymbol = true
		}
	}
	return
}

// containsSubstring checks if the password contains user information
func containsSubstring(password, userInfo string) bool {
	return strings.Contains(password, userInfo)
}

// hasSequentialChars checks for sequential character patterns
func hasSequentialChars(password string) bool {
	if len(password) < 3 {
		return false
	}

	// Check for sequential ASCII characters
	for i := 0; i < len(password)-2; i++ {
		if password[i+1] == password[i]+1 && password[i+2] == password[i]+2 {
			return true
		}
		if password[i+1] == password[i]-1 && password[i+2] == password[i]-2 {
			return true
		}
	}

	// Check for common sequential patterns
	sequential := []string{
		"123", "234", "345", "456", "567", "678", "789", "890",
		"abc", "bcd", "cde", "def", "efg", "fgh", "ghi", "hij", "ijk", "jkl", "klm", "lmn", "mno", "nop", "opq", "pqr", "qrs", "rst", "stu", "tuv", "uvw", "vwx", "wxy", "xyz",
		"qwe", "wer", "ert", "rty", "tyu", "yui", "uio", "iop", "asd", "sdf", "dfg", "fgh", "ghj", "hjk", "jkl", "zxc", "xcv", "cvb", "vbn", "bnm",
	}

	lowerPassword := strings.ToLower(password)
	for _, seq := range sequential {
		if strings.Contains(lowerPassword, seq) || strings.Contains(lowerPassword, reverse(seq)) {
			return true
		}
	}

	return false
}

// hasRepeatedChars checks for repeated character patterns
func hasRepeatedChars(password string) bool {
	if len(password) < 3 {
		return false
	}

	// Check for 3+ consecutive identical characters
	for i := 0; i < len(password)-2; i++ {
		if password[i] == password[i+1] && password[i] == password[i+2] {
			return true
		}
	}

	// Check for repeated patterns (like "abcabc")
	for patternLen := 2; patternLen <= len(password)/2; patternLen++ {
		pattern := password[:patternLen]
		repeated := strings.Repeat(pattern, len(password)/patternLen)
		if strings.HasPrefix(password, repeated) && len(repeated) >= 6 {
			return true
		}
	}

	return false
}

// calculatePasswordScore calculates a password strength score (0-100)
func calculatePasswordScore(password string, hasUpper, hasLower, hasNumber, hasSymbol bool) int {
	score := 0

	// Length scoring
	length := len(password)
	if length >= 8 {
		score += 25
	}
	if length >= 12 {
		score += 15
	}
	if length >= 16 {
		score += 10
	}

	// Character diversity scoring
	if hasLower {
		score += 10
	}
	if hasUpper {
		score += 10
	}
	if hasNumber {
		score += 10
	}
	if hasSymbol {
		score += 15
	}

	// Bonus for good practices
	if !hasSequentialChars(password) {
		score += 5
	}
	if !hasRepeatedChars(password) {
		score += 5
	}
	if !commonPasswords[strings.ToLower(password)] {
		score += 5
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// reverse reverses a string
func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// PasswordPolicyInterface defines the contract for password validation
type PasswordPolicyInterface interface {
	ValidatePassword(password string, userInfo ...string) error
	VerifyPassword(password, hash string) bool
	GetPasswordRequirements() map[string]interface{}
}

// PasswordValidator implements password policy validation
type PasswordValidator struct {
	policy PasswordPolicy
}

// NewPasswordValidator creates a new password validator
func NewPasswordValidator(policy ...PasswordPolicy) *PasswordValidator {
	var p PasswordPolicy
	if len(policy) > 0 {
		p = policy[0]
	} else {
		p = DefaultPasswordPolicy()
	}

	return &PasswordValidator{
		policy: p,
	}
}

// ValidatePassword validates a password and returns an error if invalid
func (pv *PasswordValidator) ValidatePassword(password string, userInfo ...string) error {
	result, err := ValidatePassword(password, pv.policy, userInfo...)
	if err != nil {
		return err
	}

	if !result.IsValid {
		return errors.Validation(strings.Join(result.Errors, "; "))
	}

	return nil
}

// GetPasswordRequirements returns the password policy requirements
func (pv *PasswordValidator) GetPasswordRequirements() map[string]interface{} {
	return map[string]interface{}{
		"min_length":        pv.policy.MinLength,
		"max_length":        pv.policy.MaxLength,
		"require_uppercase": pv.policy.RequireUppercase,
		"require_lowercase": pv.policy.RequireLowercase,
		"require_numbers":   pv.policy.RequireNumbers,
		"require_symbols":   pv.policy.RequireSymbols,
		"forbid_common":     pv.policy.ForbidCommon,
		"forbid_user_info":  pv.policy.ForbidUserInfo,
	}
}

// VerifyPassword compares a plain password with a hashed password
func (pv *PasswordValidator) VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
