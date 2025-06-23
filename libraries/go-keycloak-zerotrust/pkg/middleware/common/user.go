// Package common provides shared user creation utilities
package common

import (
	"time"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// UserFactory provides common user creation logic for all middleware implementations
type UserFactory struct{}

// NewUserFactory creates a new user factory
func NewUserFactory() *UserFactory {
	return &UserFactory{}
}

// CreateAuthenticatedUser converts JWT claims to an authenticated user object
func (uf *UserFactory) CreateAuthenticatedUser(claims *types.ZeroTrustClaims) *types.AuthenticatedUser {
	if claims == nil {
		return nil
	}
	
	// Extract expiration time from JWT claims
	var expiresAt time.Time
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}
	
	return &types.AuthenticatedUser{
		UserID:           claims.UserID,
		Email:            claims.Email,
		Username:         claims.PreferredUsername,
		FirstName:        claims.GivenName,
		LastName:         claims.FamilyName,
		Roles:            claims.Roles,
		TrustLevel:       claims.TrustLevel,
		DeviceID:         claims.DeviceID,
		DeviceVerified:   claims.DeviceVerified,
		LastVerification: claims.LastVerification,
		SessionState:     claims.SessionState,
		ExpiresAt:        expiresAt,
		RiskScore:        claims.RiskScore,
		LocationInfo:     claims.LocationInfo,
	}
}

// ValidateUserClaims validates that JWT claims contain required fields
func (uf *UserFactory) ValidateUserClaims(claims *types.ZeroTrustClaims) error {
	if claims == nil {
		return &types.AuthError{
			Code:    types.ErrCodeInvalidToken,
			Message: "claims cannot be nil",
		}
	}
	
	if claims.UserID == "" {
		return &types.AuthError{
			Code:    types.ErrCodeInvalidToken,
			Message: "user ID is required in token claims",
		}
	}
	
	if claims.Email == "" {
		return &types.AuthError{
			Code:    types.ErrCodeInvalidToken,
			Message: "email is required in token claims",
		}
	}
	
	if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time) {
		return &types.AuthError{
			Code:    types.ErrCodeExpiredToken,
			Message: "token has expired",
		}
	}
	
	return nil
}

// EnrichUserWithDefaults adds default values to user if not present
func (uf *UserFactory) EnrichUserWithDefaults(user *types.AuthenticatedUser, config *types.ZeroTrustConfig) {
	if user == nil || config == nil {
		return
	}
	
	// Set default trust level if not specified
	if user.TrustLevel == 0 && config.DefaultTrustLevel > 0 {
		user.TrustLevel = config.DefaultTrustLevel
	}
	
	// Set default username if not specified
	if user.Username == "" && user.Email != "" {
		user.Username = user.Email
	}
	
	// Initialize roles slice if nil
	if user.Roles == nil {
		user.Roles = []string{}
	}
}

// RoleValidator provides role validation utilities
type RoleValidator struct {
	roleCache map[string]map[string]bool // userId -> roles map for caching
}

// NewRoleValidator creates a new role validator
func NewRoleValidator() *RoleValidator {
	return &RoleValidator{
		roleCache: make(map[string]map[string]bool),
	}
}

// HasRole checks if user has a specific role (optimized O(1) lookup)
func (rv *RoleValidator) HasRole(user *types.AuthenticatedUser, requiredRole string) bool {
	if user == nil || requiredRole == "" {
		return false
	}
	
	// Check cache first
	if roleSet, exists := rv.roleCache[user.UserID]; exists {
		return roleSet[requiredRole]
	}
	
	// Build role set for user and cache it
	roleSet := make(map[string]bool)
	for _, role := range user.Roles {
		roleSet[role] = true
	}
	rv.roleCache[user.UserID] = roleSet
	
	return roleSet[requiredRole]
}

// HasAnyRole checks if user has any of the specified roles
func (rv *RoleValidator) HasAnyRole(user *types.AuthenticatedUser, requiredRoles []string) bool {
	if user == nil || len(requiredRoles) == 0 {
		return false
	}
	
	for _, role := range requiredRoles {
		if rv.HasRole(user, role) {
			return true
		}
	}
	
	return false
}

// HasAllRoles checks if user has all of the specified roles
func (rv *RoleValidator) HasAllRoles(user *types.AuthenticatedUser, requiredRoles []string) bool {
	if user == nil || len(requiredRoles) == 0 {
		return false
	}
	
	for _, role := range requiredRoles {
		if !rv.HasRole(user, role) {
			return false
		}
	}
	
	return true
}

// ClearCache clears the role cache for a specific user or all users
func (rv *RoleValidator) ClearCache(userID string) {
	if userID == "" {
		// Clear all cache
		rv.roleCache = make(map[string]map[string]bool)
	} else {
		// Clear specific user cache
		delete(rv.roleCache, userID)
	}
}

// TrustLevelValidator provides trust level validation utilities
type TrustLevelValidator struct{}

// NewTrustLevelValidator creates a new trust level validator
func NewTrustLevelValidator() *TrustLevelValidator {
	return &TrustLevelValidator{}
}

// ValidateTrustLevel checks if user meets minimum trust level requirement
func (tv *TrustLevelValidator) ValidateTrustLevel(user *types.AuthenticatedUser, minTrustLevel int) bool {
	if user == nil {
		return false
	}
	
	return user.TrustLevel >= minTrustLevel
}

// ValidateDeviceVerification checks if device verification is required and satisfied
func (tv *TrustLevelValidator) ValidateDeviceVerification(user *types.AuthenticatedUser, requireDeviceVerification bool) bool {
	if user == nil {
		return false
	}
	
	// If device verification is not required, always pass
	if !requireDeviceVerification {
		return true
	}
	
	// Check if device is verified
	return user.DeviceVerified
}

// GetTrustLevelCategory returns the trust level category for easier handling
func (tv *TrustLevelValidator) GetTrustLevelCategory(trustLevel int) string {
	switch {
	case trustLevel >= 100:
		return "FULL"
	case trustLevel >= 75:
		return "HIGH"
	case trustLevel >= 50:
		return "MEDIUM"
	case trustLevel >= 25:
		return "LOW"
	default:
		return "NONE"
	}
}

// ValidateRiskScore checks if user's risk score is within acceptable limits
func (tv *TrustLevelValidator) ValidateRiskScore(user *types.AuthenticatedUser, maxRiskScore int) bool {
	if user == nil {
		return false
	}
	
	// If no risk score is set, consider it acceptable
	if user.RiskScore == 0 {
		return true
	}
	
	return user.RiskScore <= maxRiskScore
}