// Package common provides shared user creation utilities testing
package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

func TestUserFactory(t *testing.T) {
	factory := NewUserFactory()

	t.Run("create authenticated user from claims", func(t *testing.T) {
		expiresAt := time.Now().Add(1 * time.Hour)
		claims := &types.ZeroTrustClaims{
			UserID:            "user-123",
			Email:             "test@example.com",
			PreferredUsername: "testuser",
			GivenName:         "Test",
			FamilyName:        "User",
			Roles:             []string{"user", "admin"},
			TrustLevel:        75,
			DeviceID:          "device-456",
			DeviceVerified:    true,
			LastVerification:  "2024-01-20T10:30:00Z",
			SessionState:      "session-789",
			RiskScore:         25,
			LocationInfo: &types.LocationInfo{
				Country: "US",
				City:    "San Francisco",
			},
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expiresAt),
			},
		}

		user := factory.CreateAuthenticatedUser(claims)

		assert.NotNil(t, user)
		assert.Equal(t, "user-123", user.UserID)
		assert.Equal(t, "test@example.com", user.Email)
		assert.Equal(t, "testuser", user.Username)
		assert.Equal(t, "Test", user.FirstName)
		assert.Equal(t, "User", user.LastName)
		assert.Equal(t, []string{"user", "admin"}, user.Roles)
		assert.Equal(t, 75, user.TrustLevel)
		assert.Equal(t, "device-456", user.DeviceID)
		assert.True(t, user.DeviceVerified)
		assert.Equal(t, "2024-01-20T10:30:00Z", user.LastVerification)
		assert.Equal(t, "session-789", user.SessionState)
		assert.Equal(t, expiresAt.Unix(), user.ExpiresAt.Unix())
		assert.Equal(t, 25, user.RiskScore)
		assert.NotNil(t, user.LocationInfo)
		assert.Equal(t, "US", user.LocationInfo.Country)
		assert.Equal(t, "San Francisco", user.LocationInfo.City)
	})

	t.Run("create user from nil claims", func(t *testing.T) {
		user := factory.CreateAuthenticatedUser(nil)
		assert.Nil(t, user)
	})

	t.Run("create user with minimal claims", func(t *testing.T) {
		claims := &types.ZeroTrustClaims{
			UserID: "user-123",
			Email:  "test@example.com",
		}

		user := factory.CreateAuthenticatedUser(claims)

		assert.NotNil(t, user)
		assert.Equal(t, "user-123", user.UserID)
		assert.Equal(t, "test@example.com", user.Email)
		assert.Empty(t, user.Username)
		assert.Empty(t, user.FirstName)
		assert.Empty(t, user.LastName)
		assert.Nil(t, user.Roles)
		assert.Equal(t, 0, user.TrustLevel)
		assert.Empty(t, user.DeviceID)
		assert.False(t, user.DeviceVerified)
	})

	t.Run("validate user claims", func(t *testing.T) {
		tests := []struct {
			name        string
			claims      *types.ZeroTrustClaims
			expectError bool
			errorCode   string
		}{
			{
				name:        "nil claims",
				claims:      nil,
				expectError: true,
				errorCode:   types.ErrCodeInvalidToken,
			},
			{
				name: "missing user ID",
				claims: &types.ZeroTrustClaims{
					Email: "test@example.com",
				},
				expectError: true,
				errorCode:   types.ErrCodeInvalidToken,
			},
			{
				name: "missing email",
				claims: &types.ZeroTrustClaims{
					UserID: "user-123",
				},
				expectError: true,
				errorCode:   types.ErrCodeInvalidToken,
			},
			{
				name: "expired token",
				claims: &types.ZeroTrustClaims{
					UserID: "user-123",
					Email:  "test@example.com",
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
					},
				},
				expectError: true,
				errorCode:   types.ErrCodeExpiredToken,
			},
			{
				name: "valid claims",
				claims: &types.ZeroTrustClaims{
					UserID: "user-123",
					Email:  "test@example.com",
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					},
				},
				expectError: false,
			},
			{
				name: "valid claims without expiration",
				claims: &types.ZeroTrustClaims{
					UserID: "user-123",
					Email:  "test@example.com",
				},
				expectError: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := factory.ValidateUserClaims(tt.claims)

				if tt.expectError {
					assert.Error(t, err)
					if authErr, ok := err.(*types.AuthError); ok {
						assert.Equal(t, tt.errorCode, authErr.Code)
					}
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})

	t.Run("enrich user with defaults", func(t *testing.T) {
		config := &types.ZeroTrustConfig{
			DefaultTrustLevel: 50,
		}

		tests := []struct {
			name     string
			user     *types.AuthenticatedUser
			expected *types.AuthenticatedUser
		}{
			{
				name: "set default trust level",
				user: &types.AuthenticatedUser{
					UserID:     "user-123",
					Email:      "test@example.com",
					TrustLevel: 0, // Should be set to default
				},
				expected: &types.AuthenticatedUser{
					UserID:     "user-123",
					Email:      "test@example.com",
					TrustLevel: 50,
				},
			},
			{
				name: "don't override existing trust level",
				user: &types.AuthenticatedUser{
					UserID:     "user-123",
					Email:      "test@example.com",
					TrustLevel: 75, // Should not be changed
				},
				expected: &types.AuthenticatedUser{
					UserID:     "user-123",
					Email:      "test@example.com",
					TrustLevel: 75,
				},
			},
			{
				name: "set username from email",
				user: &types.AuthenticatedUser{
					UserID:   "user-123",
					Email:    "test@example.com",
					Username: "", // Should be set to email
				},
				expected: &types.AuthenticatedUser{
					UserID:   "user-123",
					Email:    "test@example.com",
					Username: "test@example.com",
				},
			},
			{
				name: "initialize empty roles",
				user: &types.AuthenticatedUser{
					UserID: "user-123",
					Email:  "test@example.com",
					Roles:  nil, // Should be initialized
				},
				expected: &types.AuthenticatedUser{
					UserID: "user-123",
					Email:  "test@example.com",
					Roles:  []string{},
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				factory.EnrichUserWithDefaults(tt.user, config)

				assert.Equal(t, tt.expected.TrustLevel, tt.user.TrustLevel)
				assert.Equal(t, tt.expected.Username, tt.user.Username)
				assert.NotNil(t, tt.user.Roles)
			})
		}

		// Test with nil user or config
		factory.EnrichUserWithDefaults(nil, config)
		factory.EnrichUserWithDefaults(&types.AuthenticatedUser{}, nil)
		// Should not panic
	})
}

func TestRoleValidator(t *testing.T) {
	validator := NewRoleValidator()

	user := &types.AuthenticatedUser{
		UserID: "user-123",
		Roles:  []string{"user", "admin", "editor"},
	}

	t.Run("has role - optimized lookup", func(t *testing.T) {
		// First call should build cache
		result := validator.HasRole(user, "admin")
		assert.True(t, result)

		// Second call should use cache
		result = validator.HasRole(user, "admin")
		assert.True(t, result)

		// Test non-existent role
		result = validator.HasRole(user, "super-admin")
		assert.False(t, result)
	})

	t.Run("has role with nil user", func(t *testing.T) {
		result := validator.HasRole(nil, "admin")
		assert.False(t, result)
	})

	t.Run("has role with empty role", func(t *testing.T) {
		result := validator.HasRole(user, "")
		assert.False(t, result)
	})

	t.Run("has any role", func(t *testing.T) {
		tests := []struct {
			name          string
			requiredRoles []string
			expected      bool
		}{
			{
				name:          "has one of multiple roles",
				requiredRoles: []string{"super-admin", "admin", "moderator"},
				expected:      true, // user has "admin"
			},
			{
				name:          "has none of the roles",
				requiredRoles: []string{"super-admin", "moderator"},
				expected:      false,
			},
			{
				name:          "empty roles list",
				requiredRoles: []string{},
				expected:      false,
			},
			{
				name:          "nil roles list",
				requiredRoles: nil,
				expected:      false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := validator.HasAnyRole(user, tt.requiredRoles)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("has all roles", func(t *testing.T) {
		tests := []struct {
			name          string
			requiredRoles []string
			expected      bool
		}{
			{
				name:          "has all required roles",
				requiredRoles: []string{"user", "admin"},
				expected:      true,
			},
			{
				name:          "missing one role",
				requiredRoles: []string{"user", "admin", "super-admin"},
				expected:      false,
			},
			{
				name:          "empty roles list",
				requiredRoles: []string{},
				expected:      false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := validator.HasAllRoles(user, tt.requiredRoles)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("clear cache", func(t *testing.T) {
		// Build cache for user
		validator.HasRole(user, "admin")

		// Clear specific user cache
		validator.ClearCache(user.UserID)

		// Clear all cache
		validator.ClearCache("")

		// Should rebuild cache on next access
		result := validator.HasRole(user, "admin")
		assert.True(t, result)
	})

	t.Run("performance test - cache effectiveness", func(t *testing.T) {
		// Test with multiple users to verify cache per user
		user1 := &types.AuthenticatedUser{
			UserID: "user-1",
			Roles:  []string{"user", "admin"},
		}
		user2 := &types.AuthenticatedUser{
			UserID: "user-2",
			Roles:  []string{"user", "editor"},
		}

		// Build caches
		assert.True(t, validator.HasRole(user1, "admin"))
		assert.False(t, validator.HasRole(user2, "admin"))
		assert.True(t, validator.HasRole(user2, "editor"))

		// Verify caches are independent
		assert.True(t, validator.HasRole(user1, "admin"))
		assert.False(t, validator.HasRole(user1, "editor"))
	})
}

func TestTrustLevelValidator(t *testing.T) {
	validator := NewTrustLevelValidator()

	t.Run("validate trust level", func(t *testing.T) {
		tests := []struct {
			name           string
			user           *types.AuthenticatedUser
			minTrustLevel  int
			expected       bool
		}{
			{
				name: "meets minimum trust level",
				user: &types.AuthenticatedUser{
					TrustLevel: 75,
				},
				minTrustLevel: 50,
				expected:      true,
			},
			{
				name: "exactly meets minimum trust level",
				user: &types.AuthenticatedUser{
					TrustLevel: 50,
				},
				minTrustLevel: 50,
				expected:      true,
			},
			{
				name: "below minimum trust level",
				user: &types.AuthenticatedUser{
					TrustLevel: 25,
				},
				minTrustLevel: 50,
				expected:      false,
			},
			{
				name:          "nil user",
				user:          nil,
				minTrustLevel: 50,
				expected:      false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := validator.ValidateTrustLevel(tt.user, tt.minTrustLevel)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("validate device verification", func(t *testing.T) {
		tests := []struct {
			name                        string
			user                        *types.AuthenticatedUser
			requireDeviceVerification   bool
			expected                    bool
		}{
			{
				name: "device verified and required",
				user: &types.AuthenticatedUser{
					DeviceVerified: true,
				},
				requireDeviceVerification: true,
				expected:                  true,
			},
			{
				name: "device not verified but required",
				user: &types.AuthenticatedUser{
					DeviceVerified: false,
				},
				requireDeviceVerification: true,
				expected:                  false,
			},
			{
				name: "device not verified but not required",
				user: &types.AuthenticatedUser{
					DeviceVerified: false,
				},
				requireDeviceVerification: false,
				expected:                  true,
			},
			{
				name:                      "nil user",
				user:                      nil,
				requireDeviceVerification: true,
				expected:                  false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := validator.ValidateDeviceVerification(tt.user, tt.requireDeviceVerification)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("get trust level category", func(t *testing.T) {
		tests := []struct {
			trustLevel int
			expected   string
		}{
			{trustLevel: 100, expected: "FULL"},
			{trustLevel: 99, expected: "HIGH"},
			{trustLevel: 75, expected: "HIGH"},
			{trustLevel: 74, expected: "MEDIUM"},
			{trustLevel: 50, expected: "MEDIUM"},
			{trustLevel: 49, expected: "LOW"},
			{trustLevel: 25, expected: "LOW"},
			{trustLevel: 24, expected: "NONE"},
			{trustLevel: 0, expected: "NONE"},
			{trustLevel: -1, expected: "NONE"},
		}

		for _, tt := range tests {
			t.Run(tt.expected, func(t *testing.T) {
				result := validator.GetTrustLevelCategory(tt.trustLevel)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("validate risk score", func(t *testing.T) {
		tests := []struct {
			name         string
			user         *types.AuthenticatedUser
			maxRiskScore int
			expected     bool
		}{
			{
				name: "risk score within limit",
				user: &types.AuthenticatedUser{
					RiskScore: 25,
				},
				maxRiskScore: 50,
				expected:     true,
			},
			{
				name: "risk score at limit",
				user: &types.AuthenticatedUser{
					RiskScore: 50,
				},
				maxRiskScore: 50,
				expected:     true,
			},
			{
				name: "risk score above limit",
				user: &types.AuthenticatedUser{
					RiskScore: 75,
				},
				maxRiskScore: 50,
				expected:     false,
			},
			{
				name: "no risk score set",
				user: &types.AuthenticatedUser{
					RiskScore: 0,
				},
				maxRiskScore: 50,
				expected:     true, // No risk score is considered acceptable
			},
			{
				name:         "nil user",
				user:         nil,
				maxRiskScore: 50,
				expected:     false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := validator.ValidateRiskScore(tt.user, tt.maxRiskScore)
				assert.Equal(t, tt.expected, result)
			})
		}
	})
}

// Add missing import for JWT
import "github.com/golang-jwt/jwt/v5"