// Package config provides configuration validators testing
package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

func TestDefaultValidator(t *testing.T) {
	validator := &DefaultValidator{}

	t.Run("validate valid config", func(t *testing.T) {
		config := &types.ZeroTrustConfig{
			BaseURL:      "https://keycloak.example.com",
			Realm:        "test-realm",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			ZeroTrust: &types.ZeroTrustConfig{
				TrustLevelThresholds: types.TrustLevelMap{
					Read:   25,
					Write:  50,
					Admin:  75,
					Delete: 100,
				},
				RiskThresholds: types.RiskThresholdMap{
					Low:      20,
					Medium:   40,
					High:     70,
					Critical: 90,
				},
				DeviceVerificationTTL: 24 * time.Hour,
				TrustDecayInterval:    6 * time.Hour,
			},
			Cache: &types.CacheConfig{
				Type: "redis",
				Redis: &types.RedisConfig{
					Host: "localhost",
					Port: 6379,
				},
			},
		}

		err := validator.Validate(config)
		assert.NoError(t, err)
	})

	t.Run("validate keycloak configuration", func(t *testing.T) {
		tests := []struct {
			name     string
			config   *types.ZeroTrustConfig
			errorMsg string
		}{
			{
				name: "missing base URL",
				config: &types.ZeroTrustConfig{
					Realm:        "test",
					ClientID:     "test",
					ClientSecret: "test",
				},
				errorMsg: "keycloak.base_url is required",
			},
			{
				name: "invalid base URL",
				config: &types.ZeroTrustConfig{
					BaseURL:      "invalid-url",
					Realm:        "test",
					ClientID:     "test",
					ClientSecret: "test",
				},
				errorMsg: "keycloak.base_url must be a valid URL",
			},
			{
				name: "missing realm",
				config: &types.ZeroTrustConfig{
					BaseURL:      "https://test.com",
					ClientID:     "test",
					ClientSecret: "test",
				},
				errorMsg: "keycloak.realm is required",
			},
			{
				name: "invalid realm format",
				config: &types.ZeroTrustConfig{
					BaseURL:      "https://test.com",
					Realm:        "test@realm!",
					ClientID:     "test",
					ClientSecret: "test",
				},
				errorMsg: "keycloak.realm must contain only alphanumeric characters",
			},
			{
				name: "missing client ID",
				config: &types.ZeroTrustConfig{
					BaseURL:      "https://test.com",
					Realm:        "test",
					ClientSecret: "test",
				},
				errorMsg: "keycloak.client_id is required",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := validator.Validate(tt.config)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			})
		}
	})

	t.Run("validate zero trust configuration", func(t *testing.T) {
		tests := []struct {
			name     string
			config   *types.ZeroTrustConfig
			errorMsg string
		}{
			{
				name: "invalid trust threshold - out of range",
				config: &types.ZeroTrustConfig{
					BaseURL:      "https://test.com",
					Realm:        "test",
					ClientID:     "test",
					ClientSecret: "test",
					ZeroTrust: &types.ZeroTrustConfig{
						TrustLevelThresholds: types.TrustLevelMap{
							Read: 150, // Invalid: > 100
						},
					},
				},
				errorMsg: "trust threshold read must be between 0 and 100",
			},
			{
				name: "invalid trust threshold ordering",
				config: &types.ZeroTrustConfig{
					BaseURL:      "https://test.com",
					Realm:        "test",
					ClientID:     "test",
					ClientSecret: "test",
					ZeroTrust: &types.ZeroTrustConfig{
						TrustLevelThresholds: types.TrustLevelMap{
							Read:   75,
							Write:  50, // Invalid: write < read
							Admin:  80,
							Delete: 100,
						},
					},
				},
				errorMsg: "read threshold cannot be higher than write threshold",
			},
			{
				name: "invalid risk threshold - out of range",
				config: &types.ZeroTrustConfig{
					BaseURL:      "https://test.com",
					Realm:        "test",
					ClientID:     "test",
					ClientSecret: "test",
					ZeroTrust: &types.ZeroTrustConfig{
						TrustLevelThresholds: types.TrustLevelMap{
							Read:   25,
							Write:  50,
							Admin:  75,
							Delete: 100,
						},
						RiskThresholds: types.RiskThresholdMap{
							Low: -10, // Invalid: < 0
						},
					},
				},
				errorMsg: "risk threshold low must be between 0 and 100",
			},
			{
				name: "invalid risk threshold ordering",
				config: &types.ZeroTrustConfig{
					BaseURL:      "https://test.com",
					Realm:        "test",
					ClientID:     "test",
					ClientSecret: "test",
					ZeroTrust: &types.ZeroTrustConfig{
						TrustLevelThresholds: types.TrustLevelMap{
							Read:   25,
							Write:  50,
							Admin:  75,
							Delete: 100,
						},
						RiskThresholds: types.RiskThresholdMap{
							Low:    50,
							Medium: 40, // Invalid: medium < low
							High:   70,
							Critical: 90,
						},
					},
				},
				errorMsg: "low risk threshold must be less than medium threshold",
			},
			{
				name: "invalid device verification TTL",
				config: &types.ZeroTrustConfig{
					BaseURL:      "https://test.com",
					Realm:        "test",
					ClientID:     "test",
					ClientSecret: "test",
					ZeroTrust: &types.ZeroTrustConfig{
						TrustLevelThresholds: types.TrustLevelMap{
							Read:   25,
							Write:  50,
							Admin:  75,
							Delete: 100,
						},
						DeviceVerificationTTL: -1 * time.Hour, // Invalid: negative
					},
				},
				errorMsg: "device_verification_ttl must be positive",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := validator.Validate(tt.config)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			})
		}
	})

	t.Run("validate cache configuration", func(t *testing.T) {
		tests := []struct {
			name     string
			config   *types.ZeroTrustConfig
			errorMsg string
		}{
			{
				name: "invalid cache type",
				config: &types.ZeroTrustConfig{
					BaseURL:      "https://test.com",
					Realm:        "test",
					ClientID:     "test",
					ClientSecret: "test",
					Cache: &types.CacheConfig{
						Type: "invalid-type",
					},
				},
				errorMsg: "invalid cache type",
			},
			{
				name: "missing redis host",
				config: &types.ZeroTrustConfig{
					BaseURL:      "https://test.com",
					Realm:        "test",
					ClientID:     "test",
					ClientSecret: "test",
					Cache: &types.CacheConfig{
						Type: "redis",
						Redis: &types.RedisConfig{
							Port: 6379,
							// Missing Host
						},
					},
				},
				errorMsg: "redis host is required when cache type is redis",
			},
			{
				name: "invalid redis port",
				config: &types.ZeroTrustConfig{
					BaseURL:      "https://test.com",
					Realm:        "test",
					ClientID:     "test",
					ClientSecret: "test",
					Cache: &types.CacheConfig{
						Type: "redis",
						Redis: &types.RedisConfig{
							Host: "localhost",
							Port: 99999, // Invalid: > 65535
						},
					},
				},
				errorMsg: "redis port must be between 1 and 65535",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := validator.Validate(tt.config)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			})
		}
	})

	t.Run("get validation rules", func(t *testing.T) {
		rules := validator.GetValidationRules()
		assert.NotEmpty(t, rules)

		// Check for key validation rules
		rulesByPath := make(map[string]ValidationRule)
		for _, rule := range rules {
			rulesByPath[rule.Path] = rule
		}

		// Verify keycloak rules
		assert.Contains(t, rulesByPath, "keycloak.base_url")
		assert.Contains(t, rulesByPath, "keycloak.realm")
		assert.Contains(t, rulesByPath, "keycloak.client_id")

		// Verify trust level rules
		assert.Contains(t, rulesByPath, "zero_trust.trust_level_thresholds.read")
		assert.Contains(t, rulesByPath, "zero_trust.trust_level_thresholds.write")
		assert.Contains(t, rulesByPath, "zero_trust.trust_level_thresholds.admin")
		assert.Contains(t, rulesByPath, "zero_trust.trust_level_thresholds.delete")

		// Verify cache rules
		assert.Contains(t, rulesByPath, "cache.type")

		// Test specific rule properties
		baseURLRule := rulesByPath["keycloak.base_url"]
		assert.Equal(t, "string", baseURLRule.Type)
		assert.True(t, baseURLRule.Required)
		assert.NotNil(t, baseURLRule.Validator)

		realmRule := rulesByPath["keycloak.realm"]
		assert.Equal(t, "^[a-zA-Z0-9_-]+$", realmRule.Pattern)

		trustLevelRule := rulesByPath["zero_trust.trust_level_thresholds.read"]
		assert.Equal(t, "integer", trustLevelRule.Type)
		assert.Equal(t, 0, trustLevelRule.MinValue)
		assert.Equal(t, 100, trustLevelRule.MaxValue)

		cacheTypeRule := rulesByPath["cache.type"]
		assert.Contains(t, cacheTypeRule.AllowedValues, "memory")
		assert.Contains(t, cacheTypeRule.AllowedValues, "redis")
		assert.Contains(t, cacheTypeRule.AllowedValues, "external")
	})
}

func TestSecurityValidator(t *testing.T) {
	validator := &SecurityValidator{}

	t.Run("validate secure configuration", func(t *testing.T) {
		config := &types.ZeroTrustConfig{
			BaseURL:      "https://keycloak.example.com", // HTTPS
			Realm:        "test",
			ClientID:     "test",
			ClientSecret: "test",
			ZeroTrust: &types.ZeroTrustConfig{
				TrustLevelThresholds: types.TrustLevelMap{
					Admin:  75, // Above minimum
					Delete: 90, // Above minimum
				},
				EnableDeviceAttestation: true,
				EnableRiskAssessment:    true,
			},
			Security: &types.SecurityConfig{
				TLS: &types.TLSConfig{
					MinVersion: "1.2",
				},
			},
		}

		err := validator.Validate(config)
		assert.NoError(t, err)
	})

	t.Run("validate insecure configurations", func(t *testing.T) {
		tests := []struct {
			name     string
			config   *types.ZeroTrustConfig
			errorMsg string
		}{
			{
				name: "HTTP URL in production",
				config: &types.ZeroTrustConfig{
					BaseURL:      "http://keycloak.example.com", // HTTP not HTTPS
					Realm:        "test",
					ClientID:     "test",
					ClientSecret: "test",
				},
				errorMsg: "HTTP URLs are not secure",
			},
			{
				name: "low admin trust threshold",
				config: &types.ZeroTrustConfig{
					BaseURL:      "https://keycloak.example.com",
					Realm:        "test",
					ClientID:     "test",
					ClientSecret: "test",
					ZeroTrust: &types.ZeroTrustConfig{
						TrustLevelThresholds: types.TrustLevelMap{
							Admin: 30, // Below minimum of 50
						},
					},
				},
				errorMsg: "admin trust threshold is too low",
			},
			{
				name: "low delete trust threshold",
				config: &types.ZeroTrustConfig{
					BaseURL:      "https://keycloak.example.com",
					Realm:        "test",
					ClientID:     "test",
					ClientSecret: "test",
					ZeroTrust: &types.ZeroTrustConfig{
						TrustLevelThresholds: types.TrustLevelMap{
							Admin:  75,
							Delete: 60, // Below minimum of 75
						},
					},
				},
				errorMsg: "delete trust threshold is too low",
			},
			{
				name: "insecure TLS version",
				config: &types.ZeroTrustConfig{
					BaseURL:      "https://keycloak.example.com",
					Realm:        "test",
					ClientID:     "test",
					ClientSecret: "test",
					Security: &types.SecurityConfig{
						TLS: &types.TLSConfig{
							MinVersion: "1.0", // Insecure version
						},
					},
				},
				errorMsg: "TLS version 1.0 is not secure",
			},
			{
				name: "disabled device attestation",
				config: &types.ZeroTrustConfig{
					BaseURL:      "https://keycloak.example.com",
					Realm:        "test",
					ClientID:     "test",
					ClientSecret: "test",
					ZeroTrust: &types.ZeroTrustConfig{
						EnableDeviceAttestation: false, // Disabled
					},
				},
				errorMsg: "device attestation is disabled",
			},
			{
				name: "disabled risk assessment",
				config: &types.ZeroTrustConfig{
					BaseURL:      "https://keycloak.example.com",
					Realm:        "test",
					ClientID:     "test",
					ClientSecret: "test",
					ZeroTrust: &types.ZeroTrustConfig{
						EnableRiskAssessment: false, // Disabled
					},
				},
				errorMsg: "risk assessment is disabled",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := validator.Validate(tt.config)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			})
		}
	})

	t.Run("get security validation rules", func(t *testing.T) {
		rules := validator.GetValidationRules()
		assert.NotEmpty(t, rules)

		rulesByPath := make(map[string]ValidationRule)
		for _, rule := range rules {
			rulesByPath[rule.Path] = rule
		}

		// Verify HTTPS requirement
		httpsRule := rulesByPath["keycloak.base_url"]
		assert.NotNil(t, httpsRule.Validator)

		// Test HTTPS validator
		err := httpsRule.Validator("https://test.com")
		assert.NoError(t, err)

		err = httpsRule.Validator("http://test.com")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "should use HTTPS")

		// Verify minimum trust levels
		adminRule := rulesByPath["zero_trust.trust_level_thresholds.admin"]
		assert.Equal(t, 50, adminRule.MinValue)

		deleteRule := rulesByPath["zero_trust.trust_level_thresholds.delete"]
		assert.Equal(t, 75, deleteRule.MinValue)
	})
}

func TestPerformanceValidator(t *testing.T) {
	validator := &PerformanceValidator{}

	t.Run("validate good performance config", func(t *testing.T) {
		config := &types.ZeroTrustConfig{
			ZeroTrust: &types.ZeroTrustConfig{
				TrustDecayInterval:      30 * time.Minute, // Good interval
				DeviceVerificationTTL:   24 * time.Hour,   // Good TTL
			},
			Cache: &types.CacheConfig{
				TTL: &types.CacheTTLConfig{
					TokenValidation: &[]time.Duration{5 * time.Minute}[0],  // Good TTL
					UserInfo:        &[]time.Duration{10 * time.Minute}[0], // Good TTL
				},
			},
		}

		err := validator.Validate(config)
		assert.NoError(t, err) // Should only warn, not error
	})

	t.Run("validate performance warnings", func(t *testing.T) {
		// Note: Performance validator only generates warnings, not errors
		config := &types.ZeroTrustConfig{
			ZeroTrust: &types.ZeroTrustConfig{
				TrustDecayInterval:      1 * time.Minute, // Very short - will warn
				DeviceVerificationTTL:   8 * 24 * time.Hour, // Very long - will warn
			},
			Cache: &types.CacheConfig{
				TTL: &types.CacheTTLConfig{
					TokenValidation: &[]time.Duration{30 * time.Second}[0], // Very short - will warn
					UserInfo:        &[]time.Duration{1 * time.Second}[0],  // Very short - will warn
				},
			},
		}

		// Should not return error but will print warnings
		err := validator.Validate(config)
		assert.NoError(t, err)
	})

	t.Run("get performance validation rules", func(t *testing.T) {
		rules := validator.GetValidationRules()
		assert.NotEmpty(t, rules)

		rulesByPath := make(map[string]ValidationRule)
		for _, rule := range rules {
			rulesByPath[rule.Path] = rule
		}

		// Verify TTL rules
		deviceTTLRule := rulesByPath["zero_trust.device_verification_ttl"]
		assert.Equal(t, "duration", deviceTTLRule.Type)
		assert.NotNil(t, deviceTTLRule.Validator)

		tokenTTLRule := rulesByPath["cache.ttl.token_validation"]
		assert.Equal(t, "duration", tokenTTLRule.Type)
		assert.NotNil(t, tokenTTLRule.Validator)

		// Test TTL validators
		if deviceTTLRule.Validator != nil {
			// Test short TTL warning
			err := deviceTTLRule.Validator(2 * time.Minute)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "very short TTL may cause performance issues")

			// Test long TTL warning
			err = deviceTTLRule.Validator(10 * 24 * time.Hour)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "very long TTL may reduce security")

			// Test good TTL
			err = deviceTTLRule.Validator(24 * time.Hour)
			assert.NoError(t, err)
		}

		if tokenTTLRule.Validator != nil {
			// Test long cache TTL warning
			err := tokenTTLRule.Validator(45 * time.Minute)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "long token validation cache may cause stale data")

			// Test good cache TTL
			err = tokenTTLRule.Validator(15 * time.Minute)
			assert.NoError(t, err)
		}
	})
}

func TestEnvironmentValidator(t *testing.T) {
	t.Run("production environment validation", func(t *testing.T) {
		validator := &EnvironmentValidator{Environment: "production"}

		tests := []struct {
			name     string
			config   *types.ZeroTrustConfig
			errorMsg string
		}{
			{
				name: "localhost URL in production",
				config: &types.ZeroTrustConfig{
					BaseURL: "http://localhost:8082",
				},
				errorMsg: "production environment should not use localhost URLs",
			},
			{
				name: "low admin trust in production",
				config: &types.ZeroTrustConfig{
					BaseURL: "https://keycloak.prod.com",
					ZeroTrust: &types.ZeroTrustConfig{
						TrustLevelThresholds: types.TrustLevelMap{
							Admin: 60, // Below production minimum of 75
						},
					},
				},
				errorMsg: "production admin trust threshold should be at least 75",
			},
			{
				name: "low delete trust in production",
				config: &types.ZeroTrustConfig{
					BaseURL: "https://keycloak.prod.com",
					ZeroTrust: &types.ZeroTrustConfig{
						TrustLevelThresholds: types.TrustLevelMap{
							Admin:  75,
							Delete: 80, // Below production minimum of 90
						},
					},
				},
				errorMsg: "production delete trust threshold should be at least 90",
			},
			{
				name: "metrics disabled in production",
				config: &types.ZeroTrustConfig{
					BaseURL: "https://keycloak.prod.com",
					ZeroTrust: &types.ZeroTrustConfig{
						TrustLevelThresholds: types.TrustLevelMap{
							Admin:  75,
							Delete: 90,
						},
					},
					Observability: &types.ObservabilityConfig{
						Metrics: types.MetricsConfig{
							Enabled: false, // Should be enabled in production
						},
					},
				},
				errorMsg: "metrics should be enabled in production",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := validator.Validate(tt.config)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			})
		}

		// Test valid production config
		validConfig := &types.ZeroTrustConfig{
			BaseURL: "https://keycloak.prod.com",
			ZeroTrust: &types.ZeroTrustConfig{
				TrustLevelThresholds: types.TrustLevelMap{
					Admin:  75,
					Delete: 90,
				},
			},
			Observability: &types.ObservabilityConfig{
				Metrics: types.MetricsConfig{
					Enabled: true,
				},
			},
		}

		err := validator.Validate(validConfig)
		assert.NoError(t, err)
	})

	t.Run("staging environment validation", func(t *testing.T) {
		validator := &EnvironmentValidator{Environment: "staging"}

		// Staging validation only generates warnings
		config := &types.ZeroTrustConfig{
			BaseURL: "https://keycloak.staging.com",
			Observability: &types.ObservabilityConfig{
				Logging: types.LoggingConfig{
					Level: "info", // Not debug level
				},
			},
		}

		err := validator.Validate(config)
		assert.NoError(t, err) // Should only warn, not error
	})

	t.Run("development environment validation", func(t *testing.T) {
		validator := &EnvironmentValidator{Environment: "development"}

		// Development validation is very permissive
		config := &types.ZeroTrustConfig{
			BaseURL: "http://localhost:8082", // OK in development
			ZeroTrust: &types.ZeroTrustConfig{
				TrustLevelThresholds: types.TrustLevelMap{
					Read: 50, // High trust in dev - will generate info message
				},
			},
		}

		err := validator.Validate(config)
		assert.NoError(t, err)
	})

	t.Run("unknown environment", func(t *testing.T) {
		validator := &EnvironmentValidator{Environment: "unknown"}

		config := &types.ZeroTrustConfig{
			BaseURL: "http://localhost:8082",
		}

		err := validator.Validate(config)
		assert.NoError(t, err) // Should skip validation for unknown environments
	})

	t.Run("get environment validation rules", func(t *testing.T) {
		prodValidator := &EnvironmentValidator{Environment: "production"}
		rules := prodValidator.GetValidationRules()

		if len(rules) > 0 {
			rulesByPath := make(map[string]ValidationRule)
			for _, rule := range rules {
				rulesByPath[rule.Path] = rule
			}

			// Verify production-specific rules
			if baseURLRule, exists := rulesByPath["keycloak.base_url"]; exists {
				assert.NotNil(t, baseURLRule.Validator)

				// Test localhost validation for production
				err := baseURLRule.Validator("http://localhost:8082")
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "production should not use localhost URLs")

				err = baseURLRule.Validator("https://keycloak.prod.com")
				assert.NoError(t, err)
			}
		}
	})
}

// Mock types for testing (normally these would be defined in the types package)
type ValidationRule struct {
	Path          string
	Type          string
	Required      bool
	Pattern       string
	MinValue      int
	MaxValue      int
	AllowedValues []interface{}
	Validator     func(interface{}) error
}

// Add missing types for comprehensive testing
func init() {
	// These would normally be defined in the types package
	// Adding them here for testing completeness
}