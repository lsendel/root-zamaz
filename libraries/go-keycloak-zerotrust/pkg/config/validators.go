// Package config provides configuration validators for Zero Trust settings
package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// DefaultValidator provides basic configuration validation
type DefaultValidator struct{}

func (v *DefaultValidator) Validate(config *types.ZeroTrustConfig) error {
	var errors []string
	
	// Validate Keycloak configuration
	if err := v.validateKeycloak(config); err != nil {
		errors = append(errors, err.Error())
	}
	
	// Validate Zero Trust settings
	if err := v.validateZeroTrust(config); err != nil {
		errors = append(errors, err.Error())
	}
	
	// Validate cache configuration
	if err := v.validateCache(config); err != nil {
		errors = append(errors, err.Error())
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed: %s", strings.Join(errors, "; "))
	}
	
	return nil
}

func (v *DefaultValidator) GetValidationRules() []ValidationRule {
	return []ValidationRule{
		{
			Path:     "keycloak.base_url",
			Type:     "string",
			Required: true,
			Validator: func(value interface{}) error {
				if str, ok := value.(string); ok {
					if _, err := url.Parse(str); err != nil {
						return fmt.Errorf("invalid URL format")
					}
					return nil
				}
				return fmt.Errorf("must be a string")
			},
		},
		{
			Path:     "keycloak.realm",
			Type:     "string",
			Required: true,
			Pattern:  "^[a-zA-Z0-9_-]+$",
		},
		{
			Path:     "keycloak.client_id",
			Type:     "string",
			Required: true,
		},
		{
			Path:     "zero_trust.trust_level_thresholds.read",
			Type:     "integer",
			Required: true,
			MinValue: 0,
			MaxValue: 100,
		},
		{
			Path:     "zero_trust.trust_level_thresholds.write",
			Type:     "integer",
			Required: true,
			MinValue: 0,
			MaxValue: 100,
		},
		{
			Path:     "zero_trust.trust_level_thresholds.admin",
			Type:     "integer",
			Required: true,
			MinValue: 0,
			MaxValue: 100,
		},
		{
			Path:     "zero_trust.trust_level_thresholds.delete",
			Type:     "integer",
			Required: true,
			MinValue: 0,
			MaxValue: 100,
		},
		{
			Path:         "cache.type",
			Type:         "string",
			Required:     true,
			AllowedValues: []interface{}{"memory", "redis", "external"},
		},
	}
}

func (v *DefaultValidator) validateKeycloak(config *types.ZeroTrustConfig) error {
	if config.BaseURL == "" {
		return fmt.Errorf("keycloak.base_url is required")
	}
	
	if _, err := url.Parse(config.BaseURL); err != nil {
		return fmt.Errorf("keycloak.base_url must be a valid URL: %w", err)
	}
	
	if config.Realm == "" {
		return fmt.Errorf("keycloak.realm is required")
	}
	
	if config.ClientID == "" {
		return fmt.Errorf("keycloak.client_id is required")
	}
	
	// Validate realm name format
	if matched, _ := regexp.MatchString("^[a-zA-Z0-9_-]+$", config.Realm); !matched {
		return fmt.Errorf("keycloak.realm must contain only alphanumeric characters, hyphens, and underscores")
	}
	
	return nil
}

func (v *DefaultValidator) validateZeroTrust(config *types.ZeroTrustConfig) error {
	if config.ZeroTrust == nil {
		return fmt.Errorf("zero_trust configuration is required")
	}
	
	zt := config.ZeroTrust
	
	// Validate trust thresholds
	thresholds := []struct {
		name  string
		value int
	}{
		{"read", zt.TrustLevelThresholds.Read},
		{"write", zt.TrustLevelThresholds.Write},
		{"admin", zt.TrustLevelThresholds.Admin},
		{"delete", zt.TrustLevelThresholds.Delete},
	}
	
	for _, threshold := range thresholds {
		if threshold.value < 0 || threshold.value > 100 {
			return fmt.Errorf("trust threshold %s must be between 0 and 100, got %d", threshold.name, threshold.value)
		}
	}
	
	// Validate threshold ordering (read <= write <= admin <= delete)
	if zt.TrustLevelThresholds.Read > zt.TrustLevelThresholds.Write {
		return fmt.Errorf("read threshold cannot be higher than write threshold")
	}
	if zt.TrustLevelThresholds.Write > zt.TrustLevelThresholds.Admin {
		return fmt.Errorf("write threshold cannot be higher than admin threshold")
	}
	if zt.TrustLevelThresholds.Admin > zt.TrustLevelThresholds.Delete {
		return fmt.Errorf("admin threshold cannot be higher than delete threshold")
	}
	
	// Validate risk thresholds
	riskThresholds := []struct {
		name  string
		value int
	}{
		{"low", zt.RiskThresholds.Low},
		{"medium", zt.RiskThresholds.Medium},
		{"high", zt.RiskThresholds.High},
		{"critical", zt.RiskThresholds.Critical},
	}
	
	for _, threshold := range riskThresholds {
		if threshold.value < 0 || threshold.value > 100 {
			return fmt.Errorf("risk threshold %s must be between 0 and 100, got %d", threshold.name, threshold.value)
		}
	}
	
	// Validate risk threshold ordering
	if zt.RiskThresholds.Low >= zt.RiskThresholds.Medium {
		return fmt.Errorf("low risk threshold must be less than medium threshold")
	}
	if zt.RiskThresholds.Medium >= zt.RiskThresholds.High {
		return fmt.Errorf("medium risk threshold must be less than high threshold")
	}
	if zt.RiskThresholds.High >= zt.RiskThresholds.Critical {
		return fmt.Errorf("high risk threshold must be less than critical threshold")
	}
	
	// Validate TTL values
	if zt.DeviceVerificationTTL <= 0 {
		return fmt.Errorf("device_verification_ttl must be positive")
	}
	if zt.TrustDecayInterval <= 0 {
		return fmt.Errorf("trust_decay_interval must be positive")
	}
	
	return nil
}

func (v *DefaultValidator) validateCache(config *types.ZeroTrustConfig) error {
	if config.Cache == nil {
		return nil // Cache is optional
	}
	
	cache := config.Cache
	
	// Validate cache type
	validTypes := map[string]bool{
		"memory":   true,
		"redis":    true,
		"external": true,
	}
	
	if !validTypes[cache.Type] {
		return fmt.Errorf("invalid cache type: %s, must be one of: memory, redis, external", cache.Type)
	}
	
	// Validate Redis configuration if type is redis
	if cache.Type == "redis" && cache.Redis != nil {
		if cache.Redis.Host == "" {
			return fmt.Errorf("redis host is required when cache type is redis")
		}
		if cache.Redis.Port <= 0 || cache.Redis.Port > 65535 {
			return fmt.Errorf("redis port must be between 1 and 65535, got %d", cache.Redis.Port)
		}
	}
	
	return nil
}

// SecurityValidator provides security-focused validation
type SecurityValidator struct{}

func (v *SecurityValidator) Validate(config *types.ZeroTrustConfig) error {
	var errors []string
	
	// Check for insecure configurations
	if err := v.validateSecuritySettings(config); err != nil {
		errors = append(errors, err.Error())
	}
	
	// Validate TLS settings
	if err := v.validateTLSSettings(config); err != nil {
		errors = append(errors, err.Error())
	}
	
	// Validate authentication requirements
	if err := v.validateAuthSettings(config); err != nil {
		errors = append(errors, err.Error())
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("security validation failed: %s", strings.Join(errors, "; "))
	}
	
	return nil
}

func (v *SecurityValidator) GetValidationRules() []ValidationRule {
	return []ValidationRule{
		{
			Path:     "keycloak.base_url",
			Type:     "string",
			Required: true,
			Validator: func(value interface{}) error {
				if str, ok := value.(string); ok {
					if !strings.HasPrefix(str, "https://") {
						return fmt.Errorf("Keycloak URL should use HTTPS in production")
					}
					return nil
				}
				return fmt.Errorf("must be a string")
			},
		},
		{
			Path:     "zero_trust.trust_level_thresholds.admin",
			Type:     "integer",
			Required: true,
			MinValue: 50, // Minimum security requirement for admin access
		},
		{
			Path:     "zero_trust.trust_level_thresholds.delete",
			Type:     "integer",
			Required: true,
			MinValue: 75, // High security requirement for delete operations
		},
	}
}

func (v *SecurityValidator) validateSecuritySettings(config *types.ZeroTrustConfig) error {
	// Check for HTTP in production environments
	if strings.HasPrefix(config.BaseURL, "http://") {
		return fmt.Errorf("HTTP URLs are not secure, use HTTPS in production")
	}
	
	// Validate minimum trust levels for security-critical operations
	if config.ZeroTrust != nil {
		if config.ZeroTrust.TrustLevelThresholds.Admin < 50 {
			return fmt.Errorf("admin trust threshold is too low (%d), should be at least 50 for security", 
				config.ZeroTrust.TrustLevelThresholds.Admin)
		}
		
		if config.ZeroTrust.TrustLevelThresholds.Delete < 75 {
			return fmt.Errorf("delete trust threshold is too low (%d), should be at least 75 for security", 
				config.ZeroTrust.TrustLevelThresholds.Delete)
		}
	}
	
	return nil
}

func (v *SecurityValidator) validateTLSSettings(config *types.ZeroTrustConfig) error {
	if config.Security == nil || config.Security.TLS == nil {
		return nil // TLS settings are optional
	}
	
	tls := config.Security.TLS
	
	// Validate minimum TLS version
	validVersions := map[string]bool{
		"1.2": true,
		"1.3": true,
	}
	
	if !validVersions[tls.MinVersion] {
		return fmt.Errorf("TLS version %s is not secure, use 1.2 or 1.3", tls.MinVersion)
	}
	
	return nil
}

func (v *SecurityValidator) validateAuthSettings(config *types.ZeroTrustConfig) error {
	if config.ZeroTrust == nil {
		return nil
	}
	
	// Warn about disabled security features
	if !config.ZeroTrust.EnableDeviceAttestation {
		return fmt.Errorf("device attestation is disabled, which reduces security")
	}
	
	if !config.ZeroTrust.EnableRiskAssessment {
		return fmt.Errorf("risk assessment is disabled, which reduces security")
	}
	
	return nil
}

// PerformanceValidator validates performance-related configuration
type PerformanceValidator struct{}

func (v *PerformanceValidator) Validate(config *types.ZeroTrustConfig) error {
	var warnings []string
	
	// Check for performance-impacting configurations
	if err := v.validatePerformanceSettings(config); err != nil {
		warnings = append(warnings, err.Error())
	}
	
	// Check TTL values
	if err := v.validateTTLSettings(config); err != nil {
		warnings = append(warnings, err.Error())
	}
	
	// Note: Performance validation typically generates warnings, not errors
	if len(warnings) > 0 {
		fmt.Printf("Performance warnings: %s\n", strings.Join(warnings, "; "))
	}
	
	return nil
}

func (v *PerformanceValidator) GetValidationRules() []ValidationRule {
	return []ValidationRule{
		{
			Path:     "zero_trust.device_verification_ttl",
			Type:     "duration",
			Required: false,
			Validator: func(value interface{}) error {
				if duration, ok := value.(time.Duration); ok {
					if duration < 5*time.Minute {
						return fmt.Errorf("very short TTL may cause performance issues")
					}
					if duration > 7*24*time.Hour {
						return fmt.Errorf("very long TTL may reduce security")
					}
					return nil
				}
				return nil
			},
		},
		{
			Path:     "cache.ttl.token_validation",
			Type:     "duration",
			Required: false,
			Validator: func(value interface{}) error {
				if duration, ok := value.(time.Duration); ok {
					if duration > 30*time.Minute {
						return fmt.Errorf("long token validation cache may cause stale data")
					}
					return nil
				}
				return nil
			},
		},
	}
}

func (v *PerformanceValidator) validatePerformanceSettings(config *types.ZeroTrustConfig) error {
	if config.ZeroTrust == nil {
		return nil
	}
	
	// Check for very short verification intervals
	if config.ZeroTrust.TrustDecayInterval < 5*time.Minute {
		return fmt.Errorf("trust decay interval is very short (%v), may cause high CPU usage", 
			config.ZeroTrust.TrustDecayInterval)
	}
	
	// Check for very long device verification TTL
	if config.ZeroTrust.DeviceVerificationTTL > 7*24*time.Hour {
		return fmt.Errorf("device verification TTL is very long (%v), may reduce security", 
			config.ZeroTrust.DeviceVerificationTTL)
	}
	
	return nil
}

func (v *PerformanceValidator) validateTTLSettings(config *types.ZeroTrustConfig) error {
	if config.Cache == nil || config.Cache.TTL == nil {
		return nil
	}
	
	ttl := config.Cache.TTL
	
	// Check for very short cache TTLs
	if ttl.TokenValidation != nil && *ttl.TokenValidation < 1*time.Minute {
		return fmt.Errorf("token validation cache TTL is very short, may cause high load")
	}
	
	if ttl.UserInfo != nil && *ttl.UserInfo < 5*time.Minute {
		return fmt.Errorf("user info cache TTL is very short, may cause high load")
	}
	
	return nil
}

// EnvironmentValidator validates environment-specific settings
type EnvironmentValidator struct {
	Environment string
}

func (v *EnvironmentValidator) Validate(config *types.ZeroTrustConfig) error {
	switch strings.ToLower(v.Environment) {
	case "production", "prod":
		return v.validateProductionConfig(config)
	case "staging", "stage":
		return v.validateStagingConfig(config)
	case "development", "dev":
		return v.validateDevelopmentConfig(config)
	default:
		return nil // Unknown environment, skip validation
	}
}

func (v *EnvironmentValidator) GetValidationRules() []ValidationRule {
	rules := []ValidationRule{}
	
	switch strings.ToLower(v.Environment) {
	case "production", "prod":
		rules = append(rules, ValidationRule{
			Path:     "keycloak.base_url",
			Type:     "string",
			Required: true,
			Validator: func(value interface{}) error {
				if str, ok := value.(string); ok {
					if strings.Contains(str, "localhost") || strings.Contains(str, "127.0.0.1") {
						return fmt.Errorf("production should not use localhost URLs")
					}
					return nil
				}
				return nil
			},
		})
	}
	
	return rules
}

func (v *EnvironmentValidator) validateProductionConfig(config *types.ZeroTrustConfig) error {
	// Production-specific validations
	if strings.Contains(config.BaseURL, "localhost") || strings.Contains(config.BaseURL, "127.0.0.1") {
		return fmt.Errorf("production environment should not use localhost URLs")
	}
	
	if config.ZeroTrust != nil {
		// Require higher security in production
		if config.ZeroTrust.TrustLevelThresholds.Admin < 75 {
			return fmt.Errorf("production admin trust threshold should be at least 75")
		}
		
		if config.ZeroTrust.TrustLevelThresholds.Delete < 90 {
			return fmt.Errorf("production delete trust threshold should be at least 90")
		}
	}
	
	// Require observability in production
	if config.Observability == nil || !config.Observability.Metrics.Enabled {
		return fmt.Errorf("metrics should be enabled in production")
	}
	
	return nil
}

func (v *EnvironmentValidator) validateStagingConfig(config *types.ZeroTrustConfig) error {
	// Staging-specific validations
	if config.Observability == nil || config.Observability.Logging.Level != "debug" {
		fmt.Println("Warning: Consider enabling debug logging in staging for better troubleshooting")
	}
	
	return nil
}

func (v *EnvironmentValidator) validateDevelopmentConfig(config *types.ZeroTrustConfig) error {
	// Development-specific validations (usually more permissive)
	if config.ZeroTrust != nil && config.ZeroTrust.TrustLevelThresholds.Read > 25 {
		fmt.Println("Info: High trust thresholds in development may impact testing")
	}
	
	return nil
}