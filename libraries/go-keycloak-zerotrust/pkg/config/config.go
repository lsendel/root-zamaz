// Package config provides configuration management for the go-keycloak-zerotrust library
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *types.Config {
	return &types.Config{
		Timeout:       30 * time.Second,
		RetryAttempts: 3,
		Cache: &types.CacheConfig{
			Enabled:  true,
			Provider: "memory",
			TTL:      15 * time.Minute,
			MaxSize:  1000,
			Prefix:   "keycloak_zt",
		},
		ZeroTrust: &types.ZeroTrustConfig{
			DefaultTrustLevel: 25,
			TrustLevelThresholds: types.TrustLevelMap{
				Read:   25,
				Write:  50,
				Admin:  75,
				Delete: 100,
			},
			DeviceAttestation:     false,
			DeviceVerificationTTL: 24 * time.Hour,
			RiskAssessment:        false,
			RiskThresholds: types.RiskThresholdMap{
				Low:      25,
				Medium:   50,
				High:     75,
				Critical: 90,
			},
			ContinuousVerification: false,
			VerificationInterval:   4 * time.Hour,
			GeolocationEnabled:     false,
		},
		MultiTenant: false,
		Middleware: &types.MiddlewareConfig{
			TokenHeader:    "Authorization",
			ContextUserKey: "user",
			SkipPaths:      []string{"/health", "/metrics"},
			RequestTimeout: 30 * time.Second,
			CorsEnabled:    false,
			CorsOrigins:    []string{"*"},
		},
		Plugins: make(map[string]map[string]interface{}),
	}
}

// validateFilePath validates and cleans the file path to prevent path traversal attacks
func validateFilePath(filePath string) (string, error) {
	// Clean the path to resolve any ".." or "." elements
	cleanPath := filepath.Clean(filePath)
	
	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("invalid file path: path traversal not allowed")
	}
	
	// Convert to absolute path to prevent relative path issues
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve absolute path: %w", err)
	}
	
	// Ensure the file has a valid extension for config files
	ext := filepath.Ext(absPath)
	if ext != ".yaml" && ext != ".yml" && ext != ".json" {
		return "", fmt.Errorf("invalid file extension: only .yaml, .yml, and .json files are allowed")
	}
	
	return absPath, nil
}

// LoadFromFile loads configuration from a YAML file
func LoadFromFile(filePath string) (*types.Config, error) {
	// Validate and sanitize the file path
	safePath, err := validateFilePath(filePath)
	if err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}
	
	data, err := os.ReadFile(safePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := DefaultConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

// LoadFromEnv loads configuration from environment variables
func LoadFromEnv() *types.Config {
	config := DefaultConfig()

	// Core Keycloak settings
	if baseURL := os.Getenv("KEYCLOAK_BASE_URL"); baseURL != "" {
		config.BaseURL = baseURL
	}
	if realm := os.Getenv("KEYCLOAK_REALM"); realm != "" {
		config.Realm = realm
	}
	if clientID := os.Getenv("KEYCLOAK_CLIENT_ID"); clientID != "" {
		config.ClientID = clientID
	}
	if clientSecret := os.Getenv("KEYCLOAK_CLIENT_SECRET"); clientSecret != "" {
		config.ClientSecret = clientSecret
	}
	if adminUser := os.Getenv("KEYCLOAK_ADMIN_USER"); adminUser != "" {
		config.AdminUser = adminUser
	}
	if adminPass := os.Getenv("KEYCLOAK_ADMIN_PASSWORD"); adminPass != "" {
		config.AdminPass = adminPass
	}

	// Cache settings
	if cacheProvider := os.Getenv("KEYCLOAK_CACHE_PROVIDER"); cacheProvider != "" {
		config.Cache.Provider = cacheProvider
	}
	if redisURL := os.Getenv("KEYCLOAK_REDIS_URL"); redisURL != "" {
		config.Cache.RedisURL = redisURL
	}
	if cachePrefix := os.Getenv("KEYCLOAK_CACHE_PREFIX"); cachePrefix != "" {
		config.Cache.Prefix = cachePrefix
	}

	// Zero Trust settings
	if os.Getenv("KEYCLOAK_DEVICE_ATTESTATION") == "true" {
		config.ZeroTrust.DeviceAttestation = true
	}
	if os.Getenv("KEYCLOAK_RISK_ASSESSMENT") == "true" {
		config.ZeroTrust.RiskAssessment = true
	}
	if os.Getenv("KEYCLOAK_CONTINUOUS_VERIFICATION") == "true" {
		config.ZeroTrust.ContinuousVerification = true
	}
	if os.Getenv("KEYCLOAK_GEOLOCATION_ENABLED") == "true" {
		config.ZeroTrust.GeolocationEnabled = true
	}
	if geoAPI := os.Getenv("KEYCLOAK_GEOLOCATION_API"); geoAPI != "" {
		config.ZeroTrust.GeolocationAPI = geoAPI
	}

	// Multi-tenant settings
	if os.Getenv("KEYCLOAK_MULTI_TENANT") == "true" {
		config.MultiTenant = true
	}

	return config
}

// SaveToFile saves configuration to a YAML file
func SaveToFile(config *types.Config, filePath string) error {
	// Validate and sanitize the file path
	safePath, err := validateFilePath(filePath)
	if err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}
	
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(safePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate validates the configuration
func Validate(config *types.Config) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Validate required fields
	if config.BaseURL == "" {
		return fmt.Errorf("baseURL is required")
	}
	if config.Realm == "" {
		return fmt.Errorf("realm is required")
	}
	if config.ClientID == "" {
		return fmt.Errorf("clientID is required")
	}
	if config.ClientSecret == "" {
		return fmt.Errorf("clientSecret is required")
	}

	// Validate cache configuration
	if config.Cache != nil && config.Cache.Enabled {
		if config.Cache.Provider == "redis" && config.Cache.RedisURL == "" {
			return fmt.Errorf("redis URL required when using redis cache provider")
		}
		if config.Cache.TTL <= 0 {
			return fmt.Errorf("cache TTL must be positive")
		}
		if config.Cache.MaxSize <= 0 {
			return fmt.Errorf("cache max size must be positive")
		}
	}

	// Validate Zero Trust configuration
	if config.ZeroTrust != nil {
		if config.ZeroTrust.DefaultTrustLevel < 0 || config.ZeroTrust.DefaultTrustLevel > 100 {
			return fmt.Errorf("default trust level must be between 0 and 100")
		}
		if config.ZeroTrust.DeviceVerificationTTL <= 0 {
			return fmt.Errorf("device verification TTL must be positive")
		}
		if config.ZeroTrust.VerificationInterval <= 0 {
			return fmt.Errorf("verification interval must be positive")
		}
	}

	// Validate middleware configuration
	if config.Middleware != nil {
		if config.Middleware.TokenHeader == "" {
			return fmt.Errorf("token header cannot be empty")
		}
		if config.Middleware.ContextUserKey == "" {
			return fmt.Errorf("context user key cannot be empty")
		}
		if config.Middleware.RequestTimeout <= 0 {
			return fmt.Errorf("request timeout must be positive")
		}
	}

	return nil
}

// Merge merges multiple configurations, with later configs taking precedence
func Merge(configs ...*types.Config) *types.Config {
	if len(configs) == 0 {
		return DefaultConfig()
	}

	result := DefaultConfig()
	
	for _, config := range configs {
		if config == nil {
			continue
		}

		// Merge core settings
		if config.BaseURL != "" {
			result.BaseURL = config.BaseURL
		}
		if config.Realm != "" {
			result.Realm = config.Realm
		}
		if config.ClientID != "" {
			result.ClientID = config.ClientID
		}
		if config.ClientSecret != "" {
			result.ClientSecret = config.ClientSecret
		}
		if config.AdminUser != "" {
			result.AdminUser = config.AdminUser
		}
		if config.AdminPass != "" {
			result.AdminPass = config.AdminPass
		}
		if config.Timeout > 0 {
			result.Timeout = config.Timeout
		}
		if config.RetryAttempts > 0 {
			result.RetryAttempts = config.RetryAttempts
		}

		// Merge cache configuration
		if config.Cache != nil {
			if result.Cache == nil {
				result.Cache = &types.CacheConfig{}
			}
			mergeCacheConfig(result.Cache, config.Cache)
		}

		// Merge Zero Trust configuration
		if config.ZeroTrust != nil {
			if result.ZeroTrust == nil {
				result.ZeroTrust = &types.ZeroTrustConfig{}
			}
			mergeZeroTrustConfig(result.ZeroTrust, config.ZeroTrust)
		}

		// Merge middleware configuration
		if config.Middleware != nil {
			if result.Middleware == nil {
				result.Middleware = &types.MiddlewareConfig{}
			}
			mergeMiddlewareConfig(result.Middleware, config.Middleware)
		}

		// Merge multi-tenant settings
		result.MultiTenant = config.MultiTenant
		if config.TenantResolver != nil {
			result.TenantResolver = config.TenantResolver
		}

		// Merge plugins
		if config.Plugins != nil {
			if result.Plugins == nil {
				result.Plugins = make(map[string]map[string]interface{})
			}
			for key, value := range config.Plugins {
				result.Plugins[key] = value
			}
		}
	}

	return result
}

// mergeCacheConfig merges cache configuration
func mergeCacheConfig(dst, src *types.CacheConfig) {
	if src.Enabled {
		dst.Enabled = src.Enabled
	}
	if src.Provider != "" {
		dst.Provider = src.Provider
	}
	if src.TTL > 0 {
		dst.TTL = src.TTL
	}
	if src.MaxSize > 0 {
		dst.MaxSize = src.MaxSize
	}
	if src.RedisURL != "" {
		dst.RedisURL = src.RedisURL
	}
	if src.Prefix != "" {
		dst.Prefix = src.Prefix
	}
}

// mergeZeroTrustConfig merges Zero Trust configuration
func mergeZeroTrustConfig(dst, src *types.ZeroTrustConfig) {
	if src.DefaultTrustLevel > 0 {
		dst.DefaultTrustLevel = src.DefaultTrustLevel
	}
	if src.TrustLevelThresholds.Read > 0 {
		dst.TrustLevelThresholds.Read = src.TrustLevelThresholds.Read
	}
	if src.TrustLevelThresholds.Write > 0 {
		dst.TrustLevelThresholds.Write = src.TrustLevelThresholds.Write
	}
	if src.TrustLevelThresholds.Admin > 0 {
		dst.TrustLevelThresholds.Admin = src.TrustLevelThresholds.Admin
	}
	if src.TrustLevelThresholds.Delete > 0 {
		dst.TrustLevelThresholds.Delete = src.TrustLevelThresholds.Delete
	}
	
	dst.DeviceAttestation = src.DeviceAttestation
	if src.DeviceVerificationTTL > 0 {
		dst.DeviceVerificationTTL = src.DeviceVerificationTTL
	}
	
	dst.RiskAssessment = src.RiskAssessment
	if src.RiskThresholds.Low > 0 {
		dst.RiskThresholds.Low = src.RiskThresholds.Low
	}
	if src.RiskThresholds.Medium > 0 {
		dst.RiskThresholds.Medium = src.RiskThresholds.Medium
	}
	if src.RiskThresholds.High > 0 {
		dst.RiskThresholds.High = src.RiskThresholds.High
	}
	if src.RiskThresholds.Critical > 0 {
		dst.RiskThresholds.Critical = src.RiskThresholds.Critical
	}
	
	dst.ContinuousVerification = src.ContinuousVerification
	if src.VerificationInterval > 0 {
		dst.VerificationInterval = src.VerificationInterval
	}
	
	dst.GeolocationEnabled = src.GeolocationEnabled
	if src.GeolocationAPI != "" {
		dst.GeolocationAPI = src.GeolocationAPI
	}
}

// mergeMiddlewareConfig merges middleware configuration
func mergeMiddlewareConfig(dst, src *types.MiddlewareConfig) {
	if src.TokenHeader != "" {
		dst.TokenHeader = src.TokenHeader
	}
	if src.ContextUserKey != "" {
		dst.ContextUserKey = src.ContextUserKey
	}
	if len(src.SkipPaths) > 0 {
		dst.SkipPaths = src.SkipPaths
	}
	if src.RequestTimeout > 0 {
		dst.RequestTimeout = src.RequestTimeout
	}
	if src.ErrorHandler != nil {
		dst.ErrorHandler = src.ErrorHandler
	}
	dst.CorsEnabled = src.CorsEnabled
	if len(src.CorsOrigins) > 0 {
		dst.CorsOrigins = src.CorsOrigins
	}
}