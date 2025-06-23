// Package config provides configuration transformers for Zero Trust settings
package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// EnvironmentTransformer applies environment-specific configuration overrides
type EnvironmentTransformer struct {
	environment string
}

func (t *EnvironmentTransformer) Transform(config *types.ZeroTrustConfig) (*types.ZeroTrustConfig, error) {
	// Create a copy of the config
	newConfig := *config
	
	// Apply environment-specific transformations
	switch strings.ToLower(t.environment) {
	case "production", "prod":
		t.transformForProduction(&newConfig)
	case "staging", "stage":
		t.transformForStaging(&newConfig)
	case "development", "dev":
		t.transformForDevelopment(&newConfig)
	}
	
	return &newConfig, nil
}

func (t *EnvironmentTransformer) GetPriority() int {
	return 100 // High priority - environment overrides should be applied early
}

func (t *EnvironmentTransformer) transformForProduction(config *types.ZeroTrustConfig) {
	// Production optimizations and security enhancements
	if config.ZeroTrust == nil {
		config.ZeroTrust = &types.ZeroTrustSettings{}
	}
	
	// Increase trust thresholds for production security
	if config.ZeroTrust.TrustLevelThresholds.Admin < 85 {
		config.ZeroTrust.TrustLevelThresholds.Admin = 85
	}
	if config.ZeroTrust.TrustLevelThresholds.Delete < 95 {
		config.ZeroTrust.TrustLevelThresholds.Delete = 95
	}
	
	// Shorter verification intervals for better security
	if config.ZeroTrust.TrustDecayInterval > 15*time.Minute {
		config.ZeroTrust.TrustDecayInterval = 15 * time.Minute
	}
	
	// Enable all security features
	config.ZeroTrust.EnableDeviceAttestation = true
	config.ZeroTrust.EnableRiskAssessment = true
	config.ZeroTrust.EnableContinuousAuth = true
	
	// Configure observability for production
	if config.Observability == nil {
		config.Observability = &types.ObservabilityConfig{}
	}
	if config.Observability.Logging.Level == "" || config.Observability.Logging.Level == "debug" {
		config.Observability.Logging.Level = "warn"
	}
	if config.Observability.Tracing.SampleRate == 0 || config.Observability.Tracing.SampleRate > 0.1 {
		config.Observability.Tracing.SampleRate = 0.05
	}
	
	// Security hardening
	if config.Security == nil {
		config.Security = &types.SecurityConfig{}
	}
	if config.Security.RateLimiting == nil {
		config.Security.RateLimiting = &types.RateLimitingConfig{
			Enabled:           true,
			RequestsPerMinute: 500,
			BurstSize:         100,
		}
	}
}

func (t *EnvironmentTransformer) transformForStaging(config *types.ZeroTrustConfig) {
	// Staging optimizations - balance between production and development
	if config.ZeroTrust == nil {
		config.ZeroTrust = &types.ZeroTrustSettings{}
	}
	
	// Moderate trust thresholds
	if config.ZeroTrust.TrustLevelThresholds.Admin < 70 {
		config.ZeroTrust.TrustLevelThresholds.Admin = 70
	}
	if config.ZeroTrust.TrustLevelThresholds.Delete < 85 {
		config.ZeroTrust.TrustLevelThresholds.Delete = 85
	}
	
	// Configure observability for debugging
	if config.Observability == nil {
		config.Observability = &types.ObservabilityConfig{}
	}
	config.Observability.Logging.Level = "debug"
	config.Observability.Tracing.SampleRate = 0.5
}

func (t *EnvironmentTransformer) transformForDevelopment(config *types.ZeroTrustConfig) {
	// Development optimizations - easier testing and debugging
	if config.ZeroTrust == nil {
		config.ZeroTrust = &types.ZeroTrustSettings{}
	}
	
	// Lower trust thresholds for easier testing
	config.ZeroTrust.TrustLevelThresholds.Read = 10
	config.ZeroTrust.TrustLevelThresholds.Write = 25
	config.ZeroTrust.TrustLevelThresholds.Admin = 50
	config.ZeroTrust.TrustLevelThresholds.Delete = 75
	
	// Longer intervals to reduce noise during development
	config.ZeroTrust.TrustDecayInterval = 1 * time.Hour
	config.ZeroTrust.DeviceVerificationTTL = 7 * 24 * time.Hour
	
	// Enable debug features
	if config.Development == nil {
		config.Development = &types.DevelopmentConfig{}
	}
	config.Development.Debug.Enabled = true
	
	// Configure observability for development
	if config.Observability == nil {
		config.Observability = &types.ObservabilityConfig{}
	}
	config.Observability.Logging.Level = "debug"
	config.Observability.Tracing.SampleRate = 1.0
}

// SecretTransformer replaces secret placeholders with actual values from secret sources
type SecretTransformer struct {
	sources []SecretSource
}

func (t *SecretTransformer) Transform(config *types.ZeroTrustConfig) (*types.ZeroTrustConfig, error) {
	// Create a copy of the config
	newConfig := *config
	
	ctx := context.Background()
	
	// Transform secrets in various configuration fields
	if err := t.transformSecrets(ctx, &newConfig); err != nil {
		return nil, fmt.Errorf("secret transformation failed: %w", err)
	}
	
	return &newConfig, nil
}

func (t *SecretTransformer) GetPriority() int {
	return 90 // High priority - secrets should be resolved early
}

func (t *SecretTransformer) transformSecrets(ctx context.Context, config *types.ZeroTrustConfig) error {
	// Transform Keycloak secrets
	var err error
	config.ClientSecret, err = t.resolveSecret(ctx, config.ClientSecret)
	if err != nil {
		return fmt.Errorf("failed to resolve client secret: %w", err)
	}
	
	// Transform database password
	if config.Database != nil && config.Database.Connection.Password != "" {
		config.Database.Connection.Password, err = t.resolveSecret(ctx, config.Database.Connection.Password)
		if err != nil {
			return fmt.Errorf("failed to resolve database password: %w", err)
		}
	}
	
	// Transform Redis password
	if config.Cache != nil && config.Cache.Redis != nil && config.Cache.Redis.Password != "" {
		config.Cache.Redis.Password, err = t.resolveSecret(ctx, config.Cache.Redis.Password)
		if err != nil {
			return fmt.Errorf("failed to resolve Redis password: %w", err)
		}
	}
	
	return nil
}

func (t *SecretTransformer) resolveSecret(ctx context.Context, value string) (string, error) {
	// Check if value is a secret reference (e.g., ${SECRET_NAME} or secret://path)
	if !t.isSecretReference(value) {
		return value, nil
	}
	
	secretKey := t.extractSecretKey(value)
	if secretKey == "" {
		return value, nil
	}
	
	// Try each secret source
	for _, source := range t.sources {
		secret, err := source.GetSecret(ctx, secretKey)
		if err == nil && secret != "" {
			return secret, nil
		}
	}
	
	return "", fmt.Errorf("secret not found: %s", secretKey)
}

func (t *SecretTransformer) isSecretReference(value string) bool {
	// Check for ${...} pattern or secret:// scheme
	envPattern := regexp.MustCompile(`^\$\{[^}]+\}$`)
	return envPattern.MatchString(value) || strings.HasPrefix(value, "secret://")
}

func (t *SecretTransformer) extractSecretKey(value string) string {
	// Extract key from ${KEY} format
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		return value[2 : len(value)-1]
	}
	
	// Extract key from secret://key format
	if strings.HasPrefix(value, "secret://") {
		return value[9:]
	}
	
	return ""
}

// DefaultsTransformer applies sensible defaults to missing configuration values
type DefaultsTransformer struct{}

func (t *DefaultsTransformer) Transform(config *types.ZeroTrustConfig) (*types.ZeroTrustConfig, error) {
	newConfig := *config
	
	// Apply Zero Trust defaults
	t.applyZeroTrustDefaults(&newConfig)
	
	// Apply cache defaults
	t.applyCacheDefaults(&newConfig)
	
	// Apply observability defaults
	t.applyObservabilityDefaults(&newConfig)
	
	// Apply security defaults
	t.applySecurityDefaults(&newConfig)
	
	return &newConfig, nil
}

func (t *DefaultsTransformer) GetPriority() int {
	return 10 // Low priority - defaults should be applied last
}

func (t *DefaultsTransformer) applyZeroTrustDefaults(config *types.ZeroTrustConfig) {
	if config.ZeroTrust == nil {
		config.ZeroTrust = &types.ZeroTrustSettings{}
	}
	
	zt := config.ZeroTrust
	
	// Feature flags defaults
	if !zt.EnableDeviceAttestation && !zt.EnableRiskAssessment && !zt.EnableContinuousAuth {
		zt.EnableDeviceAttestation = true
		zt.EnableRiskAssessment = true
		zt.EnableContinuousAuth = true
	}
	
	// Trust level defaults
	if zt.TrustLevelThresholds.Read == 0 {
		zt.TrustLevelThresholds.Read = 25
	}
	if zt.TrustLevelThresholds.Write == 0 {
		zt.TrustLevelThresholds.Write = 50
	}
	if zt.TrustLevelThresholds.Admin == 0 {
		zt.TrustLevelThresholds.Admin = 75
	}
	if zt.TrustLevelThresholds.Delete == 0 {
		zt.TrustLevelThresholds.Delete = 90
	}
	
	// Risk threshold defaults
	if zt.RiskThresholds.Low == 0 {
		zt.RiskThresholds.Low = 25
	}
	if zt.RiskThresholds.Medium == 0 {
		zt.RiskThresholds.Medium = 50
	}
	if zt.RiskThresholds.High == 0 {
		zt.RiskThresholds.High = 75
	}
	if zt.RiskThresholds.Critical == 0 {
		zt.RiskThresholds.Critical = 90
	}
	
	// Time-based defaults
	if zt.DeviceVerificationTTL == 0 {
		zt.DeviceVerificationTTL = 24 * time.Hour
	}
	if zt.TrustDecayInterval == 0 {
		zt.TrustDecayInterval = 1 * time.Hour
	}
}

func (t *DefaultsTransformer) applyCacheDefaults(config *types.ZeroTrustConfig) {
	if config.Cache == nil {
		config.Cache = &types.CacheConfig{
			Type: "memory",
		}
	}
	
	cache := config.Cache
	
	// Cache type default
	if cache.Type == "" {
		cache.Type = "memory"
	}
	
	// Redis defaults
	if cache.Type == "redis" && cache.Redis == nil {
		cache.Redis = &types.RedisConfig{
			Host:     "localhost",
			Port:     6379,
			Database: 0,
			PoolSize: 10,
		}
	}
	
	// TTL defaults
	if cache.TTL == nil {
		cache.TTL = &types.CacheTTLConfig{}
	}
	
	ttl := cache.TTL
	if ttl.UserInfo == nil {
		duration := 15 * time.Minute
		ttl.UserInfo = &duration
	}
	if ttl.TokenValidation == nil {
		duration := 5 * time.Minute
		ttl.TokenValidation = &duration
	}
	if ttl.DeviceInfo == nil {
		duration := 1 * time.Hour
		ttl.DeviceInfo = &duration
	}
	if ttl.LocationInfo == nil {
		duration := 1 * time.Hour
		ttl.LocationInfo = &duration
	}
	if ttl.RiskAssessment == nil {
		duration := 10 * time.Minute
		ttl.RiskAssessment = &duration
	}
}

func (t *DefaultsTransformer) applyObservabilityDefaults(config *types.ZeroTrustConfig) {
	if config.Observability == nil {
		config.Observability = &types.ObservabilityConfig{}
	}
	
	obs := config.Observability
	
	// Metrics defaults
	if obs.Metrics.Enabled == false && obs.Metrics.Endpoint == "" {
		obs.Metrics.Enabled = true
		obs.Metrics.Endpoint = "/metrics"
		obs.Metrics.IncludeSensitiveData = false
	}
	
	// Logging defaults
	if obs.Logging.Level == "" {
		obs.Logging.Level = "info"
	}
	if obs.Logging.Format == "" {
		obs.Logging.Format = "json"
	}
	if obs.Logging.Output == "" {
		obs.Logging.Output = "stdout"
	}
	
	// Tracing defaults
	if obs.Tracing.ServiceName == "" {
		obs.Tracing.ServiceName = "keycloak-zerotrust"
	}
	if obs.Tracing.SampleRate == 0 {
		obs.Tracing.SampleRate = 0.1
	}
}

func (t *DefaultsTransformer) applySecurityDefaults(config *types.ZeroTrustConfig) {
	if config.Security == nil {
		config.Security = &types.SecurityConfig{}
	}
	
	sec := config.Security
	
	// TLS defaults
	if sec.TLS == nil {
		sec.TLS = &types.TLSConfig{
			MinVersion: "1.2",
			CipherSuites: []string{
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			},
		}
	}
	
	// Rate limiting defaults
	if sec.RateLimiting == nil {
		sec.RateLimiting = &types.RateLimitingConfig{
			Enabled:           true,
			RequestsPerMinute: 100,
			BurstSize:         50,
		}
	}
	
	// CORS defaults
	if sec.CORS == nil {
		sec.CORS = &types.CORSConfig{
			Enabled: true,
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
			AllowedHeaders: []string{"Authorization", "Content-Type", "X-Device-ID"},
			ExposeHeaders:  []string{"X-Trust-Level", "X-Risk-Score"},
		}
	}
}

// ValidationTransformer ensures configuration consistency after all transformations
type ValidationTransformer struct{}

func (t *ValidationTransformer) Transform(config *types.ZeroTrustConfig) (*types.ZeroTrustConfig, error) {
	newConfig := *config
	
	// Fix common configuration inconsistencies
	t.fixTrustThresholdOrdering(&newConfig)
	t.fixRiskThresholdOrdering(&newConfig)
	t.fixTTLValues(&newConfig)
	
	return &newConfig, nil
}

func (t *ValidationTransformer) GetPriority() int {
	return 5 // Very low priority - validation should be last
}

func (t *ValidationTransformer) fixTrustThresholdOrdering(config *types.ZeroTrustConfig) {
	if config.ZeroTrust == nil {
		return
	}
	
	zt := config.ZeroTrust
	
	// Ensure read <= write <= admin <= delete
	if zt.TrustLevelThresholds.Write < zt.TrustLevelThresholds.Read {
		zt.TrustLevelThresholds.Write = zt.TrustLevelThresholds.Read
	}
	if zt.TrustLevelThresholds.Admin < zt.TrustLevelThresholds.Write {
		zt.TrustLevelThresholds.Admin = zt.TrustLevelThresholds.Write
	}
	if zt.TrustLevelThresholds.Delete < zt.TrustLevelThresholds.Admin {
		zt.TrustLevelThresholds.Delete = zt.TrustLevelThresholds.Admin
	}
}

func (t *ValidationTransformer) fixRiskThresholdOrdering(config *types.ZeroTrustConfig) {
	if config.ZeroTrust == nil {
		return
	}
	
	zt := config.ZeroTrust
	
	// Ensure low < medium < high < critical
	if zt.RiskThresholds.Medium <= zt.RiskThresholds.Low {
		zt.RiskThresholds.Medium = zt.RiskThresholds.Low + 1
	}
	if zt.RiskThresholds.High <= zt.RiskThresholds.Medium {
		zt.RiskThresholds.High = zt.RiskThresholds.Medium + 1
	}
	if zt.RiskThresholds.Critical <= zt.RiskThresholds.High {
		zt.RiskThresholds.Critical = zt.RiskThresholds.High + 1
	}
}

func (t *ValidationTransformer) fixTTLValues(config *types.ZeroTrustConfig) {
	if config.ZeroTrust == nil {
		return
	}
	
	zt := config.ZeroTrust
	
	// Ensure reasonable minimum values
	if zt.DeviceVerificationTTL < 5*time.Minute {
		zt.DeviceVerificationTTL = 5 * time.Minute
	}
	if zt.TrustDecayInterval < 1*time.Minute {
		zt.TrustDecayInterval = 1 * time.Minute
	}
}

// EnvironmentSecretSource loads secrets from environment variables
type EnvironmentSecretSource struct{}

func (s *EnvironmentSecretSource) GetSecret(ctx context.Context, key string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", fmt.Errorf("environment variable %s not found", key)
	}
	return value, nil
}

func (s *EnvironmentSecretSource) ListSecrets(ctx context.Context) (map[string]string, error) {
	secrets := make(map[string]string)
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			secrets[parts[0]] = parts[1]
		}
	}
	return secrets, nil
}

func (s *EnvironmentSecretSource) GetSourceName() string {
	return "environment"
}

// FileSecretSource loads secrets from files (e.g., Docker secrets)
type FileSecretSource struct {
	BasePath string
}

// validateSecretPath validates and secures the secret file path
func (s *FileSecretSource) validateSecretPath(key string) (string, error) {
	// Clean the key to prevent path traversal
	cleanKey := filepath.Clean(key)
	
	// Check for path traversal attempts
	if strings.Contains(cleanKey, "..") || strings.Contains(cleanKey, "/") || strings.Contains(cleanKey, "\\") {
		return "", fmt.Errorf("invalid secret key: path traversal or directory separators not allowed")
	}
	
	// Ensure key only contains safe characters (alphanumeric, underscore, hyphen, dot)
	if !regexp.MustCompile(`^[a-zA-Z0-9._-]+$`).MatchString(cleanKey) {
		return "", fmt.Errorf("invalid secret key: only alphanumeric characters, dots, underscores, and hyphens are allowed")
	}
	
	// Build the secure file path
	safePath := filepath.Join(s.BasePath, cleanKey)
	
	// Verify the resolved path is still within the base directory
	absBasePath, err := filepath.Abs(s.BasePath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve base path: %w", err)
	}
	
	absSafePath, err := filepath.Abs(safePath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve secret path: %w", err)
	}
	
	if !strings.HasPrefix(absSafePath, absBasePath) {
		return "", fmt.Errorf("invalid secret path: outside of base directory")
	}
	
	return absSafePath, nil
}

func (s *FileSecretSource) GetSecret(ctx context.Context, key string) (string, error) {
	safePath, err := s.validateSecretPath(key)
	if err != nil {
		return "", fmt.Errorf("invalid secret key: %w", err)
	}
	
	content, err := os.ReadFile(safePath)
	if err != nil {
		return "", fmt.Errorf("failed to read secret file %s: %w", safePath, err)
	}
	return strings.TrimSpace(string(content)), nil
}

func (s *FileSecretSource) ListSecrets(ctx context.Context) (map[string]string, error) {
	secrets := make(map[string]string)
	
	entries, err := os.ReadDir(s.BasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secrets directory: %w", err)
	}
	
	for _, entry := range entries {
		if !entry.IsDir() {
			secret, err := s.GetSecret(ctx, entry.Name())
			if err == nil {
				secrets[entry.Name()] = secret
			}
		}
	}
	
	return secrets, nil
}

func (s *FileSecretSource) GetSourceName() string {
	return "file"
}