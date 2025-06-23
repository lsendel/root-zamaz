// Package config provides configuration management for the go-keycloak-zerotrust library
package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	
	// Test default values
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, 3, config.RetryAttempts)
	assert.NotNil(t, config.Cache)
	assert.NotNil(t, config.ZeroTrust)
	assert.NotNil(t, config.Middleware)
	assert.False(t, config.MultiTenant)
	assert.NotNil(t, config.Plugins)
	
	// Test cache defaults
	assert.True(t, config.Cache.Enabled)
	assert.Equal(t, "memory", config.Cache.Provider)
	assert.Equal(t, 15*time.Minute, config.Cache.TTL)
	assert.Equal(t, 1000, config.Cache.MaxSize)
	assert.Equal(t, "keycloak_zt", config.Cache.Prefix)
	
	// Test zero trust defaults
	assert.Equal(t, 25, config.ZeroTrust.DefaultTrustLevel)
	assert.Equal(t, 25, config.ZeroTrust.TrustLevelThresholds.Read)
	assert.Equal(t, 50, config.ZeroTrust.TrustLevelThresholds.Write)
	assert.Equal(t, 75, config.ZeroTrust.TrustLevelThresholds.Admin)
	assert.Equal(t, 100, config.ZeroTrust.TrustLevelThresholds.Delete)
	assert.False(t, config.ZeroTrust.DeviceAttestation)
	assert.Equal(t, 24*time.Hour, config.ZeroTrust.DeviceVerificationTTL)
	assert.False(t, config.ZeroTrust.RiskAssessment)
	assert.False(t, config.ZeroTrust.ContinuousVerification)
	assert.Equal(t, 4*time.Hour, config.ZeroTrust.VerificationInterval)
	assert.False(t, config.ZeroTrust.GeolocationEnabled)
	
	// Test middleware defaults
	assert.Equal(t, "Authorization", config.Middleware.TokenHeader)
	assert.Equal(t, "user", config.Middleware.ContextUserKey)
	assert.Contains(t, config.Middleware.SkipPaths, "/health")
	assert.Contains(t, config.Middleware.SkipPaths, "/metrics")
	assert.Equal(t, 30*time.Second, config.Middleware.RequestTimeout)
	assert.False(t, config.Middleware.CorsEnabled)
	assert.Contains(t, config.Middleware.CorsOrigins, "*")
}

func TestValidateFilePath(t *testing.T) {
	tests := []struct {
		name        string
		filePath    string
		expectError bool
		description string
	}{
		{
			name:        "valid yaml file",
			filePath:    "config.yaml",
			expectError: false,
			description: "Valid yaml extension should pass",
		},
		{
			name:        "valid yml file",
			filePath:    "config.yml",
			expectError: false,
			description: "Valid yml extension should pass",
		},
		{
			name:        "valid json file",
			filePath:    "config.json",
			expectError: false,
			description: "Valid json extension should pass",
		},
		{
			name:        "path traversal attempt",
			filePath:    "../../../etc/passwd",
			expectError: true,
			description: "Path traversal should be blocked",
		},
		{
			name:        "invalid extension",
			filePath:    "config.txt",
			expectError: true,
			description: "Invalid extension should be rejected",
		},
		{
			name:        "no extension",
			filePath:    "config",
			expectError: true,
			description: "No extension should be rejected",
		},
		{
			name:        "relative path with traversal",
			filePath:    "./config/../../../secret.yaml",
			expectError: true,
			description: "Complex path traversal should be blocked",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateFilePath(tt.filePath)
			
			if tt.expectError {
				assert.Error(t, err, tt.description)
				assert.Empty(t, result)
			} else {
				assert.NoError(t, err, tt.description)
				assert.NotEmpty(t, result)
				assert.True(t, filepath.IsAbs(result), "Result should be absolute path")
			}
		})
	}
}

func TestLoadFromFile(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "config_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	
	t.Run("load valid yaml config", func(t *testing.T) {
		configData := `
base_url: "https://keycloak.example.com"
realm: "test-realm"
client_id: "test-client"
client_secret: "test-secret"
timeout: "60s"
retry_attempts: 5

cache:
  enabled: true
  provider: "redis"
  ttl: "30m"
  max_size: 2000
  redis_url: "redis://localhost:6379"
  prefix: "test_prefix"

zero_trust:
  default_trust_level: 30
  trust_level_thresholds:
    read: 30
    write: 60
    admin: 80
    delete: 100
  device_attestation: true
  device_verification_ttl: "48h"
  risk_assessment: true
  continuous_verification: true
  verification_interval: "2h"
  geolocation_enabled: true
  geolocation_api: "https://api.ipgeolocation.io"

multi_tenant: true

middleware:
  token_header: "X-Auth-Token"
  context_user_key: "authenticated_user"
  skip_paths:
    - "/health"
    - "/metrics"
    - "/public/*"
  request_timeout: "45s"
  cors_enabled: true
  cors_origins:
    - "https://frontend.example.com"
    - "https://admin.example.com"

plugins:
  custom_plugin:
    enabled: true
    config:
      key: "value"
`
		
		configFile := filepath.Join(tempDir, "config.yaml")
		err := os.WriteFile(configFile, []byte(configData), 0600)
		require.NoError(t, err)
		
		config, err := LoadFromFile(configFile)
		require.NoError(t, err)
		
		// Verify core settings
		assert.Equal(t, "https://keycloak.example.com", config.BaseURL)
		assert.Equal(t, "test-realm", config.Realm)
		assert.Equal(t, "test-client", config.ClientID)
		assert.Equal(t, "test-secret", config.ClientSecret)
		assert.Equal(t, 60*time.Second, config.Timeout)
		assert.Equal(t, 5, config.RetryAttempts)
		
		// Verify cache settings
		assert.True(t, config.Cache.Enabled)
		assert.Equal(t, "redis", config.Cache.Provider)
		assert.Equal(t, 30*time.Minute, config.Cache.TTL)
		assert.Equal(t, 2000, config.Cache.MaxSize)
		assert.Equal(t, "redis://localhost:6379", config.Cache.RedisURL)
		assert.Equal(t, "test_prefix", config.Cache.Prefix)
		
		// Verify zero trust settings
		assert.Equal(t, 30, config.ZeroTrust.DefaultTrustLevel)
		assert.Equal(t, 30, config.ZeroTrust.TrustLevelThresholds.Read)
		assert.Equal(t, 60, config.ZeroTrust.TrustLevelThresholds.Write)
		assert.Equal(t, 80, config.ZeroTrust.TrustLevelThresholds.Admin)
		assert.Equal(t, 100, config.ZeroTrust.TrustLevelThresholds.Delete)
		assert.True(t, config.ZeroTrust.DeviceAttestation)
		assert.Equal(t, 48*time.Hour, config.ZeroTrust.DeviceVerificationTTL)
		assert.True(t, config.ZeroTrust.RiskAssessment)
		assert.True(t, config.ZeroTrust.ContinuousVerification)
		assert.Equal(t, 2*time.Hour, config.ZeroTrust.VerificationInterval)
		assert.True(t, config.ZeroTrust.GeolocationEnabled)
		assert.Equal(t, "https://api.ipgeolocation.io", config.ZeroTrust.GeolocationAPI)
		
		// Verify multi-tenant
		assert.True(t, config.MultiTenant)
		
		// Verify middleware settings
		assert.Equal(t, "X-Auth-Token", config.Middleware.TokenHeader)
		assert.Equal(t, "authenticated_user", config.Middleware.ContextUserKey)
		assert.Contains(t, config.Middleware.SkipPaths, "/health")
		assert.Contains(t, config.Middleware.SkipPaths, "/metrics")
		assert.Contains(t, config.Middleware.SkipPaths, "/public/*")
		assert.Equal(t, 45*time.Second, config.Middleware.RequestTimeout)
		assert.True(t, config.Middleware.CorsEnabled)
		assert.Contains(t, config.Middleware.CorsOrigins, "https://frontend.example.com")
		assert.Contains(t, config.Middleware.CorsOrigins, "https://admin.example.com")
		
		// Verify plugins
		assert.Contains(t, config.Plugins, "custom_plugin")
		pluginConfig := config.Plugins["custom_plugin"]
		assert.Equal(t, true, pluginConfig["enabled"])
	})
	
	t.Run("load invalid yaml", func(t *testing.T) {
		invalidData := `
base_url: "https://keycloak.example.com"
invalid_yaml: [
`
		
		configFile := filepath.Join(tempDir, "invalid.yaml")
		err := os.WriteFile(configFile, []byte(invalidData), 0600)
		require.NoError(t, err)
		
		_, err = LoadFromFile(configFile)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse config file")
	})
	
	t.Run("load non-existent file", func(t *testing.T) {
		_, err := LoadFromFile(filepath.Join(tempDir, "nonexistent.yaml"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read config file")
	})
	
	t.Run("invalid file path", func(t *testing.T) {
		_, err := LoadFromFile("../../../etc/passwd")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid file path")
	})
}

func TestLoadFromEnv(t *testing.T) {
	// Save original environment
	originalEnv := make(map[string]string)
	envVars := []string{
		"KEYCLOAK_BASE_URL",
		"KEYCLOAK_REALM",
		"KEYCLOAK_CLIENT_ID",
		"KEYCLOAK_CLIENT_SECRET",
		"KEYCLOAK_ADMIN_USER",
		"KEYCLOAK_ADMIN_PASSWORD",
		"KEYCLOAK_CACHE_PROVIDER",
		"KEYCLOAK_REDIS_URL",
		"KEYCLOAK_CACHE_PREFIX",
		"KEYCLOAK_DEVICE_ATTESTATION",
		"KEYCLOAK_RISK_ASSESSMENT",
		"KEYCLOAK_CONTINUOUS_VERIFICATION",
		"KEYCLOAK_GEOLOCATION_ENABLED",
		"KEYCLOAK_GEOLOCATION_API",
		"KEYCLOAK_MULTI_TENANT",
	}
	
	for _, envVar := range envVars {
		originalEnv[envVar] = os.Getenv(envVar)
	}
	
	// Clean up environment after test
	defer func() {
		for envVar, value := range originalEnv {
			if value == "" {
				os.Unsetenv(envVar)
			} else {
				os.Setenv(envVar, value)
			}
		}
	}()
	
	t.Run("load with environment variables", func(t *testing.T) {
		// Set test environment variables
		os.Setenv("KEYCLOAK_BASE_URL", "https://env-keycloak.example.com")
		os.Setenv("KEYCLOAK_REALM", "env-realm")
		os.Setenv("KEYCLOAK_CLIENT_ID", "env-client")
		os.Setenv("KEYCLOAK_CLIENT_SECRET", "env-secret")
		os.Setenv("KEYCLOAK_ADMIN_USER", "env-admin")
		os.Setenv("KEYCLOAK_ADMIN_PASSWORD", "env-password")
		os.Setenv("KEYCLOAK_CACHE_PROVIDER", "redis")
		os.Setenv("KEYCLOAK_REDIS_URL", "redis://env-redis:6379")
		os.Setenv("KEYCLOAK_CACHE_PREFIX", "env_prefix")
		os.Setenv("KEYCLOAK_DEVICE_ATTESTATION", "true")
		os.Setenv("KEYCLOAK_RISK_ASSESSMENT", "true")
		os.Setenv("KEYCLOAK_CONTINUOUS_VERIFICATION", "true")
		os.Setenv("KEYCLOAK_GEOLOCATION_ENABLED", "true")
		os.Setenv("KEYCLOAK_GEOLOCATION_API", "https://env-geo.example.com")
		os.Setenv("KEYCLOAK_MULTI_TENANT", "true")
		
		config := LoadFromEnv()
		
		// Verify environment variables were loaded
		assert.Equal(t, "https://env-keycloak.example.com", config.BaseURL)
		assert.Equal(t, "env-realm", config.Realm)
		assert.Equal(t, "env-client", config.ClientID)
		assert.Equal(t, "env-secret", config.ClientSecret)
		assert.Equal(t, "env-admin", config.AdminUser)
		assert.Equal(t, "env-password", config.AdminPass)
		assert.Equal(t, "redis", config.Cache.Provider)
		assert.Equal(t, "redis://env-redis:6379", config.Cache.RedisURL)
		assert.Equal(t, "env_prefix", config.Cache.Prefix)
		assert.True(t, config.ZeroTrust.DeviceAttestation)
		assert.True(t, config.ZeroTrust.RiskAssessment)
		assert.True(t, config.ZeroTrust.ContinuousVerification)
		assert.True(t, config.ZeroTrust.GeolocationEnabled)
		assert.Equal(t, "https://env-geo.example.com", config.ZeroTrust.GeolocationAPI)
		assert.True(t, config.MultiTenant)
	})
	
	t.Run("load with empty environment", func(t *testing.T) {
		// Clear all environment variables
		for _, envVar := range envVars {
			os.Unsetenv(envVar)
		}
		
		config := LoadFromEnv()
		
		// Should return default config
		defaultConfig := DefaultConfig()
		assert.Equal(t, defaultConfig.Timeout, config.Timeout)
		assert.Equal(t, defaultConfig.RetryAttempts, config.RetryAttempts)
		assert.Equal(t, defaultConfig.Cache.Provider, config.Cache.Provider)
		assert.Equal(t, defaultConfig.ZeroTrust.DefaultTrustLevel, config.ZeroTrust.DefaultTrustLevel)
		assert.Equal(t, defaultConfig.MultiTenant, config.MultiTenant)
	})
}

func TestSaveToFile(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "config_save_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	
	t.Run("save valid config", func(t *testing.T) {
		config := &types.Config{
			BaseURL:      "https://test.example.com",
			Realm:        "test-realm",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			Timeout:      60 * time.Second,
			Cache: &types.CacheConfig{
				Enabled:  true,
				Provider: "redis",
				TTL:      30 * time.Minute,
				MaxSize:  1000,
				RedisURL: "redis://localhost:6379",
				Prefix:   "test",
			},
			ZeroTrust: &types.ZeroTrustConfig{
				DefaultTrustLevel: 50,
				DeviceAttestation: true,
			},
		}
		
		configFile := filepath.Join(tempDir, "save_test.yaml")
		err := SaveToFile(config, configFile)
		require.NoError(t, err)
		
		// Verify file was created and has correct permissions
		fileInfo, err := os.Stat(configFile)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), fileInfo.Mode().Perm())
		
		// Verify file contents by loading it back
		loadedConfig, err := LoadFromFile(configFile)
		require.NoError(t, err)
		
		assert.Equal(t, config.BaseURL, loadedConfig.BaseURL)
		assert.Equal(t, config.Realm, loadedConfig.Realm)
		assert.Equal(t, config.ClientID, loadedConfig.ClientID)
		assert.Equal(t, config.ClientSecret, loadedConfig.ClientSecret)
	})
	
	t.Run("save to invalid path", func(t *testing.T) {
		config := DefaultConfig()
		err := SaveToFile(config, "../../../etc/passwd")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid file path")
	})
}

func TestValidate(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		config := &types.Config{
			BaseURL:      "https://keycloak.example.com",
			Realm:        "test-realm",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			Cache: &types.CacheConfig{
				Enabled:  true,
				Provider: "redis",
				RedisURL: "redis://localhost:6379",
				TTL:      30 * time.Minute,
				MaxSize:  1000,
			},
			ZeroTrust: &types.ZeroTrustConfig{
				DefaultTrustLevel:       50,
				DeviceVerificationTTL:   24 * time.Hour,
				VerificationInterval:    4 * time.Hour,
			},
			Middleware: &types.MiddlewareConfig{
				TokenHeader:    "Authorization",
				ContextUserKey: "user",
				RequestTimeout: 30 * time.Second,
			},
		}
		
		err := Validate(config)
		assert.NoError(t, err)
	})
	
	t.Run("nil config", func(t *testing.T) {
		err := Validate(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "configuration cannot be nil")
	})
	
	t.Run("missing required fields", func(t *testing.T) {
		tests := []struct {
			name   string
			config *types.Config
			errMsg string
		}{
			{
				name: "missing baseURL",
				config: &types.Config{
					Realm:        "test",
					ClientID:     "test",
					ClientSecret: "test",
				},
				errMsg: "baseURL is required",
			},
			{
				name: "missing realm",
				config: &types.Config{
					BaseURL:      "https://test.com",
					ClientID:     "test",
					ClientSecret: "test",
				},
				errMsg: "realm is required",
			},
			{
				name: "missing clientID",
				config: &types.Config{
					BaseURL:      "https://test.com",
					Realm:        "test",
					ClientSecret: "test",
				},
				errMsg: "clientID is required",
			},
			{
				name: "missing clientSecret",
				config: &types.Config{
					BaseURL:  "https://test.com",
					Realm:    "test",
					ClientID: "test",
				},
				errMsg: "clientSecret is required",
			},
		}
		
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := Validate(tt.config)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			})
		}
	})
	
	t.Run("invalid cache config", func(t *testing.T) {
		config := &types.Config{
			BaseURL:      "https://test.com",
			Realm:        "test",
			ClientID:     "test",
			ClientSecret: "test",
			Cache: &types.CacheConfig{
				Enabled:  true,
				Provider: "redis",
				// Missing RedisURL
				TTL:     30 * time.Minute,
				MaxSize: 1000,
			},
		}
		
		err := Validate(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "redis URL required")
	})
	
	t.Run("invalid zero trust config", func(t *testing.T) {
		config := &types.Config{
			BaseURL:      "https://test.com",
			Realm:        "test",
			ClientID:     "test",
			ClientSecret: "test",
			ZeroTrust: &types.ZeroTrustConfig{
				DefaultTrustLevel:       150, // Invalid: > 100
				DeviceVerificationTTL:   24 * time.Hour,
				VerificationInterval:    4 * time.Hour,
			},
		}
		
		err := Validate(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "default trust level must be between 0 and 100")
	})
	
	t.Run("invalid middleware config", func(t *testing.T) {
		config := &types.Config{
			BaseURL:      "https://test.com",
			Realm:        "test",
			ClientID:     "test",
			ClientSecret: "test",
			Middleware: &types.MiddlewareConfig{
				TokenHeader:    "", // Invalid: empty
				ContextUserKey: "user",
				RequestTimeout: 30 * time.Second,
			},
		}
		
		err := Validate(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token header cannot be empty")
	})
}

func TestMerge(t *testing.T) {
	t.Run("merge empty configs", func(t *testing.T) {
		result := Merge()
		defaultConfig := DefaultConfig()
		assert.Equal(t, defaultConfig.Timeout, result.Timeout)
	})
	
	t.Run("merge with nil configs", func(t *testing.T) {
		config1 := &types.Config{
			BaseURL: "https://test1.com",
		}
		
		result := Merge(nil, config1, nil)
		assert.Equal(t, "https://test1.com", result.BaseURL)
		assert.Equal(t, DefaultConfig().Timeout, result.Timeout) // Should get default
	})
	
	t.Run("merge multiple configs", func(t *testing.T) {
		config1 := &types.Config{
			BaseURL:  "https://test1.com",
			Realm:    "realm1",
			ClientID: "client1",
		}
		
		config2 := &types.Config{
			BaseURL:      "https://test2.com", // Should override config1
			ClientSecret: "secret2",           // Should be added
			Timeout:      60 * time.Second,    // Should override default
		}
		
		config3 := &types.Config{
			Realm:        "realm3", // Should override config1
			RetryAttempts: 5,       // Should override default
		}
		
		result := Merge(config1, config2, config3)
		
		// Later configs should take precedence
		assert.Equal(t, "https://test2.com", result.BaseURL) // From config2
		assert.Equal(t, "realm3", result.Realm)             // From config3
		assert.Equal(t, "client1", result.ClientID)         // From config1
		assert.Equal(t, "secret2", result.ClientSecret)     // From config2
		assert.Equal(t, 60*time.Second, result.Timeout)     // From config2
		assert.Equal(t, 5, result.RetryAttempts)            // From config3
	})
	
	t.Run("merge cache configs", func(t *testing.T) {
		config1 := &types.Config{
			Cache: &types.CacheConfig{
				Enabled:  true,
				Provider: "memory",
				TTL:      15 * time.Minute,
			},
		}
		
		config2 := &types.Config{
			Cache: &types.CacheConfig{
				Provider: "redis",                     // Should override
				RedisURL: "redis://localhost:6379",   // Should be added
				TTL:      30 * time.Minute,           // Should override
			},
		}
		
		result := Merge(config1, config2)
		
		assert.True(t, result.Cache.Enabled)                           // From config1
		assert.Equal(t, "redis", result.Cache.Provider)                // From config2
		assert.Equal(t, "redis://localhost:6379", result.Cache.RedisURL) // From config2
		assert.Equal(t, 30*time.Minute, result.Cache.TTL)             // From config2
	})
	
	t.Run("merge zero trust configs", func(t *testing.T) {
		config1 := &types.Config{
			ZeroTrust: &types.ZeroTrustConfig{
				DefaultTrustLevel: 25,
				DeviceAttestation: false,
				TrustLevelThresholds: types.TrustLevelMap{
					Read:  25,
					Write: 50,
				},
			},
		}
		
		config2 := &types.Config{
			ZeroTrust: &types.ZeroTrustConfig{
				DefaultTrustLevel: 30, // Should override
				DeviceAttestation: true, // Should override
				TrustLevelThresholds: types.TrustLevelMap{
					Admin:  75, // Should be added
					Delete: 100, // Should be added
				},
			},
		}
		
		result := Merge(config1, config2)
		
		assert.Equal(t, 30, result.ZeroTrust.DefaultTrustLevel)  // From config2
		assert.True(t, result.ZeroTrust.DeviceAttestation)       // From config2
		assert.Equal(t, 25, result.ZeroTrust.TrustLevelThresholds.Read)   // From config1
		assert.Equal(t, 50, result.ZeroTrust.TrustLevelThresholds.Write)  // From config1
		assert.Equal(t, 75, result.ZeroTrust.TrustLevelThresholds.Admin)  // From config2
		assert.Equal(t, 100, result.ZeroTrust.TrustLevelThresholds.Delete) // From config2
	})
	
	t.Run("merge plugins", func(t *testing.T) {
		config1 := &types.Config{
			Plugins: map[string]map[string]interface{}{
				"plugin1": {
					"enabled": true,
					"setting": "value1",
				},
			},
		}
		
		config2 := &types.Config{
			Plugins: map[string]map[string]interface{}{
				"plugin1": { // Should override completely
					"enabled": false,
					"setting": "value2",
				},
				"plugin2": { // Should be added
					"enabled": true,
				},
			},
		}
		
		result := Merge(config1, config2)
		
		assert.Contains(t, result.Plugins, "plugin1")
		assert.Contains(t, result.Plugins, "plugin2")
		assert.Equal(t, false, result.Plugins["plugin1"]["enabled"])     // From config2
		assert.Equal(t, "value2", result.Plugins["plugin1"]["setting"])  // From config2
		assert.Equal(t, true, result.Plugins["plugin2"]["enabled"])      // From config2
	})
}