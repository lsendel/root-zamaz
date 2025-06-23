// Advanced Configuration Example
// This example demonstrates advanced configuration loading, validation, and transformation

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/config"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/integrations"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

func main() {
	fmt.Println("⚙️  Advanced Configuration Example")
	fmt.Println("==================================")
	fmt.Println()

	ctx := context.Background()

	// 1. Environment Variable Configuration
	demonstrateEnvironmentConfig()
	fmt.Println()

	// 2. Multi-Environment Configuration
	demonstrateMultiEnvironmentConfig()
	fmt.Println()

	// 3. Configuration Validation
	demonstrateConfigValidation()
	fmt.Println()

	// 4. Configuration Transformation
	demonstrateConfigTransformation()
	fmt.Println()

	// 5. Secret Management
	demonstrateSecretManagement(ctx)
	fmt.Println()

	// 6. Configuration Watching
	demonstrateConfigWatching(ctx)
	fmt.Println()

	// 7. External Service Integration
	demonstrateExternalServices(ctx)
	fmt.Println()

	// 8. Configuration Schema Generation
	demonstrateConfigSchema()
	fmt.Println()

	fmt.Println("🎉 Advanced configuration example completed!")
}

func demonstrateEnvironmentConfig() {
	fmt.Println("🌍 Environment Variable Configuration")
	fmt.Println("------------------------------------")

	// Set some example environment variables
	os.Setenv("ZEROTRUST_KEYCLOAK_BASE_URL", "https://keycloak.example.com")
	os.Setenv("ZEROTRUST_KEYCLOAK_REALM", "production")
	os.Setenv("ZEROTRUST_KEYCLOAK_CLIENT_ID", "api-service")
	os.Setenv("ZEROTRUST_ZERO_TRUST_TRUST_LEVEL_THRESHOLDS_READ", "30")
	os.Setenv("ZEROTRUST_ZERO_TRUST_TRUST_LEVEL_THRESHOLDS_ADMIN", "85")
	os.Setenv("ZEROTRUST_CACHE_TYPE", "redis")
	os.Setenv("ZEROTRUST_CACHE_REDIS_HOST", "redis.example.com")

	// Load configuration from environment variables
	config, err := config.LoadFromEnv()
	if err != nil {
		log.Printf("Failed to load config from environment: %v", err)
		return
	}

	fmt.Printf("✅ Configuration loaded from environment variables:\n")
	fmt.Printf("   Keycloak URL: %s\n", config.BaseURL)
	fmt.Printf("   Realm: %s\n", config.Realm)
	fmt.Printf("   Client ID: %s\n", config.ClientID)
	if config.ZeroTrust != nil {
		fmt.Printf("   Read Trust Threshold: %d\n", config.ZeroTrust.TrustLevelThresholds.Read)
		fmt.Printf("   Admin Trust Threshold: %d\n", config.ZeroTrust.TrustLevelThresholds.Admin)
	}
	if config.Cache != nil {
		fmt.Printf("   Cache Type: %s\n", config.Cache.Type)
		if config.Cache.Redis != nil {
			fmt.Printf("   Redis Host: %s\n", config.Cache.Redis.Host)
		}
	}
}

func demonstrateMultiEnvironmentConfig() {
	fmt.Println("🏗️  Multi-Environment Configuration")
	fmt.Println("----------------------------------")

	environments := []string{"development", "staging", "production"}

	for _, env := range environments {
		fmt.Printf("Environment: %s\n", env)

		options := config.LoaderOptions{
			Environment:     env,
			ConfigPaths:     []string{"./configs"},
			ValidateOnLoad:  true,
			TransformOnLoad: true,
			SecretSources: []config.SecretSource{
				&config.EnvironmentSecretSource{},
			},
		}

		loader := config.NewConfigLoader(options)
		
		// Add environment-specific validator
		loader.RegisterValidator(&config.EnvironmentValidator{Environment: env})

		// Create a minimal config for demonstration
		baseConfig := &types.ZeroTrustConfig{
			BaseURL:      "http://localhost:8080",
			Realm:        "demo",
			ClientID:     "demo-client",
			ClientSecret: "demo-secret",
			ZeroTrust: &types.ZeroTrustSettings{
				TrustLevelThresholds: types.TrustLevelThresholds{
					Read:   20,
					Write:  40,
					Admin:  60,
					Delete: 80,
				},
			},
		}

		// Apply environment-specific transformations
		transformer := &config.EnvironmentTransformer{}
		transformedConfig, err := transformer.Transform(baseConfig)
		if err != nil {
			log.Printf("   ❌ Transformation failed: %v", err)
			continue
		}

		fmt.Printf("   Trust Thresholds - Read: %d, Write: %d, Admin: %d, Delete: %d\n",
			transformedConfig.ZeroTrust.TrustLevelThresholds.Read,
			transformedConfig.ZeroTrust.TrustLevelThresholds.Write,
			transformedConfig.ZeroTrust.TrustLevelThresholds.Admin,
			transformedConfig.ZeroTrust.TrustLevelThresholds.Delete)
	}
}

func demonstrateConfigValidation() {
	fmt.Println("✅ Configuration Validation")
	fmt.Println("---------------------------")

	// Test different configurations
	testConfigs := []struct {
		name   string
		config *types.ZeroTrustConfig
		valid  bool
	}{
		{
			name: "Valid Configuration",
			config: &types.ZeroTrustConfig{
				BaseURL:      "https://keycloak.example.com",
				Realm:        "production",
				ClientID:     "api-service",
				ClientSecret: "secret123",
				ZeroTrust: &types.ZeroTrustSettings{
					TrustLevelThresholds: types.TrustLevelThresholds{
						Read:   25,
						Write:  50,
						Admin:  75,
						Delete: 90,
					},
					RiskThresholds: types.RiskThresholds{
						Low:      25,
						Medium:   50,
						High:     75,
						Critical: 90,
					},
					DeviceVerificationTTL: 24 * time.Hour,
					TrustDecayInterval:    1 * time.Hour,
				},
			},
			valid: true,
		},
		{
			name: "Invalid URL",
			config: &types.ZeroTrustConfig{
				BaseURL:      "not-a-url",
				Realm:        "test",
				ClientID:     "client",
				ClientSecret: "secret",
			},
			valid: false,
		},
		{
			name: "Invalid Trust Thresholds",
			config: &types.ZeroTrustConfig{
				BaseURL:      "https://keycloak.example.com",
				Realm:        "test",
				ClientID:     "client",
				ClientSecret: "secret",
				ZeroTrust: &types.ZeroTrustSettings{
					TrustLevelThresholds: types.TrustLevelThresholds{
						Read:   50, // Higher than write - invalid
						Write:  25,
						Admin:  75,
						Delete: 90,
					},
				},
			},
			valid: false,
		},
	}

	// Create validators
	defaultValidator := &config.DefaultValidator{}
	securityValidator := &config.SecurityValidator{}
	performanceValidator := &config.PerformanceValidator{}

	for _, test := range testConfigs {
		fmt.Printf("Testing: %s\n", test.name)

		// Test with default validator
		err := defaultValidator.Validate(test.config)
		if test.valid && err != nil {
			fmt.Printf("   ❌ Default validation failed unexpectedly: %v\n", err)
		} else if !test.valid && err == nil {
			fmt.Printf("   ❌ Default validation passed unexpectedly\n")
		} else {
			fmt.Printf("   ✅ Default validation: %s\n", getValidationStatus(err))
		}

		// Test with security validator
		err = securityValidator.Validate(test.config)
		fmt.Printf("   🔒 Security validation: %s\n", getValidationStatus(err))

		// Test with performance validator
		err = performanceValidator.Validate(test.config)
		fmt.Printf("   ⚡ Performance validation: %s\n", getValidationStatus(err))

		fmt.Println()
	}
}

func getValidationStatus(err error) string {
	if err != nil {
		return fmt.Sprintf("FAILED (%s)", err.Error())
	}
	return "PASSED"
}

func demonstrateConfigTransformation() {
	fmt.Println("🔄 Configuration Transformation")
	fmt.Println("-------------------------------")

	// Create base configuration
	baseConfig := &types.ZeroTrustConfig{
		BaseURL:      "http://localhost:8080",
		Realm:        "demo",
		ClientID:     "demo-client",
		ClientSecret: "${KEYCLOAK_CLIENT_SECRET}",
		Cache: &types.CacheConfig{
			Type: "redis",
			Redis: &types.RedisConfig{
				Password: "${REDIS_PASSWORD}",
			},
		},
	}

	fmt.Println("Original configuration:")
	printConfig(baseConfig)

	// Apply secret transformation
	fmt.Println("\n🔐 Applying Secret Transformation...")
	secretSources := []config.SecretSource{
		&MockSecretSource{
			secrets: map[string]string{
				"KEYCLOAK_CLIENT_SECRET": "actual-secret-123",
				"REDIS_PASSWORD":         "redis-pass-456",
			},
		},
	}

	secretTransformer := &config.SecretTransformer{}
	// Note: This would normally be initialized with secret sources
	secretTransformer.Transform(baseConfig)

	// Apply defaults transformation
	fmt.Println("🎯 Applying Defaults Transformation...")
	defaultsTransformer := &config.DefaultsTransformer{}
	transformedConfig, err := defaultsTransformer.Transform(baseConfig)
	if err != nil {
		log.Printf("Defaults transformation failed: %v", err)
		return
	}

	fmt.Println("\nTransformed configuration:")
	printConfig(transformedConfig)

	// Apply validation transformation
	fmt.Println("\n✅ Applying Validation Transformation...")
	validationTransformer := &config.ValidationTransformer{}
	finalConfig, err := validationTransformer.Transform(transformedConfig)
	if err != nil {
		log.Printf("Validation transformation failed: %v", err)
		return
	}

	fmt.Println("\nFinal configuration:")
	printConfig(finalConfig)
}

func demonstrateSecretManagement(ctx context.Context) {
	fmt.Println("🔐 Secret Management")
	fmt.Println("-------------------")

	// Create mock secret sources
	envSecretSource := &MockSecretSource{
		name: "environment",
		secrets: map[string]string{
			"KEYCLOAK_CLIENT_SECRET": "env-secret-123",
			"DATABASE_PASSWORD":      "env-db-pass",
		},
	}

	fileSecretSource := &MockSecretSource{
		name: "file",
		secrets: map[string]string{
			"REDIS_PASSWORD":    "file-redis-pass",
			"JWT_SIGNING_KEY":   "file-jwt-key",
		},
	}

	vaultSecretSource := &MockSecretSource{
		name: "vault",
		secrets: map[string]string{
			"API_ENCRYPTION_KEY": "vault-encryption-key",
			"TLS_PRIVATE_KEY":    "vault-tls-key",
		},
	}

	secretSources := []config.SecretSource{envSecretSource, fileSecretSource, vaultSecretSource}

	// Demonstrate secret retrieval
	secretKeys := []string{
		"KEYCLOAK_CLIENT_SECRET",
		"DATABASE_PASSWORD",
		"REDIS_PASSWORD",
		"JWT_SIGNING_KEY",
		"API_ENCRYPTION_KEY",
		"MISSING_SECRET",
	}

	for _, key := range secretKeys {
		fmt.Printf("Retrieving secret: %s\n", key)

		var secretValue string
		var sourceFound string

		for _, source := range secretSources {
			value, err := source.GetSecret(ctx, key)
			if err == nil && value != "" {
				secretValue = value
				sourceFound = source.GetSourceName()
				break
			}
		}

		if secretValue != "" {
			fmt.Printf("   ✅ Found in %s: %s\n", sourceFound, maskSecret(secretValue))
		} else {
			fmt.Printf("   ❌ Not found in any source\n")
		}
	}

	// Demonstrate secret listing
	fmt.Println("\nListing all secrets by source:")
	for _, source := range secretSources {
		fmt.Printf("\n%s secrets:\n", source.GetSourceName())
		secrets, err := source.ListSecrets(ctx)
		if err != nil {
			fmt.Printf("   ❌ Failed to list secrets: %v\n", err)
			continue
		}

		for key, value := range secrets {
			fmt.Printf("   %s: %s\n", key, maskSecret(value))
		}
	}
}

func demonstrateConfigWatching(ctx context.Context) {
	fmt.Println("👀 Configuration Watching")
	fmt.Println("-------------------------")

	// Create a temporary config file
	configContent := `
keycloak:
  base_url: "http://localhost:8080"
  realm: "demo"
  client_id: "demo-client"

zero_trust:
  trust_level_thresholds:
    read: 25
    write: 50
    admin: 75
    delete: 90
`

	tempFile := "/tmp/demo-config.yaml"
	if err := os.WriteFile(tempFile, []byte(configContent), 0644); err != nil {
		log.Printf("Failed to create temp config file: %v", err)
		return
	}
	defer os.Remove(tempFile)

	// Create config loader with watching
	options := config.LoaderOptions{
		ConfigPaths:     []string{"/tmp"},
		WatchChanges:    true,
		ValidateOnLoad:  true,
		TransformOnLoad: true,
	}

	loader := config.NewConfigLoader(options)

	// Register change handler
	changeHandler := &DemoConfigChangeHandler{}
	loader.RegisterChangeHandler(changeHandler)

	// Load initial configuration
	initialConfig, err := loader.LoadFromFile(tempFile)
	if err != nil {
		log.Printf("Failed to load initial config: %v", err)
		return
	}

	fmt.Printf("✅ Initial configuration loaded:\n")
	fmt.Printf("   Keycloak URL: %s\n", initialConfig.BaseURL)
	fmt.Printf("   Admin threshold: %d\n", initialConfig.ZeroTrust.TrustLevelThresholds.Admin)

	// Create a timeout context for the demo
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Start watching (in a real app, this would run continuously)
	fmt.Println("\n👁️  Starting configuration watcher...")
	watchErrChan := make(chan error, 1)

	go func() {
		watchErrChan <- loader.WatchConfig(timeoutCtx, func(newConfig *types.ZeroTrustConfig) {
			fmt.Printf("📝 Configuration changed! New admin threshold: %d\n", 
				newConfig.ZeroTrust.TrustLevelThresholds.Admin)
		})
	}()

	// Simulate config file change after a delay
	go func() {
		time.Sleep(2 * time.Second)
		
		updatedContent := `
keycloak:
  base_url: "http://localhost:8080"
  realm: "demo"
  client_id: "demo-client"

zero_trust:
  trust_level_thresholds:
    read: 30
    write: 55
    admin: 80
    delete: 95
`
		fmt.Println("✏️  Simulating configuration file change...")
		os.WriteFile(tempFile, []byte(updatedContent), 0644)
	}()

	// Wait for watching to complete or timeout
	select {
	case err := <-watchErrChan:
		if err != nil {
			fmt.Printf("Config watching failed: %v\n", err)
		}
	case <-timeoutCtx.Done():
		fmt.Println("⏰ Config watching demo completed")
	}
}

func demonstrateExternalServices(ctx context.Context) {
	fmt.Println("🔗 External Service Integration")
	fmt.Println("------------------------------")

	// Create integration configuration
	integrationConfig := &integrations.IntegrationConfig{
		SPIRE: &integrations.SPIREConfig{
			Enabled:     true,
			SocketPath:  "/tmp/spire-agent/public/api.sock",
			TrustDomain: "example.com",
		},
		LDAP: &integrations.LDAPConfig{
			Enabled:      true,
			URL:          "ldap://ldap.example.com",
			BindDN:       "cn=admin,dc=example,dc=com",
			BindPassword: "admin-password",
			BaseDN:       "dc=example,dc=com",
		},
		ThreatFeeds: &integrations.ThreatFeedsConfig{
			Enabled: true,
			Providers: []integrations.ThreatFeedProviderConfig{
				{
					Name:           "virustotal",
					Type:           "threat_intelligence",
					URL:            "https://www.virustotal.com/vtapi/v2",
					APIKey:         "vt-api-key",
					UpdateInterval: 1 * time.Hour,
				},
			},
		},
		Notifications: &integrations.NotificationConfig{
			Enabled: true,
			Providers: []integrations.NotificationProviderConfig{
				{
					Name:     "slack",
					Type:     "webhook",
					Endpoint: "https://hooks.slack.com/services/...",
					APIKey:   "slack-token",
				},
			},
		},
	}

	// Initialize external service manager
	serviceManager := integrations.NewExternalServiceManager(integrationConfig)

	fmt.Println("🚀 Initializing external services...")
	if err := serviceManager.Initialize(ctx); err != nil {
		log.Printf("Failed to initialize external services: %v", err)
		return
	}

	// Perform health checks
	fmt.Println("\n🏥 Performing health checks...")
	healthStatus := serviceManager.HealthCheck(ctx)
	for serviceName, healthy := range healthStatus {
		status := "❌ UNHEALTHY"
		if healthy {
			status = "✅ HEALTHY"
		}
		fmt.Printf("   %s: %s\n", serviceName, status)
	}

	// Get service metrics
	fmt.Println("\n📊 Service metrics:")
	metrics := serviceManager.GetMetrics(ctx)
	for serviceName, serviceMetrics := range metrics {
		fmt.Printf("   %s:\n", serviceName)
		for key, value := range serviceMetrics {
			fmt.Printf("     %s: %v\n", key, value)
		}
	}

	// Demonstrate service retrieval
	fmt.Println("\n🔍 Service lookup:")
	if spireService, exists := serviceManager.GetService("spire"); exists {
		fmt.Printf("   Found SPIRE service: %s (%s)\n", 
			spireService.GetServiceName(), spireService.GetServiceType())
	}

	threatServices := serviceManager.GetServicesByType("threat_intelligence")
	fmt.Printf("   Found %d threat intelligence services\n", len(threatServices))

	// Cleanup
	fmt.Println("\n🧹 Cleaning up external services...")
	if err := serviceManager.Shutdown(ctx); err != nil {
		log.Printf("Service shutdown failed: %v", err)
	} else {
		fmt.Println("✅ All external services shut down successfully")
	}
}

func demonstrateConfigSchema() {
	fmt.Println("📋 Configuration Schema Generation")
	fmt.Println("---------------------------------")

	// Create config loader to get schema
	options := config.LoaderOptions{
		ValidateOnLoad: true,
	}

	loader := config.NewConfigLoader(options)
	schema := loader.GetConfigSchema()

	fmt.Println("Generated configuration schema:")
	schemaJSON, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal schema: %v", err)
		return
	}

	fmt.Println(string(schemaJSON))

	// Show validation rules
	fmt.Println("\nValidation rules:")
	defaultValidator := &config.DefaultValidator{}
	rules := defaultValidator.GetValidationRules()

	for _, rule := range rules {
		fmt.Printf("Field: %s\n", rule.Path)
		fmt.Printf("  Type: %s, Required: %t\n", rule.Type, rule.Required)
		if rule.MinValue != nil {
			fmt.Printf("  Min: %v\n", rule.MinValue)
		}
		if rule.MaxValue != nil {
			fmt.Printf("  Max: %v\n", rule.MaxValue)
		}
		if len(rule.AllowedValues) > 0 {
			fmt.Printf("  Allowed values: %v\n", rule.AllowedValues)
		}
		if rule.Pattern != "" {
			fmt.Printf("  Pattern: %s\n", rule.Pattern)
		}
		fmt.Println()
	}
}

// Helper functions and types

func printConfig(config *types.ZeroTrustConfig) {
	configJSON, _ := json.MarshalIndent(config, "", "  ")
	fmt.Println(string(configJSON))
}

func maskSecret(secret string) string {
	if len(secret) <= 6 {
		return "***"
	}
	return secret[:3] + "***" + secret[len(secret)-3:]
}

// MockSecretSource for demonstration
type MockSecretSource struct {
	name    string
	secrets map[string]string
}

func (s *MockSecretSource) GetSecret(ctx context.Context, key string) (string, error) {
	if value, exists := s.secrets[key]; exists {
		return value, nil
	}
	return "", fmt.Errorf("secret not found: %s", key)
}

func (s *MockSecretSource) ListSecrets(ctx context.Context) (map[string]string, error) {
	return s.secrets, nil
}

func (s *MockSecretSource) GetSourceName() string {
	if s.name != "" {
		return s.name
	}
	return "mock"
}

// DemoConfigChangeHandler demonstrates configuration change handling
type DemoConfigChangeHandler struct{}

func (h *DemoConfigChangeHandler) OnConfigChange(ctx context.Context, oldConfig, newConfig *types.ZeroTrustConfig) error {
	fmt.Printf("🔄 Configuration changed detected!\n")
	
	if oldConfig.ZeroTrust != nil && newConfig.ZeroTrust != nil {
		oldAdmin := oldConfig.ZeroTrust.TrustLevelThresholds.Admin
		newAdmin := newConfig.ZeroTrust.TrustLevelThresholds.Admin
		
		if oldAdmin != newAdmin {
			fmt.Printf("   Admin threshold changed: %d -> %d\n", oldAdmin, newAdmin)
		}
	}
	
	return nil
}

func (h *DemoConfigChangeHandler) GetHandlerName() string {
	return "demo_change_handler"
}