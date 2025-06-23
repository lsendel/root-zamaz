// Plugin System Example
// This example demonstrates how to create and use plugins with the Zero Trust library

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/config"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/plugins"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// CustomSecurityPlugin demonstrates a custom security plugin
type CustomSecurityPlugin struct {
	config     map[string]interface{}
	alertCount int
	enabled    bool
}

func (p *CustomSecurityPlugin) GetName() string        { return "custom_security" }
func (p *CustomSecurityPlugin) GetVersion() string     { return "1.0.0" }
func (p *CustomSecurityPlugin) GetDescription() string { return "Custom security plugin for enhanced monitoring" }

func (p *CustomSecurityPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	p.config = config
	p.enabled = true
	p.alertCount = 0
	
	if enabled, ok := config["enabled"].(bool); ok {
		p.enabled = enabled
	}
	
	log.Printf("Custom security plugin initialized with config: %v", config)
	return nil
}

func (p *CustomSecurityPlugin) Cleanup(ctx context.Context) error {
	log.Printf("Custom security plugin cleanup - Total alerts: %d", p.alertCount)
	return nil
}

func (p *CustomSecurityPlugin) GetMetadata() plugins.PluginMetadata {
	return plugins.PluginMetadata{
		Name:        p.GetName(),
		Version:     p.GetVersion(),
		Description: p.GetDescription(),
		Author:      "Security Team",
		License:     "MIT",
		Tags:        []string{"security", "monitoring", "custom"},
		Config:      p.config,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

func (p *CustomSecurityPlugin) ExecuteHook(ctx context.Context, hookType plugins.HookType, data map[string]interface{}) error {
	if !p.enabled {
		return nil
	}
	
	// Custom security logic
	switch hookType {
	case plugins.HookPostAuth:
		return p.handleAuthEvent(ctx, data)
	case plugins.HookDeviceAttestation:
		return p.handleDeviceEvent(ctx, data)
	case plugins.HookError:
		return p.handleErrorEvent(ctx, data)
	}
	
	return nil
}

func (p *CustomSecurityPlugin) GetHookTypes() []plugins.HookType {
	return []plugins.HookType{
		plugins.HookPostAuth,
		plugins.HookDeviceAttestation,
		plugins.HookError,
	}
}

func (p *CustomSecurityPlugin) handleAuthEvent(ctx context.Context, data map[string]interface{}) error {
	// Check for suspicious authentication patterns
	if userID, ok := data["user_id"].(string); ok {
		if ipAddress, ok := data["ip_address"].(string); ok {
			// Example: Flag logins from new countries
			if p.isNewCountry(userID, ipAddress) {
				p.alertCount++
				log.Printf("SECURITY ALERT: User %s login from new country (IP: %s)", userID, ipAddress)
				
				// Trigger additional verification
				data["require_additional_verification"] = true
			}
		}
	}
	
	return nil
}

func (p *CustomSecurityPlugin) handleDeviceEvent(ctx context.Context, data map[string]interface{}) error {
	// Check for device security issues
	if deviceID, ok := data["device_id"].(string); ok {
		if trustScore, ok := data["trust_score"].(int); ok {
			if trustScore < 30 {
				p.alertCount++
				log.Printf("SECURITY ALERT: Low trust device detected (Device: %s, Score: %d)", deviceID, trustScore)
				
				// Require device re-attestation
				data["require_reatttestation"] = true
			}
		}
	}
	
	return nil
}

func (p *CustomSecurityPlugin) handleErrorEvent(ctx context.Context, data map[string]interface{}) error {
	// Monitor for error patterns that might indicate attacks
	if errorType, ok := data["error_type"].(string); ok {
		if errorType == "authentication_failure" || errorType == "invalid_token" {
			p.alertCount++
			log.Printf("SECURITY ALERT: Potential attack detected - Error: %s", errorType)
		}
	}
	
	return nil
}

func (p *CustomSecurityPlugin) isNewCountry(userID, ipAddress string) bool {
	// Simplified check - in production, this would query user's historical locations
	// For demo, we'll flag certain IP ranges as "new countries"
	suspiciousIPs := []string{"1.2.3.", "192.0.2.", "203.0.113."}
	
	for _, suspiciousIP := range suspiciousIPs {
		if contains(ipAddress, suspiciousIP) {
			return true
		}
	}
	
	return false
}

func contains(str, substr string) bool {
	return len(str) >= len(substr) && str[:len(substr)] == substr
}

// CustomValidatorPlugin demonstrates a custom validator plugin
type CustomValidatorPlugin struct {
	config  map[string]interface{}
	enabled bool
	rules   []plugins.ValidationRule
}

func (p *CustomValidatorPlugin) GetName() string        { return "custom_validator" }
func (p *CustomValidatorPlugin) GetVersion() string     { return "1.0.0" }
func (p *CustomValidatorPlugin) GetDescription() string { return "Custom validation plugin for business rules" }

func (p *CustomValidatorPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	p.config = config
	p.enabled = true
	
	// Define custom validation rules
	p.rules = []plugins.ValidationRule{
		{
			Field:    "email",
			Type:     "string",
			Required: true,
			Pattern:  `^[a-zA-Z0-9._%+-]+@company\.com$`,
		},
		{
			Field:     "trust_level",
			Type:      "integer",
			Required:  true,
			MinValue:  0,
			MaxValue:  100,
		},
	}
	
	log.Printf("Custom validator plugin initialized with %d rules", len(p.rules))
	return nil
}

func (p *CustomValidatorPlugin) Cleanup(ctx context.Context) error {
	log.Println("Custom validator plugin cleanup completed")
	return nil
}

func (p *CustomValidatorPlugin) GetMetadata() plugins.PluginMetadata {
	return plugins.PluginMetadata{
		Name:        p.GetName(),
		Version:     p.GetVersion(),
		Description: p.GetDescription(),
		Author:      "Business Team",
		License:     "MIT",
		Tags:        []string{"validation", "business_rules", "custom"},
		Config:      p.config,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

func (p *CustomValidatorPlugin) ValidateToken(ctx context.Context, token string, claims *types.ZeroTrustClaims) error {
	if !p.enabled {
		return nil
	}
	
	// Custom token validation logic
	if claims.Email == "" {
		return fmt.Errorf("email claim is required")
	}
	
	// Validate company email domain
	if !contains(claims.Email, "@company.com") {
		return fmt.Errorf("only company email addresses are allowed")
	}
	
	// Check trust level requirements
	if claims.TrustLevel < 25 {
		return fmt.Errorf("minimum trust level of 25 required, got %d", claims.TrustLevel)
	}
	
	return nil
}

func (p *CustomValidatorPlugin) ValidateUser(ctx context.Context, user *types.UserInfo) error {
	if !p.enabled {
		return nil
	}
	
	// Custom user validation logic
	if user.Email == "" {
		return fmt.Errorf("user email is required")
	}
	
	if !contains(user.Email, "@company.com") {
		return fmt.Errorf("only company users are allowed")
	}
	
	return nil
}

func (p *CustomValidatorPlugin) ValidateDevice(ctx context.Context, device *types.Device) error {
	if !p.enabled {
		return nil
	}
	
	// Custom device validation logic
	if device.TrustLevel < 30 {
		return fmt.Errorf("device trust level too low: %d", device.TrustLevel)
	}
	
	// Only allow certain device types
	allowedTypes := []string{"mobile", "desktop", "tablet"}
	typeAllowed := false
	for _, allowedType := range allowedTypes {
		if device.DeviceType == allowedType {
			typeAllowed = true
			break
		}
	}
	
	if !typeAllowed {
		return fmt.Errorf("device type %s not allowed", device.DeviceType)
	}
	
	return nil
}

func (p *CustomValidatorPlugin) GetValidationRules() []plugins.ValidationRule {
	return p.rules
}

// CustomTransformerPlugin demonstrates a custom transformer plugin
type CustomTransformerPlugin struct {
	config  map[string]interface{}
	enabled bool
}

func (p *CustomTransformerPlugin) GetName() string        { return "custom_transformer" }
func (p *CustomTransformerPlugin) GetVersion() string     { return "1.0.0" }
func (p *CustomTransformerPlugin) GetDescription() string { return "Custom transformer plugin for data enrichment" }

func (p *CustomTransformerPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	p.config = config
	p.enabled = true
	
	log.Println("Custom transformer plugin initialized")
	return nil
}

func (p *CustomTransformerPlugin) Cleanup(ctx context.Context) error {
	log.Println("Custom transformer plugin cleanup completed")
	return nil
}

func (p *CustomTransformerPlugin) GetMetadata() plugins.PluginMetadata {
	return plugins.PluginMetadata{
		Name:        p.GetName(),
		Version:     p.GetVersion(),
		Description: p.GetDescription(),
		Author:      "Data Team",
		License:     "MIT",
		Tags:        []string{"transformation", "enrichment", "custom"},
		Config:      p.config,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

func (p *CustomTransformerPlugin) TransformClaims(ctx context.Context, claims *types.ZeroTrustClaims) (*types.ZeroTrustClaims, error) {
	if !p.enabled {
		return claims, nil
	}
	
	// Create a copy of claims
	newClaims := *claims
	
	// Add custom claims based on business logic
	if newClaims.Email != "" {
		// Extract department from email
		if contains(newClaims.Email, "engineering") {
			newClaims.Roles = append(newClaims.Roles, "developer")
		} else if contains(newClaims.Email, "sales") {
			newClaims.Roles = append(newClaims.Roles, "sales_rep")
		} else if contains(newClaims.Email, "admin") {
			newClaims.Roles = append(newClaims.Roles, "administrator")
		}
	}
	
	// Enhance trust level based on roles
	if containsRole(newClaims.Roles, "administrator") {
		newClaims.TrustLevel += 10 // Admins get trust bonus
	}
	
	// Cap trust level at 100
	if newClaims.TrustLevel > 100 {
		newClaims.TrustLevel = 100
	}
	
	log.Printf("Transformed claims for user %s: trust_level=%d, roles=%v", 
		newClaims.UserID, newClaims.TrustLevel, newClaims.Roles)
	
	return &newClaims, nil
}

func (p *CustomTransformerPlugin) TransformUserInfo(ctx context.Context, user *types.UserInfo) (*types.UserInfo, error) {
	if !p.enabled {
		return user, nil
	}
	
	// Create a copy of user info
	newUser := *user
	
	// Add custom attributes
	if newUser.Attributes == nil {
		newUser.Attributes = make(map[string]interface{})
	}
	
	// Add department based on email
	if contains(newUser.Email, "engineering") {
		newUser.Attributes["department"] = "Engineering"
	} else if contains(newUser.Email, "sales") {
		newUser.Attributes["department"] = "Sales"
	}
	
	// Add last login enrichment
	newUser.Attributes["last_transform"] = time.Now().Format(time.RFC3339)
	
	return &newUser, nil
}

func (p *CustomTransformerPlugin) GetTransformationRules() []plugins.TransformationRule {
	return []plugins.TransformationRule{
		{
			SourceField: "email",
			TargetField: "department",
			Transform:   "extract_department",
			Condition:   "contains(@company.com)",
		},
		{
			SourceField: "roles",
			TargetField: "trust_level",
			Transform:   "role_based_trust",
		},
	}
}

func containsRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

func main() {
	fmt.Println("🔌 Plugin System Example")
	fmt.Println("========================")
	fmt.Println()

	ctx := context.Background()

	// 1. Initialize plugin manager
	fmt.Println("🔧 Initializing Plugin Manager...")
	
	pluginConfig := &plugins.PluginConfig{
		PluginDir:       "./plugins",
		EnableHotReload: false,
		MaxPlugins:      10,
		Timeout:         30 * time.Second,
		EnabledPlugins:  []string{"custom_security", "custom_validator", "custom_transformer"},
		PluginConfigs: map[string]interface{}{
			"custom_security": map[string]interface{}{
				"enabled":       true,
				"alert_threshold": 5,
			},
			"custom_validator": map[string]interface{}{
				"enabled":     true,
				"strict_mode": true,
			},
			"custom_transformer": map[string]interface{}{
				"enabled": true,
			},
		},
	}
	
	pluginManager := plugins.NewPluginManager(pluginConfig)
	
	// 2. Register custom plugins
	fmt.Println("📝 Registering Custom Plugins...")
	
	// Register security plugin
	securityPlugin := &CustomSecurityPlugin{}
	if err := pluginManager.RegisterPlugin(ctx, securityPlugin); err != nil {
		log.Fatalf("Failed to register security plugin: %v", err)
	}
	
	// Register validator plugin
	validatorPlugin := &CustomValidatorPlugin{}
	if err := pluginManager.RegisterPlugin(ctx, validatorPlugin); err != nil {
		log.Fatalf("Failed to register validator plugin: %v", err)
	}
	
	// Register transformer plugin
	transformerPlugin := &CustomTransformerPlugin{}
	if err := pluginManager.RegisterPlugin(ctx, transformerPlugin); err != nil {
		log.Fatalf("Failed to register transformer plugin: %v", err)
	}
	
	fmt.Printf("✅ Registered %d plugins successfully\n", 3)
	fmt.Println()

	// 3. List all plugins
	fmt.Println("📋 Loaded Plugins:")
	pluginList := pluginManager.ListPlugins()
	for i, plugin := range pluginList {
		fmt.Printf("%d. %s v%s - %s\n", i+1, plugin.Name, plugin.Version, plugin.Description)
		fmt.Printf("   Author: %s, Tags: %v\n", plugin.Author, plugin.Tags)
	}
	fmt.Println()

	// 4. Demonstrate hook execution
	fmt.Println("🪝 Demonstrating Hook Execution...")
	
	// Simulate authentication event
	authData := map[string]interface{}{
		"user_id":    "user123",
		"ip_address": "203.0.113.1", // This will trigger our security alert
		"success":    true,
		"timestamp":  time.Now(),
	}
	
	fmt.Println("🔐 Executing post-auth hook...")
	if err := pluginManager.ExecuteHook(ctx, plugins.HookPostAuth, authData); err != nil {
		fmt.Printf("Hook execution failed: %v\n", err)
	}
	fmt.Println()

	// Simulate device attestation event
	deviceData := map[string]interface{}{
		"device_id":   "device456",
		"user_id":     "user123",
		"trust_score": 25, // Low trust score will trigger alert
		"platform":    "android",
		"verified":    true,
	}
	
	fmt.Println("📱 Executing device attestation hook...")
	if err := pluginManager.ExecuteHook(ctx, plugins.HookDeviceAttestation, deviceData); err != nil {
		fmt.Printf("Hook execution failed: %v\n", err)
	}
	fmt.Println()

	// 5. Demonstrate plugin validation
	fmt.Println("✅ Demonstrating Plugin Validation...")
	
	// Test token validation
	claims := &types.ZeroTrustClaims{
		UserID:     "user123",
		Username:   "john.doe",
		Email:      "john.doe@company.com", // Valid company email
		TrustLevel: 50,
		Roles:      []string{"user"},
	}
	
	fmt.Println("🎫 Testing token validation...")
	if validator, ok := pluginManager.GetPlugin("custom_validator"); ok {
		if validatorPlugin, ok := validator.(plugins.ValidatorPlugin); ok {
			if err := validatorPlugin.ValidateToken(ctx, "dummy-token", claims); err != nil {
				fmt.Printf("❌ Token validation failed: %v\n", err)
			} else {
				fmt.Println("✅ Token validation passed")
			}
		}
	}
	fmt.Println()

	// 6. Demonstrate data transformation
	fmt.Println("🔄 Demonstrating Data Transformation...")
	
	originalClaims := &types.ZeroTrustClaims{
		UserID:     "user456",
		Username:   "jane.smith",
		Email:      "jane.smith.engineering@company.com", // Engineering email
		TrustLevel: 60,
		Roles:      []string{"user"},
	}
	
	fmt.Printf("Original claims: trust_level=%d, roles=%v\n", originalClaims.TrustLevel, originalClaims.Roles)
	
	if transformer, ok := pluginManager.GetPlugin("custom_transformer"); ok {
		if transformerPlugin, ok := transformer.(plugins.TransformerPlugin); ok {
			transformedClaims, err := transformerPlugin.TransformClaims(ctx, originalClaims)
			if err != nil {
				fmt.Printf("❌ Claims transformation failed: %v\n", err)
			} else {
				fmt.Printf("Transformed claims: trust_level=%d, roles=%v\n", 
					transformedClaims.TrustLevel, transformedClaims.Roles)
			}
		}
	}
	fmt.Println()

	// 7. Demonstrate middleware processing
	fmt.Println("🌐 Demonstrating Middleware Processing...")
	
	request := &plugins.PluginRequest{
		ID:     "req123",
		Type:   "http",
		Method: "POST",
		Path:   "/api/secure",
		Headers: map[string]string{
			"Authorization": "Bearer token123",
			"X-Real-IP":    "203.0.113.1",
		},
		UserInfo: &types.UserInfo{
			UserID: "user123",
			Email:  "user@company.com",
		},
	}
	
	response, err := pluginManager.ProcessMiddleware(ctx, request)
	if err != nil {
		fmt.Printf("❌ Middleware processing failed: %v\n", err)
	} else {
		fmt.Printf("✅ Middleware processing completed: status=%d, continue=%t\n", 
			response.StatusCode, response.Continue)
	}
	fmt.Println()

	// 8. Show plugin metrics
	fmt.Println("📊 Plugin Metrics:")
	for _, plugin := range pluginList {
		fmt.Printf("Plugin: %s\n", plugin.Name)
		configJSON, _ := json.MarshalIndent(plugin.Config, "  ", "  ")
		fmt.Printf("  Config: %s\n", configJSON)
	}
	fmt.Println()

	// 9. Configuration integration example
	fmt.Println("⚙️  Configuration Integration Example...")
	
	// Create a config loader with plugin support
	loaderOptions := config.LoaderOptions{
		Environment:     "development",
		ConfigPaths:     []string{"./configs"},
		ValidateOnLoad:  true,
		TransformOnLoad: true,
	}
	
	configLoader := config.NewConfigLoader(loaderOptions)
	
	// Add custom transformer that integrates with plugins
	configLoader.RegisterTransformer(&PluginConfigTransformer{
		pluginManager: pluginManager,
	})
	
	fmt.Println("✅ Plugin-aware configuration loader created")
	fmt.Println()

	// 10. Cleanup
	fmt.Println("🧹 Cleaning up plugins...")
	if err := pluginManager.Shutdown(ctx); err != nil {
		fmt.Printf("Plugin shutdown failed: %v\n", err)
	} else {
		fmt.Println("✅ All plugins shut down successfully")
	}

	fmt.Println()
	fmt.Println("🎉 Plugin system example completed!")
}

// PluginConfigTransformer integrates plugins with configuration loading
type PluginConfigTransformer struct {
	pluginManager *plugins.PluginManager
}

func (t *PluginConfigTransformer) Transform(config *types.ZeroTrustConfig) (*types.ZeroTrustConfig, error) {
	// Apply plugin-based configuration transformations
	newConfig := *config
	
	// Example: Allow plugins to modify trust thresholds based on environment
	if newConfig.ZeroTrust != nil {
		// Get validator plugins and apply their recommendations
		validators := t.pluginManager.GetServicesByType("validator")
		for _, validator := range validators {
			// Plugin could suggest trust level adjustments
			log.Printf("Applied configuration transformation from plugin: %s", validator.GetServiceName())
		}
	}
	
	return &newConfig, nil
}

func (t *PluginConfigTransformer) GetPriority() int {
	return 50 // Medium priority
}