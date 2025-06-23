// Package config provides advanced configuration loading and management for Zero Trust
package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
	"gopkg.in/yaml.v3"
)

// ConfigLoader provides advanced configuration loading capabilities
type ConfigLoader struct {
	viper          *viper.Viper
	watchers       []ConfigWatcher
	validators     []ConfigValidator
	transformers   []ConfigTransformer
	changeHandlers []ConfigChangeHandler
	environment    string
	configPaths    []string
}

// ConfigWatcher monitors configuration changes
type ConfigWatcher interface {
	Watch(ctx context.Context, callback func(event ConfigEvent)) error
	Stop() error
}

// ConfigValidator validates configuration values
type ConfigValidator interface {
	Validate(config *types.ZeroTrustConfig) error
	GetValidationRules() []ValidationRule
}

// ConfigTransformer transforms configuration during loading
type ConfigTransformer interface {
	Transform(config *types.ZeroTrustConfig) (*types.ZeroTrustConfig, error)
	GetPriority() int
}

// ConfigChangeHandler handles configuration changes
type ConfigChangeHandler interface {
	OnConfigChange(ctx context.Context, oldConfig, newConfig *types.ZeroTrustConfig) error
	GetHandlerName() string
}

// ConfigEvent represents a configuration change event
type ConfigEvent struct {
	Type      ConfigEventType `json:"type"`
	Path      string          `json:"path"`
	Timestamp time.Time       `json:"timestamp"`
	Source    string          `json:"source"`
	Changes   []ConfigChange  `json:"changes"`
}

// ConfigEventType represents the type of configuration event
type ConfigEventType string

const (
	ConfigEventCreated  ConfigEventType = "created"
	ConfigEventModified ConfigEventType = "modified"
	ConfigEventDeleted  ConfigEventType = "deleted"
	ConfigEventReloaded ConfigEventType = "reloaded"
)

// ConfigChange represents a specific configuration change
type ConfigChange struct {
	Key      string      `json:"key"`
	OldValue interface{} `json:"old_value,omitempty"`
	NewValue interface{} `json:"new_value"`
	Action   string      `json:"action"` // added, modified, deleted
}

// ValidationRule represents a configuration validation rule
type ValidationRule struct {
	Path        string                 `json:"path"`
	Type        string                 `json:"type"`
	Required    bool                   `json:"required"`
	MinValue    interface{}            `json:"min_value,omitempty"`
	MaxValue    interface{}            `json:"max_value,omitempty"`
	AllowedValues []interface{}        `json:"allowed_values,omitempty"`
	Pattern     string                 `json:"pattern,omitempty"`
	Validator   func(interface{}) error `json:"-"`
}

// LoaderOptions configures the configuration loader
type LoaderOptions struct {
	Environment     string
	ConfigPaths     []string
	WatchChanges    bool
	ValidateOnLoad  bool
	TransformOnLoad bool
	SecretSources   []SecretSource
}

// SecretSource represents a source for secrets
type SecretSource interface {
	GetSecret(ctx context.Context, key string) (string, error)
	ListSecrets(ctx context.Context) (map[string]string, error)
	GetSourceName() string
}

// NewConfigLoader creates a new configuration loader
func NewConfigLoader(options LoaderOptions) *ConfigLoader {
	v := viper.New()
	
	// Set default configuration type
	v.SetConfigType("yaml")
	
	// Add config paths
	for _, path := range options.ConfigPaths {
		v.AddConfigPath(path)
	}
	
	// Set environment variable settings
	v.SetEnvPrefix("ZEROTRUST")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()
	
	loader := &ConfigLoader{
		viper:          v,
		watchers:       make([]ConfigWatcher, 0),
		validators:     make([]ConfigValidator, 0),
		transformers:   make([]ConfigTransformer, 0),
		changeHandlers: make([]ConfigChangeHandler, 0),
		environment:    options.Environment,
		configPaths:    options.ConfigPaths,
	}
	
	// Register default validators
	loader.RegisterValidator(&DefaultValidator{})
	loader.RegisterValidator(&SecurityValidator{})
	loader.RegisterValidator(&PerformanceValidator{})
	
	// Register default transformers
	loader.RegisterTransformer(&EnvironmentTransformer{environment: options.Environment})
	loader.RegisterTransformer(&SecretTransformer{sources: options.SecretSources})
	
	return loader
}

// validateFilePath validates and cleans the file path to prevent path traversal attacks
func (l *ConfigLoader) validateFilePath(filePath string) (string, error) {
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

// LoadConfig loads configuration from files and environment
func (l *ConfigLoader) LoadConfig(configName string) (*types.ZeroTrustConfig, error) {
	// Set config name
	l.viper.SetConfigName(configName)
	
	// Try to read config file
	if err := l.viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found, continue with environment variables
	}
	
	// Load base configuration
	var config types.ZeroTrustConfig
	if err := l.viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	// Apply transformers
	transformedConfig := &config
	for _, transformer := range l.getSortedTransformers() {
		var err error
		transformedConfig, err = transformer.Transform(transformedConfig)
		if err != nil {
			return nil, fmt.Errorf("config transformation failed: %w", err)
		}
	}
	
	// Validate configuration
	for _, validator := range l.validators {
		if err := validator.Validate(transformedConfig); err != nil {
			return nil, fmt.Errorf("config validation failed: %w", err)
		}
	}
	
	return transformedConfig, nil
}

// LoadFromFile loads configuration from a specific file
func (l *ConfigLoader) LoadFromFile(filePath string) (*types.ZeroTrustConfig, error) {
	// Validate and sanitize the file path to prevent path traversal
	safePath, err := l.validateFilePath(filePath)
	if err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}
	
	// Read file directly
	data, err := os.ReadFile(safePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	
	// Parse YAML
	var config types.ZeroTrustConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	
	// Apply transformers and validators
	return l.processConfig(&config)
}

// LoadFromEnv loads configuration entirely from environment variables
func (l *ConfigLoader) LoadFromEnv() (*types.ZeroTrustConfig, error) {
	// Create new viper instance for env-only loading
	v := viper.New()
	v.SetEnvPrefix("ZEROTRUST")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()
	
	// Set all possible config keys
	l.setConfigDefaults(v)
	
	var config types.ZeroTrustConfig
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal env config: %w", err)
	}
	
	return l.processConfig(&config)
}

// WatchConfig starts watching for configuration changes
func (l *ConfigLoader) WatchConfig(ctx context.Context, callback func(*types.ZeroTrustConfig)) error {
	// Start file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}
	
	// Add config paths to watcher
	for _, path := range l.configPaths {
		if err := watcher.Add(path); err != nil {
			return fmt.Errorf("failed to watch path %s: %w", path, err)
		}
	}
	
	go func() {
		defer watcher.Close()
		
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				
				if event.Op&fsnotify.Write == fsnotify.Write {
					// Config file changed, reload
					if config, err := l.reloadConfig(); err == nil {
						callback(config)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				fmt.Printf("Config watcher error: %v\n", err)
			}
		}
	}()
	
	return nil
}

// RegisterValidator registers a configuration validator
func (l *ConfigLoader) RegisterValidator(validator ConfigValidator) {
	l.validators = append(l.validators, validator)
}

// RegisterTransformer registers a configuration transformer
func (l *ConfigLoader) RegisterTransformer(transformer ConfigTransformer) {
	l.transformers = append(l.transformers, transformer)
}

// RegisterChangeHandler registers a configuration change handler
func (l *ConfigLoader) RegisterChangeHandler(handler ConfigChangeHandler) {
	l.changeHandlers = append(l.changeHandlers, handler)
}

// GetConfigSchema returns the configuration schema
func (l *ConfigLoader) GetConfigSchema() map[string]interface{} {
	schema := make(map[string]interface{})
	
	// Collect validation rules from all validators
	for _, validator := range l.validators {
		rules := validator.GetValidationRules()
		for _, rule := range rules {
			schema[rule.Path] = map[string]interface{}{
				"type":           rule.Type,
				"required":       rule.Required,
				"allowed_values": rule.AllowedValues,
				"pattern":        rule.Pattern,
			}
		}
	}
	
	return schema
}

// ValidateConfig validates a configuration without loading it
func (l *ConfigLoader) ValidateConfig(config *types.ZeroTrustConfig) error {
	for _, validator := range l.validators {
		if err := validator.Validate(config); err != nil {
			return err
		}
	}
	return nil
}

// Private helper methods

func (l *ConfigLoader) processConfig(config *types.ZeroTrustConfig) (*types.ZeroTrustConfig, error) {
	// Apply transformers
	transformedConfig := config
	for _, transformer := range l.getSortedTransformers() {
		var err error
		transformedConfig, err = transformer.Transform(transformedConfig)
		if err != nil {
			return nil, fmt.Errorf("config transformation failed: %w", err)
		}
	}
	
	// Validate configuration
	for _, validator := range l.validators {
		if err := validator.Validate(transformedConfig); err != nil {
			return nil, fmt.Errorf("config validation failed: %w", err)
		}
	}
	
	return transformedConfig, nil
}

func (l *ConfigLoader) getSortedTransformers() []ConfigTransformer {
	// Sort transformers by priority
	transformers := make([]ConfigTransformer, len(l.transformers))
	copy(transformers, l.transformers)
	
	// Simple bubble sort by priority (higher priority first)
	for i := 0; i < len(transformers)-1; i++ {
		for j := 0; j < len(transformers)-i-1; j++ {
			if transformers[j].GetPriority() < transformers[j+1].GetPriority() {
				transformers[j], transformers[j+1] = transformers[j+1], transformers[j]
			}
		}
	}
	
	return transformers
}

func (l *ConfigLoader) reloadConfig() (*types.ZeroTrustConfig, error) {
	// Get current config
	oldConfig := &types.ZeroTrustConfig{}
	if err := l.viper.Unmarshal(oldConfig); err != nil {
		return nil, err
	}
	
	// Reload from file
	if err := l.viper.ReadInConfig(); err != nil {
		return nil, err
	}
	
	// Parse new config
	var newConfig types.ZeroTrustConfig
	if err := l.viper.Unmarshal(&newConfig); err != nil {
		return nil, err
	}
	
	// Process new config
	processedConfig, err := l.processConfig(&newConfig)
	if err != nil {
		return nil, err
	}
	
	// Notify change handlers
	ctx := context.Background()
	for _, handler := range l.changeHandlers {
		if err := handler.OnConfigChange(ctx, oldConfig, processedConfig); err != nil {
			fmt.Printf("Config change handler %s failed: %v\n", handler.GetHandlerName(), err)
		}
	}
	
	return processedConfig, nil
}

func (l *ConfigLoader) setConfigDefaults(v *viper.Viper) {
	// Set all possible configuration keys for environment variable mapping
	v.SetDefault("keycloak.base_url", "")
	v.SetDefault("keycloak.realm", "")
	v.SetDefault("keycloak.client_id", "")
	v.SetDefault("keycloak.client_secret", "")
	
	v.SetDefault("zero_trust.enable_device_attestation", true)
	v.SetDefault("zero_trust.enable_risk_assessment", true)
	v.SetDefault("zero_trust.enable_continuous_auth", true)
	
	v.SetDefault("zero_trust.trust_level_thresholds.read", 25)
	v.SetDefault("zero_trust.trust_level_thresholds.write", 50)
	v.SetDefault("zero_trust.trust_level_thresholds.admin", 75)
	v.SetDefault("zero_trust.trust_level_thresholds.delete", 90)
	
	v.SetDefault("cache.type", "memory")
	v.SetDefault("cache.redis.host", "localhost")
	v.SetDefault("cache.redis.port", 6379)
	
	v.SetDefault("observability.logging.level", "info")
	v.SetDefault("observability.logging.format", "json")
	v.SetDefault("observability.metrics.enabled", true)
}

// LoadConfigWithOptions loads configuration with advanced options
func LoadConfigWithOptions(configName string, options LoaderOptions) (*types.ZeroTrustConfig, error) {
	loader := NewConfigLoader(options)
	return loader.LoadConfig(configName)
}

// LoadConfig provides a simple configuration loading interface
func LoadConfig(configPath string) (*types.ZeroTrustConfig, error) {
	options := LoaderOptions{
		ConfigPaths:     []string{filepath.Dir(configPath)},
		ValidateOnLoad:  true,
		TransformOnLoad: true,
	}
	
	loader := NewConfigLoader(options)
	configName := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
	return loader.LoadConfig(configName)
}

// LoadFromFile loads configuration from a specific file path
func LoadFromFile(filePath string) (*types.ZeroTrustConfig, error) {
	options := LoaderOptions{
		ValidateOnLoad:  true,
		TransformOnLoad: true,
	}
	
	loader := NewConfigLoader(options)
	return loader.LoadFromFile(filePath)
}

// LoadFromEnv loads configuration from environment variables only
func LoadFromEnv() (*types.ZeroTrustConfig, error) {
	options := LoaderOptions{
		ValidateOnLoad:  true,
		TransformOnLoad: true,
	}
	
	loader := NewConfigLoader(options)
	return loader.LoadFromEnv()
}