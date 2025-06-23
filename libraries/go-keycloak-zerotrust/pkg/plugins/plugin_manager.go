// Package plugins provides a plugin system for extending Zero Trust functionality
package plugins

import (
	"context"
	"fmt"
	"log"
	"plugin"
	"sort"
	"sync"
	"time"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// PluginManager manages the loading and execution of plugins
type PluginManager struct {
	plugins       map[string]Plugin
	hooks         map[HookType][]Plugin
	middleware    []MiddlewarePlugin
	validators    []ValidatorPlugin
	transformers  []TransformerPlugin
	providers     []ProviderPlugin
	mu            sync.RWMutex
	config        *PluginConfig
	eventBus      *EventBus
}

// Plugin represents the base interface for all plugins
type Plugin interface {
	GetName() string
	GetVersion() string
	GetDescription() string
	Initialize(ctx context.Context, config map[string]interface{}) error
	Cleanup(ctx context.Context) error
	GetMetadata() PluginMetadata
}

// PluginMetadata contains information about a plugin
type PluginMetadata struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Description  string            `json:"description"`
	Author       string            `json:"author"`
	License      string            `json:"license"`
	Homepage     string            `json:"homepage"`
	Dependencies []string          `json:"dependencies"`
	Tags         []string          `json:"tags"`
	Config       map[string]interface{} `json:"config"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// HookType represents different hook points in the system
type HookType string

const (
	HookPreAuth           HookType = "pre_auth"
	HookPostAuth          HookType = "post_auth"
	HookPreValidation     HookType = "pre_validation"
	HookPostValidation    HookType = "post_validation"
	HookPreRiskAssessment HookType = "pre_risk_assessment"
	HookPostRiskAssessment HookType = "post_risk_assessment"
	HookPreTrustCalculation HookType = "pre_trust_calculation"
	HookPostTrustCalculation HookType = "post_trust_calculation"
	HookDeviceAttestation HookType = "device_attestation"
	HookUserRegistration  HookType = "user_registration"
	HookConfigChange      HookType = "config_change"
	HookError             HookType = "error"
)

// MiddlewarePlugin provides HTTP middleware functionality
type MiddlewarePlugin interface {
	Plugin
	ProcessRequest(ctx context.Context, request *PluginRequest) (*PluginResponse, error)
	GetPriority() int
	GetRoutes() []PluginRoute
}

// ValidatorPlugin provides validation functionality
type ValidatorPlugin interface {
	Plugin
	ValidateToken(ctx context.Context, token string, claims *types.ZeroTrustClaims) error
	ValidateUser(ctx context.Context, user *types.UserInfo) error
	ValidateDevice(ctx context.Context, device *types.Device) error
	GetValidationRules() []ValidationRule
}

// TransformerPlugin provides data transformation functionality
type TransformerPlugin interface {
	Plugin
	TransformClaims(ctx context.Context, claims *types.ZeroTrustClaims) (*types.ZeroTrustClaims, error)
	TransformUserInfo(ctx context.Context, user *types.UserInfo) (*types.UserInfo, error)
	GetTransformationRules() []TransformationRule
}

// ProviderPlugin provides external service integration
type ProviderPlugin interface {
	Plugin
	GetProviderType() string
	GetProviderName() string
	IsHealthy(ctx context.Context) bool
	GetMetrics(ctx context.Context) map[string]interface{}
}

// AuthProviderPlugin provides authentication services
type AuthProviderPlugin interface {
	ProviderPlugin
	Authenticate(ctx context.Context, credentials map[string]interface{}) (*AuthResult, error)
	ValidateToken(ctx context.Context, token string) (*types.ZeroTrustClaims, error)
	RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error)
}

// RiskProviderPlugin provides risk assessment services
type RiskProviderPlugin interface {
	ProviderPlugin
	AssessRisk(ctx context.Context, context *RiskContext) (*RiskResult, error)
	GetRiskFactors(ctx context.Context) []RiskFactor
}

// NotificationProviderPlugin provides notification services
type NotificationProviderPlugin interface {
	ProviderPlugin
	SendNotification(ctx context.Context, notification *Notification) error
	GetSupportedChannels() []string
}

// PluginConfig configures the plugin system
type PluginConfig struct {
	PluginDir       string                 `yaml:"plugin_dir"`
	EnableHotReload bool                   `yaml:"enable_hot_reload"`
	MaxPlugins      int                    `yaml:"max_plugins"`
	Timeout         time.Duration          `yaml:"timeout"`
	EnabledPlugins  []string               `yaml:"enabled_plugins"`
	DisabledPlugins []string               `yaml:"disabled_plugins"`
	PluginConfigs   map[string]interface{} `yaml:"plugin_configs"`
}

// PluginRequest represents a request to a plugin
type PluginRequest struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Method   string                 `json:"method"`
	Path     string                 `json:"path"`
	Headers  map[string]string      `json:"headers"`
	Body     []byte                 `json:"body"`
	Context  map[string]interface{} `json:"context"`
	UserInfo *types.UserInfo        `json:"user_info,omitempty"`
	Claims   *types.ZeroTrustClaims `json:"claims,omitempty"`
}

// PluginResponse represents a response from a plugin
type PluginResponse struct {
	StatusCode int                    `json:"status_code"`
	Headers    map[string]string      `json:"headers"`
	Body       []byte                 `json:"body"`
	Context    map[string]interface{} `json:"context"`
	Modified   bool                   `json:"modified"`
	Continue   bool                   `json:"continue"`
}

// PluginRoute represents a route handled by a plugin
type PluginRoute struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Handler     string `json:"handler"`
	Description string `json:"description"`
}

// ValidationRule represents a validation rule from a plugin
type ValidationRule struct {
	Field       string      `json:"field"`
	Type        string      `json:"type"`
	Required    bool        `json:"required"`
	MinValue    interface{} `json:"min_value,omitempty"`
	MaxValue    interface{} `json:"max_value,omitempty"`
	Pattern     string      `json:"pattern,omitempty"`
	CustomRule  string      `json:"custom_rule,omitempty"`
}

// TransformationRule represents a transformation rule from a plugin
type TransformationRule struct {
	SourceField string `json:"source_field"`
	TargetField string `json:"target_field"`
	Transform   string `json:"transform"`
	Condition   string `json:"condition,omitempty"`
}

// AuthResult represents authentication result
type AuthResult struct {
	Success      bool                   `json:"success"`
	UserID       string                 `json:"user_id"`
	Claims       *types.ZeroTrustClaims `json:"claims"`
	Tokens       *TokenPair             `json:"tokens"`
	Error        string                 `json:"error,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// RiskContext provides context for risk assessment
type RiskContext struct {
	UserID      string                 `json:"user_id"`
	DeviceID    string                 `json:"device_id"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	Location    *types.LocationInfo    `json:"location,omitempty"`
	Session     map[string]interface{} `json:"session"`
	Historical  map[string]interface{} `json:"historical"`
}

// RiskResult represents risk assessment result
type RiskResult struct {
	RiskScore   int                    `json:"risk_score"`
	RiskLevel   string                 `json:"risk_level"`
	Factors     []RiskFactor           `json:"factors"`
	Confidence  float64                `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// RiskFactor represents a risk factor
type RiskFactor struct {
	Type        string  `json:"type"`
	Score       int     `json:"score"`
	Weight      float64 `json:"weight"`
	Description string  `json:"description"`
	Source      string  `json:"source"`
}

// Notification represents a notification to be sent
type Notification struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Channel     string                 `json:"channel"`
	Recipient   string                 `json:"recipient"`
	Subject     string                 `json:"subject"`
	Message     string                 `json:"message"`
	Priority    string                 `json:"priority"`
	Metadata    map[string]interface{} `json:"metadata"`
	ScheduledAt *time.Time             `json:"scheduled_at,omitempty"`
}

// EventBus handles plugin events
type EventBus struct {
	subscribers map[HookType][]EventSubscriber
	mu          sync.RWMutex
}

// EventSubscriber represents an event subscriber
type EventSubscriber interface {
	HandleEvent(ctx context.Context, event *PluginEvent) error
	GetEventTypes() []HookType
}

// PluginEvent represents an event in the system
type PluginEvent struct {
	Type      HookType               `json:"type"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	Context   context.Context        `json:"-"`
}

// NewPluginManager creates a new plugin manager
func NewPluginManager(config *PluginConfig) *PluginManager {
	return &PluginManager{
		plugins:      make(map[string]Plugin),
		hooks:        make(map[HookType][]Plugin),
		middleware:   make([]MiddlewarePlugin, 0),
		validators:   make([]ValidatorPlugin, 0),
		transformers: make([]TransformerPlugin, 0),
		providers:    make([]ProviderPlugin, 0),
		config:       config,
		eventBus:     NewEventBus(),
	}
}

// LoadPlugins loads all plugins from the plugin directory
func (pm *PluginManager) LoadPlugins(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if pm.config.PluginDir == "" {
		log.Println("No plugin directory specified, skipping plugin loading")
		return nil
	}
	
	// Load built-in plugins first
	if err := pm.loadBuiltinPlugins(ctx); err != nil {
		return fmt.Errorf("failed to load built-in plugins: %w", err)
	}
	
	// Load external plugins from directory
	if err := pm.loadExternalPlugins(ctx); err != nil {
		return fmt.Errorf("failed to load external plugins: %w", err)
	}
	
	log.Printf("Loaded %d plugins successfully", len(pm.plugins))
	return nil
}

// RegisterPlugin registers a plugin manually
func (pm *PluginManager) RegisterPlugin(ctx context.Context, plugin Plugin) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	name := plugin.GetName()
	
	// Check if plugin is disabled
	for _, disabled := range pm.config.DisabledPlugins {
		if disabled == name {
			log.Printf("Plugin %s is disabled, skipping", name)
			return nil
		}
	}
	
	// Initialize plugin
	pluginConfig, exists := pm.config.PluginConfigs[name]
	if !exists {
		pluginConfig = make(map[string]interface{})
	}
	
	if err := plugin.Initialize(ctx, pluginConfig.(map[string]interface{})); err != nil {
		return fmt.Errorf("failed to initialize plugin %s: %w", name, err)
	}
	
	// Register plugin
	pm.plugins[name] = plugin
	
	// Register plugin by type
	pm.registerPluginByType(plugin)
	
	log.Printf("Registered plugin: %s v%s", plugin.GetName(), plugin.GetVersion())
	return nil
}

// ExecuteHook executes all plugins registered for a specific hook
func (pm *PluginManager) ExecuteHook(ctx context.Context, hookType HookType, data map[string]interface{}) error {
	pm.mu.RLock()
	plugins := pm.hooks[hookType]
	pm.mu.RUnlock()
	
	if len(plugins) == 0 {
		return nil
	}
	
	// Create plugin event
	event := &PluginEvent{
		Type:      hookType,
		Source:    "plugin_manager",
		Timestamp: time.Now(),
		Data:      data,
		Context:   ctx,
	}
	
	// Execute plugins in parallel
	errChan := make(chan error, len(plugins))
	
	for _, plugin := range plugins {
		go func(p Plugin) {
			defer func() {
				if r := recover(); r != nil {
					errChan <- fmt.Errorf("plugin %s panicked: %v", p.GetName(), r)
				}
			}()
			
			// Create timeout context
			timeoutCtx, cancel := context.WithTimeout(ctx, pm.config.Timeout)
			defer cancel()
			
			// Execute plugin hook
			if hookPlugin, ok := p.(HookPlugin); ok {
				err := hookPlugin.ExecuteHook(timeoutCtx, hookType, data)
				errChan <- err
			} else {
				errChan <- nil
			}
		}(plugin)
	}
	
	// Collect results
	var errors []string
	for i := 0; i < len(plugins); i++ {
		if err := <-errChan; err != nil {
			errors = append(errors, err.Error())
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("plugin execution failed: %v", errors)
	}
	
	// Publish event to event bus
	return pm.eventBus.PublishEvent(ctx, event)
}

// ProcessMiddleware processes request through all middleware plugins
func (pm *PluginManager) ProcessMiddleware(ctx context.Context, request *PluginRequest) (*PluginResponse, error) {
	pm.mu.RLock()
	middleware := make([]MiddlewarePlugin, len(pm.middleware))
	copy(middleware, pm.middleware)
	pm.mu.RUnlock()
	
	// Sort middleware by priority (higher priority first)
	sort.Slice(middleware, func(i, j int) bool {
		return middleware[i].GetPriority() > middleware[j].GetPriority()
	})
	
	response := &PluginResponse{
		StatusCode: 200,
		Headers:    make(map[string]string),
		Context:    make(map[string]interface{}),
		Continue:   true,
	}
	
	// Process through middleware chain
	for _, mw := range middleware {
		if !response.Continue {
			break
		}
		
		// Create timeout context
		timeoutCtx, cancel := context.WithTimeout(ctx, pm.config.Timeout)
		
		resp, err := mw.ProcessRequest(timeoutCtx, request)
		cancel()
		
		if err != nil {
			return nil, fmt.Errorf("middleware %s failed: %w", mw.GetName(), err)
		}
		
		if resp != nil {
			response = resp
		}
	}
	
	return response, nil
}

// GetPlugin returns a plugin by name
func (pm *PluginManager) GetPlugin(name string) (Plugin, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	plugin, exists := pm.plugins[name]
	return plugin, exists
}

// ListPlugins returns all loaded plugins
func (pm *PluginManager) ListPlugins() []PluginMetadata {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	var plugins []PluginMetadata
	for _, plugin := range pm.plugins {
		plugins = append(plugins, plugin.GetMetadata())
	}
	
	return plugins
}

// GetProviders returns all provider plugins of a specific type
func (pm *PluginManager) GetProviders(providerType string) []ProviderPlugin {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	var providers []ProviderPlugin
	for _, provider := range pm.providers {
		if provider.GetProviderType() == providerType {
			providers = append(providers, provider)
		}
	}
	
	return providers
}

// Shutdown gracefully shuts down all plugins
func (pm *PluginManager) Shutdown(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	var errors []string
	
	for name, plugin := range pm.plugins {
		if err := plugin.Cleanup(ctx); err != nil {
			errors = append(errors, fmt.Sprintf("plugin %s cleanup failed: %v", name, err))
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("plugin shutdown errors: %v", errors)
	}
	
	return nil
}

// Private helper methods

func (pm *PluginManager) loadBuiltinPlugins(ctx context.Context) error {
	// Register built-in plugins here
	
	// Example: Logging plugin
	loggingPlugin := &LoggingPlugin{}
	if err := pm.RegisterPlugin(ctx, loggingPlugin); err != nil {
		return fmt.Errorf("failed to register logging plugin: %w", err)
	}
	
	// Example: Metrics plugin
	metricsPlugin := &MetricsPlugin{}
	if err := pm.RegisterPlugin(ctx, metricsPlugin); err != nil {
		return fmt.Errorf("failed to register metrics plugin: %w", err)
	}
	
	return nil
}

func (pm *PluginManager) loadExternalPlugins(ctx context.Context) error {
	// Load external plugins from .so files
	// This would scan the plugin directory for compiled plugin files
	
	// For now, return nil as external plugin loading requires
	// specific implementation based on plugin format
	return nil
}

func (pm *PluginManager) registerPluginByType(p Plugin) {
	// Register plugin by interface type
	if middleware, ok := p.(MiddlewarePlugin); ok {
		pm.middleware = append(pm.middleware, middleware)
	}
	
	if validator, ok := p.(ValidatorPlugin); ok {
		pm.validators = append(pm.validators, validator)
	}
	
	if transformer, ok := p.(TransformerPlugin); ok {
		pm.transformers = append(pm.transformers, transformer)
	}
	
	if provider, ok := p.(ProviderPlugin); ok {
		pm.providers = append(pm.providers, provider)
	}
	
	// Register for hooks if plugin implements HookPlugin
	if hookPlugin, ok := p.(HookPlugin); ok {
		for _, hookType := range hookPlugin.GetHookTypes() {
			pm.hooks[hookType] = append(pm.hooks[hookType], p)
		}
	}
}

// HookPlugin represents a plugin that can handle hooks
type HookPlugin interface {
	ExecuteHook(ctx context.Context, hookType HookType, data map[string]interface{}) error
	GetHookTypes() []HookType
}

// NewEventBus creates a new event bus
func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[HookType][]EventSubscriber),
	}
}

// Subscribe subscribes to events
func (eb *EventBus) Subscribe(subscriber EventSubscriber) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	
	for _, eventType := range subscriber.GetEventTypes() {
		eb.subscribers[eventType] = append(eb.subscribers[eventType], subscriber)
	}
}

// PublishEvent publishes an event to all subscribers
func (eb *EventBus) PublishEvent(ctx context.Context, event *PluginEvent) error {
	eb.mu.RLock()
	subscribers := eb.subscribers[event.Type]
	eb.mu.RUnlock()
	
	var errors []string
	
	for _, subscriber := range subscribers {
		if err := subscriber.HandleEvent(ctx, event); err != nil {
			errors = append(errors, err.Error())
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("event handling errors: %v", errors)
	}
	
	return nil
}

// LoadPlugin loads a plugin from a shared library file
func LoadPlugin(pluginPath string) (Plugin, error) {
	// Load the plugin .so file
	p, err := plugin.Open(pluginPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open plugin %s: %w", pluginPath, err)
	}
	
	// Look for the New function
	newFunc, err := p.Lookup("New")
	if err != nil {
		return nil, fmt.Errorf("plugin %s does not export 'New' function: %w", pluginPath, err)
	}
	
	// Call the New function
	newPluginFunc, ok := newFunc.(func() Plugin)
	if !ok {
		return nil, fmt.Errorf("plugin %s 'New' function has wrong signature", pluginPath)
	}
	
	return newPluginFunc(), nil
}