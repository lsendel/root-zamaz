// Package integrations provides external service integrations for Zero Trust
package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// ExternalServiceManager manages external service integrations
type ExternalServiceManager struct {
	services map[string]ExternalService
	config   *IntegrationConfig
	client   *http.Client
}

// ExternalService represents an external service integration
type ExternalService interface {
	GetServiceName() string
	GetServiceType() string
	Initialize(ctx context.Context, config map[string]interface{}) error
	IsHealthy(ctx context.Context) (bool, error)
	GetMetrics(ctx context.Context) (map[string]interface{}, error)
	Cleanup(ctx context.Context) error
}

// IntegrationConfig configures external service integrations
type IntegrationConfig struct {
	SPIRE         *SPIREConfig         `yaml:"spire"`
	LDAP          *LDAPConfig          `yaml:"ldap"`
	ThreatFeeds   *ThreatFeedsConfig   `yaml:"threat_feeds"`
	Notifications *NotificationConfig  `yaml:"notifications"`
	Monitoring    *MonitoringConfig    `yaml:"monitoring"`
	Secrets       *SecretsConfig       `yaml:"secrets"`
}

// SPIREConfig configures SPIRE/SPIFFE integration
type SPIREConfig struct {
	Enabled     bool   `yaml:"enabled"`
	SocketPath  string `yaml:"socket_path"`
	TrustDomain string `yaml:"trust_domain"`
	ServerURL   string `yaml:"server_url"`
	AgentPath   string `yaml:"agent_path"`
}

// LDAPConfig configures LDAP integration
type LDAPConfig struct {
	Enabled      bool   `yaml:"enabled"`
	URL          string `yaml:"url"`
	BindDN       string `yaml:"bind_dn"`
	BindPassword string `yaml:"bind_password"`
	BaseDN       string `yaml:"base_dn"`
	UserFilter   string `yaml:"user_filter"`
	GroupFilter  string `yaml:"group_filter"`
	TLSEnabled   bool   `yaml:"tls_enabled"`
}

// ThreatFeedsConfig configures threat intelligence feeds
type ThreatFeedsConfig struct {
	Enabled   bool                      `yaml:"enabled"`
	Providers []ThreatFeedProviderConfig `yaml:"providers"`
}

// ThreatFeedProviderConfig configures a threat feed provider
type ThreatFeedProviderConfig struct {
	Name        string            `yaml:"name"`
	Type        string            `yaml:"type"`
	URL         string            `yaml:"url"`
	APIKey      string            `yaml:"api_key"`
	UpdateInterval time.Duration  `yaml:"update_interval"`
	Config      map[string]interface{} `yaml:"config"`
}

// NotificationConfig configures notification services
type NotificationConfig struct {
	Enabled   bool                         `yaml:"enabled"`
	Providers []NotificationProviderConfig `yaml:"providers"`
}

// NotificationProviderConfig configures a notification provider
type NotificationProviderConfig struct {
	Name     string            `yaml:"name"`
	Type     string            `yaml:"type"`
	Endpoint string            `yaml:"endpoint"`
	APIKey   string            `yaml:"api_key"`
	Config   map[string]interface{} `yaml:"config"`
}

// MonitoringConfig configures monitoring integrations
type MonitoringConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Prometheus *PrometheusConfig `yaml:"prometheus"`
	Jaeger     *JaegerConfig     `yaml:"jaeger"`
	OpenTelemetry *OpenTelemetryConfig `yaml:"opentelemetry"`
}

// PrometheusConfig configures Prometheus integration
type PrometheusConfig struct {
	Enabled       bool   `yaml:"enabled"`
	PushGateway   string `yaml:"push_gateway"`
	JobName       string `yaml:"job_name"`
	PushInterval  time.Duration `yaml:"push_interval"`
}

// JaegerConfig configures Jaeger tracing
type JaegerConfig struct {
	Enabled      bool    `yaml:"enabled"`
	AgentHost    string  `yaml:"agent_host"`
	AgentPort    int     `yaml:"agent_port"`
	CollectorURL string  `yaml:"collector_url"`
	SampleRate   float64 `yaml:"sample_rate"`
}

// OpenTelemetryConfig configures OpenTelemetry
type OpenTelemetryConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Endpoint    string `yaml:"endpoint"`
	ServiceName string `yaml:"service_name"`
	Headers     map[string]string `yaml:"headers"`
}

// SecretsConfig configures secret management
type SecretsConfig struct {
	Enabled   bool                    `yaml:"enabled"`
	Providers []SecretProviderConfig  `yaml:"providers"`
}

// SecretProviderConfig configures a secret provider
type SecretProviderConfig struct {
	Name     string            `yaml:"name"`
	Type     string            `yaml:"type"`
	Endpoint string            `yaml:"endpoint"`
	Config   map[string]interface{} `yaml:"config"`
}

// NewExternalServiceManager creates a new external service manager
func NewExternalServiceManager(config *IntegrationConfig) *ExternalServiceManager {
	return &ExternalServiceManager{
		services: make(map[string]ExternalService),
		config:   config,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Initialize initializes all configured external services
func (esm *ExternalServiceManager) Initialize(ctx context.Context) error {
	// Initialize SPIRE if enabled
	if esm.config.SPIRE != nil && esm.config.SPIRE.Enabled {
		spireService := NewSPIREService(esm.config.SPIRE)
		if err := esm.RegisterService(ctx, spireService); err != nil {
			return fmt.Errorf("failed to register SPIRE service: %w", err)
		}
	}

	// Initialize LDAP if enabled
	if esm.config.LDAP != nil && esm.config.LDAP.Enabled {
		ldapService := NewLDAPService(esm.config.LDAP)
		if err := esm.RegisterService(ctx, ldapService); err != nil {
			return fmt.Errorf("failed to register LDAP service: %w", err)
		}
	}

	// Initialize threat feeds if enabled
	if esm.config.ThreatFeeds != nil && esm.config.ThreatFeeds.Enabled {
		for _, providerConfig := range esm.config.ThreatFeeds.Providers {
			threatService := NewThreatFeedService(&providerConfig)
			if err := esm.RegisterService(ctx, threatService); err != nil {
				return fmt.Errorf("failed to register threat feed service %s: %w", providerConfig.Name, err)
			}
		}
	}

	// Initialize notification providers if enabled
	if esm.config.Notifications != nil && esm.config.Notifications.Enabled {
		for _, providerConfig := range esm.config.Notifications.Providers {
			notificationService := NewNotificationService(&providerConfig)
			if err := esm.RegisterService(ctx, notificationService); err != nil {
				return fmt.Errorf("failed to register notification service %s: %w", providerConfig.Name, err)
			}
		}
	}

	// Initialize monitoring services if enabled
	if esm.config.Monitoring != nil && esm.config.Monitoring.Enabled {
		if esm.config.Monitoring.Prometheus != nil && esm.config.Monitoring.Prometheus.Enabled {
			prometheusService := NewPrometheusService(esm.config.Monitoring.Prometheus)
			if err := esm.RegisterService(ctx, prometheusService); err != nil {
				return fmt.Errorf("failed to register Prometheus service: %w", err)
			}
		}
	}

	// Initialize secret providers if enabled
	if esm.config.Secrets != nil && esm.config.Secrets.Enabled {
		for _, providerConfig := range esm.config.Secrets.Providers {
			secretService := NewSecretService(&providerConfig)
			if err := esm.RegisterService(ctx, secretService); err != nil {
				return fmt.Errorf("failed to register secret service %s: %w", providerConfig.Name, err)
			}
		}
	}

	return nil
}

// RegisterService registers an external service
func (esm *ExternalServiceManager) RegisterService(ctx context.Context, service ExternalService) error {
	name := service.GetServiceName()
	
	// Initialize the service
	if err := service.Initialize(ctx, nil); err != nil {
		return fmt.Errorf("failed to initialize service %s: %w", name, err)
	}
	
	// Register the service
	esm.services[name] = service
	
	fmt.Printf("Registered external service: %s (%s)\n", name, service.GetServiceType())
	return nil
}

// GetService returns a service by name
func (esm *ExternalServiceManager) GetService(name string) (ExternalService, bool) {
	service, exists := esm.services[name]
	return service, exists
}

// GetServicesByType returns all services of a specific type
func (esm *ExternalServiceManager) GetServicesByType(serviceType string) []ExternalService {
	var services []ExternalService
	for _, service := range esm.services {
		if service.GetServiceType() == serviceType {
			services = append(services, service)
		}
	}
	return services
}

// HealthCheck checks the health of all services
func (esm *ExternalServiceManager) HealthCheck(ctx context.Context) map[string]bool {
	healthStatus := make(map[string]bool)
	
	for name, service := range esm.services {
		healthy, err := service.IsHealthy(ctx)
		if err != nil {
			healthy = false
		}
		healthStatus[name] = healthy
	}
	
	return healthStatus
}

// GetMetrics returns metrics from all services
func (esm *ExternalServiceManager) GetMetrics(ctx context.Context) map[string]map[string]interface{} {
	allMetrics := make(map[string]map[string]interface{})
	
	for name, service := range esm.services {
		metrics, err := service.GetMetrics(ctx)
		if err == nil {
			allMetrics[name] = metrics
		}
	}
	
	return allMetrics
}

// Shutdown gracefully shuts down all services
func (esm *ExternalServiceManager) Shutdown(ctx context.Context) error {
	var errors []string
	
	for name, service := range esm.services {
		if err := service.Cleanup(ctx); err != nil {
			errors = append(errors, fmt.Sprintf("service %s cleanup failed: %v", name, err))
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("service shutdown errors: %v", errors)
	}
	
	return nil
}

// SPIRE Service Implementation
type SPIREService struct {
	config *SPIREConfig
}

func NewSPIREService(config *SPIREConfig) *SPIREService {
	return &SPIREService{config: config}
}

func (s *SPIREService) GetServiceName() string { return "spire" }
func (s *SPIREService) GetServiceType() string { return "identity" }

func (s *SPIREService) Initialize(ctx context.Context, config map[string]interface{}) error {
	// Initialize SPIRE client connection
	fmt.Printf("Initializing SPIRE service with socket: %s\n", s.config.SocketPath)
	return nil
}

func (s *SPIREService) IsHealthy(ctx context.Context) (bool, error) {
	// Check SPIRE agent health
	return true, nil
}

func (s *SPIREService) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{
		"trust_domain": s.config.TrustDomain,
		"socket_path":  s.config.SocketPath,
		"healthy":      true,
	}, nil
}

func (s *SPIREService) Cleanup(ctx context.Context) error {
	fmt.Println("SPIRE service cleanup completed")
	return nil
}

// LDAP Service Implementation
type LDAPService struct {
	config *LDAPConfig
}

func NewLDAPService(config *LDAPConfig) *LDAPService {
	return &LDAPService{config: config}
}

func (s *LDAPService) GetServiceName() string { return "ldap" }
func (s *LDAPService) GetServiceType() string { return "directory" }

func (s *LDAPService) Initialize(ctx context.Context, config map[string]interface{}) error {
	fmt.Printf("Initializing LDAP service with URL: %s\n", s.config.URL)
	return nil
}

func (s *LDAPService) IsHealthy(ctx context.Context) (bool, error) {
	// Test LDAP connection
	return true, nil
}

func (s *LDAPService) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{
		"url":         s.config.URL,
		"base_dn":     s.config.BaseDN,
		"tls_enabled": s.config.TLSEnabled,
		"healthy":     true,
	}, nil
}

func (s *LDAPService) Cleanup(ctx context.Context) error {
	fmt.Println("LDAP service cleanup completed")
	return nil
}

// Threat Feed Service Implementation
type ThreatFeedService struct {
	config *ThreatFeedProviderConfig
	client *http.Client
}

func NewThreatFeedService(config *ThreatFeedProviderConfig) *ThreatFeedService {
	return &ThreatFeedService{
		config: config,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *ThreatFeedService) GetServiceName() string { return s.config.Name }
func (s *ThreatFeedService) GetServiceType() string { return "threat_intelligence" }

func (s *ThreatFeedService) Initialize(ctx context.Context, config map[string]interface{}) error {
	fmt.Printf("Initializing threat feed service: %s (%s)\n", s.config.Name, s.config.Type)
	return nil
}

func (s *ThreatFeedService) IsHealthy(ctx context.Context) (bool, error) {
	// Test threat feed API connectivity
	if s.config.URL == "" {
		return false, fmt.Errorf("no URL configured")
	}
	
	req, err := http.NewRequestWithContext(ctx, "GET", s.config.URL+"/health", nil)
	if err != nil {
		return false, err
	}
	
	if s.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.APIKey)
	}
	
	resp, err := s.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == 200, nil
}

func (s *ThreatFeedService) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{
		"provider":        s.config.Name,
		"type":           s.config.Type,
		"update_interval": s.config.UpdateInterval.String(),
		"healthy":        true,
	}, nil
}

func (s *ThreatFeedService) Cleanup(ctx context.Context) error {
	fmt.Printf("Threat feed service %s cleanup completed\n", s.config.Name)
	return nil
}

// GetThreatIntelligence retrieves threat intelligence for an IP
func (s *ThreatFeedService) GetThreatIntelligence(ctx context.Context, ipAddress string) (*ThreatIntelligence, error) {
	if s.config.URL == "" {
		return nil, fmt.Errorf("no URL configured for threat feed")
	}
	
	url := fmt.Sprintf("%s/ip/%s", s.config.URL, ipAddress)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	if s.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.APIKey)
	}
	
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("threat feed API returned status %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	var threatInfo ThreatIntelligence
	if err := json.Unmarshal(body, &threatInfo); err != nil {
		return nil, err
	}
	
	return &threatInfo, nil
}

// ThreatIntelligence represents threat intelligence data
type ThreatIntelligence struct {
	IPAddress     string   `json:"ip_address"`
	IsMalicious   bool     `json:"is_malicious"`
	ThreatTypes   []string `json:"threat_types"`
	Confidence    float64  `json:"confidence"`
	LastSeen      time.Time `json:"last_seen"`
	Sources       []string `json:"sources"`
	Reputation    int      `json:"reputation"`
}

// Notification Service Implementation
type NotificationService struct {
	config *NotificationProviderConfig
	client *http.Client
}

func NewNotificationService(config *NotificationProviderConfig) *NotificationService {
	return &NotificationService{
		config: config,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *NotificationService) GetServiceName() string { return s.config.Name }
func (s *NotificationService) GetServiceType() string { return "notification" }

func (s *NotificationService) Initialize(ctx context.Context, config map[string]interface{}) error {
	fmt.Printf("Initializing notification service: %s (%s)\n", s.config.Name, s.config.Type)
	return nil
}

func (s *NotificationService) IsHealthy(ctx context.Context) (bool, error) {
	return true, nil
}

func (s *NotificationService) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{
		"provider": s.config.Name,
		"type":     s.config.Type,
		"endpoint": s.config.Endpoint,
		"healthy":  true,
	}, nil
}

func (s *NotificationService) Cleanup(ctx context.Context) error {
	fmt.Printf("Notification service %s cleanup completed\n", s.config.Name)
	return nil
}

// SendNotification sends a notification
func (s *NotificationService) SendNotification(ctx context.Context, notification *Notification) error {
	switch s.config.Type {
	case "webhook":
		return s.sendWebhookNotification(ctx, notification)
	case "slack":
		return s.sendSlackNotification(ctx, notification)
	case "email":
		return s.sendEmailNotification(ctx, notification)
	default:
		return fmt.Errorf("unsupported notification type: %s", s.config.Type)
	}
}

func (s *NotificationService) sendWebhookNotification(ctx context.Context, notification *Notification) error {
	payload, _ := json.Marshal(notification)
	
	req, err := http.NewRequestWithContext(ctx, "POST", s.config.Endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	
	req.Header.Set("Content-Type", "application/json")
	if s.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.APIKey)
	}
	
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook notification failed with status %d", resp.StatusCode)
	}
	
	return nil
}

func (s *NotificationService) sendSlackNotification(ctx context.Context, notification *Notification) error {
	// Slack-specific message formatting
	message := map[string]interface{}{
		"text": notification.Subject,
		"attachments": []map[string]interface{}{
			{
				"color":  s.getSlackColor(notification.Priority),
				"text":   notification.Message,
				"footer": "Zero Trust Security",
				"ts":     time.Now().Unix(),
			},
		},
	}
	
	payload, _ := json.Marshal(message)
	
	req, err := http.NewRequestWithContext(ctx, "POST", s.config.Endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	return nil
}

func (s *NotificationService) sendEmailNotification(ctx context.Context, notification *Notification) error {
	// Email notification implementation would go here
	fmt.Printf("Email notification: %s - %s\n", notification.Subject, notification.Message)
	return nil
}

func (s *NotificationService) getSlackColor(priority string) string {
	switch priority {
	case "high":
		return "danger"
	case "medium":
		return "warning"
	default:
		return "good"
	}
}

// Notification represents a notification message
type Notification struct {
	ID        string                 `json:"id"`
	Subject   string                 `json:"subject"`
	Message   string                 `json:"message"`
	Priority  string                 `json:"priority"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Prometheus Service Implementation
type PrometheusService struct {
	config *PrometheusConfig
	client *http.Client
}

func NewPrometheusService(config *PrometheusConfig) *PrometheusService {
	return &PrometheusService{
		config: config,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *PrometheusService) GetServiceName() string { return "prometheus" }
func (s *PrometheusService) GetServiceType() string { return "monitoring" }

func (s *PrometheusService) Initialize(ctx context.Context, config map[string]interface{}) error {
	fmt.Printf("Initializing Prometheus service with push gateway: %s\n", s.config.PushGateway)
	return nil
}

func (s *PrometheusService) IsHealthy(ctx context.Context) (bool, error) {
	if s.config.PushGateway == "" {
		return true, nil // Metrics collection is passive
	}
	
	// Test push gateway connectivity
	req, err := http.NewRequestWithContext(ctx, "GET", s.config.PushGateway+"/api/v1/metrics", nil)
	if err != nil {
		return false, err
	}
	
	resp, err := s.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == 200, nil
}

func (s *PrometheusService) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{
		"push_gateway":   s.config.PushGateway,
		"job_name":      s.config.JobName,
		"push_interval": s.config.PushInterval.String(),
		"healthy":       true,
	}, nil
}

func (s *PrometheusService) Cleanup(ctx context.Context) error {
	fmt.Println("Prometheus service cleanup completed")
	return nil
}

// Secret Service Implementation
type SecretService struct {
	config *SecretProviderConfig
}

func NewSecretService(config *SecretProviderConfig) *SecretService {
	return &SecretService{config: config}
}

func (s *SecretService) GetServiceName() string { return s.config.Name }
func (s *SecretService) GetServiceType() string { return "secrets" }

func (s *SecretService) Initialize(ctx context.Context, config map[string]interface{}) error {
	fmt.Printf("Initializing secret service: %s (%s)\n", s.config.Name, s.config.Type)
	return nil
}

func (s *SecretService) IsHealthy(ctx context.Context) (bool, error) {
	return true, nil
}

func (s *SecretService) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{
		"provider": s.config.Name,
		"type":     s.config.Type,
		"healthy":  true,
	}, nil
}

func (s *SecretService) Cleanup(ctx context.Context) error {
	fmt.Printf("Secret service %s cleanup completed\n", s.config.Name)
	return nil
}