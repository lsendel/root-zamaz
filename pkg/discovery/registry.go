package discovery

import (
	"context"
	"fmt"
	"time"
)

// ServiceRegistry defines the interface for service discovery implementations
type ServiceRegistry interface {
	// Register a service with the registry
	Register(ctx context.Context, service *Service) error
	
	// Deregister a service from the registry
	Deregister(ctx context.Context, serviceID string) error
	
	// Discover services by name
	Discover(ctx context.Context, serviceName string) ([]*Service, error)
	
	// Watch for service changes
	Watch(ctx context.Context, serviceName string) (<-chan ServiceEvent, error)
	
	// Health check the registry connection
	Health() error
	
	// Close the registry connection
	Close() error
}

// Service represents a discoverable service
type Service struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Address     string            `json:"address"`
	Port        int               `json:"port"`
	Tags        []string          `json:"tags,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
	Health      HealthStatus      `json:"health"`
	Environment string            `json:"environment,omitempty"`
	Version     string            `json:"version,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	TTL         time.Duration     `json:"ttl,omitempty"`
}

// HealthStatus represents the health state of a service
type HealthStatus string

const (
	HealthPassing  HealthStatus = "passing"
	HealthWarning  HealthStatus = "warning"
	HealthCritical HealthStatus = "critical"
	HealthUnknown  HealthStatus = "unknown"
)

// ServiceEvent represents a change in service state
type ServiceEvent struct {
	Type     EventType `json:"type"`
	Service  *Service  `json:"service"`
	Error    error     `json:"error,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// EventType represents the type of service event
type EventType string

const (
	EventServiceRegistered   EventType = "service_registered"
	EventServiceDeregistered EventType = "service_deregistered"
	EventServiceHealthChange EventType = "service_health_change"
	EventServiceUpdated      EventType = "service_updated"
	EventError               EventType = "error"
)

// RegistryConfig holds configuration for service registry implementations
type RegistryConfig struct {
	Provider    string        `env:"SERVICE_REGISTRY_PROVIDER" default:"kubernetes"`
	Consul      ConsulConfig  `json:"consul,omitempty"`
	Kubernetes  K8sConfig     `json:"kubernetes,omitempty"`
	HealthCheck HealthConfig  `json:"health_check"`
	TTL         time.Duration `env:"SERVICE_TTL" default:"30s"`
	RefreshRate time.Duration `env:"SERVICE_REFRESH_RATE" default:"10s"`
}

// ConsulConfig holds Consul-specific configuration
type ConsulConfig struct {
	Address    string        `env:"CONSUL_ADDRESS" default:"localhost:8500"`
	Datacenter string        `env:"CONSUL_DATACENTER" default:"dc1"`
	Token      string        `env:"CONSUL_TOKEN"`
	Scheme     string        `env:"CONSUL_SCHEME" default:"http"`
	Timeout    time.Duration `env:"CONSUL_TIMEOUT" default:"10s"`
	Namespace  string        `env:"CONSUL_NAMESPACE"`
	TLSConfig  TLSConfig     `json:"tls,omitempty"`
}

// K8sConfig holds Kubernetes-specific configuration
type K8sConfig struct {
	InCluster     bool     `env:"K8S_IN_CLUSTER" default:"true"`
	KubeConfig    string   `env:"KUBECONFIG"`
	Namespace     string   `env:"K8S_NAMESPACE" default:"zamaz"`
	LabelSelector string   `env:"K8S_LABEL_SELECTOR" default:"app.kubernetes.io/part-of=zamaz-platform"`
	Annotations   []string `env:"K8S_ANNOTATIONS"`
}

// HealthConfig holds health check configuration
type HealthConfig struct {
	Enabled       bool          `env:"HEALTH_CHECK_ENABLED" default:"true"`
	HTTPPath      string        `env:"HEALTH_HTTP_PATH" default:"/health"`
	Interval      time.Duration `env:"HEALTH_INTERVAL" default:"10s"`
	Timeout       time.Duration `env:"HEALTH_TIMEOUT" default:"5s"`
	MaxFails      int           `env:"HEALTH_MAX_FAILS" default:"3"`
	DeregAfter    time.Duration `env:"HEALTH_DEREG_AFTER" default:"60s"`
	RetryInterval time.Duration `env:"HEALTH_RETRY_INTERVAL" default:"30s"`
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled            bool   `env:"TLS_ENABLED" default:"false"`
	CertFile           string `env:"TLS_CERT_FILE"`
	KeyFile            string `env:"TLS_KEY_FILE"`
	CAFile             string `env:"TLS_CA_FILE"`
	InsecureSkipVerify bool   `env:"TLS_INSECURE_SKIP_VERIFY" default:"false"`
}

// ServiceOptions provides options for service registration
type ServiceOptions struct {
	Tags        []string
	Meta        map[string]string
	HealthCheck *HealthCheckDefinition
	TTL         time.Duration
	Namespace   string
}

// HealthCheckDefinition defines a health check for a service
type HealthCheckDefinition struct {
	HTTP                           string        `json:"http,omitempty"`
	TCP                            string        `json:"tcp,omitempty"`
	Script                         string        `json:"script,omitempty"`
	Interval                       time.Duration `json:"interval"`
	Timeout                        time.Duration `json:"timeout"`
	DeregisterCriticalServiceAfter time.Duration `json:"deregister_critical_service_after,omitempty"`
	TLSSkipVerify                  bool          `json:"tls_skip_verify,omitempty"`
}

// RegistryFactory creates service registry instances
type RegistryFactory interface {
	Create(config RegistryConfig) (ServiceRegistry, error)
	SupportedProviders() []string
}

// NewService creates a new service instance with default values
func NewService(id, name, address string, port int) *Service {
	return &Service{
		ID:      id,
		Name:    name,
		Address: address,
		Port:    port,
		Health:  HealthUnknown,
		Tags:    make([]string, 0),
		Meta:    make(map[string]string),
	}
}

// AddTag adds a tag to the service
func (s *Service) AddTag(tag string) *Service {
	s.Tags = append(s.Tags, tag)
	return s
}

// AddMeta adds metadata to the service
func (s *Service) AddMeta(key, value string) *Service {
	if s.Meta == nil {
		s.Meta = make(map[string]string)
	}
	s.Meta[key] = value
	return s
}

// SetHealth sets the health status of the service
func (s *Service) SetHealth(status HealthStatus) *Service {
	s.Health = status
	return s
}

// GetEndpoint returns the full endpoint URL for the service
func (s *Service) GetEndpoint() string {
	return fmt.Sprintf("%s:%d", s.Address, s.Port)
}

// HasTag checks if the service has a specific tag
func (s *Service) HasTag(tag string) bool {
	for _, t := range s.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// GetMeta retrieves metadata value by key
func (s *Service) GetMeta(key string) (string, bool) {
	if s.Meta == nil {
		return "", false
	}
	value, exists := s.Meta[key]
	return value, exists
}

// IsHealthy returns true if the service is in a healthy state
func (s *Service) IsHealthy() bool {
	return s.Health == HealthPassing
}

// IsReady returns true if the service is ready to serve traffic
func (s *Service) IsReady() bool {
	return s.Health == HealthPassing || s.Health == HealthWarning
}

// Validate performs basic validation on the service definition
func (s *Service) Validate() error {
	if s.ID == "" {
		return fmt.Errorf("service ID cannot be empty")
	}
	if s.Name == "" {
		return fmt.Errorf("service name cannot be empty")
	}
	if s.Address == "" {
		return fmt.Errorf("service address cannot be empty")
	}
	if s.Port <= 0 || s.Port > 65535 {
		return fmt.Errorf("service port must be between 1 and 65535")
	}
	return nil
}