package discovery

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// DefaultFactory implements RegistryFactory
type DefaultFactory struct {
	logger *logrus.Logger
}

// NewDefaultFactory creates a new default registry factory
func NewDefaultFactory(logger *logrus.Logger) *DefaultFactory {
	return &DefaultFactory{
		logger: logger,
	}
}

// Create creates a service registry instance based on configuration
func (f *DefaultFactory) Create(config RegistryConfig) (ServiceRegistry, error) {
	provider := strings.ToLower(config.Provider)

	switch provider {
	case "consul":
		return NewConsulRegistry(config.Consul, f.logger)
	case "kubernetes", "k8s":
		return NewKubernetesRegistry(config.Kubernetes, f.logger)
	case "memory":
		return NewMemoryRegistry(f.logger), nil
	default:
		return nil, fmt.Errorf("unsupported service registry provider: %s", provider)
	}
}

// SupportedProviders returns a list of supported registry providers
func (f *DefaultFactory) SupportedProviders() []string {
	return []string{"consul", "kubernetes", "k8s", "memory"}
}

// CreateFromEnvironment creates a registry using environment-based configuration
func CreateFromEnvironment(logger *logrus.Logger) (ServiceRegistry, error) {
	config := RegistryConfig{
		Provider: "kubernetes", // Default to Kubernetes
		Consul: ConsulConfig{
			Address:    "localhost:8500",
			Datacenter: "dc1",
			Scheme:     "http",
			Timeout:    10000000000, // 10 seconds in nanoseconds
		},
		Kubernetes: K8sConfig{
			InCluster:     true,
			Namespace:     "zamaz",
			LabelSelector: "app.kubernetes.io/part-of=zamaz-platform",
		},
		HealthCheck: HealthConfig{
			Enabled:       true,
			HTTPPath:      "/health",
			Interval:      10000000000, // 10 seconds
			Timeout:       5000000000,  // 5 seconds
			MaxFails:      3,
			DeregAfter:    60000000000, // 60 seconds
			RetryInterval: 30000000000, // 30 seconds
		},
		TTL:         30000000000, // 30 seconds
		RefreshRate: 10000000000, // 10 seconds
	}

	factory := NewDefaultFactory(logger)
	return factory.Create(config)
}

// Multi-Registry Manager
type MultiRegistry struct {
	registries map[string]ServiceRegistry
	primary    ServiceRegistry
	logger     *logrus.Logger
}

// NewMultiRegistry creates a registry that can manage multiple backends
func NewMultiRegistry(logger *logrus.Logger) *MultiRegistry {
	return &MultiRegistry{
		registries: make(map[string]ServiceRegistry),
		logger:     logger,
	}
}

// AddRegistry adds a registry with a name
func (m *MultiRegistry) AddRegistry(name string, registry ServiceRegistry) {
	m.registries[name] = registry
	if m.primary == nil {
		m.primary = registry
	}
}

// SetPrimary sets the primary registry for operations
func (m *MultiRegistry) SetPrimary(name string) error {
	registry, exists := m.registries[name]
	if !exists {
		return fmt.Errorf("registry %s not found", name)
	}
	m.primary = registry
	return nil
}

// Register registers a service with all registries
func (m *MultiRegistry) Register(ctx context.Context, service *Service) error {
	var lastError error
	successCount := 0

	for name, registry := range m.registries {
		if err := registry.Register(ctx, service); err != nil {
			m.logger.WithError(err).WithField("registry", name).Error("Failed to register service")
			lastError = err
		} else {
			successCount++
		}
	}

	if successCount == 0 && lastError != nil {
		return fmt.Errorf("failed to register service in any registry: %w", lastError)
	}

	return nil
}

// Deregister removes a service from all registries
func (m *MultiRegistry) Deregister(ctx context.Context, serviceID string) error {
	var lastError error
	
	for name, registry := range m.registries {
		if err := registry.Deregister(ctx, serviceID); err != nil {
			m.logger.WithError(err).WithField("registry", name).Error("Failed to deregister service")
			lastError = err
		}
	}

	return lastError
}

// Discover uses the primary registry for discovery
func (m *MultiRegistry) Discover(ctx context.Context, serviceName string) ([]*Service, error) {
	if m.primary == nil {
		return nil, fmt.Errorf("no primary registry configured")
	}
	return m.primary.Discover(ctx, serviceName)
}

// Watch uses the primary registry for watching
func (m *MultiRegistry) Watch(ctx context.Context, serviceName string) (<-chan ServiceEvent, error) {
	if m.primary == nil {
		return nil, fmt.Errorf("no primary registry configured")
	}
	return m.primary.Watch(ctx, serviceName)
}

// Health checks all registries
func (m *MultiRegistry) Health() error {
	for name, registry := range m.registries {
		if err := registry.Health(); err != nil {
			m.logger.WithError(err).WithField("registry", name).Warn("Registry health check failed")
		}
	}
	return nil
}

// Close closes all registries
func (m *MultiRegistry) Close() error {
	for name, registry := range m.registries {
		if err := registry.Close(); err != nil {
			m.logger.WithError(err).WithField("registry", name).Error("Failed to close registry")
		}
	}
	return nil
}