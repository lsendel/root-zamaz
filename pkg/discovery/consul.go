package discovery

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/sirupsen/logrus"
)

// ConsulRegistry implements ServiceRegistry interface using Consul
type ConsulRegistry struct {
	client   *api.Client
	config   ConsulConfig
	services map[string]*Service
	watchers map[string]chan ServiceEvent
	mutex    sync.RWMutex
	logger   *logrus.Logger
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewConsulRegistry creates a new Consul-based service registry
func NewConsulRegistry(config ConsulConfig, logger *logrus.Logger) (*ConsulRegistry, error) {
	consulConfig := api.DefaultConfig()
	consulConfig.Address = config.Address
	consulConfig.Datacenter = config.Datacenter
	consulConfig.Token = config.Token
	consulConfig.Scheme = config.Scheme
	
	if config.Namespace != "" {
		consulConfig.Namespace = config.Namespace
	}

	// Configure TLS if enabled
	if config.TLSConfig.Enabled {
		consulConfig.TLSConfig = api.TLSConfig{
			CertFile:           config.TLSConfig.CertFile,
			KeyFile:            config.TLSConfig.KeyFile,
			CAFile:             config.TLSConfig.CAFile,
			InsecureSkipVerify: config.TLSConfig.InsecureSkipVerify,
		}
	}

	client, err := api.NewClient(consulConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	registry := &ConsulRegistry{
		client:   client,
		config:   config,
		services: make(map[string]*Service),
		watchers: make(map[string]chan ServiceEvent),
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
	}

	// Test connection
	if err := registry.Health(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to Consul: %w", err)
	}

	registry.logger.WithFields(logrus.Fields{
		"address":    config.Address,
		"datacenter": config.Datacenter,
		"namespace":  config.Namespace,
	}).Info("Connected to Consul registry")

	return registry, nil
}

// Register registers a service with Consul
func (c *ConsulRegistry) Register(ctx context.Context, service *Service) error {
	if err := service.Validate(); err != nil {
		return fmt.Errorf("invalid service: %w", err)
	}

	// Build Consul service registration
	registration := &api.AgentServiceRegistration{
		ID:      service.ID,
		Name:    service.Name,
		Address: service.Address,
		Port:    service.Port,
		Tags:    service.Tags,
		Meta:    service.Meta,
	}

	// Add health check if configured
	if healthCheck := c.buildHealthCheck(service); healthCheck != nil {
		registration.Check = healthCheck
	}

	// Register with Consul
	if err := c.client.Agent().ServiceRegister(registration); err != nil {
		return fmt.Errorf("failed to register service %s: %w", service.ID, err)
	}

	// Store locally
	c.mutex.Lock()
	c.services[service.ID] = service
	c.mutex.Unlock()

	c.logger.WithFields(logrus.Fields{
		"service_id":   service.ID,
		"service_name": service.Name,
		"endpoint":     service.GetEndpoint(),
		"tags":         service.Tags,
	}).Info("Service registered with Consul")

	// Notify watchers
	c.notifyWatchers(ServiceEvent{
		Type:    EventServiceRegistered,
		Service: service,
	})

	return nil
}

// Deregister removes a service from Consul
func (c *ConsulRegistry) Deregister(ctx context.Context, serviceID string) error {
	if err := c.client.Agent().ServiceDeregister(serviceID); err != nil {
		return fmt.Errorf("failed to deregister service %s: %w", serviceID, err)
	}

	// Remove from local cache
	c.mutex.Lock()
	service := c.services[serviceID]
	delete(c.services, serviceID)
	c.mutex.Unlock()

	if service != nil {
		c.logger.WithFields(logrus.Fields{
			"service_id":   serviceID,
			"service_name": service.Name,
		}).Info("Service deregistered from Consul")

		// Notify watchers
		c.notifyWatchers(ServiceEvent{
			Type:    EventServiceDeregistered,
			Service: service,
		})
	}

	return nil
}

// Discover finds services by name
func (c *ConsulRegistry) Discover(ctx context.Context, serviceName string) ([]*Service, error) {
	services, _, err := c.client.Health().Service(serviceName, "", true, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to discover services for %s: %w", serviceName, err)
	}

	var result []*Service
	for _, service := range services {
		s := c.convertConsulService(service)
		result = append(result, s)
	}

	c.logger.WithFields(logrus.Fields{
		"service_name": serviceName,
		"count":        len(result),
	}).Debug("Discovered services")

	return result, nil
}

// Watch monitors service changes
func (c *ConsulRegistry) Watch(ctx context.Context, serviceName string) (<-chan ServiceEvent, error) {
	c.mutex.Lock()
	eventChan := make(chan ServiceEvent, 100)
	c.watchers[serviceName] = eventChan
	c.mutex.Unlock()

	// Start watching in background
	go c.watchService(ctx, serviceName, eventChan)

	c.logger.WithField("service_name", serviceName).Info("Started watching service")
	
	return eventChan, nil
}

// Health checks the connection to Consul
func (c *ConsulRegistry) Health() error {
	ctx, cancel := context.WithTimeout(context.Background(), c.config.Timeout)
	defer cancel()

	// Try to get leader status as a simple health check
	_, err := c.client.Status().Leader()
	if err != nil {
		return fmt.Errorf("consul health check failed: %w", err)
	}

	return nil
}

// Close shuts down the registry
func (c *ConsulRegistry) Close() error {
	c.cancel()

	// Close all watchers
	c.mutex.Lock()
	for serviceName, ch := range c.watchers {
		close(ch)
		delete(c.watchers, serviceName)
	}
	c.mutex.Unlock()

	c.logger.Info("Consul registry closed")
	return nil
}

// buildHealthCheck creates a Consul health check from service configuration
func (c *ConsulRegistry) buildHealthCheck(service *Service) *api.AgentServiceCheck {
	// Check if service has health check metadata
	healthHTTP, hasHTTP := service.GetMeta("health_check_http")
	healthTCP, hasTCP := service.GetMeta("health_check_tcp")
	
	var check *api.AgentServiceCheck

	if hasHTTP {
		check = &api.AgentServiceCheck{
			HTTP:     healthHTTP,
			Interval: "10s",
			Timeout:  "3s",
		}
	} else if hasTCP {
		check = &api.AgentServiceCheck{
			TCP:      healthTCP,
			Interval: "10s",
			Timeout:  "3s",
		}
	} else {
		// Default HTTP health check
		check = &api.AgentServiceCheck{
			HTTP:     fmt.Sprintf("http://%s:%d/health", service.Address, service.Port),
			Interval: "10s",
			Timeout:  "3s",
		}
	}

	// Configure deregistration after failure
	check.DeregisterCriticalServiceAfter = "60s"

	return check
}

// convertConsulService converts Consul service to our Service type
func (c *ConsulRegistry) convertConsulService(consulService *api.ServiceEntry) *Service {
	service := &Service{
		ID:      consulService.Service.ID,
		Name:    consulService.Service.Service,
		Address: consulService.Service.Address,
		Port:    consulService.Service.Port,
		Tags:    consulService.Service.Tags,
		Meta:    consulService.Service.Meta,
	}

	// Determine health status
	service.Health = c.determineHealthStatus(consulService.Checks)

	// Add node information to metadata
	if service.Meta == nil {
		service.Meta = make(map[string]string)
	}
	service.Meta["node"] = consulService.Node.Node
	service.Meta["datacenter"] = consulService.Node.Datacenter

	return service
}

// determineHealthStatus converts Consul health checks to our health status
func (c *ConsulRegistry) determineHealthStatus(checks api.HealthChecks) HealthStatus {
	if len(checks) == 0 {
		return HealthUnknown
	}

	hasWarning := false
	for _, check := range checks {
		switch check.Status {
		case api.HealthCritical:
			return HealthCritical
		case api.HealthWarning:
			hasWarning = true
		}
	}

	if hasWarning {
		return HealthWarning
	}

	return HealthPassing
}

// watchService monitors a specific service for changes
func (c *ConsulRegistry) watchService(ctx context.Context, serviceName string, eventChan chan ServiceEvent) {
	defer close(eventChan)

	var lastIndex uint64
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.ctx.Done():
			return
		default:
			// Watch for service changes
			services, meta, err := c.client.Health().Service(
				serviceName, 
				"", 
				false, 
				&api.QueryOptions{
					WaitIndex: lastIndex,
					WaitTime:  time.Minute,
				},
			)

			if err != nil {
				eventChan <- ServiceEvent{
					Type:  EventError,
					Error: fmt.Errorf("watch error for service %s: %w", serviceName, err),
				}
				time.Sleep(5 * time.Second)
				continue
			}

			lastIndex = meta.LastIndex

			// Convert and send service updates
			for _, service := range services {
				s := c.convertConsulService(service)
				eventChan <- ServiceEvent{
					Type:    EventServiceUpdated,
					Service: s,
				}
			}
		}
	}
}

// notifyWatchers sends events to all watchers
func (c *ConsulRegistry) notifyWatchers(event ServiceEvent) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	for _, ch := range c.watchers {
		select {
		case ch <- event:
		default:
			// Channel is full, skip
		}
	}
}

// GetServicesByTag finds services with specific tags
func (c *ConsulRegistry) GetServicesByTag(ctx context.Context, tag string) ([]*Service, error) {
	services, _, err := c.client.Catalog().Services(&api.QueryOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	var result []*Service
	for serviceName, tags := range services {
		for _, serviceTag := range tags {
			if serviceTag == tag {
				// Get detailed service information
				serviceInstances, err := c.Discover(ctx, serviceName)
				if err != nil {
					c.logger.WithError(err).WithField("service", serviceName).Warn("Failed to get service details")
					continue
				}
				result = append(result, serviceInstances...)
				break
			}
		}
	}

	return result, nil
}

// GetServicesByNamespace finds services in a specific namespace (using meta)
func (c *ConsulRegistry) GetServicesByNamespace(ctx context.Context, namespace string) ([]*Service, error) {
	services, _, err := c.client.Catalog().Services(&api.QueryOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	var result []*Service
	for serviceName := range services {
		serviceInstances, err := c.Discover(ctx, serviceName)
		if err != nil {
			continue
		}

		for _, service := range serviceInstances {
			if ns, exists := service.GetMeta("namespace"); exists && ns == namespace {
				result = append(result, service)
			}
		}
	}

	return result, nil
}