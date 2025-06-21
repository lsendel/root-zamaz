package discovery

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// MemoryRegistry implements ServiceRegistry interface using in-memory storage
// This is useful for testing and development environments
type MemoryRegistry struct {
	services map[string]*Service
	watchers map[string][]chan ServiceEvent
	mutex    sync.RWMutex
	logger   *logrus.Logger
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewMemoryRegistry creates a new in-memory service registry
func NewMemoryRegistry(logger *logrus.Logger) *MemoryRegistry {
	ctx, cancel := context.WithCancel(context.Background())

	registry := &MemoryRegistry{
		services: make(map[string]*Service),
		watchers: make(map[string][]chan ServiceEvent),
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
	}

	// Start background health checking
	go registry.healthChecker()

	logger.Info("Created in-memory service registry")
	return registry
}

// Register registers a service in memory
func (m *MemoryRegistry) Register(ctx context.Context, service *Service) error {
	if err := service.Validate(); err != nil {
		return fmt.Errorf("invalid service: %w", err)
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Store service
	serviceCopy := *service
	m.services[service.ID] = &serviceCopy

	m.logger.WithFields(logrus.Fields{
		"service_id":   service.ID,
		"service_name": service.Name,
		"endpoint":     service.GetEndpoint(),
		"tags":         service.Tags,
	}).Info("Service registered in memory")

	// Notify watchers
	event := ServiceEvent{
		Type:    EventServiceRegistered,
		Service: &serviceCopy,
	}
	m.notifyWatchers(service.Name, event)
	m.notifyWatchers("*", event) // Notify global watchers

	return nil
}

// Deregister removes a service from memory
func (m *MemoryRegistry) Deregister(ctx context.Context, serviceID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	service, exists := m.services[serviceID]
	if !exists {
		return fmt.Errorf("service %s not found", serviceID)
	}

	delete(m.services, serviceID)

	m.logger.WithFields(logrus.Fields{
		"service_id":   serviceID,
		"service_name": service.Name,
	}).Info("Service deregistered from memory")

	// Notify watchers
	event := ServiceEvent{
		Type:    EventServiceDeregistered,
		Service: service,
	}
	m.notifyWatchers(service.Name, event)
	m.notifyWatchers("*", event) // Notify global watchers

	return nil
}

// Discover finds services by name
func (m *MemoryRegistry) Discover(ctx context.Context, serviceName string) ([]*Service, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var services []*Service

	if serviceName == "" {
		// Return all services
		for _, service := range m.services {
			serviceCopy := *service
			services = append(services, &serviceCopy)
		}
	} else {
		// Return services with matching name
		for _, service := range m.services {
			if service.Name == serviceName {
				serviceCopy := *service
				services = append(services, &serviceCopy)
			}
		}
	}

	m.logger.WithFields(logrus.Fields{
		"service_name": serviceName,
		"count":        len(services),
	}).Debug("Discovered services from memory")

	return services, nil
}

// Watch monitors service changes
func (m *MemoryRegistry) Watch(ctx context.Context, serviceName string) (<-chan ServiceEvent, error) {
	eventChan := make(chan ServiceEvent, 100)

	m.mutex.Lock()
	if serviceName == "" {
		serviceName = "*" // Watch all services
	}
	m.watchers[serviceName] = append(m.watchers[serviceName], eventChan)
	m.mutex.Unlock()

	m.logger.WithField("service_name", serviceName).Info("Started watching service in memory")

	// Send current services as registration events
	go func() {
		services, _ := m.Discover(ctx, serviceName)
		for _, service := range services {
			if serviceName == "*" || service.Name == serviceName {
				select {
				case eventChan <- ServiceEvent{
					Type:    EventServiceRegistered,
					Service: service,
				}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Clean up watcher when context is done
	go func() {
		<-ctx.Done()
		m.removeWatcher(serviceName, eventChan)
		close(eventChan)
	}()

	return eventChan, nil
}

// Health always returns healthy for memory registry
func (m *MemoryRegistry) Health() error {
	return nil
}

// Close shuts down the registry
func (m *MemoryRegistry) Close() error {
	m.cancel()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Close all watchers
	for serviceName, watchers := range m.watchers {
		for _, ch := range watchers {
			close(ch)
		}
		delete(m.watchers, serviceName)
	}

	m.logger.Info("Memory registry closed")
	return nil
}

// GetServicesByTag finds services with specific tags
func (m *MemoryRegistry) GetServicesByTag(tag string) []*Service {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var services []*Service
	for _, service := range m.services {
		if service.HasTag(tag) {
			serviceCopy := *service
			services = append(services, &serviceCopy)
		}
	}
	return services
}

// GetServicesByMeta finds services with specific metadata
func (m *MemoryRegistry) GetServicesByMeta(key, value string) []*Service {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var services []*Service
	for _, service := range m.services {
		if metaValue, exists := service.GetMeta(key); exists && metaValue == value {
			serviceCopy := *service
			services = append(services, &serviceCopy)
		}
	}
	return services
}

// UpdateServiceHealth updates the health status of a service
func (m *MemoryRegistry) UpdateServiceHealth(serviceID string, health HealthStatus) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	service, exists := m.services[serviceID]
	if !exists {
		return fmt.Errorf("service %s not found", serviceID)
	}

	oldHealth := service.Health
	service.Health = health

	m.logger.WithFields(logrus.Fields{
		"service_id": serviceID,
		"old_health": oldHealth,
		"new_health": health,
	}).Debug("Updated service health")

	// Notify watchers of health change
	event := ServiceEvent{
		Type:    EventServiceHealthChange,
		Service: service,
		Metadata: map[string]string{
			"old_health": string(oldHealth),
			"new_health": string(health),
		},
	}
	m.notifyWatchers(service.Name, event)
	m.notifyWatchers("*", event)

	return nil
}

// GetServiceStats returns statistics about the registry
func (m *MemoryRegistry) GetServiceStats() map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	healthCounts := make(map[HealthStatus]int)
	tagCounts := make(map[string]int)
	namespaceCounts := make(map[string]int)

	for _, service := range m.services {
		healthCounts[service.Health]++

		if service.Namespace != "" {
			namespaceCounts[service.Namespace]++
		}

		for _, tag := range service.Tags {
			tagCounts[tag]++
		}
	}

	return map[string]interface{}{
		"total_services":   len(m.services),
		"health_counts":    healthCounts,
		"tag_counts":       tagCounts,
		"namespace_counts": namespaceCounts,
		"active_watchers":  len(m.watchers),
	}
}

// notifyWatchers sends events to watchers for a specific service or all services
func (m *MemoryRegistry) notifyWatchers(serviceName string, event ServiceEvent) {
	watchers, exists := m.watchers[serviceName]
	if !exists {
		return
	}

	for _, ch := range watchers {
		select {
		case ch <- event:
		default:
			// Channel is full, skip
			m.logger.WithField("service_name", serviceName).Warn("Watcher channel full, dropping event")
		}
	}
}

// removeWatcher removes a specific watcher channel
func (m *MemoryRegistry) removeWatcher(serviceName string, eventChan chan ServiceEvent) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	watchers := m.watchers[serviceName]
	for i, ch := range watchers {
		if ch == eventChan {
			// Remove from slice
			m.watchers[serviceName] = append(watchers[:i], watchers[i+1:]...)
			break
		}
	}

	// Remove empty watcher lists
	if len(m.watchers[serviceName]) == 0 {
		delete(m.watchers, serviceName)
	}
}

// healthChecker runs periodic health checks on registered services
func (m *MemoryRegistry) healthChecker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.performHealthChecks()
		}
	}
}

// performHealthChecks checks the health of all registered services
func (m *MemoryRegistry) performHealthChecks() {
	m.mutex.RLock()
	services := make([]*Service, 0, len(m.services))
	for _, service := range m.services {
		serviceCopy := *service
		services = append(services, &serviceCopy)
	}
	m.mutex.RUnlock()

	for _, service := range services {
		// For memory registry, we'll just mark services as healthy
		// In a real implementation, you would perform actual health checks
		if service.Health == HealthUnknown {
			m.UpdateServiceHealth(service.ID, HealthPassing)
		}
	}
}
