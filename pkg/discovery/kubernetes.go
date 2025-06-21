package discovery

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// KubernetesRegistry implements ServiceRegistry interface using Kubernetes API
type KubernetesRegistry struct {
	clientset     kubernetes.Interface
	config        K8sConfig
	services      map[string]*Service
	watchers      map[string]chan ServiceEvent
	mutex         sync.RWMutex
	logger        *logrus.Logger
	ctx           context.Context
	cancel        context.CancelFunc
	labelSelector labels.Selector
}

// NewKubernetesRegistry creates a new Kubernetes-based service registry
func NewKubernetesRegistry(config K8sConfig, logger *logrus.Logger) (*KubernetesRegistry, error) {
	var kubeConfig *rest.Config
	var err error

	if config.InCluster {
		kubeConfig, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
		}
	} else {
		kubeConfig, err = clientcmd.BuildConfigFromFlags("", config.KubeConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build kubeconfig: %w", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	// Parse label selector
	var labelSelector labels.Selector
	if config.LabelSelector != "" {
		labelSelector, err = labels.Parse(config.LabelSelector)
		if err != nil {
			return nil, fmt.Errorf("invalid label selector: %w", err)
		}
	} else {
		labelSelector = labels.Everything()
	}

	ctx, cancel := context.WithCancel(context.Background())

	registry := &KubernetesRegistry{
		clientset:     clientset,
		config:        config,
		services:      make(map[string]*Service),
		watchers:      make(map[string]chan ServiceEvent),
		logger:        logger,
		ctx:           ctx,
		cancel:        cancel,
		labelSelector: labelSelector,
	}

	// Test connection
	if err := registry.Health(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to Kubernetes: %w", err)
	}

	registry.logger.WithFields(logrus.Fields{
		"namespace":      config.Namespace,
		"label_selector": config.LabelSelector,
		"in_cluster":     config.InCluster,
	}).Info("Connected to Kubernetes registry")

	// Start watching all services in background
	go registry.watchAllServices()

	return registry, nil
}

// Register registers a service with Kubernetes (creates/updates service)
func (k *KubernetesRegistry) Register(ctx context.Context, service *Service) error {
	if err := service.Validate(); err != nil {
		return fmt.Errorf("invalid service: %w", err)
	}

	// Convert to Kubernetes Service
	k8sService := k.convertToK8sService(service)

	// Check if service already exists
	existing, err := k.clientset.CoreV1().Services(k.config.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		// Create new service
		_, err = k.clientset.CoreV1().Services(k.config.Namespace).Create(ctx, k8sService, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create service %s: %w", service.Name, err)
		}
		k.logger.WithField("service", service.Name).Info("Created Kubernetes service")
	} else {
		// Update existing service
		k8sService.ResourceVersion = existing.ResourceVersion
		_, err = k.clientset.CoreV1().Services(k.config.Namespace).Update(ctx, k8sService, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update service %s: %w", service.Name, err)
		}
		k.logger.WithField("service", service.Name).Info("Updated Kubernetes service")
	}

	// Store locally
	k.mutex.Lock()
	k.services[service.ID] = service
	k.mutex.Unlock()

	// Notify watchers
	k.notifyWatchers(ServiceEvent{
		Type:    EventServiceRegistered,
		Service: service,
	})

	return nil
}

// Deregister removes a service from Kubernetes
func (k *KubernetesRegistry) Deregister(ctx context.Context, serviceID string) error {
	// Find service name from ID
	k.mutex.RLock()
	service, exists := k.services[serviceID]
	k.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("service %s not found in registry", serviceID)
	}

	// Delete Kubernetes service
	err := k.clientset.CoreV1().Services(k.config.Namespace).Delete(ctx, service.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete service %s: %w", service.Name, err)
	}

	// Remove from local cache
	k.mutex.Lock()
	delete(k.services, serviceID)
	k.mutex.Unlock()

	k.logger.WithField("service", service.Name).Info("Deleted Kubernetes service")

	// Notify watchers
	k.notifyWatchers(ServiceEvent{
		Type:    EventServiceDeregistered,
		Service: service,
	})

	return nil
}

// Discover finds services by name
func (k *KubernetesRegistry) Discover(ctx context.Context, serviceName string) ([]*Service, error) {
	var services []*Service

	if serviceName != "" {
		// Get specific service
		k8sService, err := k.clientset.CoreV1().Services(k.config.Namespace).Get(ctx, serviceName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get service %s: %w", serviceName, err)
		}

		if k.matchesSelector(k8sService) {
			service := k.convertFromK8sService(k8sService)
			services = append(services, service)
		}
	} else {
		// List all services
		serviceList, err := k.clientset.CoreV1().Services(k.config.Namespace).List(ctx, metav1.ListOptions{
			LabelSelector: k.labelSelector.String(),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list services: %w", err)
		}

		for _, k8sService := range serviceList.Items {
			service := k.convertFromK8sService(&k8sService)
			services = append(services, service)
		}
	}

	// Get endpoints for health status
	for _, service := range services {
		k.updateServiceHealth(ctx, service)
	}

	k.logger.WithFields(logrus.Fields{
		"service_name": serviceName,
		"count":        len(services),
	}).Debug("Discovered Kubernetes services")

	return services, nil
}

// Watch monitors service changes
func (k *KubernetesRegistry) Watch(ctx context.Context, serviceName string) (<-chan ServiceEvent, error) {
	k.mutex.Lock()
	eventChan := make(chan ServiceEvent, 100)
	watchKey := serviceName
	if serviceName == "" {
		watchKey = "*" // Watch all services
	}
	k.watchers[watchKey] = eventChan
	k.mutex.Unlock()

	k.logger.WithField("service_name", serviceName).Info("Started watching Kubernetes service")

	// Return the channel - actual watching is done by watchAllServices
	return eventChan, nil
}

// Health checks the connection to Kubernetes
func (k *KubernetesRegistry) Health() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try to list services as a health check
	_, err := k.clientset.CoreV1().Services(k.config.Namespace).List(ctx, metav1.ListOptions{
		Limit: 1,
	})
	if err != nil {
		return fmt.Errorf("kubernetes health check failed: %w", err)
	}

	return nil
}

// Close shuts down the registry
func (k *KubernetesRegistry) Close() error {
	k.cancel()

	// Close all watchers
	k.mutex.Lock()
	for watchKey, ch := range k.watchers {
		close(ch)
		delete(k.watchers, watchKey)
	}
	k.mutex.Unlock()

	k.logger.Info("Kubernetes registry closed")
	return nil
}

// convertToK8sService converts our Service to Kubernetes Service
func (k *KubernetesRegistry) convertToK8sService(service *Service) *v1.Service {
	k8sService := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        service.Name,
			Namespace:   k.config.Namespace,
			Labels:      make(map[string]string),
			Annotations: make(map[string]string),
		},
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeClusterIP,
			Ports: []v1.ServicePort{
				{
					Name:     "http",
					Port:     int32(service.Port),
					Protocol: v1.ProtocolTCP,
				},
			},
			Selector: map[string]string{
				"app": service.Name,
			},
		},
	}

	// Add tags as labels
	for _, tag := range service.Tags {
		parts := strings.SplitN(tag, "=", 2)
		if len(parts) == 2 {
			k8sService.Labels[parts[0]] = parts[1]
		} else {
			k8sService.Labels[tag] = "true"
		}
	}

	// Add metadata as annotations
	for key, value := range service.Meta {
		k8sService.Annotations[key] = value
	}

	// Add service discovery annotations
	k8sService.Annotations["service.alpha.kubernetes.io/endpoints-tolerate-unready"] = "true"
	k8sService.Annotations["service.zamaz.io/id"] = service.ID
	k8sService.Annotations["service.zamaz.io/version"] = service.Version
	k8sService.Annotations["service.zamaz.io/environment"] = service.Environment

	return k8sService
}

// convertFromK8sService converts Kubernetes Service to our Service
func (k *KubernetesRegistry) convertFromK8sService(k8sService *v1.Service) *Service {
	service := &Service{
		Name:      k8sService.Name,
		Namespace: k8sService.Namespace,
		Tags:      make([]string, 0),
		Meta:      make(map[string]string),
		Health:    HealthUnknown,
	}

	// Get service ID from annotation
	if id, exists := k8sService.Annotations["service.zamaz.io/id"]; exists {
		service.ID = id
	} else {
		service.ID = k8sService.Name
	}

	// Get version and environment from annotations
	if version, exists := k8sService.Annotations["service.zamaz.io/version"]; exists {
		service.Version = version
	}
	if env, exists := k8sService.Annotations["service.zamaz.io/environment"]; exists {
		service.Environment = env
	}

	// Get address and port
	service.Address = k8sService.Spec.ClusterIP
	if len(k8sService.Spec.Ports) > 0 {
		service.Port = int(k8sService.Spec.Ports[0].Port)
	}

	// Convert labels to tags
	for key, value := range k8sService.Labels {
		if key == "app" || strings.HasPrefix(key, "kubernetes.io/") {
			continue // Skip system labels
		}
		if value == "true" {
			service.Tags = append(service.Tags, key)
		} else {
			service.Tags = append(service.Tags, fmt.Sprintf("%s=%s", key, value))
		}
	}

	// Convert annotations to metadata
	for key, value := range k8sService.Annotations {
		if strings.HasPrefix(key, "kubernetes.io/") || strings.HasPrefix(key, "service.zamaz.io/") {
			continue // Skip system annotations
		}
		service.Meta[key] = value
	}

	return service
}

// updateServiceHealth updates service health based on endpoints
func (k *KubernetesRegistry) updateServiceHealth(ctx context.Context, service *Service) {
	endpoints, err := k.clientset.CoreV1().Endpoints(k.config.Namespace).Get(ctx, service.Name, metav1.GetOptions{})
	if err != nil {
		service.Health = HealthCritical
		return
	}

	// Check if there are any ready endpoints
	hasReadyEndpoints := false
	hasNotReadyEndpoints := false

	for _, subset := range endpoints.Subsets {
		if len(subset.Addresses) > 0 {
			hasReadyEndpoints = true
		}
		if len(subset.NotReadyAddresses) > 0 {
			hasNotReadyEndpoints = true
		}
	}

	if hasReadyEndpoints && !hasNotReadyEndpoints {
		service.Health = HealthPassing
	} else if hasReadyEndpoints && hasNotReadyEndpoints {
		service.Health = HealthWarning
	} else if hasNotReadyEndpoints {
		service.Health = HealthCritical
	} else {
		service.Health = HealthUnknown
	}
}

// matchesSelector checks if a service matches the configured label selector
func (k *KubernetesRegistry) matchesSelector(service *v1.Service) bool {
	return k.labelSelector.Matches(labels.Set(service.Labels))
}

// watchAllServices watches for changes to all services
func (k *KubernetesRegistry) watchAllServices() {
	for {
		select {
		case <-k.ctx.Done():
			return
		default:
			k.doWatchServices()
		}
	}
}

// doWatchServices performs the actual service watching
func (k *KubernetesRegistry) doWatchServices() {
	defer func() {
		// Retry after delay on error
		time.Sleep(5 * time.Second)
	}()

	watcher, err := k.clientset.CoreV1().Services(k.config.Namespace).Watch(k.ctx, metav1.ListOptions{
		LabelSelector: k.labelSelector.String(),
	})
	if err != nil {
		k.logger.WithError(err).Error("Failed to start service watcher")
		return
	}
	defer watcher.Stop()

	for {
		select {
		case <-k.ctx.Done():
			return
		case event, ok := <-watcher.ResultChan():
			if !ok {
				k.logger.Warn("Service watcher channel closed")
				return
			}

			k8sService, ok := event.Object.(*v1.Service)
			if !ok {
				continue
			}

			service := k.convertFromK8sService(k8sService)

			var eventType EventType
			switch event.Type {
			case watch.Added:
				eventType = EventServiceRegistered
				k.mutex.Lock()
				k.services[service.ID] = service
				k.mutex.Unlock()
			case watch.Modified:
				eventType = EventServiceUpdated
				k.mutex.Lock()
				k.services[service.ID] = service
				k.mutex.Unlock()
			case watch.Deleted:
				eventType = EventServiceDeregistered
				k.mutex.Lock()
				delete(k.services, service.ID)
				k.mutex.Unlock()
			default:
				continue
			}

			// Update health status
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			k.updateServiceHealth(ctx, service)
			cancel()

			// Notify watchers
			k.notifyWatchers(ServiceEvent{
				Type:    eventType,
				Service: service,
			})
		}
	}
}

// notifyWatchers sends events to all watchers
func (k *KubernetesRegistry) notifyWatchers(event ServiceEvent) {
	k.mutex.RLock()
	defer k.mutex.RUnlock()

	for watchKey, ch := range k.watchers {
		// Send to specific service watchers or all-service watchers
		if watchKey == "*" || watchKey == event.Service.Name {
			select {
			case ch <- event:
			default:
				// Channel is full, skip
			}
		}
	}
}

// GetServicesByLabel finds services with specific labels
func (k *KubernetesRegistry) GetServicesByLabel(ctx context.Context, labelSelector string) ([]*Service, error) {
	selector, err := labels.Parse(labelSelector)
	if err != nil {
		return nil, fmt.Errorf("invalid label selector: %w", err)
	}

	serviceList, err := k.clientset.CoreV1().Services(k.config.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list services by label: %w", err)
	}

	var services []*Service
	for _, k8sService := range serviceList.Items {
		service := k.convertFromK8sService(&k8sService)
		k.updateServiceHealth(ctx, service)
		services = append(services, service)
	}

	return services, nil
}

// GetServicesByNamespace finds services in a specific namespace
func (k *KubernetesRegistry) GetServicesByNamespace(ctx context.Context, namespace string) ([]*Service, error) {
	serviceList, err := k.clientset.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: k.labelSelector.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list services in namespace %s: %w", namespace, err)
	}

	var services []*Service
	for _, k8sService := range serviceList.Items {
		service := k.convertFromK8sService(&k8sService)
		k.updateServiceHealth(ctx, service)
		services = append(services, service)
	}

	return services, nil
}
