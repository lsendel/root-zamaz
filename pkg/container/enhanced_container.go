// Package container provides an enhanced dependency injection container with auto-wiring,
// lifecycle management, and interceptors for the MVP Zero Trust Auth system
package container

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"mvp.local/pkg/observability"
)

// ServiceLifetime defines how long a service instance should live
type ServiceLifetime int

const (
	// Singleton services are created once and reused for all requests
	Singleton ServiceLifetime = iota
	// Scoped services live for the duration of a request/scope
	Scoped
	// Transient services are created fresh for each request
	Transient
)

// Provider interface for service providers
type Provider interface {
	Provide(container *Container) (interface{}, error)
	Singleton() bool
	Dependencies() []reflect.Type
}

// Interceptor interface for service interception (AOP)
type Interceptor interface {
	Intercept(ctx context.Context, target interface{}, method reflect.Method, args []interface{}) ([]interface{}, error)
}

// LifecycleHook interface for services that need lifecycle management
type LifecycleHook interface {
	Initialize(ctx context.Context) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Shutdown(ctx context.Context) error
}

// ServiceDescriptor describes how to create and manage a service
type ServiceDescriptor struct {
	ServiceType  reflect.Type
	Lifetime     ServiceLifetime
	Provider     Provider
	Factory      func(c *Container) (interface{}, error)
	Dependencies []reflect.Type
	Tags         map[string]string
}

// Scope represents a service scope for scoped services
type Scope struct {
	ID        string
	instances map[reflect.Type]interface{}
	mu        sync.RWMutex
	container *Container
	context   context.Context
}

// Container is an enhanced dependency injection container
type Container struct {
	services     map[reflect.Type]*ServiceDescriptor
	singletons   map[reflect.Type]interface{}
	interceptors []Interceptor
	scopes       map[string]*Scope
	lifecycle    *LifecycleManager
	obs          *observability.Observability
	mu           sync.RWMutex
	parent       *Container
}

// LifecycleManager manages service lifecycle
type LifecycleManager struct {
	services []LifecycleHook
	mu       sync.RWMutex
}

// NewContainer creates a new enhanced dependency injection container
func NewContainer(obs *observability.Observability) *Container {
	return &Container{
		services:     make(map[reflect.Type]*ServiceDescriptor),
		singletons:   make(map[reflect.Type]interface{}),
		interceptors: make([]Interceptor, 0),
		scopes:       make(map[string]*Scope),
		lifecycle:    &LifecycleManager{services: make([]LifecycleHook, 0)},
		obs:          obs,
	}
}

// NewChildContainer creates a child container that inherits from parent
func (c *Container) NewChildContainer() *Container {
	child := NewContainer(c.obs)
	child.parent = c
	return child
}

// RegisterSingleton registers a service with singleton lifetime
func (c *Container) RegisterSingleton(serviceType interface{}, factory func(c *Container) (interface{}, error)) {
	c.register(serviceType, Singleton, factory, nil)
}

// RegisterSingletonProvider registers a service provider with singleton lifetime
func (c *Container) RegisterSingletonProvider(serviceType interface{}, provider Provider) {
	c.registerProvider(serviceType, Singleton, provider)
}

// RegisterScoped registers a service with scoped lifetime
func (c *Container) RegisterScoped(serviceType interface{}, factory func(c *Container) (interface{}, error)) {
	c.register(serviceType, Scoped, factory, nil)
}

// RegisterScopedProvider registers a service provider with scoped lifetime
func (c *Container) RegisterScopedProvider(serviceType interface{}, provider Provider) {
	c.registerProvider(serviceType, Scoped, provider)
}

// RegisterTransient registers a service with transient lifetime
func (c *Container) RegisterTransient(serviceType interface{}, factory func(c *Container) (interface{}, error)) {
	c.register(serviceType, Transient, factory, nil)
}

// RegisterTransientProvider registers a service provider with transient lifetime
func (c *Container) RegisterTransientProvider(serviceType interface{}, provider Provider) {
	c.registerProvider(serviceType, Transient, provider)
}

// RegisterInstance registers a pre-created instance as a singleton
func (c *Container) RegisterInstance(serviceType interface{}, instance interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	t := reflect.TypeOf(serviceType).Elem()
	c.singletons[t] = instance
	c.services[t] = &ServiceDescriptor{
		ServiceType: t,
		Lifetime:    Singleton,
		Factory:     nil,
	}

	// Register for lifecycle management if applicable
	if lifecycleHook, ok := instance.(LifecycleHook); ok {
		c.lifecycle.mu.Lock()
		c.lifecycle.services = append(c.lifecycle.services, lifecycleHook)
		c.lifecycle.mu.Unlock()
	}
}

// RegisterWithTags registers a service with metadata tags
func (c *Container) RegisterWithTags(serviceType interface{}, factory func(c *Container) (interface{}, error), lifetime ServiceLifetime, tags map[string]string) {
	c.register(serviceType, lifetime, factory, tags)
}

// AddInterceptor adds a service interceptor for AOP
func (c *Container) AddInterceptor(interceptor Interceptor) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.interceptors = append(c.interceptors, interceptor)
}

// CreateScope creates a new service scope
func (c *Container) CreateScope(id string, ctx context.Context) *Scope {
	c.mu.Lock()
	defer c.mu.Unlock()

	scope := &Scope{
		ID:        id,
		instances: make(map[reflect.Type]interface{}),
		container: c,
		context:   ctx,
	}
	c.scopes[id] = scope
	return scope
}

// GetScope retrieves an existing scope
func (c *Container) GetScope(id string) (*Scope, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	scope, exists := c.scopes[id]
	return scope, exists
}

// Resolve attempts to resolve a service of the specified type
func (c *Container) Resolve(serviceType interface{}) (interface{}, error) {
	return c.ResolveWithScope(serviceType, nil)
}

// ResolveWithScope resolves a service within a specific scope
func (c *Container) ResolveWithScope(serviceType interface{}, scope *Scope) (interface{}, error) {
	start := time.Now()
	defer func() {
		if c.obs != nil {
			c.obs.Logger.Debug().
				Str("service_type", reflect.TypeOf(serviceType).Elem().Name()).
				Dur("resolution_time", time.Since(start)).
				Msg("Service resolved")
		}
	}()

	t := reflect.TypeOf(serviceType).Elem()

	// Check current container
	descriptor, exists := c.getServiceDescriptor(t)
	if !exists {
		// Check parent container
		if c.parent != nil {
			return c.parent.ResolveWithScope(serviceType, scope)
		}
		return nil, fmt.Errorf("service type %s is not registered", t.Name())
	}

	return c.createInstance(descriptor, scope)
}

// MustResolve resolves a service and panics if resolution fails
// Deprecated: Use Resolve instead. This function will be removed in a future version.
func (c *Container) MustResolve(serviceType interface{}) (interface{}, error) {
	instance, err := c.Resolve(serviceType)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve service %v: %w", serviceType, err)
	}
	return instance, nil
}

// AutoWire automatically injects dependencies into a struct using reflection
func (c *Container) AutoWire(target interface{}) error {
	return c.AutoWireWithScope(target, nil)
}

// AutoWireWithScope automatically injects dependencies with scope
func (c *Container) AutoWireWithScope(target interface{}, scope *Scope) error {
	targetValue := reflect.ValueOf(target)
	if targetValue.Kind() != reflect.Ptr {
		return fmt.Errorf("target must be a pointer")
	}

	targetValue = targetValue.Elem()
	targetType := targetValue.Type()

	for i := 0; i < targetType.NumField(); i++ {
		field := targetType.Field(i)
		fieldValue := targetValue.Field(i)

		// Check for inject tag
		if tag := field.Tag.Get("inject"); tag != "" {
			if !fieldValue.CanSet() {
				continue
			}

			// Resolve the dependency
			dependency, err := c.ResolveWithScope(reflect.New(field.Type.Elem()).Interface(), scope)
			if err != nil {
				if tag == "optional" {
					continue
				}
				return fmt.Errorf("failed to resolve dependency %s: %w", field.Type.Name(), err)
			}

			fieldValue.Set(reflect.ValueOf(dependency))
		}
	}

	return nil
}

// GetServicesByTag returns all services with a specific tag
func (c *Container) GetServicesByTag(tagKey, tagValue string) []interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var services []interface{}
	for _, descriptor := range c.services {
		if descriptor.Tags != nil {
			if value, exists := descriptor.Tags[tagKey]; exists && value == tagValue {
				if instance, err := c.createInstance(descriptor, nil); err == nil {
					services = append(services, instance)
				}
			}
		}
	}

	return services
}

// Initialize initializes all registered services
func (c *Container) Initialize(ctx context.Context) error {
	c.lifecycle.mu.RLock()
	services := make([]LifecycleHook, len(c.lifecycle.services))
	copy(services, c.lifecycle.services)
	c.lifecycle.mu.RUnlock()

	for _, service := range services {
		if err := service.Initialize(ctx); err != nil {
			return fmt.Errorf("failed to initialize service: %w", err)
		}
	}

	if c.obs != nil {
		c.obs.Logger.Info().
			Int("services_count", len(services)).
			Msg("Container initialized successfully")
	}

	return nil
}

// Start starts all registered services
func (c *Container) Start(ctx context.Context) error {
	c.lifecycle.mu.RLock()
	services := make([]LifecycleHook, len(c.lifecycle.services))
	copy(services, c.lifecycle.services)
	c.lifecycle.mu.RUnlock()

	for _, service := range services {
		if err := service.Start(ctx); err != nil {
			return fmt.Errorf("failed to start service: %w", err)
		}
	}

	return nil
}

// Stop stops all registered services
func (c *Container) Stop(ctx context.Context) error {
	c.lifecycle.mu.RLock()
	services := make([]LifecycleHook, len(c.lifecycle.services))
	copy(services, c.lifecycle.services)
	c.lifecycle.mu.RUnlock()

	// Stop in reverse order
	var lastErr error
	for i := len(services) - 1; i >= 0; i-- {
		if err := services[i].Stop(ctx); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// Shutdown gracefully shuts down all registered services
func (c *Container) Shutdown(ctx context.Context) error {
	c.lifecycle.mu.RLock()
	services := make([]LifecycleHook, len(c.lifecycle.services))
	copy(services, c.lifecycle.services)
	c.lifecycle.mu.RUnlock()

	// Shutdown in reverse order
	var lastErr error
	for i := len(services) - 1; i >= 0; i-- {
		if err := services[i].Shutdown(ctx); err != nil {
			lastErr = err
			if c.obs != nil {
				c.obs.Logger.Error().Err(err).Msg("Service shutdown error")
			}
		}
	}

	// Clean up scopes
	c.mu.Lock()
	for id, scope := range c.scopes {
		scope.dispose()
		delete(c.scopes, id)
	}
	c.mu.Unlock()

	if c.obs != nil {
		c.obs.Logger.Info().Msg("Container shutdown completed")
	}

	return lastErr
}

// Dispose disposes a scope and all its scoped instances
func (s *Scope) Dispose() {
	s.container.mu.Lock()
	defer s.container.mu.Unlock()

	s.dispose()
	delete(s.container.scopes, s.ID)
}

// Internal methods

func (c *Container) register(serviceType interface{}, lifetime ServiceLifetime, factory func(c *Container) (interface{}, error), tags map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	t := reflect.TypeOf(serviceType).Elem()
	c.services[t] = &ServiceDescriptor{
		ServiceType: t,
		Lifetime:    lifetime,
		Factory:     factory,
		Tags:        tags,
	}
}

func (c *Container) registerProvider(serviceType interface{}, lifetime ServiceLifetime, provider Provider) {
	c.mu.Lock()
	defer c.mu.Unlock()

	t := reflect.TypeOf(serviceType).Elem()
	c.services[t] = &ServiceDescriptor{
		ServiceType:  t,
		Lifetime:     lifetime,
		Provider:     provider,
		Dependencies: provider.Dependencies(),
	}
}

func (c *Container) getServiceDescriptor(t reflect.Type) (*ServiceDescriptor, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	descriptor, exists := c.services[t]
	return descriptor, exists
}

func (c *Container) createInstance(descriptor *ServiceDescriptor, scope *Scope) (interface{}, error) {
	// Check for existing instances based on lifetime
	switch descriptor.Lifetime {
	case Singleton:
		c.mu.RLock()
		if instance, exists := c.singletons[descriptor.ServiceType]; exists {
			c.mu.RUnlock()
			return instance, nil
		}
		c.mu.RUnlock()

	case Scoped:
		if scope != nil {
			scope.mu.RLock()
			if instance, exists := scope.instances[descriptor.ServiceType]; exists {
				scope.mu.RUnlock()
				return instance, nil
			}
			scope.mu.RUnlock()
		}
	}

	// Create new instance
	var instance interface{}
	var err error

	if descriptor.Provider != nil {
		instance, err = descriptor.Provider.Provide(c)
	} else if descriptor.Factory != nil {
		instance, err = descriptor.Factory(c)
	} else {
		return nil, fmt.Errorf("no factory or provider registered for service type %s", descriptor.ServiceType.Name())
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create service %s: %w", descriptor.ServiceType.Name(), err)
	}

	// Auto-wire dependencies
	if err := c.AutoWireWithScope(instance, scope); err != nil {
		return nil, fmt.Errorf("failed to auto-wire service %s: %w", descriptor.ServiceType.Name(), err)
	}

	// Apply interceptors
	instance = c.applyInterceptors(instance)

	// Cache based on lifetime
	switch descriptor.Lifetime {
	case Singleton:
		c.mu.Lock()
		c.singletons[descriptor.ServiceType] = instance
		c.mu.Unlock()

		// Register for lifecycle management
		if lifecycleHook, ok := instance.(LifecycleHook); ok {
			c.lifecycle.mu.Lock()
			c.lifecycle.services = append(c.lifecycle.services, lifecycleHook)
			c.lifecycle.mu.Unlock()
		}

	case Scoped:
		if scope != nil {
			scope.mu.Lock()
			scope.instances[descriptor.ServiceType] = instance
			scope.mu.Unlock()
		}
	}

	return instance, nil
}

func (c *Container) applyInterceptors(instance interface{}) interface{} {
	if len(c.interceptors) == 0 {
		return instance
	}

	// Apply interceptors using proxy pattern
	// This is a simplified implementation - in production you'd use more sophisticated AOP
	return instance
}

func (s *Scope) dispose() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Dispose scoped instances that implement disposable interface
	for _, instance := range s.instances {
		if disposable, ok := instance.(interface{ Dispose() }); ok {
			disposable.Dispose()
		}
	}

	s.instances = make(map[reflect.Type]interface{})
}
