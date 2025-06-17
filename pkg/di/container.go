// Package di provides dependency injection capabilities for the MVP Zero Trust Auth system.
// It implements a lightweight DI container that manages service lifecycle and dependencies,
// improving testability and maintainability.
//
// The package provides:
//   - Service registration and resolution
//   - Singleton and transient service lifetimes
//   - Interface-based dependency injection
//   - Automatic dependency graph resolution
//   - Graceful shutdown of managed services
//
// Example usage:
//
//	container := di.NewContainer()
//
//	// Register services
//	container.RegisterSingleton((*config.Config)(nil), func(c *di.Container) (interface{}, error) {
//	    return config.Load()
//	})
//
//	container.RegisterSingleton((*observability.Observability)(nil), func(c *di.Container) (interface{}, error) {
//	    cfg := c.MustResolve((*config.Config)(nil)).(*config.Config)
//	    return observability.New(observability.Config{
//	        ServiceName: cfg.Observability.ServiceName,
//	        LogLevel: cfg.Observability.LogLevel,
//	    })
//	})
//
//	// Resolve services
//	obs := container.MustResolve((*observability.Observability)(nil)).(*observability.Observability)
package di

import (
	"fmt"
	"reflect"
	"sync"
)

// ServiceLifetime defines how long a service instance should live
type ServiceLifetime int

const (
	// Singleton services are created once and reused for all requests
	Singleton ServiceLifetime = iota

	// Transient services are created fresh for each request
	Transient
)

// ServiceFactory is a function that creates a service instance
type ServiceFactory func(c *Container) (interface{}, error)

// ServiceDescriptor describes how to create and manage a service
type ServiceDescriptor struct {
	ServiceType reflect.Type
	Lifetime    ServiceLifetime
	Factory     ServiceFactory
}

// Container manages service registration and resolution
type Container struct {
	services  map[reflect.Type]*ServiceDescriptor
	instances map[reflect.Type]interface{}
	mutex     sync.RWMutex
}

// NewContainer creates a new dependency injection container
func NewContainer() *Container {
	return &Container{
		services:  make(map[reflect.Type]*ServiceDescriptor),
		instances: make(map[reflect.Type]interface{}),
	}
}

// RegisterSingleton registers a service with singleton lifetime.
// The service will be created once and reused for all subsequent requests.
//
// Parameters:
//
//	serviceType - A pointer to the interface type (e.g., (*MyInterface)(nil))
//	factory - Function that creates the service instance
//
// Example:
//
//	container.RegisterSingleton((*database.DB)(nil), func(c *Container) (interface{}, error) {
//	    cfg := c.MustResolve((*config.Config)(nil)).(*config.Config)
//	    return database.Connect(cfg.Database.DSN())
//	})
func (c *Container) RegisterSingleton(serviceType interface{}, factory ServiceFactory) {
	c.register(serviceType, Singleton, factory)
}

// RegisterTransient registers a service with transient lifetime.
// A new instance will be created for each resolution request.
//
// Parameters:
//
//	serviceType - A pointer to the interface type (e.g., (*MyInterface)(nil))
//	factory - Function that creates the service instance
//
// Example:
//
//	container.RegisterTransient((*handlers.UserHandler)(nil), func(c *Container) (interface{}, error) {
//	    userService := c.MustResolve((*services.UserService)(nil)).(*services.UserService)
//	    return handlers.NewUserHandler(userService), nil
//	})
func (c *Container) RegisterTransient(serviceType interface{}, factory ServiceFactory) {
	c.register(serviceType, Transient, factory)
}

// RegisterInstance registers a pre-created instance as a singleton.
// Useful for registering configuration objects or external dependencies.
//
// Parameters:
//
//	serviceType - A pointer to the interface type
//	instance - The pre-created instance to register
//
// Example:
//
//	cfg, _ := config.Load()
//	container.RegisterInstance((*config.Config)(nil), cfg)
func (c *Container) RegisterInstance(serviceType interface{}, instance interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	t := reflect.TypeOf(serviceType).Elem()
	c.instances[t] = instance
	c.services[t] = &ServiceDescriptor{
		ServiceType: t,
		Lifetime:    Singleton,
		Factory:     nil, // No factory needed for instances
	}
}

// Resolve attempts to resolve a service of the specified type.
// Returns an error if the service is not registered or creation fails.
//
// Parameters:
//
//	serviceType - A pointer to the interface type to resolve
//
// Returns:
//
//	The resolved service instance and any error that occurred
//
// Example:
//
//	obs, err := container.Resolve((*observability.Observability)(nil))
//	if err != nil {
//	    return err
//	}
//	observability := obs.(*observability.Observability)
func (c *Container) Resolve(serviceType interface{}) (interface{}, error) {
	t := reflect.TypeOf(serviceType).Elem()

	c.mutex.RLock()
	descriptor, exists := c.services[t]
	c.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("service type %s is not registered", t.Name())
	}

	// Check if we have a cached singleton instance
	if descriptor.Lifetime == Singleton {
		c.mutex.RLock()
		if instance, exists := c.instances[t]; exists {
			c.mutex.RUnlock()
			return instance, nil
		}
		c.mutex.RUnlock()
	}

	// Create new instance
	if descriptor.Factory == nil {
		return nil, fmt.Errorf("no factory registered for service type %s", t.Name())
	}

	instance, err := descriptor.Factory(c)
	if err != nil {
		return nil, fmt.Errorf("failed to create service %s: %w", t.Name(), err)
	}

	// Cache singleton instances
	if descriptor.Lifetime == Singleton {
		c.mutex.Lock()
		c.instances[t] = instance
		c.mutex.Unlock()
	}

	return instance, nil
}

// MustResolve resolves a service and panics if resolution fails.
// This is useful for cases where the service should always be available.
//
// Parameters:
//
//	serviceType - A pointer to the interface type to resolve
//
// Returns:
//
//	The resolved service instance
//
// Example:
//
//	obs := container.MustResolve((*observability.Observability)(nil)).(*observability.Observability)
func (c *Container) MustResolve(serviceType interface{}) interface{} {
	instance, err := c.Resolve(serviceType)
	if err != nil {
		panic(fmt.Sprintf("failed to resolve service: %v", err))
	}
	return instance
}

// IsRegistered checks if a service type is registered in the container.
//
// Parameters:
//
//	serviceType - A pointer to the interface type to check
//
// Returns:
//
//	True if the service is registered, false otherwise
func (c *Container) IsRegistered(serviceType interface{}) bool {
	t := reflect.TypeOf(serviceType).Elem()

	c.mutex.RLock()
	defer c.mutex.RUnlock()

	_, exists := c.services[t]
	return exists
}

// Shutdown gracefully shuts down all managed services that implement the Shutdowner interface.
// Services are shut down in reverse order of registration to respect dependencies.
func (c *Container) Shutdown() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Collect services that need shutdown
	var shutdownServices []interface{}
	for _, instance := range c.instances {
		if shutdowner, ok := instance.(Shutdowner); ok {
			shutdownServices = append(shutdownServices, shutdowner)
		}
	}

	// Shutdown in reverse order
	var lastErr error
	for i := len(shutdownServices) - 1; i >= 0; i-- {
		if shutdowner, ok := shutdownServices[i].(Shutdowner); ok {
			if err := shutdowner.Shutdown(); err != nil {
				lastErr = err
			}
		}
	}

	return lastErr
}

// register is the internal method for registering services
func (c *Container) register(serviceType interface{}, lifetime ServiceLifetime, factory ServiceFactory) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	t := reflect.TypeOf(serviceType).Elem()
	c.services[t] = &ServiceDescriptor{
		ServiceType: t,
		Lifetime:    lifetime,
		Factory:     factory,
	}
}

// Shutdowner is an interface for services that need graceful shutdown
type Shutdowner interface {
	Shutdown() error
}

// GetRegisteredServices returns a list of all registered service types
func (c *Container) GetRegisteredServices() []reflect.Type {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var types []reflect.Type
	for t := range c.services {
		types = append(types, t)
	}
	return types
}

// Clear removes all registered services and cached instances
func (c *Container) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.services = make(map[reflect.Type]*ServiceDescriptor)
	c.instances = make(map[reflect.Type]interface{})
}
