package di

import (
	"errors"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test interfaces and implementations
type TestService interface {
	GetValue() string
}

type TestServiceImpl struct {
	value string
}

func (t *TestServiceImpl) GetValue() string {
	return t.value
}

type DependentService interface {
	GetTestValue() string
}

type DependentServiceImpl struct {
	testService TestService
}

func (d *DependentServiceImpl) GetTestValue() string {
	return d.testService.GetValue()
}

type ShutdownService interface {
	GetStatus() string
	Shutdown() error
}

type ShutdownServiceImpl struct {
	isShutdown bool
}

func (s *ShutdownServiceImpl) GetStatus() string {
	if s.isShutdown {
		return "shutdown"
	}
	return "running"
}

func (s *ShutdownServiceImpl) Shutdown() error {
	s.isShutdown = true
	return nil
}

func TestContainer_RegisterSingleton(t *testing.T) {
	container := NewContainer()

	t.Run("Register_And_Resolve_Singleton", func(t *testing.T) {
		container.RegisterSingleton((*TestService)(nil), func(c *Container) (interface{}, error) {
			return &TestServiceImpl{value: "test"}, nil
		})

		// Resolve first time
		service1, err := container.Resolve((*TestService)(nil))
		require.NoError(t, err)
		require.NotNil(t, service1)

		testService1 := service1.(TestService)
		assert.Equal(t, "test", testService1.GetValue())

		// Resolve second time - should be same instance
		service2, err := container.Resolve((*TestService)(nil))
		require.NoError(t, err)

		// Should be the same instance (singleton)
		assert.Same(t, service1, service2)
	})

	t.Run("MustResolve_Success", func(t *testing.T) {
		newContainer := NewContainer()
		newContainer.RegisterSingleton((*TestService)(nil), func(c *Container) (interface{}, error) {
			return &TestServiceImpl{value: "must_resolve"}, nil
		})

		service, err := newContainer.MustResolve((*TestService)(nil))
		require.NoError(t, err)
		require.NotNil(t, service)

		testService := service.(TestService)
		assert.Equal(t, "must_resolve", testService.GetValue())
	})

	t.Run("MustResolve_Panic_On_Error", func(t *testing.T) {
		container := NewContainer()

		assert.Panics(t, func() {
			container.MustResolve((*TestService)(nil))
		})
	})
}

func TestContainer_RegisterTransient(t *testing.T) {
	container := NewContainer()

	t.Run("Register_And_Resolve_Transient", func(t *testing.T) {
		callCount := 0
		container.RegisterTransient((*TestService)(nil), func(c *Container) (interface{}, error) {
			callCount++
			return &TestServiceImpl{value: "transient"}, nil
		})

		// Resolve first time
		service1, err := container.Resolve((*TestService)(nil))
		require.NoError(t, err)
		assert.Equal(t, 1, callCount)

		// Resolve second time - should create new instance
		service2, err := container.Resolve((*TestService)(nil))
		require.NoError(t, err)
		assert.Equal(t, 2, callCount)

		// Should be different instances (transient)
		assert.NotSame(t, service1, service2)
	})
}

func TestContainer_RegisterInstance(t *testing.T) {
	container := NewContainer()

	t.Run("Register_And_Resolve_Instance", func(t *testing.T) {
		instance := &TestServiceImpl{value: "instance"}
		container.RegisterInstance((*TestService)(nil), instance)

		resolved, err := container.Resolve((*TestService)(nil))
		require.NoError(t, err)

		// Should be the exact same instance
		assert.Same(t, instance, resolved)
	})
}

func TestContainer_DependencyResolution(t *testing.T) {
	container := NewContainer()

	t.Run("Resolve_With_Dependencies", func(t *testing.T) {
		// Register dependency
		container.RegisterSingleton((*TestService)(nil), func(c *Container) (interface{}, error) {
			return &TestServiceImpl{value: "dependency"}, nil
		})

		// Register service that depends on TestService
		container.RegisterSingleton((*DependentService)(nil), func(c *Container) (interface{}, error) {
			testServiceIface, err := c.MustResolve((*TestService)(nil))
			if err != nil {
				return nil, err
			}
			testService := testServiceIface.(TestService)
			return &DependentServiceImpl{testService: testService}, nil
		})

		// Resolve dependent service
		service, err := container.Resolve((*DependentService)(nil))
		require.NoError(t, err)

		dependentService := service.(DependentService)
		assert.Equal(t, "dependency", dependentService.GetTestValue())
	})

	t.Run("Circular_Dependency_Detection", func(t *testing.T) {
		container := NewContainer()

		// This would create a circular dependency in a real scenario
		// For this test, we'll simulate an error during resolution
		container.RegisterSingleton((*TestService)(nil), func(c *Container) (interface{}, error) {
			// Try to resolve the dependent service (would be circular)
			return nil, errors.New("circular dependency detected")
		})

		_, err := container.Resolve((*TestService)(nil))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "circular dependency detected")
	})
}

func TestContainer_ErrorHandling(t *testing.T) {
	container := NewContainer()

	t.Run("Resolve_Unregistered_Service", func(t *testing.T) {
		_, err := container.Resolve((*TestService)(nil))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "is not registered")
	})

	t.Run("Factory_Returns_Error", func(t *testing.T) {
		container.RegisterSingleton((*TestService)(nil), func(c *Container) (interface{}, error) {
			return nil, errors.New("factory error")
		})

		_, err := container.Resolve((*TestService)(nil))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "factory error")
	})
}

func TestContainer_IsRegistered(t *testing.T) {
	container := NewContainer()

	t.Run("Check_Registration_Status", func(t *testing.T) {
		// Initially not registered
		assert.False(t, container.IsRegistered((*TestService)(nil)))

		// Register service
		container.RegisterSingleton((*TestService)(nil), func(c *Container) (interface{}, error) {
			return &TestServiceImpl{value: "test"}, nil
		})

		// Now should be registered
		assert.True(t, container.IsRegistered((*TestService)(nil)))
	})
}

func TestContainer_Shutdown(t *testing.T) {
	container := NewContainer()

	t.Run("Shutdown_Services", func(t *testing.T) {
		// Register a service that implements Shutdowner
		container.RegisterSingleton((*ShutdownService)(nil), func(c *Container) (interface{}, error) {
			return &ShutdownServiceImpl{}, nil
		})

		// Resolve to create instance
		service, err := container.Resolve((*ShutdownService)(nil))
		require.NoError(t, err)

		shutdownService := service.(ShutdownService)
		assert.Equal(t, "running", shutdownService.GetStatus())

		// Shutdown container
		err = container.Shutdown()
		assert.NoError(t, err)

		// Service should be shutdown
		assert.Equal(t, "shutdown", shutdownService.GetStatus())
	})

	t.Run("Shutdown_With_Error", func(t *testing.T) {
		container := NewContainer()

		// Register service that fails shutdown
		container.RegisterInstance((*ShutdownService)(nil), &FailingShutdownService{})

		err := container.Shutdown()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "shutdown failed")
	})
}

func TestContainer_GetRegisteredServices(t *testing.T) {
	container := NewContainer()

	t.Run("List_Registered_Services", func(t *testing.T) {
		// Initially empty
		services := container.GetRegisteredServices()
		assert.Empty(t, services)

		// Register some services
		container.RegisterSingleton((*TestService)(nil), func(c *Container) (interface{}, error) {
			return &TestServiceImpl{}, nil
		})

		container.RegisterTransient((*DependentService)(nil), func(c *Container) (interface{}, error) {
			return &DependentServiceImpl{}, nil
		})

		services = container.GetRegisteredServices()
		assert.Len(t, services, 2)

		// Check that both types are present
		var hasTestService, hasDependentService bool
		for _, serviceType := range services {
			if serviceType == reflect.TypeOf((*TestService)(nil)).Elem() {
				hasTestService = true
			}
			if serviceType == reflect.TypeOf((*DependentService)(nil)).Elem() {
				hasDependentService = true
			}
		}

		assert.True(t, hasTestService)
		assert.True(t, hasDependentService)
	})
}

func TestContainer_Clear(t *testing.T) {
	container := NewContainer()

	t.Run("Clear_All_Services", func(t *testing.T) {
		// Register services
		container.RegisterSingleton((*TestService)(nil), func(c *Container) (interface{}, error) {
			return &TestServiceImpl{}, nil
		})

		// Resolve to create cached instance
		_, err := container.Resolve((*TestService)(nil))
		require.NoError(t, err)

		// Verify service is registered
		assert.True(t, container.IsRegistered((*TestService)(nil)))

		// Clear container
		container.Clear()

		// Verify service is no longer registered
		assert.False(t, container.IsRegistered((*TestService)(nil)))

		// Should not be able to resolve
		_, err = container.Resolve((*TestService)(nil))
		assert.Error(t, err)
	})
}

func TestContainer_ConcurrentAccess(t *testing.T) {
	container := NewContainer()

	t.Run("Concurrent_Resolution", func(t *testing.T) {
		callCount := 0
		container.RegisterSingleton((*TestService)(nil), func(c *Container) (interface{}, error) {
			callCount++
			return &TestServiceImpl{value: "concurrent"}, nil
		})

		// Resolve concurrently
		const numGoroutines = 10
		results := make(chan interface{}, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func() {
				service, err := container.Resolve((*TestService)(nil))
				if err != nil {
					results <- err
				} else {
					results <- service
				}
			}()
		}

		// Collect results
		var services []interface{}
		for i := 0; i < numGoroutines; i++ {
			result := <-results
			if err, ok := result.(error); ok {
				t.Errorf("Resolution failed: %v", err)
			} else {
				services = append(services, result)
			}
		}

		// All should be the same instance (singleton)
		require.Len(t, services, numGoroutines)
		firstService := services[0]
		for _, service := range services[1:] {
			assert.Same(t, firstService, service)
		}

		// Factory should only be called once
		assert.Equal(t, 1, callCount)
	})
}

// Helper type for testing shutdown errors
type FailingShutdownService struct{}

func (f *FailingShutdownService) Shutdown() error {
	return errors.New("shutdown failed")
}

func TestContainerLifecycle(t *testing.T) {
	t.Run("Full_Lifecycle_Test", func(t *testing.T) {
		container := NewContainer()

		// Register configuration
		container.RegisterInstance((*map[string]string)(nil), map[string]string{
			"service_name": "test-service",
			"log_level":    "debug",
		})

		// Register logger that depends on config
		container.RegisterSingleton((*string)(nil), func(c *Container) (interface{}, error) {
			configIface, err := c.MustResolve((*map[string]string)(nil))
			if err != nil {
				return nil, err
			}
			config := configIface.(map[string]string)
			return "Logger for " + config["service_name"], nil
		})

		// Register service that depends on logger
		container.RegisterTransient((*TestService)(nil), func(c *Container) (interface{}, error) {
			loggerIface, err := c.MustResolve((*string)(nil))
			if err != nil {
				return nil, err
			}
			logger := loggerIface.(string)
			return &TestServiceImpl{value: logger + " - test implementation"}, nil
		})

		// Resolve and test
		service, err := container.Resolve((*TestService)(nil))
		require.NoError(t, err)

		testService := service.(TestService)
		assert.Equal(t, "Logger for test-service - test implementation", testService.GetValue())

		// Test that registered services are listed
		services := container.GetRegisteredServices()
		assert.Len(t, services, 3) // config, logger, test service

		// Test shutdown
		err = container.Shutdown()
		assert.NoError(t, err)
	})
}
