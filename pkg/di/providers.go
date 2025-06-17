// Package di provides service registration patterns for structured dependency injection.
// This file contains service providers that encapsulate service registration logic.
package di

import (
    "context"
    "database/sql"

    "go.opentelemetry.io/otel/trace"

    "mvp.local/pkg/config"
    "mvp.local/pkg/messaging"
    "mvp.local/pkg/observability"
)

// ServiceProvider defines an interface for registering services in the DI container
type ServiceProvider interface {
    Register(container *Container) error
}

// ConfigServiceProvider registers configuration-related services
type ConfigServiceProvider struct{}

// Register registers configuration services in the container
func (p *ConfigServiceProvider) Register(container *Container) error {
    // Register configuration as singleton
    container.RegisterSingleton((*config.Config)(nil), func(c *Container) (interface{}, error) {
        return config.Load()
    })
    
    return nil
}

// ObservabilityServiceProvider registers observability-related services
type ObservabilityServiceProvider struct{}

// Register registers observability services in the container
func (p *ObservabilityServiceProvider) Register(container *Container) error {
    // Register observability as singleton
    container.RegisterSingleton((*observability.Observability)(nil), func(c *Container) (interface{}, error) {
        cfg := c.MustResolve((*config.Config)(nil)).(*config.Config)
        
        obsCfg := observability.Config{
            ServiceName:    cfg.Observability.ServiceName,
            ServiceVersion: cfg.Observability.ServiceVersion,
            Environment:    cfg.Observability.Environment,
            LogLevel:       cfg.Observability.LogLevel,
            LogFormat:      cfg.Observability.LogFormat,
            PrometheusPort: cfg.Observability.PrometheusPort,
            JaegerEndpoint: cfg.Observability.JaegerEndpoint,
        }
        
        obs, err := observability.New(obsCfg)
        if err != nil {
            return nil, err
        }
        
        // Start observability services
        if err := obs.Start(context.Background()); err != nil {
            return nil, err
        }
        
        return obs, nil
    })
    
    // Register tracer as singleton (extracted from observability)
    container.RegisterSingleton((*trace.Tracer)(nil), func(c *Container) (interface{}, error) {
        obs := c.MustResolve((*observability.Observability)(nil)).(*observability.Observability)
        return obs.Tracer, nil
    })
    
    // Register security metrics as singleton
    container.RegisterSingleton((*observability.SecurityMetrics)(nil), func(c *Container) (interface{}, error) {
        obs := c.MustResolve((*observability.Observability)(nil)).(*observability.Observability)
        return observability.NewSecurityMetrics(obs.Meter)
    })
    
    // Register business metrics as singleton
    container.RegisterSingleton((*observability.BusinessMetrics)(nil), func(c *Container) (interface{}, error) {
        obs := c.MustResolve((*observability.Observability)(nil)).(*observability.Observability)
        return observability.NewBusinessMetrics(obs.Meter)
    })
    
    // Register performance metrics as singleton
    container.RegisterSingleton((*observability.PerformanceMetrics)(nil), func(c *Container) (interface{}, error) {
        obs := c.MustResolve((*observability.Observability)(nil)).(*observability.Observability)
        return observability.NewPerformanceMetrics(obs.Meter)
    })
    
    return nil
}

// MessagingServiceProvider registers messaging-related services
type MessagingServiceProvider struct{}

// Register registers messaging services in the container
func (p *MessagingServiceProvider) Register(container *Container) error {
    // Register NATS client as singleton
    container.RegisterSingleton((*messaging.Client)(nil), func(c *Container) (interface{}, error) {
        cfg := c.MustResolve((*config.Config)(nil)).(*config.Config)
        tracer := c.MustResolve((*trace.Tracer)(nil)).(trace.Tracer)
        
        natsConfig := messaging.Config{
            URL:         cfg.NATS.URL,
            ClusterName: cfg.NATS.ClusterID,
            ClientID:    cfg.NATS.ClientID,
        }
        
        return messaging.NewClient(natsConfig, tracer)
    })
    
    return nil
}

// DatabaseServiceProvider registers database-related services
type DatabaseServiceProvider struct{}

// Register registers database services in the container
func (p *DatabaseServiceProvider) Register(container *Container) error {
    // Register database connection as singleton
    container.RegisterSingleton((*sql.DB)(nil), func(c *Container) (interface{}, error) {
        cfg := c.MustResolve((*config.Config)(nil)).(*config.Config)
        
        db, err := sql.Open("postgres", cfg.Database.DatabaseDSN())
        if err != nil {
            return nil, err
        }
        
        // Configure connection pool
        db.SetMaxOpenConns(cfg.Database.MaxConnections)
        db.SetMaxIdleConns(cfg.Database.MaxIdleConns)
        db.SetConnMaxLifetime(cfg.Database.ConnMaxLifetime)
        
        // Test connection
        if err := db.Ping(); err != nil {
            db.Close()
            return nil, err
        }
        
        return db, nil
    })
    
    return nil
}

// AppServiceProvider combines all service providers for application setup
type AppServiceProvider struct {
    providers []ServiceProvider
}

// NewAppServiceProvider creates a new application service provider with all standard providers
func NewAppServiceProvider() *AppServiceProvider {
    return &AppServiceProvider{
        providers: []ServiceProvider{
            &ConfigServiceProvider{},
            &ObservabilityServiceProvider{},
            &MessagingServiceProvider{},
            &DatabaseServiceProvider{},
        },
    }
}

// Register registers all services from all providers
func (p *AppServiceProvider) Register(container *Container) error {
    for _, provider := range p.providers {
        if err := provider.Register(container); err != nil {
            return err
        }
    }
    return nil
}

// AddProvider adds a custom service provider to the application provider
func (p *AppServiceProvider) AddProvider(provider ServiceProvider) {
    p.providers = append(p.providers, provider)
}

// WithProviders creates a new AppServiceProvider with the specified providers
func WithProviders(providers ...ServiceProvider) *AppServiceProvider {
    return &AppServiceProvider{
        providers: providers,
    }
}

// TestServiceProvider provides services configured for testing
type TestServiceProvider struct{}

// Register registers test-specific services
func (p *TestServiceProvider) Register(container *Container) error {
    // Register test configuration
    container.RegisterInstance((*config.Config)(nil), &config.Config{
        App: config.AppConfig{
            Name:        "test-service",
            Version:     "test",
            Environment: "test",
            Debug:       true,
        },
        HTTP: config.HTTPConfig{
            Port: 0, // Random port for testing
            Host: "localhost",
        },
        Observability: config.ObservabilityConfig{
            ServiceName:    "test-service",
            ServiceVersion: "test",
            Environment:    "test",
            LogLevel:       "debug",
            LogFormat:      "console",
            PrometheusPort: 0, // Random port for testing
        },
        Database: config.DatabaseConfig{
            Host:     "localhost",
            Port:     5432,
            Database: "test_db",
            Username: "test_user",
            Password: "test_pass",
            SSLMode:  "disable",
        },
        NATS: config.NATSConfig{
            URL:       "nats://localhost:4222",
            ClusterID: "test-cluster",
            ClientID:  "test-client",
        },
    })
    
    return nil
}

// MockServiceProvider provides mock implementations for testing
type MockServiceProvider struct {
    mocks map[interface{}]interface{}
}

// NewMockServiceProvider creates a new mock service provider
func NewMockServiceProvider() *MockServiceProvider {
    return &MockServiceProvider{
        mocks: make(map[interface{}]interface{}),
    }
}

// RegisterMock registers a mock implementation for a service type
func (p *MockServiceProvider) RegisterMock(serviceType interface{}, mock interface{}) {
    p.mocks[serviceType] = mock
}

// Register registers all mock services in the container
func (p *MockServiceProvider) Register(container *Container) error {
    for serviceType, mock := range p.mocks {
        container.RegisterInstance(serviceType, mock)
    }
    return nil
}

// ConfigureContainer is a helper function to set up a container with standard services
func ConfigureContainer() (*Container, error) {
    container := NewContainer()
    
    appProvider := NewAppServiceProvider()
    if err := appProvider.Register(container); err != nil {
        return nil, err
    }
    
    return container, nil
}

// ConfigureTestContainer is a helper function to set up a container for testing
func ConfigureTestContainer() (*Container, error) {
    container := NewContainer()
    
    // Register test configuration first
    testProvider := &TestServiceProvider{}
    if err := testProvider.Register(container); err != nil {
        return nil, err
    }
    
    // Register observability (depends on config)
    obsProvider := &ObservabilityServiceProvider{}
    if err := obsProvider.Register(container); err != nil {
        return nil, err
    }
    
    return container, nil
}

// ShutdownContainer gracefully shuts down all services in the container
func ShutdownContainer(container *Container) error {
    // Shutdown observability if present
    if container.IsRegistered((*observability.Observability)(nil)) {
        if obs, err := container.Resolve((*observability.Observability)(nil)); err == nil {
            if observabilityService, ok := obs.(*observability.Observability); ok {
                observabilityService.Shutdown(context.Background())
            }
        }
    }
    
    // Shutdown database if present
    if container.IsRegistered((*sql.DB)(nil)) {
        if db, err := container.Resolve((*sql.DB)(nil)); err == nil {
            if database, ok := db.(*sql.DB); ok {
                database.Close()
            }
        }
    }
    
    // Shutdown NATS client if present
    if container.IsRegistered((*messaging.Client)(nil)) {
        if client, err := container.Resolve((*messaging.Client)(nil)); err == nil {
            if natsClient, ok := client.(*messaging.Client); ok {
                natsClient.Close()
            }
        }
    }
    
    // Use container's shutdown method for any remaining services
    return container.Shutdown()
}