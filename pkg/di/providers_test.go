package di

import (
    "context"
    "database/sql"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "go.opentelemetry.io/otel/trace"

    "mvp.local/pkg/config"
    "mvp.local/pkg/messaging"
    "mvp.local/pkg/observability"
)

func TestConfigServiceProvider(t *testing.T) {
    t.Run("Register_Config_Service", func(t *testing.T) {
        container := NewContainer()
        provider := &ConfigServiceProvider{}
        
        err := provider.Register(container)
        require.NoError(t, err)
        
        // Verify config is registered
        assert.True(t, container.IsRegistered((*config.Config)(nil)))
        
        // Resolve config
        cfg, err := container.Resolve((*config.Config)(nil))
        require.NoError(t, err)
        require.NotNil(t, cfg)
        
        config := cfg.(*config.Config)
        assert.NotEmpty(t, config.App.Name)
    })
}

func TestObservabilityServiceProvider(t *testing.T) {
    t.Run("Register_Observability_Services", func(t *testing.T) {
        container := NewContainer()
        
        // Register config first (dependency)
        configProvider := &ConfigServiceProvider{}
        err := configProvider.Register(container)
        require.NoError(t, err)
        
        // Override with test config to avoid port conflicts
        testConfig := &config.Config{
            Observability: config.ObservabilityConfig{
                ServiceName:    "test-service",
                ServiceVersion: "test",
                Environment:    "test",
                LogLevel:       "debug",
                LogFormat:      "console",
                PrometheusPort: 0, // Random port
            },
        }
        container.RegisterInstance((*config.Config)(nil), testConfig)
        
        // Register observability services
        obsProvider := &ObservabilityServiceProvider{}
        err = obsProvider.Register(container)
        require.NoError(t, err)
        
        // Verify services are registered
        assert.True(t, container.IsRegistered((*observability.Observability)(nil)))
        assert.True(t, container.IsRegistered((*trace.Tracer)(nil)))
        assert.True(t, container.IsRegistered((*observability.SecurityMetrics)(nil)))
        
        // Resolve observability
        obs, err := container.Resolve((*observability.Observability)(nil))
        require.NoError(t, err)
        require.NotNil(t, obs)
        
        observabilityService := obs.(*observability.Observability)
        assert.NotNil(t, observabilityService.Logger)
        assert.NotNil(t, observabilityService.Tracer)
        
        // Resolve tracer
        tracer, err := container.Resolve((*trace.Tracer)(nil))
        require.NoError(t, err)
        require.NotNil(t, tracer)
        
        // Resolve security metrics
        metrics, err := container.Resolve((*observability.SecurityMetrics)(nil))
        require.NoError(t, err)
        require.NotNil(t, metrics)
        
        // Cleanup
        observabilityService.Shutdown(context.Background())
    })
}

func TestMessagingServiceProvider(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping messaging test in short mode (requires NATS)")
    }
    
    t.Run("Register_Messaging_Service", func(t *testing.T) {
        container := NewContainer()
        
        // Setup dependencies
        testConfig := &config.Config{
            NATS: config.NATSConfig{
                URL:       "nats://localhost:4222",
                ClusterID: "test-cluster",
                ClientID:  "test-client",
            },
            Observability: config.ObservabilityConfig{
                ServiceName:    "test-service",
                ServiceVersion: "test",
                Environment:    "test",
                LogLevel:       "debug",
                LogFormat:      "console",
                PrometheusPort: 0,
            },
        }
        container.RegisterInstance((*config.Config)(nil), testConfig)
        
        // Register observability (for tracer)
        obsProvider := &ObservabilityServiceProvider{}
        err := obsProvider.Register(container)
        require.NoError(t, err)
        
        // Register messaging service
        msgProvider := &MessagingServiceProvider{}
        err = msgProvider.Register(container)
        
        if err != nil {
            t.Skipf("NATS not available, skipping test: %v", err)
        }
        
        // Verify service is registered
        assert.True(t, container.IsRegistered((*messaging.Client)(nil)))
        
        // Resolve messaging client
        client, err := container.Resolve((*messaging.Client)(nil))
        require.NoError(t, err)
        require.NotNil(t, client)
        
        natsClient := client.(*messaging.Client)
        defer natsClient.Close()
        
        // Cleanup observability
        obs := container.MustResolve((*observability.Observability)(nil)).(*observability.Observability)
        obs.Shutdown(context.Background())
    })
}

func TestDatabaseServiceProvider(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping database test in short mode (requires PostgreSQL)")
    }
    
    t.Run("Register_Database_Service", func(t *testing.T) {
        container := NewContainer()
        
        // Setup config with test database
        testConfig := &config.Config{
            Database: config.DatabaseConfig{
                Host:            "localhost",
                Port:            5432,
                Database:        "postgres", // Use default postgres DB for testing
                Username:        "postgres",
                Password:        "postgres",
                SSLMode:         "disable",
                MaxConnections:  5,
                MaxIdleConns:    2,
                ConnMaxLifetime: 300,
            },
        }
        container.RegisterInstance((*config.Config)(nil), testConfig)
        
        // Register database service
        dbProvider := &DatabaseServiceProvider{}
        err := dbProvider.Register(container)
        
        if err != nil {
            t.Skipf("Database not available, skipping test: %v", err)
        }
        
        // Verify service is registered
        assert.True(t, container.IsRegistered((*sql.DB)(nil)))
        
        // Resolve database
        db, err := container.Resolve((*sql.DB)(nil))
        require.NoError(t, err)
        require.NotNil(t, db)
        
        database := db.(*sql.DB)
        defer database.Close()
        
        // Test connection
        err = database.Ping()
        assert.NoError(t, err)
    })
}

func TestAppServiceProvider(t *testing.T) {
    t.Run("Register_All_Services", func(t *testing.T) {
        container := NewContainer()
        
        // Override config to avoid external dependencies in test
        testConfig := &config.Config{
            App: config.AppConfig{
                Name:        "test-app",
                Version:     "test",
                Environment: "test",
            },
            Observability: config.ObservabilityConfig{
                ServiceName:    "test-service",
                ServiceVersion: "test",
                Environment:    "test",
                LogLevel:       "debug",
                LogFormat:      "console",
                PrometheusPort: 0,
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
        }
        container.RegisterInstance((*config.Config)(nil), testConfig)
        
        // Create app provider without config provider (since we're overriding)
        appProvider := WithProviders(
            &ObservabilityServiceProvider{},
            // Skip messaging and database for this test
        )
        
        err := appProvider.Register(container)
        require.NoError(t, err)
        
        // Verify core services are registered
        assert.True(t, container.IsRegistered((*config.Config)(nil)))
        assert.True(t, container.IsRegistered((*observability.Observability)(nil)))
        
        // Test adding custom provider
        customProvider := &MockServiceProvider{}
        appProvider.AddProvider(customProvider)
        
        err = customProvider.Register(container)
        assert.NoError(t, err)
        
        // Cleanup
        obs := container.MustResolve((*observability.Observability)(nil)).(*observability.Observability)
        obs.Shutdown(context.Background())
    })
}

func TestTestServiceProvider(t *testing.T) {
    t.Run("Register_Test_Services", func(t *testing.T) {
        container := NewContainer()
        provider := &TestServiceProvider{}
        
        err := provider.Register(container)
        require.NoError(t, err)
        
        // Verify config is registered with test values
        assert.True(t, container.IsRegistered((*config.Config)(nil)))
        
        cfg, err := container.Resolve((*config.Config)(nil))
        require.NoError(t, err)
        
        config := cfg.(*config.Config)
        assert.Equal(t, "test-service", config.App.Name)
        assert.Equal(t, "test", config.App.Environment)
        assert.True(t, config.App.Debug)
        assert.Equal(t, 0, config.HTTP.Port) // Random port for testing
    })
}

func TestMockServiceProvider(t *testing.T) {
    t.Run("Register_Mock_Services", func(t *testing.T) {
        container := NewContainer()
        provider := NewMockServiceProvider()
        
        // Create mock implementations
        mockConfig := &config.Config{
            App: config.AppConfig{Name: "mock-service"},
        }
        
        // Register mocks
        provider.RegisterMock((*config.Config)(nil), mockConfig)
        
        err := provider.Register(container)
        require.NoError(t, err)
        
        // Verify mock is registered and resolved
        assert.True(t, container.IsRegistered((*config.Config)(nil)))
        
        resolved, err := container.Resolve((*config.Config)(nil))
        require.NoError(t, err)
        
        // Should be the same mock instance
        assert.Same(t, mockConfig, resolved)
    })
}

func TestConfigureContainer(t *testing.T) {
    t.Run("Configure_Standard_Container", func(t *testing.T) {
        // This test may fail if external dependencies aren't available
        // So we'll just test the setup without resolution
        
        container := NewContainer()
        
        // Register just config and observability for testing
        configProvider := &ConfigServiceProvider{}
        err := configProvider.Register(container)
        require.NoError(t, err)
        
        // Override with test config
        testConfig := &config.Config{
            Observability: config.ObservabilityConfig{
                ServiceName:    "test-service",
                ServiceVersion: "test",
                Environment:    "test",
                LogLevel:       "debug",
                LogFormat:      "console",
                PrometheusPort: 0,
            },
        }
        container.RegisterInstance((*config.Config)(nil), testConfig)
        
        obsProvider := &ObservabilityServiceProvider{}
        err = obsProvider.Register(container)
        require.NoError(t, err)
        
        // Verify services are available
        assert.True(t, container.IsRegistered((*config.Config)(nil)))
        assert.True(t, container.IsRegistered((*observability.Observability)(nil)))
        
        // Test shutdown
        err = ShutdownContainer(container)
        assert.NoError(t, err)
    })
}

func TestConfigureTestContainer(t *testing.T) {
    t.Run("Configure_Test_Container", func(t *testing.T) {
        container, err := ConfigureTestContainer()
        require.NoError(t, err)
        require.NotNil(t, container)
        
        // Verify test services are available
        assert.True(t, container.IsRegistered((*config.Config)(nil)))
        assert.True(t, container.IsRegistered((*observability.Observability)(nil)))
        
        // Verify config has test values
        cfg, err := container.Resolve((*config.Config)(nil))
        require.NoError(t, err)
        
        config := cfg.(*config.Config)
        assert.Equal(t, "test-service", config.App.Name)
        assert.Equal(t, "test", config.App.Environment)
        
        // Test shutdown
        err = ShutdownContainer(container)
        assert.NoError(t, err)
    })
}

func TestShutdownContainer(t *testing.T) {
    t.Run("Graceful_Shutdown", func(t *testing.T) {
        container, err := ConfigureTestContainer()
        require.NoError(t, err)
        
        // Resolve observability to ensure it's created
        obs, err := container.Resolve((*observability.Observability)(nil))
        require.NoError(t, err)
        require.NotNil(t, obs)
        
        // Test graceful shutdown
        err = ShutdownContainer(container)
        assert.NoError(t, err)
    })
}