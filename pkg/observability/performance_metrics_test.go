package observability

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func setupTestObservabilityForPerf(t *testing.T) *Observability {
    obs, err := New(Config{
        ServiceName:    "test-service",
        ServiceVersion: "test",
        Environment:    "test",
        LogLevel:       "debug",
        LogFormat:      "console",
        PrometheusPort: 0,
    })
    require.NoError(t, err)
    return obs
}

func TestNewPerformanceMetrics(t *testing.T) {
    t.Run("Create_Performance_Metrics", func(t *testing.T) {
        obs := setupTestObservabilityForPerf(t)
        defer obs.Shutdown(context.Background())

        metrics, err := NewPerformanceMetrics(obs.Meter)
        require.NoError(t, err)
        require.NotNil(t, metrics)

        // Verify all metrics are initialized
        assert.NotNil(t, metrics.httpRequestDuration)
        assert.NotNil(t, metrics.httpRequestSize)
        assert.NotNil(t, metrics.httpResponseSize)
        assert.NotNil(t, metrics.dbQueryDuration)
        assert.NotNil(t, metrics.dbConnections)
        assert.NotNil(t, metrics.cacheHits)
        assert.NotNil(t, metrics.cacheMisses)
        assert.NotNil(t, metrics.cpuUsage)
        assert.NotNil(t, metrics.memoryUsage)
        assert.NotNil(t, metrics.goroutines)
        assert.NotNil(t, metrics.externalServiceCalls)
        assert.NotNil(t, metrics.messageQueueSize)
    })
}

func TestPerformanceMetrics_HTTPMetrics(t *testing.T) {
    obs := setupTestObservabilityForPerf(t)
    defer obs.Shutdown(context.Background())

    metrics, err := NewPerformanceMetrics(obs.Meter)
    require.NoError(t, err)

    ctx := context.Background()

    t.Run("Record_HTTP_Request", func(t *testing.T) {
        duration := 150 * time.Millisecond
        requestSize := int64(1024)   // 1KB request
        responseSize := int64(2048)  // 2KB response

        metrics.RecordHTTPRequest(ctx, "GET", "/api/users", "200", duration, requestSize, responseSize)
        metrics.RecordHTTPRequest(ctx, "POST", "/api/auth", "201", 50*time.Millisecond, 512, 256)
        metrics.RecordHTTPRequest(ctx, "GET", "/api/reports", "500", 2*time.Second, 256, 128)
    })

    t.Run("Set_HTTP_Active_Connections", func(t *testing.T) {
        metrics.SetHTTPActiveConnections(ctx, 25)
        metrics.SetHTTPActiveConnections(ctx, 30)
        metrics.SetHTTPActiveConnections(ctx, 18)
    })
}

func TestPerformanceMetrics_DatabaseMetrics(t *testing.T) {
    obs := setupTestObservabilityForPerf(t)
    defer obs.Shutdown(context.Background())

    metrics, err := NewPerformanceMetrics(obs.Meter)
    require.NoError(t, err)

    ctx := context.Background()

    t.Run("Record_DB_Query", func(t *testing.T) {
        // Successful queries
        metrics.RecordDBQuery(ctx, "SELECT", "users", 25*time.Millisecond, true)
        metrics.RecordDBQuery(ctx, "INSERT", "audit_log", 10*time.Millisecond, true)
        metrics.RecordDBQuery(ctx, "UPDATE", "sessions", 15*time.Millisecond, true)

        // Failed query
        metrics.RecordDBQuery(ctx, "SELECT", "users", 500*time.Millisecond, false)
    })

    t.Run("Set_DB_Connections", func(t *testing.T) {
        metrics.SetDBConnections(ctx, 8, 2)  // 8 active, 2 idle
        metrics.SetDBConnections(ctx, 12, 3) // 12 active, 3 idle
        metrics.SetDBConnections(ctx, 5, 5)  // 5 active, 5 idle
    })
}

func TestPerformanceMetrics_CacheMetrics(t *testing.T) {
    obs := setupTestObservabilityForPerf(t)
    defer obs.Shutdown(context.Background())

    metrics, err := NewPerformanceMetrics(obs.Meter)
    require.NoError(t, err)

    ctx := context.Background()

    t.Run("Record_Cache_Operation", func(t *testing.T) {
        // Cache hits
        metrics.RecordCacheOperation(ctx, "get", true, 1*time.Millisecond)
        metrics.RecordCacheOperation(ctx, "get", true, 2*time.Millisecond)

        // Cache misses
        metrics.RecordCacheOperation(ctx, "get", false, 5*time.Millisecond)
        metrics.RecordCacheOperation(ctx, "get", false, 8*time.Millisecond)

        // Cache writes
        metrics.RecordCacheOperation(ctx, "set", true, 3*time.Millisecond)
        metrics.RecordCacheOperation(ctx, "delete", true, 1*time.Millisecond)
    })

    t.Run("Set_Cache_Size", func(t *testing.T) {
        metrics.SetCacheSize(ctx, 1024*1024)    // 1MB
        metrics.SetCacheSize(ctx, 2*1024*1024)  // 2MB
        metrics.SetCacheSize(ctx, 512*1024)     // 512KB
    })
}

func TestPerformanceMetrics_SystemMetrics(t *testing.T) {
    obs := setupTestObservabilityForPerf(t)
    defer obs.Shutdown(context.Background())

    metrics, err := NewPerformanceMetrics(obs.Meter)
    require.NoError(t, err)

    ctx := context.Background()

    t.Run("Record_System_Metrics", func(t *testing.T) {
        // This should not panic and should record actual system metrics
        metrics.RecordSystemMetrics(ctx)
    })

    t.Run("Set_CPU_Usage", func(t *testing.T) {
        metrics.SetCPUUsage(ctx, 45.5)
        metrics.SetCPUUsage(ctx, 78.2)
        metrics.SetCPUUsage(ctx, 12.1)
    })
}

func TestPerformanceMetrics_ExternalServiceMetrics(t *testing.T) {
    obs := setupTestObservabilityForPerf(t)
    defer obs.Shutdown(context.Background())

    metrics, err := NewPerformanceMetrics(obs.Meter)
    require.NoError(t, err)

    ctx := context.Background()

    t.Run("Record_External_Service_Call", func(t *testing.T) {
        // Successful calls
        metrics.RecordExternalServiceCall(ctx, "user-service", "get_profile", 100*time.Millisecond, true)
        metrics.RecordExternalServiceCall(ctx, "auth-service", "validate_token", 50*time.Millisecond, true)

        // Failed calls
        metrics.RecordExternalServiceCall(ctx, "billing-service", "create_invoice", 2*time.Second, false)
        metrics.RecordExternalServiceCall(ctx, "email-service", "send_notification", 5*time.Second, false)
    })
}

func TestPerformanceMetrics_MessageMetrics(t *testing.T) {
    obs := setupTestObservabilityForPerf(t)
    defer obs.Shutdown(context.Background())

    metrics, err := NewPerformanceMetrics(obs.Meter)
    require.NoError(t, err)

    ctx := context.Background()

    t.Run("Set_Message_Queue_Size", func(t *testing.T) {
        metrics.SetMessageQueueSize(ctx, "user-events", 15)
        metrics.SetMessageQueueSize(ctx, "audit-events", 3)
        metrics.SetMessageQueueSize(ctx, "billing-events", 0)
    })

    t.Run("Record_Message_Processing", func(t *testing.T) {
        // Successful processing
        metrics.RecordMessageProcessing(ctx, "user-events", "user_registered", 25*time.Millisecond, true)
        metrics.RecordMessageProcessing(ctx, "audit-events", "login_attempt", 10*time.Millisecond, true)

        // Failed processing
        metrics.RecordMessageProcessing(ctx, "billing-events", "payment_failed", 100*time.Millisecond, false)
    })
}

func TestPerformanceMetrics_SystemMetricsCollection(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping system metrics collection test in short mode")
    }

    obs := setupTestObservabilityForPerf(t)
    defer obs.Shutdown(context.Background())

    metrics, err := NewPerformanceMetrics(obs.Meter)
    require.NoError(t, err)

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    t.Run("Start_System_Metrics_Collection", func(t *testing.T) {
        // Start collection with a short interval for testing
        metrics.StartSystemMetricsCollection(ctx, 10*time.Millisecond)

        // Let it run for a short time
        time.Sleep(50 * time.Millisecond)

        // Cancel the context to stop collection
        cancel()

        // Wait a bit to ensure the goroutine has stopped
        time.Sleep(20 * time.Millisecond)

        // Test should complete without hanging
    })
}

func TestPerformanceMetrics_IntegrationScenario(t *testing.T) {
    obs := setupTestObservabilityForPerf(t)
    defer obs.Shutdown(context.Background())

    metrics, err := NewPerformanceMetrics(obs.Meter)
    require.NoError(t, err)

    ctx := context.Background()

    t.Run("Complete_Request_Lifecycle", func(t *testing.T) {
        // 1. Incoming HTTP request
        metrics.SetHTTPActiveConnections(ctx, 10)

        // 2. Database query for authentication
        metrics.RecordDBQuery(ctx, "SELECT", "users", 15*time.Millisecond, true)

        // 3. Cache lookup for user permissions
        metrics.RecordCacheOperation(ctx, "get", true, 2*time.Millisecond)

        // 4. External service call for additional data
        metrics.RecordExternalServiceCall(ctx, "profile-service", "get_details", 75*time.Millisecond, true)

        // 5. Process business logic (record system metrics)
        metrics.RecordSystemMetrics(ctx)

        // 6. Database update for audit log
        metrics.RecordDBQuery(ctx, "INSERT", "audit_log", 8*time.Millisecond, true)

        // 7. Complete HTTP request
        requestDuration := 150 * time.Millisecond
        metrics.RecordHTTPRequest(ctx, "GET", "/api/user/profile", "200", requestDuration, 256, 1024)

        // 8. Update connection count
        metrics.SetHTTPActiveConnections(ctx, 9)
    })

    t.Run("High_Load_Scenario", func(t *testing.T) {
        // Simulate high load conditions
        metrics.SetHTTPActiveConnections(ctx, 100)
        metrics.SetCPUUsage(ctx, 85.5)
        metrics.SetDBConnections(ctx, 25, 0) // All connections active

        // Multiple concurrent requests with varying performance
        for i := 0; i < 10; i++ {
            duration := time.Duration(50+i*10) * time.Millisecond
            metrics.RecordHTTPRequest(ctx, "POST", "/api/data", "200", duration, 512, 256)
            metrics.RecordDBQuery(ctx, "SELECT", "data", duration/3, true)
        }

        // Cache under pressure
        for i := 0; i < 20; i++ {
            hit := i%3 != 0 // 2/3 hit rate
            metrics.RecordCacheOperation(ctx, "get", hit, 5*time.Millisecond)
        }

        // External services degraded
        metrics.RecordExternalServiceCall(ctx, "slow-service", "process", 2*time.Second, false)
        metrics.RecordExternalServiceCall(ctx, "slow-service", "process", 1800*time.Millisecond, true)
    })

    t.Run("Message_Processing_Scenario", func(t *testing.T) {
        // Queue builds up
        metrics.SetMessageQueueSize(ctx, "events", 50)

        // Process messages with varying success
        for i := 0; i < 10; i++ {
            success := i%8 != 0 // 7/8 success rate
            duration := time.Duration(20+i*5) * time.Millisecond
            metrics.RecordMessageProcessing(ctx, "events", "user_action", duration, success)

            // Queue size decreases as messages are processed
            metrics.SetMessageQueueSize(ctx, "events", int64(50-i*5))
        }
    })
}