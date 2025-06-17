package integration

import (
    "context"
    "net/http"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "mvp.local/pkg/observability"
    "mvp.local/pkg/messaging"
    "mvp.local/pkg/testutil"
)

func TestObservabilityIntegration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test in short mode")
    }

    ctx := context.Background()

    t.Run("Observability_Initialization", func(t *testing.T) {
        obs := testutil.SetupTestObservability(t)

        // Test that observability components are initialized
        assert.NotNil(t, obs.Logger)
        assert.NotNil(t, obs.Tracer)
        assert.NotNil(t, obs.Meter)
        assert.NotNil(t, obs.Registry)
    })

    t.Run("Metrics_Collection", func(t *testing.T) {
        obs := testutil.SetupTestObservability(t)

        // Start observability
        // Assign a port for the metrics server to avoid conflicts
        obs.MetricsServer.Addr = ":0" // Use a random available port
        err := obs.Start(ctx)
        require.NoError(t, err)

        // Create security metrics
        securityMetrics, err := observability.NewSecurityMetrics(obs.Meter)
        require.NoError(t, err)

        // Record some metrics
        securityMetrics.RecordAuthzDecision(ctx, "test-tenant", "test-service", "read", "allow")
        securityMetrics.RecordTenantOperation(ctx, "test-tenant", "create", "success")

        // Wait a bit for metrics to be collected
        time.Sleep(1 * time.Second)

        // Test metrics endpoint
        // Use the actual port assigned to the metrics server
        resp, err := http.Get("http://localhost" + obs.MetricsServer.Addr + "/metrics")
        require.NoError(t, err)
        assert.Equal(t, http.StatusOK, resp.StatusCode)
        resp.Body.Close()
    })

    t.Run("Distributed_Tracing", func(t *testing.T) {
        obs := testutil.SetupTestObservability(t)

        // Create a traced operation
        ctx, span := obs.CreateSpan(ctx, "test-operation")
        defer span.End()

        // Nested span
        _, childSpan := obs.Tracer.Start(ctx, "child-operation")
        childSpan.End()

        // Verify span context
        assert.True(t, span.SpanContext().IsValid())
    })

    t.Run("NATS_Messaging_With_Tracing", func(t *testing.T) {
        obs := testutil.SetupTestObservability(t)

        // Create NATS client
        natsClient, err := messaging.NewClient(messaging.Config{
            URL: "nats://localhost:4222", // Ensure NATS is running for this test
        }, obs.Tracer)
        require.NoError(t, err)
        defer natsClient.Close()

        // Create event
        event := messaging.Event{
            Type:     "test.event",
            Source:   "test",
            TenantID: "test-tenant",
            Data:     map[string]string{"test": "data"},
        }

        // Publish event with tracing
        ctx, span := obs.CreateSpan(ctx, "publish-test-event")
        err = natsClient.PublishEvent(ctx, "test.subject", event)
        span.End()

        require.NoError(t, err)

        // Verify trace ID was added to event
        assert.NotEmpty(t, event.TraceID)
    })

    t.Run("Structured_Logging", func(t *testing.T) {
        obs := testutil.SetupTestObservability(t)

        // Test basic logging
        obs.Logger.Info().
            Str("tenant_id", "test-tenant").
            Str("operation", "test").
            Msg("Test log message")

        // Test correlation ID logging
        correlatedLogger := obs.WithCorrelationID("test-correlation-id")
        correlatedLogger.Info().Msg("Correlated log message")

        // No assertion needed - just ensure no panics
    })

    t.Run("Health_Check_Endpoint", func(t *testing.T) {
        obs := testutil.SetupTestObservability(t)

        // Assign a port for the metrics server to avoid conflicts
        obs.MetricsServer.Addr = ":0" // Use a random available port
        err := obs.Start(ctx)
        require.NoError(t, err)

        // Wait for server to start
        time.Sleep(100 * time.Millisecond)

        // Test health endpoint
        // Use the actual port assigned to the metrics server
        resp, err := http.Get("http://localhost" + obs.MetricsServer.Addr + "/health")
        require.NoError(t, err)
        assert.Equal(t, http.StatusOK, resp.StatusCode)
        resp.Body.Close()
    })
}
