package testutil

import (
    "context"
    "testing"

    "mvp.local/pkg/observability"
    "go.opentelemetry.io/otel/trace/noop"
    "go.opentelemetry.io/otel/trace"
)

func SetupTestObservability(t *testing.T) *observability.Observability {
    t.Helper()

    obs, err := observability.New(observability.Config{
        ServiceName:    "test-service",
        ServiceVersion: "test",
        Environment:    "test",
        LogLevel:       "debug",
        LogFormat:      "console",
        PrometheusPort: 0, // Use random port
    })
    if err != nil {
        t.Fatalf("Failed to create test observability: %v", err)
    }

    t.Cleanup(func() {
        ctx := context.Background()
        obs.Shutdown(ctx)
    })

    return obs
}

func NoopTracer() trace.Tracer {
    return noop.NewTracerProvider().Tracer("test")
}
