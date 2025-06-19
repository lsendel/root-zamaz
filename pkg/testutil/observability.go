package testutil

import (
	"context"
	"io"
	"testing"

	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"mvp.local/pkg/observability"
)

func SetupTestObservability(t testing.TB) *observability.Observability {
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

// SetupTestObservabilityWithWriter is like SetupTestObservability but sends logs
// to the provided writer for easier assertions in tests.
func SetupTestObservabilityWithWriter(t testing.TB, w io.Writer) *observability.Observability {
	t.Helper()

	obs := SetupTestObservability(t)
	obs.Logger = obs.Logger.Output(w)
	return obs
}
