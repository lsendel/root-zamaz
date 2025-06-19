package observability

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				JaegerEndpoint: "http://localhost:4318/v1/traces",
				PrometheusPort: 9090,
				LogLevel:       "info",
				LogFormat:      "json",
			},
			wantErr: false,
		},
		{
			name: "console log format",
			config: Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				JaegerEndpoint: "http://localhost:4318/v1/traces",
				PrometheusPort: 9090,
				LogLevel:       "debug",
				LogFormat:      "console",
			},
			wantErr: false,
		},
		{
			name: "invalid log level defaults to info",
			config: Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				JaegerEndpoint: "http://localhost:4318/v1/traces",
				PrometheusPort: 9090,
				LogLevel:       "invalid",
				LogFormat:      "json",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs, err := New(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, obs)
			assert.NotNil(t, obs.Logger)
			assert.NotNil(t, obs.Tracer)
			assert.NotNil(t, obs.Meter)
			assert.NotNil(t, obs.Registry)
			assert.NotNil(t, obs.MetricsServer)

			// Cleanup
			ctx := context.Background()
			obs.Shutdown(ctx)
		})
	}
}

func TestObservability_Start(t *testing.T) {
	config := Config{
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Environment:    "test",
		JaegerEndpoint: "http://localhost:4318/v1/traces",
		PrometheusPort: 9099, // Use different port to avoid conflicts
		LogLevel:       "info",
		LogFormat:      "json",
	}

	obs, err := New(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = obs.Start(ctx)
	assert.NoError(t, err)

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Cleanup
	err = obs.Shutdown(ctx)
	assert.NoError(t, err)
}

func TestObservability_WithCorrelationID(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf).With().Timestamp().Logger()

	obs := &Observability{Logger: logger}
	correlationID := "test-correlation-123"

	newLogger := obs.WithCorrelationID(correlationID)
	newLogger.Info().Msg("test message")

	output := buf.String()
	assert.Contains(t, output, correlationID)
	assert.Contains(t, output, "test message")
}

func TestObservability_CreateSpan(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	tracer := tp.Tracer("test-tracer")

	obs := &Observability{Tracer: tracer}
	ctx := context.Background()

	testAttrs := []attribute.KeyValue{
		attribute.String("test.key", "test.value"),
		attribute.Int("test.number", 42),
	}

	ctx, span := obs.CreateSpan(ctx, "test-operation", testAttrs...)
	assert.NotNil(t, span)
	span.End()

	// Check recorded spans
	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)

	recordedSpan := spans[0]
	assert.Equal(t, "test-operation", recordedSpan.Name())

	// Check attributes
	attrs := recordedSpan.Attributes()
	assert.Len(t, attrs, 2)

	// Verify attributes
	foundKey := false
	foundNumber := false
	for _, attr := range attrs {
		if attr.Key == "test.key" && attr.Value.AsString() == "test.value" {
			foundKey = true
		}
		if attr.Key == "test.number" && attr.Value.AsInt64() == 42 {
			foundNumber = true
		}
	}
	assert.True(t, foundKey, "test.key attribute not found")
	assert.True(t, foundNumber, "test.number attribute not found")
}

func TestObservability_LoggerLevels(t *testing.T) {
	tests := []struct {
		name          string
		logLevel      string
		expectedLevel zerolog.Level
	}{
		{"debug level", "debug", zerolog.DebugLevel},
		{"info level", "info", zerolog.InfoLevel},
		{"warn level", "warn", zerolog.WarnLevel},
		{"error level", "error", zerolog.ErrorLevel},
		{"invalid defaults to info", "invalid", zerolog.InfoLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture log output
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			config := Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				JaegerEndpoint: "http://localhost:4318/v1/traces",
				PrometheusPort: 9090,
				LogLevel:       tt.logLevel,
				LogFormat:      "json",
			}

			obs, err := New(config)
			require.NoError(t, err)

			// Test logging at different levels
			obs.Logger.Debug().Msg("debug message")
			obs.Logger.Info().Msg("info message")
			obs.Logger.Warn().Msg("warn message")
			obs.Logger.Error().Msg("error message")

			// Restore stdout
			w.Close()
			out, _ := io.ReadAll(r)
			os.Stdout = oldStdout

			output := string(out)

			// Check which messages appear based on log level
			switch tt.expectedLevel {
			case zerolog.DebugLevel:
				assert.Contains(t, output, "debug message")
				assert.Contains(t, output, "info message")
				assert.Contains(t, output, "warn message")
				assert.Contains(t, output, "error message")
			case zerolog.InfoLevel:
				assert.NotContains(t, output, "debug message")
				assert.Contains(t, output, "info message")
				assert.Contains(t, output, "warn message")
				assert.Contains(t, output, "error message")
			case zerolog.WarnLevel:
				assert.NotContains(t, output, "debug message")
				assert.NotContains(t, output, "info message")
				assert.Contains(t, output, "warn message")
				assert.Contains(t, output, "error message")
			case zerolog.ErrorLevel:
				assert.NotContains(t, output, "debug message")
				assert.NotContains(t, output, "info message")
				assert.NotContains(t, output, "warn message")
				assert.Contains(t, output, "error message")
			}

			// Cleanup
			ctx := context.Background()
			obs.Shutdown(ctx)
		})
	}
}
