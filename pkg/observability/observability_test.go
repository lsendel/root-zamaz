package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func TestNewObservability(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		expectError bool
		check       func(t *testing.T, obs *Observability, cfg Config, outputBuffer *bytes.Buffer)
	}{
		{
			name: "Valid config - JSON logging",
			cfg: Config{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				JaegerEndpoint: "http://localhost:14268/api/traces", // Mock, won't connect
				PrometheusPort: 9091,
				LogLevel:       "debug",
				LogFormat:      "json",
			},
			expectError: false,
			check: func(t *testing.T, obs *Observability, cfg Config, outputBuffer *bytes.Buffer) {
				require.NotNil(t, obs)
				assert.NotNil(t, obs.Logger)
				assert.NotNil(t, obs.Tracer)
				assert.NotNil(t, obs.Meter)
				assert.NotNil(t, obs.Registry)
				assert.NotNil(t, obs.MetricsServer)
				assert.NotNil(t, obs.tp)
				assert.NotNil(t, obs.mp)

				// Check logger level
				assert.Equal(t, zerolog.DebugLevel, obs.Logger.GetLevel())

				// Check logger output format (JSON) by logging a test message
				obs.Logger.Info().Str("test_key", "test_value").Msg("test log message")
				logOutput := outputBuffer.String()
				assert.Contains(t, logOutput, `"level":"info"`)
				assert.Contains(t, logOutput, `"service":"test-service"`)
				assert.Contains(t, logOutput, `"test_key":"test_value"`)
				assert.Contains(t, logOutput, `"message":"test log message"`)
				var jsonLog map[string]interface{}
				err := json.Unmarshal([]byte(logOutput), &jsonLog)
				assert.NoError(t, err, "Log output should be valid JSON")
			},
		},
		{
			name: "Valid config - Console logging",
			cfg: Config{
				ServiceName:    "console-service",
				ServiceVersion: "dev",
				Environment:    "dev",
				JaegerEndpoint: "http://localhost:14268/api/traces",
				PrometheusPort: 9092,
				LogLevel:       "warn",
				LogFormat:      "console",
			},
			expectError: false,
			check: func(t *testing.T, obs *Observability, cfg Config, outputBuffer *bytes.Buffer) {
				require.NotNil(t, obs)
				assert.Equal(t, zerolog.WarnLevel, obs.Logger.GetLevel())

				obs.Logger.Warn().Msg("console test")
				logOutput := outputBuffer.String()
				// Console format is harder to assert precisely, but check for core parts
				assert.Contains(t, logOutput, "WRN") // Default console level for warn
				assert.Contains(t, logOutput, "console test")
				assert.Contains(t, logOutput, "service=console-service")
				assert.NotContains(t, logOutput, "{") // Should not be JSON
			},
		},
		{
			name: "Invalid log level",
			cfg: Config{
				LogLevel:  "invalid-level",
				LogFormat: "json",
			},
			expectError: false, // Defaults to InfoLevel
			check: func(t *testing.T, obs *Observability, cfg Config, outputBuffer *bytes.Buffer) {
				require.NotNil(t, obs)
				assert.Equal(t, zerolog.InfoLevel, obs.Logger.GetLevel())
			},
		},
		// Note: Testing Jaeger/Prometheus exporter creation failures is hard without mocks
		// or by providing invalid endpoints that cause immediate errors.
		// For this example, we assume they initialize if endpoint syntax is okay.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture logger output
			var outputBuffer bytes.Buffer
			originalWriter := zerolog.GlobalLevelWriter()
			zerolog.GlobalLevelWriter(&outputBuffer)
			defer zerolog.GlobalLevelWriter(originalWriter) // Restore original writer

			// Redirect os.Stdout for console logging checks
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w
			defer func() {
				os.Stdout = oldStdout
				w.Close()
			}()


			obs, err := New(tt.cfg)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, obs)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, obs)
				if tt.check != nil {
					// Read console output if applicable
					w.Close() // Close writer to flush
					consoleBytes, _ := os.ReadAll(r)
					outputBuffer.Write(consoleBytes) // Append console output to the buffer for unified checking

					tt.check(t, obs, tt.cfg, &outputBuffer)
				}
				// Cleanup resources if New was successful
				if obs != nil {
					obs.Shutdown(context.Background())
				}
			}
		})
	}
}

func TestObservability_WithCorrelationID(t *testing.T) {
	var outputBuffer bytes.Buffer
	originalWriter := zerolog.GlobalLevelWriter()
	zerolog.GlobalLevelWriter(&outputBuffer)
	defer zerolog.GlobalLevelWriter(originalWriter)


	cfg := Config{ServiceName: "corr-test", LogLevel: "info", LogFormat: "json"}
	obs, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, obs)
	defer obs.Shutdown(context.Background())

	correlationID := "test-corr-id-123"
	correlatedLogger := obs.WithCorrelationID(correlationID)

	// Log a message with the correlated logger
	correlatedLogger.Info().Msg("correlated message")

	logOutput := outputBuffer.String()
	assert.Contains(t, logOutput, `"correlation_id":"test-corr-id-123"`)
	assert.Contains(t, logOutput, `"message":"correlated message"`)
}

func TestObservability_CreateSpan(t *testing.T) {
	cfg := Config{ServiceName: "span-test"}
	obs, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, obs)
	defer obs.Shutdown(context.Background())

	ctx := context.Background()
	attr := attribute.String("key", "value")

	newCtx, span := obs.CreateSpan(ctx, "testSpan", attr)

	require.NotNil(t, newCtx)
	require.NotNil(t, span)
	defer span.End()

	spanCtx := span.SpanContext()
	assert.True(t, spanCtx.IsValid())
	assert.True(t, spanCtx.IsSampled()) // Default is AlwaysSample

	// Test that attributes are set (though not directly readable from live span easily)
	// This primarily tests that the call doesn't panic and returns a valid span.
}

func TestObservability_StartShutdown(t *testing.T) {
	cfg := Config{
		ServiceName:    "start-stop-test",
		PrometheusPort: 0, // Use a random available port
		LogLevel:       "error", // Keep logs quiet for this test
	}
	obs, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, obs)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// The Start method itself doesn't return an error for server start issues (it logs them)
		// So, we primarily test that it doesn't panic.
		startErr := obs.Start(ctx)
		assert.NoError(t, startErr, "obs.Start() should not return an error")
	}()

	// Give the server a moment to attempt to start
	// Even if it fails to bind, Start itself is non-blocking for ListenAndServe
	time.Sleep(50 * time.Millisecond)

	// Test health endpoint (if server started successfully on a random port)
	// We need to get the actual port the server is listening on.
	// The Addr field is updated after ListenAndServe starts.
	// This part is a bit tricky as ListenAndServe blocks.
	// For a unit test, we might not be able to reliably hit the HTTP endpoint
	// without more complex goroutine management or by making Start return the actual address.

	// For this test, we will check if the server address is populated,
	// indicating ListenAndServe was called.
	// A more robust test would involve an HTTP client making a request.

	// Try to hit the health endpoint if the server is running
	// This requires the server to be accessible.
	// If PrometheusPort was 0, Addr will be like ":<random_port>"
	if obs.MetricsServer != nil && obs.MetricsServer.Addr != "" && obs.MetricsServer.Addr != ":0" {
		// The server might not be fully up yet, or might fail to bind.
		// This is more of an integration aspect.
		// For now, just ensuring Start and Shutdown run without panic is the core goal.
	}


	shutdownErr := obs.Shutdown(ctx)
	assert.NoError(t, shutdownErr, "obs.Shutdown() should not return an error")

	wg.Wait() // Wait for the Start goroutine to finish (which it will after Shutdown)

	// Try to make a request to the server after shutdown - it should fail
	if obs.MetricsServer != nil && obs.MetricsServer.Addr != "" && obs.MetricsServer.Addr != ":0" {
		// This check is only meaningful if a port was dynamically assigned and server started.
		// After shutdown, this request should error out.
		_, errAfterShutdown := http.Get("http://localhost" + obs.MetricsServer.Addr + "/health")
		assert.Error(t, errAfterShutdown, "Request to /health after shutdown should fail")
	}
}

func TestObservability_MetricsServerEndpoints(t *testing.T) {
	cfg := Config{ServiceName: "metrics-ep-test", PrometheusPort: 0} // Random port
	obs, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, obs)

	// Start the server in a goroutine
	go func() {
		_ = obs.Start(context.Background())
	}()

	// Wait for the server to start and assign a port
	// This is a common challenge in testing HTTP servers.
	// A more robust way would be to have Start signal readiness.
	time.Sleep(100 * time.Millisecond)
	require.NotEmpty(t, obs.MetricsServer.Addr, "MetricsServer.Addr should be set after Start")
	require.NotEqual(t, ":0", obs.MetricsServer.Addr, "MetricsServer.Addr should be a specific port after Start")


	t.Run("/health endpoint", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://localhost"+obs.MetricsServer.Addr+"/health", nil)
		rr := httptest.NewRecorder()
		obs.MetricsServer.Handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "OK", rr.Body.String())
	})

	t.Run("/metrics endpoint", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://localhost"+obs.MetricsServer.Addr+"/metrics", nil)
		rr := httptest.NewRecorder()
		obs.MetricsServer.Handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		// Basic check for prometheus metrics format
		assert.True(t, strings.Contains(rr.Body.String(), "# HELP"), "Should contain Prometheus help text")
		assert.True(t, strings.Contains(rr.Body.String(), "# TYPE"), "Should contain Prometheus type text")
	})

	// Shutdown the server
	err = obs.Shutdown(context.Background())
	assert.NoError(t, err)
}
