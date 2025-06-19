package middleware

import (
	"bytes"
	"encoding/json" // Added for checking generated correlation ID
	"fmt"           // Added for string formatting in tests
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	// "go.opentelemetry.io/otel" // Commented out as it's not directly used after refactoring. Tracer/Meter obtained differently.
	// "go.opentelemetry.io/otel/attribute" // Commented out as it's not directly used after refactoring.
	"go.opentelemetry.io/otel/metric/noop" // Corrected import for noop meter provider
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	oteltrace "go.opentelemetry.io/otel/trace"

	"mvp.local/pkg/observability"
)

// testSetup holds all common test components.
type testSetup struct {
	App            *fiber.App
	LogBuffer      *bytes.Buffer
	Logger         zerolog.Logger
	Tracer         oteltrace.Tracer
	SpanRecorder   *tracetest.SpanRecorder
	Obs            *observability.Observability
	SecurityMetrics *observability.SecurityMetrics
}

// newTestSetup creates a new test setup.
func newTestSetup() *testSetup {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(ctx *fiber.Ctx, err error) error {
			// Ensure errors are returned to be caught by ObservabilityMiddleware
			return ctx.Status(fiber.StatusInternalServerError).SendString(err.Error())
		},
	})

	var logBuffer bytes.Buffer
	logger := zerolog.New(&logBuffer).With().Timestamp().Logger()

	spanRecorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	tracer := tracerProvider.Tracer("test-tracer")

	// Initialize observability components
	obs := &observability.Observability{
		Logger: logger,
		Tracer: tracer,
		// Meter can be nil if not testing metrics directly, or use a test meter
		Meter: noop.NewMeterProvider().Meter("test"), // Corrected usage of noop meter provider
	}

	// Initialize security metrics (can be a mock or a simple instance)
	// For simplicity, using a real one but it won't be asserted against heavily in these tests.
	// If specific metric assertions are needed, a mock would be better.
	secMetrics, err := observability.NewSecurityMetrics(obs.Meter)
	if err != nil {
		panic("failed to create security metrics for test: " + err.Error())
	}


	return &testSetup{
		App:            app,
		LogBuffer:      &logBuffer,
		Logger:         logger,
		Tracer:         tracer,
		SpanRecorder:   spanRecorder,
		Obs:            obs,
		SecurityMetrics: secMetrics,
	}
}

func TestObservabilityMiddleware_LogIDs(t *testing.T) {
	testCorrelationID := "test-corr-id-123"
	testTenantID := "test-tenant-id-456"

	tests := []struct {
		name                 string
		setupMiddleware      func(app *fiber.App, obs *observability.Observability, tracer oteltrace.Tracer, sm *observability.SecurityMetrics)
		requestHeaders       map[string]string
		expectedLogInclusions []string
		expectedSpanCount    int
	}{
		{
			name: "logs correlation ID from header",
			setupMiddleware: func(app *fiber.App, obs *observability.Observability, tracer oteltrace.Tracer, sm *observability.SecurityMetrics) {
				app.Use(CorrelationIDMiddleware())
				app.Use(ObservabilityMiddleware(obs, sm))
			},
			requestHeaders: map[string]string{
				CorrelationIDHeader: testCorrelationID,
			},
			expectedLogInclusions: []string{`"correlation_id":"` + testCorrelationID + `"`},
		},
		{
			name: "logs generated correlation ID when header is missing",
			setupMiddleware: func(app *fiber.App, obs *observability.Observability, tracer oteltrace.Tracer, sm *observability.SecurityMetrics) {
				app.Use(CorrelationIDMiddleware())
				app.Use(ObservabilityMiddleware(obs, sm))
			},
			requestHeaders:       map[string]string{},
			expectedLogInclusions: []string{`"correlation_id":`, `"level":"info"`}, // Check that a correlation_id field exists
		},
		{
			name: "logs tenant ID from header",
			setupMiddleware: func(app *fiber.App, obs *observability.Observability, tracer oteltrace.Tracer, sm *observability.SecurityMetrics) {
				app.Use(TenantContextMiddleware())
				app.Use(ObservabilityMiddleware(obs, sm))
			},
			requestHeaders: map[string]string{
				TenantIDHeader: testTenantID,
			},
			expectedLogInclusions: []string{`"tenant_id":"` + testTenantID + `"`},
		},
		{
			name: "logs trace ID from span",
			setupMiddleware: func(app *fiber.App, obs *observability.Observability, tracer oteltrace.Tracer, sm *observability.SecurityMetrics) {
				app.Use(TracingMiddleware(tracer))
				app.Use(ObservabilityMiddleware(obs, sm))
			},
			requestHeaders:       map[string]string{},
			expectedLogInclusions: []string{`"trace_id":`, `"level":"info"`}, // Check that a trace_id field exists
			expectedSpanCount:    1,
		},
		{
			name: "logs all IDs when present",
			setupMiddleware: func(app *fiber.App, obs *observability.Observability, tracer oteltrace.Tracer, sm *observability.SecurityMetrics) {
				app.Use(CorrelationIDMiddleware())
				app.Use(TenantContextMiddleware())
				app.Use(TracingMiddleware(tracer))
				app.Use(ObservabilityMiddleware(obs, sm))
			},
			requestHeaders: map[string]string{
				CorrelationIDHeader: testCorrelationID,
				TenantIDHeader:      testTenantID,
			},
			expectedLogInclusions: []string{
				`"correlation_id":"` + testCorrelationID + `"`,
				`"tenant_id":"` + testTenantID + `"`,
				`"trace_id":`,
			},
			expectedSpanCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := newTestSetup()
			tt.setupMiddleware(setup.App, setup.Obs, setup.Tracer, setup.SecurityMetrics)

			setup.App.Get("/log_ids_test", func(c *fiber.Ctx) error {
				return c.SendStatus(fiber.StatusOK)
			})

			req := httptest.NewRequest("GET", "/log_ids_test", nil)
			for k, v := range tt.requestHeaders {
				req.Header.Set(k, v)
			}

			_, err := setup.App.Test(req)
			require.NoError(t, err)

			logOutput := setup.LogBuffer.String()
			//t.Logf("Log output for %s: %s", tt.name, logOutput) // For debugging

			for _, inclusion := range tt.expectedLogInclusions {
				assert.Contains(t, logOutput, inclusion)
			}

			if tt.expectedSpanCount > 0 {
				spans := setup.SpanRecorder.Ended()
				assert.Len(t, spans, tt.expectedSpanCount)
				if len(spans) > 0 {
					traceIDFromSpan := spans[0].SpanContext().TraceID().String()
					assert.Contains(t, logOutput, `"trace_id":"`+traceIDFromSpan+`"`)
				}
			}

			// Verify that generated correlation ID is a UUID
			if tt.name == "logs generated correlation ID when header is missing" {
				// Extract correlation_id from log output
				var logEntry map[string]interface{}
				// Zerolog might output multiple JSON objects if not careful, ensure buffer is clean or parse line by line.
				// Assuming a single log entry for this test for simplicity.
				// For multiple entries, one would need to parse each JSON object from the buffer.
				logBytes := setup.LogBuffer.Bytes()

				// Find the first valid JSON object in the buffer
				decoder := json.NewDecoder(bytes.NewReader(logBytes))
				if err := decoder.Decode(&logEntry); err != nil {
					// Fallback or error if no JSON object is found or if there are multiple and the first isn't the one.
					// This might happen if there are preamble/non-JSON parts or multiple log lines.
					// A more robust way would be to split by newline and parse each line if multiple logs are expected.
					// For this specific test, we expect one log line from ObservabilityMiddleware.
					require.NoError(t, err, "Failed to unmarshal log output: %s", logBytes)
				}

				loggedCorrID, ok := logEntry["correlation_id"].(string)
				require.True(t, ok, "correlation_id not found or not a string in log output: %v", logEntry)
				_, err = uuid.Parse(loggedCorrID)
				assert.NoError(t, err, "Generated correlation_id ('%s') is not a valid UUID", loggedCorrID)
			}
		})
	}
}


// Helper to create a new Fiber app for testing (kept for other tests if they don't need full setup)
func newTestApp() *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(ctx *fiber.Ctx, err error) error {
			ctx.Status(fiber.StatusInternalServerError).SendString(err.Error())
			return nil
		},
	})
	return app
}

// --- CorrelationIDMiddleware Tests ---
func TestCorrelationIDMiddleware_Fiber(t *testing.T) {
	tests := []struct {
		name              string
		incomingHeader    string
		expectedGenerated bool
	}{
		{
			name:              "uses existing correlation ID from header",
			incomingHeader:    "test-correlation-id",
			expectedGenerated: false,
		},
		{
			name:              "generates new correlation ID when missing",
			incomingHeader:    "",
			expectedGenerated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newTestApp()
			app.Use(CorrelationIDMiddleware())

			// Test handler to capture the correlation ID
			var capturedCorrelationID string
			app.Get("/test", func(c *fiber.Ctx) error {
				capturedCorrelationID = c.Locals("correlation_id").(string)
				return c.SendString("ok")
			})

			req := httptest.NewRequest("GET", "/test", nil)
			if tt.incomingHeader != "" {
				req.Header.Set(CorrelationIDHeader, tt.incomingHeader)
			}

			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, fiber.StatusOK, resp.StatusCode)

			// Check response header
			respCorrelationID := resp.Header.Get(CorrelationIDHeader)
			assert.NotEmpty(t, respCorrelationID)

			if tt.expectedGenerated {
				// Should be a valid UUID
				_, err := uuid.Parse(capturedCorrelationID)
				assert.NoError(t, err)
				assert.Equal(t, capturedCorrelationID, respCorrelationID)
			} else {
				assert.Equal(t, tt.incomingHeader, capturedCorrelationID)
				assert.Equal(t, tt.incomingHeader, respCorrelationID)
			}
		})
	}
}

// --- TenantContextMiddleware Tests ---
func TestTenantContextMiddleware_Fiber(t *testing.T) {
	tests := []struct {
		name             string
		tenantHeader     string
		expectedInLocals bool
	}{
		{
			name:             "sets tenant ID from header",
			tenantHeader:     "tenant-123",
			expectedInLocals: true,
		},
		{
			name:             "no tenant ID in header",
			tenantHeader:     "",
			expectedInLocals: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newTestApp()
			app.Use(TenantContextMiddleware())

			var capturedTenantID interface{}
			app.Get("/test", func(c *fiber.Ctx) error {
				capturedTenantID = c.Locals("tenant_id")
				return c.SendString("ok")
			})

			req := httptest.NewRequest("GET", "/test", nil)
			if tt.tenantHeader != "" {
				req.Header.Set(TenantIDHeader, tt.tenantHeader)
			}

			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, fiber.StatusOK, resp.StatusCode)

			if tt.expectedInLocals {
				assert.Equal(t, tt.tenantHeader, capturedTenantID)
			} else {
				assert.Nil(t, capturedTenantID)
			}
		})
	}
}

// --- ObservabilityMiddleware Tests ---

// TestObservabilityMiddleware_Tracing uses the shared setup to test tracing.
// This test is simplified as the original TestObservabilityMiddleware_TracingAndMetrics
// was testing a custom middleware setup rather than the actual ObservabilityMiddleware's tracing.
// The actual ObservabilityMiddleware doesn't create spans itself, it relies on TracingMiddleware.
// This test will verify that when TracingMiddleware and ObservabilityMiddleware are used together,
// the trace ID from the span created by TracingMiddleware is logged by ObservabilityMiddleware.
func TestObservabilityMiddleware_LogsTraceID(t *testing.T) {
	setup := newTestSetup()

	// Apply necessary middleware
	setup.App.Use(CorrelationIDMiddleware()) // To have correlation ID available
	setup.App.Use(TracingMiddleware(setup.Tracer)) // To create a span and trace ID
	setup.App.Use(ObservabilityMiddleware(setup.Obs, setup.SecurityMetrics))

	setup.App.Get("/test_trace", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test_trace", nil)
	_, err := setup.App.Test(req)
	require.NoError(t, err)

	// Verify span was created
	spans := setup.SpanRecorder.Ended()
	require.Len(t, spans, 1, "Expected one span to be recorded")
	expectedTraceID := spans[0].SpanContext().TraceID().String()

	// Verify log output
	logOutput := setup.LogBuffer.String()
	assert.Contains(t, logOutput, `"trace_id":"`+expectedTraceID+`"`)
	assert.Contains(t, logOutput, `"level":"info"`)
	assert.Contains(t, logOutput, `"message":"HTTP Request"`)
}

func TestObservabilityMiddleware_LoggingLevels(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		handler        fiber.Handler
		expectedStatus int
		expectedLevel  string
		expectedError  string // Substring to check for in error log
	}{
		{
			name: "successful request logs info",
			path: "/log_success",
			handler: func(c *fiber.Ctx) error {
				return c.SendStatus(fiber.StatusOK)
			},
			expectedStatus: fiber.StatusOK,
			expectedLevel:  "info",
		},
		{
			name: "failed request logs error",
			path: "/log_fail",
			handler: func(c *fiber.Ctx) error {
				return fiber.NewError(fiber.StatusInternalServerError, "internal server problem")
			},
			expectedStatus: fiber.StatusInternalServerError,
			expectedLevel:  "error",
			expectedError:  "internal server problem",
		},
		{
			name: "error returned by next but status code is 200",
			path: "/log_error_with_200",
			handler: func(c *fiber.Ctx) error {
				c.Status(fiber.StatusOK)
				return fmt.Errorf("simulated processing error")
			},
			expectedStatus: fiber.StatusOK,
			expectedLevel:  "error",
			expectedError:  "simulated processing error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setup := newTestSetup()
			// Apply ObservabilityMiddleware without other middlewares for focused testing
			setup.App.Use(ObservabilityMiddleware(setup.Obs, setup.SecurityMetrics))
			setup.App.Get(tt.path, tt.handler)

			req := httptest.NewRequest("GET", tt.path, nil)
			resp, appErr := setup.App.Test(req)
			require.NoError(t, appErr)

			logOutput := setup.LogBuffer.String()
			//t.Logf("Log output for %s: %s", tt.name, logOutput) // Debugging line

			assert.Contains(t, logOutput, `"level":"`+tt.expectedLevel+`"`)
			assert.Contains(t, logOutput, fmt.Sprintf(`"status":%d`, tt.expectedStatus))
			assert.Contains(t, logOutput, `"method":"GET"`)
			assert.Contains(t, logOutput, `"path":"`+tt.path+`"`)
			assert.Contains(t, logOutput, `"message":"HTTP Request"`)

			if tt.expectedError != "" {
				assert.Contains(t, logOutput, tt.expectedError)
			}
			if tt.expectedLevel == "error" {
				// Ensure the actual error message passed to logger.Error().Err(err) is logged.
				// This often appears under an "error" key in zerolog.
				assert.Contains(t, logOutput, `"error":"`+tt.expectedError+`"`)
			}

			// Assert final response status code. This might be different from logged status
			// if an error handler in the app (like the one in newTestSetup) modifies it.
			if tt.name == "failed request logs error" {
				assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			} else if tt.name == "error returned by next but status code is 200" {
				// The app's error handler changes status to 500 for any returned error.
				assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
			} else {
				assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			}
		})
	}
}

// TestObservabilityMiddleware_Metrics checks if metrics are recorded.
// This is a basic check. More detailed metric testing might require a mock meter provider.
func TestObservabilityMiddleware_Metrics(t *testing.T) {
	setup := newTestSetup()

	// Apply necessary middleware
	setup.App.Use(CorrelationIDMiddleware())
	setup.App.Use(TenantContextMiddleware()) // Metrics are tenant-specific
	setup.App.Use(ObservabilityMiddleware(setup.Obs, setup.SecurityMetrics))

	setup.App.Get("/metric_success", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	setup.App.Get("/metric_error", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusBadRequest).SendString("client error")
	})

	// Test successful request
	reqSuccess := httptest.NewRequest("GET", "/metric_success", nil)
	reqSuccess.Header.Set(TenantIDHeader, "tenant-metric-test")
	_, err := setup.App.Test(reqSuccess)
	require.NoError(t, err)
	// Add assertions for metrics if a mock meter or testable meter is used.
	// For now, this test primarily ensures the middleware runs without panicking with metrics.

	// Test error request
	reqError := httptest.NewRequest("GET", "/metric_error", nil)
	reqError.Header.Set(TenantIDHeader, "tenant-metric-test")
	_, err = setup.App.Test(reqError)
	require.NoError(t, err)
	// Add assertions for metrics here as well.

	// Minimal assertion: check log for tenant_id to ensure path was taken
	logOutput := setup.LogBuffer.String()
	assert.Contains(t, logOutput, `"tenant_id":"tenant-metric-test"`)
	assert.Contains(t, logOutput, `"message":"HTTP Request"`)
}
