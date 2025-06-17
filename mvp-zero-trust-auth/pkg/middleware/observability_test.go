package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"mvp.local/pkg/observability"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	oteltrace "go.opentelemetry.io/otel/trace"
	"net/http/httptest"
)

// Mock SecurityMetrics
type MockSecurityMetrics struct {
	mock.Mock
	// Embed observability.SecurityMetrics if it was a struct with methods.
	// If it's an interface, this mock satisfies it by implementing methods.
}

func (m *MockSecurityMetrics) RecordTenantOperation(ctx context.Context, tenantID, operation, status string) {
	m.Called(ctx, tenantID, operation, status)
}

// Helper to create a new Fiber app for testing
func newTestApp() *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(ctx *fiber.Ctx, err error) error { // Optional: custom error handler for tests
			ctx.Status(fiber.StatusInternalServerError).SendString(err.Error())
			return nil
		},
	})
	return app
}

// --- CorrelationIDMiddleware Tests ---
func TestCorrelationIDMiddleware_Fiber(t *testing.T) {
	t.Run("Header present", func(t *testing.T) {
		app := newTestApp()
		existingCorrID := "existing-id-123"
		var actualCorrID string

		app.Use(CorrelationIDMiddleware())
		app.Get("/", func(c *fiber.Ctx) error {
			actualCorrID = c.Locals("correlation_id").(string)
			return c.SendStatus(fiber.StatusOK)
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set(CorrelationIDHeader, existingCorrID)

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Equal(t, existingCorrID, actualCorrID)
		assert.Equal(t, existingCorrID, resp.Header.Get(CorrelationIDHeader))
	})

	t.Run("Header not present", func(t *testing.T) {
		app := newTestApp()
		var actualCorrID, headerCorrID string

		app.Use(CorrelationIDMiddleware())
		app.Get("/", func(c *fiber.Ctx) error {
			actualCorrID = c.Locals("correlation_id").(string)
			return c.SendStatus(fiber.StatusOK)
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.NotEmpty(t, actualCorrID)
		_, parseErr := uuid.Parse(actualCorrID)
		assert.NoError(t, parseErr)

		headerCorrID = resp.Header.Get(CorrelationIDHeader)
		assert.Equal(t, actualCorrID, headerCorrID)
	})
}

// --- TenantContextMiddleware Tests ---
func TestTenantContextMiddleware_Fiber(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	tracer := tp.Tracer("test-tracer-tenant")

	t.Run("TenantID header present", func(t *testing.T) {
		app := newTestApp()
		tenantID := "tenant-abc-123"
		var actualTenantID string
		var spanFromHandler oteltrace.Span

		app.Use(func(c *fiber.Ctx) error { // Dummy middleware to put span in context
			ctx, span := tracer.Start(c.UserContext(), "test-op")
			defer span.End()
			c.SetUserContext(ctx)
			return c.Next()
		})
		app.Use(TenantContextMiddleware())
		app.Get("/", func(c *fiber.Ctx) error {
			actualTenantID = c.Locals("tenant_id").(string)
			spanFromHandler = oteltrace.SpanFromContext(c.UserContext())
			return c.SendStatus(fiber.StatusOK)
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set(TenantIDHeader, tenantID)

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Equal(t, tenantID, actualTenantID)

		require.True(t, spanFromHandler.SpanContext().IsValid())
		// Attributes are added to the span from the dummy middleware
		finishedSpans := spanRecorder.Ended()
		require.GreaterOrEqual(t, len(finishedSpans), 1)

		// Find the relevant span
		var targetSpan sdktrace.ReadOnlySpan
		for _, s := range finishedSpans {
			if s.Name() == "test-op" { // Name of the span created in dummy middleware
				targetSpan = s
				break
			}
		}
		require.NotNil(t, targetSpan, "test-op span not found")

		foundAttr := false
		for _, attr := range targetSpan.Attributes() {
			if attr.Key == "tenant.id" {
				assert.Equal(t, attribute.StringValue(tenantID), attr.Value)
				foundAttr = true
				break
			}
		}
		assert.True(t, foundAttr, "tenant.id attribute not found on span")
		spanRecorder.Reset()
	})

	t.Run("TenantID header not present", func(t *testing.T) {
		app := newTestApp()
		var actualTenantID interface{}

		app.Use(func(c *fiber.Ctx) error { // Dummy middleware
			ctx, span := tracer.Start(c.UserContext(), "test-op-no-tenant")
			defer span.End()
			c.SetUserContext(ctx)
			return c.Next()
		})
		app.Use(TenantContextMiddleware())
		app.Get("/", func(c *fiber.Ctx) error {
			actualTenantID = c.Locals("tenant_id")
			return c.SendStatus(fiber.StatusOK)
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Nil(t, actualTenantID)

		finishedSpans := spanRecorder.Ended()
		require.GreaterOrEqual(t, len(finishedSpans), 1)

		var targetSpan sdktrace.ReadOnlySpan
		for _, s := range finishedSpans {
			if s.Name() == "test-op-no-tenant" {
				targetSpan = s
				break
			}
		}
		require.NotNil(t, targetSpan, "test-op-no-tenant span not found")

		for _, attr := range targetSpan.Attributes() {
			assert.NotEqual(t, attribute.Key("tenant.id"), attr.Key, "tenant.id attribute should not be set")
		}
		spanRecorder.Reset()
	})
}

// --- TracingMiddleware Tests ---
func TestTracingMiddleware_Fiber(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
	tracer := tp.Tracer("test-tracer-http-fiber")

	app := newTestApp()
	app.Use(TracingMiddleware(tracer))

	app.Get("/test", func(c *fiber.Ctx) error {
		span := oteltrace.SpanFromContext(c.UserContext())
		assert.True(t, span.SpanContext().IsValid())
		return c.Status(fiber.StatusOK).SendString("ok")
	})

	app.Get("/error", func(c *fiber.Ctx) error {
		// Simulate an error returned by a handler
		return fiber.NewError(fiber.StatusInternalServerError, "handler error")
	})

	app.Get("/statuserror", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusBadRequest)
	})


	t.Run("Successful request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test?query=param", nil)
		req.Header.Set("User-Agent", "test-agent-fiber")

		resp, err := app.Test(req, 1000) // Added timeout for app.Test
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		finishedSpans := spanRecorder.Ended()
		require.Len(t, finishedSpans, 1)
		s := finishedSpans[0]

		assert.Equal(t, "/test", s.Name()) // Fiber uses Path by default
		attrs := s.Attributes()
		expectedValues := map[attribute.Key]string{
			"http.method":     "GET",
			"http.url":        "/test?query=param",
			"http.target":     "/test",
			"http.host":       "example.com", // Default from httptest
			"http.scheme":     "http",        // Default from httptest
			"http.user_agent": "test-agent-fiber",
		}
		for k, v := range expectedValues {
			val, ok := getAttribute(attrs, k)
			require.True(t, ok, "Expected attribute %s not found", k)
			assert.Equal(t, v, val.AsString())
		}
		statusCode, ok := getAttribute(attrs, "http.status_code")
		require.True(t, ok)
		assert.Equal(t, int64(fiber.StatusOK), statusCode.AsInt64())

		responseSize, ok := getAttribute(attrs, "http.response_size")
		require.True(t, ok)
		assert.Equal(t, int64(len("ok")), responseSize.AsInt64())

		_, errorAttrFound := getAttribute(attrs, "error")
		assert.False(t, errorAttrFound, "Error attribute should not be true")
		spanRecorder.Reset()
	})

	t.Run("Handler returns error", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/error", nil)
		resp, err := app.Test(req, 1000)
		require.NoError(t, err) // app.Test itself shouldn't error for handler errors if ErrorHandler is set
		defer resp.Body.Close()

		assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode) // Checked against ErrorHandler
		finishedSpans := spanRecorder.Ended()
		require.Len(t, finishedSpans, 1)
		s := finishedSpans[0]

		assert.Equal(t, "/error", s.Name())
		errorAttr, ok := getAttribute(s.Attributes(), "error")
		assert.True(t, ok, "Error attribute should be true")
		assert.True(t, errorAttr.AsBool())

		statusCode, ok := getAttribute(s.Attributes(), "http.status_code")
		require.True(t, ok)
		assert.Equal(t, int64(fiber.StatusInternalServerError), statusCode.AsInt64())
		spanRecorder.Reset()
	})

	t.Run("Status code error", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/statuserror", nil)
		resp, err := app.Test(req,1000)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
		finishedSpans := spanRecorder.Ended()
		require.Len(t, finishedSpans, 1)
		s := finishedSpans[0]

		assert.Equal(t, "/statuserror", s.Name())
		errorAttr, ok := getAttribute(s.Attributes(), "error")
		assert.True(t, ok, "Error attribute should be true for status >= 400")
		assert.True(t, errorAttr.AsBool())

		statusCode, ok := getAttribute(s.Attributes(), "http.status_code")
		require.True(t, ok)
		assert.Equal(t, int64(fiber.StatusBadRequest), statusCode.AsInt64())
		spanRecorder.Reset()
	})
}

// Helper to get attribute from a slice
func getAttribute(attrs []attribute.KeyValue, key attribute.Key) (attribute.Value, bool) {
	for _, attr := range attrs {
		if attr.Key == key {
			return attr.Value, true
		}
	}
	return attribute.Value{}, false
}


// --- ObservabilityMiddleware Tests ---
func TestObservabilityMiddleware_Fiber(t *testing.T) {
	// Setup mock observability
	var logBuf bytes.Buffer
	// Configure zerolog to write to our buffer for assertions
	// Set a known time for predictable timestamps in logs, or use regex for timestamp matching
	mockLogger := zerolog.New(&logBuf).With().Timestamp().Logger()

	// Mock Observability struct
	mockObs := &observability.Observability{
		Logger: mockLogger,
		Tracer: oteltrace.NewNoopTracerProvider().Tracer("noop-tracer"), // Noop for this test
		// Meter can also be noop if not testing specific metrics instrumentations here
	}
	mockSecMetrics := new(MockSecurityMetrics)

	app := newTestApp()
	// Apply prerequisite middlewares to populate context correctly
	app.Use(CorrelationIDMiddleware()) // Sets up correlation_id in Locals and X-Correlation-ID header
	app.Use(TenantContextMiddleware())   // Sets up tenant_id in Locals if X-Tenant-ID header is present

	// Apply the middleware to test
	app.Use(ObservabilityMiddleware(mockObs, mockSecMetrics))

	// Dummy handler that also puts a span in context for trace_id logging
	app.Get("/logtest_fiber", func(c *fiber.Ctx) error {
		// Simulate a trace by putting a span in context
		tp := sdktrace.NewTracerProvider() // Can be a noop or test provider
		ctx, span := tp.Tracer("dummy-tracer").Start(c.UserContext(), "dummy-span-for-log")
		defer span.End()
		c.SetUserContext(ctx)
		return c.Status(fiber.StatusOK).SendString("logged_fiber")
	})

	// Mock expectations for SecurityMetrics
	mockSecMetrics.On("RecordTenantOperation", mock.AnythingOfType("*context.valueCtx"), "log-tenant-id-fiber", "GET", "success").Return()

	// Perform request
	req := httptest.NewRequest("GET", "/logtest_fiber", nil)
	req.Header.Set(CorrelationIDHeader, "log-corr-id-fiber")
	req.Header.Set(TenantIDHeader, "log-tenant-id-fiber")
	req.Header.Set("User-Agent", "log-test-agent-fiber")
	// Fiber's c.IP() might use X-Forwarded-For or similar, or fallback to RemoteAddr
	// For httptest, RemoteAddr is usually "192.0.2.1:1234" or similar.
	// req.RemoteAddr = "10.0.0.1:12345" // This is not directly used by Fiber's c.IP() in test like this.

	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Assertions
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	mockSecMetrics.AssertExpectations(t)

	// Assert log output
	logOutput := logBuf.String()
	t.Log("Log output (Fiber):", logOutput)

	var logEntry map[string]interface{}
	err = json.Unmarshal([]byte(logOutput), &logEntry)
	require.NoError(t, err, "Log output should be valid JSON")

	assert.Equal(t, "info", logEntry["level"])
	assert.Equal(t, "HTTP Request", logEntry["message"])
	assert.Equal(t, "GET", logEntry["method"])
	assert.Equal(t, "/logtest_fiber", logEntry["path"])
	assert.Equal(t, float64(fiber.StatusOK), logEntry["status"]) // JSON numbers are float64
	assert.NotEmpty(t, logEntry["latency"], "Latency should be present") // Check for presence
	assert.NotEmpty(t, logEntry["client_ip"], "Client IP should be present") // Fiber usually populates this
	assert.Equal(t, "log-test-agent-fiber", logEntry["user_agent"])
	assert.Equal(t, "log-tenant-id-fiber", logEntry["tenant_id"])
	assert.Equal(t, "log-corr-id-fiber", logEntry["correlation_id"])
	assert.NotEmpty(t, logEntry["trace_id"], "TraceID should be in logs")
	assert.NotEqual(t, oteltrace.TraceID{}.String(), logEntry["trace_id"], "TraceID should not be empty/default")
}
