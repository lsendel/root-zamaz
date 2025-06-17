// Package middleware provides HTTP middleware functions for the MVP Zero Trust Auth system.
// It includes observability, security, and request processing middleware that integrates
// with the Fiber web framework.
//
// The package provides:
//   - Request/response observability with structured logging and metrics
//   - Distributed tracing integration with automatic span creation
//   - Correlation ID handling for request tracing across services
//   - Tenant context extraction and propagation
//   - Security metrics collection for authentication and authorization events
//
// Example usage:
//
//	app := fiber.New()
//
//	// Add observability middleware
//	app.Use(middleware.ObservabilityMiddleware(obs, securityMetrics))
//
//	// Add correlation ID middleware
//	app.Use(middleware.CorrelationIDMiddleware())
//
//	// Add tenant context middleware
//	app.Use(middleware.TenantMiddleware())
package middleware

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"mvp.local/pkg/observability"
)

const (
	// CorrelationIDHeader is the HTTP header name for request correlation IDs
	CorrelationIDHeader = "X-Correlation-ID"

	// TenantIDHeader is the HTTP header name for tenant identification
	TenantIDHeader = "X-Tenant-ID"
)

// ObservabilityMiddleware provides comprehensive request/response observability.
// It instruments HTTP requests with structured logging, distributed tracing,
// and metrics collection for monitoring and debugging purposes.
//
// The middleware performs the following operations:
//   - Measures request latency and records metrics
//   - Extracts correlation IDs and tenant context from headers/locals
//   - Creates structured log entries with request/response details
//   - Integrates with distributed tracing to capture trace/span IDs
//   - Records security-related metrics for authentication events
//
// Parameters:
//
//	obs - Observability instance for logging and tracing
//	metrics - SecurityMetrics instance for recording security events
//
// Returns:
//
//	A Fiber middleware handler function
//
// Example:
//
//	app.Use(ObservabilityMiddleware(observability, securityMetrics))
//
// The middleware automatically captures:
//   - HTTP method, path, status code, and response time
//   - Correlation ID from headers or generates one if missing
//   - Tenant ID from headers for multi-tenant applications
//   - Trace ID from OpenTelemetry span context
//   - User agent and other relevant request metadata
//
// All request data is logged in structured JSON format for easy parsing
// and analysis by log aggregation systems.
func ObservabilityMiddleware(obs *observability.Observability, metrics *observability.SecurityMetrics) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		// Call Next to execute subsequent handlers and final route handler
		err := c.Next()

		latency := time.Since(start)

		// Extract correlation ID and tenant context from c.Locals
		correlationIDInterface := c.Locals("correlation_id")
		tenantIDInterface := c.Locals("tenant_id")

		var correlationID, tenantID, traceID string

		if correlationIDInterface != nil {
			correlationID = fmt.Sprintf("%v", correlationIDInterface)
		}

		if tenantIDInterface != nil {
			tenantID = fmt.Sprintf("%v", tenantIDInterface)
		}

		// Get trace ID from span in UserContext
		if span := trace.SpanFromContext(c.UserContext()); span.SpanContext().IsValid() {
			traceID = span.SpanContext().TraceID().String()
		}

		// Structured logging
		logger := obs.Logger
		if correlationID != "" {
			logger = obs.WithCorrelationID(correlationID)
		}

		// Log event
		logEvent := logger.Info()
		if err != nil { // If an error occurred in downstream handlers
			logEvent = logger.Error().Err(err)
		}

		logEvent.
			Str("method", c.Method()).
			Str("path", c.Path()).
			Int("status", c.Response().StatusCode()).
			Dur("latency", latency).
			Str("client_ip", c.IP()).
			Str("user_agent", c.Get("User-Agent")). // Get User-Agent header
			Str("tenant_id", tenantID).             // Ensure tenantID is string
			Str("trace_id", traceID).
			Msg("HTTP Request")

		// Record metrics
		if tenantID != "" && metrics != nil {
			metricStatus := "success"
			if c.Response().StatusCode() >= 400 {
				metricStatus = "error"
			}
			if err != nil && c.Response().StatusCode() < 400 { // If error bubbles up but status is not >400
				metricStatus = "error" // Still mark as error
			}

			metrics.RecordTenantOperation(
				c.UserContext(), // Use UserContext for tracing
				tenantID,
				c.Method(),
				metricStatus,
			)
		}
		return err // Return the error so Fiber can handle it
	}
}

func CorrelationIDMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		correlationID := c.Get(CorrelationIDHeader)
		if correlationID == "" {
			correlationID = uuid.New().String()
		}

		c.Locals("correlation_id", correlationID)
		c.Set(CorrelationIDHeader, correlationID) // Set for response header
		return c.Next()
	}
}

func TracingMiddleware(tracer trace.Tracer) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userCtx := c.UserContext()                   // Get context from Fiber
		ctx, span := tracer.Start(userCtx, c.Path(), // Use c.Path() for span name, or c.Route().Path for matched route path
			trace.WithAttributes(
				attribute.String("http.method", c.Method()),
				attribute.String("http.url", c.OriginalURL()),
				attribute.String("http.scheme", string(c.Request().URI().Scheme())),
				attribute.String("http.host", string(c.Request().URI().Host())),
				attribute.String("http.user_agent", c.Get("User-Agent")),
				attribute.String("http.target", c.Path()), // Or c.OriginalURL()
			),
		)
		defer span.End()

		c.SetUserContext(ctx) // Set the new context with the span back to Fiber context

		err := c.Next() // Execute subsequent handlers

		// After handler execution, record response attributes
		span.SetAttributes(
			attribute.Int("http.status_code", c.Response().StatusCode()),
			attribute.Int("http.response_size", len(c.Response().Body())),
		)

		if err != nil { // If an error was returned by c.Next()
			span.RecordError(err)
			// Ensure error status is set if not already a >400 status by a previous handler
			if c.Response().StatusCode() < 400 {
				span.SetAttributes(attribute.Bool("error", true))
			}
		}
		// Also set error attribute if status code implies error, even if err == nil
		if c.Response().StatusCode() >= 400 {
			span.SetAttributes(attribute.Bool("error", true))
		}

		return err // Propagate the error
	}
}

func TenantContextMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		tenantID := c.Get(TenantIDHeader)
		if tenantID != "" {
			c.Locals("tenant_id", tenantID)

			// Add tenant ID to tracing span
			if span := trace.SpanFromContext(c.UserContext()); span.SpanContext().IsValid() {
				span.SetAttributes(attribute.String("tenant.id", tenantID))
			}
		}
		return c.Next()
	}
}
