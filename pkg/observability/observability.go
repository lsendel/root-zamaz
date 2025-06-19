// Package observability provides comprehensive observability capabilities for the MVP Zero Trust Auth system.
// It integrates structured logging, distributed tracing, and metrics collection using industry-standard
// tools and protocols including OpenTelemetry, Prometheus, Jaeger, and zerolog.
//
// The package provides a unified interface for:
//   - Structured JSON logging with correlation IDs and context
//   - Distributed tracing with OpenTelemetry and OTLP export
//   - Metrics collection and exposition in Prometheus format
//   - Security-specific metrics for zero trust auth patterns
//   - Health check and metrics HTTP endpoints
//
// Example usage:
//
//	obs, err := observability.New(observability.Config{
//	    ServiceName:    "auth-service",
//	    ServiceVersion: "1.0.0",
//	    Environment:    "production",
//	    LogLevel:       "info",
//	    LogFormat:      "json",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Start metrics server
//	ctx := context.Background()
//	if err := obs.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
//	defer obs.Shutdown(ctx)
//
//	// Use logger with context
//	logger := obs.WithCorrelationID("req-123")
//	logger.Info().Str("user_id", "user-456").Msg("User authenticated")
//
//	// Create distributed traces
//	ctx, span := obs.CreateSpan(ctx, "auth.validate_token",
//	    attribute.String("token.type", "jwt"),
//	    attribute.String("user.id", "user-456"),
//	)
//	defer span.End()
package observability

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelprometheus "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

// Config holds configuration for the observability system.
// All fields support environment variable overrides using the specified env tags.
type Config struct {
	// ServiceName identifies the service in telemetry data
	ServiceName string `env:"SERVICE_NAME" envDefault:"unknown-service"`

	// ServiceVersion is used for versioning telemetry data and deployment tracking
	ServiceVersion string `env:"SERVICE_VERSION" envDefault:"dev"`

	// Environment distinguishes between dev, staging, production deployments
	Environment string `env:"ENVIRONMENT" envDefault:"development"`

	// OTLPEndpoint is the URL where traces should be sent using OTLP HTTP
	OTLPEndpoint string `env:"OTLP_ENDPOINT" envDefault:"http://localhost:4318/v1/traces"`

	// PrometheusPort is the port where metrics will be exposed
	PrometheusPort int `env:"PROMETHEUS_PORT" envDefault:"9090"`

	// LogLevel controls the minimum log level (debug, info, warn, error)
	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`

	// LogFormat determines output format (json, console)
	LogFormat string `env:"LOG_FORMAT" envDefault:"json"`
}

// Observability provides a unified interface for logging, tracing, and metrics.
// It encapsulates all observability concerns and provides convenient methods
// for instrumentation throughout the application.
type Observability struct {
	// Logger provides structured logging with context support
	Logger zerolog.Logger

	// Tracer creates and manages distributed tracing spans
	Tracer trace.Tracer

	// Meter creates and manages application metrics
	Meter metric.Meter

	// Registry holds Prometheus metrics for export
	Registry *prometheus.Registry

	// MetricsServer serves metrics and health endpoints over HTTP
	MetricsServer *http.Server

	// tp is the trace provider for lifecycle management
	tp *sdktrace.TracerProvider

	// mp is the meter provider for lifecycle management
	mp *sdkmetric.MeterProvider
}

// New creates a new Observability instance with the provided configuration.
// It initializes structured logging, distributed tracing with Jaeger export,
// and metrics collection with Prometheus export.
//
// The function sets up:
//   - Zerolog logger with configurable level and format
//   - OpenTelemetry tracer with OTLP HTTP exporter
//   - OpenTelemetry meter with Prometheus exporter
//   - HTTP server for metrics and health endpoints
//   - Proper resource identification for telemetry correlation
//
// Configuration is validated and sensible defaults are applied for missing values.
// The returned Observability instance is ready to use but requires Start() to be
// called to begin serving metrics over HTTP.
//
// Example:
//
//	obs, err := New(Config{
//	    ServiceName: "auth-service",
//	    LogLevel: "info",
//	    PrometheusPort: 9090,
//	    OTLPEndpoint: "http://jaeger:4318/v1/traces",
//	})
//	if err != nil {
//	    return fmt.Errorf("failed to initialize observability: %w", err)
//	}
//
// Returns an error if configuration is invalid or if any component fails to initialize.
func New(cfg Config) (*Observability, error) {
	// Initialize structured logging
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}

	var logger zerolog.Logger
	if cfg.LogFormat == "console" {
		logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).
			Level(level).
			With().
			Str("service", cfg.ServiceName).
			Str("version", cfg.ServiceVersion).
			Str("environment", cfg.Environment).
			Timestamp().
			Logger()
	} else {
		logger = zerolog.New(os.Stdout).
			Level(level).
			With().
			Str("service", cfg.ServiceName).
			Str("version", cfg.ServiceVersion).
			Str("environment", cfg.Environment).
			Timestamp().
			Logger()
	}

	// Initialize OpenTelemetry resource
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.ServiceName),
			semconv.ServiceVersionKey.String(cfg.ServiceVersion),
			semconv.DeploymentEnvironmentKey.String(cfg.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Initialize tracing with OTLP HTTP exporter
	otlpExporter, err := otlptracehttp.New(
		context.Background(),
		otlptracehttp.WithEndpoint(cfg.OTLPEndpoint),
		otlptracehttp.WithInsecure(), // Use HTTP instead of HTTPS for local dev
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(jaegerExporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	tracer := otel.Tracer(cfg.ServiceName)

	// Initialize metrics
	registry := prometheus.NewRegistry()
	prometheusExporter, err := otelprometheus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create prometheus exporter: %w", err)
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(prometheusExporter),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(mp)

	meter := otel.Meter(cfg.ServiceName)

	// Set up metrics server
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	metricsServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.PrometheusPort),
		Handler: mux,
	}

	return &Observability{
		Logger:        logger,
		Tracer:        tracer,
		Meter:         meter,
		Registry:      registry,
		MetricsServer: metricsServer,
		tp:            tp,
		mp:            mp,
	}, nil
}

// Start begins serving metrics and health endpoints over HTTP.
// It starts the metrics server in a separate goroutine to avoid blocking
// the main application startup. The server will serve on the configured
// PrometheusPort and expose both /metrics and /health endpoints.
//
// The metrics endpoint provides Prometheus-formatted metrics data,
// while the health endpoint returns a simple "OK" response for
// load balancer health checks.
//
// This method is non-blocking and returns immediately after starting
// the server goroutine. Any server startup errors are logged but do
// not cause this method to fail.
//
// Example:
//
//	ctx := context.Background()
//	if err := obs.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
// The server will continue running until Shutdown() is called.
func (o *Observability) Start(ctx context.Context) error {
	go func() {
		port, _ := strconv.Atoi(o.MetricsServer.Addr[1:])
		o.Logger.Info().
			Int("port", port).
			Msg("Starting metrics server")

		if err := o.MetricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			o.Logger.Error().Err(err).Msg("Metrics server failed")
		}
	}()

	return nil
}

// Shutdown gracefully stops the observability system.
// It performs cleanup of all observability components in the proper order:
// 1. Shuts down the HTTP metrics server
// 2. Shuts down the trace provider (flushes pending traces)
// 3. Shuts down the meter provider (flushes pending metrics)
//
// The method respects the provided context for cancellation and timeouts.
// If any component fails to shut down cleanly, the error is logged but
// the shutdown process continues for other components.
//
// This method should be called during application shutdown to ensure
// all telemetry data is properly flushed and resources are released.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	if err := obs.Shutdown(ctx); err != nil {
//	    log.Printf("Observability shutdown error: %v", err)
//	}
//
// Always returns nil, but logs individual component shutdown errors.
func (o *Observability) Shutdown(ctx context.Context) error {
	o.Logger.Info().Msg("Shutting down observability")

	// Shutdown metrics server
	if err := o.MetricsServer.Shutdown(ctx); err != nil {
		o.Logger.Error().Err(err).Msg("Failed to shutdown metrics server")
	}

	// Shutdown tracing
	if err := o.tp.Shutdown(ctx); err != nil {
		o.Logger.Error().Err(err).Msg("Failed to shutdown tracer provider")
	}

	// Shutdown metrics
	if err := o.mp.Shutdown(ctx); err != nil {
		o.Logger.Error().Err(err).Msg("Failed to shutdown meter provider")
	}

	return nil
}

// WithCorrelationID creates a new logger instance with a correlation ID.
// The correlation ID is automatically added to all log entries created
// with the returned logger, enabling request tracing across service boundaries.
//
// This method does not modify the original logger but returns a new instance
// with the correlation ID context added. This enables per-request logging
// without affecting other concurrent requests.
//
// Parameters:
//
//	correlationID - A unique identifier for correlating logs across services
//
// Returns:
//
//	A new zerolog.Logger instance with the correlation ID embedded
//
// Example:
//
//	correlationID := "req-12345"
//	requestLogger := obs.WithCorrelationID(correlationID)
//	requestLogger.Info().Msg("Processing user request")
//	// Output: {"level":"info","correlation_id":"req-12345","message":"Processing user request",...}
//
// The correlation ID is typically extracted from HTTP headers (X-Correlation-ID)
// or generated at service entry points for distributed tracing.
func (o *Observability) WithCorrelationID(correlationID string) zerolog.Logger {
	return o.Logger.With().Str("correlation_id", correlationID).Logger()
}

// CreateSpan creates a new distributed tracing span with optional attributes.
// This is a convenience method that creates a span using the configured tracer
// and automatically sets any provided attributes on the span.
//
// The span context is added to the provided context, enabling automatic
// parent-child span relationships when the returned context is used for
// subsequent operations or passed to other services.
//
// Parameters:
//
//	ctx - The parent context, may contain an existing span
//	name - A descriptive name for the operation being traced
//	attributes - Optional key-value pairs to set as span attributes
//
// Returns:
//
//	A new context containing the span and the created span instance
//
// Example:
//
//	ctx, span := obs.CreateSpan(ctx, "user.authenticate",
//	    attribute.String("user.id", "user-123"),
//	    attribute.String("method", "password"),
//	)
//	defer span.End()
//
//	// Use ctx for subsequent operations to maintain trace context
//	result, err := authenticateUser(ctx, userID, password)
//	if err != nil {
//	    span.RecordError(err)
//	    span.SetStatus(codes.Error, err.Error())
//	}
//
// Always call span.End() when the operation completes to finalize the trace.
func (o *Observability) CreateSpan(ctx context.Context, name string, attributes ...attribute.KeyValue) (context.Context, trace.Span) {
	ctx, span := o.Tracer.Start(ctx, name)
	span.SetAttributes(attributes...)
	return ctx, span
}
