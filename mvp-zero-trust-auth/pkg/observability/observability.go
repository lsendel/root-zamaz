package observability

import (
    "context"
    "fmt"
    "os"
    "time"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/rs/zerolog"
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/exporters/jaeger"
    otelprometheus "go.opentelemetry.io/otel/exporters/prometheus"
    "go.opentelemetry.io/otel/metric"
    "go.opentelemetry.io/otel/propagation"
    "go.opentelemetry.io/otel/sdk/resource"
    sdkmetric "go.opentelemetry.io/otel/sdk/metric"
    sdktrace "go.opentelemetry.io/otel/sdk/trace"
    "go.opentelemetry.io/otel/semconv/v1.17.0"
    "go.opentelemetry.io/otel/trace"
    "net/http"
)

type Config struct {
    ServiceName     string `env:"SERVICE_NAME" envDefault:"unknown-service"`
    ServiceVersion  string `env:"SERVICE_VERSION" envDefault:"dev"`
    Environment     string `env:"ENVIRONMENT" envDefault:"development"`
    JaegerEndpoint  string `env:"JAEGER_ENDPOINT" envDefault:"http://localhost:14268/api/traces"`
    PrometheusPort  int    `env:"PROMETHEUS_PORT" envDefault:"9090"`
    LogLevel        string `env:"LOG_LEVEL" envDefault:"info"`
    LogFormat       string `env:"LOG_FORMAT" envDefault:"json"`
}

type Observability struct {
    Logger       zerolog.Logger
    Tracer       trace.Tracer
    Meter        metric.Meter
    Registry     *prometheus.Registry
    MetricsServer *http.Server
    tp           *sdktrace.TracerProvider
    mp           *sdkmetric.MeterProvider
}

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

    // Initialize tracing
    jaegerExporter, err := jaeger.New(
        jaeger.WithCollectorEndpoint(
            jaeger.WithEndpoint(cfg.JaegerEndpoint),
        ),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to create jaeger exporter: %w", err)
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

func (o *Observability) Start(ctx context.Context) error {
    go func() {
        o.Logger.Info().
            Int("port", o.MetricsServer.Addr[1:]). // Corrected to get port from Addr
            Msg("Starting metrics server")

        if err := o.MetricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            o.Logger.Error().Err(err).Msg("Metrics server failed")
        }
    }()

    return nil
}

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

// WithCorrelationID adds a correlation ID to the logger
func (o *Observability) WithCorrelationID(correlationID string) zerolog.Logger {
    return o.Logger.With().Str("correlation_id", correlationID).Logger()
}

// CreateSpan creates a new span with automatic attributes
func (o *Observability) CreateSpan(ctx context.Context, name string, attributes ...attribute.KeyValue) (context.Context, trace.Span) {
    ctx, span := o.Tracer.Start(ctx, name)
    span.SetAttributes(attributes...)
    return ctx, span
}
