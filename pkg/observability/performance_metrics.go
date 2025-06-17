// Package observability provides performance metrics for the MVP Zero Trust Auth system.
// Performance metrics focus on system performance, resource utilization, and operational health.
package observability

import (
	"context"
	"runtime"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// PerformanceMetrics tracks system performance and resource utilization
type PerformanceMetrics struct {
	// HTTP performance metrics
	httpRequestDuration   metric.Float64Histogram
	httpRequestSize       metric.Int64Histogram
	httpResponseSize      metric.Int64Histogram
	httpActiveConnections metric.Int64Gauge

	// Database performance metrics
	dbQueryDuration metric.Float64Histogram
	dbConnections   metric.Int64Gauge
	dbTransactions  metric.Int64Counter
	dbErrors        metric.Int64Counter

	// Cache performance metrics
	cacheHits    metric.Int64Counter
	cacheMisses  metric.Int64Counter
	cacheLatency metric.Float64Histogram
	cacheSize    metric.Int64Gauge

	// System resource metrics
	cpuUsage    metric.Float64Gauge
	memoryUsage metric.Int64Gauge
	goroutines  metric.Int64Gauge
	gcDuration  metric.Float64Histogram

	// External service metrics
	externalServiceCalls   metric.Int64Counter
	externalServiceLatency metric.Float64Histogram
	externalServiceErrors  metric.Int64Counter

	// Queue/messaging metrics
	messageQueueSize      metric.Int64Gauge
	messageProcessingTime metric.Float64Histogram
	messageErrors         metric.Int64Counter
}

// NewPerformanceMetrics creates a new PerformanceMetrics instance
func NewPerformanceMetrics(meter metric.Meter) (*PerformanceMetrics, error) {
	httpRequestDuration, err := meter.Float64Histogram(
		"http_request_duration_seconds",
		metric.WithDescription("HTTP request duration"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	httpRequestSize, err := meter.Int64Histogram(
		"http_request_size_bytes",
		metric.WithDescription("HTTP request size in bytes"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return nil, err
	}

	httpResponseSize, err := meter.Int64Histogram(
		"http_response_size_bytes",
		metric.WithDescription("HTTP response size in bytes"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return nil, err
	}

	httpActiveConnections, err := meter.Int64Gauge(
		"http_active_connections",
		metric.WithDescription("Number of active HTTP connections"),
	)
	if err != nil {
		return nil, err
	}

	dbQueryDuration, err := meter.Float64Histogram(
		"db_query_duration_seconds",
		metric.WithDescription("Database query duration"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	dbConnections, err := meter.Int64Gauge(
		"db_connections_active",
		metric.WithDescription("Number of active database connections"),
	)
	if err != nil {
		return nil, err
	}

	dbTransactions, err := meter.Int64Counter(
		"db_transactions_total",
		metric.WithDescription("Total number of database transactions"),
	)
	if err != nil {
		return nil, err
	}

	dbErrors, err := meter.Int64Counter(
		"db_errors_total",
		metric.WithDescription("Total number of database errors"),
	)
	if err != nil {
		return nil, err
	}

	cacheHits, err := meter.Int64Counter(
		"cache_hits_total",
		metric.WithDescription("Total number of cache hits"),
	)
	if err != nil {
		return nil, err
	}

	cacheMisses, err := meter.Int64Counter(
		"cache_misses_total",
		metric.WithDescription("Total number of cache misses"),
	)
	if err != nil {
		return nil, err
	}

	cacheLatency, err := meter.Float64Histogram(
		"cache_operation_duration_seconds",
		metric.WithDescription("Cache operation latency"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	cacheSize, err := meter.Int64Gauge(
		"cache_size_bytes",
		metric.WithDescription("Current cache size in bytes"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return nil, err
	}

	cpuUsage, err := meter.Float64Gauge(
		"system_cpu_usage_percent",
		metric.WithDescription("System CPU usage percentage"),
	)
	if err != nil {
		return nil, err
	}

	memoryUsage, err := meter.Int64Gauge(
		"system_memory_usage_bytes",
		metric.WithDescription("System memory usage in bytes"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return nil, err
	}

	goroutines, err := meter.Int64Gauge(
		"system_goroutines_active",
		metric.WithDescription("Number of active goroutines"),
	)
	if err != nil {
		return nil, err
	}

	gcDuration, err := meter.Float64Histogram(
		"system_gc_duration_seconds",
		metric.WithDescription("Garbage collection duration"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	externalServiceCalls, err := meter.Int64Counter(
		"external_service_calls_total",
		metric.WithDescription("Total number of external service calls"),
	)
	if err != nil {
		return nil, err
	}

	externalServiceLatency, err := meter.Float64Histogram(
		"external_service_latency_seconds",
		metric.WithDescription("External service call latency"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	externalServiceErrors, err := meter.Int64Counter(
		"external_service_errors_total",
		metric.WithDescription("Total number of external service errors"),
	)
	if err != nil {
		return nil, err
	}

	messageQueueSize, err := meter.Int64Gauge(
		"message_queue_size",
		metric.WithDescription("Current message queue size"),
	)
	if err != nil {
		return nil, err
	}

	messageProcessingTime, err := meter.Float64Histogram(
		"message_processing_duration_seconds",
		metric.WithDescription("Message processing duration"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	messageErrors, err := meter.Int64Counter(
		"message_errors_total",
		metric.WithDescription("Total number of message processing errors"),
	)
	if err != nil {
		return nil, err
	}

	return &PerformanceMetrics{
		httpRequestDuration:    httpRequestDuration,
		httpRequestSize:        httpRequestSize,
		httpResponseSize:       httpResponseSize,
		httpActiveConnections:  httpActiveConnections,
		dbQueryDuration:        dbQueryDuration,
		dbConnections:          dbConnections,
		dbTransactions:         dbTransactions,
		dbErrors:               dbErrors,
		cacheHits:              cacheHits,
		cacheMisses:            cacheMisses,
		cacheLatency:           cacheLatency,
		cacheSize:              cacheSize,
		cpuUsage:               cpuUsage,
		memoryUsage:            memoryUsage,
		goroutines:             goroutines,
		gcDuration:             gcDuration,
		externalServiceCalls:   externalServiceCalls,
		externalServiceLatency: externalServiceLatency,
		externalServiceErrors:  externalServiceErrors,
		messageQueueSize:       messageQueueSize,
		messageProcessingTime:  messageProcessingTime,
		messageErrors:          messageErrors,
	}, nil
}

// RecordHTTPRequest records HTTP request metrics
func (pm *PerformanceMetrics) RecordHTTPRequest(ctx context.Context, method, path, statusCode string, duration time.Duration, requestSize, responseSize int64) {
	attributes := []attribute.KeyValue{
		attribute.String("method", method),
		attribute.String("path", path),
		attribute.String("status_code", statusCode),
	}

	pm.httpRequestDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attributes...))
	pm.httpRequestSize.Record(ctx, requestSize, metric.WithAttributes(attributes...))
	pm.httpResponseSize.Record(ctx, responseSize, metric.WithAttributes(attributes...))
}

// SetHTTPActiveConnections sets the current number of active HTTP connections
func (pm *PerformanceMetrics) SetHTTPActiveConnections(ctx context.Context, count int64) {
	pm.httpActiveConnections.Record(ctx, count)
}

// RecordDBQuery records database query metrics
func (pm *PerformanceMetrics) RecordDBQuery(ctx context.Context, operation, table string, duration time.Duration, success bool) {
	attributes := []attribute.KeyValue{
		attribute.String("operation", operation),
		attribute.String("table", table),
		attribute.Bool("success", success),
	}

	pm.dbQueryDuration.Record(ctx, duration.Seconds(), metric.WithAttributes(attributes...))
	pm.dbTransactions.Add(ctx, 1, metric.WithAttributes(attributes...))

	if !success {
		pm.dbErrors.Add(ctx, 1, metric.WithAttributes(attributes...))
	}
}

// SetDBConnections sets the current number of active database connections
func (pm *PerformanceMetrics) SetDBConnections(ctx context.Context, active, idle int64) {
	pm.dbConnections.Record(ctx, active,
		metric.WithAttributes(attribute.String("state", "active")),
	)
	pm.dbConnections.Record(ctx, idle,
		metric.WithAttributes(attribute.String("state", "idle")),
	)
}

// RecordCacheOperation records cache operation metrics
func (pm *PerformanceMetrics) RecordCacheOperation(ctx context.Context, operation string, hit bool, duration time.Duration) {
	attributes := []attribute.KeyValue{
		attribute.String("operation", operation),
	}

	if hit {
		pm.cacheHits.Add(ctx, 1, metric.WithAttributes(attributes...))
	} else {
		pm.cacheMisses.Add(ctx, 1, metric.WithAttributes(attributes...))
	}

	pm.cacheLatency.Record(ctx, duration.Seconds(), metric.WithAttributes(attributes...))
}

// SetCacheSize sets the current cache size
func (pm *PerformanceMetrics) SetCacheSize(ctx context.Context, sizeBytes int64) {
	pm.cacheSize.Record(ctx, sizeBytes)
}

// RecordSystemMetrics records current system performance metrics
func (pm *PerformanceMetrics) RecordSystemMetrics(ctx context.Context) {
	// Get runtime memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Record memory usage
	pm.memoryUsage.Record(ctx, int64(memStats.Alloc))

	// Record active goroutines
	pm.goroutines.Record(ctx, int64(runtime.NumGoroutine()))

	// Record GC pause time
	if memStats.NumGC > 0 {
		lastGCPause := time.Duration(memStats.PauseNs[(memStats.NumGC+255)%256])
		pm.gcDuration.Record(ctx, lastGCPause.Seconds())
	}
}

// SetCPUUsage sets the current CPU usage percentage
func (pm *PerformanceMetrics) SetCPUUsage(ctx context.Context, percentage float64) {
	pm.cpuUsage.Record(ctx, percentage)
}

// RecordExternalServiceCall records external service call metrics
func (pm *PerformanceMetrics) RecordExternalServiceCall(ctx context.Context, service, operation string, duration time.Duration, success bool) {
	attributes := []attribute.KeyValue{
		attribute.String("service", service),
		attribute.String("operation", operation),
		attribute.Bool("success", success),
	}

	pm.externalServiceCalls.Add(ctx, 1, metric.WithAttributes(attributes...))
	pm.externalServiceLatency.Record(ctx, duration.Seconds(), metric.WithAttributes(attributes...))

	if !success {
		pm.externalServiceErrors.Add(ctx, 1, metric.WithAttributes(attributes...))
	}
}

// SetMessageQueueSize sets the current message queue size
func (pm *PerformanceMetrics) SetMessageQueueSize(ctx context.Context, queueName string, size int64) {
	pm.messageQueueSize.Record(ctx, size,
		metric.WithAttributes(attribute.String("queue", queueName)),
	)
}

// RecordMessageProcessing records message processing metrics
func (pm *PerformanceMetrics) RecordMessageProcessing(ctx context.Context, queueName, messageType string, duration time.Duration, success bool) {
	attributes := []attribute.KeyValue{
		attribute.String("queue", queueName),
		attribute.String("message_type", messageType),
		attribute.Bool("success", success),
	}

	pm.messageProcessingTime.Record(ctx, duration.Seconds(), metric.WithAttributes(attributes...))

	if !success {
		pm.messageErrors.Add(ctx, 1, metric.WithAttributes(attributes...))
	}
}

// StartSystemMetricsCollection starts a background goroutine that periodically collects system metrics
func (pm *PerformanceMetrics) StartSystemMetricsCollection(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pm.RecordSystemMetrics(ctx)
			}
		}
	}()
}
