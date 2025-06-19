package observability

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// SLAMetrics tracks high level service level indicators.
type SLAMetrics struct {
	uptimeSeconds metric.Int64Counter
	httpRequests  metric.Int64Counter
	httpErrors    metric.Int64Counter
}

// NewSLAMetrics creates SLA metrics using the provided meter.
func NewSLAMetrics(meter metric.Meter) (*SLAMetrics, error) {
	uptime, err := meter.Int64Counter(
		"service_uptime_seconds",
		metric.WithDescription("Total service uptime in seconds"),
	)
	if err != nil {
		return nil, err
	}

	requests, err := meter.Int64Counter(
		"http_requests_total",
		metric.WithDescription("Total number of HTTP requests"),
	)
	if err != nil {
		return nil, err
	}

	errors, err := meter.Int64Counter(
		"http_request_errors_total",
		metric.WithDescription("Total number of failed HTTP requests"),
	)
	if err != nil {
		return nil, err
	}

	return &SLAMetrics{
		uptimeSeconds: uptime,
		httpRequests:  requests,
		httpErrors:    errors,
	}, nil
}

// RecordHTTPRequest records a completed HTTP request.
func (sm *SLAMetrics) RecordHTTPRequest(ctx context.Context, method, path string, status int) {
	attrs := []attribute.KeyValue{
		attribute.String("method", method),
		attribute.String("path", path),
		attribute.Int("status_code", status),
	}
	sm.httpRequests.Add(ctx, 1, metric.WithAttributes(attrs...))
	if status >= 500 {
		sm.httpErrors.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// StartUptimeCollection increments uptime at the given interval.
func (sm *SLAMetrics) StartUptimeCollection(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	start := time.Now()
	go func() {
		defer ticker.Stop()
		last := start
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				delta := now.Sub(last).Seconds()
				sm.uptimeSeconds.Add(ctx, int64(delta))
				last = now
			}
		}
	}()
}
