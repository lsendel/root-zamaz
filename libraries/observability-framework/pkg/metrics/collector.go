// Package metrics provides universal metrics collection for observability
package metrics

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// MetricsCollector interface for collecting various metrics
type MetricsCollector interface {
	// HTTP Metrics
	IncrementCounter(name string, labels map[string]string)
	RecordHistogram(name string, value float64, labels map[string]string)
	SetGauge(name string, value float64, labels map[string]string)
	RecordDuration(name string, duration time.Duration, labels map[string]string)
	RecordHTTPRequest(method, endpoint string, statusCode int, duration time.Duration)
	
	// Error Metrics
	RecordError(errorType, component string)
	
	// Cache Metrics
	RecordCacheOperation(operation, result string)
	
	// Zero Trust Metrics
	RecordAuthAttempt(method string, success bool, trustScore int)
	RecordTrustScore(userID string, score int, factors map[string]int)
	
	// System Metrics
	GetMetrics() *Metrics
	Close() error
}

// UniversalMetricsCollector provides comprehensive metrics collection
type UniversalMetricsCollector struct {
	serviceName string
	
	// Core metrics from go-keycloak-zerotrust
	TokenValidations    int64         `json:"tokenValidations"`
	CacheHits          int64         `json:"cacheHits"`
	CacheMisses        int64         `json:"cacheMisses"`
	ErrorCount         int64         `json:"errorCount"`
	AverageLatency     time.Duration `json:"averageLatency"`
	ActiveConnections  int           `json:"activeConnections"`
	HealthStatus       string        `json:"healthStatus"`
	LastHealthCheck    time.Time     `json:"lastHealthCheck"`
	
	// Prometheus metrics
	prometheus struct {
		httpRequests      *prometheus.CounterVec
		httpDuration      *prometheus.HistogramVec
		authAttempts      *prometheus.CounterVec
		trustScores       *prometheus.GaugeVec
		cacheOperations   *prometheus.CounterVec
		errorRate         *prometheus.CounterVec
		activeConnections *prometheus.GaugeVec
		responseSize      *prometheus.HistogramVec
	}
	
	mutex sync.RWMutex
}

// Metrics represents collected metrics data
type Metrics struct {
	TokenValidations  int64         `json:"tokenValidations"`
	CacheHits        int64         `json:"cacheHits"`
	CacheMisses      int64         `json:"cacheMisses"`
	ErrorCount       int64         `json:"errorCount"`
	AverageLatency   time.Duration `json:"averageLatency"`
	ActiveConns      int           `json:"activeConnections"`
	HealthStatus     string        `json:"healthStatus"`
	LastHealthCheck  time.Time     `json:"lastHealthCheck"`
}

// CollectorConfig configures the metrics collector
type CollectorConfig struct {
	ServiceName   string
	Namespace     string
	EnableDebug   bool
	CustomLabels  map[string]string
}

// CollectorOption functional option for configuring collector
type CollectorOption func(*CollectorConfig)

// WithServiceName sets the service name
func WithServiceName(name string) CollectorOption {
	return func(c *CollectorConfig) {
		c.ServiceName = name
	}
}

// WithNamespace sets the metrics namespace
func WithNamespace(namespace string) CollectorOption {
	return func(c *CollectorConfig) {
		c.Namespace = namespace
	}
}

// WithCustomLabels adds custom labels to all metrics
func WithCustomLabels(labels map[string]string) CollectorOption {
	return func(c *CollectorConfig) {
		c.CustomLabels = labels
	}
}

// WithDebug enables debug logging
func WithDebug(enable bool) CollectorOption {
	return func(c *CollectorConfig) {
		c.EnableDebug = enable
	}
}

// NewUniversalCollector creates a new universal metrics collector
func NewUniversalCollector(opts ...CollectorOption) *UniversalMetricsCollector {
	config := &CollectorConfig{
		ServiceName: "unknown",
		Namespace:   "zerotrust",
		EnableDebug: false,
		CustomLabels: make(map[string]string),
	}
	
	for _, opt := range opts {
		opt(config)
	}
	
	collector := &UniversalMetricsCollector{
		serviceName:     config.ServiceName,
		HealthStatus:    "starting",
		LastHealthCheck: time.Now(),
	}
	
	// Initialize Prometheus metrics
	collector.initPrometheusMetrics(config)
	
	return collector
}

// initPrometheusMetrics initializes Prometheus metrics
func (u *UniversalMetricsCollector) initPrometheusMetrics(config *CollectorConfig) {
	// HTTP request metrics
	u.prometheus.httpRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: config.ServiceName,
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status_code"},
	)
	
	u.prometheus.httpDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: config.Namespace,
			Subsystem: config.ServiceName,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request duration in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)
	
	// Authentication metrics
	u.prometheus.authAttempts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: config.ServiceName,
			Name:      "auth_attempts_total",
			Help:      "Total authentication attempts",
		},
		[]string{"method", "success", "trust_level"},
	)
	
	// Trust score metrics
	u.prometheus.trustScores = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: config.Namespace,
			Subsystem: config.ServiceName,
			Name:      "trust_score",
			Help:      "Current trust score for users",
		},
		[]string{"user_id", "factor"},
	)
	
	// Cache metrics
	u.prometheus.cacheOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: config.ServiceName,
			Name:      "cache_operations_total",
			Help:      "Total cache operations",
		},
		[]string{"operation", "result"},
	)
	
	// Error metrics
	u.prometheus.errorRate = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: config.Namespace,
			Subsystem: config.ServiceName,
			Name:      "errors_total",
			Help:      "Total errors by type and component",
		},
		[]string{"error_type", "component"},
	)
	
	// Active connections
	u.prometheus.activeConnections = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: config.Namespace,
			Subsystem: config.ServiceName,
			Name:      "active_connections",
			Help:      "Number of active connections",
		},
		[]string{"service"},
	)
	
	// Response size
	u.prometheus.responseSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: config.Namespace,
			Subsystem: config.ServiceName,
			Name:      "response_size_bytes",
			Help:      "Response size in bytes",
			Buckets:   []float64{100, 1000, 10000, 100000, 1000000},
		},
		[]string{"method", "endpoint"},
	)
}

// IncrementCounter increments a counter metric
func (u *UniversalMetricsCollector) IncrementCounter(name string, labels map[string]string) {
	switch name {
	case "http_requests_total":
		u.prometheus.httpRequests.With(prometheus.Labels(labels)).Inc()
	case "auth_attempts_total":
		u.prometheus.authAttempts.With(prometheus.Labels(labels)).Inc()
	case "cache_operations_total":
		u.prometheus.cacheOperations.With(prometheus.Labels(labels)).Inc()
	case "errors_total":
		u.prometheus.errorRate.With(prometheus.Labels(labels)).Inc()
		u.mutex.Lock()
		u.ErrorCount++
		u.mutex.Unlock()
	}
}

// RecordHistogram records a histogram metric
func (u *UniversalMetricsCollector) RecordHistogram(name string, value float64, labels map[string]string) {
	switch name {
	case "http_request_duration_seconds":
		u.prometheus.httpDuration.With(prometheus.Labels(labels)).Observe(value)
	case "response_size_bytes":
		u.prometheus.responseSize.With(prometheus.Labels(labels)).Observe(value)
	}
}

// SetGauge sets a gauge metric value
func (u *UniversalMetricsCollector) SetGauge(name string, value float64, labels map[string]string) {
	switch name {
	case "trust_score":
		u.prometheus.trustScores.With(prometheus.Labels(labels)).Set(value)
	case "active_connections":
		u.prometheus.activeConnections.With(prometheus.Labels(labels)).Set(value)
		u.mutex.Lock()
		u.ActiveConnections = int(value)
		u.mutex.Unlock()
	}
}

// RecordDuration records a duration metric
func (u *UniversalMetricsCollector) RecordDuration(name string, duration time.Duration, labels map[string]string) {
	seconds := duration.Seconds()
	u.RecordHistogram(name, seconds, labels)
	
	u.mutex.Lock()
	u.AverageLatency = duration
	u.mutex.Unlock()
}

// RecordHTTPRequest records HTTP request metrics
func (u *UniversalMetricsCollector) RecordHTTPRequest(method, endpoint string, statusCode int, duration time.Duration) {
	labels := map[string]string{
		"method":      method,
		"endpoint":    endpoint,
		"status_code": string(rune(statusCode)),
	}
	
	u.IncrementCounter("http_requests_total", labels)
	
	durationLabels := map[string]string{
		"method":   method,
		"endpoint": endpoint,
	}
	u.RecordDuration("http_request_duration_seconds", duration, durationLabels)
}

// RecordError records error metrics
func (u *UniversalMetricsCollector) RecordError(errorType, component string) {
	labels := map[string]string{
		"error_type": errorType,
		"component":  component,
	}
	u.IncrementCounter("errors_total", labels)
}

// RecordCacheOperation records cache operation metrics
func (u *UniversalMetricsCollector) RecordCacheOperation(operation, result string) {
	labels := map[string]string{
		"operation": operation,
		"result":    result,
	}
	u.IncrementCounter("cache_operations_total", labels)
	
	u.mutex.Lock()
	if result == "hit" {
		u.CacheHits++
	} else {
		u.CacheMisses++
	}
	u.mutex.Unlock()
}

// RecordAuthAttempt records authentication attempt metrics
func (u *UniversalMetricsCollector) RecordAuthAttempt(method string, success bool, trustScore int) {
	successStr := "false"
	if success {
		successStr = "true"
	}
	
	var trustLevel string
	switch {
	case trustScore >= 80:
		trustLevel = "high"
	case trustScore >= 60:
		trustLevel = "medium"
	default:
		trustLevel = "low"
	}
	
	labels := map[string]string{
		"method":      method,
		"success":     successStr,
		"trust_level": trustLevel,
	}
	u.IncrementCounter("auth_attempts_total", labels)
	
	u.mutex.Lock()
	u.TokenValidations++
	u.mutex.Unlock()
}

// RecordTrustScore records trust score metrics
func (u *UniversalMetricsCollector) RecordTrustScore(userID string, score int, factors map[string]int) {
	// Overall trust score
	labels := map[string]string{
		"user_id": userID,
		"factor":  "overall",
	}
	u.SetGauge("trust_score", float64(score), labels)
	
	// Individual factor scores
	for factor, factorScore := range factors {
		factorLabels := map[string]string{
			"user_id": userID,
			"factor":  factor,
		}
		u.SetGauge("trust_score", float64(factorScore), factorLabels)
	}
}

// GetMetrics returns current metrics
func (u *UniversalMetricsCollector) GetMetrics() *Metrics {
	u.mutex.RLock()
	defer u.mutex.RUnlock()
	
	return &Metrics{
		TokenValidations: u.TokenValidations,
		CacheHits:       u.CacheHits,
		CacheMisses:     u.CacheMisses,
		ErrorCount:      u.ErrorCount,
		AverageLatency:  u.AverageLatency,
		ActiveConns:     u.ActiveConnections,
		HealthStatus:    u.HealthStatus,
		LastHealthCheck: u.LastHealthCheck,
	}
}

// UpdateHealthStatus updates the health status
func (u *UniversalMetricsCollector) UpdateHealthStatus(status string) {
	u.mutex.Lock()
	u.HealthStatus = status
	u.LastHealthCheck = time.Now()
	u.mutex.Unlock()
}

// Close cleanups resources
func (u *UniversalMetricsCollector) Close() error {
	u.mutex.Lock()
	u.HealthStatus = "shutdown"
	u.mutex.Unlock()
	return nil
}