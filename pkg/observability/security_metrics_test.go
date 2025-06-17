package observability

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/metric/metricdata/metricdatatest"
)

func TestNewSecurityMetrics(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	meter := provider.Meter("test-meter")

	sm, err := NewSecurityMetrics(meter)
	require.NoError(t, err)
	require.NotNil(t, sm)

	assert.NotNil(t, sm.authzDecisions)
	assert.NotNil(t, sm.certificateEvents)
	assert.NotNil(t, sm.tenantOperations)
	assert.NotNil(t, sm.policyEvaluations)
	assert.NotNil(t, sm.mtlsConnections)
	assert.NotNil(t, sm.securityViolations)
}

func TestSecurityMetrics_RecordAuthzDecision(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	meter := provider.Meter("test-meter")
	sm, _ := NewSecurityMetrics(meter)

	ctx := context.Background()
	tenantID := "tenant-1"
	service := "service-A"
	action := "read"
	decision := "allow"

	sm.RecordAuthzDecision(ctx, tenantID, service, action, decision)

	var rm metricdata.ResourceMetrics
	err := reader.Collect(ctx, &rm)
	require.NoError(t, err)

	require.Len(t, rm.ScopeMetrics, 1, "Expected one scope metric")
	require.Len(t, rm.ScopeMetrics[0].Metrics, 1, "Expected one metric")

	m := rm.ScopeMetrics[0].Metrics[0]
	assert.Equal(t, "authz_decisions_total", m.Name)
	assert.Equal(t, "Total number of authorization decisions", m.Description)

	sum, ok := m.Data.(metricdata.Sum[int64])
	require.True(t, ok, "Metric data should be Sum[int64]")
	require.Len(t, sum.DataPoints, 1)
	dp := sum.DataPoints[0]
	assert.Equal(t, int64(1), dp.Value)

	expectedAttrs := attribute.NewSet(
		attribute.String("tenant_id", tenantID),
		attribute.String("service", service),
		attribute.String("action", action),
		attribute.String("decision", decision),
	)
	metricdatatest.AssertAttributesEqual(t, expectedAttrs, dp.Attributes)
}

func TestSecurityMetrics_RecordCertificateEvent(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	meter := provider.Meter("test-meter")
	sm, _ := NewSecurityMetrics(meter)

	ctx := context.Background()
	tenantID := "tenant-2"
	service := "service-B"
	event := "issued"

	sm.RecordCertificateEvent(ctx, tenantID, service, event)

	var rm metricdata.ResourceMetrics
	err := reader.Collect(ctx, &rm)
	require.NoError(t, err)

	m := rm.ScopeMetrics[0].Metrics[0]
	assert.Equal(t, "certificate_events_total", m.Name)
	sum, _ := m.Data.(metricdata.Sum[int64])
	dp := sum.DataPoints[0]
	assert.Equal(t, int64(1), dp.Value)

	expectedAttrs := attribute.NewSet(
		attribute.String("tenant_id", tenantID),
		attribute.String("service", service),
		attribute.String("event", event),
	)
	metricdatatest.AssertAttributesEqual(t, expectedAttrs, dp.Attributes)
}

func TestSecurityMetrics_RecordTenantOperation(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	meter := provider.Meter("test-meter")
	sm, _ := NewSecurityMetrics(meter)

	ctx := context.Background()
	tenantID := "tenant-3"
	operation := "create_user"
	status := "success"

	sm.RecordTenantOperation(ctx, tenantID, operation, status)

	var rm metricdata.ResourceMetrics
	err := reader.Collect(ctx, &rm)
	require.NoError(t, err)

	m := rm.ScopeMetrics[0].Metrics[0]
	assert.Equal(t, "tenant_operations_total", m.Name)
	sum, _ := m.Data.(metricdata.Sum[int64])
	dp := sum.DataPoints[0]
	assert.Equal(t, int64(1), dp.Value)

	expectedAttrs := attribute.NewSet(
		attribute.String("tenant_id", tenantID),
		attribute.String("operation", operation),
		attribute.String("status", status),
	)
	metricdatatest.AssertAttributesEqual(t, expectedAttrs, dp.Attributes)
}

func TestSecurityMetrics_RecordPolicyEvaluation(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	meter := provider.Meter("test-meter")
	sm, _ := NewSecurityMetrics(meter)

	ctx := context.Background()
	tenantID := "tenant-4"
	policyType := "access_policy"
	duration := 150 * time.Millisecond

	sm.RecordPolicyEvaluation(ctx, tenantID, policyType, duration)

	var rm metricdata.ResourceMetrics
	err := reader.Collect(ctx, &rm)
	require.NoError(t, err)

	m := rm.ScopeMetrics[0].Metrics[0]
	assert.Equal(t, "policy_evaluation_duration_seconds", m.Name)

	hist, ok := m.Data.(metricdata.Histogram[float64])
	require.True(t, ok, "Metric data should be Histogram[float64]")
	require.Len(t, hist.DataPoints, 1)
	dp := hist.DataPoints[0]

	assert.Equal(t, duration.Seconds(), dp.Sum) // For a single recording, sum is the value
	assert.Equal(t, uint64(1), dp.Count)
	// Could also check bounds if specific buckets are defined, but default explicit bounds are fine for this test.

	expectedAttrs := attribute.NewSet(
		attribute.String("tenant_id", tenantID),
		attribute.String("policy_type", policyType),
	)
	metricdatatest.AssertAttributesEqual(t, expectedAttrs, dp.Attributes)
}

func TestSecurityMetrics_RecordMTLSConnection(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	meter := provider.Meter("test-meter")
	sm, _ := NewSecurityMetrics(meter)

	ctx := context.Background()
	tenantID := "tenant-5"
	service := "service-C"
	status := "success"

	sm.RecordMTLSConnection(ctx, tenantID, service, status)

	var rm metricdata.ResourceMetrics
	err := reader.Collect(ctx, &rm)
	require.NoError(t, err)

	m := rm.ScopeMetrics[0].Metrics[0]
	assert.Equal(t, "mtls_connections_total", m.Name)
	sum, _ := m.Data.(metricdata.Sum[int64])
	dp := sum.DataPoints[0]
	assert.Equal(t, int64(1), dp.Value)

	expectedAttrs := attribute.NewSet(
		attribute.String("tenant_id", tenantID),
		attribute.String("service", service),
		attribute.String("status", status),
	)
	metricdatatest.AssertAttributesEqual(t, expectedAttrs, dp.Attributes)
}

func TestSecurityMetrics_RecordSecurityViolation(t *testing.T) {
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	meter := provider.Meter("test-meter")
	sm, _ := NewSecurityMetrics(meter)

	ctx := context.Background()
	tenantID := "tenant-6"
	violationType := "unauthorized_access"
	severity := "high"

	sm.RecordSecurityViolation(ctx, tenantID, violationType, severity)

	var rm metricdata.ResourceMetrics
	err := reader.Collect(ctx, &rm)
	require.NoError(t, err)

	m := rm.ScopeMetrics[0].Metrics[0]
	assert.Equal(t, "security_violations_total", m.Name)
	sum, _ := m.Data.(metricdata.Sum[int64])
	dp := sum.DataPoints[0]
	assert.Equal(t, int64(1), dp.Value)

	expectedAttrs := attribute.NewSet(
		attribute.String("tenant_id", tenantID),
		attribute.String("violation_type", violationType),
		attribute.String("severity", severity),
	)
	metricdatatest.AssertAttributesEqual(t, expectedAttrs, dp.Attributes)
}
