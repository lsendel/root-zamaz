package observability

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
)

func TestNewSecurityMetrics(t *testing.T) {
	meter := otel.Meter("test-meter")
	
	sm, err := NewSecurityMetrics(meter)
	require.NoError(t, err)
	assert.NotNil(t, sm)
	
	// Verify all metrics are initialized
	assert.NotNil(t, sm.authzDecisions)
	assert.NotNil(t, sm.certificateEvents)
	assert.NotNil(t, sm.tenantOperations)
	assert.NotNil(t, sm.policyEvaluations)
	assert.NotNil(t, sm.mtlsConnections)
	assert.NotNil(t, sm.securityViolations)
}

func TestSecurityMetrics_RecordAuthzDecision(t *testing.T) {
	meter := otel.Meter("test-meter")
	sm, err := NewSecurityMetrics(meter)
	require.NoError(t, err)

	tests := []struct {
		name     string
		tenantID string
		service  string
		action   string
		decision string
	}{
		{
			name:     "allow decision",
			tenantID: "tenant-123",
			service:  "api-service",
			action:   "GET",
			decision: "allow",
		},
		{
			name:     "deny decision",
			tenantID: "tenant-456",
			service:  "admin-service",
			action:   "DELETE",
			decision: "deny",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This test verifies the method doesn't panic
			// In a real test with a metrics exporter, we'd verify the metrics were recorded
			ctx := context.Background()
			sm.RecordAuthzDecision(ctx, tt.tenantID, tt.service, tt.action, tt.decision)
		})
	}
}

func TestSecurityMetrics_RecordCertificateEvent(t *testing.T) {
	meter := otel.Meter("test-meter")
	sm, err := NewSecurityMetrics(meter)
	require.NoError(t, err)

	ctx := context.Background()
	
	// Test different event types
	events := []struct {
		tenantID string
		service  string
		event    string
	}{
		{"tenant-1", "cert-service", "issued"},
		{"tenant-2", "cert-service", "renewed"},
		{"tenant-3", "cert-service", "revoked"},
		{"tenant-4", "cert-service", "expired"},
	}
	for _, e := range events {
		sm.RecordCertificateEvent(ctx, e.tenantID, e.service, e.event)
	}
}

func TestSecurityMetrics_RecordTenantOperation(t *testing.T) {
	meter := otel.Meter("test-meter")
	sm, err := NewSecurityMetrics(meter)
	require.NoError(t, err)

	ctx := context.Background()
	
	operations := []struct {
		tenantID  string
		operation string
		status    string
	}{
		{"tenant-1", "create", "success"},
		{"tenant-2", "update", "success"},
		{"tenant-3", "delete", "failure"},
	}

	for _, op := range operations {
		sm.RecordTenantOperation(ctx, op.tenantID, op.operation, op.status)
	}
}

func TestSecurityMetrics_RecordPolicyEvaluation(t *testing.T) {
	meter := otel.Meter("test-meter")
	sm, err := NewSecurityMetrics(meter)
	require.NoError(t, err)

	ctx := context.Background()
	
	evaluations := []struct {
		tenantID   string
		policyType string
		duration   time.Duration
	}{
		{"tenant-1", "access-control", 100 * time.Millisecond},
		{"tenant-2", "rate-limit", 250 * time.Millisecond},
		{"tenant-3", "data-access", 50 * time.Millisecond},
	}

	for _, eval := range evaluations {
		sm.RecordPolicyEvaluation(ctx, eval.tenantID, eval.policyType, eval.duration)
	}
}

func TestSecurityMetrics_RecordMTLSConnection(t *testing.T) {
	meter := otel.Meter("test-meter")
	sm, err := NewSecurityMetrics(meter)
	require.NoError(t, err)

	ctx := context.Background()
	
	connections := []struct {
		tenantID string
		service  string
		status   string
	}{
		{"tenant-1", "workload-1", "established"},
		{"tenant-2", "workload-2", "failed"},
		{"tenant-3", "workload-3", "established"},
	}

	for _, conn := range connections {
		sm.RecordMTLSConnection(ctx, conn.tenantID, conn.service, conn.status)
	}
}

func TestSecurityMetrics_RecordSecurityViolation(t *testing.T) {
	meter := otel.Meter("test-meter")
	sm, err := NewSecurityMetrics(meter)
	require.NoError(t, err)

	ctx := context.Background()
	
	violations := []struct {
		violationType string
		resource      string
		tenantID      string
	}{
		{"unauthorized_access", "/api/admin", "tenant-123"},
		{"invalid_token", "/api/users", "tenant-456"},
		{"rate_limit_exceeded", "/api/data", "tenant-789"},
	}

	for _, v := range violations {
		sm.RecordSecurityViolation(ctx, v.tenantID, v.violationType, "high")
	}
}

func TestSecurityMetrics_ConcurrentOperations(t *testing.T) {
	meter := otel.Meter("test-meter")
	sm, err := NewSecurityMetrics(meter)
	require.NoError(t, err)

	ctx := context.Background()
	
	// Test concurrent metric recording
	done := make(chan bool)
	
	// Start multiple goroutines recording metrics
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				sm.RecordAuthzDecision(ctx, "tenant-concurrent", "test-service", "GET", "allow")
				sm.RecordTenantOperation(ctx, "tenant-concurrent", "read", "success")
			}
			done <- true
		}(i)
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}