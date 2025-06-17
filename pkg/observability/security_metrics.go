package observability

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type SecurityMetrics struct {
	authzDecisions     metric.Int64Counter
	certificateEvents  metric.Int64Counter
	tenantOperations   metric.Int64Counter
	policyEvaluations  metric.Float64Histogram
	mtlsConnections    metric.Int64Counter
	securityViolations metric.Int64Counter
}

func NewSecurityMetrics(meter metric.Meter) (*SecurityMetrics, error) {
	authzDecisions, err := meter.Int64Counter(
		"authz_decisions_total",
		metric.WithDescription("Total number of authorization decisions"),
	)
	if err != nil {
		return nil, err
	}

	certificateEvents, err := meter.Int64Counter(
		"certificate_events_total",
		metric.WithDescription("Total number of certificate events"),
	)
	if err != nil {
		return nil, err
	}

	tenantOperations, err := meter.Int64Counter(
		"tenant_operations_total",
		metric.WithDescription("Total number of tenant operations"),
	)
	if err != nil {
		return nil, err
	}

	policyEvaluations, err := meter.Float64Histogram(
		"policy_evaluation_duration_seconds",
		metric.WithDescription("Time spent evaluating policies"),
	)
	if err != nil {
		return nil, err
	}

	mtlsConnections, err := meter.Int64Counter(
		"mtls_connections_total",
		metric.WithDescription("Total number of mTLS connections"),
	)
	if err != nil {
		return nil, err
	}

	securityViolations, err := meter.Int64Counter(
		"security_violations_total",
		metric.WithDescription("Total number of security violations"),
	)
	if err != nil {
		return nil, err
	}

	return &SecurityMetrics{
		authzDecisions:     authzDecisions,
		certificateEvents:  certificateEvents,
		tenantOperations:   tenantOperations,
		policyEvaluations:  policyEvaluations,
		mtlsConnections:    mtlsConnections,
		securityViolations: securityViolations,
	}, nil
}

func (sm *SecurityMetrics) RecordAuthzDecision(ctx context.Context, tenantID, service, action, decision string) {
	sm.authzDecisions.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("service", service),
			attribute.String("action", action),
			attribute.String("decision", decision),
		),
	)
}

func (sm *SecurityMetrics) RecordCertificateEvent(ctx context.Context, tenantID, service, event string) {
	sm.certificateEvents.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("service", service),
			attribute.String("event", event),
		),
	)
}

func (sm *SecurityMetrics) RecordTenantOperation(ctx context.Context, tenantID, operation, status string) {
	sm.tenantOperations.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("operation", operation),
			attribute.String("status", status),
		),
	)
}

func (sm *SecurityMetrics) RecordPolicyEvaluation(ctx context.Context, tenantID, policyType string, duration time.Duration) {
	sm.policyEvaluations.Record(ctx, duration.Seconds(),
		metric.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("policy_type", policyType),
		),
	)
}

func (sm *SecurityMetrics) RecordMTLSConnection(ctx context.Context, tenantID, service, status string) {
	sm.mtlsConnections.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("service", service),
			attribute.String("status", status),
		),
	)
}

func (sm *SecurityMetrics) RecordSecurityViolation(ctx context.Context, tenantID, violationType, severity string) {
	sm.securityViolations.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("tenant_id", tenantID),
			attribute.String("violation_type", violationType),
			attribute.String("severity", severity),
		),
	)
}
