// Package observability provides business metrics for the MVP Zero Trust Auth system.
// Business metrics focus on tracking key business indicators and user behavior patterns.
package observability

import (
    "context"
    "time"

    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/metric"
)

// BusinessMetrics tracks business-relevant metrics for the zero trust auth system
type BusinessMetrics struct {
    // User activity metrics
    userRegistrations    metric.Int64Counter
    userAuthentications  metric.Int64Counter
    userSessions         metric.Int64Counter
    
    // Tenant metrics
    tenantCreations      metric.Int64Counter
    tenantActiveSessions metric.Int64Gauge
    tenantResourceUsage  metric.Float64Histogram
    
    // API usage metrics
    apiRequests          metric.Int64Counter
    apiLatency           metric.Float64Histogram
    apiErrors            metric.Int64Counter
    
    // Feature usage metrics
    featureUsage         metric.Int64Counter
    featureAdoption      metric.Float64Gauge
    
    // Billing metrics
    billingEvents        metric.Int64Counter
    resourceConsumption  metric.Float64Counter
}

// NewBusinessMetrics creates a new BusinessMetrics instance with all metrics initialized
func NewBusinessMetrics(meter metric.Meter) (*BusinessMetrics, error) {
    userRegistrations, err := meter.Int64Counter(
        "business_user_registrations_total",
        metric.WithDescription("Total number of user registrations"),
    )
    if err != nil {
        return nil, err
    }

    userAuthentications, err := meter.Int64Counter(
        "business_user_authentications_total",
        metric.WithDescription("Total number of user authentication attempts"),
    )
    if err != nil {
        return nil, err
    }

    userSessions, err := meter.Int64Counter(
        "business_user_sessions_total",
        metric.WithDescription("Total number of user sessions created"),
    )
    if err != nil {
        return nil, err
    }

    tenantCreations, err := meter.Int64Counter(
        "business_tenant_creations_total",
        metric.WithDescription("Total number of tenant creations"),
    )
    if err != nil {
        return nil, err
    }

    tenantActiveSessions, err := meter.Int64Gauge(
        "business_tenant_active_sessions",
        metric.WithDescription("Current number of active sessions per tenant"),
    )
    if err != nil {
        return nil, err
    }

    tenantResourceUsage, err := meter.Float64Histogram(
        "business_tenant_resource_usage_seconds",
        metric.WithDescription("Resource usage per tenant operation"),
    )
    if err != nil {
        return nil, err
    }

    apiRequests, err := meter.Int64Counter(
        "business_api_requests_total",
        metric.WithDescription("Total number of API requests"),
    )
    if err != nil {
        return nil, err
    }

    apiLatency, err := meter.Float64Histogram(
        "business_api_latency_seconds",
        metric.WithDescription("API request latency"),
        metric.WithUnit("s"),
    )
    if err != nil {
        return nil, err
    }

    apiErrors, err := meter.Int64Counter(
        "business_api_errors_total",
        metric.WithDescription("Total number of API errors"),
    )
    if err != nil {
        return nil, err
    }

    featureUsage, err := meter.Int64Counter(
        "business_feature_usage_total",
        metric.WithDescription("Total feature usage events"),
    )
    if err != nil {
        return nil, err
    }

    featureAdoption, err := meter.Float64Gauge(
        "business_feature_adoption_rate",
        metric.WithDescription("Feature adoption rate percentage"),
    )
    if err != nil {
        return nil, err
    }

    billingEvents, err := meter.Int64Counter(
        "business_billing_events_total",
        metric.WithDescription("Total billing events"),
    )
    if err != nil {
        return nil, err
    }

    resourceConsumption, err := meter.Float64Counter(
        "business_resource_consumption_total",
        metric.WithDescription("Total resource consumption units"),
    )
    if err != nil {
        return nil, err
    }

    return &BusinessMetrics{
        userRegistrations:    userRegistrations,
        userAuthentications:  userAuthentications,
        userSessions:         userSessions,
        tenantCreations:      tenantCreations,
        tenantActiveSessions: tenantActiveSessions,
        tenantResourceUsage:  tenantResourceUsage,
        apiRequests:          apiRequests,
        apiLatency:           apiLatency,
        apiErrors:            apiErrors,
        featureUsage:         featureUsage,
        featureAdoption:      featureAdoption,
        billingEvents:        billingEvents,
        resourceConsumption:  resourceConsumption,
    }, nil
}

// RecordUserRegistration records a new user registration event
func (bm *BusinessMetrics) RecordUserRegistration(ctx context.Context, tenantID, source, method string) {
    bm.userRegistrations.Add(ctx, 1,
        metric.WithAttributes(
            attribute.String("tenant_id", tenantID),
            attribute.String("source", source),
            attribute.String("method", method),
        ),
    )
}

// RecordUserAuthentication records a user authentication attempt
func (bm *BusinessMetrics) RecordUserAuthentication(ctx context.Context, tenantID, userID, method, result string) {
    bm.userAuthentications.Add(ctx, 1,
        metric.WithAttributes(
            attribute.String("tenant_id", tenantID),
            attribute.String("user_id", userID),
            attribute.String("method", method),
            attribute.String("result", result),
        ),
    )
}

// RecordUserSession records a new user session creation
func (bm *BusinessMetrics) RecordUserSession(ctx context.Context, tenantID, userID, sessionType string, duration time.Duration) {
    bm.userSessions.Add(ctx, 1,
        metric.WithAttributes(
            attribute.String("tenant_id", tenantID),
            attribute.String("user_id", userID),
            attribute.String("session_type", sessionType),
            attribute.Float64("duration_minutes", duration.Minutes()),
        ),
    )
}

// RecordTenantCreation records a new tenant creation
func (bm *BusinessMetrics) RecordTenantCreation(ctx context.Context, tenantID, plan, source string) {
    bm.tenantCreations.Add(ctx, 1,
        metric.WithAttributes(
            attribute.String("tenant_id", tenantID),
            attribute.String("plan", plan),
            attribute.String("source", source),
        ),
    )
}

// SetTenantActiveSessions sets the current number of active sessions for a tenant
func (bm *BusinessMetrics) SetTenantActiveSessions(ctx context.Context, tenantID string, count int64) {
    bm.tenantActiveSessions.Record(ctx, count,
        metric.WithAttributes(
            attribute.String("tenant_id", tenantID),
        ),
    )
}

// RecordTenantResourceUsage records resource usage for a tenant operation
func (bm *BusinessMetrics) RecordTenantResourceUsage(ctx context.Context, tenantID, operation, resourceType string, usage float64) {
    bm.tenantResourceUsage.Record(ctx, usage,
        metric.WithAttributes(
            attribute.String("tenant_id", tenantID),
            attribute.String("operation", operation),
            attribute.String("resource_type", resourceType),
        ),
    )
}

// RecordAPIRequest records an API request with latency
func (bm *BusinessMetrics) RecordAPIRequest(ctx context.Context, tenantID, endpoint, method, statusCode string, latency time.Duration) {
    // Count the request
    bm.apiRequests.Add(ctx, 1,
        metric.WithAttributes(
            attribute.String("tenant_id", tenantID),
            attribute.String("endpoint", endpoint),
            attribute.String("method", method),
            attribute.String("status_code", statusCode),
        ),
    )

    // Record latency
    bm.apiLatency.Record(ctx, latency.Seconds(),
        metric.WithAttributes(
            attribute.String("tenant_id", tenantID),
            attribute.String("endpoint", endpoint),
            attribute.String("method", method),
        ),
    )
}

// RecordAPIError records an API error
func (bm *BusinessMetrics) RecordAPIError(ctx context.Context, tenantID, endpoint, method, errorType, errorCode string) {
    bm.apiErrors.Add(ctx, 1,
        metric.WithAttributes(
            attribute.String("tenant_id", tenantID),
            attribute.String("endpoint", endpoint),
            attribute.String("method", method),
            attribute.String("error_type", errorType),
            attribute.String("error_code", errorCode),
        ),
    )
}

// RecordFeatureUsage records a feature usage event
func (bm *BusinessMetrics) RecordFeatureUsage(ctx context.Context, tenantID, userID, feature, action string) {
    bm.featureUsage.Add(ctx, 1,
        metric.WithAttributes(
            attribute.String("tenant_id", tenantID),
            attribute.String("user_id", userID),
            attribute.String("feature", feature),
            attribute.String("action", action),
        ),
    )
}

// SetFeatureAdoption sets the feature adoption rate for a specific feature
func (bm *BusinessMetrics) SetFeatureAdoption(ctx context.Context, tenantID, feature string, adoptionRate float64) {
    bm.featureAdoption.Record(ctx, adoptionRate,
        metric.WithAttributes(
            attribute.String("tenant_id", tenantID),
            attribute.String("feature", feature),
        ),
    )
}

// RecordBillingEvent records a billing-related event
func (bm *BusinessMetrics) RecordBillingEvent(ctx context.Context, tenantID, eventType, plan string, amount float64) {
    bm.billingEvents.Add(ctx, 1,
        metric.WithAttributes(
            attribute.String("tenant_id", tenantID),
            attribute.String("event_type", eventType),
            attribute.String("plan", plan),
            attribute.Float64("amount", amount),
        ),
    )
}

// RecordResourceConsumption records resource consumption for billing purposes
func (bm *BusinessMetrics) RecordResourceConsumption(ctx context.Context, tenantID, resourceType string, units float64) {
    bm.resourceConsumption.Add(ctx, units,
        metric.WithAttributes(
            attribute.String("tenant_id", tenantID),
            attribute.String("resource_type", resourceType),
        ),
    )
}