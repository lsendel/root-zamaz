package observability

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func setupTestObservability(t *testing.T) *Observability {
    obs, err := New(Config{
        ServiceName:    "test-service",
        ServiceVersion: "test",
        Environment:    "test",
        LogLevel:       "debug",
        LogFormat:      "console",
        PrometheusPort: 0,
    })
    require.NoError(t, err)
    return obs
}

func TestNewBusinessMetrics(t *testing.T) {
    t.Run("Create_Business_Metrics", func(t *testing.T) {
        obs := setupTestObservability(t)
        defer obs.Shutdown(context.Background())

        metrics, err := NewBusinessMetrics(obs.Meter)
        require.NoError(t, err)
        require.NotNil(t, metrics)

        // Verify all metrics are initialized
        assert.NotNil(t, metrics.userRegistrations)
        assert.NotNil(t, metrics.userAuthentications)
        assert.NotNil(t, metrics.userSessions)
        assert.NotNil(t, metrics.tenantCreations)
        assert.NotNil(t, metrics.tenantActiveSessions)
        assert.NotNil(t, metrics.apiRequests)
        assert.NotNil(t, metrics.apiLatency)
        assert.NotNil(t, metrics.featureUsage)
        assert.NotNil(t, metrics.billingEvents)
    })
}

func TestBusinessMetrics_UserMetrics(t *testing.T) {
    obs := setupTestObservability(t)
    defer obs.Shutdown(context.Background())

    metrics, err := NewBusinessMetrics(obs.Meter)
    require.NoError(t, err)

    ctx := context.Background()

    t.Run("Record_User_Registration", func(t *testing.T) {
        // Test recording user registration - should not panic
        metrics.RecordUserRegistration(ctx, "tenant-123", "web", "email")
        metrics.RecordUserRegistration(ctx, "tenant-123", "api", "oauth")
        metrics.RecordUserRegistration(ctx, "tenant-456", "mobile", "email")
    })

    t.Run("Record_User_Authentication", func(t *testing.T) {
        metrics.RecordUserAuthentication(ctx, "tenant-123", "user-123", "password", "success")
        metrics.RecordUserAuthentication(ctx, "tenant-123", "user-456", "oauth", "success")
        metrics.RecordUserAuthentication(ctx, "tenant-123", "user-789", "password", "failure")
    })

    t.Run("Record_User_Session", func(t *testing.T) {
        sessionDuration := 30 * time.Minute
        metrics.RecordUserSession(ctx, "tenant-123", "user-123", "web", sessionDuration)
        
        apiSessionDuration := 10 * time.Minute
        metrics.RecordUserSession(ctx, "tenant-456", "user-456", "api", apiSessionDuration)
    })
}

func TestBusinessMetrics_TenantMetrics(t *testing.T) {
    obs := setupTestObservability(t)
    defer obs.Shutdown(context.Background())

    metrics, err := NewBusinessMetrics(obs.Meter)
    require.NoError(t, err)

    ctx := context.Background()

    t.Run("Record_Tenant_Creation", func(t *testing.T) {
        metrics.RecordTenantCreation(ctx, "tenant-123", "pro", "website")
        metrics.RecordTenantCreation(ctx, "tenant-456", "enterprise", "sales")
        metrics.RecordTenantCreation(ctx, "tenant-789", "free", "referral")
    })

    t.Run("Set_Tenant_Active_Sessions", func(t *testing.T) {
        metrics.SetTenantActiveSessions(ctx, "tenant-123", 15)
        metrics.SetTenantActiveSessions(ctx, "tenant-456", 3)
        metrics.SetTenantActiveSessions(ctx, "tenant-789", 0)
    })

    t.Run("Record_Tenant_Resource_Usage", func(t *testing.T) {
        metrics.RecordTenantResourceUsage(ctx, "tenant-123", "user_lookup", "database", 0.025)
        metrics.RecordTenantResourceUsage(ctx, "tenant-123", "auth_check", "cache", 0.001)
        metrics.RecordTenantResourceUsage(ctx, "tenant-456", "report_generation", "compute", 1.5)
    })
}

func TestBusinessMetrics_APIMetrics(t *testing.T) {
    obs := setupTestObservability(t)
    defer obs.Shutdown(context.Background())

    metrics, err := NewBusinessMetrics(obs.Meter)
    require.NoError(t, err)

    ctx := context.Background()

    t.Run("Record_API_Request", func(t *testing.T) {
        latency := 150 * time.Millisecond
        metrics.RecordAPIRequest(ctx, "tenant-123", "/api/users", "GET", "200", latency)
        
        slowLatency := 2 * time.Second
        metrics.RecordAPIRequest(ctx, "tenant-456", "/api/reports", "POST", "201", slowLatency)
        
        errorLatency := 50 * time.Millisecond
        metrics.RecordAPIRequest(ctx, "tenant-789", "/api/auth", "POST", "401", errorLatency)
    })

    t.Run("Record_API_Error", func(t *testing.T) {
        metrics.RecordAPIError(ctx, "tenant-123", "/api/users", "POST", "validation_error", "400")
        metrics.RecordAPIError(ctx, "tenant-456", "/api/auth", "POST", "authentication_failed", "401")
        metrics.RecordAPIError(ctx, "tenant-789", "/api/reports", "GET", "internal_error", "500")
    })
}

func TestBusinessMetrics_FeatureMetrics(t *testing.T) {
    obs := setupTestObservability(t)
    defer obs.Shutdown(context.Background())

    metrics, err := NewBusinessMetrics(obs.Meter)
    require.NoError(t, err)

    ctx := context.Background()

    t.Run("Record_Feature_Usage", func(t *testing.T) {
        metrics.RecordFeatureUsage(ctx, "tenant-123", "user-123", "reports", "generate")
        metrics.RecordFeatureUsage(ctx, "tenant-123", "user-456", "dashboard", "view")
        metrics.RecordFeatureUsage(ctx, "tenant-456", "user-789", "api_access", "create_key")
    })

    t.Run("Set_Feature_Adoption", func(t *testing.T) {
        metrics.SetFeatureAdoption(ctx, "tenant-123", "reports", 75.5)
        metrics.SetFeatureAdoption(ctx, "tenant-123", "dashboard", 92.3)
        metrics.SetFeatureAdoption(ctx, "tenant-456", "api_access", 45.0)
    })
}

func TestBusinessMetrics_BillingMetrics(t *testing.T) {
    obs := setupTestObservability(t)
    defer obs.Shutdown(context.Background())

    metrics, err := NewBusinessMetrics(obs.Meter)
    require.NoError(t, err)

    ctx := context.Background()

    t.Run("Record_Billing_Event", func(t *testing.T) {
        metrics.RecordBillingEvent(ctx, "tenant-123", "subscription_created", "pro", 99.99)
        metrics.RecordBillingEvent(ctx, "tenant-456", "upgrade", "enterprise", 299.99)
        metrics.RecordBillingEvent(ctx, "tenant-789", "payment_failed", "pro", 99.99)
    })

    t.Run("Record_Resource_Consumption", func(t *testing.T) {
        metrics.RecordResourceConsumption(ctx, "tenant-123", "api_calls", 1500.0)
        metrics.RecordResourceConsumption(ctx, "tenant-123", "storage_gb", 25.5)
        metrics.RecordResourceConsumption(ctx, "tenant-456", "compute_hours", 120.0)
    })
}

func TestBusinessMetrics_IntegrationScenario(t *testing.T) {
    obs := setupTestObservability(t)
    defer obs.Shutdown(context.Background())

    metrics, err := NewBusinessMetrics(obs.Meter)
    require.NoError(t, err)

    ctx := context.Background()

    t.Run("Complete_User_Journey", func(t *testing.T) {
        tenantID := "tenant-integration-test"
        userID := "user-integration-test"

        // 1. User registration
        metrics.RecordUserRegistration(ctx, tenantID, "web", "email")

        // 2. User authentication
        metrics.RecordUserAuthentication(ctx, tenantID, userID, "password", "success")

        // 3. User session
        sessionDuration := 45 * time.Minute
        metrics.RecordUserSession(ctx, tenantID, userID, "web", sessionDuration)

        // 4. API usage
        apiLatency := 200 * time.Millisecond
        metrics.RecordAPIRequest(ctx, tenantID, "/api/profile", "GET", "200", apiLatency)

        // 5. Feature usage
        metrics.RecordFeatureUsage(ctx, tenantID, userID, "profile_management", "update")

        // 6. Resource consumption
        metrics.RecordResourceConsumption(ctx, tenantID, "api_calls", 5.0)

        // Verify no panics occurred and metrics were recorded
        // In a real scenario, you might check the metrics backend
    })

    t.Run("Tenant_Operations_Lifecycle", func(t *testing.T) {
        tenantID := "tenant-lifecycle-test"

        // 1. Tenant creation
        metrics.RecordTenantCreation(ctx, tenantID, "pro", "sales")

        // 2. Set initial active sessions
        metrics.SetTenantActiveSessions(ctx, tenantID, 0)

        // 3. Record resource usage as tenant grows
        metrics.RecordTenantResourceUsage(ctx, tenantID, "initial_setup", "compute", 0.5)

        // 4. Track feature adoption
        metrics.SetFeatureAdoption(ctx, tenantID, "basic_auth", 100.0)
        metrics.SetFeatureAdoption(ctx, tenantID, "advanced_reporting", 25.0)

        // 5. Billing events
        metrics.RecordBillingEvent(ctx, tenantID, "subscription_created", "pro", 99.99)

        // 6. Update active sessions as users join
        metrics.SetTenantActiveSessions(ctx, tenantID, 5)

        // 7. Record ongoing resource consumption
        metrics.RecordResourceConsumption(ctx, tenantID, "storage_gb", 10.0)
        metrics.RecordResourceConsumption(ctx, tenantID, "bandwidth_gb", 5.0)
    })
}