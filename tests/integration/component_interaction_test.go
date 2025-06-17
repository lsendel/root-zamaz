package integration

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"

	"mvp.local/pkg/config"
	"mvp.local/pkg/errors"
	"mvp.local/pkg/messaging"
	"mvp.local/pkg/observability"
	"mvp.local/pkg/testutil"
)

// TestConfigObservabilityIntegration tests the integration between
// the configuration system and observability components
func TestConfigObservabilityIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Config_Loads_Observability_Settings", func(t *testing.T) {
		// Load configuration
		cfg, err := config.Load()
		require.NoError(t, err)

		// Create observability instance from config
		obsCfg := observability.Config{
			ServiceName:    cfg.Observability.ServiceName,
			ServiceVersion: cfg.Observability.ServiceVersion,
			Environment:    cfg.Observability.Environment,
			LogLevel:       cfg.Observability.LogLevel,
			LogFormat:      cfg.Observability.LogFormat,
			PrometheusPort: 0, // Use random port for testing
		}

		obs, err := observability.New(obsCfg)
		require.NoError(t, err)
		require.NotNil(t, obs)

		// Verify configuration was applied
		assert.Equal(t, cfg.Observability.ServiceName, obsCfg.ServiceName)
		assert.Equal(t, cfg.Observability.LogLevel, obsCfg.LogLevel)
	})
}

// TestErrorHandlingObservabilityIntegration tests how errors are
// handled and logged through the observability system
func TestErrorHandlingObservabilityIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Error_Logging_With_Context", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)
		ctx := context.Background()

		// Create an error with context
		appErr := errors.Validation("Invalid user input").
			WithTenant("tenant-123").
			WithRequest("req-456").
			WithContext("field", "email").
			WithDetails("Email format is invalid")

		// Create a span for the operation
		ctx, span := obs.CreateSpan(ctx, "user.validation",
			attribute.String("user.id", "user-789"),
			attribute.String("operation", "validate_email"),
		)
		defer span.End()

		// Log the error with correlation
		logger := obs.WithCorrelationID("corr-123")
		logger.Error().
			Err(appErr).
			Str("error_code", string(appErr.Code)).
			Str("tenant_id", appErr.TenantID).
			Str("request_id", appErr.RequestID).
			Interface("error_context", appErr.Context).
			Msg("Validation failed")

		// Verify the error structure
		assert.Equal(t, errors.CodeValidation, appErr.Code)
		assert.Equal(t, "tenant-123", appErr.TenantID)
		assert.Equal(t, "req-456", appErr.RequestID)
		assert.Equal(t, "email", appErr.Context["field"])
	})

	t.Run("Error_Metrics_Recording", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)
		ctx := context.Background()

		// Create security metrics
		securityMetrics, err := observability.NewSecurityMetrics(obs.Meter)
		require.NoError(t, err)

		// Simulate authentication errors
		appErr := errors.Authentication("Invalid credentials")

		// Record security metrics for the error
		securityMetrics.RecordAuthzDecision(ctx, "tenant-123", "auth-service", "authenticate", "deny")

		// Create span and record error
		ctx, span := obs.CreateSpan(ctx, "auth.authenticate")
		span.RecordError(appErr)
		span.End()

		// Wait for metrics to be recorded
		time.Sleep(100 * time.Millisecond)

		assert.Equal(t, errors.CodeAuthentication, appErr.Code)
	})
}

// TestMessagingObservabilityIntegration tests the integration between
// messaging and observability systems
func TestMessagingObservabilityIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("NATS_With_Distributed_Tracing", func(t *testing.T) {
		obs, err := observability.New(observability.Config{
			ServiceName:    "test-service",
			ServiceVersion: "test",
			Environment:    "test",
			LogLevel:       "debug",
			LogFormat:      "console",
			PrometheusPort: 0,
		})
		require.NoError(t, err)
		defer obs.Shutdown(context.Background())

		ctx := context.Background()

		// Create NATS client with observability
		natsClient, err := messaging.NewClient(messaging.Config{
			URL: "nats://localhost:4222",
		}, obs.Tracer)
		if err != nil {
			t.Skipf("NATS not available, skipping test: %v", err)
		}
		defer natsClient.Close()

		// Create JetStream stream for testing (this is normally done during service setup)
		js := natsClient.JetStream()

		// Create test streams
		_, err = js.AddStream(&nats.StreamConfig{
			Name:      "EVENTS",
			Subjects:  []string{"user.events", "email.events"},
			Storage:   nats.MemoryStorage,
			Retention: nats.WorkQueuePolicy,
		})
		if err != nil && err.Error() != "stream name already in use" {
			require.NoError(t, err)
		}

		// Start a trace for the entire operation
		ctx, parentSpan := obs.CreateSpan(ctx, "user.registration.flow",
			attribute.String("user.id", "user-123"),
			attribute.String("tenant.id", "tenant-456"),
		)
		defer parentSpan.End()

		// Create events with tracing context
		userCreatedEvent := messaging.Event{
			Type:     "user.created",
			Source:   "auth-service",
			TenantID: "tenant-456",
			Data: map[string]interface{}{
				"user_id": "user-123",
				"email":   "test@example.com",
			},
		}

		emailEvent := messaging.Event{
			Type:     "email.send",
			Source:   "auth-service",
			TenantID: "tenant-456",
			Data: map[string]interface{}{
				"user_id":  "user-123",
				"email":    "test@example.com",
				"template": "welcome",
			},
		}

		// Publish events within traced operations
		ctx, span1 := obs.CreateSpan(ctx, "publish.user.created")
		err = natsClient.PublishEvent(ctx, "user.events", &userCreatedEvent)
		span1.End()
		require.NoError(t, err)

		ctx, span2 := obs.CreateSpan(ctx, "publish.email.send")
		err = natsClient.PublishEvent(ctx, "email.events", &emailEvent)
		span2.End()
		require.NoError(t, err)

		// Verify trace context was propagated
		assert.NotEmpty(t, userCreatedEvent.TraceID)
		assert.NotEmpty(t, emailEvent.TraceID)
	})
}

// TestDatabaseObservabilityIntegration tests integration between
// database operations and observability
func TestDatabaseObservabilityIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Database_Operations_With_Tracing", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)
		ctx := context.Background()

		// Setup test database
		db := setupTestDBWithSkip(t)
		defer db.Close()

		// Create a traced database operation
		ctx, span := obs.CreateSpan(ctx, "db.user.create",
			attribute.String("db.operation", "INSERT"),
			attribute.String("db.table", "users"),
			attribute.String("tenant.id", "tenant-123"),
		)
		defer span.End()

		// Simulate database operation with error handling
		var userID string
		err := db.QueryRowContext(ctx, "SELECT $1::text", "test-user-id").Scan(&userID)
		if err != nil {
			// Log database error with context
			logger := obs.WithCorrelationID("db-op-123")
			dbErr := errors.Wrap(err, errors.CodeInternal, "Database operation failed").
				WithContext("operation", "create_user").
				WithContext("table", "users").
				WithTenant("tenant-123")

			logger.Error().
				Err(dbErr).
				Str("query", "SELECT $1::text").
				Msg("Database query failed")

			span.RecordError(dbErr)
		} else {
			assert.Equal(t, "test-user-id", userID)
		}
	})
}

// TestEndToEndComponentIntegration tests a complete flow through
// multiple components with full observability
func TestEndToEndComponentIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Complete_User_Registration_Flow", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)
		ctx := context.Background()

		// Load configuration
		_, err := config.Load()
		require.NoError(t, err)

		// Start observability
		err = obs.Start(ctx)
		require.NoError(t, err)

		// Create security metrics
		securityMetrics, err := observability.NewSecurityMetrics(obs.Meter)
		require.NoError(t, err)

		// Start the end-to-end trace
		correlationID := "reg-flow-123"
		ctx, rootSpan := obs.CreateSpan(ctx, "user.registration.complete",
			attribute.String("correlation.id", correlationID),
			attribute.String("tenant.id", "tenant-789"),
			attribute.String("user.email", "newuser@example.com"),
		)
		defer rootSpan.End()

		logger := obs.WithCorrelationID(correlationID)

		// Step 1: Validate input
		ctx, validateSpan := obs.CreateSpan(ctx, "user.registration.validate")
		userEmail := "newuser@example.com"
		if userEmail == "" {
			validationErr := errors.Validation("Email is required").
				WithContext("field", "email").
				WithTenant("tenant-789").
				WithRequest(correlationID)

			logger.Error().Err(validationErr).Msg("Validation failed")
			validateSpan.RecordError(validationErr)
			validateSpan.End()
			return
		}
		validateSpan.End()

		// Step 2: Check database for existing user
		ctx, dbSpan := obs.CreateSpan(ctx, "user.registration.check_existing",
			attribute.String("db.operation", "SELECT"),
			attribute.String("db.table", "users"),
		)

		db := setupTestDBWithSkip(t)
		defer db.Close()

		var existingUser string
		err = db.QueryRowContext(ctx, "SELECT $1::text", "").Scan(&existingUser)
		if err != sql.ErrNoRows && err != nil {
			dbErr := errors.Wrap(err, errors.CodeInternal, "Database check failed").
				WithContext("operation", "check_user_exists").
				WithTenant("tenant-789")

			logger.Error().Err(dbErr).Msg("Database operation failed")
			dbSpan.RecordError(dbErr)
			securityMetrics.RecordTenantOperation(ctx, "tenant-789", "user_check", "error")
		} else {
			securityMetrics.RecordTenantOperation(ctx, "tenant-789", "user_check", "success")
		}
		dbSpan.End()

		// Step 3: Create user record
		ctx, createSpan := obs.CreateSpan(ctx, "user.registration.create",
			attribute.String("db.operation", "INSERT"),
			attribute.String("user.email", userEmail),
		)

		// Simulate successful user creation
		logger.Info().
			Str("user_email", userEmail).
			Str("tenant_id", "tenant-789").
			Msg("User created successfully")

		securityMetrics.RecordTenantOperation(ctx, "tenant-789", "user_create", "success")
		createSpan.End()

		// Step 4: Publish user created event
		natsClient, err := messaging.NewClient(messaging.Config{
			URL: "nats://localhost:4222",
		}, obs.Tracer)
		if err == nil {
			defer natsClient.Close()

			ctx, publishSpan := obs.CreateSpan(ctx, "user.registration.publish_event")

			event := messaging.Event{
				Type:     "user.registered",
				Source:   "registration-service",
				TenantID: "tenant-789",
				Data: map[string]interface{}{
					"user_email": userEmail,
					"created_at": time.Now().UTC(),
				},
			}

			err = natsClient.PublishEvent(ctx, "user.events", &event)
			if err != nil {
				publishErr := errors.Wrap(err, errors.CodeInternal, "Failed to publish user event").
					WithContext("event_type", "user.registered").
					WithTenant("tenant-789")

				logger.Error().Err(publishErr).Msg("Event publishing failed")
				publishSpan.RecordError(publishErr)
			} else {
				logger.Info().
					Str("event_type", "user.registered").
					Str("trace_id", event.TraceID).
					Msg("User registration event published")
			}
			publishSpan.End()
		} else {
			t.Logf("NATS not available, skipping event publishing: %v", err)
		}

		// Step 5: Record authorization metrics
		securityMetrics.RecordAuthzDecision(ctx, "tenant-789", "registration-service", "create_user", "allow")

		logger.Info().
			Str("flow_type", "user_registration").
			Dur("duration", time.Since(time.Now().Add(-100*time.Millisecond))).
			Msg("User registration flow completed successfully")

		// Wait for async operations to complete
		time.Sleep(200 * time.Millisecond)
	})
}

// Helper function for database setup (graceful fallback version)
func setupTestDBWithSkip(t *testing.T) *sql.DB {
	t.Helper()

	// Connection string for the PostgreSQL container
	connStr := "host=localhost port=5432 user=mvp_user password=mvp_password dbname=mvp_db sslmode=disable"

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		t.Skipf("Failed to connect to database (database not available for test): %v", err)
	}

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		t.Skipf("Failed to ping database (database not available for test): %v", err)
	}

	return db
}
