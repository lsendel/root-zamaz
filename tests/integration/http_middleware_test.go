package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"

	"mvp.local/pkg/errors"
	"mvp.local/pkg/middleware"
	"mvp.local/pkg/observability"
	"mvp.local/pkg/testutil"
)

// TestHTTPMiddlewareIntegration tests the integration of various
// middleware components with HTTP requests
func TestHTTPMiddlewareIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Observability_Middleware_Full_Request_Cycle", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)

		// Create security metrics
		securityMetrics, err := observability.NewSecurityMetrics(obs.Meter)
		require.NoError(t, err)

		// Create Fiber app with middleware
		app := fiber.New(fiber.Config{
			DisableStartupMessage: true,
		})

		// Add observability middleware
		app.Use(middleware.ObservabilityMiddleware(obs, securityMetrics, nil))

		// Add a test route that creates spans and logs
		app.Post("/api/users", func(c *fiber.Ctx) error {
			ctx := c.UserContext()

			// Extract correlation ID from middleware
			correlationID := c.Get(middleware.CorrelationIDHeader, "")
			if correlationID == "" {
				correlationID = "generated-id"
			}

			// Create a span for the operation
			ctx, span := obs.CreateSpan(ctx, "users.create",
				attribute.String("user.action", "create"),
				attribute.String("correlation.id", correlationID),
			)
			defer span.End()

			// Parse request body
			var userReq map[string]interface{}
			if err := c.BodyParser(&userReq); err != nil {
				appErr := errors.Validation("Invalid request body").
					WithContext("error", err.Error()).
					WithRequest(correlationID)

				logger := obs.WithCorrelationID(correlationID)
				logger.Error().Err(appErr).Msg("Request parsing failed")
				span.RecordError(appErr)

				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "Invalid request body",
					"code":  string(errors.CodeValidation),
				})
			}

			// Validate required fields
			email, hasEmail := userReq["email"].(string)
			if !hasEmail || email == "" {
				validationErr := errors.Validation("Email is required").
					WithContext("field", "email").
					WithRequest(correlationID)

				logger := obs.WithCorrelationID(correlationID)
				logger.Error().Err(validationErr).Msg("Validation failed")
				span.RecordError(validationErr)

				// Record security metrics
				securityMetrics.RecordAuthzDecision(ctx, "default", "user-service", "create", "deny")

				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "Email is required",
					"code":  string(errors.CodeValidation),
				})
			}

			// Simulate successful user creation
			logger := obs.WithCorrelationID(correlationID)
			logger.Info().
				Str("user_email", email).
				Str("operation", "create_user").
				Msg("User created successfully")

			// Record successful authorization
			securityMetrics.RecordAuthzDecision(ctx, "default", "user-service", "create", "allow")
			securityMetrics.RecordTenantOperation(ctx, "default", "user_create", "success")

			return c.Status(fiber.StatusCreated).JSON(fiber.Map{
				"message":        "User created successfully",
				"user_id":        "user-123",
				"email":          email,
				"correlation_id": correlationID,
			})
		})

		// Test successful request
		t.Run("Successful_Request", func(t *testing.T) {
			requestBody := map[string]interface{}{
				"email": "test@example.com",
				"name":  "Test User",
			}
			bodyJSON, _ := json.Marshal(requestBody)

			req := httptest.NewRequest("POST", "/api/users", bytes.NewReader(bodyJSON))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(middleware.CorrelationIDHeader, "test-correlation-123")
			req.Header.Set(middleware.TenantIDHeader, "test-tenant")

			resp, err := app.Test(req, -1)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusCreated, resp.StatusCode)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			var response map[string]interface{}
			err = json.Unmarshal(body, &response)
			require.NoError(t, err)

			assert.Equal(t, "User created successfully", response["message"])
			assert.Equal(t, "test@example.com", response["email"])
			assert.Equal(t, "test-correlation-123", response["correlation_id"])
		})

		// Test validation error
		t.Run("Validation_Error", func(t *testing.T) {
			requestBody := map[string]interface{}{
				"name": "Test User",
				// Missing email field
			}
			bodyJSON, _ := json.Marshal(requestBody)

			req := httptest.NewRequest("POST", "/api/users", bytes.NewReader(bodyJSON))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(middleware.CorrelationIDHeader, "test-correlation-456")

			resp, err := app.Test(req, -1)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			var response map[string]interface{}
			err = json.Unmarshal(body, &response)
			require.NoError(t, err)

			assert.Equal(t, "Email is required", response["error"])
			assert.Equal(t, string(errors.CodeValidation), response["code"])
		})

		// Test malformed JSON
		t.Run("Malformed_JSON", func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/users", bytes.NewReader([]byte("invalid json")))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(middleware.CorrelationIDHeader, "test-correlation-789")

			resp, err := app.Test(req, -1)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})

		// Allow time for async metrics recording
		time.Sleep(100 * time.Millisecond)
	})
}

// TestMiddlewareChainIntegration tests how multiple middleware
// components work together
func TestMiddlewareChainIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Complete_Middleware_Chain", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)

		// Create security metrics
		securityMetrics, err := observability.NewSecurityMetrics(obs.Meter)
		require.NoError(t, err)

		// Create Fiber app
		app := fiber.New(fiber.Config{
			DisableStartupMessage: true,
		})

		// Add correlation ID middleware (would be custom)
		app.Use(func(c *fiber.Ctx) error {
			correlationID := c.Get(middleware.CorrelationIDHeader)
			if correlationID == "" {
				correlationID = "gen-" + time.Now().Format("20060102150405")
				c.Set(middleware.CorrelationIDHeader, correlationID)
			}
			c.Locals("correlation_id", correlationID)
			return c.Next()
		})

		// Add tenant middleware
		app.Use(func(c *fiber.Ctx) error {
			tenantID := c.Get(middleware.TenantIDHeader)
			if tenantID == "" {
				tenantID = "default"
			}
			c.Locals("tenant_id", tenantID)
			return c.Next()
		})

		// Add observability middleware
		app.Use(middleware.ObservabilityMiddleware(obs, securityMetrics, nil))

		// Add authentication simulation middleware
		app.Use(func(c *fiber.Ctx) error {
			authHeader := c.Get("Authorization")
			if authHeader == "" {
				ctx := c.UserContext()
				securityMetrics.RecordAuthzDecision(ctx,
					c.Locals("tenant_id").(string),
					"api-gateway",
					"authenticate",
					"deny")

				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "Unauthorized",
					"code":  string(errors.CodeAuthentication),
				})
			}

			// Simulate successful authentication
			c.Locals("user_id", "user-authenticated")
			return c.Next()
		})

		// Add a protected route
		app.Get("/api/protected", func(c *fiber.Ctx) error {
			ctx := c.UserContext()
			correlationID := c.Locals("correlation_id").(string)
			tenantID := c.Locals("tenant_id").(string)
			userID := c.Locals("user_id").(string)

			// Create span for the protected operation
			ctx, span := obs.CreateSpan(ctx, "protected.resource.access",
				attribute.String("user.id", userID),
				attribute.String("tenant.id", tenantID),
				attribute.String("resource", "protected_data"),
			)
			defer span.End()

			// Log successful access
			logger := obs.WithCorrelationID(correlationID)
			logger.Info().
				Str("user_id", userID).
				Str("tenant_id", tenantID).
				Str("resource", "protected_data").
				Msg("Protected resource accessed")

			// Record authorization success
			securityMetrics.RecordAuthzDecision(ctx, tenantID, "api-service", "read", "allow")

			return c.JSON(fiber.Map{
				"message":        "Access granted to protected resource",
				"user_id":        userID,
				"tenant_id":      tenantID,
				"correlation_id": correlationID,
				"timestamp":      time.Now().UTC(),
			})
		})

		// Test successful authenticated request
		t.Run("Authenticated_Request", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/protected", nil)
			req.Header.Set("Authorization", "Bearer valid-token")
			req.Header.Set(middleware.CorrelationIDHeader, "middleware-test-123")
			req.Header.Set(middleware.TenantIDHeader, "tenant-456")

			resp, err := app.Test(req, -1)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			var response map[string]interface{}
			err = json.Unmarshal(body, &response)
			require.NoError(t, err)

			assert.Equal(t, "Access granted to protected resource", response["message"])
			assert.Equal(t, "user-authenticated", response["user_id"])
			assert.Equal(t, "tenant-456", response["tenant_id"])
			assert.Equal(t, "middleware-test-123", response["correlation_id"])
		})

		// Test unauthenticated request
		t.Run("Unauthenticated_Request", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/protected", nil)
			req.Header.Set(middleware.CorrelationIDHeader, "unauth-test-456")
			req.Header.Set(middleware.TenantIDHeader, "tenant-789")

			resp, err := app.Test(req, -1)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			var response map[string]interface{}
			err = json.Unmarshal(body, &response)
			require.NoError(t, err)

			assert.Equal(t, "Unauthorized", response["error"])
			assert.Equal(t, string(errors.CodeAuthentication), response["code"])
		})

		// Allow time for async operations
		time.Sleep(100 * time.Millisecond)
	})
}

// TestErrorPropagationThroughMiddleware tests how errors are
// properly handled and propagated through the middleware chain
func TestErrorPropagationThroughMiddleware(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Error_Handling_Chain", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)

		securityMetrics, err := observability.NewSecurityMetrics(obs.Meter)
		require.NoError(t, err)

		app := fiber.New(fiber.Config{
			DisableStartupMessage: true,
			ErrorHandler: func(c *fiber.Ctx, err error) error {
				// Custom error handler that integrates with observability
				correlationID := c.Get(middleware.CorrelationIDHeader, "unknown")

				logger := obs.WithCorrelationID(correlationID)

				if errors.IsCode(err, errors.CodeValidation) {
					logger.Error().Err(err).Msg("Validation error occurred")
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
						"error": err.Error(),
						"code":  string(errors.CodeValidation),
					})
				} else if errors.IsCode(err, errors.CodeAuthentication) {
					logger.Error().Err(err).Msg("Authentication error occurred")
					return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": err.Error(),
						"code":  string(errors.CodeAuthentication),
					})
				} else {
					logger.Error().Err(err).Msg("Internal error occurred")
					return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
						"error": "Internal server error",
						"code":  string(errors.CodeInternal),
					})
				}
			},
		})

		app.Use(middleware.ObservabilityMiddleware(obs, securityMetrics, nil))

		// Route that throws different types of errors
		app.Get("/api/error/:type", func(c *fiber.Ctx) error {
			errorType := c.Params("type")
			correlationID := c.Get(middleware.CorrelationIDHeader, "error-test")

			ctx := c.UserContext()
			ctx, span := obs.CreateSpan(ctx, "error.simulation",
				attribute.String("error.type", errorType),
			)
			defer span.End()

			switch errorType {
			case "validation":
				err := errors.Validation("Simulated validation error").
					WithRequest(correlationID).
					WithContext("field", "test_field")
				span.RecordError(err)
				return err
			case "auth":
				err := errors.Authentication("Simulated auth error").
					WithRequest(correlationID)
				span.RecordError(err)
				return err
			case "internal":
				err := errors.Internal("Simulated internal error").
					WithRequest(correlationID)
				span.RecordError(err)
				return err
			default:
				return c.JSON(fiber.Map{"message": "No error"})
			}
		})

		testCases := []struct {
			errorType      string
			expectedStatus int
			expectedCode   string
		}{
			{"validation", http.StatusBadRequest, string(errors.CodeValidation)},
			{"auth", http.StatusUnauthorized, string(errors.CodeAuthentication)},
			{"internal", http.StatusInternalServerError, string(errors.CodeInternal)},
		}

		for _, tc := range testCases {
			t.Run("Error_Type_"+tc.errorType, func(t *testing.T) {
				req := httptest.NewRequest("GET", "/api/error/"+tc.errorType, nil)
				req.Header.Set(middleware.CorrelationIDHeader, "error-test-"+tc.errorType)

				resp, err := app.Test(req, -1)
				require.NoError(t, err)
				defer resp.Body.Close()

				assert.Equal(t, tc.expectedStatus, resp.StatusCode)

				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)

				var response map[string]interface{}
				err = json.Unmarshal(body, &response)
				require.NoError(t, err)

				assert.Equal(t, tc.expectedCode, response["code"])
			})
		}

		time.Sleep(100 * time.Millisecond)
	})
}
