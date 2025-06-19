package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"mvp.local/pkg/errors"
	"mvp.local/pkg/testutil"
)

func TestDefaultErrorHandlerConfig(t *testing.T) {
	t.Run("DefaultErrorHandlerConfig_Values", func(t *testing.T) {
		config := DefaultErrorHandlerConfig()

		assert.False(t, config.IncludeStackTrace)
		assert.True(t, config.LogErrors)
		assert.True(t, config.SanitizeErrors)
	})
}

func TestErrorHandlerMiddleware(t *testing.T) {
	t.Run("ErrorHandlerMiddleware_AppError", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)
		errorHandler := ErrorHandlerMiddleware(obs)

		app := fiber.New(fiber.Config{
			ErrorHandler: errorHandler,
		})

		app.Get("/validation-error", func(c *fiber.Ctx) error {
			return errors.Validation("Invalid input provided").
				WithContext("field", "email").
				WithRequest("test-req-123")
		})

		req := httptest.NewRequest("GET", "/validation-error", nil)
		req.Header.Set("X-Request-ID", "test-req-123")

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var response ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		assert.False(t, response.Success)
		assert.Equal(t, string(errors.CodeValidation), string(response.Error.Code))
		assert.Equal(t, "Invalid input provided", response.Error.Message)
		assert.Equal(t, "test-req-123", response.RequestID)
		assert.Equal(t, "/validation-error", response.Path)
		assert.Equal(t, "GET", response.Method)
		assert.WithinDuration(t, time.Now(), response.Timestamp, 5*time.Second)
	})

	t.Run("ErrorHandlerMiddleware_FiberError", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)
		errorHandler := ErrorHandlerMiddleware(obs)

		app := fiber.New(fiber.Config{
			ErrorHandler: errorHandler,
		})

		app.Get("/fiber-error", func(c *fiber.Ctx) error {
			return fiber.NewError(fiber.StatusNotFound, "Resource not found")
		})

		req := httptest.NewRequest("GET", "/fiber-error", nil)

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)

		var response ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		assert.False(t, response.Success)
		assert.Equal(t, string(errors.CodeNotFound), string(response.Error.Code))
		assert.Equal(t, "Resource not found", response.Error.Message)
	})

	t.Run("ErrorHandlerMiddleware_GenericError", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)
		errorHandler := ErrorHandlerMiddleware(obs)

		app := fiber.New(fiber.Config{
			ErrorHandler: errorHandler,
		})

		app.Get("/generic-error", func(c *fiber.Ctx) error {
			return assert.AnError // Generic Go error
		})

		req := httptest.NewRequest("GET", "/generic-error", nil)

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		var response ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		assert.False(t, response.Success)
		assert.Equal(t, string(errors.CodeInternal), string(response.Error.Code))
		assert.Equal(t, "An internal error occurred", response.Error.Message) // Sanitized
	})

	t.Run("ErrorHandlerMiddleware_WithStackTrace", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)
		config := ErrorHandlerConfig{
			IncludeStackTrace: true,
			LogErrors:         true,
			SanitizeErrors:    false,
		}
		errorHandler := ErrorHandlerMiddleware(obs, config)

		app := fiber.New(fiber.Config{
			ErrorHandler: errorHandler,
		})

		app.Get("/stack-trace-error", func(c *fiber.Ctx) error {
			return assert.AnError
		})

		req := httptest.NewRequest("GET", "/stack-trace-error", nil)

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		var response ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		assert.Contains(t, response.Error.Details, "assert.AnError")
	})

	t.Run("ErrorHandlerMiddleware_NoSanitization", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)
		config := ErrorHandlerConfig{
			IncludeStackTrace: false,
			LogErrors:         true,
			SanitizeErrors:    false,
		}
		errorHandler := ErrorHandlerMiddleware(obs, config)

		app := fiber.New(fiber.Config{
			ErrorHandler: errorHandler,
		})

		app.Get("/no-sanitize", func(c *fiber.Ctx) error {
			return errors.Internal("Internal database connection failed").
				WithContext("database", "sensitive_info").
				WithContext("password", "secret123")
		})

		req := httptest.NewRequest("GET", "/no-sanitize", nil)

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		var response ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		// Without sanitization, sensitive context is preserved
		assert.Equal(t, "Internal database connection failed", response.Error.Message)
		assert.Contains(t, response.Error.Context, "database")
		assert.Contains(t, response.Error.Context, "password")
	})

	t.Run("ErrorHandlerMiddleware_RateLimitHeader", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)
		errorHandler := ErrorHandlerMiddleware(obs)

		app := fiber.New(fiber.Config{
			ErrorHandler: errorHandler,
		})

		app.Get("/rate-limit", func(c *fiber.Ctx) error {
			return errors.RateLimit("Too many requests")
		})

		req := httptest.NewRequest("GET", "/rate-limit", nil)

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
		assert.Equal(t, "60", resp.Header.Get("Retry-After"))

		var response ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, string(errors.CodeRateLimit), string(response.Error.Code))
	})

	t.Run("ErrorHandlerMiddleware_CorrelationIDFallback", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)
		errorHandler := ErrorHandlerMiddleware(obs)

		app := fiber.New(fiber.Config{
			ErrorHandler: errorHandler,
		})

		app.Get("/correlation-fallback", func(c *fiber.Ctx) error {
			return errors.Validation("Test error")
		})

		req := httptest.NewRequest("GET", "/correlation-fallback", nil)
		req.Header.Set("X-Correlation-ID", "correlation-123")

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		var response ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, "correlation-123", response.RequestID)
	})
}

func TestStatusCodeMapping(t *testing.T) {
	testCases := []struct {
		errorCode    errors.ErrorCode
		expectedHTTP int
	}{
		{errors.CodeValidation, 400},
		{errors.CodeAuthentication, 401},
		{errors.CodeUnauthorized, 401},
		{errors.CodeAuthorization, 403},
		{errors.CodeForbidden, 403},
		{errors.CodeNotFound, 404},
		{errors.CodeConflict, 409},
		{errors.CodeTimeout, 408},
		{errors.CodeUnavailable, 503},
		{errors.CodeRateLimit, 429},
		{errors.CodeInternal, 500},
	}

	for _, tc := range testCases {
		t.Run(string(tc.errorCode), func(t *testing.T) {
			statusCode := getHTTPStatusCode(tc.errorCode)
			assert.Equal(t, tc.expectedHTTP, statusCode)
		})
	}

	t.Run("UnknownErrorCode", func(t *testing.T) {
		statusCode := getHTTPStatusCode("unknown_code")
		assert.Equal(t, 500, statusCode) // Should default to internal server error
	})
}

func TestReverseStatusCodeMapping(t *testing.T) {
	testCases := []struct {
		httpStatus    int
		expectedError errors.ErrorCode
	}{
		{400, errors.CodeValidation},
		{401, errors.CodeAuthentication},
		{403, errors.CodeAuthorization},
		{404, errors.CodeNotFound},
		{409, errors.CodeConflict},
		{408, errors.CodeTimeout},
		{503, errors.CodeUnavailable},
		{429, errors.CodeRateLimit},
		{500, errors.CodeInternal},
	}

	for _, tc := range testCases {
		t.Run(string(tc.expectedError), func(t *testing.T) {
			errorCode := getErrorCodeFromStatus(tc.httpStatus)
			assert.Equal(t, tc.expectedError, errorCode)
		})
	}

	t.Run("UnknownStatusCode", func(t *testing.T) {
		errorCode := getErrorCodeFromStatus(999)
		assert.Equal(t, errors.CodeInternal, errorCode) // Should default to internal
	})
}

func TestSanitizeError(t *testing.T) {
	t.Run("SanitizeError_ServerError", func(t *testing.T) {
		appErr := &errors.AppError{
			Code:      errors.CodeInternal,
			Message:   "Database connection failed with credentials",
			Details:   "Connection string: postgres://user:pass@localhost",
			Context:   map[string]interface{}{"password": "secret", "field": "username"},
			RequestID: "req-123",
			TenantID:  "tenant-456",
		}

		sanitized := sanitizeError(appErr, 500)

		assert.Equal(t, errors.CodeInternal, sanitized.Code)
		assert.Equal(t, "An internal error occurred", sanitized.Message)
		assert.Empty(t, sanitized.Details)
		assert.Empty(t, sanitized.Context)
		assert.Equal(t, "req-123", sanitized.RequestID)
		assert.Equal(t, "tenant-456", sanitized.TenantID)
	})

	t.Run("SanitizeError_ClientError", func(t *testing.T) {
		appErr := &errors.AppError{
			Code:    errors.CodeValidation,
			Message: "Invalid email format",
			Details: "User provided invalid email",
			Context: map[string]interface{}{
				"field":    "email",
				"password": "secret123",
				"resource": "user",
				"token":    "sensitive_token",
			},
			RequestID: "req-789",
		}

		sanitized := sanitizeError(appErr, 400)

		assert.Equal(t, errors.CodeValidation, sanitized.Code)
		assert.Equal(t, "Invalid email format", sanitized.Message)
		assert.Equal(t, "User provided invalid email", sanitized.Details)
		assert.Equal(t, "req-789", sanitized.RequestID)

		// Should only include safe context keys
		assert.Contains(t, sanitized.Context, "field")
		assert.Contains(t, sanitized.Context, "resource")
		assert.NotContains(t, sanitized.Context, "password")
		assert.NotContains(t, sanitized.Context, "token")
	})
}

func TestConvertFiberError(t *testing.T) {
	t.Run("ConvertFiberError_NotFound", func(t *testing.T) {
		fiberErr := fiber.NewError(fiber.StatusNotFound, "Page not found")
		appErr := convertFiberError(fiberErr)

		assert.Equal(t, errors.CodeNotFound, appErr.Code)
		assert.Equal(t, "Page not found", appErr.Message)
	})

	t.Run("ConvertFiberError_BadRequest", func(t *testing.T) {
		fiberErr := fiber.NewError(fiber.StatusBadRequest, "Invalid request")
		appErr := convertFiberError(fiberErr)

		assert.Equal(t, errors.CodeValidation, appErr.Code)
		assert.Equal(t, "Invalid request", appErr.Message)
	})
}

func TestTransactionContext(t *testing.T) {
	t.Run("SetAndGetTransactionInContext", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			// Mock transaction
			var mockTx *gorm.DB = &gorm.DB{}

			SetTransactionInContext(c, mockTx)
			retrievedTx := GetTransactionFromContext(c)

			assert.Equal(t, mockTx, retrievedTx)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("GetTransactionFromContext_NoTransaction", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			retrievedTx := GetTransactionFromContext(c)
			assert.Nil(t, retrievedTx)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("GetTransactionFromContext_WrongType", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			// Set wrong type in context
			c.Locals(string(TransactionContextKey), "not a transaction")

			retrievedTx := GetTransactionFromContext(c)
			assert.Nil(t, retrievedTx)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestRecoveryMiddleware(t *testing.T) {
	t.Run("RecoveryMiddleware_NormalExecution", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)

		app := fiber.New()
		app.Use(RecoveryMiddleware(obs))
		app.Get("/normal", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "normal execution"})
		})

		req := httptest.NewRequest("GET", "/normal", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("RecoveryMiddleware_Panic", func(t *testing.T) {
		var logBuffer bytes.Buffer
		obs := testutil.SetupTestObservabilityWithWriter(t, &logBuffer)

		app := fiber.New()
		app.Use(RecoveryMiddleware(obs))
		app.Get("/panic", func(c *fiber.Ctx) error {
			panic("intentional panic for testing")
		})

		req := httptest.NewRequest("GET", "/panic", nil)
		req.Header.Set("X-Request-ID", "panic-test-123")

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		var response ErrorResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		require.NoError(t, err)

		assert.False(t, response.Success)
		assert.Equal(t, string(errors.CodeInternal), string(response.Error.Code))
		assert.Equal(t, "An unexpected error occurred", response.Error.Message)
		assert.Equal(t, "System panic recovered", response.Error.Details)
		assert.Equal(t, "panic-test-123", response.RequestID)
		assert.True(t, response.Error.Context["panic"].(bool))

		// Verify panic was logged
		logOutput := logBuffer.String()
		assert.Contains(t, logOutput, "Panic recovered")
		assert.Contains(t, logOutput, "intentional panic for testing")
		assert.Contains(t, logOutput, "stack_trace")
	})

	t.Run("RecoveryMiddleware_PanicWithTransaction", func(t *testing.T) {
		var logBuffer bytes.Buffer
		obs := testutil.SetupTestObservabilityWithWriter(t, &logBuffer)

		app := fiber.New()
		app.Use(RecoveryMiddleware(obs))
		app.Get("/panic-with-tx", func(c *fiber.Ctx) error {
			// Mock transaction that can be rolled back
			mockTx := &gorm.DB{}
			SetTransactionInContext(c, mockTx)

			panic("panic with active transaction")
		})

		req := httptest.NewRequest("GET", "/panic-with-tx", nil)

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		// Verify both panic and transaction rollback were logged
		logOutput := logBuffer.String()
		assert.Contains(t, logOutput, "Panic recovered")
		assert.Contains(t, logOutput, "panic with active transaction")
	})
}

func BenchmarkGetHTTPStatusCode(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = getHTTPStatusCode(errors.CodeValidation)
		_ = getHTTPStatusCode(errors.CodeAuthentication)
		_ = getHTTPStatusCode(errors.CodeInternal)
		_ = getHTTPStatusCode("unknown")
	}
}
