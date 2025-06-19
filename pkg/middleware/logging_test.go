package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"mvp.local/pkg/testutil"
)

func TestLoggingMiddleware(t *testing.T) {
	t.Run("LoggingMiddleware_SuccessfulRequest", func(t *testing.T) {
		// Capture logs
		var logBuffer bytes.Buffer
		obs := testutil.SetupTestObservabilityWithWriter(t, &logBuffer)

		app := fiber.New()
		app.Use(LoggingMiddleware(obs))
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "success"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("User-Agent", "test-agent")
		req.Header.Set("X-Correlation-ID", "test-correlation-123")

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Check that request was logged
		logOutput := logBuffer.String()
		assert.Contains(t, logOutput, "HTTP request")
		assert.Contains(t, logOutput, "GET")
		assert.Contains(t, logOutput, "/test")
		assert.Contains(t, logOutput, "test-agent")
		assert.Contains(t, logOutput, "test-correlation-123")
		assert.Contains(t, logOutput, "200")
	})

	t.Run("LoggingMiddleware_WithError", func(t *testing.T) {
		var logBuffer bytes.Buffer
		obs := testutil.SetupTestObservabilityWithWriter(t, &logBuffer)

		app := fiber.New()
		app.Use(LoggingMiddleware(obs))
		app.Get("/error", func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "internal server error",
			})
		})

		req := httptest.NewRequest("GET", "/error", nil)
		req.Header.Set("X-Correlation-ID", "error-test-456")

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		logOutput := logBuffer.String()
		assert.Contains(t, logOutput, "HTTP request")
		assert.Contains(t, logOutput, "500")
		assert.Contains(t, logOutput, "error-test-456")
	})

	t.Run("LoggingMiddleware_LongRequest", func(t *testing.T) {
		var logBuffer bytes.Buffer
		obs := testutil.SetupTestObservabilityWithWriter(t, &logBuffer)

		app := fiber.New()
		app.Use(LoggingMiddleware(obs))
		app.Get("/slow", func(c *fiber.Ctx) error {
			// Simulate slow request
			time.Sleep(50 * time.Millisecond)
			return c.JSON(fiber.Map{"message": "slow response"})
		})

		req := httptest.NewRequest("GET", "/slow", nil)
		req.Header.Set("X-Correlation-ID", "slow-test-789")

		start := time.Now()
		resp, err := app.Test(req, 1000) // 1 second timeout
		duration := time.Since(start)

		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, duration >= 50*time.Millisecond)

		logOutput := logBuffer.String()
		assert.Contains(t, logOutput, "HTTP request")
		assert.Contains(t, logOutput, "duration")
		assert.Contains(t, logOutput, "slow-test-789")
	})

	t.Run("LoggingMiddleware_PostRequest", func(t *testing.T) {
		var logBuffer bytes.Buffer
		obs := testutil.SetupTestObservabilityWithWriter(t, &logBuffer)

		app := fiber.New()
		app.Use(LoggingMiddleware(obs))
		app.Post("/api/users", func(c *fiber.Ctx) error {
			var body map[string]interface{}
			if err := c.BodyParser(&body); err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "invalid body",
				})
			}
			return c.Status(fiber.StatusCreated).JSON(fiber.Map{
				"message": "user created",
				"id":      "user-123",
			})
		})

		requestBody := map[string]interface{}{
			"email": "test@example.com",
			"name":  "Test User",
		}
		bodyJSON, _ := json.Marshal(requestBody)

		req := httptest.NewRequest("POST", "/api/users", bytes.NewReader(bodyJSON))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Correlation-ID", "post-test-111")

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		logOutput := logBuffer.String()
		assert.Contains(t, logOutput, "HTTP request")
		assert.Contains(t, logOutput, "POST")
		assert.Contains(t, logOutput, "/api/users")
		assert.Contains(t, logOutput, "201")
		assert.Contains(t, logOutput, "post-test-111")
		assert.Contains(t, logOutput, "application/json")
	})

	t.Run("LoggingMiddleware_NoCorrelationID", func(t *testing.T) {
		var logBuffer bytes.Buffer
		obs := testutil.SetupTestObservabilityWithWriter(t, &logBuffer)

		app := fiber.New()
		app.Use(LoggingMiddleware(obs))
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "no correlation"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		// No correlation ID header

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		logOutput := logBuffer.String()
		assert.Contains(t, logOutput, "HTTP request")
		// Should still log without correlation ID
		assert.Contains(t, logOutput, "GET")
		assert.Contains(t, logOutput, "/test")
	})

	t.Run("LoggingMiddleware_LargeResponseBody", func(t *testing.T) {
		var logBuffer bytes.Buffer
		obs := testutil.SetupTestObservabilityWithWriter(t, &logBuffer)

		app := fiber.New()
		app.Use(LoggingMiddleware(obs))
		app.Get("/large", func(c *fiber.Ctx) error {
			// Create large response
			largeData := make([]string, 1000)
			for i := range largeData {
				largeData[i] = "This is a large response item"
			}
			return c.JSON(fiber.Map{
				"data": largeData,
				"size": len(largeData),
			})
		})

		req := httptest.NewRequest("GET", "/large", nil)
		req.Header.Set("X-Correlation-ID", "large-test-222")

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		logOutput := logBuffer.String()
		assert.Contains(t, logOutput, "HTTP request")
		assert.Contains(t, logOutput, "large-test-222")
		assert.Contains(t, logOutput, "bytes") // Should log response size
	})

	t.Run("LoggingMiddleware_HealthCheckEndpoint", func(t *testing.T) {
		var logBuffer bytes.Buffer
		obs := testutil.SetupTestObservabilityWithWriter(t, &logBuffer)

		app := fiber.New()
		app.Use(LoggingMiddleware(obs))
		app.Get("/health", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"status": "healthy"})
		})

		req := httptest.NewRequest("GET", "/health", nil)

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		logOutput := logBuffer.String()
		// Health check endpoints are typically logged at debug level
		// but should still be logged
		assert.Contains(t, logOutput, "/health")
	})

	t.Run("LoggingMiddleware_WithQueryParams", func(t *testing.T) {
		var logBuffer bytes.Buffer
		obs := testutil.SetupTestObservabilityWithWriter(t, &logBuffer)

		app := fiber.New()
		app.Use(LoggingMiddleware(obs))
		app.Get("/search", func(c *fiber.Ctx) error {
			query := c.Query("q", "")
			limit := c.Query("limit", "10")
			return c.JSON(fiber.Map{
				"query":   query,
				"limit":   limit,
				"results": []string{},
			})
		})

		req := httptest.NewRequest("GET", "/search?q=test&limit=20", nil)
		req.Header.Set("X-Correlation-ID", "search-test-333")

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		logOutput := logBuffer.String()
		assert.Contains(t, logOutput, "HTTP request")
		assert.Contains(t, logOutput, "/search")
		assert.Contains(t, logOutput, "search-test-333")
		// Query parameters should be included in the logged URL
		assert.Contains(t, logOutput, "q=test")
		assert.Contains(t, logOutput, "limit=20")
	})

	t.Run("LoggingMiddleware_DifferentMethods", func(t *testing.T) {
		var logBuffer bytes.Buffer
		obs := testutil.SetupTestObservabilityWithWriter(t, &logBuffer)

		app := fiber.New()
		app.Use(LoggingMiddleware(obs))

		app.Get("/get", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"method": "GET"})
		})
		app.Post("/post", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"method": "POST"})
		})
		app.Put("/put", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"method": "PUT"})
		})
		app.Delete("/delete", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"method": "DELETE"})
		})

		methods := []string{"GET", "POST", "PUT", "DELETE"}
		paths := []string{"/get", "/post", "/put", "/delete"}

		for i, method := range methods {
			req := httptest.NewRequest(method, paths[i], nil)
			req.Header.Set("X-Correlation-ID", "method-test-"+method)

			resp, err := app.Test(req)
			require.NoError(t, err)
			resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
		}

		logOutput := logBuffer.String()

		// Verify all methods were logged
		for _, method := range methods {
			assert.Contains(t, logOutput, method)
			assert.Contains(t, logOutput, "method-test-"+method)
		}
	})
}

func TestLoggingMiddleware_JSONLogFormat(t *testing.T) {
	t.Run("LoggingMiddleware_ParseableJSON", func(t *testing.T) {
		var logBuffer bytes.Buffer
		obs := testutil.SetupTestObservabilityWithWriter(t, &logBuffer)

		app := fiber.New()
		app.Use(LoggingMiddleware(obs))
		app.Get("/json-test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"test": "json"})
		})

		req := httptest.NewRequest("GET", "/json-test", nil)
		req.Header.Set("X-Correlation-ID", "json-test-444")

		resp, err := app.Test(req)
		require.NoError(t, err)
		resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		logOutput := logBuffer.String()
		lines := strings.Split(strings.TrimSpace(logOutput), "\n")

		// Find the HTTP request log line
		var requestLogLine string
		for _, line := range lines {
			if strings.Contains(line, "HTTP request") {
				requestLogLine = line
				break
			}
		}

		assert.NotEmpty(t, requestLogLine, "Should find HTTP request log line")

		// Parse as JSON to verify it's valid JSON
		var logEntry map[string]interface{}
		err = json.Unmarshal([]byte(requestLogLine), &logEntry)
		require.NoError(t, err, "Log entry should be valid JSON")

		// Verify expected fields are present
		assert.Equal(t, "HTTP request", logEntry["message"])
		assert.Equal(t, "GET", logEntry["method"])
		assert.Equal(t, "/json-test", logEntry["path"])
		assert.Equal(t, float64(200), logEntry["status_code"])
		assert.Equal(t, "json-test-444", logEntry["correlation_id"])
		assert.Contains(t, logEntry, "duration")
		assert.Contains(t, logEntry, "bytes_written")
	})
}

// Benchmark tests
func BenchmarkLoggingMiddleware(b *testing.B) {
	var logBuffer bytes.Buffer
	obs := testutil.SetupTestObservabilityWithWriter(b, &logBuffer)

	app := fiber.New()
	app.Use(LoggingMiddleware(obs))
	app.Get("/bench", func(c *fiber.Ctx) error {
		return c.SendStatus(200)
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/bench", nil)
			req.Header.Set("X-Correlation-ID", "bench-test")
			_, _ = app.Test(req)
		}
	})
}

func BenchmarkLoggingMiddleware_WithoutCorrelationID(b *testing.B) {
	var logBuffer bytes.Buffer
	obs := testutil.SetupTestObservabilityWithWriter(b, &logBuffer)

	app := fiber.New()
	app.Use(LoggingMiddleware(obs))
	app.Get("/bench", func(c *fiber.Ctx) error {
		return c.SendStatus(200)
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/bench", nil)
			// No correlation ID header
			_, _ = app.Test(req)
		}
	})
}
