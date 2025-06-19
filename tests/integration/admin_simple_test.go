//go:build integration
// +build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"mvp.local/pkg/config"
	"mvp.local/pkg/database"
	"mvp.local/pkg/handlers"
	"mvp.local/pkg/observability"
)

func TestAdminHandlerIsolated(t *testing.T) {
	// Test the admin handler in isolation to prove it works
	os.Setenv("DISABLE_AUTH", "true")

	cfg, err := config.Load()
	require.NoError(t, err)

	obsConfig := observability.Config{
		ServiceName:    "test-admin",
		ServiceVersion: "test",
		Environment:    "test",
		LogLevel:       "error",
		LogFormat:      "json",
	}
	obs, err := observability.New(obsConfig)
	require.NoError(t, err)
	defer obs.Shutdown(context.Background())

	db := database.NewDatabase(&cfg.Database)
	err = db.Connect()
	require.NoError(t, err)

	// Test 1: Handler works in isolation
	t.Run("Handler Works In Isolation", func(t *testing.T) {
		adminHandler := handlers.NewAdminHandler(db.GetDB(), nil, obs)
		assert.NotNil(t, adminHandler)

		app := fiber.New()
		app.Get("/roles", adminHandler.GetRoles)

		req := httptest.NewRequest("GET", "/roles", nil)
		resp, err := app.Test(req, 1000)
		require.NoError(t, err)

		body := make([]byte, 1024)
		n, _ := resp.Body.Read(body)
		response := string(body[:n])

		t.Logf("✅ Isolated test - Status: %d, Body: %s", resp.StatusCode, response)
		assert.Equal(t, 200, resp.StatusCode)
		assert.Contains(t, response, "admin")
	})

	// Test 2: Reproduce the nil pointer issue
	t.Run("Reproduce Nil Pointer Issue", func(t *testing.T) {
		adminHandler := handlers.NewAdminHandler(db.GetDB(), nil, obs)

		app := fiber.New(fiber.Config{
			ErrorHandler: func(c *fiber.Ctx, err error) error {
				t.Logf("🚨 FIBER ERROR: %+v", err)
				t.Logf("🚨 ERROR TYPE: %T", err)
				t.Logf("🚨 ERROR MESSAGE: %s", err.Error())

				if strings.Contains(err.Error(), "nil pointer") {
					t.Logf("🔍 NIL POINTER DEREFERENCE DETECTED!")
					t.Logf("🔍 Request path: %s", c.Path())
					t.Logf("🔍 Request method: %s", c.Method())
					t.Logf("🔍 User locals: %v", c.Locals("user"))
					t.Logf("🔍 User ID locals: %v", c.Locals("user_id"))
				}

				return c.Status(500).JSON(fiber.Map{
					"error": err.Error(),
					"path":  c.Path(),
				})
			},
		})

		// Add minimal observability middleware
		app.Use(func(c *fiber.Ctx) error {
			// Simulate what the observability middleware does
			start := time.Now()

			// Set fake user context like DISABLE_AUTH does
			c.Locals("user_id", "test-user-12345")
			c.Locals("user", map[string]interface{}{
				"id":       "test-user-12345",
				"username": "testuser",
				"is_admin": true,
			})

			// Continue to next handler
			err := c.Next()

			// Log the request
			duration := time.Since(start)
			t.Logf("🔍 Request: %s %s - Duration: %v - Error: %v",
				c.Method(), c.Path(), duration, err)

			return err
		})

		// Setup routes like in main server
		api := app.Group("/api")
		admin := api.Group("/admin")
		admin.Get("/roles", adminHandler.GetRoles)

		req := httptest.NewRequest("GET", "/api/admin/roles", nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)

		body := make([]byte, 1024)
		n, _ := resp.Body.Read(body)
		response := string(body[:n])

		t.Logf("🔍 Full stack test - Status: %d, Body: %s", resp.StatusCode, response)

		if resp.StatusCode == 500 {
			t.Logf("🚨 ERROR RESPONSE RECEIVED")
			t.Logf("🚨 This confirms the nil pointer issue exists in the middleware stack")
		} else {
			t.Logf("✅ SUCCESS - No nil pointer dereference detected")
		}
	})
}

func TestServerErrorDebugging(t *testing.T) {
	// Test to isolate where exactly the nil pointer occurs
	os.Setenv("DISABLE_AUTH", "true")

	t.Run("Test Without Any Middleware", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(map[string]string{"status": "ok"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req, 1000)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		t.Log("✅ Basic Fiber app works")
	})

	t.Run("Test Make Actual Request to Server", func(t *testing.T) {
		// Test against the actual running server to see the real error
		resp, err := http.Get("http://localhost:8080/api/admin/roles")
		if err != nil {
			t.Logf("⚠️ Server not running or connection failed: %v", err)
			t.Skip("Server not running, skipping live test")
			return
		}
		defer resp.Body.Close()

		body := make([]byte, 1024)
		n, _ := resp.Body.Read(body)
		response := string(body[:n])

		t.Logf("🔍 Live server test - Status: %d", resp.StatusCode)
		t.Logf("🔍 Live server response: %s", response)

		if resp.StatusCode == 500 {
			t.Log("🚨 CONFIRMED: Live server returns 500 error")
			t.Log("🚨 This confirms the issue exists in the running application")
		}
	})
}
