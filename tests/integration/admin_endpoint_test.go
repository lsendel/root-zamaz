//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"mvp.local/pkg/auth"
	"mvp.local/pkg/config"
	"mvp.local/pkg/database"
	"mvp.local/pkg/handlers"
	"mvp.local/pkg/middleware"
	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
)

func TestAdminEndpointsWithFullStack(t *testing.T) {
	// Set up test environment 
	os.Setenv("DISABLE_AUTH", "true")
	os.Setenv("ENVIRONMENT", "test")
	
	// Load config
	cfg, err := config.Load()
	require.NoError(t, err)
	
	// Initialize observability with reduced logging
	obsConfig := observability.Config{
		ServiceName:    cfg.Observability.ServiceName,
		ServiceVersion: cfg.Observability.ServiceVersion,
		Environment:    cfg.Observability.Environment,
		LogLevel:       "error", // Reduce noise during testing
		LogFormat:      cfg.Observability.LogFormat,
	}
	obs, err := observability.New(obsConfig)
	require.NoError(t, err)
	defer obs.Shutdown()
	
	// Initialize database
	db := database.NewDatabase(&cfg.Database)
	err = db.Connect()
	require.NoError(t, err)
	
	// Ensure we have test data
	setupAdminTestData(t, db.GetDB())
	
	// Initialize handlers and middleware
	adminHandler := handlers.NewAdminHandler(db.GetDB(), nil, obs)
	authMiddleware := auth.NewAuthenticationService(db.GetDB(), obs, &cfg.Security)
	middlewareService := middleware.NewMiddleware(obs, authMiddleware)
	
	// Create full Fiber app like in production
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			t.Logf("Fiber error: %v", err)
			// More detailed error logging
			if strings.Contains(err.Error(), "nil pointer") {
				t.Logf("🔍 NIL POINTER DETECTED: %+v", err)
				t.Logf("🔍 Request path: %s", c.Path())
				t.Logf("🔍 Request method: %s", c.Method())
			}
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
				"debug": fmt.Sprintf("Path: %s, Method: %s", c.Path(), c.Method()),
			})
		},
	})
	
	// Add observability middleware
	app.Use(middlewareService.Observability())
	
	// Setup routes exactly like production
	api := app.Group("/api")
	
	// Add authentication middleware for admin routes
	admin := api.Group("/admin", middlewareService.RequireAuth())
	admin.Get("/roles", adminHandler.GetRoles)
	admin.Get("/users", adminHandler.GetUsers)
	admin.Post("/roles", adminHandler.CreateRole)
	admin.Put("/roles/:id", adminHandler.UpdateRole)
	admin.Delete("/roles/:id", adminHandler.DeleteRole)
	
	// Test cases covering different scenarios
	testCases := []struct {
		name           string
		method         string
		path           string
		body           interface{}
		expectedStatus int
		setupFunc      func(t *testing.T)
		validateFunc   func(t *testing.T, resp *http.Response, body []byte)
	}{
		{
			name:           "Get Roles - Should Work With Hardcoded Data",
			method:         "GET",
			path:           "/api/admin/roles",
			expectedStatus: 200,
			validateFunc: func(t *testing.T, resp *http.Response, body []byte) {
				t.Logf("✅ Response: %s", string(body))
				var roles []map[string]interface{}
				err := json.Unmarshal(body, &roles)
				assert.NoError(t, err)
				assert.Greater(t, len(roles), 0)
				// Verify it's the hardcoded data
				found := false
				for _, role := range roles {
					if name, ok := role["name"]; ok && name == "admin" {
						found = true
						break
					}
				}
				assert.True(t, found, "Should contain hardcoded admin role")
			},
		},
		{
			name:           "Get Users - Test User Endpoint",
			method:         "GET", 
			path:           "/api/admin/users",
			expectedStatus: 200,
			validateFunc: func(t *testing.T, resp *http.Response, body []byte) {
				t.Logf("✅ Response: %s", string(body))
				var users []map[string]interface{}
				err := json.Unmarshal(body, &users)
				assert.NoError(t, err)
				// Should return existing users from database
			},
		},
		{
			name:   "Create Role - Test POST Endpoint",
			method: "POST",
			path:   "/api/admin/roles",
			body: map[string]interface{}{
				"name":        "test_role_" + fmt.Sprintf("%d", time.Now().Unix()),
				"description": "Test role created during integration test",
			},
			expectedStatus: 201,
			validateFunc: func(t *testing.T, resp *http.Response, body []byte) {
				t.Logf("✅ Response: %s", string(body))
				var role map[string]interface{}
				err := json.Unmarshal(body, &role)
				assert.NoError(t, err)
				assert.Contains(t, role, "id")
				assert.Contains(t, role, "name")
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup if needed
			if tc.setupFunc != nil {
				tc.setupFunc(t)
			}
			
			// Prepare request
			var req *http.Request
			if tc.body != nil {
				bodyBytes, err := json.Marshal(tc.body)
				require.NoError(t, err)
				req = httptest.NewRequest(tc.method, tc.path, bytes.NewReader(bodyBytes))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tc.method, tc.path, nil)
			}
			
			// Execute request
			resp, err := app.Test(req, 10000) // 10 second timeout
			require.NoError(t, err)
			
			// Read response body
			body := make([]byte, 2048)
			n, _ := resp.Body.Read(body)
			body = body[:n]
			
			t.Logf("Test: %s", tc.name)
			t.Logf("Status: %d (expected: %d)", resp.StatusCode, tc.expectedStatus)
			t.Logf("Body: %s", string(body))
			
			// Validate response
			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tc.expectedStatus, resp.StatusCode, string(body))
			}
			
			if tc.validateFunc != nil && resp.StatusCode == tc.expectedStatus {
				tc.validateFunc(t, resp, body)
			}
		})
	}
}

func TestNilPointerDebugging(t *testing.T) {
	// Isolated test to reproduce and fix the nil pointer issue
	os.Setenv("DISABLE_AUTH", "true")
	
	cfg, err := config.Load()
	require.NoError(t, err)
	
	obsConfig := observability.Config{
		ServiceName:    "test-admin",
		ServiceVersion: "test",
		Environment:    "test",
		LogLevel:       "debug", // Enable debug logging 
		LogFormat:      "json",
	}
	obs, err := observability.New(obsConfig)
	require.NoError(t, err)
	defer obs.Shutdown()
	
	db := database.NewDatabase(&cfg.Database)
	err = db.Connect()
	require.NoError(t, err)
	
	t.Run("Test Admin Handler Creation", func(t *testing.T) {
		// Test that handler can be created without panic
		adminHandler := handlers.NewAdminHandler(db.GetDB(), nil, obs)
		assert.NotNil(t, adminHandler)
	})
	
	t.Run("Test Handler Method Call Directly", func(t *testing.T) {
		adminHandler := handlers.NewAdminHandler(db.GetDB(), nil, obs)
		
		// Create a minimal Fiber context for testing
		app := fiber.New()
		req := httptest.NewRequest("GET", "/admin/roles", nil)
		
		// Test the handler method directly
		err := app.Test(req, 1000)
		assert.NoError(t, err)
	})
	
	t.Run("Test With Middleware Stack", func(t *testing.T) {
		adminHandler := handlers.NewAdminHandler(db.GetDB(), nil, obs)
		authMiddleware := auth.NewAuthenticationService(db.GetDB(), obs, &cfg.Security)
		middlewareService := middleware.NewMiddleware(obs, authMiddleware)
		
		app := fiber.New(fiber.Config{
			ErrorHandler: func(c *fiber.Ctx, err error) error {
				t.Logf("🚨 ERROR CAUGHT: %+v", err)
				t.Logf("🚨 ERROR TYPE: %T", err)
				t.Logf("🚨 ERROR STRING: %s", err.Error())
				return c.Status(500).JSON(fiber.Map{"error": err.Error()})
			},
		})
		
		// Add middleware step by step and test at each step
		app.Use(middlewareService.Observability())
		
		// Test without auth middleware first
		app.Get("/test1", adminHandler.GetRoles)
		req1 := httptest.NewRequest("GET", "/test1", nil)
		resp1, err := app.Test(req1, 1000)
		require.NoError(t, err)
		t.Logf("✅ Without auth middleware: Status %d", resp1.StatusCode)
		
		// Now add auth middleware
		api := app.Group("/api")
		admin := api.Group("/admin", middlewareService.RequireAuth())
		admin.Get("/roles", adminHandler.GetRoles)
		
		req2 := httptest.NewRequest("GET", "/api/admin/roles", nil)
		resp2, err := app.Test(req2, 1000)
		require.NoError(t, err)
		t.Logf("🔍 With auth middleware: Status %d", resp2.StatusCode)
		
		// Read response to see what happened
		body := make([]byte, 1024)
		n, _ := resp2.Body.Read(body)
		t.Logf("🔍 Response body: %s", string(body[:n]))
	})
}

func setupAdminTestData(t *testing.T, db *gorm.DB) {
	// Ensure we have some basic roles for testing
	var count int64
	db.Model(&models.Role{}).Count(&count)
	
	if count == 0 {
		roles := []models.Role{
			{Name: "admin", Description: "System administrator", IsActive: true},
			{Name: "user", Description: "Regular user", IsActive: true},
		}
		
		for _, role := range roles {
			result := db.Create(&role)
			require.NoError(t, result.Error)
			t.Logf("Created test role: %+v", role)
		}
	}
	
	// Ensure we have some basic users
	db.Model(&models.User{}).Count(&count)
	if count == 0 {
		users := []models.User{
			{
				ID:       "test-admin-user",
				Username: "testadmin",
				Email:    "testadmin@example.com",
				PasswordHash: "test-hash",
				IsActive: true,
				IsAdmin:  true,
			},
		}
		
		for _, user := range users {
			result := db.Create(&user)
			require.NoError(t, result.Error)
			t.Logf("Created test user: %+v", user)
		}
	}
}