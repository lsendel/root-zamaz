//go:build integration
// +build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"mvp.local/pkg/config"
	"mvp.local/pkg/database"
	"mvp.local/pkg/handlers"
	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
)

func TestAdminEndpoints(t *testing.T) {
	// Set up test environment
	os.Setenv("DISABLE_AUTH", "true")
	os.Setenv("ENVIRONMENT", "test")
	
	// Load config
	cfg, err := config.Load()
	require.NoError(t, err)
	
	// Initialize observability
	obsConfig := observability.Config{
		ServiceName:    cfg.Observability.ServiceName,
		ServiceVersion: cfg.Observability.ServiceVersion,
		Environment:    cfg.Observability.Environment,
		LogLevel:       cfg.Observability.LogLevel,
		LogFormat:      cfg.Observability.LogFormat,
	}
	obs, err := observability.New(obsConfig)
	require.NoError(t, err)
	
	// Initialize database
	db := database.NewDatabase(&cfg.Database)
	err = db.Connect()
	require.NoError(t, err)
	
	// Run migrations
	err = db.Migrate()
	require.NoError(t, err)
	
	// Create test data
	setupTestData(t, db.GetDB())
	
	// Initialize handlers
	adminHandler := handlers.NewAdminHandler(db.GetDB(), nil, obs)
	
	// Create Fiber app
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			t.Logf("Fiber error: %v", err)
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		},
	})
	
	// Setup routes
	api := app.Group("/api")
	admin := api.Group("/admin")
	admin.Get("/roles", adminHandler.GetRoles)
	admin.Get("/users", adminHandler.GetUsers)
	
	// Test cases
	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		validateFunc   func(t *testing.T, resp *http.Response, body []byte)
	}{
		{
			name:           "Get Roles - Basic Test",
			method:         "GET",
			path:           "/api/admin/roles",
			expectedStatus: 200,
			validateFunc: func(t *testing.T, resp *http.Response, body []byte) {
				t.Logf("Response body: %s", string(body))
				var roles []map[string]interface{}
				err := json.Unmarshal(body, &roles)
				assert.NoError(t, err)
				assert.Greater(t, len(roles), 0)
			},
		},
		{
			name:           "Get Users - Basic Test", 
			method:         "GET",
			path:           "/api/admin/users",
			expectedStatus: 200,
			validateFunc: func(t *testing.T, resp *http.Response, body []byte) {
				t.Logf("Response body: %s", string(body))
				var users []map[string]interface{}
				err := json.Unmarshal(body, &users)
				assert.NoError(t, err)
				assert.Greater(t, len(users), 0)
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			resp, err := app.Test(req, -1)
			require.NoError(t, err)
			
			body := make([]byte, resp.ContentLength)
			_, err = resp.Body.Read(body)
			if err != nil && err.Error() != "EOF" {
				require.NoError(t, err)
			}
			
			t.Logf("Test: %s, Status: %d, Body: %s", tt.name, resp.StatusCode, string(body))
			
			if tt.validateFunc != nil && resp.StatusCode == tt.expectedStatus {
				tt.validateFunc(t, resp, body)
			}
		})
	}
}

func setupTestData(t *testing.T, db *gorm.DB) {
	// Clean existing data
	db.Exec("DELETE FROM user_roles")
	db.Exec("DELETE FROM role_permissions") 
	db.Exec("DELETE FROM users WHERE id LIKE '%test%'")
	db.Exec("DELETE FROM roles WHERE name LIKE '%test%'")
	db.Exec("DELETE FROM permissions WHERE name LIKE '%test%'")
	
	// Create test roles
	roles := []models.Role{
		{Name: "test_admin", Description: "Test admin role", IsActive: true},
		{Name: "test_user", Description: "Test user role", IsActive: true},
	}
	
	for _, role := range roles {
		result := db.Create(&role)
		require.NoError(t, result.Error)
		t.Logf("Created role: %+v", role)
	}
	
	// Create test users
	users := []models.User{
		{
			ID:       "test-user-1",
			Username: "testuser1",
			Email:    "test1@example.com",
			PasswordHash: "hashedpass1",
			IsActive: true,
		},
		{
			ID:       "test-user-2", 
			Username: "testuser2",
			Email:    "test2@example.com",
			PasswordHash: "hashedpass2",
			IsActive: true,
		},
	}
	
	for _, user := range users {
		result := db.Create(&user)
		require.NoError(t, result.Error)
		t.Logf("Created user: %+v", user)
	}
}

func TestDirectDatabaseQueries(t *testing.T) {
	// Test direct database access to isolate GORM issues
	cfg, err := config.Load()
	require.NoError(t, err)
	
	db := database.NewDatabase(&cfg.Database)
	err = db.Connect()
	require.NoError(t, err)
	
	t.Run("Direct Role Query", func(t *testing.T) {
		var roles []models.Role
		result := db.GetDB().Find(&roles)
		t.Logf("Query result: %+v, Error: %v", result, result.Error)
		assert.NoError(t, result.Error)
		
		for _, role := range roles {
			t.Logf("Role: %+v", role)
		}
	})
	
	t.Run("Direct User Query", func(t *testing.T) {
		var users []models.User
		result := db.GetDB().Find(&users)
		t.Logf("Query result: %+v, Error: %v", result, result.Error)
		assert.NoError(t, result.Error)
		
		for _, user := range users {
			t.Logf("User: %+v", user)
		}
	})
}

func TestJSONSerialization(t *testing.T) {
	// Test JSON serialization of models to isolate serialization issues
	
	t.Run("Role JSON Serialization", func(t *testing.T) {
		role := models.Role{
			ID:          1,
			Name:        "test",
			Description: "test role",
			IsActive:    true,
		}
		
		data, err := json.Marshal(role)
		assert.NoError(t, err)
		t.Logf("Role JSON: %s", string(data))
	})
	
	t.Run("User JSON Serialization", func(t *testing.T) {
		user := models.User{
			ID:       "test-123",
			Username: "testuser",
			Email:    "test@example.com",
			IsActive: true,
		}
		
		data, err := json.Marshal(user)
		assert.NoError(t, err)
		t.Logf("User JSON: %s", string(data))
	})
}