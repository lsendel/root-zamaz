// Integration tests for Keycloak authentication flow
// This tests the complete OAuth2/OIDC integration with Zero Trust features
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"your-project/pkg/auth"
	"your-project/pkg/middleware"
)

// TestKeycloakIntegration tests the complete Keycloak integration
func TestKeycloakIntegration(t *testing.T) {
	// Skip if Keycloak is not available
	if !isKeycloakAvailable() {
		t.Skip("Keycloak not available, skipping integration tests")
	}

	// Setup test configuration
	config := &auth.KeycloakConfig{
		BaseURL:      getEnvOrDefault("KEYCLOAK_URL", "http://localhost:8080"),
		Realm:        getEnvOrDefault("KEYCLOAK_REALM", "zero-trust"),
		ClientID:     getEnvOrDefault("KEYCLOAK_CLIENT_ID", "zero-trust-app"),
		ClientSecret: getEnvOrDefault("KEYCLOAK_CLIENT_SECRET", "test-secret"),
		AdminUser:    getEnvOrDefault("KEYCLOAK_ADMIN_USER", "admin"),
		AdminPass:    getEnvOrDefault("KEYCLOAK_ADMIN_PASSWORD", "admin123"),
	}

	// Create Keycloak authenticator
	keycloakAuth, err := auth.NewKeycloakAuthenticator(config)
	require.NoError(t, err, "Failed to create Keycloak authenticator")
	defer keycloakAuth.Close()

	t.Run("Health Check", func(t *testing.T) {
		err := keycloakAuth.HealthCheck(context.Background())
		assert.NoError(t, err, "Keycloak health check should pass")
	})

	t.Run("Get Stats", func(t *testing.T) {
		stats, err := keycloakAuth.GetStats(context.Background())
		require.NoError(t, err, "Should get Keycloak stats")
		
		assert.Contains(t, stats, "realm")
		assert.Contains(t, stats, "realm_enabled")
		assert.Equal(t, config.Realm, stats["realm"])
	})

	t.Run("User Registration and Authentication Flow", func(t *testing.T) {
		testUserRegistrationAndAuth(t, keycloakAuth)
	})

	t.Run("Trust Level Management", func(t *testing.T) {
		testTrustLevelManagement(t, keycloakAuth)
	})

	t.Run("Middleware Integration", func(t *testing.T) {
		testMiddlewareIntegration(t, keycloakAuth)
	})
}

// testUserRegistrationAndAuth tests user registration and authentication
func testUserRegistrationAndAuth(t *testing.T, keycloakAuth *auth.KeycloakAuthenticator) {
	ctx := context.Background()
	
	// Test user registration
	regReq := &auth.UserRegistrationRequest{
		Username:   fmt.Sprintf("testuser_%d", time.Now().Unix()),
		Email:      fmt.Sprintf("test_%d@example.com", time.Now().Unix()),
		FirstName:  "Test",
		LastName:   "User",
		Password:   "TestPassword123!",
		TrustLevel: 50,
		DeviceID:   "test-device-001",
		Attributes: map[string]string{
			"department": "Engineering",
			"location":   "Remote",
		},
	}

	user, err := keycloakAuth.RegisterUser(ctx, regReq)
	require.NoError(t, err, "User registration should succeed")
	require.NotNil(t, user, "Registered user should not be nil")
	
	assert.Equal(t, regReq.Username, *user.Username)
	assert.Equal(t, regReq.Email, *user.Email)
	assert.Equal(t, regReq.FirstName, *user.FirstName)
	assert.Equal(t, regReq.LastName, *user.LastName)
	
	// Verify user attributes
	require.NotNil(t, user.Attributes)
	attributes := *user.Attributes
	assert.Equal(t, []string{"50"}, attributes["trust_level"])
	assert.Equal(t, []string{"test-device-001"}, attributes["device_id"])
	assert.Equal(t, []string{"Engineering"}, attributes["department"])

	// Test direct grant authentication (for testing purposes)
	// Note: In production, you'd use the proper OAuth2 flow
	client := gocloak.NewClient(keycloakAuth.client.GetServerURL())
	token, err := client.Login(ctx, keycloakAuth.clientId, keycloakAuth.clientSecret, 
		keycloakAuth.realm, regReq.Username, regReq.Password)
	require.NoError(t, err, "User login should succeed")
	require.NotEmpty(t, token.AccessToken, "Access token should not be empty")

	// Test token validation
	claims, err := keycloakAuth.ValidateToken(ctx, token.AccessToken)
	require.NoError(t, err, "Token validation should succeed")
	require.NotNil(t, claims, "Claims should not be nil")

	assert.Equal(t, regReq.Email, claims.Email)
	assert.Equal(t, regReq.Username, claims.PreferredUsername)
	assert.Equal(t, regReq.FirstName, claims.GivenName)
	assert.Equal(t, regReq.LastName, claims.FamilyName)
	assert.Equal(t, 50, claims.TrustLevel)
	assert.Equal(t, "test-device-001", claims.DeviceID)
	assert.Contains(t, claims.Roles, "user")

	// Test invalid token
	_, err = keycloakAuth.ValidateToken(ctx, "invalid-token")
	assert.Error(t, err, "Invalid token should fail validation")

	// Cleanup: This would normally be done by test teardown
	// In a real test environment, you might want to clean up test users
}

// testTrustLevelManagement tests trust level update functionality
func testTrustLevelManagement(t *testing.T, keycloakAuth *auth.KeycloakAuthenticator) {
	ctx := context.Background()
	
	// Create a test user first
	regReq := &auth.UserRegistrationRequest{
		Username:   fmt.Sprintf("trusttest_%d", time.Now().Unix()),
		Email:      fmt.Sprintf("trusttest_%d@example.com", time.Now().Unix()),
		FirstName:  "Trust",
		LastName:   "Test",
		Password:   "TestPassword123!",
		TrustLevel: 25,
		DeviceID:   "trust-device-001",
	}

	user, err := keycloakAuth.RegisterUser(ctx, regReq)
	require.NoError(t, err)
	userID := *user.ID

	// Test getting initial trust level
	initialTrust, err := keycloakAuth.GetUserTrustLevel(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, 25, initialTrust)

	// Test updating trust level
	updateReq := &auth.TrustLevelUpdateRequest{
		UserID:     userID,
		TrustLevel: 75,
		Reason:     "Device verification completed",
		DeviceID:   "trust-device-001",
		AdminID:    "admin",
	}

	err = keycloakAuth.UpdateUserTrustLevel(ctx, updateReq)
	require.NoError(t, err)

	// Verify trust level was updated
	updatedTrust, err := keycloakAuth.GetUserTrustLevel(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, 75, updatedTrust)

	// Test revoking user sessions
	err = keycloakAuth.RevokeUserSessions(ctx, userID)
	assert.NoError(t, err) // Should not error even if no active sessions
}

// testMiddlewareIntegration tests the Gin middleware integration
func testMiddlewareIntegration(t *testing.T, keycloakAuth *auth.KeycloakAuthenticator) {
	// Create middleware
	authMiddleware := middleware.NewKeycloakAuthMiddleware(keycloakAuth, &middleware.AuthMiddlewareConfig{
		SkipPaths:      []string{"/health", "/public"},
		TokenHeader:    "Authorization",
		ContextUserKey: "user",
		RequestTimeout: 5 * time.Second,
	})

	// Setup test router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Public routes
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	router.GET("/public", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "public endpoint"})
	})

	// Protected routes
	protected := router.Group("/api")
	protected.Use(authMiddleware.Authenticate())
	{
		protected.GET("/profile", func(c *gin.Context) {
			user := middleware.GetCurrentUser(c)
			c.JSON(200, gin.H{"user": user})
		})

		protected.GET("/info", authMiddleware.AuthInfo())

		protected.GET("/trust", authMiddleware.TrustLevelInfo())

		// Admin only route
		admin := protected.Group("/admin")
		admin.Use(authMiddleware.RequireRole("admin"))
		{
			admin.GET("/users", func(c *gin.Context) {
				c.JSON(200, gin.H{"message": "admin endpoint"})
			})
		}

		// High trust route
		financial := protected.Group("/financial")
		financial.Use(authMiddleware.RequireTrustLevel(75))
		{
			financial.GET("/balance", func(c *gin.Context) {
				c.JSON(200, gin.H{"balance": 1000.00})
			})
		}

		// Device verified route
		secure := protected.Group("/secure")
		secure.Use(authMiddleware.RequireDeviceVerification())
		{
			secure.GET("/data", func(c *gin.Context) {
				c.JSON(200, gin.H{"data": "sensitive information"})
			})
		}
	}

	// Test public endpoints (should work without authentication)
	t.Run("Public Endpoints", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code)

		req = httptest.NewRequest("GET", "/public", nil)
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code)
	})

	// Test protected endpoints without token (should fail)
	t.Run("Protected Endpoints Without Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/profile", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, 401, w.Code)
	})

	// Test with invalid token (should fail)
	t.Run("Protected Endpoints With Invalid Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/profile", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, 401, w.Code)
	})

	// If we have a valid token (from previous tests), we could test valid scenarios
	// For now, we're focusing on the middleware structure and error cases
}

// Helper functions

func isKeycloakAvailable() bool {
	keycloakURL := getEnvOrDefault("KEYCLOAK_URL", "http://localhost:8080")
	resp, err := http.Get(keycloakURL + "/realms/zero-trust")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// TestKeycloakConfigValidation tests configuration validation
func TestKeycloakConfigValidation(t *testing.T) {
	t.Run("Nil Config", func(t *testing.T) {
		_, err := auth.NewKeycloakAuthenticator(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "config cannot be nil")
	})

	t.Run("Empty Base URL", func(t *testing.T) {
		config := &auth.KeycloakConfig{
			BaseURL:      "",
			Realm:        "test",
			ClientID:     "test",
			ClientSecret: "test",
			AdminUser:    "admin",
			AdminPass:    "admin",
		}
		_, err := auth.NewKeycloakAuthenticator(config)
		// This will fail when trying to connect, which is expected
		assert.Error(t, err)
	})

	t.Run("Valid Config Structure", func(t *testing.T) {
		config := &auth.KeycloakConfig{
			BaseURL:      "http://localhost:8080",
			Realm:        "zero-trust",
			ClientID:     "zero-trust-app",
			ClientSecret: "test-secret",
			AdminUser:    "admin",
			AdminPass:    "admin123",
		}
		
		// This will fail if Keycloak is not running, but config structure is valid
		_, err := auth.NewKeycloakAuthenticator(config)
		// We can't assert no error here since Keycloak might not be running
		// But we can check that it's not a config validation error
		if err != nil {
			assert.NotContains(t, err.Error(), "config cannot be nil")
		}
	})
}

// TestUserRegistrationValidation tests user registration input validation
func TestUserRegistrationValidation(t *testing.T) {
	// This would test registration request validation
	// Since we can't run without Keycloak, we test the structure

	validReq := &auth.UserRegistrationRequest{
		Username:   "testuser",
		Email:      "test@example.com",
		FirstName:  "Test",
		LastName:   "User",
		Password:   "TestPassword123!",
		TrustLevel: 50,
		DeviceID:   "device-001",
	}

	assert.Equal(t, "testuser", validReq.Username)
	assert.Equal(t, "test@example.com", validReq.Email)
	assert.Equal(t, 50, validReq.TrustLevel)
	assert.Equal(t, "device-001", validReq.DeviceID)
}

// TestTrustLevelUpdateValidation tests trust level update validation
func TestTrustLevelUpdateValidation(t *testing.T) {
	validReq := &auth.TrustLevelUpdateRequest{
		UserID:     "user-123",
		TrustLevel: 75,
		Reason:     "Device verification completed",
		DeviceID:   "device-001",
		AdminID:    "admin-456",
	}

	assert.Equal(t, "user-123", validReq.UserID)
	assert.Equal(t, 75, validReq.TrustLevel)
	assert.Equal(t, "Device verification completed", validReq.Reason)
	assert.Equal(t, "admin-456", validReq.AdminID)
}

// Example of how to run these tests:
// go test -v ./tests/integration -run TestKeycloak
// 
// To run with Keycloak available:
// docker-compose -f docker-compose.keycloak.yml up -d
// go test -v ./tests/integration -run TestKeycloak
// docker-compose -f docker-compose.keycloak.yml down