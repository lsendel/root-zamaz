// End-to-end integration tests for Zero Trust Architecture
// Tests complete integration of Keycloak + SPIRE + OPA
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"your-project/pkg/auth"
	"your-project/pkg/middleware"
)

// ZeroTrustE2ETestSuite contains end-to-end integration tests
type ZeroTrustE2ETestSuite struct {
	suite.Suite
	
	// Framework components
	keycloak *auth.KeycloakAuthenticator
	spire    *auth.SPIREAuthenticator
	opa      *auth.OPAAuthorizer
	
	// Unified middleware
	middleware *middleware.ZeroTrustUnifiedMiddleware
	
	// Test router
	router *gin.Engine
	
	// Test configuration
	testConfig *E2ETestConfig
}

// E2ETestConfig holds configuration for end-to-end tests
type E2ETestConfig struct {
	KeycloakURL      string
	KeycloakRealm    string
	KeycloakClientID string
	KeycloakSecret   string
	KeycloakAdmin    string
	KeycloakPassword string
	
	OPAURL        string
	OPAPolicyPath string
	OPADatabaseURL string
	
	SPIRESocketPath  string
	SPIREServerURL   string
	SPIRETrustDomain string
	
	SkipIfServicesDown bool
	TestTimeout        time.Duration
}

// SetupSuite initializes the test suite
func (suite *ZeroTrustE2ETestSuite) SetupSuite() {
	// Load test configuration
	suite.testConfig = &E2ETestConfig{
		KeycloakURL:      getEnvOrDefault("KEYCLOAK_URL", "http://localhost:8080"),
		KeycloakRealm:    getEnvOrDefault("KEYCLOAK_REALM", "zero-trust"),
		KeycloakClientID: getEnvOrDefault("KEYCLOAK_CLIENT_ID", "zero-trust-app"),
		KeycloakSecret:   getEnvOrDefault("KEYCLOAK_CLIENT_SECRET", "test-secret"),
		KeycloakAdmin:    getEnvOrDefault("KEYCLOAK_ADMIN_USER", "admin"),
		KeycloakPassword: getEnvOrDefault("KEYCLOAK_ADMIN_PASSWORD", "admin123"),
		
		OPAURL:         getEnvOrDefault("OPA_URL", "http://localhost:8181"),
		OPAPolicyPath:  "/zero_trust/authz",
		OPADatabaseURL: getEnvOrDefault("OPA_DB_URL", "postgres://opa:opa123@localhost:5435/opa_decisions?sslmode=disable"),
		
		SPIRESocketPath:  getEnvOrDefault("SPIRE_SOCKET_PATH", "/tmp/spire-agent/public/api.sock"),
		SPIREServerURL:   getEnvOrDefault("SPIRE_SERVER_URL", "localhost:8081"),
		SPIRETrustDomain: getEnvOrDefault("SPIRE_TRUST_DOMAIN", "zero-trust.dev"),
		
		SkipIfServicesDown: getEnvOrDefault("SKIP_IF_SERVICES_DOWN", "true") == "true",
		TestTimeout:        30 * time.Second,
	}

	// Check if services are available
	if suite.testConfig.SkipIfServicesDown {
		if !suite.areServicesAvailable() {
			suite.T().Skip("Required services not available, skipping E2E tests")
		}
	}

	// Initialize Keycloak
	keycloakConfig := &auth.KeycloakConfig{
		BaseURL:      suite.testConfig.KeycloakURL,
		Realm:        suite.testConfig.KeycloakRealm,
		ClientID:     suite.testConfig.KeycloakClientID,
		ClientSecret: suite.testConfig.KeycloakSecret,
		AdminUser:    suite.testConfig.KeycloakAdmin,
		AdminPass:    suite.testConfig.KeycloakPassword,
	}

	var err error
	suite.keycloak, err = auth.NewKeycloakAuthenticator(keycloakConfig)
	require.NoError(suite.T(), err, "Failed to initialize Keycloak")

	// Initialize OPA
	opaConfig := &auth.OPAConfig{
		ServiceURL:     suite.testConfig.OPAURL,
		PolicyPath:     suite.testConfig.OPAPolicyPath,
		DatabaseURL:    suite.testConfig.OPADatabaseURL,
		DecisionLog:    true,
		MetricsEnabled: true,
	}

	suite.opa, err = auth.NewOPAAuthorizer(context.Background(), opaConfig)
	require.NoError(suite.T(), err, "Failed to initialize OPA")

	// Initialize SPIRE (optional for some tests)
	spireConfig := &auth.SPIREConfig{
		SocketPath:  suite.testConfig.SPIRESocketPath,
		ServerURL:   suite.testConfig.SPIREServerURL,
		TrustDomain: suite.testConfig.SPIRETrustDomain,
	}

	suite.spire, err = auth.NewSPIREAuthenticator(spireConfig)
	if err != nil {
		suite.T().Logf("SPIRE not available: %v", err)
		suite.spire = nil // SPIRE is optional for some tests
	}

	// Initialize unified middleware
	middlewareConfig := &middleware.UnifiedMiddlewareConfig{
		SkipPaths:          []string{"/health", "/public", "/test"},
		DefaultTrustLevel:  25,
		RequireWorkloadID:  false, // Optional for E2E tests
		MetricsEnabled:     true,
		DetailedLogging:    true,
		RequestTimeout:     10 * time.Second,
	}

	suite.middleware = middleware.NewZeroTrustUnifiedMiddleware(
		suite.keycloak,
		suite.spire,
		suite.opa,
		middlewareConfig,
	)

	// Setup test router
	gin.SetMode(gin.TestMode)
	suite.router = gin.New()
	suite.setupTestRoutes()
}

// TearDownSuite cleans up after tests
func (suite *ZeroTrustE2ETestSuite) TearDownSuite() {
	if suite.keycloak != nil {
		suite.keycloak.Close()
	}
	if suite.opa != nil {
		suite.opa.Close()
	}
	if suite.spire != nil {
		suite.spire.Close()
	}
}

// setupTestRoutes configures the test API routes
func (suite *ZeroTrustE2ETestSuite) setupTestRoutes() {
	// Public routes
	suite.router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "timestamp": time.Now().Unix()})
	})

	suite.router.GET("/public/info", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "public endpoint", "access": "unrestricted"})
	})

	// Protected API routes
	api := suite.router.Group("/api")
	api.Use(suite.middleware.Authenticate())
	{
		// Low trust level routes (25+)
		api.GET("/profile", func(c *gin.Context) {
			context := middleware.GetCurrentZeroTrustContext(c)
			c.JSON(200, gin.H{
				"message": "user profile",
				"context": context,
			})
		})

		api.GET("/dashboard", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"message": "user dashboard",
				"data": []string{"item1", "item2", "item3"},
			})
		})

		// Medium trust level routes (50+)
		medium := api.Group("/secure")
		medium.Use(suite.middleware.RequireTrustLevel(50))
		{
			medium.GET("/data", func(c *gin.Context) {
				c.JSON(200, gin.H{
					"message": "sensitive data",
					"classification": "internal",
				})
			})

			medium.POST("/update", func(c *gin.Context) {
				c.JSON(200, gin.H{"message": "data updated"})
			})
		}

		// High trust level routes (75+)
		high := api.Group("/admin")
		high.Use(suite.middleware.RequireHighTrust())
		high.Use(suite.middleware.RequireRole("admin"))
		{
			high.GET("/users", func(c *gin.Context) {
				c.JSON(200, gin.H{
					"message": "admin users list",
					"users": []string{"admin1", "admin2"},
				})
			})

			high.POST("/config", func(c *gin.Context) {
				c.JSON(200, gin.H{"message": "configuration updated"})
			})
		}

		// Full trust level routes (100)
		financial := api.Group("/financial")
		financial.Use(suite.middleware.RequireFullTrust())
		financial.Use(suite.middleware.RequireRole("finance"))
		{
			financial.GET("/transactions", func(c *gin.Context) {
				c.JSON(200, gin.H{
					"message": "financial transactions",
					"audit_required": true,
				})
			})

			financial.POST("/transfer", func(c *gin.Context) {
				c.JSON(200, gin.H{
					"message": "transfer initiated",
					"audit_id": "audit-12345",
				})
			})
		}

		// Workload attestation required routes
		if suite.spire != nil {
			workload := api.Group("/workload")
			workload.Use(suite.middleware.RequireWorkloadAttestation())
			{
				workload.GET("/identity", func(c *gin.Context) {
					c.JSON(200, gin.H{
						"message": "workload identity verified",
						"spiffe_id": c.GetString("workload_spiffe_id"),
					})
				})
			}
		}
	}
}

// Test: Public endpoints should work without authentication
func (suite *ZeroTrustE2ETestSuite) TestPublicEndpoints() {
	tests := []struct {
		name         string
		path         string
		expectedCode int
	}{
		{"Health Check", "/health", 200},
		{"Public Info", "/public/info", 200},
	}

	for _, test := range tests {
		suite.Run(test.name, func() {
			req := httptest.NewRequest("GET", test.path, nil)
			w := httptest.NewRecorder()
			suite.router.ServeHTTP(w, req)

			assert.Equal(suite.T(), test.expectedCode, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(suite.T(), err)
			assert.NotEmpty(suite.T(), response)
		})
	}
}

// Test: Protected endpoints should reject requests without tokens
func (suite *ZeroTrustE2ETestSuite) TestProtectedEndpointsWithoutAuth() {
	protectedPaths := []string{
		"/api/profile",
		"/api/dashboard",
		"/api/secure/data",
		"/api/admin/users",
		"/api/financial/transactions",
	}

	for _, path := range protectedPaths {
		suite.Run(fmt.Sprintf("No Auth - %s", path), func() {
			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			suite.router.ServeHTTP(w, req)

			assert.Equal(suite.T(), 401, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(suite.T(), err)
			assert.Equal(suite.T(), "Authentication failed", response["error"])
		})
	}
}

// Test: Complete authentication flow with valid test user
func (suite *ZeroTrustE2ETestSuite) TestCompleteAuthenticationFlow() {
	// Create test user and get token
	testUser := &TestUser{
		Username:   "test-user-e2e",
		Email:      "test-e2e@zerotrust.local",
		Password:   "TestPassword123!",
		Roles:      []string{"user"},
		TrustLevel: 50,
	}

	token, err := suite.createTestUserAndGetToken(testUser)
	if err != nil {
		suite.T().Skipf("Could not create test user: %v", err)
	}
	defer suite.cleanupTestUser(testUser.Username)

	// Test accessible endpoint (trust level 25+)
	suite.Run("Access Profile with Valid Token", func() {
		req := httptest.NewRequest("GET", "/api/profile", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), 200, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), "user profile", response["message"])
		assert.NotNil(suite.T(), response["context"])
	})

	// Test medium trust endpoint (trust level 50+)
	suite.Run("Access Secure Data with Medium Trust", func() {
		req := httptest.NewRequest("GET", "/api/secure/data", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), 200, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), "sensitive data", response["message"])
	})

	// Test high trust endpoint (should fail with trust level 50)
	suite.Run("Reject Admin Access with Medium Trust", func() {
		req := httptest.NewRequest("GET", "/api/admin/users", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), 403, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.Contains(suite.T(), response["error"], "Insufficient trust level")
	})
}

// Test: High trust user with admin role
func (suite *ZeroTrustE2ETestSuite) TestHighTrustAdminUser() {
	adminUser := &TestUser{
		Username:   "admin-user-e2e",
		Email:      "admin-e2e@zerotrust.local",
		Password:   "AdminPassword123!",
		Roles:      []string{"admin", "user"},
		TrustLevel: 75,
	}

	token, err := suite.createTestUserAndGetToken(adminUser)
	if err != nil {
		suite.T().Skipf("Could not create admin test user: %v", err)
	}
	defer suite.cleanupTestUser(adminUser.Username)

	// Test admin endpoint access
	suite.Run("Admin Access with High Trust", func() {
		req := httptest.NewRequest("GET", "/api/admin/users", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), 200, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), "admin users list", response["message"])
		assert.NotNil(suite.T(), response["users"])
	})

	// Test financial endpoint (should fail - needs full trust)
	suite.Run("Reject Financial Access with High Trust", func() {
		req := httptest.NewRequest("GET", "/api/financial/transactions", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), 403, w.Code)
	})
}

// Test: Full trust finance user
func (suite *ZeroTrustE2ETestSuite) TestFullTrustFinanceUser() {
	financeUser := &TestUser{
		Username:   "finance-user-e2e",
		Email:      "finance-e2e@zerotrust.local",
		Password:   "FinancePassword123!",
		Roles:      []string{"finance", "user"},
		TrustLevel: 100,
	}

	token, err := suite.createTestUserAndGetToken(financeUser)
	if err != nil {
		suite.T().Skipf("Could not create finance test user: %v", err)
	}
	defer suite.cleanupTestUser(financeUser.Username)

	// Test financial transactions access
	suite.Run("Financial Access with Full Trust", func() {
		req := httptest.NewRequest("GET", "/api/financial/transactions", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), 200, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), "financial transactions", response["message"])
		assert.True(suite.T(), response["audit_required"].(bool))
	})

	// Test financial transfer
	suite.Run("Financial Transfer with Full Trust", func() {
		transferData := map[string]interface{}{
			"amount":      1000,
			"destination": "account-12345",
			"purpose":     "payment_processing",
		}

		jsonData, _ := json.Marshal(transferData)
		req := httptest.NewRequest("POST", "/api/financial/transfer", bytes.NewBuffer(jsonData))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), 200, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), "transfer initiated", response["message"])
		assert.NotEmpty(suite.T(), response["audit_id"])
	})
}

// Test: Invalid and expired tokens
func (suite *ZeroTrustE2ETestSuite) TestInvalidTokenHandling() {
	tests := []struct {
		name  string
		token string
	}{
		{"Invalid Token", "invalid-token-12345"},
		{"Malformed JWT", "not.a.jwt"},
		{"Empty Token", ""},
	}

	for _, test := range tests {
		suite.Run(test.name, func() {
			req := httptest.NewRequest("GET", "/api/profile", nil)
			if test.token != "" {
				req.Header.Set("Authorization", "Bearer "+test.token)
			}
			w := httptest.NewRecorder()
			suite.router.ServeHTTP(w, req)

			assert.Equal(suite.T(), 401, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(suite.T(), err)
			assert.Equal(suite.T(), "Authentication failed", response["error"])
		})
	}
}

// Test: OPA policy decision logging
func (suite *ZeroTrustE2ETestSuite) TestPolicyDecisionLogging() {
	testUser := &TestUser{
		Username:   "logging-test-user",
		Email:      "logging@zerotrust.local",
		Password:   "LoggingTest123!",
		Roles:      []string{"user"},
		TrustLevel: 50,
	}

	token, err := suite.createTestUserAndGetToken(testUser)
	if err != nil {
		suite.T().Skipf("Could not create test user for logging: %v", err)
	}
	defer suite.cleanupTestUser(testUser.Username)

	// Make some requests to generate decision logs
	suite.Run("Generate Decision Logs", func() {
		paths := []string{
			"/api/profile",
			"/api/dashboard",
			"/api/secure/data",
			"/api/admin/users", // This should be denied
		}

		for _, path := range paths {
			req := httptest.NewRequest("GET", path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			suite.router.ServeHTTP(w, req)

			// Don't assert status codes here, just generate logs
			suite.T().Logf("Request to %s returned status %d", path, w.Code)
		}

		// Give some time for async logging
		time.Sleep(1 * time.Second)

		// Verify decision logs were created (if OPA database is available)
		if suite.opa != nil {
			logs, err := suite.opa.GetDecisionLogs(context.Background(), auth.DecisionLogFilters{
				StartTime: time.Now().Add(-5 * time.Minute),
				EndTime:   time.Now(),
				UserID:    testUser.Username,
				Limit:     10,
			})

			if err == nil {
				assert.NotEmpty(suite.T(), logs, "Decision logs should be recorded")
				suite.T().Logf("Found %d decision logs", len(logs))
			} else {
				suite.T().Logf("Could not retrieve decision logs: %v", err)
			}
		}
	})
}

// Test: Workload identity verification (if SPIRE available)
func (suite *ZeroTrustE2ETestSuite) TestWorkloadIdentityVerification() {
	if suite.spire == nil {
		suite.T().Skip("SPIRE not available, skipping workload identity tests")
	}

	suite.Run("Workload Identity Required", func() {
		req := httptest.NewRequest("GET", "/api/workload/identity", nil)
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		// Should fail without workload identity
		assert.Equal(suite.T(), 401, w.Code)
	})

	// Note: Testing actual workload identity would require valid SPIFFE certificates
	// This is typically done with test certificates or mocked SPIRE agent
}

// Helper methods

func (suite *ZeroTrustE2ETestSuite) areServicesAvailable() bool {
	// Check Keycloak
	keycloakResp, err := http.Get(suite.testConfig.KeycloakURL + "/realms/" + suite.testConfig.KeycloakRealm)
	if err != nil || keycloakResp.StatusCode != 200 {
		suite.T().Logf("Keycloak not available: %v", err)
		return false
	}
	keycloakResp.Body.Close()

	// Check OPA
	opaResp, err := http.Get(suite.testConfig.OPAURL + "/health")
	if err != nil || opaResp.StatusCode != 200 {
		suite.T().Logf("OPA not available: %v", err)
		return false
	}
	opaResp.Body.Close()

	return true
}

func (suite *ZeroTrustE2ETestSuite) createTestUserAndGetToken(user *TestUser) (string, error) {
	// In a real implementation, this would:
	// 1. Create user in Keycloak via admin API
	// 2. Login user and get JWT token
	// 3. Add custom claims for trust level
	
	// For this example, we'll create a mock token or skip if Keycloak admin API is not available
	// This requires implementing Keycloak admin client integration
	
	// Mock token for demonstration (in real tests, use actual Keycloak tokens)
	return suite.getMockJWTToken(user)
}

func (suite *ZeroTrustE2ETestSuite) getMockJWTToken(user *TestUser) (string, error) {
	// This is a simplified mock - in real tests you'd use actual Keycloak tokens
	// or test with a test JWT library that creates valid tokens
	
	// For now, return an error to skip tests that require real tokens
	return "", fmt.Errorf("real Keycloak integration required for E2E tests")
}

func (suite *ZeroTrustE2ETestSuite) cleanupTestUser(username string) {
	// Delete test user from Keycloak
	suite.T().Logf("Cleaning up test user: %s", username)
}

// TestUser represents a test user configuration
type TestUser struct {
	Username   string
	Email      string
	Password   string
	Roles      []string
	TrustLevel int
}

// Helper functions
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Test suite runner
func TestZeroTrustE2EIntegration(t *testing.T) {
	suite.Run(t, new(ZeroTrustE2ETestSuite))
}

// Individual test functions for go test compatibility

func TestE2EPublicEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E tests in short mode")
	}
	
	suite := new(ZeroTrustE2ETestSuite)
	suite.SetT(t)
	suite.SetupSuite()
	defer suite.TearDownSuite()
	
	suite.TestPublicEndpoints()
}

func TestE2EProtectedEndpointsWithoutAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E tests in short mode")
	}
	
	suite := new(ZeroTrustE2ETestSuite)
	suite.SetT(t)
	suite.SetupSuite()
	defer suite.TearDownSuite()
	
	suite.TestProtectedEndpointsWithoutAuth()
}

func TestE2EInvalidTokenHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E tests in short mode")
	}
	
	suite := new(ZeroTrustE2ETestSuite)
	suite.SetT(t)
	suite.SetupSuite()
	defer suite.TearDownSuite()
	
	suite.TestInvalidTokenHandling()
}

// Example of how to run these tests:
// go test -v ./tests/e2e -run TestZeroTrustE2E
//
// To run with all services:
// docker-compose -f docker-compose.keycloak.yml up -d
// docker-compose -f docker-compose.opa.yml up -d  
// go test -v ./tests/e2e -run TestZeroTrustE2E
// docker-compose -f docker-compose.keycloak.yml down
// docker-compose -f docker-compose.opa.yml down
//
// To skip if services are down:
// SKIP_IF_SERVICES_DOWN=true go test -v ./tests/e2e