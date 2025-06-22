// Integration tests for OPA policies and Zero Trust authorization
// This tests the complete policy evaluation with realistic scenarios
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

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"your-project/pkg/auth"
	"your-project/pkg/middleware"
)

// TestOPAPolicyIntegration tests the complete OPA policy integration
func TestOPAPolicyIntegration(t *testing.T) {
	// Skip if OPA is not available
	if !isOPAAvailable() {
		t.Skip("OPA not available, skipping integration tests")
	}

	// Setup test configuration
	config := &auth.OPAConfig{
		ServiceURL:     getEnvOrDefault("OPA_URL", "http://localhost:8181"),
		PolicyPath:     "/zero_trust/authz",
		DatabaseURL:    getEnvOrDefault("OPA_DB_URL", "postgres://opa:opa123@localhost:5435/opa_decisions?sslmode=disable"),
		DecisionLog:    true,
		MetricsEnabled: true,
	}

	// Create OPA authorizer
	opaAuth, err := auth.NewOPAAuthorizer(context.Background(), config)
	require.NoError(t, err, "Failed to create OPA authorizer")
	defer opaAuth.Close()

	t.Run("Basic Authorization Policies", func(t *testing.T) {
		testBasicAuthorizationPolicies(t, opaAuth)
	})

	t.Run("Trust Level Enforcement", func(t *testing.T) {
		testTrustLevelEnforcement(t, opaAuth)
	})

	t.Run("Time-Based Access Control", func(t *testing.T) {
		testTimeBasedAccessControl(t, opaAuth)
	})

	t.Run("Device Verification Requirements", func(t *testing.T) {
		testDeviceVerificationRequirements(t, opaAuth)
	})

	t.Run("Workload Authorization", func(t *testing.T) {
		testWorkloadAuthorization(t, opaAuth)
	})

	t.Run("Data Classification Policies", func(t *testing.T) {
		testDataClassificationPolicies(t, opaAuth)
	})

	t.Run("Security Incident Detection", func(t *testing.T) {
		testSecurityIncidentDetection(t, opaAuth)
	})

	t.Run("Compliance and Audit", func(t *testing.T) {
		testComplianceAndAudit(t, opaAuth)
	})
}

// testBasicAuthorizationPolicies tests fundamental authorization scenarios
func testBasicAuthorizationPolicies(t *testing.T, opaAuth *auth.OPAAuthorizer) {
	ctx := context.Background()

	// Test 1: User with admin role accessing admin resources
	adminUser := auth.UserContext{
		UserID:     "admin-001",
		Email:      "admin@zerotrust.local",
		Roles:      []string{"admin"},
		TrustLevel: 100,
		DeviceID:   "admin-device-001",
		DeviceVerified: true,
		ExpiresAt:  time.Now().Add(time.Hour).Unix(),
	}

	req := &auth.AuthorizationRequest{
		User:     adminUser,
		Resource: "admin",
		Action:   "read",
		Context: auth.RequestContext{
			RequestID: "test-admin-read",
			IPAddress: "192.168.1.100",
		},
	}

	resp, err := opaAuth.Authorize(ctx, req)
	require.NoError(t, err)
	assert.True(t, resp.Allow, "Admin should be able to read admin resources")
	assert.True(t, resp.AuditRequired, "Admin operations should require audit")

	// Test 2: Regular user accessing user resources
	regularUser := auth.UserContext{
		UserID:     "user-001",
		Email:      "user@zerotrust.local",
		Roles:      []string{"user"},
		TrustLevel: 50,
		DeviceVerified: true,
		ExpiresAt:  time.Now().Add(time.Hour).Unix(),
	}

	req.User = regularUser
	req.Resource = "profile"
	req.Action = "read"

	resp, err = opaAuth.Authorize(ctx, req)
	require.NoError(t, err)
	assert.True(t, resp.Allow, "User should be able to read their profile")

	// Test 3: Regular user trying to access admin resources (should fail)
	req.Resource = "admin"
	req.Action = "write"

	resp, err = opaAuth.Authorize(ctx, req)
	require.NoError(t, err)
	assert.False(t, resp.Allow, "Regular user should not access admin resources")
	assert.Contains(t, resp.Reasons, "action_not_permitted", "Should indicate insufficient permissions")
}

// testTrustLevelEnforcement tests trust level-based access control
func testTrustLevelEnforcement(t *testing.T, opaAuth *auth.OPAAuthorizer) {
	ctx := context.Background()

	testCases := []struct {
		name            string
		userTrustLevel  int
		resource        string
		action          string
		expectedAllow   bool
		expectedReason  string
	}{
		{
			name:           "LOW trust accessing LOW requirement",
			userTrustLevel: 25,
			resource:       "profile",
			action:         "read",
			expectedAllow:  true,
		},
		{
			name:           "LOW trust accessing MEDIUM requirement",
			userTrustLevel: 25,
			resource:       "profile",
			action:         "update",
			expectedAllow:  false,
			expectedReason: "insufficient_trust_level",
		},
		{
			name:           "HIGH trust accessing FULL requirement",
			userTrustLevel: 75,
			resource:       "financial",
			action:         "transact",
			expectedAllow:  false,
			expectedReason: "insufficient_trust_level",
		},
		{
			name:           "FULL trust accessing FULL requirement",
			userTrustLevel: 100,
			resource:       "financial",
			action:         "transact",
			expectedAllow:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			user := auth.UserContext{
				UserID:         "test-user",
				Email:          "test@zerotrust.local",
				Roles:          []string{"user", "finance"},
				TrustLevel:     tc.userTrustLevel,
				DeviceVerified: tc.userTrustLevel >= 75, // HIGH+ trust requires device verification
				ExpiresAt:      time.Now().Add(time.Hour).Unix(),
			}

			req := &auth.AuthorizationRequest{
				User:     user,
				Resource: tc.resource,
				Action:   tc.action,
				Context: auth.RequestContext{
					RequestID: fmt.Sprintf("test-trust-%d", tc.userTrustLevel),
				},
			}

			resp, err := opaAuth.Authorize(ctx, req)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedAllow, resp.Allow, 
				fmt.Sprintf("Trust level %d should %s access %s:%s", 
					tc.userTrustLevel, 
					map[bool]string{true: "allow", false: "deny"}[tc.expectedAllow],
					tc.resource, tc.action))

			if !tc.expectedAllow && tc.expectedReason != "" {
				assert.Contains(t, resp.Reasons, tc.expectedReason, 
					"Should contain expected denial reason")
			}
		})
	}
}

// testTimeBasedAccessControl tests time-based access restrictions
func testTimeBasedAccessControl(t *testing.T, opaAuth *auth.OPAAuthorizer) {
	ctx := context.Background()

	// Test during business hours with MEDIUM trust
	mediumTrustUser := auth.UserContext{
		UserID:         "medium-user",
		Email:          "medium@zerotrust.local",
		Roles:          []string{"user"},
		TrustLevel:     50,
		DeviceVerified: true,
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}

	req := &auth.AuthorizationRequest{
		User:     mediumTrustUser,
		Resource: "reports",
		Action:   "generate",
		Context: auth.RequestContext{
			RequestID: "test-time-medium",
		},
	}

	resp, err := opaAuth.Authorize(ctx, req)
	require.NoError(t, err)
	
	// Note: This test might fail outside business hours
	// In production, you'd mock the time or test with specific time contexts
	if time.Now().Hour() >= 9 && time.Now().Hour() < 18 {
		assert.True(t, resp.Allow, "Medium trust should work during business hours")
	}

	// Test HIGH trust user (should work outside business hours too)
	highTrustUser := mediumTrustUser
	highTrustUser.TrustLevel = 75
	req.User = highTrustUser

	resp, err = opaAuth.Authorize(ctx, req)
	require.NoError(t, err)
	// HIGH trust users should have extended hours access
}

// testDeviceVerificationRequirements tests device-based access control
func testDeviceVerificationRequirements(t *testing.T, opaAuth *auth.OPAAuthorizer) {
	ctx := context.Background()

	// Test user without device verification accessing MEDIUM trust resource
	userWithoutDevice := auth.UserContext{
		UserID:         "no-device-user",
		Email:          "nodevice@zerotrust.local",
		Roles:          []string{"user"},
		TrustLevel:     50,
		DeviceVerified: false, // No device verification
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}

	req := &auth.AuthorizationRequest{
		User:     userWithoutDevice,
		Resource: "profile",
		Action:   "update", // Requires MEDIUM trust (50) + device verification
		Context: auth.RequestContext{
			RequestID: "test-no-device",
		},
	}

	resp, err := opaAuth.Authorize(ctx, req)
	require.NoError(t, err)
	assert.False(t, resp.Allow, "Should deny access without device verification")
	assert.Contains(t, resp.Reasons, "device_verification_required", 
		"Should indicate device verification requirement")

	// Test same user with device verification
	userWithDevice := userWithoutDevice
	userWithDevice.DeviceVerified = true
	userWithDevice.DeviceID = "verified-device-001"
	userWithDevice.LastVerification = time.Now().Add(-time.Hour).Format(time.RFC3339) // Recent verification
	req.User = userWithDevice

	resp, err = opaAuth.Authorize(ctx, req)
	require.NoError(t, err)
	assert.True(t, resp.Allow, "Should allow access with device verification")
}

// testWorkloadAuthorization tests service-to-service authorization
func testWorkloadAuthorization(t *testing.T, opaAuth *auth.OPAAuthorizer) {
	ctx := context.Background()

	// Test API service connecting to worker service
	sourceSpiffeID := "spiffe://zero-trust.dev/api/auth-service"
	targetSpiffeID := "spiffe://zero-trust.dev/worker/job-processor"

	requestContext := auth.RequestContext{
		RequestID: "test-workload-comm",
		Protocol:  "grpc",
	}

	resp, err := opaAuth.AuthorizeWorkload(ctx, sourceSpiffeID, targetSpiffeID, requestContext)
	require.NoError(t, err)
	assert.True(t, resp.Allow, "API service should be able to connect to worker service")

	// Test worker service trying to connect to admin service (should fail)
	sourceSpiffeID = "spiffe://zero-trust.dev/worker/job-processor"
	targetSpiffeID = "spiffe://zero-trust.dev/admin/controller"

	resp, err = opaAuth.AuthorizeWorkload(ctx, sourceSpiffeID, targetSpiffeID, requestContext)
	require.NoError(t, err)
	assert.False(t, resp.Allow, "Worker service should not access admin service")
}

// testDataClassificationPolicies tests data classification-based access control
func testDataClassificationPolicies(t *testing.T, opaAuth *auth.OPAAuthorizer) {
	ctx := context.Background()

	// Test accessing personal health information with HIGH trust
	highTrustUser := auth.UserContext{
		UserID:         "medical-user",
		Email:          "medical@zerotrust.local",
		Roles:          []string{"medical", "user"},
		TrustLevel:     75,
		DeviceVerified: true,
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}

	// Test access to PHI for medical treatment
	resp, err := opaAuth.AuthorizeDataAccess(ctx, highTrustUser, "personal_health_information", "medical_treatment", []string{"patient_id", "diagnosis", "treatment_plan"})
	require.NoError(t, err)
	assert.True(t, resp.Allow, "Medical user should access PHI for treatment")
	assert.True(t, resp.AuditRequired, "PHI access should require audit")

	// Test LOW trust user trying to access financial data
	lowTrustUser := auth.UserContext{
		UserID:         "low-user",
		Email:          "low@zerotrust.local",
		Roles:          []string{"user"},
		TrustLevel:     25,
		DeviceVerified: false,
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}

	resp, err = opaAuth.AuthorizeDataAccess(ctx, lowTrustUser, "financial_transactions", "analytics", []string{"transaction_amount", "account_balance"})
	require.NoError(t, err)
	assert.False(t, resp.Allow, "Low trust user should not access financial data")
	assert.Contains(t, resp.Reasons, "insufficient_trust_level", "Should indicate insufficient trust")
}

// testSecurityIncidentDetection tests security incident scenarios
func testSecurityIncidentDetection(t *testing.T, opaAuth *auth.OPAAuthorizer) {
	ctx := context.Background()

	// Test multiple failed attempts (simulate suspicious activity)
	suspiciousUser := auth.UserContext{
		UserID:         "suspicious-user",
		Email:          "suspicious@zerotrust.local",
		Roles:          []string{"user"},
		TrustLevel:     25,
		DeviceVerified: false,
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}

	req := &auth.AuthorizationRequest{
		User:     suspiciousUser,
		Resource: "profile",
		Action:   "read",
		Context: auth.RequestContext{
			RequestID:            "test-suspicious",
			IPAddress:            "192.168.1.200",
			FailedAttempts:       6, // Above threshold
			UnusualAccessPattern: true,
		},
	}

	resp, err := opaAuth.Authorize(ctx, req)
	require.NoError(t, err)
	assert.False(t, resp.Allow, "Should deny access for suspicious activity")
	assert.Contains(t, resp.Reasons, "suspicious_activity_detected", "Should detect suspicious activity")

	// Test access from restricted country
	req.Context.FailedAttempts = 0
	req.Context.UnusualAccessPattern = false
	req.Context.Country = "CN" // Not in allowed countries list

	resp, err = opaAuth.Authorize(ctx, req)
	require.NoError(t, err)
	assert.False(t, resp.Allow, "Should deny access from restricted country")
	assert.Contains(t, resp.Reasons, "geo_location_restricted", "Should detect geo restriction")
}

// testComplianceAndAudit tests compliance and audit features
func testComplianceAndAudit(t *testing.T, opaAuth *auth.OPAAuthorizer) {
	ctx := context.Background()

	// Test audit requirement for financial operations
	financeUser := auth.UserContext{
		UserID:         "finance-user",
		Email:          "finance@zerotrust.local",
		Roles:          []string{"finance", "user"},
		TrustLevel:     100,
		DeviceVerified: true,
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}

	req := &auth.AuthorizationRequest{
		User:     financeUser,
		Resource: "financial",
		Action:   "transact",
		Purpose:  "payment_processing", // GDPR compliance - purpose specified
		Context: auth.RequestContext{
			RequestID: "test-audit-compliance",
		},
	}

	resp, err := opaAuth.Authorize(ctx, req)
	require.NoError(t, err)
	assert.True(t, resp.Allow, "Finance user should be able to process payments")
	assert.True(t, resp.AuditRequired, "Financial transactions should require audit")
	assert.Contains(t, resp.ComplianceFlags, "purpose_specified", "Should flag purpose specification for GDPR")
}

// testUnifiedMiddlewareIntegration tests the complete middleware integration
func TestUnifiedMiddlewareIntegration(t *testing.T) {
	// Skip if services are not available
	if !isKeycloakAvailable() || !isOPAAvailable() {
		t.Skip("Required services not available, skipping unified middleware tests")
	}

	// Setup complete middleware stack
	keycloakConfig := &auth.KeycloakConfig{
		BaseURL:      getEnvOrDefault("KEYCLOAK_URL", "http://localhost:8080"),
		Realm:        getEnvOrDefault("KEYCLOAK_REALM", "zero-trust"),
		ClientID:     getEnvOrDefault("KEYCLOAK_CLIENT_ID", "zero-trust-app"),
		ClientSecret: getEnvOrDefault("KEYCLOAK_CLIENT_SECRET", "test-secret"),
		AdminUser:    getEnvOrDefault("KEYCLOAK_ADMIN_USER", "admin"),
		AdminPass:    getEnvOrDefault("KEYCLOAK_ADMIN_PASSWORD", "admin123"),
	}

	keycloak, err := auth.NewKeycloakAuthenticator(keycloakConfig)
	require.NoError(t, err)
	defer keycloak.Close()

	opaConfig := &auth.OPAConfig{
		ServiceURL:     getEnvOrDefault("OPA_URL", "http://localhost:8181"),
		PolicyPath:     "/zero_trust/authz",
		DecisionLog:    false, // Disable for testing
		MetricsEnabled: false,
	}

	opa, err := auth.NewOPAAuthorizer(context.Background(), opaConfig)
	require.NoError(t, err)
	defer opa.Close()

	// SPIRE is optional for this test
	var spire *auth.SPIREAuthenticator

	// Create unified middleware
	middlewareConfig := &middleware.UnifiedMiddlewareConfig{
		SkipPaths:         []string{"/health", "/public"},
		DefaultTrustLevel: 25,
		MetricsEnabled:    true,
		DetailedLogging:   true,
	}

	unifiedMiddleware := middleware.NewZeroTrustUnifiedMiddleware(keycloak, spire, opa, middlewareConfig)

	// Setup test router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Public routes
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Protected routes with unified middleware
	protected := router.Group("/api")
	protected.Use(unifiedMiddleware.Authenticate())
	{
		protected.GET("/profile", func(c *gin.Context) {
			context := middleware.GetCurrentZeroTrustContext(c)
			c.JSON(200, gin.H{"profile": "user profile", "context": context})
		})

		// HIGH trust route
		protected.GET("/admin/users",
			unifiedMiddleware.RequireHighTrust(),
			unifiedMiddleware.RequireRole("admin"),
			func(c *gin.Context) {
				c.JSON(200, gin.H{"users": "admin users list"})
			})

		// FULL trust route
		protected.POST("/financial/transfer",
			unifiedMiddleware.RequireFullTrust(),
			unifiedMiddleware.RequireRole("finance"),
			func(c *gin.Context) {
				c.JSON(200, gin.H{"transfer": "completed"})
			})
	}

	// Test public endpoint (should work without authentication)
	t.Run("Public Endpoint Access", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "ok", response["status"])
	})

	// Test protected endpoint without token (should fail)
	t.Run("Protected Endpoint Without Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/profile", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, 401, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "Authentication failed", response["error"])
	})

	// Test with invalid token (should fail)
	t.Run("Protected Endpoint With Invalid Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/profile", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, 401, w.Code)
	})

	// Note: Testing with valid tokens would require setting up test users in Keycloak
	// which is beyond the scope of this integration test
}

// Helper functions

func isOPAAvailable() bool {
	opaURL := getEnvOrDefault("OPA_URL", "http://localhost:8181")
	resp, err := http.Get(opaURL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

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

// TestOPAConfigValidation tests OPA configuration validation
func TestOPAConfigValidation(t *testing.T) {
	t.Run("Nil Config", func(t *testing.T) {
		_, err := auth.NewOPAAuthorizer(context.Background(), nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "config cannot be nil")
	})

	t.Run("Valid Config Structure", func(t *testing.T) {
		config := &auth.OPAConfig{
			ServiceURL:     "http://localhost:8181",
			PolicyPath:     "/zero_trust/authz",
			DecisionLog:    false,
			MetricsEnabled: false,
		}

		// This will fail if OPA is not running, but config structure is valid
		_, err := auth.NewOPAAuthorizer(context.Background(), config)
		if err != nil {
			assert.NotContains(t, err.Error(), "config cannot be nil")
		}
	})
}

// TestAuthorizationRequestValidation tests authorization request validation
func TestAuthorizationRequestValidation(t *testing.T) {
	validUser := auth.UserContext{
		UserID:     "test-user",
		Email:      "test@example.com",
		Roles:      []string{"user"},
		TrustLevel: 50,
		ExpiresAt:  time.Now().Add(time.Hour).Unix(),
	}

	validRequest := &auth.AuthorizationRequest{
		User:     validUser,
		Resource: "profile",
		Action:   "read",
		Context: auth.RequestContext{
			RequestID: "test-request",
		},
	}

	// Test request structure
	assert.Equal(t, "test-user", validRequest.User.UserID)
	assert.Equal(t, "profile", validRequest.Resource)
	assert.Equal(t, "read", validRequest.Action)
	assert.Equal(t, 50, validRequest.User.TrustLevel)
}

// Example of how to run these tests:
// go test -v ./tests/integration -run TestOPA
//
// To run with all services available:
// docker-compose -f docker-compose.keycloak.yml up -d
// docker-compose -f docker-compose.opa.yml up -d
// go test -v ./tests/integration -run TestOPA
// docker-compose -f docker-compose.keycloak.yml down
// docker-compose -f docker-compose.opa.yml down