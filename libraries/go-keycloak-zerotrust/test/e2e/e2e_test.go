// Package e2e provides end-to-end tests for the Zero Trust library
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/go-keycloak-zerotrust/middleware/gin"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/cache"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/client"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/config"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/plugins"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/zerotrust"
)

// TestSuite holds the test environment
type TestSuite struct {
	T                 *testing.T
	Config            *types.ZeroTrustConfig
	KeycloakClient    types.KeycloakClient
	PluginManager     *plugins.PluginManager
	DeviceService     *zerotrust.DeviceAttestationService
	Router            *gin.Engine
	MockKeycloakServer *httptest.Server
}

// NewTestSuite creates a new test suite
func NewTestSuite(t *testing.T) *TestSuite {
	// Create mock Keycloak server
	mockServer := createMockKeycloakServer()
	
	// Create test configuration
	config := &types.ZeroTrustConfig{
		BaseURL:      mockServer.URL,
		Realm:        "test-realm",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		ZeroTrust: &types.ZeroTrustSettings{
			EnableDeviceAttestation:   true,
			EnableRiskAssessment:     true,
			EnableContinuousAuth:     true,
			DeviceVerificationTTL:    24 * time.Hour,
			TrustDecayInterval:       1 * time.Hour,
			TrustLevelThresholds: types.TrustLevelThresholds{
				Read:   25,
				Write:  50,
				Admin:  75,
				Delete: 90,
			},
			RiskThresholds: types.RiskThresholds{
				Low:      25,
				Medium:   50,
				High:     75,
				Critical: 90,
			},
		},
		Cache: &types.CacheConfig{
			Type: "memory",
		},
		Observability: &types.ObservabilityConfig{
			Logging: types.LoggingConfig{
				Level: "debug",
			},
			Metrics: types.MetricsConfig{
				Enabled: true,
			},
		},
	}

	// Initialize components
	keycloakClient, _ := client.NewKeycloakClient(config)
	
	deviceStorage := NewMockDeviceStorage()
	deviceService := zerotrust.NewDeviceAttestationService(config, deviceStorage)
	
	pluginConfig := &plugins.PluginConfig{
		EnabledPlugins: []string{"logging", "metrics", "security_audit"},
		Timeout:        30 * time.Second,
	}
	pluginManager := plugins.NewPluginManager(pluginConfig)
	
	// Create router with middleware
	router := gin.New()
	middleware := ginmiddleware.NewKeycloakMiddleware(keycloakClient)
	
	// Setup routes
	setupTestRoutes(router, middleware)
	
	return &TestSuite{
		T:                  t,
		Config:             config,
		KeycloakClient:     keycloakClient,
		PluginManager:      pluginManager,
		DeviceService:      deviceService,
		Router:             router,
		MockKeycloakServer: mockServer,
	}
}

// Cleanup cleans up test resources
func (s *TestSuite) Cleanup() {
	if s.MockKeycloakServer != nil {
		s.MockKeycloakServer.Close()
	}
	if s.KeycloakClient != nil {
		s.KeycloakClient.Close()
	}
	if s.PluginManager != nil {
		s.PluginManager.Shutdown(context.Background())
	}
}

// TestCompleteWorkflow tests the complete Zero Trust authentication workflow
func TestCompleteWorkflow(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	ctx := context.Background()

	// Step 1: Device Registration
	t.Run("Device Registration", func(t *testing.T) {
		nonce, err := suite.DeviceService.GenerateNonce()
		require.NoError(t, err)

		attestation := &zerotrust.DeviceAttestation{
			DeviceID:          "test-device-001",
			UserID:            "test-user-123",
			Platform:          "ios",
			DeviceFingerprint: "ios-fingerprint-abc123",
			HardwareData: map[string]interface{}{
				"secure_enclave": true,
				"touch_id":       true,
			},
			SoftwareData: map[string]interface{}{
				"jailbroken":  false,
				"os_version":  "iOS 16.0",
			},
			Timestamp: time.Now(),
			Nonce:     nonce,
			Signature: "test-signature",
		}

		result, err := suite.DeviceService.AttestDevice(ctx, attestation)
		require.NoError(t, err)
		assert.True(t, result.IsValid)
		assert.GreaterOrEqual(t, result.TrustScore, 70)
	})

	// Step 2: Token Validation
	t.Run("Token Validation", func(t *testing.T) {
		// Get test token
		token := getTestToken()
		
		// Validate token
		claims, err := suite.KeycloakClient.ValidateToken(ctx, token)
		require.NoError(t, err)
		assert.Equal(t, "test-user-123", claims.UserID)
		assert.GreaterOrEqual(t, claims.TrustLevel, 50)
	})

	// Step 3: API Access with Middleware
	t.Run("API Access", func(t *testing.T) {
		token := getTestToken()

		// Test read access (requires trust level 25)
		req, _ := http.NewRequest("GET", "/api/data", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		
		w := httptest.NewRecorder()
		suite.Router.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)

		// Test admin access (requires trust level 75)
		req, _ = http.NewRequest("POST", "/api/admin", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		
		w = httptest.NewRecorder()
		suite.Router.ServeHTTP(w, req)
		
		// Should fail if trust level is insufficient
		if getTestTrustLevel() < 75 {
			assert.Equal(t, http.StatusForbidden, w.Code)
		} else {
			assert.Equal(t, http.StatusOK, w.Code)
		}
	})

	// Step 4: Risk Assessment
	t.Run("Risk Assessment", func(t *testing.T) {
		// Create risk assessment engine
		riskEngine := zerotrust.NewRiskAssessmentEngine(
			suite.Config,
			NewMockUserBehaviorAnalyzer(),
			zerotrust.NewGeolocationService(suite.Config, NewMockUserBaselineStorage()),
			NewMockThreatIntelligenceService(),
			suite.DeviceService,
			NewMockBaselineStorage(),
		)

		session := &zerotrust.SessionContext{
			UserID:        "test-user-123",
			IPAddress:     "192.168.1.100",
			UserAgent:     "Mozilla/5.0 Safari",
			DeviceID:      "test-device-001",
			Timestamp:     time.Now(),
			RequestPath:   "/api/data",
			RequestMethod: "GET",
			AuthMethod:    "mfa",
		}

		result, err := riskEngine.AssessRisk(ctx, session)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.LessOrEqual(t, result.OverallRiskScore, 50) // Low to medium risk expected
	})

	// Step 5: Plugin Execution
	t.Run("Plugin Execution", func(t *testing.T) {
		// Register test plugin
		testPlugin := &TestSecurityPlugin{}
		err := suite.PluginManager.RegisterPlugin(ctx, testPlugin)
		require.NoError(t, err)

		// Execute auth hook
		authData := map[string]interface{}{
			"user_id":    "test-user-123",
			"ip_address": "192.168.1.100",
			"success":    true,
		}

		err = suite.PluginManager.ExecuteHook(ctx, plugins.HookPostAuth, authData)
		assert.NoError(t, err)
		assert.Equal(t, 1, testPlugin.ExecutionCount)
	})

	// Step 6: Continuous Verification
	t.Run("Continuous Verification", func(t *testing.T) {
		trustEngine := zerotrust.NewTrustEngine(suite.Config)

		// Initial trust score
		input := &zerotrust.TrustCalculationInput{
			UserID: "test-user-123",
			VerificationResult: &zerotrust.VerificationResult{
				IsValid:           true,
				TrustScore:        80,
				VerificationLevel: "hardware",
			},
			AuthenticationMethod: "biometric",
			PreviousTrustLevel:   75,
		}

		initialScore := trustEngine.CalculateTrustScore(ctx, input)
		assert.GreaterOrEqual(t, initialScore, 75)

		// Apply trust decay after 2 hours
		decayedScore := trustEngine.DecayTrustScore(initialScore, 2*time.Hour)
		assert.Less(t, decayedScore, initialScore)
		assert.GreaterOrEqual(t, decayedScore, 25) // Should maintain minimum trust
	})
}

// TestHighLoadScenario tests the system under high load
func TestHighLoadScenario(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	concurrentRequests := 100
	requestsPerUser := 10

	// Create channels for coordination
	startChan := make(chan struct{})
	errorChan := make(chan error, concurrentRequests*requestsPerUser)
	doneChan := make(chan struct{}, concurrentRequests)

	// Launch concurrent users
	for i := 0; i < concurrentRequests; i++ {
		go func(userID int) {
			defer func() { doneChan <- struct{}{} }()
			
			// Wait for start signal
			<-startChan

			// Perform multiple requests per user
			for j := 0; j < requestsPerUser; j++ {
				token := fmt.Sprintf("test-token-user-%d", userID)
				
				req, _ := http.NewRequest("GET", "/api/data", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				
				w := httptest.NewRecorder()
				suite.Router.ServeHTTP(w, req)
				
				if w.Code != http.StatusOK && w.Code != http.StatusUnauthorized {
					errorChan <- fmt.Errorf("unexpected status code: %d", w.Code)
				}
			}
		}(i)
	}

	// Start all requests simultaneously
	startTime := time.Now()
	close(startChan)

	// Wait for all requests to complete
	for i := 0; i < concurrentRequests; i++ {
		<-doneChan
	}
	duration := time.Since(startTime)

	// Check for errors
	close(errorChan)
	var errors []error
	for err := range errorChan {
		errors = append(errors, err)
	}

	assert.Empty(t, errors, "High load test encountered errors")
	
	// Performance assertions
	totalRequests := concurrentRequests * requestsPerUser
	requestsPerSecond := float64(totalRequests) / duration.Seconds()
	
	t.Logf("High load test completed: %d requests in %v (%.2f req/s)", 
		totalRequests, duration, requestsPerSecond)
	
	// Assert minimum performance threshold
	assert.Greater(t, requestsPerSecond, 100.0, "Performance below threshold")
}

// TestConfigurationIntegration tests configuration system integration
func TestConfigurationIntegration(t *testing.T) {
	// Test environment variable configuration
	t.Run("Environment Config", func(t *testing.T) {
		os.Setenv("ZEROTRUST_KEYCLOAK_BASE_URL", "https://test.keycloak.com")
		os.Setenv("ZEROTRUST_KEYCLOAK_REALM", "test-realm")
		os.Setenv("ZEROTRUST_ZERO_TRUST_TRUST_LEVEL_THRESHOLDS_ADMIN", "80")
		defer func() {
			os.Unsetenv("ZEROTRUST_KEYCLOAK_BASE_URL")
			os.Unsetenv("ZEROTRUST_KEYCLOAK_REALM")
			os.Unsetenv("ZEROTRUST_ZERO_TRUST_TRUST_LEVEL_THRESHOLDS_ADMIN")
		}()

		cfg, err := config.LoadFromEnv()
		require.NoError(t, err)
		assert.Equal(t, "https://test.keycloak.com", cfg.BaseURL)
		assert.Equal(t, "test-realm", cfg.Realm)
		assert.Equal(t, 80, cfg.ZeroTrust.TrustLevelThresholds.Admin)
	})

	// Test configuration validation
	t.Run("Config Validation", func(t *testing.T) {
		loader := config.NewConfigLoader(config.LoaderOptions{
			ValidateOnLoad: true,
		})

		// Invalid configuration
		invalidConfig := &types.ZeroTrustConfig{
			BaseURL: "not-a-url",
			Realm:   "",
		}

		err := loader.ValidateConfig(invalidConfig)
		assert.Error(t, err)

		// Valid configuration
		validConfig := &types.ZeroTrustConfig{
			BaseURL:      "https://keycloak.example.com",
			Realm:        "valid-realm",
			ClientID:     "client-id",
			ClientSecret: "secret",
			ZeroTrust: &types.ZeroTrustSettings{
				TrustLevelThresholds: types.TrustLevelThresholds{
					Read:   25,
					Write:  50,
					Admin:  75,
					Delete: 90,
				},
			},
		}

		err = loader.ValidateConfig(validConfig)
		assert.NoError(t, err)
	})

	// Test configuration transformation
	t.Run("Config Transformation", func(t *testing.T) {
		loader := config.NewConfigLoader(config.LoaderOptions{
			Environment:     "production",
			TransformOnLoad: true,
		})

		baseConfig := &types.ZeroTrustConfig{
			BaseURL:      "http://localhost:8080",
			Realm:        "test",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}

		// Environment transformer should enhance security for production
		transformer := &config.EnvironmentTransformer{}
		transformedConfig, err := transformer.Transform(baseConfig)
		require.NoError(t, err)
		
		// Production should have higher trust thresholds
		assert.GreaterOrEqual(t, transformedConfig.ZeroTrust.TrustLevelThresholds.Admin, 85)
		assert.GreaterOrEqual(t, transformedConfig.ZeroTrust.TrustLevelThresholds.Delete, 95)
	})
}

// TestMultiLanguageIntegration tests Java and Python client integration
func TestMultiLanguageIntegration(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	// This test would typically interact with actual Java/Python services
	// For unit testing, we simulate the expected behavior

	t.Run("Java Client Simulation", func(t *testing.T) {
		// Simulate Java client request
		javaHeaders := map[string]string{
			"User-Agent":       "Java-Client/1.0",
			"X-Client-Version": "1.0.0",
			"Authorization":    "Bearer " + getTestToken(),
		}

		req, _ := http.NewRequest("POST", "/api/java/validate", nil)
		for k, v := range javaHeaders {
			req.Header.Set(k, v)
		}

		w := httptest.NewRecorder()
		suite.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Python Client Simulation", func(t *testing.T) {
		// Simulate Python client request
		pythonHeaders := map[string]string{
			"User-Agent":       "Python-Client/1.0",
			"X-Client-Version": "1.0.0",
			"Authorization":    "Bearer " + getTestToken(),
		}

		req, _ := http.NewRequest("GET", "/api/python/user", nil)
		for k, v := range pythonHeaders {
			req.Header.Set(k, v)
		}

		w := httptest.NewRecorder()
		suite.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestErrorScenarios tests various error conditions
func TestErrorScenarios(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()

	ctx := context.Background()

	t.Run("Invalid Token", func(t *testing.T) {
		_, err := suite.KeycloakClient.ValidateToken(ctx, "invalid-token")
		assert.Error(t, err)
	})

	t.Run("Expired Token", func(t *testing.T) {
		expiredToken := getExpiredTestToken()
		_, err := suite.KeycloakClient.ValidateToken(ctx, expiredToken)
		assert.Error(t, err)
	})

	t.Run("Invalid Device Attestation", func(t *testing.T) {
		attestation := &zerotrust.DeviceAttestation{
			DeviceID: "", // Invalid: empty device ID
			UserID:   "test-user",
			Platform: "android",
		}

		_, err := suite.DeviceService.AttestDevice(ctx, attestation)
		assert.Error(t, err)
	})

	t.Run("Rate Limiting", func(t *testing.T) {
		// Enable rate limiting plugin
		rateLimitPlugin := &plugins.RateLimitPlugin{}
		rateLimitPlugin.Initialize(ctx, map[string]interface{}{
			"enabled":     true,
			"rate_limit":  5,
			"time_window": "1m",
		})

		// Make requests until rate limited
		token := getTestToken()
		var lastStatus int
		
		for i := 0; i < 10; i++ {
			req, _ := http.NewRequest("GET", "/api/data", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Real-IP", "192.168.1.100")
			
			pluginReq := &plugins.PluginRequest{
				Headers: req.Header,
			}
			
			resp, err := rateLimitPlugin.ProcessRequest(ctx, pluginReq)
			require.NoError(t, err)
			
			lastStatus = resp.StatusCode
			if resp.StatusCode == 429 {
				break
			}
		}
		
		assert.Equal(t, 429, lastStatus, "Rate limiting should trigger")
	})
}

// Helper functions

func createMockKeycloakServer() *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/test-realm/protocol/openid-connect/token/introspect":
			response := map[string]interface{}{
				"active":     true,
				"sub":        "test-user-123",
				"username":   "testuser",
				"email":      "test@example.com",
				"exp":        time.Now().Add(1 * time.Hour).Unix(),
				"trust_level": getTestTrustLevel(),
			}
			json.NewEncoder(w).Encode(response)
			
		case "/realms/test-realm/protocol/openid-connect/userinfo":
			response := map[string]interface{}{
				"sub":         "test-user-123",
				"name":        "Test User",
				"given_name":  "Test",
				"family_name": "User",
				"email":       "test@example.com",
			}
			json.NewEncoder(w).Encode(response)
			
		case "/realms/test-realm/.well-known/openid-configuration":
			response := map[string]interface{}{
				"issuer":                 fmt.Sprintf("%s/realms/test-realm", r.Host),
				"authorization_endpoint": fmt.Sprintf("%s/realms/test-realm/protocol/openid-connect/auth", r.Host),
				"token_endpoint":         fmt.Sprintf("%s/realms/test-realm/protocol/openid-connect/token", r.Host),
				"userinfo_endpoint":      fmt.Sprintf("%s/realms/test-realm/protocol/openid-connect/userinfo", r.Host),
				"introspection_endpoint": fmt.Sprintf("%s/realms/test-realm/protocol/openid-connect/token/introspect", r.Host),
			}
			json.NewEncoder(w).Encode(response)
			
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	
	return httptest.NewServer(handler)
}

func setupTestRoutes(router *gin.Engine, middleware *ginmiddleware.KeycloakMiddleware) {
	// Public routes
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy"})
	})

	// Protected routes
	api := router.Group("/api")
	api.Use(middleware.Authenticate())
	{
		// Read access (trust level 25+)
		api.GET("/data", middleware.RequireTrustLevel(25), func(c *gin.Context) {
			c.JSON(200, gin.H{"data": "test data"})
		})

		// Admin access (trust level 75+)
		api.POST("/admin", middleware.RequireTrustLevel(75), func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "admin access granted"})
		})

		// Java client endpoint
		api.POST("/java/validate", func(c *gin.Context) {
			c.JSON(200, gin.H{"valid": true})
		})

		// Python client endpoint
		api.GET("/python/user", func(c *gin.Context) {
			claims := middleware.GetClaims(c)
			c.JSON(200, gin.H{"user_id": claims.UserID})
		})
	}
}

func getTestToken() string {
	return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"
}

func getExpiredTestToken() string {
	return "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.expired.signature"
}

func getTestTrustLevel() int {
	return 60 // Medium trust level for testing
}

// Mock implementations

type MockDeviceStorage struct {
	devices map[string]*zerotrust.Device
}

func NewMockDeviceStorage() *MockDeviceStorage {
	return &MockDeviceStorage{
		devices: make(map[string]*zerotrust.Device),
	}
}

func (s *MockDeviceStorage) StoreDevice(ctx context.Context, device *zerotrust.Device) error {
	s.devices[device.ID] = device
	return nil
}

func (s *MockDeviceStorage) GetDevice(ctx context.Context, deviceID string) (*zerotrust.Device, error) {
	device, exists := s.devices[deviceID]
	if !exists {
		return nil, fmt.Errorf("device not found")
	}
	return device, nil
}

func (s *MockDeviceStorage) UpdateDevice(ctx context.Context, device *zerotrust.Device) error {
	s.devices[device.ID] = device
	return nil
}

func (s *MockDeviceStorage) ListUserDevices(ctx context.Context, userID string) ([]*zerotrust.Device, error) {
	var devices []*zerotrust.Device
	for _, device := range s.devices {
		if device.UserID == userID {
			devices = append(devices, device)
		}
	}
	return devices, nil
}

func (s *MockDeviceStorage) DeleteDevice(ctx context.Context, deviceID string) error {
	delete(s.devices, deviceID)
	return nil
}

// Test plugin implementation
type TestSecurityPlugin struct {
	ExecutionCount int
}

func (p *TestSecurityPlugin) GetName() string        { return "test_security" }
func (p *TestSecurityPlugin) GetVersion() string     { return "1.0.0" }
func (p *TestSecurityPlugin) GetDescription() string { return "Test security plugin" }

func (p *TestSecurityPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	p.ExecutionCount = 0
	return nil
}

func (p *TestSecurityPlugin) Cleanup(ctx context.Context) error {
	return nil
}

func (p *TestSecurityPlugin) GetMetadata() plugins.PluginMetadata {
	return plugins.PluginMetadata{
		Name:    p.GetName(),
		Version: p.GetVersion(),
	}
}

func (p *TestSecurityPlugin) ExecuteHook(ctx context.Context, hookType plugins.HookType, data map[string]interface{}) error {
	p.ExecutionCount++
	return nil
}

func (p *TestSecurityPlugin) GetHookTypes() []plugins.HookType {
	return []plugins.HookType{plugins.HookPostAuth}
}

// Additional mock implementations for risk assessment
type MockUserBehaviorAnalyzer struct{}

func NewMockUserBehaviorAnalyzer() *MockUserBehaviorAnalyzer {
	return &MockUserBehaviorAnalyzer{}
}

func (a *MockUserBehaviorAnalyzer) AnalyzeBehavior(ctx context.Context, userID string, currentSession *zerotrust.SessionContext) (*zerotrust.BehaviorAnalysis, error) {
	return &zerotrust.BehaviorAnalysis{
		IsAnomalous:        false,
		AnomalyScore:       0.2,
		DeviationFactors:   []string{},
		BehaviorConfidence: 0.85,
	}, nil
}

func (a *MockUserBehaviorAnalyzer) UpdateUserBaseline(ctx context.Context, userID string, session *zerotrust.SessionContext) error {
	return nil
}

func (a *MockUserBehaviorAnalyzer) GetUserBaseline(ctx context.Context, userID string) (*zerotrust.UserBaseline, error) {
	return &zerotrust.UserBaseline{
		UserID:               userID,
		TypicalDevices:       []string{"device-123"},
		AverageSessionLength: 4 * time.Hour,
	}, nil
}

type MockUserBaselineStorage struct{}

func NewMockUserBaselineStorage() *MockUserBaselineStorage {
	return &MockUserBaselineStorage{}
}

func (s *MockUserBaselineStorage) GetUserLocationBaseline(ctx context.Context, userID string) ([]*types.LocationInfo, error) {
	return []*types.LocationInfo{
		{
			Country: "US",
			Region:  "California",
			City:    "San Francisco",
		},
	}, nil
}

func (s *MockUserBaselineStorage) UpdateUserLocationBaseline(ctx context.Context, userID string, location *types.LocationInfo) error {
	return nil
}

type MockThreatIntelligenceService struct{}

func NewMockThreatIntelligenceService() *MockThreatIntelligenceService {
	return &MockThreatIntelligenceService{}
}

func (t *MockThreatIntelligenceService) CheckIPReputation(ctx context.Context, ipAddress string) (*zerotrust.IPReputation, error) {
	return &zerotrust.IPReputation{
		IsBlacklisted:   false,
		IsMalicious:     false,
		ReputationScore: 85,
	}, nil
}

func (t *MockThreatIntelligenceService) CheckUserAgentRisk(ctx context.Context, userAgent string) (*zerotrust.UserAgentRisk, error) {
	return &zerotrust.UserAgentRisk{
		IsBot:        false,
		IsSuspicious: false,
		RiskScore:    10,
	}, nil
}

func (t *MockThreatIntelligenceService) GetActiveThreatCampaigns(ctx context.Context) ([]*zerotrust.ThreatCampaign, error) {
	return []*zerotrust.ThreatCampaign{}, nil
}

type MockBaselineStorage struct {
	baselines map[string]*zerotrust.UserBaseline
}

func NewMockBaselineStorage() *MockBaselineStorage {
	return &MockBaselineStorage{
		baselines: make(map[string]*zerotrust.UserBaseline),
	}
}

func (s *MockBaselineStorage) StoreBaseline(ctx context.Context, userID string, baseline *zerotrust.UserBaseline) error {
	s.baselines[userID] = baseline
	return nil
}

func (s *MockBaselineStorage) GetBaseline(ctx context.Context, userID string) (*zerotrust.UserBaseline, error) {
	baseline, exists := s.baselines[userID]
	if !exists {
		return nil, fmt.Errorf("baseline not found")
	}
	return baseline, nil
}

func (s *MockBaselineStorage) UpdateBaseline(ctx context.Context, userID string, baseline *zerotrust.UserBaseline) error {
	s.baselines[userID] = baseline
	return nil
}