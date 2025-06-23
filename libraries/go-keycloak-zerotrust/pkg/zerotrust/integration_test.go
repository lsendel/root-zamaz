// Package zerotrust provides integration tests for Zero Trust components
package zerotrust

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// MockDeviceStorage for testing
type MockDeviceStorage struct {
	devices map[string]*Device
}

func NewMockDeviceStorage() *MockDeviceStorage {
	return &MockDeviceStorage{
		devices: make(map[string]*Device),
	}
}

func (s *MockDeviceStorage) StoreDevice(ctx context.Context, device *Device) error {
	s.devices[device.ID] = device
	return nil
}

func (s *MockDeviceStorage) GetDevice(ctx context.Context, deviceID string) (*Device, error) {
	device, exists := s.devices[deviceID]
	if !exists {
		return nil, ErrDeviceNotFound
	}
	return device, nil
}

func (s *MockDeviceStorage) UpdateDevice(ctx context.Context, device *Device) error {
	s.devices[device.ID] = device
	return nil
}

func (s *MockDeviceStorage) ListUserDevices(ctx context.Context, userID string) ([]*Device, error) {
	var devices []*Device
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

// MockUserBehaviorAnalyzer for testing
type MockUserBehaviorAnalyzer struct{}

func (a *MockUserBehaviorAnalyzer) AnalyzeBehavior(ctx context.Context, userID string, currentSession *SessionContext) (*BehaviorAnalysis, error) {
	return &BehaviorAnalysis{
		IsAnomalous:        false,
		AnomalyScore:       0.2,
		DeviationFactors:   []string{},
		TypicalBehavior:    map[string]interface{}{"login_hours": []int{9, 10, 11, 14, 15, 16}},
		CurrentBehavior:    map[string]interface{}{"login_hour": currentSession.Timestamp.Hour()},
		BehaviorConfidence: 0.85,
	}, nil
}

func (a *MockUserBehaviorAnalyzer) UpdateUserBaseline(ctx context.Context, userID string, session *SessionContext) error {
	return nil
}

func (a *MockUserBehaviorAnalyzer) GetUserBaseline(ctx context.Context, userID string) (*UserBaseline, error) {
	return &UserBaseline{
		UserID:               userID,
		TypicalLocations:     []types.LocationInfo{{Country: "US", Region: "California", City: "San Francisco"}},
		TypicalDevices:       []string{"device-123"},
		TypicalLoginTimes:    []TimePattern{{DayOfWeek: 1, StartHour: 9, EndHour: 17, Frequency: 0.8}},
		TypicalIPRanges:      []string{"192.168.1.0/24"},
		TypicalUserAgents:    []string{"Mozilla/5.0 Chrome"},
		AverageSessionLength: 4 * time.Hour,
		CreatedAt:            time.Now().Add(-30 * 24 * time.Hour),
		UpdatedAt:            time.Now(),
		SampleSize:           100,
	}, nil
}

// MockThreatIntelligenceService for testing
type MockThreatIntelligenceService struct{}

func (t *MockThreatIntelligenceService) CheckIPReputation(ctx context.Context, ipAddress string) (*IPReputation, error) {
	// Simulate different IP reputations
	if ipAddress == "10.0.0.1" {
		return &IPReputation{
			IsBlacklisted:   false,
			IsMalicious:     false,
			ReputationScore: 85,
			Categories:      []string{"residential"},
			Source:          "mock",
			LastSeen:        time.Now(),
		}, nil
	}
	
	return &IPReputation{
		IsBlacklisted:   true,
		IsMalicious:     true,
		ReputationScore: 15,
		Categories:      []string{"botnet", "malware"},
		Source:          "mock",
		LastSeen:        time.Now(),
	}, nil
}

func (t *MockThreatIntelligenceService) CheckUserAgentRisk(ctx context.Context, userAgent string) (*UserAgentRisk, error) {
	return &UserAgentRisk{
		IsBot:         false,
		IsSuspicious:  false,
		RiskScore:     10,
		Anomalies:     []string{},
		BrowserFamily: "Chrome",
		OSFamily:      "Windows",
	}, nil
}

func (t *MockThreatIntelligenceService) GetActiveThreatCampaigns(ctx context.Context) ([]*ThreatCampaign, error) {
	return []*ThreatCampaign{
		{
			ID:          "campaign-001",
			Name:        "Test Campaign",
			Type:        "phishing",
			Severity:    "medium",
			Indicators:  []string{"suspicious-domain.com"},
			Description: "Test threat campaign",
			StartDate:   time.Now().Add(-24 * time.Hour),
			IsActive:    true,
		},
	}, nil
}

// MockBaselineStorage for testing
type MockBaselineStorage struct {
	baselines map[string]*UserBaseline
}

func NewMockBaselineStorage() *MockBaselineStorage {
	return &MockBaselineStorage{
		baselines: make(map[string]*UserBaseline),
	}
}

func (s *MockBaselineStorage) StoreBaseline(ctx context.Context, userID string, baseline *UserBaseline) error {
	s.baselines[userID] = baseline
	return nil
}

func (s *MockBaselineStorage) GetBaseline(ctx context.Context, userID string) (*UserBaseline, error) {
	baseline, exists := s.baselines[userID]
	if !exists {
		return nil, ErrBaselineNotFound
	}
	return baseline, nil
}

func (s *MockBaselineStorage) UpdateBaseline(ctx context.Context, userID string, baseline *UserBaseline) error {
	s.baselines[userID] = baseline
	return nil
}

// MockUserBaselineStorage for geolocation service
type MockUserBaselineStorage struct{}

func (s *MockUserBaselineStorage) GetUserLocationBaseline(ctx context.Context, userID string) ([]*types.LocationInfo, error) {
	return []*types.LocationInfo{
		{
			Country:   "US",
			Region:    "California", 
			City:      "San Francisco",
			Latitude:  37.7749,
			Longitude: -122.4194,
			ISP:       "Comcast",
			Timezone:  "America/Los_Angeles",
		},
	}, nil
}

func (s *MockUserBaselineStorage) UpdateUserLocationBaseline(ctx context.Context, userID string, location *types.LocationInfo) error {
	return nil
}

// Test configuration
func getTestConfig() *types.ZeroTrustConfig {
	return &types.ZeroTrustConfig{
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
	}
}

// Error definitions
var (
	ErrDeviceNotFound   = fmt.Errorf("device not found")
	ErrBaselineNotFound = fmt.Errorf("baseline not found")
)

// TestDeviceAttestationIntegration tests the complete device attestation flow
func TestDeviceAttestationIntegration(t *testing.T) {
	ctx := context.Background()
	config := getTestConfig()
	storage := NewMockDeviceStorage()
	
	service := NewDeviceAttestationService(config, storage)
	
	// Test Android device attestation
	attestation := &DeviceAttestation{
		DeviceID:          "device-android-123",
		UserID:            "user-123",
		Platform:          "android",
		DeviceFingerprint: "android-fingerprint-abc",
		HardwareData: map[string]interface{}{
			"bootloader_unlocked": false,
			"safetynet_enabled":   true,
		},
		SoftwareData: map[string]interface{}{
			"os_version":     "Android 12",
			"security_patch": "2023-10-01",
		},
		Timestamp: time.Now(),
		Nonce:     "test-nonce-123",
		Signature: "test-signature",
	}
	
	// Perform attestation
	result, err := service.AttestDevice(ctx, attestation)
	if err != nil {
		t.Fatalf("Device attestation failed: %v", err)
	}
	
	if !result.IsValid {
		t.Errorf("Expected device to be valid")
	}
	
	if result.TrustScore <= 0 {
		t.Errorf("Expected positive trust score, got %d", result.TrustScore)
	}
	
	// Verify device was stored
	device, err := service.VerifyDevice(ctx, attestation.DeviceID)
	if err != nil {
		t.Fatalf("Failed to verify stored device: %v", err)
	}
	
	if device.Platform != "android" {
		t.Errorf("Expected platform 'android', got '%s'", device.Platform)
	}
	
	// Test device list for user
	devices, err := service.GetUserDevices(ctx, "user-123")
	if err != nil {
		t.Fatalf("Failed to get user devices: %v", err)
	}
	
	if len(devices) != 1 {
		t.Errorf("Expected 1 device, got %d", len(devices))
	}
	
	t.Logf("✅ Device attestation integration test passed - Trust Score: %d", result.TrustScore)
}

// TestRiskAssessmentIntegration tests the complete risk assessment flow
func TestRiskAssessmentIntegration(t *testing.T) {
	ctx := context.Background()
	config := getTestConfig()
	
	// Initialize services
	userBehavior := &MockUserBehaviorAnalyzer{}
	geoLocation := NewGeolocationService(config, &MockUserBaselineStorage{})
	threatIntel := &MockThreatIntelligenceService{}
	deviceAnalyzer := NewDeviceAttestationService(config, NewMockDeviceStorage())
	baselineStorage := NewMockBaselineStorage()
	
	riskEngine := NewRiskAssessmentEngine(
		config,
		userBehavior,
		geoLocation,
		threatIntel,
		deviceAnalyzer,
		baselineStorage,
	)
	
	// Create test session context
	session := &SessionContext{
		UserID:           "user-123",
		IPAddress:        "10.0.0.1", // Good IP
		UserAgent:        "Mozilla/5.0 Chrome",
		DeviceID:         "device-123",
		Timestamp:        time.Now(),
		RequestPath:      "/api/v1/sensitive",
		RequestMethod:    "GET",
		Headers:          map[string]string{"Content-Type": "application/json"},
		AuthMethod:       "mfa",
		SessionDuration:  2 * time.Hour,
		RequestCount:     15,
		FailedAttempts:   0,
	}
	
	// Perform risk assessment
	result, err := riskEngine.AssessRisk(ctx, session)
	if err != nil {
		t.Fatalf("Risk assessment failed: %v", err)
	}
	
	if result.OverallRiskScore < 0 || result.OverallRiskScore > 100 {
		t.Errorf("Risk score out of range: %d", result.OverallRiskScore)
	}
	
	if result.RiskLevel == "" {
		t.Errorf("Risk level should not be empty")
	}
	
	if len(result.RiskFactors) == 0 {
		t.Errorf("Expected at least one risk factor")
	}
	
	if result.Confidence <= 0 || result.Confidence > 1 {
		t.Errorf("Confidence out of range: %f", result.Confidence)
	}
	
	// Test with high-risk IP
	session.IPAddress = "1.2.3.4" // Will be flagged as malicious by mock
	resultHighRisk, err := riskEngine.AssessRisk(ctx, session)
	if err != nil {
		t.Fatalf("High risk assessment failed: %v", err)
	}
	
	if resultHighRisk.OverallRiskScore <= result.OverallRiskScore {
		t.Errorf("Expected higher risk score for malicious IP")
	}
	
	t.Logf("✅ Risk assessment integration test passed - Low Risk: %d, High Risk: %d", 
		result.OverallRiskScore, resultHighRisk.OverallRiskScore)
}

// TestTrustEngineIntegration tests the trust engine with multiple factors
func TestTrustEngineIntegration(t *testing.T) {
	ctx := context.Background()
	config := getTestConfig()
	
	engine := NewTrustEngine(config)
	
	// Test trust calculation with various inputs
	testCases := []struct {
		name     string
		input    *TrustCalculationInput
		minScore int
		maxScore int
	}{
		{
			name: "High Trust - MFA + Biometric",
			input: &TrustCalculationInput{
				UserID: "user-123",
				DeviceAttestation: &DeviceAttestation{
					Platform: "ios",
				},
				VerificationResult: &VerificationResult{
					IsValid:           true,
					TrustScore:        80,
					VerificationLevel: "hardware",
					RiskFactors:       []string{},
				},
				AuthenticationMethod: "biometric",
				BiometricData: &BiometricVerificationData{
					BiometricType:       "fingerprint",
					VerificationScore:   0.95,
					IsAuthentic:         true,
					QualityScore:        0.9,
					FalseAcceptanceRate: 0.001,
				},
				PreviousTrustLevel: 75,
			},
			minScore: 70,
			maxScore: 100,
		},
		{
			name: "Medium Trust - Password Only",
			input: &TrustCalculationInput{
				UserID: "user-456",
				VerificationResult: &VerificationResult{
					IsValid:           true,
					TrustScore:        40,
					VerificationLevel: "software",
					RiskFactors:       []string{"unverified_device"},
				},
				AuthenticationMethod: "password",
				PreviousTrustLevel:   50,
			},
			minScore: 30,
			maxScore: 60,
		},
		{
			name: "Low Trust - Risk Factors",
			input: &TrustCalculationInput{
				UserID: "user-789",
				VerificationResult: &VerificationResult{
					IsValid:           true,
					TrustScore:        20,
					VerificationLevel: "none",
					RiskFactors:       []string{"jailbroken", "vpn_detected"},
				},
				AuthenticationMethod: "password",
				PreviousTrustLevel:   15,
			},
			minScore: 10,
			maxScore: 40,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			score := engine.CalculateTrustScore(ctx, tc.input)
			
			if score < tc.minScore || score > tc.maxScore {
				t.Errorf("Trust score %d not in expected range [%d, %d]", 
					score, tc.minScore, tc.maxScore)
			}
			
			t.Logf("Trust score for %s: %d", tc.name, score)
		})
	}
	
	// Test trust decay
	originalScore := 80
	timeSince := 5 * time.Hour
	decayedScore := engine.DecayTrustScore(originalScore, timeSince)
	
	if decayedScore >= originalScore {
		t.Errorf("Expected trust decay, got %d (original: %d)", decayedScore, originalScore)
	}
	
	// Test adaptive policies
	actions := engine.EvaluateAdaptivePolicies(ctx, 20, 80) // Low trust, high risk
	if len(actions) == 0 {
		t.Errorf("Expected adaptive policy actions for low trust/high risk")
	}
	
	t.Logf("✅ Trust engine integration test passed - Decay: %d→%d, Actions: %v", 
		originalScore, decayedScore, actions)
}

// TestGeolocationIntegration tests geolocation service
func TestGeolocationIntegration(t *testing.T) {
	ctx := context.Background()
	config := getTestConfig()
	
	service := NewGeolocationService(config, &MockUserBaselineStorage{})
	
	// Test location info retrieval
	location, err := service.GetLocationInfo(ctx, "8.8.8.8")
	if err != nil {
		t.Fatalf("Failed to get location info: %v", err)
	}
	
	if location.Country == "" {
		t.Errorf("Expected country information")
	}
	
	// Test location risk calculation
	risk, err := service.CalculateLocationRisk(ctx, "user-123", location)
	if err != nil {
		t.Fatalf("Failed to calculate location risk: %v", err)
	}
	
	if risk.RiskScore < 0 || risk.RiskScore > 100 {
		t.Errorf("Risk score out of range: %d", risk.RiskScore)
	}
	
	// Test high-risk location detection
	highRiskLocation := &types.LocationInfo{
		Country: "CN", // High-risk country
		Region:  "Beijing",
		City:    "Beijing",
		ISP:     "China Telecom",
	}
	
	isHighRisk, reasons := service.IsHighRiskLocation(ctx, highRiskLocation)
	if !isHighRisk {
		t.Errorf("Expected high-risk location to be flagged")
	}
	
	if len(reasons) == 0 {
		t.Errorf("Expected risk reasons for high-risk location")
	}
	
	t.Logf("✅ Geolocation integration test passed - Risk Score: %d, High Risk: %t", 
		risk.RiskScore, isHighRisk)
}

// TestZeroTrustWorkflow tests the complete Zero Trust workflow
func TestZeroTrustWorkflow(t *testing.T) {
	ctx := context.Background()
	config := getTestConfig()
	
	// Initialize all services
	deviceStorage := NewMockDeviceStorage()
	deviceService := NewDeviceAttestationService(config, deviceStorage)
	geoService := NewGeolocationService(config, &MockUserBaselineStorage{})
	
	riskEngine := NewRiskAssessmentEngine(
		config,
		&MockUserBehaviorAnalyzer{},
		geoService,
		&MockThreatIntelligenceService{},
		deviceService,
		NewMockBaselineStorage(),
	)
	
	trustEngine := NewTrustEngine(config)
	
	// Step 1: Device attestation
	attestation := &DeviceAttestation{
		DeviceID:          "workflow-device-123",
		UserID:            "workflow-user-123",
		Platform:          "ios",
		DeviceFingerprint: "ios-fingerprint",
		HardwareData:      map[string]interface{}{"secure_enclave": true},
		SoftwareData:      map[string]interface{}{"jailbroken": false},
		Timestamp:         time.Now(),
		Nonce:             "workflow-nonce",
		Signature:         "workflow-signature",
	}
	
	deviceResult, err := deviceService.AttestDevice(ctx, attestation)
	if err != nil {
		t.Fatalf("Device attestation failed: %v", err)
	}
	
	// Step 2: Risk assessment
	session := &SessionContext{
		UserID:        "workflow-user-123",
		IPAddress:     "10.0.0.1",
		UserAgent:     "Mozilla/5.0 Safari iOS",
		DeviceID:      "workflow-device-123",
		Timestamp:     time.Now(),
		AuthMethod:    "biometric",
		RequestPath:   "/api/v1/transfer",
		RequestMethod: "POST",
	}
	
	riskResult, err := riskEngine.AssessRisk(ctx, session)
	if err != nil {
		t.Fatalf("Risk assessment failed: %v", err)
	}
	
	// Step 3: Trust calculation
	trustInput := &TrustCalculationInput{
		UserID:             "workflow-user-123",
		DeviceAttestation:  attestation,
		VerificationResult: deviceResult,
		SessionContext:     session,
		RiskAssessment:     riskResult,
		AuthenticationMethod: "biometric",
		PreviousTrustLevel: 60,
	}
	
	finalTrustScore := trustEngine.CalculateTrustScore(ctx, trustInput)
	
	// Step 4: Adaptive policy evaluation
	adaptiveActions := trustEngine.EvaluateAdaptivePolicies(ctx, finalTrustScore, riskResult.OverallRiskScore)
	
	// Verify complete workflow
	if !deviceResult.IsValid {
		t.Errorf("Device should be valid in workflow")
	}
	
	if riskResult.OverallRiskScore < 0 || riskResult.OverallRiskScore > 100 {
		t.Errorf("Invalid risk score: %d", riskResult.OverallRiskScore)
	}
	
	if finalTrustScore < 0 || finalTrustScore > 100 {
		t.Errorf("Invalid trust score: %d", finalTrustScore)
	}
	
	// Log workflow results
	workflowSummary := map[string]interface{}{
		"device_trust_score":   deviceResult.TrustScore,
		"device_verified":      deviceResult.IsValid,
		"risk_score":          riskResult.OverallRiskScore,
		"risk_level":          riskResult.RiskLevel,
		"final_trust_score":   finalTrustScore,
		"adaptive_actions":    adaptiveActions,
		"workflow_status":     "completed",
	}
	
	summaryJSON, _ := json.MarshalIndent(workflowSummary, "", "  ")
	t.Logf("✅ Zero Trust workflow completed successfully:\n%s", summaryJSON)
}

// Benchmark tests
func BenchmarkDeviceAttestation(b *testing.B) {
	ctx := context.Background()
	config := getTestConfig()
	storage := NewMockDeviceStorage()
	service := NewDeviceAttestationService(config, storage)
	
	attestation := &DeviceAttestation{
		DeviceID:          "bench-device",
		UserID:            "bench-user",
		Platform:          "android",
		DeviceFingerprint: "bench-fingerprint",
		HardwareData:      map[string]interface{}{"bootloader_unlocked": false},
		SoftwareData:      map[string]interface{}{"os_version": "Android 12"},
		Timestamp:         time.Now(),
		Nonce:             "bench-nonce",
		Signature:         "bench-signature",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		attestation.DeviceID = fmt.Sprintf("bench-device-%d", i)
		_, err := service.AttestDevice(ctx, attestation)
		if err != nil {
			b.Fatalf("Attestation failed: %v", err)
		}
	}
}

func BenchmarkRiskAssessment(b *testing.B) {
	ctx := context.Background()
	config := getTestConfig()
	
	riskEngine := NewRiskAssessmentEngine(
		config,
		&MockUserBehaviorAnalyzer{},
		NewGeolocationService(config, &MockUserBaselineStorage{}),
		&MockThreatIntelligenceService{},
		NewDeviceAttestationService(config, NewMockDeviceStorage()),
		NewMockBaselineStorage(),
	)
	
	session := &SessionContext{
		UserID:        "bench-user",
		IPAddress:     "10.0.0.1",
		UserAgent:     "Mozilla/5.0 Chrome",
		DeviceID:      "bench-device",
		Timestamp:     time.Now(),
		AuthMethod:    "mfa",
		RequestPath:   "/api/test",
		RequestMethod: "GET",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session.UserID = fmt.Sprintf("bench-user-%d", i)
		_, err := riskEngine.AssessRisk(ctx, session)
		if err != nil {
			b.Fatalf("Risk assessment failed: %v", err)
		}
	}
}