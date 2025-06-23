// Zero Trust Authentication Demo
// This example demonstrates the complete Zero Trust authentication flow
// including device attestation, risk assessment, and adaptive policies.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/client"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/zerotrust"
)

// InMemoryDeviceStorage provides a simple in-memory device storage implementation
type InMemoryDeviceStorage struct {
	devices map[string]*zerotrust.Device
}

func NewInMemoryDeviceStorage() *InMemoryDeviceStorage {
	return &InMemoryDeviceStorage{
		devices: make(map[string]*zerotrust.Device),
	}
}

func (s *InMemoryDeviceStorage) StoreDevice(ctx context.Context, device *zerotrust.Device) error {
	s.devices[device.ID] = device
	return nil
}

func (s *InMemoryDeviceStorage) GetDevice(ctx context.Context, deviceID string) (*zerotrust.Device, error) {
	device, exists := s.devices[deviceID]
	if !exists {
		return nil, fmt.Errorf("device not found: %s", deviceID)
	}
	return device, nil
}

func (s *InMemoryDeviceStorage) UpdateDevice(ctx context.Context, device *zerotrust.Device) error {
	s.devices[device.ID] = device
	return nil
}

func (s *InMemoryDeviceStorage) ListUserDevices(ctx context.Context, userID string) ([]*zerotrust.Device, error) {
	var devices []*zerotrust.Device
	for _, device := range s.devices {
		if device.UserID == userID {
			devices = append(devices, device)
		}
	}
	return devices, nil
}

func (s *InMemoryDeviceStorage) DeleteDevice(ctx context.Context, deviceID string) error {
	delete(s.devices, deviceID)
	return nil
}

// DemoUserBaselineStorage provides baseline storage for the demo
type DemoUserBaselineStorage struct{}

func (s *DemoUserBaselineStorage) GetUserLocationBaseline(ctx context.Context, userID string) ([]*types.LocationInfo, error) {
	// Return demo baseline locations
	return []*types.LocationInfo{
		{
			Country:   "US",
			Region:    "California",
			City:      "San Francisco",
			Latitude:  37.7749,
			Longitude: -122.4194,
			ISP:       "Comcast Cable",
			Timezone:  "America/Los_Angeles",
		},
		{
			Country:   "US",
			Region:    "California",
			City:      "Palo Alto",
			Latitude:  37.4419,
			Longitude: -122.1430,
			ISP:       "Comcast Cable",
			Timezone:  "America/Los_Angeles",
		},
	}, nil
}

func (s *DemoUserBaselineStorage) UpdateUserLocationBaseline(ctx context.Context, userID string, location *types.LocationInfo) error {
	log.Printf("📍 Updated location baseline for user %s: %s, %s", userID, location.City, location.Country)
	return nil
}

func main() {
	fmt.Println("🛡️  Zero Trust Authentication Demo")
	fmt.Println("=====================================")
	fmt.Println()

	ctx := context.Background()

	// 1. Initialize configuration
	config := &types.ZeroTrustConfig{
		BaseURL:      getEnv("KEYCLOAK_BASE_URL", "http://localhost:8080"),
		Realm:        getEnv("KEYCLOAK_REALM", "demo"),
		ClientID:     getEnv("KEYCLOAK_CLIENT_ID", "demo-client"),
		ClientSecret: getEnv("KEYCLOAK_CLIENT_SECRET", "demo-secret"),
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

	fmt.Printf("🔧 Configuration:\n")
	fmt.Printf("   Keycloak URL: %s\n", config.BaseURL)
	fmt.Printf("   Realm: %s\n", config.Realm)
	fmt.Printf("   Client ID: %s\n", config.ClientID)
	fmt.Println()

	// 2. Initialize Keycloak client
	fmt.Println("🔗 Initializing Keycloak client...")
	keycloakClient, err := client.NewKeycloakClient(config)
	if err != nil {
		log.Fatalf("Failed to create Keycloak client: %v", err)
	}
	defer keycloakClient.Close()

	// Test connection
	if err := keycloakClient.Health(ctx); err != nil {
		log.Printf("⚠️  Keycloak health check failed (demo will continue): %v", err)
	} else {
		fmt.Println("✅ Connected to Keycloak successfully")
	}
	fmt.Println()

	// 3. Initialize Zero Trust services
	fmt.Println("🛡️  Initializing Zero Trust services...")
	
	// Device attestation service
	deviceStorage := NewInMemoryDeviceStorage()
	deviceService := zerotrust.NewDeviceAttestationService(config, deviceStorage)
	
	// Geolocation service
	geoService := zerotrust.NewGeolocationService(config, &DemoUserBaselineStorage{})
	
	// Trust engine
	trustEngine := zerotrust.NewTrustEngine(config)
	
	fmt.Println("✅ Zero Trust services initialized")
	fmt.Println()

	// 4. Demo scenarios
	runDeviceAttestationDemo(ctx, deviceService)
	fmt.Println()
	
	runGeolocationDemo(ctx, geoService)
	fmt.Println()
	
	runTrustEngineDemo(ctx, trustEngine)
	fmt.Println()
	
	runIntegratedWorkflowDemo(ctx, keycloakClient, deviceService, geoService, trustEngine)
	fmt.Println()

	fmt.Println("🎉 Zero Trust demo completed successfully!")
}

func runDeviceAttestationDemo(ctx context.Context, service *zerotrust.DeviceAttestationService) {
	fmt.Println("📱 Device Attestation Demo")
	fmt.Println("--------------------------")

	// Generate a nonce for attestation
	nonce, err := service.GenerateNonce()
	if err != nil {
		log.Printf("Failed to generate nonce: %v", err)
		return
	}

	// Test different device types
	devices := []struct {
		name        string
		platform    string
		fingerprint string
		hardware    map[string]interface{}
		software    map[string]interface{}
	}{
		{
			name:        "iOS Device (Secure)",
			platform:    "ios",
			fingerprint: "ios-device-secure-123",
			hardware:    map[string]interface{}{"secure_enclave": true, "touch_id": true},
			software:    map[string]interface{}{"jailbroken": false, "os_version": "iOS 16.0"},
		},
		{
			name:        "Android Device (Rooted)",
			platform:    "android",
			fingerprint: "android-device-rooted-456",
			hardware:    map[string]interface{}{"bootloader_unlocked": true, "safetynet": false},
			software:    map[string]interface{}{"os_version": "Android 13", "root_detected": true},
		},
		{
			name:        "Web Browser",
			platform:    "web",
			fingerprint: "web-browser-chrome-789",
			hardware:    map[string]interface{}{"user_agent": "Chrome/118.0", "webgl_hash": "abc123"},
			software:    map[string]interface{}{"canvas_hash": "def456", "plugins": []string{"PDF Viewer"}},
		},
	}

	for i, device := range devices {
		fmt.Printf("%d. Testing %s\n", i+1, device.name)

		attestation := &zerotrust.DeviceAttestation{
			DeviceID:          fmt.Sprintf("demo-device-%d", i+1),
			UserID:            "demo-user-123",
			Platform:          device.platform,
			DeviceFingerprint: device.fingerprint,
			HardwareData:      device.hardware,
			SoftwareData:      device.software,
			Timestamp:         time.Now(),
			Nonce:             nonce,
			Signature:         fmt.Sprintf("demo-signature-%d", i+1),
		}

		result, err := service.AttestDevice(ctx, attestation)
		if err != nil {
			fmt.Printf("   ❌ Attestation failed: %v\n", err)
			continue
		}

		fmt.Printf("   ✅ Valid: %t\n", result.IsValid)
		fmt.Printf("   🎯 Trust Score: %d/100\n", result.TrustScore)
		fmt.Printf("   🔒 Verification Level: %s\n", result.VerificationLevel)
		if len(result.RiskFactors) > 0 {
			fmt.Printf("   ⚠️  Risk Factors: %v\n", result.RiskFactors)
		}
		fmt.Printf("   ⏰ Expires: %s\n", result.ExpiresAt.Format("2006-01-02 15:04:05"))
	}
}

func runGeolocationDemo(ctx context.Context, service *zerotrust.GeolocationServiceImpl) {
	fmt.Println("🌍 Geolocation Risk Demo")
	fmt.Println("------------------------")

	testIPs := []struct {
		name string
		ip   string
		desc string
	}{
		{"Safe IP (Google DNS)", "8.8.8.8", "Known safe public DNS"},
		{"Local IP", "192.168.1.1", "Private network address"},
		{"Demo External IP", "1.2.3.4", "Example external IP"},
	}

	for i, testIP := range testIPs {
		fmt.Printf("%d. Testing %s (%s)\n", i+1, testIP.name, testIP.ip)

		// Get location info
		location, err := service.GetLocationInfo(ctx, testIP.ip)
		if err != nil {
			fmt.Printf("   ❌ Failed to get location: %v\n", err)
			continue
		}

		fmt.Printf("   📍 Location: %s, %s, %s\n", location.City, location.Region, location.Country)
		fmt.Printf("   🌐 ISP: %s\n", location.ISP)

		// Calculate location risk
		risk, err := service.CalculateLocationRisk(ctx, "demo-user-123", location)
		if err != nil {
			fmt.Printf("   ❌ Failed to calculate risk: %v\n", err)
			continue
		}

		fmt.Printf("   🎯 Risk Score: %d/100\n", risk.RiskScore)
		fmt.Printf("   📊 Risk Level: %s\n", risk.CountryRisk)
		fmt.Printf("   🆕 New Location: %t\n", risk.IsNewLocation)
		if risk.DistanceFromTypical > 0 {
			fmt.Printf("   📏 Distance from Typical: %.1f km\n", risk.DistanceFromTypical)
		}
		if len(risk.RiskReasons) > 0 {
			fmt.Printf("   ⚠️  Risk Reasons: %v\n", risk.RiskReasons)
		}
		if risk.VPNDetected {
			fmt.Printf("   🔒 VPN Detected: %t\n", risk.VPNDetected)
		}
		if risk.TorDetected {
			fmt.Printf("   🧅 Tor Detected: %t\n", risk.TorDetected)
		}
	}
}

func runTrustEngineDemo(ctx context.Context, engine *zerotrust.TrustEngine) {
	fmt.Println("🎯 Trust Engine Demo")
	fmt.Println("--------------------")

	testScenarios := []struct {
		name           string
		authMethod     string
		deviceScore    int
		verifiedDevice bool
		riskFactors    []string
		hasBiometric   bool
	}{
		{
			name:           "High Trust Scenario",
			authMethod:     "biometric",
			deviceScore:    85,
			verifiedDevice: true,
			riskFactors:    []string{},
			hasBiometric:   true,
		},
		{
			name:           "Medium Trust Scenario",
			authMethod:     "mfa",
			deviceScore:    60,
			verifiedDevice: true,
			riskFactors:    []string{"new_location"},
			hasBiometric:   false,
		},
		{
			name:           "Low Trust Scenario",
			authMethod:     "password",
			deviceScore:    30,
			verifiedDevice: false,
			riskFactors:    []string{"vpn_detected", "suspicious_behavior"},
			hasBiometric:   false,
		},
	}

	for i, scenario := range testScenarios {
		fmt.Printf("%d. %s\n", i+1, scenario.name)

		// Build trust calculation input
		input := &zerotrust.TrustCalculationInput{
			UserID: "demo-user-123",
			VerificationResult: &zerotrust.VerificationResult{
				IsValid:           scenario.verifiedDevice,
				TrustScore:        scenario.deviceScore,
				VerificationLevel: map[bool]string{true: "hardware", false: "software"}[scenario.verifiedDevice],
				RiskFactors:       scenario.riskFactors,
			},
			AuthenticationMethod: scenario.authMethod,
			PreviousTrustLevel:   50, // Starting trust level
		}

		// Add biometric data if available
		if scenario.hasBiometric {
			input.BiometricData = &zerotrust.BiometricVerificationData{
				BiometricType:       "fingerprint",
				VerificationScore:   0.92,
				IsAuthentic:         true,
				QualityScore:        0.88,
				FalseAcceptanceRate: 0.001,
			}
		}

		// Calculate trust score
		trustScore := engine.CalculateTrustScore(ctx, input)
		fmt.Printf("   🎯 Final Trust Score: %d/100\n", trustScore)

		// Test trust decay
		decayTime := 3 * time.Hour
		decayedScore := engine.DecayTrustScore(trustScore, decayTime)
		fmt.Printf("   ⏳ After %v decay: %d/100\n", decayTime, decayedScore)

		// Evaluate adaptive policies
		riskScore := len(scenario.riskFactors) * 25 // Simple risk calculation
		actions := engine.EvaluateAdaptivePolicies(ctx, trustScore, riskScore)
		if len(actions) > 0 {
			fmt.Printf("   🔧 Adaptive Actions: %v\n", actions)
		} else {
			fmt.Printf("   ✅ No additional actions required\n")
		}
	}
}

func runIntegratedWorkflowDemo(ctx context.Context, keycloakClient types.KeycloakClient, deviceService *zerotrust.DeviceAttestationService, geoService *zerotrust.GeolocationServiceImpl, trustEngine *zerotrust.TrustEngine) {
	fmt.Println("🔗 Integrated Workflow Demo")
	fmt.Println("---------------------------")

	userID := "demo-user-integrated"
	deviceID := "demo-device-integrated"

	// Step 1: Device Attestation
	fmt.Println("1. 📱 Device Attestation...")
	nonce, _ := deviceService.GenerateNonce()
	
	attestation := &zerotrust.DeviceAttestation{
		DeviceID:          deviceID,
		UserID:            userID,
		Platform:          "ios",
		DeviceFingerprint: "integrated-ios-device",
		HardwareData:      map[string]interface{}{"secure_enclave": true, "face_id": true},
		SoftwareData:      map[string]interface{}{"jailbroken": false, "os_version": "iOS 16.2"},
		Timestamp:         time.Now(),
		Nonce:             nonce,
		Signature:         "integrated-signature",
	}

	deviceResult, err := deviceService.AttestDevice(ctx, attestation)
	if err != nil {
		fmt.Printf("   ❌ Device attestation failed: %v\n", err)
		return
	}
	fmt.Printf("   ✅ Device Trust Score: %d/100\n", deviceResult.TrustScore)

	// Step 2: Location Analysis
	fmt.Println("2. 🌍 Location Analysis...")
	clientIP := "8.8.8.8" // Example IP
	
	location, err := geoService.GetLocationInfo(ctx, clientIP)
	if err != nil {
		fmt.Printf("   ❌ Location lookup failed: %v\n", err)
		return
	}
	
	locationRisk, err := geoService.CalculateLocationRisk(ctx, userID, location)
	if err != nil {
		fmt.Printf("   ❌ Location risk assessment failed: %v\n", err)
		return
	}
	fmt.Printf("   📍 Location: %s, %s (%s)\n", location.City, location.Country, location.ISP)
	fmt.Printf("   🎯 Location Risk Score: %d/100\n", locationRisk.RiskScore)

	// Step 3: Trust Calculation
	fmt.Println("3. 🎯 Trust Calculation...")
	
	trustInput := &zerotrust.TrustCalculationInput{
		UserID:            userID,
		DeviceAttestation: attestation,
		VerificationResult: deviceResult,
		AuthenticationMethod: "biometric",
		BiometricData: &zerotrust.BiometricVerificationData{
			BiometricType:     "face_id",
			VerificationScore: 0.94,
			IsAuthentic:       true,
			QualityScore:      0.90,
		},
		PreviousTrustLevel: 65,
	}
	
	finalTrustScore := trustEngine.CalculateTrustScore(ctx, trustInput)
	fmt.Printf("   ✅ Final Trust Score: %d/100\n", finalTrustScore)

	// Step 4: Access Decision
	fmt.Println("4. 🚪 Access Decision...")
	
	// Determine access levels
	accessLevels := map[string]bool{
		"Read Access":   finalTrustScore >= 25,
		"Write Access":  finalTrustScore >= 50,
		"Admin Access":  finalTrustScore >= 75,
		"Delete Access": finalTrustScore >= 90,
	}
	
	for access, granted := range accessLevels {
		status := "❌ Denied"
		if granted {
			status = "✅ Granted"
		}
		fmt.Printf("   %s %s\n", status, access)
	}

	// Step 5: Continuous Monitoring
	fmt.Println("5. 👁️  Continuous Monitoring...")
	
	// Simulate trust decay over time
	monitoringIntervals := []time.Duration{1 * time.Hour, 4 * time.Hour, 8 * time.Hour, 24 * time.Hour}
	
	for _, interval := range monitoringIntervals {
		decayedScore := trustEngine.DecayTrustScore(finalTrustScore, interval)
		fmt.Printf("   After %v: Trust Score %d/100\n", interval, decayedScore)
		
		if decayedScore < 50 {
			fmt.Printf("   ⚠️  Trust level below threshold - Re-authentication required\n")
			break
		}
	}

	// Step 6: Summary Report
	fmt.Println("6. 📊 Summary Report...")
	
	report := map[string]interface{}{
		"user_id":             userID,
		"device_id":           deviceID,
		"device_platform":     attestation.Platform,
		"device_trust_score":  deviceResult.TrustScore,
		"device_verified":     deviceResult.IsValid,
		"location_country":    location.Country,
		"location_risk_score": locationRisk.RiskScore,
		"final_trust_score":   finalTrustScore,
		"access_granted": map[string]bool{
			"read":   accessLevels["Read Access"],
			"write":  accessLevels["Write Access"],
			"admin":  accessLevels["Admin Access"],
			"delete": accessLevels["Delete Access"],
		},
		"timestamp": time.Now().Format(time.RFC3339),
	}
	
	reportJSON, _ := json.MarshalIndent(report, "   ", "  ")
	fmt.Printf("   %s\n", reportJSON)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}