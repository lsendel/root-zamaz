// Package benchmark provides performance benchmarks for the Zero Trust library
package benchmark

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/cache"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/client"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/zerotrust"
)

var (
	testConfig *types.ZeroTrustConfig
	benchCtx   = context.Background()
)

func init() {
	testConfig = &types.ZeroTrustConfig{
		BaseURL:      "http://localhost:8080",
		Realm:        "benchmark",
		ClientID:     "benchmark-client",
		ClientSecret: "benchmark-secret",
		ZeroTrust: &types.ZeroTrustSettings{
			EnableDeviceAttestation: true,
			EnableRiskAssessment:    true,
			EnableContinuousAuth:    true,
			DeviceVerificationTTL:   24 * time.Hour,
			TrustDecayInterval:      1 * time.Hour,
			TrustLevelThresholds: types.TrustLevelThresholds{
				Read:   25,
				Write:  50,
				Admin:  75,
				Delete: 90,
			},
		},
		Cache: &types.CacheConfig{
			Type: "memory",
		},
	}
}

// BenchmarkTokenValidation benchmarks token validation performance
func BenchmarkTokenValidation(b *testing.B) {
	keycloakClient := createMockKeycloakClient()
	defer keycloakClient.Close()

	token := generateTestToken()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := keycloakClient.ValidateToken(benchCtx, token)
			if err != nil {
				b.Fatalf("Token validation failed: %v", err)
			}
		}
	})
}

// BenchmarkTokenValidationWithCache benchmarks cached token validation
func BenchmarkTokenValidationWithCache(b *testing.B) {
	// Test different cache implementations
	cacheTypes := []string{"memory", "redis"}
	
	for _, cacheType := range cacheTypes {
		b.Run(cacheType, func(b *testing.B) {
			config := *testConfig
			config.Cache.Type = cacheType
			
			if cacheType == "redis" {
				// Skip if Redis is not available
				if !isRedisAvailable() {
					b.Skip("Redis not available")
				}
				config.Cache.Redis = &types.RedisConfig{
					Host: "localhost",
					Port: 6379,
				}
			}
			
			keycloakClient := createMockKeycloakClientWithConfig(&config)
			defer keycloakClient.Close()
			
			token := generateTestToken()
			
			// Warm up cache
			keycloakClient.ValidateToken(benchCtx, token)
			
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_, err := keycloakClient.ValidateToken(benchCtx, token)
					if err != nil {
						b.Fatalf("Token validation failed: %v", err)
					}
				}
			})
		})
	}
}

// BenchmarkDeviceAttestation benchmarks device attestation performance
func BenchmarkDeviceAttestation(b *testing.B) {
	deviceService := zerotrust.NewDeviceAttestationService(testConfig, NewBenchmarkDeviceStorage())
	
	platforms := []string{"android", "ios", "web"}
	
	for _, platform := range platforms {
		b.Run(platform, func(b *testing.B) {
			nonce, _ := deviceService.GenerateNonce()
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				attestation := &zerotrust.DeviceAttestation{
					DeviceID:          fmt.Sprintf("device-%d", i),
					UserID:            fmt.Sprintf("user-%d", i%100),
					Platform:          platform,
					DeviceFingerprint: fmt.Sprintf("fingerprint-%d", i),
					HardwareData:      generateHardwareData(platform),
					SoftwareData:      generateSoftwareData(platform),
					Timestamp:         time.Now(),
					Nonce:             nonce,
					Signature:         "benchmark-signature",
				}
				
				_, err := deviceService.AttestDevice(benchCtx, attestation)
				if err != nil {
					b.Fatalf("Device attestation failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkRiskAssessment benchmarks risk assessment performance
func BenchmarkRiskAssessment(b *testing.B) {
	riskEngine := zerotrust.NewRiskAssessmentEngine(
		testConfig,
		NewBenchmarkUserBehaviorAnalyzer(),
		zerotrust.NewGeolocationService(testConfig, NewBenchmarkUserBaselineStorage()),
		NewBenchmarkThreatIntelligenceService(),
		zerotrust.NewDeviceAttestationService(testConfig, NewBenchmarkDeviceStorage()),
		NewBenchmarkBaselineStorage(),
	)
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		userID := 0
		for pb.Next() {
			session := &zerotrust.SessionContext{
				UserID:        fmt.Sprintf("user-%d", userID%1000),
				IPAddress:     fmt.Sprintf("192.168.1.%d", userID%255),
				UserAgent:     "Mozilla/5.0 Benchmark",
				DeviceID:      fmt.Sprintf("device-%d", userID%100),
				Timestamp:     time.Now(),
				RequestPath:   "/api/benchmark",
				RequestMethod: "GET",
				AuthMethod:    "mfa",
			}
			userID++
			
			_, err := riskEngine.AssessRisk(benchCtx, session)
			if err != nil {
				b.Fatalf("Risk assessment failed: %v", err)
			}
		}
	})
}

// BenchmarkTrustCalculation benchmarks trust score calculation
func BenchmarkTrustCalculation(b *testing.B) {
	trustEngine := zerotrust.NewTrustEngine(testConfig)
	
	scenarios := []struct {
		name               string
		authMethod         string
		verificationLevel  string
		hasBiometric       bool
		previousTrustLevel int
	}{
		{"HighTrust", "biometric", "hardware", true, 80},
		{"MediumTrust", "mfa", "software", false, 50},
		{"LowTrust", "password", "none", false, 25},
	}
	
	for _, scenario := range scenarios {
		b.Run(scenario.name, func(b *testing.B) {
			input := &zerotrust.TrustCalculationInput{
				UserID: "benchmark-user",
				VerificationResult: &zerotrust.VerificationResult{
					IsValid:           true,
					TrustScore:        60,
					VerificationLevel: scenario.verificationLevel,
				},
				AuthenticationMethod: scenario.authMethod,
				PreviousTrustLevel:   scenario.previousTrustLevel,
			}
			
			if scenario.hasBiometric {
				input.BiometricData = &zerotrust.BiometricVerificationData{
					BiometricType:     "fingerprint",
					VerificationScore: 0.95,
					IsAuthentic:       true,
					QualityScore:      0.9,
				}
			}
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = trustEngine.CalculateTrustScore(benchCtx, input)
			}
		})
	}
}

// BenchmarkConcurrentOperations benchmarks concurrent operations
func BenchmarkConcurrentOperations(b *testing.B) {
	keycloakClient := createMockKeycloakClient()
	defer keycloakClient.Close()
	
	deviceService := zerotrust.NewDeviceAttestationService(testConfig, NewBenchmarkDeviceStorage())
	trustEngine := zerotrust.NewTrustEngine(testConfig)
	
	concurrencyLevels := []int{10, 50, 100, 500}
	
	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("Concurrency-%d", concurrency), func(b *testing.B) {
			b.ResetTimer()
			
			var wg sync.WaitGroup
			workChan := make(chan int, b.N)
			
			// Fill work channel
			for i := 0; i < b.N; i++ {
				workChan <- i
			}
			close(workChan)
			
			// Start workers
			for i := 0; i < concurrency; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					
					for workID := range workChan {
						// Mix of operations
						switch workID % 3 {
						case 0:
							// Token validation
							token := generateTestToken()
							keycloakClient.ValidateToken(benchCtx, token)
							
						case 1:
							// Device attestation
							nonce, _ := deviceService.GenerateNonce()
							attestation := &zerotrust.DeviceAttestation{
								DeviceID:          fmt.Sprintf("device-%d", workID),
								UserID:            fmt.Sprintf("user-%d", workID%100),
								Platform:          "web",
								DeviceFingerprint: fmt.Sprintf("fp-%d", workID),
								Timestamp:         time.Now(),
								Nonce:             nonce,
								Signature:         "sig",
							}
							deviceService.AttestDevice(benchCtx, attestation)
							
						case 2:
							// Trust calculation
							input := &zerotrust.TrustCalculationInput{
								UserID:               fmt.Sprintf("user-%d", workID),
								AuthenticationMethod: "mfa",
								PreviousTrustLevel:   50,
							}
							trustEngine.CalculateTrustScore(benchCtx, input)
						}
					}
				}()
			}
			
			wg.Wait()
		})
	}
}

// BenchmarkMemoryUsage benchmarks memory allocation
func BenchmarkMemoryUsage(b *testing.B) {
	b.Run("TokenValidation", func(b *testing.B) {
		keycloakClient := createMockKeycloakClient()
		defer keycloakClient.Close()
		
		token := generateTestToken()
		
		b.ReportAllocs()
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			keycloakClient.ValidateToken(benchCtx, token)
		}
	})
	
	b.Run("DeviceAttestation", func(b *testing.B) {
		deviceService := zerotrust.NewDeviceAttestationService(testConfig, NewBenchmarkDeviceStorage())
		nonce, _ := deviceService.GenerateNonce()
		
		b.ReportAllocs()
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			attestation := &zerotrust.DeviceAttestation{
				DeviceID:          fmt.Sprintf("device-%d", i),
				UserID:            "user-123",
				Platform:          "ios",
				DeviceFingerprint: "fp-123",
				Timestamp:         time.Now(),
				Nonce:             nonce,
				Signature:         "sig",
			}
			deviceService.AttestDevice(benchCtx, attestation)
		}
	})
}

// BenchmarkCachePerformance benchmarks cache operations
func BenchmarkCachePerformance(b *testing.B) {
	cacheConfig := &cache.Config{
		DefaultTTL: 5 * time.Minute,
		MaxEntries: 10000,
	}
	
	memCache := cache.NewMemoryCache(cacheConfig)
	
	// Benchmark different key sizes
	keySizes := []int{10, 100, 1000}
	
	for _, keySize := range keySizes {
		b.Run(fmt.Sprintf("KeySize-%d", keySize), func(b *testing.B) {
			keys := make([]string, keySize)
			for i := 0; i < keySize; i++ {
				keys[i] = fmt.Sprintf("key-%d", i)
			}
			
			value := &types.ZeroTrustClaims{
				UserID:     "test-user",
				Username:   "testuser",
				Email:      "test@example.com",
				TrustLevel: 75,
			}
			
			// Pre-populate cache
			for _, key := range keys {
				memCache.Set(benchCtx, key, value, 5*time.Minute)
			}
			
			b.ResetTimer()
			
			b.Run("Get", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					key := keys[i%keySize]
					memCache.Get(benchCtx, key)
				}
			})
			
			b.Run("Set", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					key := fmt.Sprintf("new-key-%d", i)
					memCache.Set(benchCtx, key, value, 5*time.Minute)
				}
			})
		})
	}
}

// BenchmarkTrustDecay benchmarks trust decay calculations
func BenchmarkTrustDecay(b *testing.B) {
	trustEngine := zerotrust.NewTrustEngine(testConfig)
	
	intervals := []time.Duration{
		1 * time.Hour,
		4 * time.Hour,
		24 * time.Hour,
		7 * 24 * time.Hour,
	}
	
	for _, interval := range intervals {
		b.Run(fmt.Sprintf("Interval-%s", interval), func(b *testing.B) {
			initialScore := 80
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = trustEngine.DecayTrustScore(initialScore, interval)
			}
		})
	}
}

// Helper functions

func createMockKeycloakClient() types.KeycloakClient {
	// Create a mock client for benchmarking
	return &MockKeycloakClient{
		claims: &types.ZeroTrustClaims{
			UserID:     "bench-user",
			Username:   "benchuser",
			Email:      "bench@example.com",
			TrustLevel: 75,
			Roles:      []string{"user", "developer"},
		},
	}
}

func createMockKeycloakClientWithConfig(config *types.ZeroTrustConfig) types.KeycloakClient {
	return &MockKeycloakClient{
		config: config,
		claims: &types.ZeroTrustClaims{
			UserID:     "bench-user",
			Username:   "benchuser",
			Email:      "bench@example.com",
			TrustLevel: 75,
			Roles:      []string{"user", "developer"},
		},
	}
}

func generateTestToken() string {
	return fmt.Sprintf("bench-token-%d", time.Now().UnixNano())
}

func isRedisAvailable() bool {
	// Check if Redis is available for benchmarking
	// In a real scenario, this would attempt to connect to Redis
	return false
}

func generateHardwareData(platform string) map[string]interface{} {
	switch platform {
	case "android":
		return map[string]interface{}{
			"bootloader_unlocked": false,
			"safetynet_enabled":   true,
		}
	case "ios":
		return map[string]interface{}{
			"secure_enclave": true,
			"touch_id":       true,
		}
	default:
		return map[string]interface{}{
			"user_agent": "Mozilla/5.0",
			"webgl_hash": "abc123",
		}
	}
}

func generateSoftwareData(platform string) map[string]interface{} {
	switch platform {
	case "android":
		return map[string]interface{}{
			"os_version": "Android 13",
			"root_detected": false,
		}
	case "ios":
		return map[string]interface{}{
			"jailbroken": false,
			"os_version": "iOS 16.0",
		}
	default:
		return map[string]interface{}{
			"browser": "Chrome",
			"version": "118.0",
		}
	}
}

// Mock implementations for benchmarking

type MockKeycloakClient struct {
	config *types.ZeroTrustConfig
	claims *types.ZeroTrustClaims
}

func (c *MockKeycloakClient) ValidateToken(ctx context.Context, token string) (*types.ZeroTrustClaims, error) {
	// Simulate some processing delay
	time.Sleep(100 * time.Microsecond)
	return c.claims, nil
}

func (c *MockKeycloakClient) RefreshToken(ctx context.Context, refreshToken string) (*types.TokenPair, error) {
	return &types.TokenPair{
		AccessToken:  generateTestToken(),
		RefreshToken: generateTestToken(),
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}, nil
}

func (c *MockKeycloakClient) GetUserInfo(ctx context.Context, userID string) (*types.UserInfo, error) {
	return &types.UserInfo{
		UserID:   userID,
		Username: "benchuser",
		Email:    "bench@example.com",
	}, nil
}

func (c *MockKeycloakClient) RegisterUser(ctx context.Context, req *types.UserRegistrationRequest) (*types.User, error) {
	return &types.User{
		ID:       generateTestToken(),
		Username: req.Username,
		Email:    req.Email,
	}, nil
}

func (c *MockKeycloakClient) UpdateUserTrustLevel(ctx context.Context, req *types.TrustLevelUpdateRequest) error {
	return nil
}

func (c *MockKeycloakClient) RevokeUserSessions(ctx context.Context, userID string) error {
	return nil
}

func (c *MockKeycloakClient) Health(ctx context.Context) error {
	return nil
}

func (c *MockKeycloakClient) GetMetrics(ctx context.Context) (*types.ClientMetrics, error) {
	return &types.ClientMetrics{
		RequestCount:    1000000,
		ErrorCount:      100,
		CacheHitRate:    0.95,
		AverageLatency:  25 * time.Millisecond,
	}, nil
}

func (c *MockKeycloakClient) Close() error {
	return nil
}

// Benchmark-specific storage implementations

type BenchmarkDeviceStorage struct {
	mu      sync.RWMutex
	devices map[string]*zerotrust.Device
}

func NewBenchmarkDeviceStorage() *BenchmarkDeviceStorage {
	return &BenchmarkDeviceStorage{
		devices: make(map[string]*zerotrust.Device),
	}
}

func (s *BenchmarkDeviceStorage) StoreDevice(ctx context.Context, device *zerotrust.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[device.ID] = device
	return nil
}

func (s *BenchmarkDeviceStorage) GetDevice(ctx context.Context, deviceID string) (*zerotrust.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	device, exists := s.devices[deviceID]
	if !exists {
		return nil, fmt.Errorf("device not found")
	}
	return device, nil
}

func (s *BenchmarkDeviceStorage) UpdateDevice(ctx context.Context, device *zerotrust.Device) error {
	return s.StoreDevice(ctx, device)
}

func (s *BenchmarkDeviceStorage) ListUserDevices(ctx context.Context, userID string) ([]*zerotrust.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var devices []*zerotrust.Device
	for _, device := range s.devices {
		if device.UserID == userID {
			devices = append(devices, device)
		}
	}
	return devices, nil
}

func (s *BenchmarkDeviceStorage) DeleteDevice(ctx context.Context, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.devices, deviceID)
	return nil
}

// Additional benchmark mock implementations

type BenchmarkUserBehaviorAnalyzer struct{}

func NewBenchmarkUserBehaviorAnalyzer() *BenchmarkUserBehaviorAnalyzer {
	return &BenchmarkUserBehaviorAnalyzer{}
}

func (a *BenchmarkUserBehaviorAnalyzer) AnalyzeBehavior(ctx context.Context, userID string, currentSession *zerotrust.SessionContext) (*zerotrust.BehaviorAnalysis, error) {
	return &zerotrust.BehaviorAnalysis{
		IsAnomalous:        false,
		AnomalyScore:       0.15,
		BehaviorConfidence: 0.9,
	}, nil
}

func (a *BenchmarkUserBehaviorAnalyzer) UpdateUserBaseline(ctx context.Context, userID string, session *zerotrust.SessionContext) error {
	return nil
}

func (a *BenchmarkUserBehaviorAnalyzer) GetUserBaseline(ctx context.Context, userID string) (*zerotrust.UserBaseline, error) {
	return &zerotrust.UserBaseline{
		UserID:               userID,
		AverageSessionLength: 4 * time.Hour,
	}, nil
}

type BenchmarkUserBaselineStorage struct{}

func NewBenchmarkUserBaselineStorage() *BenchmarkUserBaselineStorage {
	return &BenchmarkUserBaselineStorage{}
}

func (s *BenchmarkUserBaselineStorage) GetUserLocationBaseline(ctx context.Context, userID string) ([]*types.LocationInfo, error) {
	return []*types.LocationInfo{
		{Country: "US", Region: "CA", City: "SF"},
	}, nil
}

func (s *BenchmarkUserBaselineStorage) UpdateUserLocationBaseline(ctx context.Context, userID string, location *types.LocationInfo) error {
	return nil
}

type BenchmarkThreatIntelligenceService struct{}

func NewBenchmarkThreatIntelligenceService() *BenchmarkThreatIntelligenceService {
	return &BenchmarkThreatIntelligenceService{}
}

func (t *BenchmarkThreatIntelligenceService) CheckIPReputation(ctx context.Context, ipAddress string) (*zerotrust.IPReputation, error) {
	return &zerotrust.IPReputation{
		IsBlacklisted:   false,
		ReputationScore: 90,
	}, nil
}

func (t *BenchmarkThreatIntelligenceService) CheckUserAgentRisk(ctx context.Context, userAgent string) (*zerotrust.UserAgentRisk, error) {
	return &zerotrust.UserAgentRisk{
		IsBot:     false,
		RiskScore: 5,
	}, nil
}

func (t *BenchmarkThreatIntelligenceService) GetActiveThreatCampaigns(ctx context.Context) ([]*zerotrust.ThreatCampaign, error) {
	return []*zerotrust.ThreatCampaign{}, nil
}

type BenchmarkBaselineStorage struct {
	mu        sync.RWMutex
	baselines map[string]*zerotrust.UserBaseline
}

func NewBenchmarkBaselineStorage() *BenchmarkBaselineStorage {
	return &BenchmarkBaselineStorage{
		baselines: make(map[string]*zerotrust.UserBaseline),
	}
}

func (s *BenchmarkBaselineStorage) StoreBaseline(ctx context.Context, userID string, baseline *zerotrust.UserBaseline) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baselines[userID] = baseline
	return nil
}

func (s *BenchmarkBaselineStorage) GetBaseline(ctx context.Context, userID string) (*zerotrust.UserBaseline, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	baseline, exists := s.baselines[userID]
	if !exists {
		return nil, fmt.Errorf("baseline not found")
	}
	return baseline, nil
}

func (s *BenchmarkBaselineStorage) UpdateBaseline(ctx context.Context, userID string, baseline *zerotrust.UserBaseline) error {
	return s.StoreBaseline(ctx, userID, baseline)
}