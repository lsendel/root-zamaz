// Performance and load testing for Zero Trust Architecture
// Tests latency, throughput, and scalability of Keycloak + SPIRE + OPA integration
package performance

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"your-project/pkg/auth"
)

// PerformanceTestConfig holds performance testing configuration
type PerformanceTestConfig struct {
	// OPA configuration
	OPAURL         string
	OPAPolicyPath  string
	OPADatabaseURL string
	
	// Keycloak configuration
	KeycloakURL      string
	KeycloakRealm    string
	KeycloakClientID string
	KeycloakSecret   string
	
	// Test parameters
	TestDuration        time.Duration
	ConcurrentUsers     int
	RequestsPerSecond   int
	WarmupDuration      time.Duration
	
	// Performance thresholds
	MaxLatencyMs        int64
	MaxP95LatencyMs     int64
	MinThroughputRPS    float64
	MaxErrorRate        float64
}

// PerformanceMetrics holds performance test results
type PerformanceMetrics struct {
	// Request metrics
	TotalRequests     int64
	SuccessfulReqs    int64
	FailedRequests    int64
	ErrorRate         float64
	
	// Latency metrics
	MinLatencyMs      int64
	MaxLatencyMs      int64
	AvgLatencyMs      int64
	P50LatencyMs      int64
	P95LatencyMs      int64
	P99LatencyMs      int64
	
	// Throughput metrics
	ThroughputRPS     float64
	Duration          time.Duration
	
	// Resource metrics
	MemoryUsageMB     float64
	CPUUsagePercent   float64
	
	// Component-specific metrics
	OPAEvaluationMs   int64
	KeycloakLatencyMs int64
	SPIRELatencyMs    int64
}

// LatencyTracker tracks request latencies
type LatencyTracker struct {
	latencies []time.Duration
	mutex     sync.RWMutex
}

func NewLatencyTracker() *LatencyTracker {
	return &LatencyTracker{
		latencies: make([]time.Duration, 0, 10000),
	}
}

func (lt *LatencyTracker) Record(latency time.Duration) {
	lt.mutex.Lock()
	defer lt.mutex.Unlock()
	lt.latencies = append(lt.latencies, latency)
}

func (lt *LatencyTracker) GetMetrics() (min, max, avg, p50, p95, p99 time.Duration) {
	lt.mutex.RLock()
	defer lt.mutex.RUnlock()
	
	if len(lt.latencies) == 0 {
		return 0, 0, 0, 0, 0, 0
	}
	
	// Sort latencies for percentile calculations
	sorted := make([]time.Duration, len(lt.latencies))
	copy(sorted, lt.latencies)
	
	// Simple bubble sort (fine for testing, use sort.Slice in production)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	
	min = sorted[0]
	max = sorted[len(sorted)-1]
	
	var total time.Duration
	for _, lat := range sorted {
		total += lat
	}
	avg = total / time.Duration(len(sorted))
	
	p50 = sorted[len(sorted)*50/100]
	p95 = sorted[len(sorted)*95/100]
	p99 = sorted[len(sorted)*99/100]
	
	return min, max, avg, p50, p95, p99
}

// Test: OPA Policy Evaluation Performance
func TestOPAPolicyEvaluationPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance tests in short mode")
	}

	config := getPerformanceTestConfig()
	
	// Initialize OPA
	opaConfig := &auth.OPAConfig{
		ServiceURL:     config.OPAURL,
		PolicyPath:     config.OPAPolicyPath,
		DecisionLog:    false, // Disable for performance testing
		MetricsEnabled: false,
	}

	opa, err := auth.NewOPAAuthorizer(context.Background(), opaConfig)
	require.NoError(t, err, "Failed to initialize OPA for performance testing")
	defer opa.Close()

	// Test configuration
	numRequests := 1000
	concurrency := 10
	
	t.Run("OPA Authorization Latency", func(t *testing.T) {
		testOPAAuthorizationLatency(t, opa, numRequests, concurrency)
	})
	
	t.Run("OPA Workload Authorization Latency", func(t *testing.T) {
		testOPAWorkloadAuthorizationLatency(t, opa, numRequests, concurrency)
	})
	
	t.Run("OPA Data Access Latency", func(t *testing.T) {
		testOPADataAccessLatency(t, opa, numRequests, concurrency)
	})
}

func testOPAAuthorizationLatency(t *testing.T, opa *auth.OPAAuthorizer, numRequests, concurrency int) {
	ctx := context.Background()
	latencyTracker := NewLatencyTracker()
	
	var totalRequests int64
	var successfulRequests int64
	var failedRequests int64
	
	semaphore := make(chan struct{}, concurrency)
	wg := sync.WaitGroup{}
	
	start := time.Now()
	
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(requestNum int) {
			defer wg.Done()
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release
			
			// Create test authorization request
			user := createTestUser(requestNum)
			authRequest := &auth.AuthorizationRequest{
				User:     user,
				Resource: getRandomResource(),
				Action:   getRandomAction(),
				Context: auth.RequestContext{
					RequestID: fmt.Sprintf("perf-test-%d", requestNum),
					IPAddress: "192.168.1.100",
				},
			}
			
			requestStart := time.Now()
			_, err := opa.Authorize(ctx, authRequest)
			requestLatency := time.Since(requestStart)
			
			atomic.AddInt64(&totalRequests, 1)
			if err != nil {
				atomic.AddInt64(&failedRequests, 1)
			} else {
				atomic.AddInt64(&successfulRequests, 1)
			}
			
			latencyTracker.Record(requestLatency)
		}(i)
	}
	
	wg.Wait()
	duration := time.Since(start)
	
	// Calculate metrics
	min, max, avg, p50, p95, p99 := latencyTracker.GetMetrics()
	
	t.Logf("OPA Authorization Performance Results:")
	t.Logf("  Total Requests: %d", totalRequests)
	t.Logf("  Successful: %d", successfulRequests)
	t.Logf("  Failed: %d", failedRequests)
	t.Logf("  Duration: %v", duration)
	t.Logf("  Throughput: %.2f RPS", float64(totalRequests)/duration.Seconds())
	t.Logf("  Latency - Min: %v, Max: %v, Avg: %v", min, max, avg)
	t.Logf("  Latency - P50: %v, P95: %v, P99: %v", p50, p95, p99)
	
	// Performance assertions
	assert.True(t, avg < 100*time.Millisecond, "Average latency should be under 100ms")
	assert.True(t, p95 < 200*time.Millisecond, "P95 latency should be under 200ms")
	assert.True(t, float64(successfulRequests)/float64(totalRequests) > 0.99, "Success rate should be > 99%")
	
	throughput := float64(totalRequests) / duration.Seconds()
	assert.True(t, throughput > 100, "Throughput should be > 100 RPS")
}

func testOPAWorkloadAuthorizationLatency(t *testing.T, opa *auth.OPAAuthorizer, numRequests, concurrency int) {
	ctx := context.Background()
	latencyTracker := NewLatencyTracker()
	
	var totalRequests int64
	var successfulRequests int64
	
	semaphore := make(chan struct{}, concurrency)
	wg := sync.WaitGroup{}
	
	start := time.Now()
	
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(requestNum int) {
			defer wg.Done()
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release
			
			sourceSpiffeID := getRandomSourceSpiffeID()
			targetSpiffeID := getRandomTargetSpiffeID()
			requestContext := auth.RequestContext{
				RequestID: fmt.Sprintf("workload-perf-%d", requestNum),
				Protocol:  "grpc",
			}
			
			requestStart := time.Now()
			_, err := opa.AuthorizeWorkload(ctx, sourceSpiffeID, targetSpiffeID, requestContext)
			requestLatency := time.Since(requestStart)
			
			atomic.AddInt64(&totalRequests, 1)
			if err == nil {
				atomic.AddInt64(&successfulRequests, 1)
			}
			
			latencyTracker.Record(requestLatency)
		}(i)
	}
	
	wg.Wait()
	duration := time.Since(start)
	
	min, max, avg, p50, p95, p99 := latencyTracker.GetMetrics()
	
	t.Logf("OPA Workload Authorization Performance Results:")
	t.Logf("  Total Requests: %d", totalRequests)
	t.Logf("  Successful: %d", successfulRequests)
	t.Logf("  Duration: %v", duration)
	t.Logf("  Throughput: %.2f RPS", float64(totalRequests)/duration.Seconds())
	t.Logf("  Latency - Min: %v, Max: %v, Avg: %v", min, max, avg)
	t.Logf("  Latency - P50: %v, P95: %v, P99: %v", p50, p95, p99)
	
	assert.True(t, avg < 50*time.Millisecond, "Workload authorization avg latency should be under 50ms")
	assert.True(t, p95 < 100*time.Millisecond, "Workload authorization P95 latency should be under 100ms")
}

func testOPADataAccessLatency(t *testing.T, opa *auth.OPAAuthorizer, numRequests, concurrency int) {
	ctx := context.Background()
	latencyTracker := NewLatencyTracker()
	
	var totalRequests int64
	var successfulRequests int64
	
	semaphore := make(chan struct{}, concurrency)
	wg := sync.WaitGroup{}
	
	start := time.Now()
	
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(requestNum int) {
			defer wg.Done()
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release
			
			user := createTestUser(requestNum)
			dataType := getRandomDataType()
			purpose := getRandomPurpose()
			fields := getRandomFields()
			
			requestStart := time.Now()
			_, err := opa.AuthorizeDataAccess(ctx, user, dataType, purpose, fields)
			requestLatency := time.Since(requestStart)
			
			atomic.AddInt64(&totalRequests, 1)
			if err == nil {
				atomic.AddInt64(&successfulRequests, 1)
			}
			
			latencyTracker.Record(requestLatency)
		}(i)
	}
	
	wg.Wait()
	duration := time.Since(start)
	
	min, max, avg, p50, p95, p99 := latencyTracker.GetMetrics()
	
	t.Logf("OPA Data Access Authorization Performance Results:")
	t.Logf("  Total Requests: %d", totalRequests)
	t.Logf("  Successful: %d", successfulRequests)
	t.Logf("  Duration: %v", duration)
	t.Logf("  Throughput: %.2f RPS", float64(totalRequests)/duration.Seconds())
	t.Logf("  Latency - Min: %v, Max: %v, Avg: %v", min, max, avg)
	t.Logf("  Latency - P50: %v, P95: %v, P99: %v", p50, p95, p99)
	
	assert.True(t, avg < 75*time.Millisecond, "Data access authorization avg latency should be under 75ms")
	assert.True(t, p95 < 150*time.Millisecond, "Data access authorization P95 latency should be under 150ms")
}

// Test: Load Testing with Sustained Traffic
func TestSustainedLoadTesting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping sustained load tests in short mode")
	}

	config := getPerformanceTestConfig()
	
	// Initialize OPA
	opaConfig := &auth.OPAConfig{
		ServiceURL:     config.OPAURL,
		PolicyPath:     config.OPAPolicyPath,
		DecisionLog:    false,
		MetricsEnabled: false,
	}

	opa, err := auth.NewOPAAuthorizer(context.Background(), opaConfig)
	require.NoError(t, err)
	defer opa.Close()

	t.Run("Sustained Load - 5 Minutes", func(t *testing.T) {
		testSustainedLoad(t, opa, 5*time.Minute, 50, 100)
	})
}

func testSustainedLoad(t *testing.T, opa *auth.OPAAuthorizer, duration time.Duration, concurrency, targetRPS int) {
	ctx := context.Background()
	
	var totalRequests int64
	var successfulRequests int64
	var failedRequests int64
	
	latencyTracker := NewLatencyTracker()
	requestInterval := time.Second / time.Duration(targetRPS)
	
	done := make(chan struct{})
	semaphore := make(chan struct{}, concurrency)
	
	// Request generator
	go func() {
		ticker := time.NewTicker(requestInterval)
		defer ticker.Stop()
		
		startTime := time.Now()
		requestNum := 0
		
		for {
			select {
			case <-ticker.C:
				if time.Since(startTime) >= duration {
					close(done)
					return
				}
				
				go func(reqNum int) {
					semaphore <- struct{}{} // Acquire
					defer func() { <-semaphore }() // Release
					
					user := createTestUser(reqNum)
					authRequest := &auth.AuthorizationRequest{
						User:     user,
						Resource: getRandomResource(),
						Action:   getRandomAction(),
						Context: auth.RequestContext{
							RequestID: fmt.Sprintf("sustained-load-%d", reqNum),
						},
					}
					
					requestStart := time.Now()
					_, err := opa.Authorize(ctx, authRequest)
					requestLatency := time.Since(requestStart)
					
					atomic.AddInt64(&totalRequests, 1)
					if err != nil {
						atomic.AddInt64(&failedRequests, 1)
					} else {
						atomic.AddInt64(&successfulRequests, 1)
					}
					
					latencyTracker.Record(requestLatency)
				}(requestNum)
				
				requestNum++
			case <-done:
				return
			}
		}
	}()
	
	// Wait for test completion
	<-done
	
	// Give time for remaining requests to complete
	time.Sleep(5 * time.Second)
	
	// Calculate metrics
	min, max, avg, p50, p95, p99 := latencyTracker.GetMetrics()
	actualRPS := float64(totalRequests) / duration.Seconds()
	errorRate := float64(failedRequests) / float64(totalRequests)
	
	t.Logf("Sustained Load Test Results:")
	t.Logf("  Duration: %v", duration)
	t.Logf("  Target RPS: %d, Actual RPS: %.2f", targetRPS, actualRPS)
	t.Logf("  Total Requests: %d", totalRequests)
	t.Logf("  Successful: %d", successfulRequests)
	t.Logf("  Failed: %d", failedRequests)
	t.Logf("  Error Rate: %.2f%%", errorRate*100)
	t.Logf("  Latency - Min: %v, Max: %v, Avg: %v", min, max, avg)
	t.Logf("  Latency - P50: %v, P95: %v, P99: %v", p50, p95, p99)
	
	// Performance assertions
	assert.True(t, actualRPS >= float64(targetRPS)*0.9, "Should achieve at least 90% of target RPS")
	assert.True(t, errorRate < 0.01, "Error rate should be < 1%")
	assert.True(t, avg < 100*time.Millisecond, "Average latency should remain under 100ms during load")
	assert.True(t, p95 < 300*time.Millisecond, "P95 latency should remain under 300ms during load")
}

// Test: Memory and Resource Usage
func TestResourceUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping resource usage tests in short mode")
	}

	config := getPerformanceTestConfig()
	
	opaConfig := &auth.OPAConfig{
		ServiceURL:     config.OPAURL,
		PolicyPath:     config.OPAPolicyPath,
		DecisionLog:    false,
		MetricsEnabled: false,
	}

	opa, err := auth.NewOPAAuthorizer(context.Background(), opaConfig)
	require.NoError(t, err)
	defer opa.Close()

	t.Run("Memory Usage During High Load", func(t *testing.T) {
		testMemoryUsage(t, opa)
	})
}

func testMemoryUsage(t *testing.T, opa *auth.OPAAuthorizer) {
	// This is a simplified memory test
	// In production, you'd use runtime.ReadMemStats() or external profiling
	
	ctx := context.Background()
	numRequests := 10000
	concurrency := 100
	
	// Record initial memory (simplified)
	t.Logf("Starting memory usage test with %d requests at %d concurrency", numRequests, concurrency)
	
	var totalRequests int64
	semaphore := make(chan struct{}, concurrency)
	wg := sync.WaitGroup{}
	
	start := time.Now()
	
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(requestNum int) {
			defer wg.Done()
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release
			
			user := createTestUser(requestNum)
			authRequest := &auth.AuthorizationRequest{
				User:     user,
				Resource: getRandomResource(),
				Action:   getRandomAction(),
				Context: auth.RequestContext{
					RequestID: fmt.Sprintf("memory-test-%d", requestNum),
				},
			}
			
			_, err := opa.Authorize(ctx, authRequest)
			if err == nil {
				atomic.AddInt64(&totalRequests, 1)
			}
		}(i)
	}
	
	wg.Wait()
	duration := time.Since(start)
	
	t.Logf("Memory usage test completed:")
	t.Logf("  Processed %d requests in %v", totalRequests, duration)
	t.Logf("  Average throughput: %.2f RPS", float64(totalRequests)/duration.Seconds())
	
	// In a real test, you'd check memory growth, GC pressure, etc.
	assert.True(t, totalRequests > int64(numRequests*0.95), "Should process at least 95% of requests")
}

// Test: Concurrent User Simulation
func TestConcurrentUserSimulation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent user simulation in short mode")
	}

	config := getPerformanceTestConfig()
	
	opaConfig := &auth.OPAConfig{
		ServiceURL:     config.OPAURL,
		PolicyPath:     config.OPAPolicyPath,
		DecisionLog:    false,
		MetricsEnabled: false,
	}

	opa, err := auth.NewOPAAuthorizer(context.Background(), opaConfig)
	require.NoError(t, err)
	defer opa.Close()

	t.Run("100 Concurrent Users", func(t *testing.T) {
		testConcurrentUsers(t, opa, 100, 30*time.Second)
	})
}

func testConcurrentUsers(t *testing.T, opa *auth.OPAAuthorizer, numUsers int, duration time.Duration) {
	ctx := context.Background()
	
	var totalRequests int64
	var successfulRequests int64
	
	latencyTracker := NewLatencyTracker()
	
	userChannels := make([]chan struct{}, numUsers)
	for i := range userChannels {
		userChannels[i] = make(chan struct{})
	}
	
	wg := sync.WaitGroup{}
	
	// Start concurrent users
	for userID := 0; userID < numUsers; userID++ {
		wg.Add(1)
		go func(uid int) {
			defer wg.Done()
			
			user := createTestUser(uid)
			requestNum := 0
			
			userStart := time.Now()
			for time.Since(userStart) < duration {
				// Simulate user behavior - random delay between requests
				time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
				
				authRequest := &auth.AuthorizationRequest{
					User:     user,
					Resource: getRandomResource(),
					Action:   getRandomAction(),
					Context: auth.RequestContext{
						RequestID: fmt.Sprintf("user-%d-req-%d", uid, requestNum),
					},
				}
				
				requestStart := time.Now()
				_, err := opa.Authorize(ctx, authRequest)
				requestLatency := time.Since(requestStart)
				
				atomic.AddInt64(&totalRequests, 1)
				if err == nil {
					atomic.AddInt64(&successfulRequests, 1)
				}
				
				latencyTracker.Record(requestLatency)
				requestNum++
			}
		}(userID)
	}
	
	wg.Wait()
	
	min, max, avg, p50, p95, p99 := latencyTracker.GetMetrics()
	actualRPS := float64(totalRequests) / duration.Seconds()
	successRate := float64(successfulRequests) / float64(totalRequests)
	
	t.Logf("Concurrent User Simulation Results:")
	t.Logf("  Users: %d, Duration: %v", numUsers, duration)
	t.Logf("  Total Requests: %d", totalRequests)
	t.Logf("  Successful: %d (%.2f%%)", successfulRequests, successRate*100)
	t.Logf("  Throughput: %.2f RPS", actualRPS)
	t.Logf("  Latency - Min: %v, Max: %v, Avg: %v", min, max, avg)
	t.Logf("  Latency - P50: %v, P95: %v, P99: %v", p50, p95, p99)
	
	assert.True(t, successRate > 0.95, "Success rate should be > 95% for concurrent users")
	assert.True(t, avg < 200*time.Millisecond, "Average latency should be reasonable under concurrent load")
}

// Helper functions

func getPerformanceTestConfig() *PerformanceTestConfig {
	return &PerformanceTestConfig{
		OPAURL:         getEnvOrDefault("OPA_URL", "http://localhost:8181"),
		OPAPolicyPath:  "/zero_trust/authz",
		OPADatabaseURL: getEnvOrDefault("OPA_DB_URL", "postgres://opa:opa123@localhost:5435/opa_decisions?sslmode=disable"),
		
		KeycloakURL:      getEnvOrDefault("KEYCLOAK_URL", "http://localhost:8080"),
		KeycloakRealm:    getEnvOrDefault("KEYCLOAK_REALM", "zero-trust"),
		KeycloakClientID: getEnvOrDefault("KEYCLOAK_CLIENT_ID", "zero-trust-app"),
		KeycloakSecret:   getEnvOrDefault("KEYCLOAK_CLIENT_SECRET", "test-secret"),
		
		TestDuration:      5 * time.Minute,
		ConcurrentUsers:   100,
		RequestsPerSecond: 1000,
		WarmupDuration:    30 * time.Second,
		
		MaxLatencyMs:     100,
		MaxP95LatencyMs:  200,
		MinThroughputRPS: 500,
		MaxErrorRate:     0.01,
	}
}

func createTestUser(requestNum int) auth.UserContext {
	trustLevels := []int{25, 50, 75, 100}
	roles := [][]string{
		{"user"},
		{"user", "manager"},
		{"user", "admin"},
		{"user", "finance"},
		{"user", "medical"},
	}
	
	return auth.UserContext{
		UserID:         fmt.Sprintf("perf-user-%d", requestNum%1000),
		Email:          fmt.Sprintf("user%d@test.com", requestNum%1000),
		Roles:          roles[requestNum%len(roles)],
		TrustLevel:     trustLevels[requestNum%len(trustLevels)],
		DeviceVerified: requestNum%2 == 0,
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}
}

func getRandomResource() string {
	resources := []string{"profile", "dashboard", "admin", "financial", "reports", "analytics"}
	return resources[rand.Intn(len(resources))]
}

func getRandomAction() string {
	actions := []string{"read", "write", "update", "delete", "create"}
	return actions[rand.Intn(len(actions))]
}

func getRandomSourceSpiffeID() string {
	sources := []string{
		"spiffe://zero-trust.dev/api/auth-service",
		"spiffe://zero-trust.dev/worker/job-processor",
		"spiffe://zero-trust.dev/client/web-app",
	}
	return sources[rand.Intn(len(sources))]
}

func getRandomTargetSpiffeID() string {
	targets := []string{
		"spiffe://zero-trust.dev/worker/job-processor",
		"spiffe://zero-trust.dev/admin/controller",
		"spiffe://zero-trust.dev/api/auth-service",
	}
	return targets[rand.Intn(len(targets))]
}

func getRandomDataType() string {
	dataTypes := []string{
		"personal_data",
		"financial_transactions",
		"personal_health_information",
		"payment_card_data",
	}
	return dataTypes[rand.Intn(len(dataTypes))]
}

func getRandomPurpose() string {
	purposes := []string{
		"medical_treatment",
		"contract_performance",
		"financial_reporting",
		"payment_processing",
		"analytics",
	}
	return purposes[rand.Intn(len(purposes))]
}

func getRandomFields() []string {
	allFields := []string{
		"name", "email", "phone", "address", "dob",
		"account_number", "transaction_amount", "card_number",
		"diagnosis", "treatment_plan", "medication",
	}
	
	numFields := rand.Intn(3) + 1
	fields := make([]string, numFields)
	for i := 0; i < numFields; i++ {
		fields[i] = allFields[rand.Intn(len(allFields))]
	}
	return fields
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Example of how to run these tests:
// go test -v ./tests/performance -run TestOPAPolicyEvaluationPerformance
//
// To run with services:
// docker-compose -f docker-compose.opa.yml up -d
// go test -v ./tests/performance -timeout 10m
// docker-compose -f docker-compose.opa.yml down
//
// To run sustained load tests:
// go test -v ./tests/performance -run TestSustainedLoadTesting -timeout 20m
//
// To run with custom parameters:
// OPA_URL=http://localhost:8181 go test -v ./tests/performance