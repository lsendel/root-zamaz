// End-to-end tests for service-to-service communication with workload identity
// Tests SPIRE workload attestation and OPA workload authorization policies
package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"your-project/pkg/auth"
)

// WorkloadCommunicationTestSuite tests service-to-service communication
type WorkloadCommunicationTestSuite struct {
	suite.Suite
	
	// Components
	opa      *auth.OPAAuthorizer
	spire    *auth.SPIREAuthenticator
	
	// Test configuration
	testConfig *WorkloadTestConfig
	
	// Test servers
	apiServer    *httptest.Server
	workerServer *httptest.Server
	adminServer  *httptest.Server
}

// WorkloadTestConfig holds workload testing configuration
type WorkloadTestConfig struct {
	OPAURL         string
	OPAPolicyPath  string
	
	SPIRESocketPath  string
	SPIREServerURL   string
	SPIRETrustDomain string
	
	// Test SPIFFE IDs
	APIServiceSPIFFE    string
	WorkerServiceSPIFFE string
	AdminServiceSPIFFE  string
	ClientServiceSPIFFE string
	
	TestTimeout time.Duration
}

// SetupSuite initializes the workload communication test suite
func (suite *WorkloadCommunicationTestSuite) SetupSuite() {
	suite.testConfig = &WorkloadTestConfig{
		OPAURL:         getEnvOrDefault("OPA_URL", "http://localhost:8181"),
		OPAPolicyPath:  "/zero_trust/workload",
		
		SPIRESocketPath:  getEnvOrDefault("SPIRE_SOCKET_PATH", "/tmp/spire-agent/public/api.sock"),
		SPIREServerURL:   getEnvOrDefault("SPIRE_SERVER_URL", "localhost:8081"),
		SPIRETrustDomain: getEnvOrDefault("SPIRE_TRUST_DOMAIN", "zero-trust.dev"),
		
		// Predefined SPIFFE IDs for test services
		APIServiceSPIFFE:    "spiffe://zero-trust.dev/api/auth-service",
		WorkerServiceSPIFFE: "spiffe://zero-trust.dev/worker/job-processor",
		AdminServiceSPIFFE:  "spiffe://zero-trust.dev/admin/controller",
		ClientServiceSPIFFE: "spiffe://zero-trust.dev/client/web-app",
		
		TestTimeout: 30 * time.Second,
	}

	// Check if OPA is available
	if !suite.isOPAAvailable() {
		suite.T().Skip("OPA not available, skipping workload communication tests")
	}

	// Initialize OPA
	opaConfig := &auth.OPAConfig{
		ServiceURL:     suite.testConfig.OPAURL,
		PolicyPath:     suite.testConfig.OPAPolicyPath,
		DecisionLog:    false, // Disable for workload tests
		MetricsEnabled: false,
	}

	var err error
	suite.opa, err = auth.NewOPAAuthorizer(context.Background(), opaConfig)
	require.NoError(suite.T(), err, "Failed to initialize OPA for workload tests")

	// Initialize SPIRE (optional)
	spireConfig := &auth.SPIREConfig{
		SocketPath:  suite.testConfig.SPIRESocketPath,
		ServerURL:   suite.testConfig.SPIREServerURL,
		TrustDomain: suite.testConfig.SPIRETrustDomain,
	}

	suite.spire, err = auth.NewSPIREAuthenticator(spireConfig)
	if err != nil {
		suite.T().Logf("SPIRE not available: %v", err)
		suite.spire = nil
	}

	// Setup test services
	suite.setupTestServices()
}

// TearDownSuite cleans up after workload tests
func (suite *WorkloadCommunicationTestSuite) TearDownSuite() {
	if suite.opa != nil {
		suite.opa.Close()
	}
	if suite.spire != nil {
		suite.spire.Close()
	}
	if suite.apiServer != nil {
		suite.apiServer.Close()
	}
	if suite.workerServer != nil {
		suite.workerServer.Close()
	}
	if suite.adminServer != nil {
		suite.adminServer.Close()
	}
}

// setupTestServices creates mock services for testing
func (suite *WorkloadCommunicationTestSuite) setupTestServices() {
	// API Service
	suite.apiServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"service": "api", "spiffe_id": "%s", "status": "running"}`, suite.testConfig.APIServiceSPIFFE)
	}))

	// Worker Service
	suite.workerServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"service": "worker", "spiffe_id": "%s", "status": "running"}`, suite.testConfig.WorkerServiceSPIFFE)
	}))

	// Admin Service
	suite.adminServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"service": "admin", "spiffe_id": "%s", "status": "running"}`, suite.testConfig.AdminServiceSPIFFE)
	}))
}

// Test: API service to worker service communication (should be allowed)
func (suite *WorkloadCommunicationTestSuite) TestAPIToWorkerCommunication() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
	defer cancel()

	sourceSpiffeID := suite.testConfig.APIServiceSPIFFE
	targetSpiffeID := suite.testConfig.WorkerServiceSPIFFE

	requestContext := auth.RequestContext{
		RequestID: "test-api-to-worker",
		Protocol:  "grpc",
	}

	response, err := suite.opa.AuthorizeWorkload(ctx, sourceSpiffeID, targetSpiffeID, requestContext)
	require.NoError(suite.T(), err)

	assert.True(suite.T(), response.Allow, "API service should be able to connect to worker service")
	assert.NotEmpty(suite.T(), response.DecisionID)
	suite.T().Logf("API→Worker communication allowed (Decision ID: %s)", response.DecisionID)
}

// Test: Worker service to API service communication (should be allowed - bidirectional)
func (suite *WorkloadCommunicationTestSuite) TestWorkerToAPICommunication() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
	defer cancel()

	sourceSpiffeID := suite.testConfig.WorkerServiceSPIFFE
	targetSpiffeID := suite.testConfig.APIServiceSPIFFE

	requestContext := auth.RequestContext{
		RequestID: "test-worker-to-api",
		Protocol:  "grpc",
	}

	response, err := suite.opa.AuthorizeWorkload(ctx, sourceSpiffeID, targetSpiffeID, requestContext)
	require.NoError(suite.T(), err)

	assert.True(suite.T(), response.Allow, "Worker service should be able to connect to API service")
	suite.T().Logf("Worker→API communication allowed (Decision ID: %s)", response.DecisionID)
}

// Test: Worker service to admin service communication (should be denied)
func (suite *WorkloadCommunicationTestSuite) TestWorkerToAdminCommunicationDenied() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
	defer cancel()

	sourceSpiffeID := suite.testConfig.WorkerServiceSPIFFE
	targetSpiffeID := suite.testConfig.AdminServiceSPIFFE

	requestContext := auth.RequestContext{
		RequestID: "test-worker-to-admin",
		Protocol:  "grpc",
	}

	response, err := suite.opa.AuthorizeWorkload(ctx, sourceSpiffeID, targetSpiffeID, requestContext)
	require.NoError(suite.T(), err)

	assert.False(suite.T(), response.Allow, "Worker service should NOT be able to connect to admin service")
	assert.NotEmpty(suite.T(), response.Reasons, "Should provide denial reasons")
	suite.T().Logf("Worker→Admin communication denied: %v", response.Reasons)
}

// Test: API service to admin service communication (should be allowed)
func (suite *WorkloadCommunicationTestSuite) TestAPIToAdminCommunication() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
	defer cancel()

	sourceSpiffeID := suite.testConfig.APIServiceSPIFFE
	targetSpiffeID := suite.testConfig.AdminServiceSPIFFE

	requestContext := auth.RequestContext{
		RequestID: "test-api-to-admin",
		Protocol:  "grpc",
	}

	response, err := suite.opa.AuthorizeWorkload(ctx, sourceSpiffeID, targetSpiffeID, requestContext)
	require.NoError(suite.T(), err)

	assert.True(suite.T(), response.Allow, "API service should be able to connect to admin service")
	suite.T().Logf("API→Admin communication allowed (Decision ID: %s)", response.DecisionID)
}

// Test: Client service communication restrictions
func (suite *WorkloadCommunicationTestSuite) TestClientServiceRestrictions() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
	defer cancel()

	sourceSpiffeID := suite.testConfig.ClientServiceSPIFFE

	tests := []struct {
		name           string
		targetSpiffeID string
		expectedAllow  bool
		description    string
	}{
		{
			name:           "Client to API",
			targetSpiffeID: suite.testConfig.APIServiceSPIFFE,
			expectedAllow:  true,
			description:    "Client should be able to connect to API service",
		},
		{
			name:           "Client to Worker",
			targetSpiffeID: suite.testConfig.WorkerServiceSPIFFE,
			expectedAllow:  false,
			description:    "Client should NOT be able to connect directly to worker service",
		},
		{
			name:           "Client to Admin",
			targetSpiffeID: suite.testConfig.AdminServiceSPIFFE,
			expectedAllow:  false,
			description:    "Client should NOT be able to connect to admin service",
		},
	}

	for _, test := range tests {
		suite.Run(test.name, func() {
			requestContext := auth.RequestContext{
				RequestID: fmt.Sprintf("test-client-%s", test.name),
				Protocol:  "https",
			}

			response, err := suite.opa.AuthorizeWorkload(ctx, sourceSpiffeID, test.targetSpiffeID, requestContext)
			require.NoError(suite.T(), err)

			assert.Equal(suite.T(), test.expectedAllow, response.Allow, test.description)
			if !response.Allow {
				assert.NotEmpty(suite.T(), response.Reasons, "Should provide denial reasons")
				suite.T().Logf("%s denied: %v", test.name, response.Reasons)
			} else {
				suite.T().Logf("%s allowed (Decision ID: %s)", test.name, response.DecisionID)
			}
		})
	}
}

// Test: Protocol-specific rules
func (suite *WorkloadCommunicationTestSuite) TestProtocolSpecificRules() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
	defer cancel()

	sourceSpiffeID := suite.testConfig.APIServiceSPIFFE
	targetSpiffeID := suite.testConfig.WorkerServiceSPIFFE

	protocols := []struct {
		protocol      string
		expectedAllow bool
		description   string
	}{
		{
			protocol:      "grpc",
			expectedAllow: true,
			description:   "gRPC should be allowed for service communication",
		},
		{
			protocol:      "https",
			expectedAllow: true,
			description:   "HTTPS should be allowed for service communication",
		},
		{
			protocol:      "http",
			expectedAllow: false,
			description:   "HTTP should be denied (insecure)",
		},
		{
			protocol:      "tcp",
			expectedAllow: false,
			description:   "Raw TCP should be denied",
		},
	}

	for _, protocolTest := range protocols {
		suite.Run(fmt.Sprintf("Protocol %s", protocolTest.protocol), func() {
			requestContext := auth.RequestContext{
				RequestID: fmt.Sprintf("test-protocol-%s", protocolTest.protocol),
				Protocol:  protocolTest.protocol,
			}

			response, err := suite.opa.AuthorizeWorkload(ctx, sourceSpiffeID, targetSpiffeID, requestContext)
			require.NoError(suite.T(), err)

			assert.Equal(suite.T(), protocolTest.expectedAllow, response.Allow, protocolTest.description)
			if !response.Allow {
				suite.T().Logf("Protocol %s denied: %v", protocolTest.protocol, response.Reasons)
			} else {
				suite.T().Logf("Protocol %s allowed", protocolTest.protocol)
			}
		})
	}
}

// Test: Invalid SPIFFE IDs
func (suite *WorkloadCommunicationTestSuite) TestInvalidSpiffeIDs() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
	defer cancel()

	invalidSpiffeIDs := []struct {
		name     string
		spiffeID string
	}{
		{"Empty SPIFFE ID", ""},
		{"Invalid format", "not-a-spiffe-id"},
		{"Wrong trust domain", "spiffe://other-domain.com/service/test"},
		{"Missing service path", "spiffe://zero-trust.dev/"},
		{"Malformed URI", "spiffe:///service/test"},
	}

	targetSpiffeID := suite.testConfig.WorkerServiceSPIFFE

	for _, invalidTest := range invalidSpiffeIDs {
		suite.Run(invalidTest.name, func() {
			requestContext := auth.RequestContext{
				RequestID: fmt.Sprintf("test-invalid-%s", invalidTest.name),
				Protocol:  "grpc",
			}

			response, err := suite.opa.AuthorizeWorkload(ctx, invalidTest.spiffeID, targetSpiffeID, requestContext)
			require.NoError(suite.T(), err)

			assert.False(suite.T(), response.Allow, "Invalid SPIFFE ID should be denied")
			assert.NotEmpty(suite.T(), response.Reasons, "Should provide denial reasons")
			suite.T().Logf("Invalid SPIFFE ID '%s' denied: %v", invalidTest.spiffeID, response.Reasons)
		})
	}
}

// Test: Time-based workload access controls
func (suite *WorkloadCommunicationTestSuite) TestTimeBasedWorkloadAccess() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
	defer cancel()

	sourceSpiffeID := suite.testConfig.WorkerServiceSPIFFE
	targetSpiffeID := suite.testConfig.APIServiceSPIFFE

	// Test current time (should generally be allowed)
	suite.Run("Current Time Access", func() {
		requestContext := auth.RequestContext{
			RequestID: "test-current-time",
			Protocol:  "grpc",
		}

		response, err := suite.opa.AuthorizeWorkload(ctx, sourceSpiffeID, targetSpiffeID, requestContext)
		require.NoError(suite.T(), err)

		suite.T().Logf("Current time access: %t", response.Allow)
		if !response.Allow {
			suite.T().Logf("Denial reasons: %v", response.Reasons)
		}
	})

	// Note: Testing specific time periods would require mocking time in OPA policies
	// or setting up test-specific time contexts
}

// Test: Load testing for workload authorization
func (suite *WorkloadCommunicationTestSuite) TestWorkloadAuthorizationLoad() {
	if testing.Short() {
		suite.T().Skip("Skipping load test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sourceSpiffeID := suite.testConfig.APIServiceSPIFFE
	targetSpiffeID := suite.testConfig.WorkerServiceSPIFFE

	const numRequests = 100
	const concurrency = 10

	suite.Run("Concurrent Authorization Requests", func() {
		semaphore := make(chan struct{}, concurrency)
		results := make(chan bool, numRequests)
		errors := make(chan error, numRequests)

		start := time.Now()

		for i := 0; i < numRequests; i++ {
			go func(requestNum int) {
				semaphore <- struct{}{} // Acquire
				defer func() { <-semaphore }() // Release

				requestContext := auth.RequestContext{
					RequestID: fmt.Sprintf("load-test-%d", requestNum),
					Protocol:  "grpc",
				}

				response, err := suite.opa.AuthorizeWorkload(ctx, sourceSpiffeID, targetSpiffeID, requestContext)
				if err != nil {
					errors <- err
					return
				}

				results <- response.Allow
			}(i)
		}

		// Collect results
		var allowCount, denyCount, errorCount int
		for i := 0; i < numRequests; i++ {
			select {
			case allowed := <-results:
				if allowed {
					allowCount++
				} else {
					denyCount++
				}
			case err := <-errors:
				errorCount++
				suite.T().Logf("Authorization error: %v", err)
			case <-ctx.Done():
				suite.T().Fatal("Load test timed out")
			}
		}

		duration := time.Since(start)
		suite.T().Logf("Load test completed in %v", duration)
		suite.T().Logf("Results: %d allowed, %d denied, %d errors", allowCount, denyCount, errorCount)
		suite.T().Logf("Average time per request: %v", duration/time.Duration(numRequests))

		assert.Equal(suite.T(), 0, errorCount, "Should have no errors")
		assert.True(suite.T(), allowCount > 0, "Should have some allowed requests")
	})
}

// Test: mTLS certificate validation (if SPIRE is available)
func (suite *WorkloadCommunicationTestSuite) TestMTLSCertificateValidation() {
	if suite.spire == nil {
		suite.T().Skip("SPIRE not available, skipping mTLS tests")
	}

	suite.Run("SPIRE Certificate Retrieval", func() {
		ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
		defer cancel()

		// Attempt to get workload identity
		identity, err := suite.spire.GetWorkloadIdentity(ctx)
		if err != nil {
			suite.T().Skipf("Could not retrieve workload identity: %v", err)
		}

		assert.NotEmpty(suite.T(), identity.SpiffeID)
		assert.NotNil(suite.T(), identity.PrivateKey)
		assert.NotEmpty(suite.T(), identity.Certificates)
		suite.T().Logf("Retrieved workload identity: %s", identity.SpiffeID)
	})

	// Note: Testing actual mTLS would require setting up test services with SPIRE certificates
}

// Helper methods

func (suite *WorkloadCommunicationTestSuite) isOPAAvailable() bool {
	resp, err := http.Get(suite.testConfig.OPAURL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// Mock gRPC service for testing
type mockGRPCService struct {
	spiffeID string
}

func (s *mockGRPCService) setupServer(address string) (*grpc.Server, net.Listener, error) {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		return nil, nil, err
	}

	// In a real implementation, this would use SPIRE-generated certificates
	server := grpc.NewServer()
	
	return server, lis, nil
}

// Test suite runner
func TestWorkloadCommunication(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping workload communication tests in short mode")
	}
	
	suite.Run(t, new(WorkloadCommunicationTestSuite))
}

// Individual test functions for go test compatibility

func TestWorkloadAPIToWorkerCommunication(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping workload tests in short mode")
	}
	
	suite := new(WorkloadCommunicationTestSuite)
	suite.SetT(t)
	suite.SetupSuite()
	defer suite.TearDownSuite()
	
	suite.TestAPIToWorkerCommunication()
}

func TestWorkloadClientServiceRestrictions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping workload tests in short mode")
	}
	
	suite := new(WorkloadCommunicationTestSuite)
	suite.SetT(t)
	suite.SetupSuite()
	defer suite.TearDownSuite()
	
	suite.TestClientServiceRestrictions()
}

func TestWorkloadProtocolSpecificRules(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping workload tests in short mode")
	}
	
	suite := new(WorkloadCommunicationTestSuite)
	suite.SetT(t)
	suite.SetupSuite()
	defer suite.TearDownSuite()
	
	suite.TestProtocolSpecificRules()
}

// Example of how to run these tests:
// go test -v ./tests/e2e -run TestWorkloadCommunication
//
// To run with OPA:
// docker-compose -f docker-compose.opa.yml up -d
// go test -v ./tests/e2e -run TestWorkload
// docker-compose -f docker-compose.opa.yml down
//
// To run with SPIRE (requires SPIRE setup):
// # Start SPIRE server and agent
// go test -v ./tests/e2e -run TestWorkload