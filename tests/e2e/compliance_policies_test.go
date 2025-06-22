// End-to-end tests for data classification and compliance policies
// Tests GDPR, SOX, HIPAA compliance through OPA policy engine
package e2e

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
	"github.com/stretchr/testify/suite"

	"your-project/pkg/auth"
	"your-project/pkg/middleware"
)

// CompliancePoliciesTestSuite tests data classification and compliance
type CompliancePoliciesTestSuite struct {
	suite.Suite
	
	// Components
	opa        *auth.OPAAuthorizer
	middleware *middleware.ZeroTrustUnifiedMiddleware
	
	// Test router with compliance endpoints
	router *gin.Engine
	
	// Test configuration
	testConfig *ComplianceTestConfig
}

// ComplianceTestConfig holds compliance testing configuration
type ComplianceTestConfig struct {
	OPAURL         string
	OPAPolicyPath  string
	OPADatabaseURL string
	
	TestTimeout time.Duration
}

// SetupSuite initializes the compliance test suite
func (suite *CompliancePoliciesTestSuite) SetupSuite() {
	suite.testConfig = &ComplianceTestConfig{
		OPAURL:         getEnvOrDefault("OPA_URL", "http://localhost:8181"),
		OPAPolicyPath:  "/zero_trust/data",
		OPADatabaseURL: getEnvOrDefault("OPA_DB_URL", "postgres://opa:opa123@localhost:5435/opa_decisions?sslmode=disable"),
		
		TestTimeout: 30 * time.Second,
	}

	// Check if OPA is available
	if !suite.isOPAAvailable() {
		suite.T().Skip("OPA not available, skipping compliance policy tests")
	}

	// Initialize OPA
	opaConfig := &auth.OPAConfig{
		ServiceURL:     suite.testConfig.OPAURL,
		PolicyPath:     suite.testConfig.OPAPolicyPath,
		DatabaseURL:    suite.testConfig.OPADatabaseURL,
		DecisionLog:    true,  // Enable for compliance auditing
		MetricsEnabled: true,
	}

	var err error
	suite.opa, err = auth.NewOPAAuthorizer(context.Background(), opaConfig)
	require.NoError(suite.T(), err, "Failed to initialize OPA for compliance tests")

	// Setup compliance test router
	gin.SetMode(gin.TestMode)
	suite.router = gin.New()
	suite.setupComplianceRoutes()
}

// TearDownSuite cleans up after compliance tests
func (suite *CompliancePoliciesTestSuite) TearDownSuite() {
	if suite.opa != nil {
		suite.opa.Close()
	}
}

// setupComplianceRoutes configures compliance-specific test routes
func (suite *CompliancePoliciesTestSuite) setupComplianceRoutes() {
	// Routes that simulate different data types and purposes
	suite.router.GET("/gdpr/personal-data", suite.handleGDPRPersonalData)
	suite.router.GET("/sox/financial-data", suite.handleSOXFinancialData)
	suite.router.GET("/hipaa/health-data", suite.handleHIPAAHealthData)
	suite.router.GET("/pci/payment-data", suite.handlePCIPaymentData)
	
	// Purpose-specific routes for GDPR testing
	suite.router.GET("/gdpr/analytics", suite.handleGDPRAnalytics)
	suite.router.GET("/gdpr/marketing", suite.handleGDPRMarketing)
	suite.router.DELETE("/gdpr/erasure", suite.handleGDPRErasure)
	
	// Classification-specific routes
	suite.router.GET("/data/public", suite.handlePublicData)
	suite.router.GET("/data/internal", suite.handleInternalData)
	suite.router.GET("/data/confidential", suite.handleConfidentialData)
	suite.router.GET("/data/restricted", suite.handleRestrictedData)
}

// Test: GDPR Personal Data Access with Purpose Limitation
func (suite *CompliancePoliciesTestSuite) TestGDPRPersonalDataAccess() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
	defer cancel()

	// Test users with different trust levels and roles
	testCases := []struct {
		name           string
		user           auth.UserContext
		purpose        string
		fields         []string
		expectedAllow  bool
		expectedAudit  bool
		description    string
	}{
		{
			name: "GDPR Compliant - Medical Treatment",
			user: auth.UserContext{
				UserID:         "medical-professional",
				Email:          "doctor@hospital.com",
				Roles:          []string{"medical", "user"},
				TrustLevel:     75,
				DeviceVerified: true,
				ExpiresAt:      time.Now().Add(time.Hour).Unix(),
			},
			purpose:       "medical_treatment",
			fields:        []string{"name", "dob", "medical_history", "diagnosis"},
			expectedAllow: true,
			expectedAudit: true,
			description:   "Medical professional should access health data for treatment",
		},
		{
			name: "GDPR Compliant - Contract Performance",
			user: auth.UserContext{
				UserID:         "customer-service",
				Email:          "service@company.com",
				Roles:          []string{"customer_service", "user"},
				TrustLevel:     50,
				DeviceVerified: true,
				ExpiresAt:      time.Now().Add(time.Hour).Unix(),
			},
			purpose:       "contract_performance",
			fields:        []string{"name", "email", "phone", "address"},
			expectedAllow: true,
			expectedAudit: true,
			description:   "Customer service should access contact data for contract performance",
		},
		{
			name: "GDPR Non-Compliant - No Purpose",
			user: auth.UserContext{
				UserID:         "marketing-user",
				Email:          "marketing@company.com",
				Roles:          []string{"marketing", "user"},
				TrustLevel:     25,
				DeviceVerified: false,
				ExpiresAt:      time.Now().Add(time.Hour).Unix(),
			},
			purpose:       "", // No purpose specified
			fields:        []string{"name", "email", "preferences"},
			expectedAllow: false,
			expectedAudit: true,
			description:   "Should deny access without purpose specification",
		},
		{
			name: "GDPR Non-Compliant - Insufficient Trust",
			user: auth.UserContext{
				UserID:         "low-trust-user",
				Email:          "contractor@external.com",
				Roles:          []string{"contractor"},
				TrustLevel:     10,
				DeviceVerified: false,
				ExpiresAt:      time.Now().Add(time.Hour).Unix(),
			},
			purpose:       "marketing",
			fields:        []string{"name", "email"},
			expectedAllow: false,
			expectedAudit: true,
			description:   "Should deny access with insufficient trust level",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			response, err := suite.opa.AuthorizeDataAccess(
				ctx,
				tc.user,
				"personal_data",
				tc.purpose,
				tc.fields,
			)
			require.NoError(suite.T(), err)

			assert.Equal(suite.T(), tc.expectedAllow, response.Allow, tc.description)
			assert.Equal(suite.T(), tc.expectedAudit, response.AuditRequired, "All personal data access should require audit")

			if tc.expectedAllow {
				assert.NotEmpty(suite.T(), response.DecisionID, "Should have decision ID for allowed access")
				suite.T().Logf("GDPR access allowed: %s (Decision: %s)", tc.name, response.DecisionID)
			} else {
				assert.NotEmpty(suite.T(), response.Reasons, "Should provide denial reasons")
				suite.T().Logf("GDPR access denied: %s - %v", tc.name, response.Reasons)
			}

			// Check compliance flags
			if response.Allow && tc.purpose != "" {
				assert.Contains(suite.T(), response.ComplianceFlags, "purpose_specified", "Should flag purpose specification")
			}
		})
	}
}

// Test: SOX Financial Data Access Controls
func (suite *CompliancePoliciesTestSuite) TestSOXFinancialDataAccess() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
	defer cancel()

	testCases := []struct {
		name           string
		user           auth.UserContext
		purpose        string
		expectedAllow  bool
		description    string
	}{
		{
			name: "SOX Compliant - Finance Professional",
			user: auth.UserContext{
				UserID:         "finance-manager",
				Email:          "finance@company.com",
				Roles:          []string{"finance", "manager", "user"},
				TrustLevel:     100,
				DeviceVerified: true,
				ExpiresAt:      time.Now().Add(time.Hour).Unix(),
			},
			purpose:       "financial_reporting",
			expectedAllow: true,
			description:   "Finance manager should access financial data for reporting",
		},
		{
			name: "SOX Compliant - Auditor",
			user: auth.UserContext{
				UserID:         "external-auditor",
				Email:          "auditor@audit-firm.com",
				Roles:          []string{"auditor", "user"},
				TrustLevel:     90,
				DeviceVerified: true,
				ExpiresAt:      time.Now().Add(time.Hour).Unix(),
			},
			purpose:       "external_audit",
			expectedAllow: true,
			description:   "External auditor should access financial data for audit",
		},
		{
			name: "SOX Non-Compliant - Regular Employee",
			user: auth.UserContext{
				UserID:         "regular-employee",
				Email:          "employee@company.com",
				Roles:          []string{"user"},
				TrustLevel:     50,
				DeviceVerified: true,
				ExpiresAt:      time.Now().Add(time.Hour).Unix(),
			},
			purpose:       "curiosity",
			expectedAllow: false,
			description:   "Regular employee should not access financial data",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			response, err := suite.opa.AuthorizeDataAccess(
				ctx,
				tc.user,
				"financial_transactions",
				tc.purpose,
				[]string{"revenue", "expenses", "profit_loss"},
			)
			require.NoError(suite.T(), err)

			assert.Equal(suite.T(), tc.expectedAllow, response.Allow, tc.description)
			assert.True(suite.T(), response.AuditRequired, "All financial data access should require audit for SOX")

			if tc.expectedAllow {
				suite.T().Logf("SOX financial access allowed: %s", tc.name)
			} else {
				suite.T().Logf("SOX financial access denied: %s - %v", tc.name, response.Reasons)
			}
		})
	}
}

// Test: HIPAA Health Data Protection
func (suite *CompliancePoliciesTestSuite) TestHIPAAHealthDataAccess() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
	defer cancel()

	testCases := []struct {
		name           string
		user           auth.UserContext
		purpose        string
		fields         []string
		expectedAllow  bool
		description    string
	}{
		{
			name: "HIPAA Compliant - Doctor Treatment",
			user: auth.UserContext{
				UserID:         "doctor-smith",
				Email:          "dr.smith@hospital.com",
				Roles:          []string{"doctor", "medical", "user"},
				TrustLevel:     90,
				DeviceVerified: true,
				ExpiresAt:      time.Now().Add(time.Hour).Unix(),
			},
			purpose:       "medical_treatment",
			fields:        []string{"patient_id", "diagnosis", "treatment_plan", "medications"},
			expectedAllow: true,
			description:   "Doctor should access PHI for treatment",
		},
		{
			name: "HIPAA Compliant - Nurse Care",
			user: auth.UserContext{
				UserID:         "nurse-jones",
				Email:          "nurse.jones@hospital.com",
				Roles:          []string{"nurse", "medical", "user"},
				TrustLevel:     75,
				DeviceVerified: true,
				ExpiresAt:      time.Now().Add(time.Hour).Unix(),
			},
			purpose:       "patient_care",
			fields:        []string{"patient_id", "vital_signs", "medication_schedule"},
			expectedAllow: true,
			description:   "Nurse should access PHI for patient care",
		},
		{
			name: "HIPAA Non-Compliant - Administrative Staff",
			user: auth.UserContext{
				UserID:         "admin-staff",
				Email:          "admin@hospital.com",
				Roles:          []string{"administrative", "user"},
				TrustLevel:     50,
				DeviceVerified: true,
				ExpiresAt:      time.Now().Add(time.Hour).Unix(),
			},
			purpose:       "administrative",
			fields:        []string{"patient_id", "diagnosis", "treatment_plan"},
			expectedAllow: false,
			description:   "Administrative staff should not access clinical PHI",
		},
		{
			name: "HIPAA Non-Compliant - Insufficient Trust",
			user: auth.UserContext{
				UserID:         "temp-worker",
				Email:          "temp@contractor.com",
				Roles:          []string{"medical", "temporary"},
				TrustLevel:     40,
				DeviceVerified: false,
				ExpiresAt:      time.Now().Add(time.Hour).Unix(),
			},
			purpose:       "medical_treatment",
			fields:        []string{"patient_id", "diagnosis"},
			expectedAllow: false,
			description:   "Should deny PHI access with insufficient trust level",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			response, err := suite.opa.AuthorizeDataAccess(
				ctx,
				tc.user,
				"personal_health_information",
				tc.purpose,
				tc.fields,
			)
			require.NoError(suite.T(), err)

			assert.Equal(suite.T(), tc.expectedAllow, response.Allow, tc.description)
			assert.True(suite.T(), response.AuditRequired, "All PHI access should require audit for HIPAA")

			if tc.expectedAllow {
				suite.T().Logf("HIPAA PHI access allowed: %s", tc.name)
				assert.Equal(suite.T(), "personal_health_information", response.DataClassification)
			} else {
				suite.T().Logf("HIPAA PHI access denied: %s - %v", tc.name, response.Reasons)
			}
		})
	}
}

// Test: PCI DSS Payment Data Protection
func (suite *CompliancePoliciesTestSuite) TestPCIPaymentDataAccess() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
	defer cancel()

	testCases := []struct {
		name           string
		user           auth.UserContext
		purpose        string
		fields         []string
		expectedAllow  bool
		description    string
	}{
		{
			name: "PCI Compliant - Payment Processor",
			user: auth.UserContext{
				UserID:         "payment-processor",
				Email:          "payments@company.com",
				Roles:          []string{"payment_processor", "finance", "user"},
				TrustLevel:     100,
				DeviceVerified: true,
				ExpiresAt:      time.Now().Add(time.Hour).Unix(),
			},
			purpose:       "payment_processing",
			fields:        []string{"masked_card_number", "transaction_id", "amount"},
			expectedAllow: true,
			description:   "Payment processor should access payment data",
		},
		{
			name: "PCI Non-Compliant - Customer Service",
			user: auth.UserContext{
				UserID:         "customer-service",
				Email:          "service@company.com",
				Roles:          []string{"customer_service", "user"},
				TrustLevel:     50,
				DeviceVerified: true,
				ExpiresAt:      time.Now().Add(time.Hour).Unix(),
			},
			purpose:       "customer_support",
			fields:        []string{"card_number", "cvv", "expiry_date"},
			expectedAllow: false,
			description:   "Customer service should not access full payment card data",
		},
		{
			name: "PCI Compliant - Limited Access",
			user: auth.UserContext{
				UserID:         "customer-service-secure",
				Email:          "secure.service@company.com",
				Roles:          []string{"customer_service", "pci_authorized", "user"},
				TrustLevel:     75,
				DeviceVerified: true,
				ExpiresAt:      time.Now().Add(time.Hour).Unix(),
			},
			purpose:       "customer_support",
			fields:        []string{"last_four_digits", "transaction_id"},
			expectedAllow: true,
			description:   "Authorized customer service can access limited payment data",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			response, err := suite.opa.AuthorizeDataAccess(
				ctx,
				tc.user,
				"payment_card_data",
				tc.purpose,
				tc.fields,
			)
			require.NoError(suite.T(), err)

			assert.Equal(suite.T(), tc.expectedAllow, response.Allow, tc.description)
			assert.True(suite.T(), response.AuditRequired, "All payment data access should require audit for PCI")

			if tc.expectedAllow {
				suite.T().Logf("PCI payment data access allowed: %s", tc.name)
			} else {
				suite.T().Logf("PCI payment data access denied: %s - %v", tc.name, response.Reasons)
			}
		})
	}
}

// Test: Data Classification Levels
func (suite *CompliancePoliciesTestSuite) TestDataClassificationLevels() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
	defer cancel()

	// Test user with medium trust
	user := auth.UserContext{
		UserID:         "test-user",
		Email:          "test@company.com",
		Roles:          []string{"user"},
		TrustLevel:     50,
		DeviceVerified: true,
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}

	classificationTests := []struct {
		classification string
		expectedAllow  bool
		requiredTrust  int
		description    string
	}{
		{
			classification: "public",
			expectedAllow:  true,
			requiredTrust:  0,
			description:    "Public data should be accessible to all users",
		},
		{
			classification: "internal",
			expectedAllow:  true,
			requiredTrust:  25,
			description:    "Internal data should be accessible to authenticated users",
		},
		{
			classification: "confidential",
			expectedAllow:  false,
			requiredTrust:  75,
			description:    "Confidential data requires high trust level",
		},
		{
			classification: "restricted",
			expectedAllow:  false,
			requiredTrust:  100,
			description:    "Restricted data requires full trust level",
		},
	}

	for _, test := range classificationTests {
		suite.Run(fmt.Sprintf("Classification %s", test.classification), func() {
			response, err := suite.opa.AuthorizeDataAccess(
				ctx,
				user,
				test.classification+"_data",
				"business_operations",
				[]string{"field1", "field2"},
			)
			require.NoError(suite.T(), err)

			assert.Equal(suite.T(), test.expectedAllow, response.Allow, test.description)
			
			if !test.expectedAllow {
				assert.Contains(suite.T(), response.Reasons, "insufficient_trust_level", 
					"Should indicate insufficient trust level")
				assert.Equal(suite.T(), test.requiredTrust, response.RequiredTrustLevel,
					"Should indicate required trust level")
			}

			suite.T().Logf("Classification %s: allowed=%t, required_trust=%d, user_trust=%d",
				test.classification, response.Allow, response.RequiredTrustLevel, user.TrustLevel)
		})
	}
}

// Test: Time-based access restrictions for compliance
func (suite *CompliancePoliciesTestSuite) TestTimeBasedComplianceAccess() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
	defer cancel()

	// Create user with time-sensitive role
	user := auth.UserContext{
		UserID:         "time-sensitive-user",
		Email:          "time.user@company.com",
		Roles:          []string{"finance", "user"},
		TrustLevel:     75,
		DeviceVerified: true,
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}

	suite.Run("Business Hours Access", func() {
		response, err := suite.opa.AuthorizeDataAccess(
			ctx,
			user,
			"financial_transactions",
			"financial_reporting",
			[]string{"revenue", "expenses"},
		)
		require.NoError(suite.T(), err)

		// Note: This test depends on current time
		// In production, you'd mock time or use time context
		currentHour := time.Now().Hour()
		isBusinessHours := currentHour >= 9 && currentHour < 18

		if isBusinessHours {
			assert.True(suite.T(), response.Allow, "Should allow access during business hours")
		}

		suite.T().Logf("Time-based access (hour %d): allowed=%t", currentHour, response.Allow)
	})
}

// Test: Emergency access procedures
func (suite *CompliancePoliciesTestSuite) TestEmergencyAccessProcedures() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
	defer cancel()

	// Create user with emergency role
	emergencyUser := auth.UserContext{
		UserID:         "emergency-responder",
		Email:          "emergency@hospital.com",
		Roles:          []string{"emergency", "medical", "user"},
		TrustLevel:     80,
		DeviceVerified: true,
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}

	suite.Run("Emergency Medical Access", func() {
		// Simulate emergency context
		requestContext := auth.RequestContext{
			RequestID: "emergency-access-001",
			Emergency: true,
		}

		// Create authorization request with emergency context
		authRequest := &auth.AuthorizationRequest{
			User:     emergencyUser,
			Resource: "data_access",
			Action:   "read",
			Purpose:  "emergency_medical_care",
			Context:  requestContext,
			Data: &auth.DataContext{
				Type:   "personal_health_information",
				Fields: []string{"patient_id", "allergies", "medications", "emergency_contacts"},
				Scope:  "single_record",
			},
		}

		response, err := suite.opa.Authorize(ctx, authRequest)
		require.NoError(suite.T(), err)

		assert.True(suite.T(), response.Allow, "Emergency access should be allowed")
		assert.True(suite.T(), response.AuditRequired, "Emergency access should require audit")

		suite.T().Logf("Emergency access granted (Decision: %s)", response.DecisionID)
	})
}

// Test: Data retention and deletion compliance
func (suite *CompliancePoliciesTestSuite) TestDataRetentionCompliance() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
	defer cancel()

	dataManager := auth.UserContext{
		UserID:         "data-manager",
		Email:          "data.manager@company.com",
		Roles:          []string{"data_protection_officer", "admin", "user"},
		TrustLevel:     90,
		DeviceVerified: true,
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}

	retentionTests := []struct {
		name           string
		action         string
		dataAge        string
		expectedAllow  bool
		description    string
	}{
		{
			name:          "Delete Expired Personal Data",
			action:        "delete",
			dataAge:       "expired",
			expectedAllow: true,
			description:   "Should allow deletion of expired personal data",
		},
		{
			name:          "Delete Active Personal Data",
			action:        "delete", 
			dataAge:       "active",
			expectedAllow: false,
			description:   "Should prevent deletion of active personal data without legal basis",
		},
		{
			name:          "Anonymize Old Data",
			action:        "anonymize",
			dataAge:       "old",
			expectedAllow: true,
			description:   "Should allow anonymization of old data",
		},
	}

	for _, test := range retentionTests {
		suite.Run(test.name, func() {
			authRequest := &auth.AuthorizationRequest{
				User:     dataManager,
				Resource: "data_retention",
				Action:   test.action,
				Purpose:  "gdpr_compliance",
				Context: auth.RequestContext{
					RequestID: fmt.Sprintf("retention-test-%s", test.name),
				},
				Data: &auth.DataContext{
					Type:              "personal_data",
					CreatedAt:         test.dataAge,
					DeletionScheduled: test.dataAge == "expired",
					Attributes: map[string]string{
						"retention_period": "2_years",
						"data_age":        test.dataAge,
					},
				},
			}

			response, err := suite.opa.Authorize(ctx, authRequest)
			require.NoError(suite.T(), err)

			assert.Equal(suite.T(), test.expectedAllow, response.Allow, test.description)
			assert.True(suite.T(), response.AuditRequired, "Data retention actions should require audit")

			if test.expectedAllow {
				suite.T().Logf("Data retention action allowed: %s", test.name)
			} else {
				suite.T().Logf("Data retention action denied: %s - %v", test.name, response.Reasons)
			}
		})
	}
}

// Test: Cross-border data transfer compliance
func (suite *CompliancePoliciesTestSuite) TestCrossBorderDataTransfer() {
	ctx, cancel := context.WithTimeout(context.Background(), suite.testConfig.TestTimeout)
	defer cancel()

	dataProcessor := auth.UserContext{
		UserID:         "data-processor",
		Email:          "processor@global-company.com",
		Roles:          []string{"data_processor", "user"},
		TrustLevel:     75,
		DeviceVerified: true,
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}

	transferTests := []struct {
		name           string
		sourceCountry  string
		targetCountry  string
		dataType       string
		expectedAllow  bool
		description    string
	}{
		{
			name:          "EU to US - Adequate Protection",
			sourceCountry: "DE",
			targetCountry: "US",
			dataType:      "personal_data",
			expectedAllow: true,
			description:   "Should allow transfer with adequate protection measures",
		},
		{
			name:          "EU to Non-Adequate Country",
			sourceCountry: "FR",
			targetCountry: "CN",
			dataType:      "personal_data",
			expectedAllow: false,
			description:   "Should deny transfer to non-adequate protection country",
		},
		{
			name:          "Internal Data Transfer",
			sourceCountry: "US",
			targetCountry: "CA",
			dataType:      "internal_data",
			expectedAllow: true,
			description:   "Should allow internal data transfer between countries",
		},
	}

	for _, test := range transferTests {
		suite.Run(test.name, func() {
			authRequest := &auth.AuthorizationRequest{
				User:     dataProcessor,
				Resource: "data_transfer",
				Action:   "transfer",
				Purpose:  "business_operations",
				Context: auth.RequestContext{
					RequestID: fmt.Sprintf("transfer-test-%s", test.name),
					Country:   test.sourceCountry,
					Headers: map[string]string{
						"X-Target-Country": test.targetCountry,
					},
				},
				Data: &auth.DataContext{
					Type: test.dataType,
					Attributes: map[string]string{
						"source_country": test.sourceCountry,
						"target_country": test.targetCountry,
					},
				},
			}

			response, err := suite.opa.Authorize(ctx, authRequest)
			require.NoError(suite.T(), err)

			assert.Equal(suite.T(), test.expectedAllow, response.Allow, test.description)

			if test.expectedAllow {
				suite.T().Logf("Cross-border transfer allowed: %s", test.name)
			} else {
				suite.T().Logf("Cross-border transfer denied: %s - %v", test.name, response.Reasons)
			}
		})
	}
}

// Helper methods

func (suite *CompliancePoliciesTestSuite) isOPAAvailable() bool {
	resp, err := http.Get(suite.testConfig.OPAURL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// Route handlers for compliance testing

func (suite *CompliancePoliciesTestSuite) handleGDPRPersonalData(c *gin.Context) {
	purpose := c.Query("purpose")
	if purpose == "" {
		c.JSON(400, gin.H{"error": "purpose parameter required for GDPR compliance"})
		return
	}
	
	c.JSON(200, gin.H{
		"data_type": "personal_data",
		"purpose":   purpose,
		"gdpr_compliant": true,
		"audit_logged": true,
	})
}

func (suite *CompliancePoliciesTestSuite) handleSOXFinancialData(c *gin.Context) {
	c.JSON(200, gin.H{
		"data_type": "financial_transactions",
		"sox_compliant": true,
		"audit_required": true,
		"segregation_of_duties": true,
	})
}

func (suite *CompliancePoliciesTestSuite) handleHIPAAHealthData(c *gin.Context) {
	c.JSON(200, gin.H{
		"data_type": "personal_health_information",
		"hipaa_compliant": true,
		"phi_protected": true,
		"minimum_necessary": true,
	})
}

func (suite *CompliancePoliciesTestSuite) handlePCIPaymentData(c *gin.Context) {
	c.JSON(200, gin.H{
		"data_type": "payment_card_data",
		"pci_compliant": true,
		"card_data_encrypted": true,
		"access_logged": true,
	})
}

func (suite *CompliancePoliciesTestSuite) handleGDPRAnalytics(c *gin.Context) {
	c.JSON(200, gin.H{
		"purpose": "analytics",
		"legal_basis": "legitimate_interest",
		"anonymized": true,
	})
}

func (suite *CompliancePoliciesTestSuite) handleGDPRMarketing(c *gin.Context) {
	c.JSON(200, gin.H{
		"purpose": "marketing",
		"legal_basis": "consent",
		"opt_out_available": true,
	})
}

func (suite *CompliancePoliciesTestSuite) handleGDPRErasure(c *gin.Context) {
	c.JSON(200, gin.H{
		"action": "data_erasure",
		"right_to_be_forgotten": true,
		"verification_required": true,
	})
}

func (suite *CompliancePoliciesTestSuite) handlePublicData(c *gin.Context) {
	c.JSON(200, gin.H{"classification": "public", "access_level": "unrestricted"})
}

func (suite *CompliancePoliciesTestSuite) handleInternalData(c *gin.Context) {
	c.JSON(200, gin.H{"classification": "internal", "access_level": "employees_only"})
}

func (suite *CompliancePoliciesTestSuite) handleConfidentialData(c *gin.Context) {
	c.JSON(200, gin.H{"classification": "confidential", "access_level": "need_to_know"})
}

func (suite *CompliancePoliciesTestSuite) handleRestrictedData(c *gin.Context) {
	c.JSON(200, gin.H{"classification": "restricted", "access_level": "highest_clearance"})
}

// Test suite runner
func TestCompliancePolicies(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping compliance policy tests in short mode")
	}
	
	suite.Run(t, new(CompliancePoliciesTestSuite))
}

// Individual test functions for go test compatibility

func TestGDPRPersonalDataAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping compliance tests in short mode")
	}
	
	suite := new(CompliancePoliciesTestSuite)
	suite.SetT(t)
	suite.SetupSuite()
	defer suite.TearDownSuite()
	
	suite.TestGDPRPersonalDataAccess()
}

func TestSOXFinancialDataAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping compliance tests in short mode")
	}
	
	suite := new(CompliancePoliciesTestSuite)
	suite.SetT(t)
	suite.SetupSuite()
	defer suite.TearDownSuite()
	
	suite.TestSOXFinancialDataAccess()
}

func TestDataClassificationLevels(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping compliance tests in short mode")
	}
	
	suite := new(CompliancePoliciesTestSuite)
	suite.SetT(t)
	suite.SetupSuite()
	defer suite.TearDownSuite()
	
	suite.TestDataClassificationLevels()
}

// Example of how to run these tests:
// go test -v ./tests/e2e -run TestCompliancePolicies
//
// To run with OPA and database:
// docker-compose -f docker-compose.opa.yml up -d
// go test -v ./tests/e2e -run TestCompliance
// docker-compose -f docker-compose.opa.yml down