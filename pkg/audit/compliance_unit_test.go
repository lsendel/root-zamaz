package audit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"mvp.local/pkg/observability"
)

func TestRiskCalculatorUnit(t *testing.T) {
	calculator := NewRiskCalculator()
	
	// Test high-risk entry
	highRiskEntry := ComplianceLogEntry{
		Action:               "delete",
		ComplianceFrameworks: []ComplianceFramework{FrameworkGDPR, FrameworkHIPAA},
		DataClassification:   ClassificationPHI,
		SensitivityLevel:     5,
		GeolocationCountry:   "CN", // High-risk country
		Details:             map[string]interface{}{"record_count": 15000},
	}
	
	highRiskScore := calculator.CalculateRisk(highRiskEntry)
	assert.Greater(t, highRiskScore, 60) // Should be high risk
	
	// Test low-risk entry
	lowRiskEntry := ComplianceLogEntry{
		Action:             "read",
		DataClassification: ClassificationPublic,
		SensitivityLevel:   1,
		GeolocationCountry: "US",
		Details:           map[string]interface{}{"record_count": 1},
	}
	
	lowRiskScore := calculator.CalculateRisk(lowRiskEntry)
	assert.Less(t, lowRiskScore, 30) // Should be low risk
	
	// Risk score should be higher for high-risk entry
	assert.Greater(t, highRiskScore, lowRiskScore)
	
	// Test specific risk factors
	deleteActionScore := calculator.calculateActionRisk("delete")
	readActionScore := calculator.calculateActionRisk("read")
	assert.Greater(t, deleteActionScore, readActionScore)
	
	// Test risk level categorization
	level := calculator.GetRiskLevel(85)
	assert.Equal(t, "CRITICAL", level)
	
	level = calculator.GetRiskLevel(25)
	assert.Equal(t, "LOW", level)
}

func TestViolationDetectorUnit(t *testing.T) {
	obs := setupUnitTestObservability()
	defer obs.Shutdown(context.Background())
	
	detector := NewViolationDetector(obs)
	
	// Test GDPR violation detection
	entry := ComplianceLogEntry{
		Action:               "bulk_download",
		ComplianceFrameworks: []ComplianceFramework{FrameworkGDPR},
		DataClassification:   ClassificationPII,
		SensitivityLevel:     4,
		LegalBasis:          "", // Missing legal basis - should trigger violation
		DataSubjects:        []string{},
		RetentionCategory:   RetentionCategoryPermanent, // Should trigger retention violation
	}
	
	violations := detector.DetectViolations(entry)
	assert.NotEmpty(t, violations)
	
	// Should detect missing legal basis violation
	foundLegalBasisViolation := false
	foundRetentionViolation := false
	
	for _, violation := range violations {
		if violation.Type == "gdpr_missing_legal_basis" {
			foundLegalBasisViolation = true
			assert.Equal(t, "GDPR", violation.Framework)
			assert.Equal(t, 4, violation.Severity)
		}
		if violation.Type == "gdpr_retention_excessive" {
			foundRetentionViolation = true
		}
	}
	
	assert.True(t, foundLegalBasisViolation, "Should detect missing legal basis violation")
	assert.True(t, foundRetentionViolation, "Should detect retention violation")
}

func TestViolationDetectorHIPAA(t *testing.T) {
	obs := setupUnitTestObservability()
	defer obs.Shutdown(context.Background())
	
	detector := NewViolationDetector(obs)
	
	// Test HIPAA violation detection
	entry := ComplianceLogEntry{
		Action:               "bulk_download",
		ComplianceFrameworks: []ComplianceFramework{FrameworkHIPAA},
		DataClassification:   ClassificationPHI,
		SensitivityLevel:     5,
		ApprovalRequired:     false, // Should trigger unauthorized access violation
		ControlsApplied:     []string{}, // Missing audit controls
	}
	
	violations := detector.DetectViolations(entry)
	assert.NotEmpty(t, violations)
	
	// Should detect unauthorized PHI access
	foundUnauthorizedAccess := false
	foundAuditControls := false
	
	for _, violation := range violations {
		if violation.Type == "hipaa_unauthorized_phi_access" {
			foundUnauthorizedAccess = true
			assert.Equal(t, "HIPAA", violation.Framework)
			assert.Equal(t, 5, violation.Severity)
		}
		if violation.Type == "hipaa_audit_controls" {
			foundAuditControls = true
		}
	}
	
	assert.True(t, foundUnauthorizedAccess, "Should detect unauthorized PHI access")
	assert.True(t, foundAuditControls, "Should detect missing audit controls")
}

func TestViolationDetectorSOX(t *testing.T) {
	obs := setupUnitTestObservability()
	defer obs.Shutdown(context.Background())
	
	detector := NewViolationDetector(obs)
	
	// Test SOX violation detection
	entry := ComplianceLogEntry{
		Action:               "financial_transaction_modify",
		ComplianceFrameworks: []ComplianceFramework{FrameworkSOX},
		DataClassification:   ClassificationConfidential,
		SensitivityLevel:     4,
		ControlsApplied:     []string{}, // Missing segregation of duties
		ApprovalStatus:      "", // Missing approval
	}
	
	violations := detector.DetectViolations(entry)
	assert.NotEmpty(t, violations)
	
	// Should detect segregation of duties violation
	foundSegregationViolation := false
	
	for _, violation := range violations {
		if violation.Type == "sox_segregation_duties" {
			foundSegregationViolation = true
			assert.Equal(t, "SOX", violation.Framework)
		}
	}
	
	assert.True(t, foundSegregationViolation, "Should detect segregation of duties violation")
}

func TestSecurityViolationDetection(t *testing.T) {
	obs := setupUnitTestObservability()
	defer obs.Shutdown(context.Background())
	
	detector := NewViolationDetector(obs)
	
	// Test security violation detection
	entry := ComplianceLogEntry{
		Action:       "privilege_escalation",
		Success:      true,
		RiskScore:    85, // High risk score
		SensitivityLevel: 4,
	}
	
	violations := detector.DetectViolations(entry)
	assert.NotEmpty(t, violations)
	
	// Should detect privilege escalation
	foundPrivilegeEscalation := false
	
	for _, violation := range violations {
		if violation.Type == "security_privilege_escalation" {
			foundPrivilegeEscalation = true
			assert.Equal(t, "SECURITY", violation.Framework)
			assert.Equal(t, 4, violation.Severity)
		}
	}
	
	assert.True(t, foundPrivilegeEscalation, "Should detect privilege escalation")
}

func TestDataHandlingViolations(t *testing.T) {
	obs := setupUnitTestObservability()
	defer obs.Shutdown(context.Background())
	
	detector := NewViolationDetector(obs)
	
	// Test data handling violation detection
	entry := ComplianceLogEntry{
		Action:             "data_processing",
		DataClassification: "", // Missing classification
		SensitivityLevel:   4,  // High sensitivity but no classification
		RetentionCategory:  RetentionCategoryPermanent,
	}
	
	violations := detector.DetectViolations(entry)
	assert.NotEmpty(t, violations)
	
	// Should detect unclassified sensitive data
	foundUnclassified := false
	foundExcessiveRetention := false
	
	for _, violation := range violations {
		if violation.Type == "data_unclassified_sensitive" {
			foundUnclassified = true
		}
		if violation.Type == "data_excessive_retention" {
			foundExcessiveRetention = true
		}
	}
	
	assert.True(t, foundUnclassified, "Should detect unclassified sensitive data")
	assert.True(t, foundExcessiveRetention, "Should detect excessive retention")
}

func TestComplianceFrameworkConstants(t *testing.T) {
	// Test framework constants
	assert.Equal(t, "GDPR", string(FrameworkGDPR))
	assert.Equal(t, "HIPAA", string(FrameworkHIPAA))
	assert.Equal(t, "SOX", string(FrameworkSOX))
	assert.Equal(t, "PCI-DSS", string(FrameworkPCIDSS))
	assert.Equal(t, "ISO27001", string(FrameworkISO27001))
	
	// Test classification constants
	assert.Equal(t, "PUBLIC", string(ClassificationPublic))
	assert.Equal(t, "PII", string(ClassificationPII))
	assert.Equal(t, "PHI", string(ClassificationPHI))
	assert.Equal(t, "RESTRICTED", string(ClassificationRestricted))
	
	// Test legal basis constants
	assert.Equal(t, "CONSENT", string(LegalBasisConsent))
	assert.Equal(t, "CONTRACT", string(LegalBasisContract))
	assert.Equal(t, "LEGITIMATE_INTEREST", string(LegalBasisLegitimateInterest))
	
	// Test retention category constants
	assert.Equal(t, "SHORT_TERM", string(RetentionCategoryShortTerm))
	assert.Equal(t, "COMPLIANCE", string(RetentionCategoryCompliance))
}

func TestRetentionCategoryDetermination(t *testing.T) {
	obs := setupUnitTestObservability()
	defer obs.Shutdown(context.Background())
	
	service := &ComplianceService{obs: obs}
	
	// Test explicit retention category
	entry := ComplianceLogEntry{
		RetentionCategory: RetentionCategoryLongTerm,
	}
	category := service.determineRetentionCategory(entry)
	assert.Equal(t, RetentionCategoryLongTerm, category)
	
	// Test GDPR PII data
	entry = ComplianceLogEntry{
		ComplianceFrameworks: []ComplianceFramework{FrameworkGDPR},
		DataClassification:   ClassificationPII,
	}
	category = service.determineRetentionCategory(entry)
	assert.Equal(t, RetentionCategoryCompliance, category)
	
	// Test HIPAA PHI data
	entry = ComplianceLogEntry{
		ComplianceFrameworks: []ComplianceFramework{FrameworkHIPAA},
		DataClassification:   ClassificationPHI,
	}
	category = service.determineRetentionCategory(entry)
	assert.Equal(t, RetentionCategoryLongTerm, category)
	
	// Test SOX data
	entry = ComplianceLogEntry{
		ComplianceFrameworks: []ComplianceFramework{FrameworkSOX},
	}
	category = service.determineRetentionCategory(entry)
	assert.Equal(t, RetentionCategoryLongTerm, category)
	
	// Test default based on classification
	entry = ComplianceLogEntry{
		DataClassification: ClassificationPublic,
	}
	category = service.determineRetentionCategory(entry)
	assert.Equal(t, RetentionCategoryShortTerm, category)
}

func TestSensitivityLevelCalculation(t *testing.T) {
	// Test sensitivity level calculation
	assert.Equal(t, 1, getSensitivityLevel(ClassificationPublic))
	assert.Equal(t, 2, getSensitivityLevel(ClassificationInternal))
	assert.Equal(t, 3, getSensitivityLevel(ClassificationConfidential))
	assert.Equal(t, 4, getSensitivityLevel(ClassificationPII))
	assert.Equal(t, 5, getSensitivityLevel(ClassificationRestricted))
	assert.Equal(t, 5, getSensitivityLevel(ClassificationPHI))
	assert.Equal(t, 1, getSensitivityLevel("unknown"))
}

func setupUnitTestObservability() *observability.Observability {
	config := observability.Config{
		ServiceName:    "test-service",
		ServiceVersion: "test",
		Environment:    "test",
		LogLevel:       "info",
		LogFormat:      "console",
		PrometheusPort: 0, // Disable metrics server for tests
	}
	obs, _ := observability.New(config)
	return obs
}