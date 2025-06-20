package audit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
)

func setupTestDB() (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Create simplified test tables for SQLite compatibility
	err = db.Exec(`
	CREATE TABLE compliance_audit_logs (
		id TEXT PRIMARY KEY,
		created_at DATETIME,
		updated_at DATETIME,
		deleted_at DATETIME,
		user_id TEXT,
		action TEXT,
		resource TEXT,
		details TEXT,
		success BOOLEAN,
		error_msg TEXT,
		ip_address TEXT,
		user_agent TEXT,
		request_id TEXT,
		session_id TEXT,
		tenant_id TEXT,
		compliance_frameworks TEXT,
		data_classification TEXT,
		sensitivity_level INTEGER,
		legal_basis TEXT,
		data_subjects TEXT,
		data_categories TEXT,
		processing_purpose TEXT,
		geolocation_country TEXT,
		risk_score INTEGER,
		controls_applied TEXT,
		approval_required BOOLEAN,
		approval_status TEXT,
		review_status TEXT,
		retention_category TEXT,
		business_justification TEXT,
		retain_until DATETIME,
		archive_date DATETIME,
		purge_date DATETIME,
		archived BOOLEAN DEFAULT false,
		archived_at DATETIME,
		business_context TEXT,
		technical_context TEXT
	)
	`).Error
	if err != nil {
		return nil, err
	}

	err = db.Exec(`
	CREATE TABLE data_subject_requests (
		id TEXT PRIMARY KEY,
		created_at DATETIME,
		updated_at DATETIME,
		deleted_at DATETIME,
		request_type TEXT,
		data_subject TEXT,
		requestor_id TEXT,
		email TEXT,
		phone_number TEXT,
		status TEXT,
		priority TEXT DEFAULT 'NORMAL',
		assigned_to TEXT,
		due_date DATETIME,
		completed_at DATETIME,
		legal_basis TEXT,
		identity_verified BOOLEAN DEFAULT false,
		verification_method TEXT,
		verified_by TEXT,
		verified_at DATETIME,
		description TEXT,
		data_categories TEXT,
		processing_purposes TEXT,
		response TEXT,
		response_method TEXT,
		rejection_reason TEXT,
		compliance_notes TEXT,
		reviewed_by TEXT,
		reviewed_at DATETIME
	)
	`).Error
	if err != nil {
		return nil, err
	}

	err = db.Exec(`
	CREATE TABLE users (
		id TEXT PRIMARY KEY,
		username TEXT,
		email TEXT,
		password_hash TEXT,
		first_name TEXT,
		last_name TEXT,
		is_active BOOLEAN DEFAULT true,
		is_admin BOOLEAN DEFAULT false,
		failed_login_attempts INTEGER DEFAULT 0,
		last_failed_login_at DATETIME,
		account_locked_at DATETIME,
		account_locked_until DATETIME,
		last_login_at DATETIME,
		last_login_ip TEXT,
		created_at DATETIME,
		updated_at DATETIME,
		deleted_at DATETIME
	)
	`).Error
	if err != nil {
		return nil, err
	}

	// Create compliance_violations table
	err = db.Exec(`
	CREATE TABLE compliance_violations (
		id TEXT PRIMARY KEY,
		created_at DATETIME,
		updated_at DATETIME,
		deleted_at DATETIME,
		audit_log_id TEXT,
		violation_type TEXT,
		framework TEXT,
		severity INTEGER,
		description TEXT,
		remediation TEXT,
		risk_score INTEGER,
		status TEXT DEFAULT 'OPEN',
		assigned_to TEXT,
		resolved_at DATETIME,
		resolution TEXT,
		resolution_by TEXT
	)
	`).Error
	if err != nil {
		return nil, err
	}

	// Create consent_records table
	err = db.Exec(`
	CREATE TABLE consent_records (
		id TEXT PRIMARY KEY,
		created_at DATETIME,
		updated_at DATETIME,
		deleted_at DATETIME,
		data_subject TEXT,
		user_id TEXT,
		consent_type TEXT,
		purpose TEXT,
		legal_basis TEXT,
		data_categories TEXT,
		status TEXT,
		consent_given BOOLEAN,
		consent_date DATETIME,
		withdrawn_date DATETIME,
		expiry_date DATETIME,
		consent_method TEXT,
		consent_text TEXT,
		consent_version TEXT,
		ip_address TEXT,
		user_agent TEXT,
		consent_proof TEXT,
		withdrawal_method TEXT,
		withdrawal_reason TEXT
	)
	`).Error

	return db, err
}

func setupTestObservability() *observability.Observability {
	config := observability.Config{
		ServiceName:    "test-service",
		ServiceVersion: "test",
		Environment:    "test",
		LogLevel:       "info",
		LogFormat:      "console",
	}
	obs, _ := observability.New(config)
	return obs
}

func TestComplianceLogEntry(t *testing.T) {
	db, err := setupTestDB()
	require.NoError(t, err)

	obs := setupTestObservability()
	defer obs.Shutdown(context.Background())

	service := NewComplianceService(db, obs)

	// Test logging a GDPR compliance event
	entry := ComplianceLogEntry{
		UserID:                "test-user-123",
		Action:                "data_access",
		Resource:              "user_profile",
		Success:               true,
		ComplianceFrameworks:  []ComplianceFramework{FrameworkGDPR},
		DataClassification:    ClassificationPII,
		SensitivityLevel:      4,
		LegalBasis:            LegalBasisLegitimateInterest,
		DataSubjects:          []string{"user@example.com"},
		DataCategories:        []string{"personal_data", "contact_info"},
		ProcessingPurpose:     "User authentication and profile management",
		GeolocationCountry:    "US",
		BusinessJustification: "Legitimate interest in providing user services",
	}

	ctx := context.Background()
	err = service.LogComplianceEvent(ctx, entry)
	assert.NoError(t, err)

	// Verify the log was created
	var count int64
	db.Model(&models.ComplianceAuditLog{}).Count(&count)
	assert.Equal(t, int64(1), count)

	// Verify the data
	var log models.ComplianceAuditLog
	err = db.First(&log).Error
	assert.NoError(t, err)
	assert.Equal(t, "data_access", log.Action)
	assert.Equal(t, "user_profile", log.Resource)
	assert.Equal(t, "PII", log.DataClassification)
	assert.Equal(t, 4, log.SensitivityLevel)
	assert.Equal(t, "LEGITIMATE_INTEREST", log.LegalBasis)
	assert.True(t, log.RiskScore > 0) // Risk calculator should have calculated a score
}

func TestRiskCalculator(t *testing.T) {
	calculator := NewRiskCalculator()

	// Test high-risk entry
	highRiskEntry := ComplianceLogEntry{
		Action:               "delete",
		ComplianceFrameworks: []ComplianceFramework{FrameworkGDPR, FrameworkHIPAA},
		DataClassification:   ClassificationPHI,
		SensitivityLevel:     5,
		GeolocationCountry:   "CN", // High-risk country
	}

	highRiskScore := calculator.CalculateRisk(highRiskEntry)
	assert.Greater(t, highRiskScore, 60) // Should be high risk

	// Test low-risk entry
	lowRiskEntry := ComplianceLogEntry{
		Action:             "read",
		DataClassification: ClassificationPublic,
		SensitivityLevel:   1,
		GeolocationCountry: "US",
	}

	lowRiskScore := calculator.CalculateRisk(lowRiskEntry)
	assert.Less(t, lowRiskScore, 30) // Should be low risk

	// Risk score should be higher for high-risk entry
	assert.Greater(t, highRiskScore, lowRiskScore)
}

func TestViolationDetector(t *testing.T) {
	obs := setupTestObservability()
	defer obs.Shutdown(context.Background())

	detector := NewViolationDetector(obs)

	// Test GDPR violation detection
	entry := ComplianceLogEntry{
		Action:               "bulk_download",
		ComplianceFrameworks: []ComplianceFramework{FrameworkGDPR},
		DataClassification:   ClassificationPII,
		SensitivityLevel:     4,
		LegalBasis:           "", // Missing legal basis - should trigger violation
		DataSubjects:         []string{},
		RetentionCategory:    RetentionCategoryPermanent, // Should trigger retention violation
	}

	violations := detector.DetectViolations(entry)
	assert.NotEmpty(t, violations)

	// Should detect missing legal basis violation
	foundLegalBasisViolation := false
	foundRetentionViolation := false

	for _, violation := range violations {
		if violation.Type == "gdpr_missing_legal_basis" {
			foundLegalBasisViolation = true
		}
		if violation.Type == "gdpr_retention_excessive" {
			foundRetentionViolation = true
		}
	}

	assert.True(t, foundLegalBasisViolation, "Should detect missing legal basis violation")
	assert.True(t, foundRetentionViolation, "Should detect retention violation")
}

func TestRetentionManager(t *testing.T) {
	db, err := setupTestDB()
	require.NoError(t, err)

	obs := setupTestObservability()
	defer obs.Shutdown(context.Background())

	policies := map[RetentionCategory]time.Duration{
		RetentionCategoryShortTerm:  24 * time.Hour,
		RetentionCategoryMediumTerm: 30 * 24 * time.Hour,
		RetentionCategoryLongTerm:   365 * 24 * time.Hour,
		RetentionCategoryCompliance: 7 * 365 * 24 * time.Hour, // 7 years for compliance
	}

	manager := NewRetentionManager(db, obs, policies)

	// Test validation
	err = manager.ValidateRetentionPolicies()
	assert.NoError(t, err)

	// Test stats (empty database)
	ctx := context.Background()
	stats, err := manager.GetRetentionStats(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, stats)
	assert.Equal(t, int64(0), stats.TotalRecords)
}

func TestGDPRService(t *testing.T) {
	db, err := setupTestDB()
	require.NoError(t, err)

	// Users table already created in setupTestDB

	obs := setupTestObservability()
	defer obs.Shutdown(context.Background())

	complianceService := NewComplianceService(db, obs)
	gdprService := NewGDPRService(db, obs, complianceService)

	// Create test user
	testUser := models.User{
		Username:  "testuser",
		Email:     "test@example.com",
		FirstName: "Test",
		LastName:  "User",
	}
	err = db.Create(&testUser).Error
	require.NoError(t, err)

	ctx := context.Background()

	// Test data subject request creation
	request, err := gdprService.ProcessDataSubjectRequest(
		ctx,
		RequestTypeAccess,
		"test@example.com",
		"requestor-123",
		map[string]interface{}{
			"data_categories": []string{"profile", "authentication"},
			"purposes":        []string{"access_request"},
		},
	)

	assert.NoError(t, err)
	assert.NotNil(t, request)
	assert.Equal(t, "ACCESS", request.RequestType)
	assert.Equal(t, "test@example.com", request.DataSubject)
	assert.Equal(t, "RECEIVED", request.Status)

	// Test access request processing
	dataMap, err := gdprService.ProcessAccessRequest(ctx, "test@example.com")
	assert.NoError(t, err)
	assert.NotNil(t, dataMap)
	assert.Equal(t, "test@example.com", dataMap.DataSubject)
	assert.NotEmpty(t, dataMap.DataCategories)
	assert.NotEmpty(t, dataMap.ProcessingActivities)
}

func TestReportingService(t *testing.T) {
	db, err := setupTestDB()
	require.NoError(t, err)

	obs := setupTestObservability()
	defer obs.Shutdown(context.Background())

	reportingService := NewReportingService(db, obs)

	// Create test period
	period := Period{
		StartDate: time.Now().AddDate(0, 0, -30),
		EndDate:   time.Now(),
		Type:      "MONTHLY",
	}

	ctx := context.Background()

	// Test dashboard generation (empty database)
	dashboard, err := reportingService.GenerateComplianceDashboard(ctx, period)
	assert.NoError(t, err)
	assert.NotNil(t, dashboard)
	assert.Equal(t, period, dashboard.Period)
	assert.Equal(t, int64(0), dashboard.Summary.TotalAuditEvents)
	assert.NotEmpty(t, dashboard.Recommendations) // Should have some default recommendations
}

func TestComplianceServiceIntegration(t *testing.T) {
	db, err := setupTestDB()
	require.NoError(t, err)

	obs := setupTestObservability()
	defer obs.Shutdown(context.Background())

	service := NewComplianceService(db, obs)
	ctx := context.Background()

	// Test GDPR event logging
	err = service.LogGDPREvent(ctx, "user-123", "gdpr_access_request", "user@example.com", LegalBasisLegitimateInterest, map[string]interface{}{
		"request_id": "req-123",
	})
	assert.NoError(t, err)

	// Test data access logging
	err = service.LogDataAccess(ctx, "user-123", "user_profile", ClassificationPII, []string{"user@example.com"}, "profile_access")
	assert.NoError(t, err)

	// Test security event logging
	err = service.LogSecurityEvent(ctx, "user-123", "failed_login", 3, []string{"rate_limiting", "audit_logging"}, map[string]interface{}{
		"ip_address": "192.168.1.1",
	})
	assert.NoError(t, err)

	// Verify events were logged
	var count int64
	db.Model(&models.ComplianceAuditLog{}).Count(&count)
	assert.Equal(t, int64(3), count)
}
