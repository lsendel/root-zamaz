// Package audit provides compliance-specific audit logging functionality
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
)

// ComplianceFramework represents different compliance standards
type ComplianceFramework string

const (
	FrameworkGDPR     ComplianceFramework = "GDPR"
	FrameworkHIPAA    ComplianceFramework = "HIPAA"
	FrameworkSOX      ComplianceFramework = "SOX"
	FrameworkPCIDSS   ComplianceFramework = "PCI-DSS"
	FrameworkISO27001 ComplianceFramework = "ISO27001"
	FrameworkCCPA     ComplianceFramework = "CCPA"
)

// DataClassification represents data sensitivity levels
type DataClassification string

const (
	ClassificationPublic       DataClassification = "PUBLIC"
	ClassificationInternal     DataClassification = "INTERNAL"
	ClassificationConfidential DataClassification = "CONFIDENTIAL"
	ClassificationRestricted   DataClassification = "RESTRICTED"
	ClassificationPII          DataClassification = "PII"
	ClassificationPHI          DataClassification = "PHI"
)

// LegalBasis represents GDPR legal basis for processing
type LegalBasis string

const (
	LegalBasisConsent            LegalBasis = "CONSENT"
	LegalBasisContract           LegalBasis = "CONTRACT"
	LegalBasisLegalObligation    LegalBasis = "LEGAL_OBLIGATION"
	LegalBasisVitalInterests     LegalBasis = "VITAL_INTERESTS"
	LegalBasisPublicTask         LegalBasis = "PUBLIC_TASK"
	LegalBasisLegitimateInterest LegalBasis = "LEGITIMATE_INTEREST"
)

// RetentionCategory represents different retention policies
type RetentionCategory string

const (
	RetentionCategoryShortTerm  RetentionCategory = "SHORT_TERM"  // 30 days
	RetentionCategoryMediumTerm RetentionCategory = "MEDIUM_TERM" // 1 year
	RetentionCategoryLongTerm   RetentionCategory = "LONG_TERM"   // 7 years
	RetentionCategoryPermanent  RetentionCategory = "PERMANENT"   // No deletion
	RetentionCategoryCompliance RetentionCategory = "COMPLIANCE"  // Based on regulations
)

// ComplianceLogEntry represents an enhanced audit log entry with compliance features
type ComplianceLogEntry struct {
	// Basic audit fields
	UserID   string
	Action   string
	Resource string
	Details  map[string]interface{}
	Success  bool
	ErrorMsg string

	// Request context
	IPAddress string
	UserAgent string
	RequestID string
	SessionID string
	TenantID  string

	// Compliance-specific fields
	ComplianceFrameworks []ComplianceFramework
	DataClassification   DataClassification
	SensitivityLevel     int // 1-5 scale
	LegalBasis           LegalBasis
	DataSubjects         []string // Affected data subjects
	DataCategories       []string // Types of data accessed
	ProcessingPurpose    string   // Business reason
	GeolocationCountry   string   // Processing location

	// Risk and controls
	RiskScore        int      // 0-100 calculated risk score
	ControlsApplied  []string // Security controls
	ApprovalRequired bool     // Whether approval needed
	ApprovalStatus   string   // Approval workflow status
	ReviewStatus     string   // Manual review status

	// Retention and lifecycle
	RetentionCategory     RetentionCategory
	BusinessJustification string // Why this action was taken

	// Context and metadata
	BusinessContext  map[string]interface{} // Additional business context
	TechnicalContext map[string]interface{} // Technical details
}

// ComplianceService provides compliance-focused audit logging
type ComplianceService struct {
	db                *gorm.DB
	obs               *observability.Observability
	retentionPolicies map[RetentionCategory]time.Duration
	riskCalculator    *RiskCalculator
	violationDetector *ViolationDetector
	retentionManager  *RetentionManager
}

// NewComplianceService creates a new compliance-aware audit service
func NewComplianceService(db *gorm.DB, obs *observability.Observability) *ComplianceService {
	service := &ComplianceService{
		db:  db,
		obs: obs,
		retentionPolicies: map[RetentionCategory]time.Duration{
			RetentionCategoryShortTerm:  30 * 24 * time.Hour,       // 30 days
			RetentionCategoryMediumTerm: 365 * 24 * time.Hour,      // 1 year
			RetentionCategoryLongTerm:   7 * 365 * 24 * time.Hour,  // 7 years
			RetentionCategoryCompliance: 10 * 365 * 24 * time.Hour, // 10 years (configurable)
		},
	}

	service.riskCalculator = NewRiskCalculator()
	service.violationDetector = NewViolationDetector(obs)
	service.retentionManager = NewRetentionManager(db, obs, service.retentionPolicies)

	return service
}

// LogComplianceEvent logs a compliance-aware audit event
func (s *ComplianceService) LogComplianceEvent(ctx context.Context, entry ComplianceLogEntry) error {
	start := time.Now()

	// Calculate risk score
	riskScore := s.riskCalculator.CalculateRisk(entry)
	entry.RiskScore = riskScore

	// Determine retention based on frameworks and data classification
	retentionCategory := s.determineRetentionCategory(entry)
	entry.RetentionCategory = retentionCategory

	// Calculate retention dates
	retentionDuration := s.retentionPolicies[retentionCategory]
	now := time.Now()
	retainUntil := now.Add(retentionDuration)
	archiveDate := now.Add(retentionDuration / 2) // Archive at halfway point

	// Create compliance audit log
	complianceLog := models.ComplianceAuditLog{
		// Basic audit fields
		UserID:   parseUUID(entry.UserID),
		Action:   entry.Action,
		Resource: entry.Resource,
		Details:  marshalJSON(entry.Details),
		Success:  entry.Success,
		ErrorMsg: entry.ErrorMsg,

		// Request context
		IPAddress: entry.IPAddress,
		UserAgent: entry.UserAgent,
		RequestID: entry.RequestID,
		SessionID: entry.SessionID,
		TenantID:  entry.TenantID,

		// Compliance fields
		ComplianceFrameworks: marshalStringSlice(entry.ComplianceFrameworks),
		DataClassification:   string(entry.DataClassification),
		SensitivityLevel:     entry.SensitivityLevel,
		LegalBasis:           string(entry.LegalBasis),
		DataSubjects:         marshalJSON(entry.DataSubjects),
		DataCategories:       marshalJSON(entry.DataCategories),
		ProcessingPurpose:    entry.ProcessingPurpose,
		GeolocationCountry:   entry.GeolocationCountry,

		// Risk and controls
		RiskScore:        entry.RiskScore,
		ControlsApplied:  marshalJSON(entry.ControlsApplied),
		ApprovalRequired: entry.ApprovalRequired,
		ApprovalStatus:   entry.ApprovalStatus,
		ReviewStatus:     entry.ReviewStatus,

		// Retention
		RetentionCategory:     string(entry.RetentionCategory),
		BusinessJustification: entry.BusinessJustification,
		RetainUntil:           &retainUntil,
		ArchiveDate:           &archiveDate,

		// Context
		BusinessContext:  marshalJSON(entry.BusinessContext),
		TechnicalContext: marshalJSON(entry.TechnicalContext),
	}

	// Save to database
	if err := s.db.WithContext(ctx).Create(&complianceLog).Error; err != nil {
		s.obs.Logger.Error().
			Err(err).
			Str("action", entry.Action).
			Str("user_id", entry.UserID).
			Msg("Failed to save compliance audit log")
		return fmt.Errorf("failed to save compliance audit log: %w", err)
	}

	// Check for compliance violations
	if violations := s.violationDetector.DetectViolations(entry); len(violations) > 0 {
		s.handleComplianceViolations(ctx, complianceLog.ID, violations)
	}

	// Log performance metrics
	duration := time.Since(start)
	s.obs.Logger.Debug().
		Str("action", entry.Action).
		Int("risk_score", entry.RiskScore).
		Str("retention_category", string(entry.RetentionCategory)).
		Dur("duration", duration).
		Msg("Compliance audit event logged")

	return nil
}

// LogGDPREvent logs a GDPR-specific audit event
func (s *ComplianceService) LogGDPREvent(ctx context.Context, userID, action string, dataSubject string, legalBasis LegalBasis, details map[string]interface{}) error {
	return s.LogComplianceEvent(ctx, ComplianceLogEntry{
		UserID:                userID,
		Action:                action,
		Resource:              "gdpr",
		Details:               details,
		Success:               true,
		ComplianceFrameworks:  []ComplianceFramework{FrameworkGDPR},
		DataClassification:    ClassificationPII,
		SensitivityLevel:      4,
		LegalBasis:            legalBasis,
		DataSubjects:          []string{dataSubject},
		DataCategories:        []string{"personal_data"},
		ProcessingPurpose:     "user_authentication",
		RetentionCategory:     RetentionCategoryCompliance,
		BusinessJustification: fmt.Sprintf("GDPR %s operation for data subject", action),
	})
}

// LogDataAccess logs data access events with compliance context
func (s *ComplianceService) LogDataAccess(ctx context.Context, userID, resource string, dataClassification DataClassification, dataSubjects []string, purpose string) error {
	frameworks := []ComplianceFramework{FrameworkGDPR}
	if dataClassification == ClassificationPHI {
		frameworks = append(frameworks, FrameworkHIPAA)
	}

	return s.LogComplianceEvent(ctx, ComplianceLogEntry{
		UserID:                userID,
		Action:                "data_access",
		Resource:              resource,
		Success:               true,
		ComplianceFrameworks:  frameworks,
		DataClassification:    dataClassification,
		SensitivityLevel:      getSensitivityLevel(dataClassification),
		LegalBasis:            LegalBasisLegitimateInterest,
		DataSubjects:          dataSubjects,
		DataCategories:        []string{"user_data"},
		ProcessingPurpose:     purpose,
		RetentionCategory:     RetentionCategoryCompliance,
		BusinessJustification: fmt.Sprintf("Authorized access to %s for %s", resource, purpose),
	})
}

// LogSecurityEvent logs security-related events with compliance context
func (s *ComplianceService) LogSecurityEvent(ctx context.Context, userID, action string, severity int, controls []string, details map[string]interface{}) error {
	return s.LogComplianceEvent(ctx, ComplianceLogEntry{
		UserID:                userID,
		Action:                action,
		Resource:              "security",
		Details:               details,
		Success:               true,
		ComplianceFrameworks:  []ComplianceFramework{FrameworkISO27001, FrameworkSOX},
		DataClassification:    ClassificationConfidential,
		SensitivityLevel:      severity,
		LegalBasis:            LegalBasisLegalObligation,
		ProcessingPurpose:     "security_monitoring",
		ControlsApplied:       controls,
		RetentionCategory:     RetentionCategoryLongTerm,
		BusinessJustification: fmt.Sprintf("Security event monitoring: %s", action),
	})
}

// Helper methods

func (s *ComplianceService) determineRetentionCategory(entry ComplianceLogEntry) RetentionCategory {
	// Explicit retention category takes precedence
	if entry.RetentionCategory != "" {
		return entry.RetentionCategory
	}

	// Determine based on compliance frameworks and data classification
	for _, framework := range entry.ComplianceFrameworks {
		switch framework {
		case FrameworkGDPR:
			if entry.DataClassification == ClassificationPII {
				return RetentionCategoryCompliance
			}
		case FrameworkHIPAA:
			if entry.DataClassification == ClassificationPHI {
				return RetentionCategoryLongTerm
			}
		case FrameworkSOX:
			return RetentionCategoryLongTerm
		case FrameworkPCIDSS:
			return RetentionCategoryMediumTerm
		}
	}

	// Default based on data classification
	switch entry.DataClassification {
	case ClassificationRestricted, ClassificationPII, ClassificationPHI:
		return RetentionCategoryCompliance
	case ClassificationConfidential:
		return RetentionCategoryLongTerm
	case ClassificationInternal:
		return RetentionCategoryMediumTerm
	default:
		return RetentionCategoryShortTerm
	}
}

func (s *ComplianceService) handleComplianceViolations(ctx context.Context, auditLogID uuid.UUID, violations []ComplianceViolation) {
	for _, violation := range violations {
		// Create violation record
		violationRecord := models.ComplianceViolation{
			AuditLogID:    auditLogID,
			ViolationType: violation.Type,
			Framework:     violation.Framework,
			Severity:      violation.Severity,
			Description:   violation.Description,
			Remediation:   violation.Remediation,
		}

		if err := s.db.WithContext(ctx).Create(&violationRecord).Error; err != nil {
			s.obs.Logger.Error().
				Err(err).
				Str("violation_type", violation.Type).
				Msg("Failed to save compliance violation")
		}

		// Log violation for alerting
		s.obs.Logger.Warn().
			Str("violation_type", violation.Type).
			Str("framework", violation.Framework).
			Int("severity", violation.Severity).
			Str("description", violation.Description).
			Msg("Compliance violation detected")
	}
}

func parseUUID(s string) *uuid.UUID {
	if s == "" {
		return nil
	}
	if parsed, err := uuid.Parse(s); err == nil {
		return &parsed
	}
	return nil
}

func marshalJSON(v interface{}) string {
	if v == nil {
		return ""
	}
	data, _ := json.Marshal(v)
	return string(data)
}

func marshalStringSlice(slice []ComplianceFramework) string {
	if len(slice) == 0 {
		return ""
	}
	strs := make([]string, len(slice))
	for i, v := range slice {
		strs[i] = string(v)
	}
	return strings.Join(strs, ",")
}

func getSensitivityLevel(classification DataClassification) int {
	switch classification {
	case ClassificationPublic:
		return 1
	case ClassificationInternal:
		return 2
	case ClassificationConfidential:
		return 3
	case ClassificationPII:
		return 4
	case ClassificationRestricted, ClassificationPHI:
		return 5
	default:
		return 1
	}
}
