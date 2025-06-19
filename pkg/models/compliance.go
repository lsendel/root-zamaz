// Package models provides compliance-specific database models for the MVP Zero Trust Auth system.
package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ComplianceAuditLog represents enhanced audit logs with compliance features
type ComplianceAuditLog struct {
	ID        uuid.UUID      `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Basic audit fields
	UserID   *uuid.UUID `gorm:"index;type:uuid" json:"user_id"`
	User     *User      `json:"user,omitempty"`
	Action   string     `gorm:"not null;size:100;index" json:"action"`
	Resource string     `gorm:"size:100;index" json:"resource"`
	Details  string     `gorm:"type:jsonb" json:"details"` // JSON data
	Success  bool       `gorm:"default:false;index" json:"success"`
	ErrorMsg string     `gorm:"size:500" json:"error_msg"`

	// Request context
	IPAddress string `gorm:"size:45;index" json:"ip_address"`
	UserAgent string `gorm:"size:500" json:"user_agent"`
	RequestID string `gorm:"size:100;index" json:"request_id"`
	SessionID string `gorm:"size:100;index" json:"session_id"`
	TenantID  string `gorm:"size:100;index" json:"tenant_id"`

	// Compliance-specific fields
	ComplianceFrameworks string `gorm:"size:200" json:"compliance_frameworks"` // Comma-separated
	DataClassification   string `gorm:"size:50;index" json:"data_classification"`
	SensitivityLevel     int    `gorm:"default:1;index" json:"sensitivity_level"` // 1-5 scale
	LegalBasis          string `gorm:"size:50" json:"legal_basis"`
	DataSubjects        string `gorm:"type:jsonb" json:"data_subjects"`  // JSON array
	DataCategories      string `gorm:"type:jsonb" json:"data_categories"` // JSON array
	ProcessingPurpose   string `gorm:"size:500" json:"processing_purpose"`
	GeolocationCountry  string `gorm:"size:10;index" json:"geolocation_country"`

	// Risk and controls
	RiskScore       int    `gorm:"default:0;index" json:"risk_score"` // 0-100
	ControlsApplied string `gorm:"type:jsonb" json:"controls_applied"` // JSON array
	ApprovalRequired bool   `gorm:"default:false" json:"approval_required"`
	ApprovalStatus  string `gorm:"size:50" json:"approval_status"`
	ReviewStatus    string `gorm:"size:50" json:"review_status"`

	// Retention and lifecycle
	RetentionCategory     string     `gorm:"size:50;index" json:"retention_category"`
	BusinessJustification string     `gorm:"size:1000" json:"business_justification"`
	RetainUntil          *time.Time `gorm:"index" json:"retain_until"`
	ArchiveDate          *time.Time `gorm:"index" json:"archive_date"`
	PurgeDate            *time.Time `gorm:"index" json:"purge_date"`
	
	// Lifecycle tracking
	Archived   bool       `gorm:"default:false;index" json:"archived"`
	ArchivedAt *time.Time `json:"archived_at"`

	// Context and metadata
	BusinessContext  string `gorm:"type:jsonb" json:"business_context"`  // JSON data
	TechnicalContext string `gorm:"type:jsonb" json:"technical_context"` // JSON data
}

// ComplianceViolation represents detected compliance violations
type ComplianceViolation struct {
	ID        uuid.UUID      `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Associated audit log
	AuditLogID uuid.UUID           `gorm:"not null;index;type:uuid" json:"audit_log_id"`
	AuditLog   ComplianceAuditLog  `json:"audit_log,omitempty"`

	// Violation details
	ViolationType string `gorm:"not null;size:100;index" json:"violation_type"`
	Framework     string `gorm:"size:50;index" json:"framework"`
	Severity      int    `gorm:"not null;index" json:"severity"` // 1-5 scale
	Description   string `gorm:"size:1000" json:"description"`
	Remediation   string `gorm:"size:1000" json:"remediation"`
	RiskScore     int    `gorm:"default:0" json:"risk_score"`

	// Resolution tracking
	Status        string     `gorm:"size:50;default:'OPEN';index" json:"status"` // OPEN, IN_PROGRESS, RESOLVED, ACCEPTED
	AssignedTo    string     `gorm:"size:100" json:"assigned_to"`
	ResolvedAt    *time.Time `json:"resolved_at"`
	Resolution    string     `gorm:"size:1000" json:"resolution"`
	ResolutionBy  string     `gorm:"size:100" json:"resolution_by"`
}

// DataSubjectRequest represents GDPR data subject requests
type DataSubjectRequest struct {
	ID        uuid.UUID      `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Request details
	RequestType   string `gorm:"not null;size:50;index" json:"request_type"` // ACCESS, RECTIFICATION, ERASURE, etc.
	DataSubject   string `gorm:"not null;size:255;index" json:"data_subject"`
	RequestorID   string `gorm:"size:100" json:"requestor_id"`
	
	// Contact information
	Email       string `gorm:"size:255" json:"email"`
	PhoneNumber string `gorm:"size:50" json:"phone_number"`
	
	// Request processing
	Status          string     `gorm:"size:50;default:'RECEIVED';index" json:"status"` // RECEIVED, VERIFIED, PROCESSING, COMPLETED, REJECTED
	Priority        string     `gorm:"size:20;default:'NORMAL'" json:"priority"`       // LOW, NORMAL, HIGH, URGENT
	AssignedTo      string     `gorm:"size:100" json:"assigned_to"`
	DueDate         *time.Time `gorm:"index" json:"due_date"`
	CompletedAt     *time.Time `json:"completed_at"`
	
	// Legal basis and verification
	LegalBasis         string `gorm:"size:100" json:"legal_basis"`
	IdentityVerified   bool   `gorm:"default:false" json:"identity_verified"`
	VerificationMethod string `gorm:"size:100" json:"verification_method"`
	VerifiedBy         string `gorm:"size:100" json:"verified_by"`
	VerifiedAt         *time.Time `json:"verified_at"`
	
	// Request details
	Description    string `gorm:"size:2000" json:"description"`
	DataCategories string `gorm:"type:jsonb" json:"data_categories"` // JSON array
	ProcessingPurposes string `gorm:"type:jsonb" json:"processing_purposes"` // JSON array
	
	// Response and resolution
	Response       string `gorm:"type:text" json:"response"`
	ResponseMethod string `gorm:"size:50" json:"response_method"` // EMAIL, POSTAL, SECURE_PORTAL
	RejectionReason string `gorm:"size:1000" json:"rejection_reason"`
	
	// Compliance tracking
	ComplianceNotes string `gorm:"type:text" json:"compliance_notes"`
	ReviewedBy      string `gorm:"size:100" json:"reviewed_by"`
	ReviewedAt      *time.Time `json:"reviewed_at"`
}

// ConsentRecord represents GDPR consent tracking
type ConsentRecord struct {
	ID        uuid.UUID      `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Data subject
	DataSubject   string `gorm:"not null;size:255;index" json:"data_subject"`
	UserID        *uuid.UUID `gorm:"type:uuid;index" json:"user_id"`
	User          *User      `json:"user,omitempty"`
	
	// Consent details
	ConsentType     string `gorm:"not null;size:100;index" json:"consent_type"` // MARKETING, ANALYTICS, etc.
	Purpose         string `gorm:"not null;size:500" json:"purpose"`
	LegalBasis      string `gorm:"size:100" json:"legal_basis"`
	DataCategories  string `gorm:"type:jsonb" json:"data_categories"` // JSON array
	
	// Consent status
	Status          string     `gorm:"not null;size:50;index" json:"status"` // GIVEN, WITHDRAWN, EXPIRED
	ConsentGiven    bool       `gorm:"not null;index" json:"consent_given"`
	ConsentDate     time.Time  `gorm:"not null;index" json:"consent_date"`
	WithdrawnDate   *time.Time `gorm:"index" json:"withdrawn_date"`
	ExpiryDate      *time.Time `gorm:"index" json:"expiry_date"`
	
	// Consent mechanism
	ConsentMethod   string `gorm:"size:100" json:"consent_method"` // WEB_FORM, EMAIL, PHONE, etc.
	ConsentText     string `gorm:"type:text" json:"consent_text"`
	ConsentVersion  string `gorm:"size:20" json:"consent_version"`
	
	// Technical details
	IPAddress       string `gorm:"size:45" json:"ip_address"`
	UserAgent       string `gorm:"size:500" json:"user_agent"`
	ConsentProof    string `gorm:"type:jsonb" json:"consent_proof"` // JSON evidence
	
	// Withdrawal details
	WithdrawalMethod string `gorm:"size:100" json:"withdrawal_method"`
	WithdrawalReason string `gorm:"size:500" json:"withdrawal_reason"`
}

// RetentionPolicy represents data retention policies
type RetentionPolicy struct {
	ID        int64          `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Policy identification
	Name        string `gorm:"uniqueIndex;not null;size:100" json:"name"`
	Description string `gorm:"size:500" json:"description"`
	Category    string `gorm:"not null;size:50;index" json:"category"`
	
	// Retention rules
	RetentionPeriod   int    `gorm:"not null" json:"retention_period"`      // Days
	RetentionUnit     string `gorm:"size:10;default:'DAYS'" json:"retention_unit"` // DAYS, MONTHS, YEARS
	ArchivePeriod     int    `json:"archive_period"`                        // Days before archival
	
	// Applicability
	DataClassification string `gorm:"size:50" json:"data_classification"`
	ComplianceFramework string `gorm:"size:50" json:"compliance_framework"`
	LegalBasis         string `gorm:"size:100" json:"legal_basis"`
	
	// Policy status
	IsActive    bool       `gorm:"default:true;index" json:"is_active"`
	EffectiveDate time.Time `gorm:"not null" json:"effective_date"`
	ExpiryDate    *time.Time `json:"expiry_date"`
	
	// Approval and governance
	ApprovedBy   string     `gorm:"size:100" json:"approved_by"`
	ApprovedAt   *time.Time `json:"approved_at"`
	ReviewDate   *time.Time `json:"review_date"`
	ReviewedBy   string     `gorm:"size:100" json:"reviewed_by"`
	
	// Policy rules
	Rules           string `gorm:"type:jsonb" json:"rules"`           // JSON policy rules
	Exceptions      string `gorm:"type:jsonb" json:"exceptions"`      // JSON exceptions
	AutomationRules string `gorm:"type:jsonb" json:"automation_rules"` // JSON automation
}

// ComplianceReport represents compliance reporting
type ComplianceReport struct {
	ID        uuid.UUID      `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Report details
	ReportType    string    `gorm:"not null;size:100;index" json:"report_type"` // GDPR_COMPLIANCE, HIPAA_AUDIT, etc.
	Title         string    `gorm:"not null;size:200" json:"title"`
	Description   string    `gorm:"size:1000" json:"description"`
	Framework     string    `gorm:"size:50;index" json:"framework"`
	
	// Reporting period
	PeriodStart   time.Time `gorm:"not null;index" json:"period_start"`
	PeriodEnd     time.Time `gorm:"not null;index" json:"period_end"`
	
	// Report generation
	GeneratedBy   string     `gorm:"size:100" json:"generated_by"`
	GeneratedAt   time.Time  `gorm:"not null" json:"generated_at"`
	Status        string     `gorm:"size:50;default:'DRAFT';index" json:"status"` // DRAFT, FINAL, PUBLISHED
	
	// Report content
	ExecutiveSummary string `gorm:"type:text" json:"executive_summary"`
	Findings        string `gorm:"type:jsonb" json:"findings"`        // JSON report data
	Recommendations string `gorm:"type:jsonb" json:"recommendations"` // JSON recommendations
	Metrics         string `gorm:"type:jsonb" json:"metrics"`         // JSON metrics
	
	// Report metadata
	Version       string `gorm:"size:20" json:"version"`
	Confidentiality string `gorm:"size:50;default:'INTERNAL'" json:"confidentiality"`
	
	// Approval and distribution
	ApprovedBy    string     `gorm:"size:100" json:"approved_by"`
	ApprovedAt    *time.Time `json:"approved_at"`
	PublishedAt   *time.Time `json:"published_at"`
	Distribution  string     `gorm:"type:jsonb" json:"distribution"` // JSON distribution list
}

// TableName methods for custom table names

func (ComplianceAuditLog) TableName() string {
	return "compliance_audit_logs"
}

func (ComplianceViolation) TableName() string {
	return "compliance_violations"
}

func (DataSubjectRequest) TableName() string {
	return "data_subject_requests"
}

func (ConsentRecord) TableName() string {
	return "consent_records"
}

func (RetentionPolicy) TableName() string {
	return "retention_policies"
}

func (ComplianceReport) TableName() string {
	return "compliance_reports"
}