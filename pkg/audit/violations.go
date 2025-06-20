// Package audit provides compliance violation detection for audit logging
package audit

import (
	"strings"
	"time"

	"mvp.local/pkg/observability"
)

// ComplianceViolation represents a detected compliance violation
type ComplianceViolation struct {
	Type        string `json:"type"`
	Framework   string `json:"framework"`
	Severity    int    `json:"severity"` // 1-5 scale
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	RiskScore   int    `json:"risk_score"`
}

// ViolationDetector detects compliance violations in audit events
type ViolationDetector struct {
	obs *observability.Observability
}

// NewViolationDetector creates a new violation detector
func NewViolationDetector(obs *observability.Observability) *ViolationDetector {
	return &ViolationDetector{obs: obs}
}

// DetectViolations analyzes an audit entry for compliance violations
func (vd *ViolationDetector) DetectViolations(entry ComplianceLogEntry) []ComplianceViolation {
	var violations []ComplianceViolation

	// Check each compliance framework
	for _, framework := range entry.ComplianceFrameworks {
		switch framework {
		case FrameworkGDPR:
			violations = append(violations, vd.detectGDPRViolations(entry)...)
		case FrameworkHIPAA:
			violations = append(violations, vd.detectHIPAAViolations(entry)...)
		case FrameworkSOX:
			violations = append(violations, vd.detectSOXViolations(entry)...)
		case FrameworkPCIDSS:
			violations = append(violations, vd.detectPCIDSSViolations(entry)...)
		case FrameworkISO27001:
			violations = append(violations, vd.detectISO27001Violations(entry)...)
		}
	}

	// Check general security violations
	violations = append(violations, vd.detectSecurityViolations(entry)...)

	// Check data handling violations
	violations = append(violations, vd.detectDataHandlingViolations(entry)...)

	return violations
}

// detectGDPRViolations detects GDPR-specific violations
func (vd *ViolationDetector) detectGDPRViolations(entry ComplianceLogEntry) []ComplianceViolation {
	var violations []ComplianceViolation

	// Check for missing legal basis
	if entry.LegalBasis == "" && entry.DataClassification == ClassificationPII {
		violations = append(violations, ComplianceViolation{
			Type:        "gdpr_missing_legal_basis",
			Framework:   string(FrameworkGDPR),
			Severity:    4,
			Description: "Processing of personal data without documented legal basis",
			Remediation: "Document valid legal basis under GDPR Article 6",
			RiskScore:   85,
		})
	}

	// Check for excessive data access
	if entry.Action == "bulk_download" && entry.DataClassification == ClassificationPII {
		violations = append(violations, ComplianceViolation{
			Type:        "gdpr_data_minimization",
			Framework:   string(FrameworkGDPR),
			Severity:    3,
			Description: "Potential violation of data minimization principle (Article 5.1.c)",
			Remediation: "Verify necessity and proportionality of bulk data access",
			RiskScore:   70,
		})
	}

	// Check for missing data subject identification
	if len(entry.DataSubjects) == 0 && entry.DataClassification == ClassificationPII {
		violations = append(violations, ComplianceViolation{
			Type:        "gdpr_missing_data_subject",
			Framework:   string(FrameworkGDPR),
			Severity:    2,
			Description: "Personal data processing without identified data subjects",
			Remediation: "Identify and document affected data subjects",
			RiskScore:   60,
		})
	}

	// Check for retention violations
	if entry.RetentionCategory == RetentionCategoryPermanent && entry.DataClassification == ClassificationPII {
		violations = append(violations, ComplianceViolation{
			Type:        "gdpr_retention_excessive",
			Framework:   string(FrameworkGDPR),
			Severity:    3,
			Description: "Indefinite retention of personal data violates storage limitation principle",
			Remediation: "Implement appropriate retention periods per GDPR Article 5.1.e",
			RiskScore:   75,
		})
	}

	// Check for cross-border transfers without safeguards
	if entry.GeolocationCountry != "" && !vd.isEEACountry(entry.GeolocationCountry) && entry.DataClassification == ClassificationPII {
		violations = append(violations, ComplianceViolation{
			Type:        "gdpr_international_transfer",
			Framework:   string(FrameworkGDPR),
			Severity:    4,
			Description: "International transfer of personal data to non-EEA country",
			Remediation: "Ensure adequate safeguards per GDPR Chapter V",
			RiskScore:   80,
		})
	}

	return violations
}

// detectHIPAAViolations detects HIPAA-specific violations
func (vd *ViolationDetector) detectHIPAAViolations(entry ComplianceLogEntry) []ComplianceViolation {
	var violations []ComplianceViolation

	// Check for PHI access without authorization
	if entry.DataClassification == ClassificationPHI && !entry.ApprovalRequired {
		violations = append(violations, ComplianceViolation{
			Type:        "hipaa_unauthorized_phi_access",
			Framework:   string(FrameworkHIPAA),
			Severity:    5,
			Description: "Access to PHI without documented authorization",
			Remediation: "Implement authorization controls per 45 CFR 164.308(a)(4)",
			RiskScore:   95,
		})
	}

	// Check for minimum necessary standard
	if entry.Action == "bulk_download" && entry.DataClassification == ClassificationPHI {
		violations = append(violations, ComplianceViolation{
			Type:        "hipaa_minimum_necessary",
			Framework:   string(FrameworkHIPAA),
			Severity:    4,
			Description: "Potential violation of minimum necessary standard",
			Remediation: "Verify minimum necessary requirement per 45 CFR 164.502(b)",
			RiskScore:   85,
		})
	}

	// Check for audit controls
	if !vd.hasAuditControls(entry.ControlsApplied) && entry.DataClassification == ClassificationPHI {
		violations = append(violations, ComplianceViolation{
			Type:        "hipaa_audit_controls",
			Framework:   string(FrameworkHIPAA),
			Severity:    3,
			Description: "Insufficient audit controls for PHI access",
			Remediation: "Implement audit controls per 45 CFR 164.312(b)",
			RiskScore:   70,
		})
	}

	return violations
}

// detectSOXViolations detects SOX-specific violations
func (vd *ViolationDetector) detectSOXViolations(entry ComplianceLogEntry) []ComplianceViolation {
	var violations []ComplianceViolation

	// Check for segregation of duties
	if vd.isFinancialAction(entry.Action) && !vd.hasSegregationOfDuties(entry.ControlsApplied) {
		violations = append(violations, ComplianceViolation{
			Type:        "sox_segregation_duties",
			Framework:   string(FrameworkSOX),
			Severity:    4,
			Description: "Financial operation without proper segregation of duties",
			Remediation: "Implement segregation of duties controls per SOX Section 404",
			RiskScore:   85,
		})
	}

	// Check for change management
	if strings.Contains(entry.Action, "modify") && !vd.hasChangeApproval(entry.ApprovalStatus) {
		violations = append(violations, ComplianceViolation{
			Type:        "sox_change_management",
			Framework:   string(FrameworkSOX),
			Severity:    3,
			Description: "System changes without proper approval process",
			Remediation: "Implement change management controls",
			RiskScore:   75,
		})
	}

	return violations
}

// detectPCIDSSViolations detects PCI-DSS-specific violations
func (vd *ViolationDetector) detectPCIDSSViolations(entry ComplianceLogEntry) []ComplianceViolation {
	var violations []ComplianceViolation

	// Check for cardholder data access logging
	if vd.isCardholderData(entry.DataCategories) && !vd.hasProperLogging(entry.ControlsApplied) {
		violations = append(violations, ComplianceViolation{
			Type:        "pcidss_access_logging",
			Framework:   string(FrameworkPCIDSS),
			Severity:    4,
			Description: "Insufficient logging for cardholder data access",
			Remediation: "Implement comprehensive logging per PCI-DSS Requirement 10",
			RiskScore:   80,
		})
	}

	// Check for encryption requirements
	if vd.isCardholderData(entry.DataCategories) && !vd.hasEncryption(entry.ControlsApplied) {
		violations = append(violations, ComplianceViolation{
			Type:        "pcidss_encryption",
			Framework:   string(FrameworkPCIDSS),
			Severity:    5,
			Description: "Cardholder data access without proper encryption",
			Remediation: "Implement encryption per PCI-DSS Requirements 3 and 4",
			RiskScore:   95,
		})
	}

	return violations
}

// detectISO27001Violations detects ISO 27001-specific violations
func (vd *ViolationDetector) detectISO27001Violations(entry ComplianceLogEntry) []ComplianceViolation {
	var violations []ComplianceViolation

	// Check for access control
	if entry.SensitivityLevel >= 4 && !vd.hasAccessControl(entry.ControlsApplied) {
		violations = append(violations, ComplianceViolation{
			Type:        "iso27001_access_control",
			Framework:   string(FrameworkISO27001),
			Severity:    3,
			Description: "High sensitivity data access without proper access controls",
			Remediation: "Implement access control per ISO 27001 A.9",
			RiskScore:   70,
		})
	}

	// Check for incident management
	if !entry.Success && entry.RiskScore > 70 && entry.ReviewStatus == "" {
		violations = append(violations, ComplianceViolation{
			Type:        "iso27001_incident_management",
			Framework:   string(FrameworkISO27001),
			Severity:    3,
			Description: "High-risk security incident without proper incident management",
			Remediation: "Follow incident management process per ISO 27001 A.16",
			RiskScore:   75,
		})
	}

	return violations
}

// detectSecurityViolations detects general security violations
func (vd *ViolationDetector) detectSecurityViolations(entry ComplianceLogEntry) []ComplianceViolation {
	var violations []ComplianceViolation

	// Check for failed authentication attempts
	if !entry.Success && strings.Contains(entry.Action, "login") {
		violations = append(violations, ComplianceViolation{
			Type:        "security_failed_authentication",
			Framework:   "SECURITY",
			Severity:    2,
			Description: "Failed authentication attempt",
			Remediation: "Monitor for brute force attacks and implement lockout policies",
			RiskScore:   entry.RiskScore,
		})
	}

	// Check for privilege escalation
	if strings.Contains(entry.Action, "privilege") || strings.Contains(entry.Action, "role_change") {
		violations = append(violations, ComplianceViolation{
			Type:        "security_privilege_escalation",
			Framework:   "SECURITY",
			Severity:    4,
			Description: "Privilege escalation detected",
			Remediation: "Review and approve all privilege changes",
			RiskScore:   85,
		})
	}

	// Check for unusual activity times
	hour := time.Now().Hour()
	if (hour < 6 || hour > 22) && entry.RiskScore > 60 {
		violations = append(violations, ComplianceViolation{
			Type:        "security_unusual_hours",
			Framework:   "SECURITY",
			Severity:    2,
			Description: "High-risk activity during unusual hours",
			Remediation: "Verify legitimacy of after-hours access",
			RiskScore:   entry.RiskScore,
		})
	}

	return violations
}

// detectDataHandlingViolations detects data handling violations
func (vd *ViolationDetector) detectDataHandlingViolations(entry ComplianceLogEntry) []ComplianceViolation {
	var violations []ComplianceViolation

	// Check for unclassified sensitive data
	if entry.DataClassification == "" && entry.SensitivityLevel > 3 {
		violations = append(violations, ComplianceViolation{
			Type:        "data_unclassified_sensitive",
			Framework:   "DATA_GOVERNANCE",
			Severity:    3,
			Description: "High sensitivity data without proper classification",
			Remediation: "Classify data according to organizational data classification policy",
			RiskScore:   70,
		})
	}

	// Check for excessive retention
	if entry.RetentionCategory == RetentionCategoryPermanent && entry.SensitivityLevel > 3 {
		violations = append(violations, ComplianceViolation{
			Type:        "data_excessive_retention",
			Framework:   "DATA_GOVERNANCE",
			Severity:    2,
			Description: "High sensitivity data with indefinite retention",
			Remediation: "Implement appropriate data retention policies",
			RiskScore:   60,
		})
	}

	return violations
}

// Helper methods for violation detection

func (vd *ViolationDetector) isEEACountry(country string) bool {
	eeaCountries := map[string]bool{
		"AT": true, "BE": true, "BG": true, "HR": true, "CY": true, "CZ": true,
		"DK": true, "EE": true, "FI": true, "FR": true, "DE": true, "GR": true,
		"HU": true, "IS": true, "IE": true, "IT": true, "LV": true, "LI": true,
		"LT": true, "LU": true, "MT": true, "NL": true, "NO": true, "PL": true,
		"PT": true, "RO": true, "SK": true, "SI": true, "ES": true, "SE": true,
	}
	return eeaCountries[strings.ToUpper(country)]
}

func (vd *ViolationDetector) hasAuditControls(controls []string) bool {
	for _, control := range controls {
		if strings.Contains(strings.ToLower(control), "audit") {
			return true
		}
	}
	return false
}

func (vd *ViolationDetector) isFinancialAction(action string) bool {
	financialActions := []string{"financial", "accounting", "payment", "invoice", "billing"}
	action = strings.ToLower(action)
	for _, fa := range financialActions {
		if strings.Contains(action, fa) {
			return true
		}
	}
	return false
}

func (vd *ViolationDetector) hasSegregationOfDuties(controls []string) bool {
	for _, control := range controls {
		if strings.Contains(strings.ToLower(control), "segregation") ||
			strings.Contains(strings.ToLower(control), "separation") ||
			strings.Contains(strings.ToLower(control), "dual_approval") {
			return true
		}
	}
	return false
}

func (vd *ViolationDetector) hasChangeApproval(approvalStatus string) bool {
	return approvalStatus != "" && strings.ToLower(approvalStatus) == "approved"
}

func (vd *ViolationDetector) isCardholderData(dataCategories []string) bool {
	for _, category := range dataCategories {
		category = strings.ToLower(category)
		if strings.Contains(category, "card") || strings.Contains(category, "payment") {
			return true
		}
	}
	return false
}

func (vd *ViolationDetector) hasProperLogging(controls []string) bool {
	for _, control := range controls {
		if strings.Contains(strings.ToLower(control), "logging") ||
			strings.Contains(strings.ToLower(control), "audit") {
			return true
		}
	}
	return false
}

func (vd *ViolationDetector) hasEncryption(controls []string) bool {
	for _, control := range controls {
		if strings.Contains(strings.ToLower(control), "encrypt") ||
			strings.Contains(strings.ToLower(control), "tls") ||
			strings.Contains(strings.ToLower(control), "ssl") {
			return true
		}
	}
	return false
}

func (vd *ViolationDetector) hasAccessControl(controls []string) bool {
	for _, control := range controls {
		control = strings.ToLower(control)
		if strings.Contains(control, "access_control") ||
			strings.Contains(control, "authentication") ||
			strings.Contains(control, "authorization") {
			return true
		}
	}
	return false
}
