// Package audit provides compliance reporting and dashboard functionality
package audit

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"gorm.io/gorm"

	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
)

// ReportingService provides compliance reporting functionality
type ReportingService struct {
	db  *gorm.DB
	obs *observability.Observability
}

// ComplianceDashboard represents compliance dashboard data
type ComplianceDashboard struct {
	GeneratedAt time.Time `json:"generated_at"`
	Period      Period    `json:"period"`

	// High-level metrics
	Summary ComplianceSummary `json:"summary"`

	// Framework-specific metrics
	GDPR     GDPRMetrics     `json:"gdpr"`
	HIPAA    HIPAAMetrics    `json:"hipaa"`
	SOX      SOXMetrics      `json:"sox"`
	Security SecurityMetrics `json:"security"`

	// Risk and violations
	RiskAssessment      RiskMetrics      `json:"risk_assessment"`
	Violations          ViolationMetrics `json:"violations"`
	DataSubjectRequests DSRMetrics       `json:"data_subject_requests"`

	// Trends and analytics
	Trends          TrendAnalysis `json:"trends"`
	Recommendations []string      `json:"recommendations"`
}

// Period represents a reporting period
type Period struct {
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
	Type      string    `json:"type"` // DAILY, WEEKLY, MONTHLY, QUARTERLY, YEARLY
}

// ComplianceSummary provides high-level compliance metrics
type ComplianceSummary struct {
	TotalAuditEvents    int64   `json:"total_audit_events"`
	ComplianceScore     float64 `json:"compliance_score"` // 0-100
	CriticalViolations  int     `json:"critical_violations"`
	OpenViolations      int     `json:"open_violations"`
	ResolvedViolations  int     `json:"resolved_violations"`
	DataSubjectRequests int     `json:"data_subject_requests"`
	AverageRiskScore    float64 `json:"average_risk_score"`
	HighRiskEvents      int     `json:"high_risk_events"`
}

// GDPRMetrics provides GDPR-specific compliance metrics
type GDPRMetrics struct {
	DataSubjectRequests  DSRBreakdown   `json:"data_subject_requests"`
	ConsentMetrics       ConsentMetrics `json:"consent_metrics"`
	DataBreaches         int            `json:"data_breaches"`
	CrossBorderTransfers int            `json:"cross_border_transfers"`
	RetentionCompliance  float64        `json:"retention_compliance"` // Percentage
	LegalBasisTracking   map[string]int `json:"legal_basis_tracking"`
}

// DSRBreakdown provides breakdown of data subject requests
type DSRBreakdown struct {
	Total               int            `json:"total"`
	ByType              map[string]int `json:"by_type"`
	ByStatus            map[string]int `json:"by_status"`
	AverageResponseTime string         `json:"average_response_time"`
	OverduRequests      int            `json:"overdue_requests"`
}

// ConsentMetrics provides consent tracking metrics
type ConsentMetrics struct {
	ActiveConsents    int            `json:"active_consents"`
	WithdrawnConsents int            `json:"withdrawn_consents"`
	ExpiredConsents   int            `json:"expired_consents"`
	ConsentByType     map[string]int `json:"consent_by_type"`
	ConsentRate       float64        `json:"consent_rate"` // Percentage
}

// HIPAAMetrics provides HIPAA-specific compliance metrics
type HIPAAMetrics struct {
	PHIAccessEvents            int     `json:"phi_access_events"`
	UnauthorizedAccess         int     `json:"unauthorized_access"`
	AuditLogCompleteness       float64 `json:"audit_log_completeness"` // Percentage
	MinimumNecessaryCompliance float64 `json:"minimum_necessary_compliance"`
	BreachIncidents            int     `json:"breach_incidents"`
	SecurityIncidents          int     `json:"security_incidents"`
}

// SOXMetrics provides SOX-specific compliance metrics
type SOXMetrics struct {
	FinancialOperations   int     `json:"financial_operations"`
	SegregationViolations int     `json:"segregation_violations"`
	ChangeManagement      int     `json:"change_management_events"`
	UnapprovedChanges     int     `json:"unapproved_changes"`
	AccessReviews         int     `json:"access_reviews"`
	CompliancePercentage  float64 `json:"compliance_percentage"`
}

// SecurityMetrics provides general security metrics
type SecurityMetrics struct {
	FailedLogins         int    `json:"failed_logins"`
	SuspiciousActivities int    `json:"suspicious_activities"`
	PrivilegeEscalations int    `json:"privilege_escalations"`
	AfterHoursAccess     int    `json:"after_hours_access"`
	SecurityIncidents    int    `json:"security_incidents"`
	ThreatLevel          string `json:"threat_level"` // LOW, MEDIUM, HIGH, CRITICAL
}

// RiskMetrics provides risk assessment metrics
type RiskMetrics struct {
	AverageRiskScore   float64          `json:"average_risk_score"`
	RiskDistribution   map[string]int   `json:"risk_distribution"` // MINIMAL, LOW, MEDIUM, HIGH, CRITICAL
	HighRiskOperations int              `json:"high_risk_operations"`
	RiskTrends         []RiskTrendPoint `json:"risk_trends"`
	TopRiskCategories  []RiskCategory   `json:"top_risk_categories"`
}

// RiskTrendPoint represents a point in risk trend analysis
type RiskTrendPoint struct {
	Date      time.Time `json:"date"`
	RiskScore float64   `json:"risk_score"`
	Events    int       `json:"events"`
}

// RiskCategory represents a risk category with metrics
type RiskCategory struct {
	Category    string  `json:"category"`
	Events      int     `json:"events"`
	AverageRisk float64 `json:"average_risk"`
	Trend       string  `json:"trend"` // INCREASING, STABLE, DECREASING
}

// ViolationMetrics provides violation tracking metrics
type ViolationMetrics struct {
	TotalViolations       int             `json:"total_violations"`
	ByFramework           map[string]int  `json:"by_framework"`
	BySeverity            map[string]int  `json:"by_severity"`
	ByStatus              map[string]int  `json:"by_status"`
	AverageResolutionTime string          `json:"average_resolution_time"`
	RecurringViolations   int             `json:"recurring_violations"`
	TopViolationTypes     []ViolationType `json:"top_violation_types"`
}

// ViolationType represents violation type metrics
type ViolationType struct {
	Type      string  `json:"type"`
	Count     int     `json:"count"`
	Severity  float64 `json:"average_severity"`
	Framework string  `json:"framework"`
}

// DSRMetrics provides data subject request metrics
type DSRMetrics struct {
	TotalRequests         int            `json:"total_requests"`
	CompletedRequests     int            `json:"completed_requests"`
	PendingRequests       int            `json:"pending_requests"`
	OverdueRequests       int            `json:"overdue_requests"`
	AverageProcessingTime string         `json:"average_processing_time"`
	RequestsByType        map[string]int `json:"requests_by_type"`
	ComplianceRate        float64        `json:"compliance_rate"` // Percentage meeting SLA
}

// TrendAnalysis provides trend analysis
type TrendAnalysis struct {
	AuditVolumetrend  string            `json:"audit_volume_trend"` // INCREASING, STABLE, DECREASING
	RiskTrend         string            `json:"risk_trend"`
	ViolationTrend    string            `json:"violation_trend"`
	ComplianceTrend   string            `json:"compliance_trend"`
	MonthlyComparison MonthlyComparison `json:"monthly_comparison"`
}

// MonthlyComparison provides month-over-month comparison
type MonthlyComparison struct {
	AuditEventsChange float64 `json:"audit_events_change"` // Percentage change
	ViolationsChange  float64 `json:"violations_change"`
	RiskScoreChange   float64 `json:"risk_score_change"`
	DSRChange         float64 `json:"dsr_change"`
}

// NewReportingService creates a new reporting service
func NewReportingService(db *gorm.DB, obs *observability.Observability) *ReportingService {
	return &ReportingService{db: db, obs: obs}
}

// GenerateComplianceDashboard generates a comprehensive compliance dashboard
func (rs *ReportingService) GenerateComplianceDashboard(ctx context.Context, period Period) (*ComplianceDashboard, error) {
	dashboard := &ComplianceDashboard{
		GeneratedAt: time.Now(),
		Period:      period,
	}

	// Generate summary metrics
	summary, err := rs.generateSummaryMetrics(ctx, period)
	if err != nil {
		return nil, fmt.Errorf("failed to generate summary metrics: %w", err)
	}
	dashboard.Summary = summary

	// Generate GDPR metrics
	gdprMetrics, err := rs.generateGDPRMetrics(ctx, period)
	if err != nil {
		return nil, fmt.Errorf("failed to generate GDPR metrics: %w", err)
	}
	dashboard.GDPR = gdprMetrics

	// Generate risk metrics
	riskMetrics, err := rs.generateRiskMetrics(ctx, period)
	if err != nil {
		return nil, fmt.Errorf("failed to generate risk metrics: %w", err)
	}
	dashboard.RiskAssessment = riskMetrics

	// Generate violation metrics
	violationMetrics, err := rs.generateViolationMetrics(ctx, period)
	if err != nil {
		return nil, fmt.Errorf("failed to generate violation metrics: %w", err)
	}
	dashboard.Violations = violationMetrics

	// Generate DSR metrics
	dsrMetrics, err := rs.generateDSRMetrics(ctx, period)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DSR metrics: %w", err)
	}
	dashboard.DataSubjectRequests = dsrMetrics

	// Generate trends
	trends, err := rs.generateTrendAnalysis(ctx, period)
	if err != nil {
		return nil, fmt.Errorf("failed to generate trend analysis: %w", err)
	}
	dashboard.Trends = trends

	// Generate recommendations
	dashboard.Recommendations = rs.generateRecommendations(dashboard)

	rs.obs.Logger.Info().
		Str("period_type", period.Type).
		Time("period_start", period.StartDate).
		Time("period_end", period.EndDate).
		Msg("Generated compliance dashboard")

	return dashboard, nil
}

// generateSummaryMetrics generates high-level summary metrics
func (rs *ReportingService) generateSummaryMetrics(ctx context.Context, period Period) (ComplianceSummary, error) {
	var summary ComplianceSummary

	// Count total audit events
	rs.db.WithContext(ctx).
		Model(&models.ComplianceAuditLog{}).
		Where("created_at BETWEEN ? AND ?", period.StartDate, period.EndDate).
		Count(&summary.TotalAuditEvents)

	// Count violations by status
	var criticalViolations, openViolations, resolvedViolations int64
	rs.db.WithContext(ctx).
		Model(&models.ComplianceViolation{}).
		Where("created_at BETWEEN ? AND ? AND severity >= 4", period.StartDate, period.EndDate).
		Count(&criticalViolations)
	summary.CriticalViolations = int(criticalViolations)

	rs.db.WithContext(ctx).
		Model(&models.ComplianceViolation{}).
		Where("created_at BETWEEN ? AND ? AND status = 'OPEN'", period.StartDate, period.EndDate).
		Count(&openViolations)
	summary.OpenViolations = int(openViolations)

	rs.db.WithContext(ctx).
		Model(&models.ComplianceViolation{}).
		Where("created_at BETWEEN ? AND ? AND status = 'RESOLVED'", period.StartDate, period.EndDate).
		Count(&resolvedViolations)
	summary.ResolvedViolations = int(resolvedViolations)

	// Count data subject requests
	var dsrCount int64
	rs.db.WithContext(ctx).
		Model(&models.DataSubjectRequest{}).
		Where("created_at BETWEEN ? AND ?", period.StartDate, period.EndDate).
		Count(&dsrCount)
	summary.DataSubjectRequests = int(dsrCount)

	// Calculate average risk score
	var avgRisk sql.NullFloat64
	rs.db.WithContext(ctx).
		Model(&models.ComplianceAuditLog{}).
		Where("created_at BETWEEN ? AND ?", period.StartDate, period.EndDate).
		Select("AVG(risk_score)").
		Scan(&avgRisk)
	if avgRisk.Valid {
		summary.AverageRiskScore = avgRisk.Float64
	}

	// Count high-risk events
	var highRiskEvents int64
	rs.db.WithContext(ctx).
		Model(&models.ComplianceAuditLog{}).
		Where("created_at BETWEEN ? AND ? AND risk_score >= 70", period.StartDate, period.EndDate).
		Count(&highRiskEvents)
	summary.HighRiskEvents = int(highRiskEvents)

	// Calculate compliance score (simplified formula)
	totalEvents := summary.TotalAuditEvents
	violationEvents := int64(summary.OpenViolations + summary.CriticalViolations)
	if totalEvents > 0 {
		summary.ComplianceScore = float64(totalEvents-violationEvents) / float64(totalEvents) * 100
	} else {
		summary.ComplianceScore = 100
	}

	return summary, nil
}

// generateGDPRMetrics generates GDPR-specific metrics
func (rs *ReportingService) generateGDPRMetrics(ctx context.Context, period Period) (GDPRMetrics, error) {
	var metrics GDPRMetrics

	// Data subject requests breakdown
	var totalDSR int64
	rs.db.WithContext(ctx).
		Model(&models.DataSubjectRequest{}).
		Where("created_at BETWEEN ? AND ?", period.StartDate, period.EndDate).
		Count(&totalDSR)

	dsrBreakdown := DSRBreakdown{
		Total:    int(totalDSR),
		ByType:   make(map[string]int),
		ByStatus: make(map[string]int),
	}

	// DSR by type
	var dsrByType []struct {
		RequestType string
		Count       int64
	}
	rs.db.WithContext(ctx).
		Model(&models.DataSubjectRequest{}).
		Where("created_at BETWEEN ? AND ?", period.StartDate, period.EndDate).
		Select("request_type, COUNT(*) as count").
		Group("request_type").
		Scan(&dsrByType)

	for _, item := range dsrByType {
		dsrBreakdown.ByType[item.RequestType] = int(item.Count)
	}

	// DSR by status
	var dsrByStatus []struct {
		Status string
		Count  int64
	}
	rs.db.WithContext(ctx).
		Model(&models.DataSubjectRequest{}).
		Where("created_at BETWEEN ? AND ?", period.StartDate, period.EndDate).
		Select("status, COUNT(*) as count").
		Group("status").
		Scan(&dsrByStatus)

	for _, item := range dsrByStatus {
		dsrBreakdown.ByStatus[item.Status] = int(item.Count)
	}

	// Overdue requests
	var overdueCount int64
	rs.db.WithContext(ctx).
		Model(&models.DataSubjectRequest{}).
		Where("due_date < ? AND status NOT IN ('COMPLETED', 'REJECTED')", time.Now()).
		Count(&overdueCount)
	dsrBreakdown.OverduRequests = int(overdueCount)

	metrics.DataSubjectRequests = dsrBreakdown

	// Consent metrics
	var activeConsents, withdrawnConsents int64
	rs.db.WithContext(ctx).
		Model(&models.ConsentRecord{}).
		Where("status = 'GIVEN' AND (expiry_date IS NULL OR expiry_date > ?)", time.Now()).
		Count(&activeConsents)

	rs.db.WithContext(ctx).
		Model(&models.ConsentRecord{}).
		Where("status = 'WITHDRAWN'").
		Count(&withdrawnConsents)

	metrics.ConsentMetrics = ConsentMetrics{
		ActiveConsents:    int(activeConsents),
		WithdrawnConsents: int(withdrawnConsents),
		ConsentByType:     make(map[string]int),
		ConsentRate:       float64(activeConsents) / float64(activeConsents+withdrawnConsents) * 100,
	}

	// Legal basis tracking
	metrics.LegalBasisTracking = make(map[string]int)
	var legalBasisCounts []struct {
		LegalBasis string
		Count      int64
	}
	rs.db.WithContext(ctx).
		Model(&models.ComplianceAuditLog{}).
		Where("created_at BETWEEN ? AND ? AND legal_basis != ''", period.StartDate, period.EndDate).
		Select("legal_basis, COUNT(*) as count").
		Group("legal_basis").
		Scan(&legalBasisCounts)

	for _, item := range legalBasisCounts {
		metrics.LegalBasisTracking[item.LegalBasis] = int(item.Count)
	}

	return metrics, nil
}

// generateRiskMetrics generates risk assessment metrics
func (rs *ReportingService) generateRiskMetrics(ctx context.Context, period Period) (RiskMetrics, error) {
	var metrics RiskMetrics

	// Average risk score
	var avgRisk sql.NullFloat64
	rs.db.WithContext(ctx).
		Model(&models.ComplianceAuditLog{}).
		Where("created_at BETWEEN ? AND ?", period.StartDate, period.EndDate).
		Select("AVG(risk_score)").
		Scan(&avgRisk)
	if avgRisk.Valid {
		metrics.AverageRiskScore = avgRisk.Float64
	}

	// Risk distribution
	metrics.RiskDistribution = make(map[string]int)
	var riskDist []struct {
		RiskLevel string
		Count     int64
	}

	rs.db.WithContext(ctx).Raw(`
		SELECT 
			CASE 
				WHEN risk_score >= 80 THEN 'CRITICAL'
				WHEN risk_score >= 60 THEN 'HIGH'
				WHEN risk_score >= 40 THEN 'MEDIUM'
				WHEN risk_score >= 20 THEN 'LOW'
				ELSE 'MINIMAL'
			END as risk_level,
			COUNT(*) as count
		FROM compliance_audit_logs 
		WHERE created_at BETWEEN ? AND ?
		GROUP BY risk_level
	`, period.StartDate, period.EndDate).Scan(&riskDist)

	for _, item := range riskDist {
		metrics.RiskDistribution[item.RiskLevel] = int(item.Count)
	}

	// High-risk operations
	var highRiskOps int64
	rs.db.WithContext(ctx).
		Model(&models.ComplianceAuditLog{}).
		Where("created_at BETWEEN ? AND ? AND risk_score >= 70", period.StartDate, period.EndDate).
		Count(&highRiskOps)
	metrics.HighRiskOperations = int(highRiskOps)

	return metrics, nil
}

// generateViolationMetrics generates violation tracking metrics
func (rs *ReportingService) generateViolationMetrics(ctx context.Context, period Period) (ViolationMetrics, error) {
	var metrics ViolationMetrics

	// Total violations
	var totalViolations int64
	rs.db.WithContext(ctx).
		Model(&models.ComplianceViolation{}).
		Where("created_at BETWEEN ? AND ?", period.StartDate, period.EndDate).
		Count(&totalViolations)
	metrics.TotalViolations = int(totalViolations)

	// By framework
	metrics.ByFramework = make(map[string]int)
	var frameworkCounts []struct {
		Framework string
		Count     int64
	}
	rs.db.WithContext(ctx).
		Model(&models.ComplianceViolation{}).
		Where("created_at BETWEEN ? AND ?", period.StartDate, period.EndDate).
		Select("framework, COUNT(*) as count").
		Group("framework").
		Scan(&frameworkCounts)

	for _, item := range frameworkCounts {
		metrics.ByFramework[item.Framework] = int(item.Count)
	}

	// By severity
	metrics.BySeverity = make(map[string]int)
	var severityCounts []struct {
		Severity string
		Count    int64
	}
	rs.db.WithContext(ctx).Raw(`
		SELECT 
			CASE 
				WHEN severity = 5 THEN 'CRITICAL'
				WHEN severity = 4 THEN 'HIGH'
				WHEN severity = 3 THEN 'MEDIUM'
				WHEN severity = 2 THEN 'LOW'
				ELSE 'MINIMAL'
			END as severity,
			COUNT(*) as count
		FROM compliance_violations 
		WHERE created_at BETWEEN ? AND ?
		GROUP BY severity
	`, period.StartDate, period.EndDate).Scan(&severityCounts)

	for _, item := range severityCounts {
		metrics.BySeverity[item.Severity] = int(item.Count)
	}

	// By status
	metrics.ByStatus = make(map[string]int)
	var statusCounts []struct {
		Status string
		Count  int64
	}
	rs.db.WithContext(ctx).
		Model(&models.ComplianceViolation{}).
		Where("created_at BETWEEN ? AND ?", period.StartDate, period.EndDate).
		Select("status, COUNT(*) as count").
		Group("status").
		Scan(&statusCounts)

	for _, item := range statusCounts {
		metrics.ByStatus[item.Status] = int(item.Count)
	}

	return metrics, nil
}

// generateDSRMetrics generates data subject request metrics
func (rs *ReportingService) generateDSRMetrics(ctx context.Context, period Period) (DSRMetrics, error) {
	var metrics DSRMetrics

	// Total requests
	var totalRequests int64
	rs.db.WithContext(ctx).
		Model(&models.DataSubjectRequest{}).
		Where("created_at BETWEEN ? AND ?", period.StartDate, period.EndDate).
		Count(&totalRequests)
	metrics.TotalRequests = int(totalRequests)

	// Completed requests
	var completedRequests int64
	rs.db.WithContext(ctx).
		Model(&models.DataSubjectRequest{}).
		Where("created_at BETWEEN ? AND ? AND status = 'COMPLETED'", period.StartDate, period.EndDate).
		Count(&completedRequests)
	metrics.CompletedRequests = int(completedRequests)

	// Pending requests
	var pendingRequests int64
	rs.db.WithContext(ctx).
		Model(&models.DataSubjectRequest{}).
		Where("status IN ('RECEIVED', 'VERIFIED', 'PROCESSING')").
		Count(&pendingRequests)
	metrics.PendingRequests = int(pendingRequests)

	// Overdue requests
	var overdueRequests int64
	rs.db.WithContext(ctx).
		Model(&models.DataSubjectRequest{}).
		Where("due_date < ? AND status NOT IN ('COMPLETED', 'REJECTED')", time.Now()).
		Count(&overdueRequests)
	metrics.OverdueRequests = int(overdueRequests)

	// Compliance rate
	if totalRequests > 0 {
		metrics.ComplianceRate = float64(completedRequests) / float64(totalRequests) * 100
	}

	return metrics, nil
}

// generateTrendAnalysis generates trend analysis
func (rs *ReportingService) generateTrendAnalysis(ctx context.Context, period Period) (TrendAnalysis, error) {
	var trends TrendAnalysis

	// Calculate previous period for comparison
	duration := period.EndDate.Sub(period.StartDate)
	prevPeriodStart := period.StartDate.Add(-duration)
	prevPeriodEnd := period.StartDate

	// Audit volume trend
	var currentVolume, prevVolume int64
	rs.db.WithContext(ctx).
		Model(&models.ComplianceAuditLog{}).
		Where("created_at BETWEEN ? AND ?", period.StartDate, period.EndDate).
		Count(&currentVolume)

	rs.db.WithContext(ctx).
		Model(&models.ComplianceAuditLog{}).
		Where("created_at BETWEEN ? AND ?", prevPeriodStart, prevPeriodEnd).
		Count(&prevVolume)

	trends.AuditVolumetrend = calculateTrend(currentVolume, prevVolume)

	// Monthly comparison
	if prevVolume > 0 {
		trends.MonthlyComparison.AuditEventsChange = float64(currentVolume-prevVolume) / float64(prevVolume) * 100
	}

	// Risk trend (simplified)
	var currentAvgRisk, prevAvgRisk sql.NullFloat64
	rs.db.WithContext(ctx).
		Model(&models.ComplianceAuditLog{}).
		Where("created_at BETWEEN ? AND ?", period.StartDate, period.EndDate).
		Select("AVG(risk_score)").
		Scan(&currentAvgRisk)

	rs.db.WithContext(ctx).
		Model(&models.ComplianceAuditLog{}).
		Where("created_at BETWEEN ? AND ?", prevPeriodStart, prevPeriodEnd).
		Select("AVG(risk_score)").
		Scan(&prevAvgRisk)

	if currentAvgRisk.Valid && prevAvgRisk.Valid {
		if currentAvgRisk.Float64 > prevAvgRisk.Float64*1.1 {
			trends.RiskTrend = "INCREASING"
		} else if currentAvgRisk.Float64 < prevAvgRisk.Float64*0.9 {
			trends.RiskTrend = "DECREASING"
		} else {
			trends.RiskTrend = "STABLE"
		}

		trends.MonthlyComparison.RiskScoreChange = (currentAvgRisk.Float64 - prevAvgRisk.Float64) / prevAvgRisk.Float64 * 100
	}

	return trends, nil
}

// generateRecommendations generates actionable recommendations
func (rs *ReportingService) generateRecommendations(dashboard *ComplianceDashboard) []string {
	var recommendations []string

	// High-level compliance score recommendations
	if dashboard.Summary.ComplianceScore < 80 {
		recommendations = append(recommendations, "Compliance score below 80% - implement immediate remediation plan")
	}

	// Critical violations
	if dashboard.Summary.CriticalViolations > 0 {
		recommendations = append(recommendations, fmt.Sprintf("Address %d critical violations immediately", dashboard.Summary.CriticalViolations))
	}

	// High-risk events
	if dashboard.Summary.HighRiskEvents > 100 {
		recommendations = append(recommendations, "High volume of high-risk events detected - review security controls")
	}

	// GDPR recommendations
	if dashboard.GDPR.DataSubjectRequests.OverduRequests > 0 {
		recommendations = append(recommendations, fmt.Sprintf("Process %d overdue data subject requests to maintain GDPR compliance", dashboard.GDPR.DataSubjectRequests.OverduRequests))
	}

	// Risk recommendations
	if dashboard.RiskAssessment.AverageRiskScore > 60 {
		recommendations = append(recommendations, "Average risk score is high - review and enhance security controls")
	}

	// Trend-based recommendations
	if dashboard.Trends.RiskTrend == "INCREASING" {
		recommendations = append(recommendations, "Risk trend is increasing - investigate root causes and implement mitigation")
	}

	if dashboard.Trends.ViolationTrend == "INCREASING" {
		recommendations = append(recommendations, "Violation trend is increasing - strengthen compliance training and controls")
	}

	// Default recommendations if none generated
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Continue monitoring compliance metrics and maintain current controls")
		recommendations = append(recommendations, "Implement regular compliance reviews and audits")
	}

	return recommendations
}

// Helper functions

func calculateTrend(current, previous int64) string {
	if previous == 0 {
		if current > 0 {
			return "INCREASING"
		}
		return "STABLE"
	}

	change := float64(current-previous) / float64(previous)
	if change > 0.1 {
		return "INCREASING"
	} else if change < -0.1 {
		return "DECREASING"
	}
	return "STABLE"
}
