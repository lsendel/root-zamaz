// Package audit provides risk assessment functionality for compliance audit logging
package audit

import (
	"strings"
	"time"
)

// RiskCalculator calculates risk scores for audit events
type RiskCalculator struct {
	// Risk factor weights
	sensitivityWeight  float64
	actionRiskWeight   float64
	timeRiskWeight     float64
	locationRiskWeight float64
	userBehaviorWeight float64
	dataVolumeWeight   float64
}

// NewRiskCalculator creates a new risk calculator with default weights
func NewRiskCalculator() *RiskCalculator {
	return &RiskCalculator{
		sensitivityWeight:  0.25,
		actionRiskWeight:   0.20,
		timeRiskWeight:     0.15,
		locationRiskWeight: 0.15,
		userBehaviorWeight: 0.15,
		dataVolumeWeight:   0.10,
	}
}

// CalculateRisk calculates a risk score (0-100) for a compliance log entry
func (rc *RiskCalculator) CalculateRisk(entry ComplianceLogEntry) int {
	score := 0.0

	// Base sensitivity score (0-100)
	sensitivityScore := rc.calculateSensitivityScore(entry)
	score += sensitivityScore * rc.sensitivityWeight

	// Action risk score (0-100)
	actionScore := rc.calculateActionRisk(entry.Action)
	score += actionScore * rc.actionRiskWeight

	// Time-based risk (0-100)
	timeScore := rc.calculateTimeRisk()
	score += timeScore * rc.timeRiskWeight

	// Location risk (0-100)
	locationScore := rc.calculateLocationRisk(entry.GeolocationCountry)
	score += locationScore * rc.locationRiskWeight

	// User behavior risk (0-100)
	behaviorScore := rc.calculateUserBehaviorRisk(entry)
	score += behaviorScore * rc.userBehaviorWeight

	// Data volume risk (0-100)
	volumeScore := rc.calculateDataVolumeRisk(entry)
	score += volumeScore * rc.dataVolumeWeight

	// Ensure score is within bounds
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return int(score)
}

// calculateSensitivityScore calculates risk based on data sensitivity
func (rc *RiskCalculator) calculateSensitivityScore(entry ComplianceLogEntry) float64 {
	baseScore := float64(entry.SensitivityLevel) * 20 // 1-5 scale -> 20-100

	// Adjust based on data classification
	switch entry.DataClassification {
	case ClassificationRestricted, ClassificationPHI:
		baseScore += 20
	case ClassificationPII:
		baseScore += 15
	case ClassificationConfidential:
		baseScore += 10
	case ClassificationInternal:
		baseScore += 5
	}

	// Adjust based on compliance frameworks
	for _, framework := range entry.ComplianceFrameworks {
		switch framework {
		case FrameworkHIPAA:
			baseScore += 15
		case FrameworkGDPR:
			baseScore += 10
		case FrameworkPCIDSS:
			baseScore += 10
		case FrameworkSOX:
			baseScore += 8
		}
	}

	if baseScore > 100 {
		baseScore = 100
	}

	return baseScore
}

// calculateActionRisk calculates risk based on the action being performed
func (rc *RiskCalculator) calculateActionRisk(action string) float64 {
	action = strings.ToLower(action)

	// High-risk actions
	highRiskActions := map[string]float64{
		"delete":               100,
		"purge":                100,
		"admin_access":         90,
		"role_change":          90,
		"permission_grant":     85,
		"data_export":          80,
		"bulk_download":        80,
		"privilege_escalation": 95,
		"password_reset":       70,
		"account_unlock":       65,
	}

	// Medium-risk actions
	mediumRiskActions := map[string]float64{
		"update":      50,
		"modify":      50,
		"create":      40,
		"login":       30,
		"data_access": 45,
		"view":        25,
		"search":      35,
		"download":    55,
	}

	// Low-risk actions
	lowRiskActions := map[string]float64{
		"read":         15,
		"list":         10,
		"ping":         5,
		"health_check": 5,
		"metrics":      5,
	}

	// Check each category
	for actionPattern, score := range highRiskActions {
		if strings.Contains(action, actionPattern) {
			return score
		}
	}

	for actionPattern, score := range mediumRiskActions {
		if strings.Contains(action, actionPattern) {
			return score
		}
	}

	for actionPattern, score := range lowRiskActions {
		if strings.Contains(action, actionPattern) {
			return score
		}
	}

	// Default risk for unknown actions
	return 30
}

// calculateTimeRisk calculates risk based on time of access
func (rc *RiskCalculator) calculateTimeRisk() float64 {
	now := time.Now()
	hour := now.Hour()

	// Business hours (8 AM - 6 PM) = lower risk
	if hour >= 8 && hour <= 18 {
		return 10
	}

	// Evening hours (6 PM - 10 PM) = medium risk
	if hour >= 18 && hour <= 22 {
		return 40
	}

	// Night/early morning hours = higher risk
	return 70
}

// calculateLocationRisk calculates risk based on geographic location
func (rc *RiskCalculator) calculateLocationRisk(country string) float64 {
	if country == "" {
		return 30 // Unknown location = medium risk
	}

	// Low-risk countries (example - would be configurable)
	lowRiskCountries := map[string]bool{
		"US": true, "CA": true, "GB": true, "DE": true, "FR": true,
		"AU": true, "NL": true, "SE": true, "CH": true, "JP": true,
	}

	// High-risk countries (example - would be configurable)
	highRiskCountries := map[string]bool{
		"CN": true, "RU": true, "IR": true, "KP": true,
	}

	country = strings.ToUpper(country)

	if highRiskCountries[country] {
		return 90
	}

	if lowRiskCountries[country] {
		return 10
	}

	// Medium risk for other countries
	return 50
}

// calculateUserBehaviorRisk calculates risk based on user behavior patterns
func (rc *RiskCalculator) calculateUserBehaviorRisk(entry ComplianceLogEntry) float64 {
	score := 0.0

	// Check for failure patterns
	if !entry.Success {
		score += 40
	}

	// Check for bulk operations
	if strings.Contains(strings.ToLower(entry.Action), "bulk") {
		score += 30
	}

	// Check for automation indicators
	userAgent := strings.ToLower(entry.UserAgent)
	if strings.Contains(userAgent, "bot") || strings.Contains(userAgent, "curl") || strings.Contains(userAgent, "wget") {
		score += 25
	}

	// Check for suspicious patterns in details
	if entry.Details != nil {
		if recordCount, exists := entry.Details["record_count"]; exists {
			if count, ok := recordCount.(float64); ok && count > 1000 {
				score += 20
			}
		}
	}

	if score > 100 {
		score = 100
	}

	return score
}

// calculateDataVolumeRisk calculates risk based on data volume accessed
func (rc *RiskCalculator) calculateDataVolumeRisk(entry ComplianceLogEntry) float64 {
	if entry.Details == nil {
		return 10 // Default low risk for unknown volume
	}

	score := 10.0

	// Check for volume indicators
	if recordCount, exists := entry.Details["record_count"]; exists {
		if count, ok := recordCount.(float64); ok {
			switch {
			case count > 10000:
				score = 90
			case count > 1000:
				score = 70
			case count > 100:
				score = 50
			case count > 10:
				score = 30
			}
		}
	}

	if dataSize, exists := entry.Details["data_size_bytes"]; exists {
		if size, ok := dataSize.(float64); ok {
			switch {
			case size > 1000000000: // 1GB
				score = 95
			case size > 100000000: // 100MB
				score = 75
			case size > 10000000: // 10MB
				score = 55
			case size > 1000000: // 1MB
				score = 35
			}
		}
	}

	return score
}

// GetRiskLevel returns a human-readable risk level
func (rc *RiskCalculator) GetRiskLevel(score int) string {
	switch {
	case score >= 80:
		return "CRITICAL"
	case score >= 60:
		return "HIGH"
	case score >= 40:
		return "MEDIUM"
	case score >= 20:
		return "LOW"
	default:
		return "MINIMAL"
	}
}

// GetRiskRecommendations returns recommended actions based on risk score
func (rc *RiskCalculator) GetRiskRecommendations(score int, entry ComplianceLogEntry) []string {
	var recommendations []string

	if score >= 80 {
		recommendations = append(recommendations, "Immediate security review required")
		recommendations = append(recommendations, "Consider blocking similar requests")
		recommendations = append(recommendations, "Notify security team")
	}

	if score >= 60 {
		recommendations = append(recommendations, "Enhanced monitoring recommended")
		recommendations = append(recommendations, "Require additional authentication")
	}

	if score >= 40 {
		recommendations = append(recommendations, "Monitor for patterns")
		recommendations = append(recommendations, "Log additional context")
	}

	// Specific recommendations based on entry characteristics
	if entry.DataClassification == ClassificationPHI || entry.DataClassification == ClassificationPII {
		recommendations = append(recommendations, "Ensure data minimization principles")
		recommendations = append(recommendations, "Verify consent or legal basis")
	}

	for _, framework := range entry.ComplianceFrameworks {
		switch framework {
		case FrameworkGDPR:
			recommendations = append(recommendations, "Document legal basis for processing")
		case FrameworkHIPAA:
			recommendations = append(recommendations, "Ensure minimum necessary standard")
		case FrameworkSOX:
			recommendations = append(recommendations, "Verify segregation of duties")
		}
	}

	return recommendations
}
