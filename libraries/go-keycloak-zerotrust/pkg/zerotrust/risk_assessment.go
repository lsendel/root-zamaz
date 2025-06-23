// Package zerotrust provides risk assessment capabilities for Zero Trust authentication
package zerotrust

import (
	"context"
	"log"
	"math"
	"time"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// RiskAssessmentEngine provides comprehensive risk scoring and analysis
type RiskAssessmentEngine struct {
	config          *types.ZeroTrustConfig
	userBehavior    UserBehaviorAnalyzer
	geoLocation     GeolocationService
	threatIntel     ThreatIntelligenceService
	deviceAnalyzer  *DeviceAttestationService
	riskRules       []RiskRule
	baselineStorage BaselineStorage
}

// UserBehaviorAnalyzer analyzes user behavior patterns
type UserBehaviorAnalyzer interface {
	AnalyzeBehavior(ctx context.Context, userID string, currentSession *SessionContext) (*BehaviorAnalysis, error)
	UpdateUserBaseline(ctx context.Context, userID string, session *SessionContext) error
	GetUserBaseline(ctx context.Context, userID string) (*UserBaseline, error)
}

// GeolocationService provides location-based risk assessment
type GeolocationService interface {
	GetLocationInfo(ctx context.Context, ipAddress string) (*types.LocationInfo, error)
	CalculateLocationRisk(ctx context.Context, userID string, location *types.LocationInfo) (*LocationRisk, error)
	IsHighRiskLocation(ctx context.Context, location *types.LocationInfo) (bool, []string)
}

// ThreatIntelligenceService provides threat intelligence data
type ThreatIntelligenceService interface {
	CheckIPReputation(ctx context.Context, ipAddress string) (*IPReputation, error)
	CheckUserAgentRisk(ctx context.Context, userAgent string) (*UserAgentRisk, error)
	GetActiveThreatCampaigns(ctx context.Context) ([]*ThreatCampaign, error)
}

// BaselineStorage stores user behavior baselines
type BaselineStorage interface {
	StoreBaseline(ctx context.Context, userID string, baseline *UserBaseline) error
	GetBaseline(ctx context.Context, userID string) (*UserBaseline, error)
	UpdateBaseline(ctx context.Context, userID string, baseline *UserBaseline) error
}

// SessionContext represents the current session context for risk assessment
type SessionContext struct {
	UserID           string                 `json:"user_id"`
	IPAddress        string                 `json:"ip_address"`
	UserAgent        string                 `json:"user_agent"`
	DeviceID         string                 `json:"device_id"`
	Location         *types.LocationInfo    `json:"location"`
	Timestamp        time.Time              `json:"timestamp"`
	RequestPath      string                 `json:"request_path"`
	RequestMethod    string                 `json:"request_method"`
	Headers          map[string]string      `json:"headers"`
	AuthMethod       string                 `json:"auth_method"`
	PreviousLogin    *time.Time             `json:"previous_login,omitempty"`
	SessionDuration  time.Duration          `json:"session_duration"`
	RequestCount     int                    `json:"request_count"`
	FailedAttempts   int                    `json:"failed_attempts"`
}

// RiskAssessmentResult represents the complete risk assessment
type RiskAssessmentResult struct {
	OverallRiskScore    int                     `json:"overall_risk_score"`
	RiskLevel          string                  `json:"risk_level"`
	RiskFactors        []RiskFactor            `json:"risk_factors"`
	BehaviorAnalysis   *BehaviorAnalysis       `json:"behavior_analysis"`
	LocationRisk       *LocationRisk           `json:"location_risk"`
	DeviceRisk         *DeviceRiskAssessment   `json:"device_risk"`
	ThreatIntelligence *ThreatIntelligence     `json:"threat_intelligence"`
	Recommendations    []string                `json:"recommendations"`
	RequiredActions    []string                `json:"required_actions"`
	Confidence         float64                 `json:"confidence"`
	AssessmentTime     time.Time               `json:"assessment_time"`
}

// RiskFactor represents an individual risk factor
type RiskFactor struct {
	Type        string      `json:"type"`
	Category    string      `json:"category"`
	Score       int         `json:"score"`
	Weight      float64     `json:"weight"`
	Description string      `json:"description"`
	Details     interface{} `json:"details,omitempty"`
	Severity    string      `json:"severity"`
}

// BehaviorAnalysis contains user behavior analysis results
type BehaviorAnalysis struct {
	IsAnomalous        bool                   `json:"is_anomalous"`
	AnomalyScore       float64                `json:"anomaly_score"`
	DeviationFactors   []string               `json:"deviation_factors"`
	TypicalBehavior    map[string]interface{} `json:"typical_behavior"`
	CurrentBehavior    map[string]interface{} `json:"current_behavior"`
	BehaviorConfidence float64                `json:"behavior_confidence"`
}

// UserBaseline represents typical user behavior patterns
type UserBaseline struct {
	UserID              string            `json:"user_id"`
	TypicalLocations    []types.LocationInfo `json:"typical_locations"`
	TypicalDevices      []string          `json:"typical_devices"`
	TypicalLoginTimes   []TimePattern     `json:"typical_login_times"`
	TypicalIPRanges     []string          `json:"typical_ip_ranges"`
	TypicalUserAgents   []string          `json:"typical_user_agents"`
	AverageSessionLength time.Duration    `json:"average_session_length"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
	SampleSize          int               `json:"sample_size"`
}

// TimePattern represents typical timing patterns
type TimePattern struct {
	DayOfWeek int           `json:"day_of_week"`
	StartHour int           `json:"start_hour"`
	EndHour   int           `json:"end_hour"`
	Frequency float64       `json:"frequency"`
}

// LocationRisk contains location-based risk assessment
type LocationRisk struct {
	RiskScore           int      `json:"risk_score"`
	IsHighRisk          bool     `json:"is_high_risk"`
	IsNewLocation       bool     `json:"is_new_location"`
	DistanceFromTypical float64  `json:"distance_from_typical_km"`
	RiskReasons         []string `json:"risk_reasons"`
	CountryRisk         string   `json:"country_risk"`
	VPNDetected         bool     `json:"vpn_detected"`
	TorDetected         bool     `json:"tor_detected"`
}

// DeviceRiskAssessment contains device-specific risk factors
type DeviceRiskAssessment struct {
	IsNewDevice        bool     `json:"is_new_device"`
	DeviceTrustScore   int      `json:"device_trust_score"`
	IsCompromised      bool     `json:"is_compromised"`
	RiskFactors        []string `json:"risk_factors"`
	LastVerification   time.Time `json:"last_verification"`
	VerificationStatus string   `json:"verification_status"`
}

// ThreatIntelligence contains threat intelligence data
type ThreatIntelligence struct {
	IPReputation    *IPReputation    `json:"ip_reputation"`
	UserAgentRisk   *UserAgentRisk   `json:"user_agent_risk"`
	ActiveThreats   []*ThreatCampaign `json:"active_threats"`
	ThreatScore     int              `json:"threat_score"`
}

// IPReputation contains IP reputation information
type IPReputation struct {
	IsBlacklisted    bool     `json:"is_blacklisted"`
	IsMalicious      bool     `json:"is_malicious"`
	ReputationScore  int      `json:"reputation_score"`
	Categories       []string `json:"categories"`
	Source           string   `json:"source"`
	LastSeen         time.Time `json:"last_seen"`
}

// UserAgentRisk contains user agent risk assessment
type UserAgentRisk struct {
	IsBot            bool     `json:"is_bot"`
	IsSuspicious     bool     `json:"is_suspicious"`
	RiskScore        int      `json:"risk_score"`
	Anomalies        []string `json:"anomalies"`
	BrowserFamily    string   `json:"browser_family"`
	OSFamily         string   `json:"os_family"`
}

// ThreatCampaign represents an active threat campaign
type ThreatCampaign struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Type            string    `json:"type"`
	Severity        string    `json:"severity"`
	Indicators      []string  `json:"indicators"`
	Description     string    `json:"description"`
	StartDate       time.Time `json:"start_date"`
	IsActive        bool      `json:"is_active"`
}

// RiskRule represents a configurable risk assessment rule
type RiskRule interface {
	Evaluate(ctx context.Context, session *SessionContext) (*RiskFactor, error)
	GetType() string
	GetWeight() float64
	IsEnabled() bool
}

// NewRiskAssessmentEngine creates a new risk assessment engine
func NewRiskAssessmentEngine(
	config *types.ZeroTrustConfig,
	userBehavior UserBehaviorAnalyzer,
	geoLocation GeolocationService,
	threatIntel ThreatIntelligenceService,
	deviceAnalyzer *DeviceAttestationService,
	baselineStorage BaselineStorage,
) *RiskAssessmentEngine {
	
	engine := &RiskAssessmentEngine{
		config:          config,
		userBehavior:    userBehavior,
		geoLocation:     geoLocation,
		threatIntel:     threatIntel,
		deviceAnalyzer:  deviceAnalyzer,
		baselineStorage: baselineStorage,
		riskRules:       make([]RiskRule, 0),
	}

	// Register default risk rules
	engine.RegisterRiskRule(&LocationRiskRule{})
	engine.RegisterRiskRule(&DeviceRiskRule{})
	engine.RegisterRiskRule(&BehaviorRiskRule{})
	engine.RegisterRiskRule(&ThreatIntelRiskRule{})
	engine.RegisterRiskRule(&TimeBasedRiskRule{})
	engine.RegisterRiskRule(&VelocityRiskRule{})

	return engine
}

// RegisterRiskRule registers a new risk assessment rule
func (e *RiskAssessmentEngine) RegisterRiskRule(rule RiskRule) {
	e.riskRules = append(e.riskRules, rule)
	log.Printf("Registered risk rule: %s", rule.GetType())
}

// AssessRisk performs comprehensive risk assessment
func (e *RiskAssessmentEngine) AssessRisk(ctx context.Context, session *SessionContext) (*RiskAssessmentResult, error) {
	startTime := time.Now()
	
	result := &RiskAssessmentResult{
		RiskFactors:     make([]RiskFactor, 0),
		Recommendations: make([]string, 0),
		RequiredActions: make([]string, 0),
		AssessmentTime:  startTime,
	}

	// Gather location information
	if session.Location == nil && session.IPAddress != "" {
		if location, err := e.geoLocation.GetLocationInfo(ctx, session.IPAddress); err == nil {
			session.Location = location
		}
	}

	// Perform behavior analysis
	if e.userBehavior != nil {
		behaviorAnalysis, err := e.userBehavior.AnalyzeBehavior(ctx, session.UserID, session)
		if err != nil {
			log.Printf("Behavior analysis failed: %v", err)
		} else {
			result.BehaviorAnalysis = behaviorAnalysis
		}
	}

	// Perform location risk assessment
	if e.geoLocation != nil && session.Location != nil {
		locationRisk, err := e.geoLocation.CalculateLocationRisk(ctx, session.UserID, session.Location)
		if err != nil {
			log.Printf("Location risk assessment failed: %v", err)
		} else {
			result.LocationRisk = locationRisk
		}
	}

	// Perform device risk assessment
	if e.deviceAnalyzer != nil && session.DeviceID != "" {
		deviceRisk := e.assessDeviceRisk(ctx, session)
		result.DeviceRisk = deviceRisk
	}

	// Gather threat intelligence
	if e.threatIntel != nil {
		threatIntel := e.gatherThreatIntelligence(ctx, session)
		result.ThreatIntelligence = threatIntel
	}

	// Apply risk rules
	totalScore := 0.0
	totalWeight := 0.0
	
	for _, rule := range e.riskRules {
		if !rule.IsEnabled() {
			continue
		}

		riskFactor, err := rule.Evaluate(ctx, session)
		if err != nil {
			log.Printf("Risk rule %s evaluation failed: %v", rule.GetType(), err)
			continue
		}

		if riskFactor != nil {
			result.RiskFactors = append(result.RiskFactors, *riskFactor)
			
			weight := rule.GetWeight()
			totalScore += float64(riskFactor.Score) * weight
			totalWeight += weight
		}
	}

	// Calculate overall risk score
	if totalWeight > 0 {
		result.OverallRiskScore = int(math.Round(totalScore / totalWeight))
	}

	// Determine risk level
	result.RiskLevel = e.determineRiskLevel(result.OverallRiskScore)

	// Generate recommendations and required actions
	e.generateRecommendations(result)

	// Calculate confidence score
	result.Confidence = e.calculateConfidence(result)

	log.Printf("Risk assessment completed for user %s: score=%d, level=%s, confidence=%.2f",
		session.UserID, result.OverallRiskScore, result.RiskLevel, result.Confidence)

	return result, nil
}

// Private helper methods

func (e *RiskAssessmentEngine) assessDeviceRisk(ctx context.Context, session *SessionContext) *DeviceRiskAssessment {
	device, err := e.deviceAnalyzer.VerifyDevice(ctx, session.DeviceID)
	if err != nil {
		return &DeviceRiskAssessment{
			IsNewDevice:        true,
			DeviceTrustScore:   0,
			IsCompromised:      false,
			RiskFactors:        []string{"device_not_found"},
			VerificationStatus: "unknown",
		}
	}

	riskFactors := make([]string, 0)
	if !device.IsVerified {
		riskFactors = append(riskFactors, "device_not_verified")
	}
	if time.Since(device.LastAttestation) > e.config.ZeroTrust.DeviceVerificationTTL {
		riskFactors = append(riskFactors, "verification_expired")
	}

	return &DeviceRiskAssessment{
		IsNewDevice:        time.Since(device.CreatedAt) < 24*time.Hour,
		DeviceTrustScore:   device.TrustLevel,
		IsCompromised:      device.TrustLevel < 25,
		RiskFactors:        riskFactors,
		LastVerification:   device.LastAttestation,
		VerificationStatus: map[bool]string{true: "verified", false: "unverified"}[device.IsVerified],
	}
}

func (e *RiskAssessmentEngine) gatherThreatIntelligence(ctx context.Context, session *SessionContext) *ThreatIntelligence {
	threatIntel := &ThreatIntelligence{
		ThreatScore: 0,
	}

	// Check IP reputation
	if session.IPAddress != "" {
		if ipRep, err := e.threatIntel.CheckIPReputation(ctx, session.IPAddress); err == nil {
			threatIntel.IPReputation = ipRep
			if ipRep.IsMalicious {
				threatIntel.ThreatScore += 50
			}
		}
	}

	// Check user agent risk
	if session.UserAgent != "" {
		if uaRisk, err := e.threatIntel.CheckUserAgentRisk(ctx, session.UserAgent); err == nil {
			threatIntel.UserAgentRisk = uaRisk
			if uaRisk.IsBot {
				threatIntel.ThreatScore += 30
			}
		}
	}

	// Get active threat campaigns
	if threats, err := e.threatIntel.GetActiveThreatCampaigns(ctx); err == nil {
		threatIntel.ActiveThreats = threats
	}

	return threatIntel
}

func (e *RiskAssessmentEngine) determineRiskLevel(score int) string {
	thresholds := e.config.ZeroTrust.RiskThresholds
	
	switch {
	case score >= thresholds.Critical:
		return "critical"
	case score >= thresholds.High:
		return "high"
	case score >= thresholds.Medium:
		return "medium"
	default:
		return "low"
	}
}

func (e *RiskAssessmentEngine) generateRecommendations(result *RiskAssessmentResult) {
	// Add recommendations based on risk factors
	for _, factor := range result.RiskFactors {
		switch factor.Type {
		case "new_location":
			result.Recommendations = append(result.Recommendations, "Verify login from new location")
		case "new_device":
			result.Recommendations = append(result.Recommendations, "Complete device verification")
		case "suspicious_behavior":
			result.Recommendations = append(result.Recommendations, "Additional authentication required")
		case "high_risk_ip":
			result.RequiredActions = append(result.RequiredActions, "Block access from high-risk IP")
		}
	}

	// Add level-based recommendations
	switch result.RiskLevel {
	case "critical":
		result.RequiredActions = append(result.RequiredActions, "Immediate manual review required")
	case "high":
		result.Recommendations = append(result.Recommendations, "Multi-factor authentication recommended")
	case "medium":
		result.Recommendations = append(result.Recommendations, "Increase monitoring")
	}
}

func (e *RiskAssessmentEngine) calculateConfidence(result *RiskAssessmentResult) float64 {
	// Simplified confidence calculation based on available data
	confidence := 0.5 // Base confidence
	
	if result.BehaviorAnalysis != nil {
		confidence += 0.2
	}
	if result.LocationRisk != nil {
		confidence += 0.1
	}
	if result.DeviceRisk != nil {
		confidence += 0.1
	}
	if result.ThreatIntelligence != nil {
		confidence += 0.1
	}
	
	return math.Min(confidence, 1.0)
}

// Example risk rule implementations

// LocationRiskRule evaluates location-based risk
type LocationRiskRule struct{}

func (r *LocationRiskRule) Evaluate(ctx context.Context, session *SessionContext) (*RiskFactor, error) {
	if session.Location == nil {
		return nil, nil
	}

	score := 0
	details := make(map[string]interface{})
	
	// Example: Check for high-risk countries
	highRiskCountries := []string{"CN", "RU", "IR", "KP"}
	for _, country := range highRiskCountries {
		if session.Location.Country == country {
			score += 40
			details["high_risk_country"] = true
			break
		}
	}

	return &RiskFactor{
		Type:        "location_risk",
		Category:    "geolocation",
		Score:       score,
		Weight:      1.0,
		Description: "Location-based risk assessment",
		Details:     details,
		Severity:    map[bool]string{true: "high", false: "low"}[score > 20],
	}, nil
}

func (r *LocationRiskRule) GetType() string   { return "location_risk" }
func (r *LocationRiskRule) GetWeight() float64 { return 1.0 }
func (r *LocationRiskRule) IsEnabled() bool   { return true }

// Placeholder implementations for other risk rules
type DeviceRiskRule struct{}
func (r *DeviceRiskRule) Evaluate(ctx context.Context, session *SessionContext) (*RiskFactor, error) {
	return &RiskFactor{Type: "device_risk", Score: 0, Weight: 1.0}, nil
}
func (r *DeviceRiskRule) GetType() string   { return "device_risk" }
func (r *DeviceRiskRule) GetWeight() float64 { return 1.2 }
func (r *DeviceRiskRule) IsEnabled() bool   { return true }

type BehaviorRiskRule struct{}
func (r *BehaviorRiskRule) Evaluate(ctx context.Context, session *SessionContext) (*RiskFactor, error) {
	return &RiskFactor{Type: "behavior_risk", Score: 0, Weight: 1.0}, nil
}
func (r *BehaviorRiskRule) GetType() string   { return "behavior_risk" }
func (r *BehaviorRiskRule) GetWeight() float64 { return 1.5 }
func (r *BehaviorRiskRule) IsEnabled() bool   { return true }

type ThreatIntelRiskRule struct{}
func (r *ThreatIntelRiskRule) Evaluate(ctx context.Context, session *SessionContext) (*RiskFactor, error) {
	return &RiskFactor{Type: "threat_intel", Score: 0, Weight: 1.0}, nil
}
func (r *ThreatIntelRiskRule) GetType() string   { return "threat_intel" }
func (r *ThreatIntelRiskRule) GetWeight() float64 { return 1.8 }
func (r *ThreatIntelRiskRule) IsEnabled() bool   { return true }

type TimeBasedRiskRule struct{}
func (r *TimeBasedRiskRule) Evaluate(ctx context.Context, session *SessionContext) (*RiskFactor, error) {
	return &RiskFactor{Type: "time_based", Score: 0, Weight: 1.0}, nil
}
func (r *TimeBasedRiskRule) GetType() string   { return "time_based" }
func (r *TimeBasedRiskRule) GetWeight() float64 { return 0.8 }
func (r *TimeBasedRiskRule) IsEnabled() bool   { return true }

type VelocityRiskRule struct{}
func (r *VelocityRiskRule) Evaluate(ctx context.Context, session *SessionContext) (*RiskFactor, error) {
	return &RiskFactor{Type: "velocity", Score: 0, Weight: 1.0}, nil
}
func (r *VelocityRiskRule) GetType() string   { return "velocity" }
func (r *VelocityRiskRule) GetWeight() float64 { return 1.3 }
func (r *VelocityRiskRule) IsEnabled() bool   { return true }