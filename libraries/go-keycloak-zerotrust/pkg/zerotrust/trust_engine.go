// Package zerotrust provides the trust engine for calculating and managing trust scores
package zerotrust

import (
	"context"
	"log"
	"math"
	"time"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// TrustEngine manages trust score calculation and continuous verification
type TrustEngine struct {
	config              *types.ZeroTrustConfig
	continuousVerifier  *ContinuousVerificationService
	trustFactors        []TrustFactor
	trustDecayRules     []TrustDecayRule
	adaptivePolicies    []AdaptivePolicy
}

// TrustFactor represents a factor that contributes to trust score calculation
type TrustFactor interface {
	CalculateScore(ctx context.Context, input *TrustCalculationInput) (int, error)
	GetWeight() float64
	GetType() string
	IsEnabled() bool
}

// TrustDecayRule defines how trust scores decay over time
type TrustDecayRule interface {
	ApplyDecay(currentScore int, timeSince time.Duration, context *TrustDecayContext) int
	GetDecayType() string
	IsApplicable(context *TrustDecayContext) bool
}

// AdaptivePolicy defines adaptive security policies based on trust levels
type AdaptivePolicy interface {
	ShouldApply(ctx context.Context, trustLevel int, riskScore int) bool
	GetRequiredActions() []string
	GetPolicyType() string
}

// TrustCalculationInput contains all data needed for trust calculation
type TrustCalculationInput struct {
	UserID              string                     `json:"user_id"`
	DeviceAttestation   *DeviceAttestation         `json:"device_attestation"`
	VerificationResult  *VerificationResult        `json:"verification_result"`
	SessionContext      *SessionContext            `json:"session_context"`
	HistoricalBehavior  *UserBaseline              `json:"historical_behavior"`
	RiskAssessment      *RiskAssessmentResult      `json:"risk_assessment"`
	PreviousTrustLevel  int                        `json:"previous_trust_level"`
	AuthenticationMethod string                    `json:"authentication_method"`
	BiometricData       *BiometricVerificationData `json:"biometric_data,omitempty"`
}

// TrustDecayContext provides context for trust decay calculations
type TrustDecayContext struct {
	UserID           string            `json:"user_id"`
	DeviceID         string            `json:"device_id"`
	LastActivity     time.Time         `json:"last_activity"`
	ActivityType     string            `json:"activity_type"`
	SecurityEvents   []SecurityEvent   `json:"security_events"`
	ComplianceState  string            `json:"compliance_state"`
}

// BiometricVerificationData contains biometric verification information
type BiometricVerificationData struct {
	BiometricType       string    `json:"biometric_type"`
	VerificationScore   float64   `json:"verification_score"`
	IsAuthentic         bool      `json:"is_authentic"`
	QualityScore        float64   `json:"quality_score"`
	TemplateMatches     int       `json:"template_matches"`
	VerificationTime    time.Time `json:"verification_time"`
	FalseAcceptanceRate float64   `json:"false_acceptance_rate"`
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Timestamp   time.Time              `json:"timestamp"`
	UserID      string                 `json:"user_id"`
	DeviceID    string                 `json:"device_id"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
	Resolved    bool                   `json:"resolved"`
}

// ContinuousVerificationService manages ongoing verification processes
type ContinuousVerificationService struct {
	config               *types.ZeroTrustConfig
	verificationTriggers []VerificationTrigger
	verificationChecks   []VerificationCheck
	scheduler            *VerificationScheduler
}

// VerificationTrigger defines when continuous verification should be triggered
type VerificationTrigger interface {
	ShouldTrigger(ctx context.Context, event *SecurityEvent, userContext *UserContext) bool
	GetTriggerType() string
	GetPriority() int
}

// VerificationCheck defines what should be verified during continuous verification
type VerificationCheck interface {
	Verify(ctx context.Context, userContext *UserContext) (*VerificationCheckResult, error)
	GetCheckType() string
	GetRequiredTrustLevel() int
}

// VerificationCheckResult contains the result of a verification check
type VerificationCheckResult struct {
	CheckType   string                 `json:"check_type"`
	Passed      bool                   `json:"passed"`
	Score       int                    `json:"score"`
	Confidence  float64                `json:"confidence"`
	Details     map[string]interface{} `json:"details"`
	Timestamp   time.Time              `json:"timestamp"`
	NextCheck   *time.Time             `json:"next_check,omitempty"`
}

// UserContext contains current user state for verification
type UserContext struct {
	UserID         string            `json:"user_id"`
	CurrentSession *SessionContext   `json:"current_session"`
	TrustLevel     int               `json:"trust_level"`
	RiskScore      int               `json:"risk_score"`
	LastVerified   time.Time         `json:"last_verified"`
	ActiveDevices  []*Device         `json:"active_devices"`
}

// VerificationScheduler manages scheduled verification tasks
type VerificationScheduler struct {
	scheduledTasks map[string]*ScheduledVerification
	taskQueue      chan *VerificationTask
}

// ScheduledVerification represents a scheduled verification task
type ScheduledVerification struct {
	ID              string        `json:"id"`
	UserID          string        `json:"user_id"`
	VerificationType string       `json:"verification_type"`
	Interval        time.Duration `json:"interval"`
	NextRun         time.Time     `json:"next_run"`
	Priority        int           `json:"priority"`
	Enabled         bool          `json:"enabled"`
}

// VerificationTask represents a verification task to be executed
type VerificationTask struct {
	ID           string        `json:"id"`
	UserID       string        `json:"user_id"`
	TaskType     string        `json:"task_type"`
	Priority     int           `json:"priority"`
	ScheduledAt  time.Time     `json:"scheduled_at"`
	MaxRetries   int           `json:"max_retries"`
	Context      *UserContext  `json:"context"`
}

// NewTrustEngine creates a new trust engine
func NewTrustEngine(config *types.ZeroTrustConfig) *TrustEngine {
	engine := &TrustEngine{
		config:           config,
		trustFactors:     make([]TrustFactor, 0),
		trustDecayRules:  make([]TrustDecayRule, 0),
		adaptivePolicies: make([]AdaptivePolicy, 0),
	}

	// Initialize continuous verification service
	engine.continuousVerifier = NewContinuousVerificationService(config)

	// Register default trust factors
	engine.RegisterTrustFactor(&DeviceTrustFactor{})
	engine.RegisterTrustFactor(&BiometricTrustFactor{})
	engine.RegisterTrustFactor(&BehaviorTrustFactor{})
	engine.RegisterTrustFactor(&LocationTrustFactor{})
	engine.RegisterTrustFactor(&AuthMethodTrustFactor{})
	engine.RegisterTrustFactor(&HistoricalTrustFactor{})

	// Register default decay rules
	engine.RegisterDecayRule(&TimeBasedDecayRule{})
	engine.RegisterDecayRule(&ActivityBasedDecayRule{})
	engine.RegisterDecayRule(&SecurityEventDecayRule{})

	// Register adaptive policies
	engine.RegisterAdaptivePolicy(&HighRiskAdaptivePolicy{})
	engine.RegisterAdaptivePolicy(&LowTrustAdaptivePolicy{})
	engine.RegisterAdaptivePolicy(&ComplianceAdaptivePolicy{})

	return engine
}

// RegisterTrustFactor registers a new trust factor
func (e *TrustEngine) RegisterTrustFactor(factor TrustFactor) {
	e.trustFactors = append(e.trustFactors, factor)
	log.Printf("Registered trust factor: %s", factor.GetType())
}

// RegisterDecayRule registers a new trust decay rule
func (e *TrustEngine) RegisterDecayRule(rule TrustDecayRule) {
	e.trustDecayRules = append(e.trustDecayRules, rule)
	log.Printf("Registered trust decay rule: %s", rule.GetDecayType())
}

// RegisterAdaptivePolicy registers a new adaptive policy
func (e *TrustEngine) RegisterAdaptivePolicy(policy AdaptivePolicy) {
	e.adaptivePolicies = append(e.adaptivePolicies, policy)
	log.Printf("Registered adaptive policy: %s", policy.GetPolicyType())
}

// CalculateDeviceTrustScore calculates trust score for device attestation
func (e *TrustEngine) CalculateDeviceTrustScore(attestation *DeviceAttestation, result *VerificationResult) int {
	input := &TrustCalculationInput{
		DeviceAttestation:  attestation,
		VerificationResult: result,
	}

	return e.CalculateTrustScore(context.Background(), input)
}

// CalculateTrustScore calculates comprehensive trust score
func (e *TrustEngine) CalculateTrustScore(ctx context.Context, input *TrustCalculationInput) int {
	totalScore := 0.0
	totalWeight := 0.0

	// Apply each trust factor
	for _, factor := range e.trustFactors {
		if !factor.IsEnabled() {
			continue
		}

		score, err := factor.CalculateScore(ctx, input)
		if err != nil {
			log.Printf("Trust factor %s calculation failed: %v", factor.GetType(), err)
			continue
		}

		weight := factor.GetWeight()
		totalScore += float64(score) * weight
		totalWeight += weight

		log.Printf("Trust factor %s: score=%d, weight=%.2f", factor.GetType(), score, weight)
	}

	// Calculate weighted average
	finalScore := 0
	if totalWeight > 0 {
		finalScore = int(math.Round(totalScore / totalWeight))
	}

	// Apply bounds (0-100)
	if finalScore < 0 {
		finalScore = 0
	} else if finalScore > 100 {
		finalScore = 100
	}

	log.Printf("Calculated trust score: %d (total_score=%.2f, total_weight=%.2f)", 
		finalScore, totalScore, totalWeight)

	return finalScore
}

// DecayTrustScore applies trust decay based on time and activity
func (e *TrustEngine) DecayTrustScore(currentScore int, timeSince time.Duration) int {
	if timeSince <= 0 {
		return currentScore
	}

	context := &TrustDecayContext{
		LastActivity: time.Now().Add(-timeSince),
	}

	decayedScore := currentScore
	for _, rule := range e.trustDecayRules {
		if rule.IsApplicable(context) {
			decayedScore = rule.ApplyDecay(decayedScore, timeSince, context)
		}
	}

	// Ensure score doesn't go below 0
	if decayedScore < 0 {
		decayedScore = 0
	}

	if decayedScore != currentScore {
		log.Printf("Trust score decayed: %d -> %d (time_since=%v)", 
			currentScore, decayedScore, timeSince)
	}

	return decayedScore
}

// EvaluateAdaptivePolicies evaluates adaptive policies and returns required actions
func (e *TrustEngine) EvaluateAdaptivePolicies(ctx context.Context, trustLevel int, riskScore int) []string {
	var requiredActions []string

	for _, policy := range e.adaptivePolicies {
		if policy.ShouldApply(ctx, trustLevel, riskScore) {
			actions := policy.GetRequiredActions()
			requiredActions = append(requiredActions, actions...)
			log.Printf("Adaptive policy %s triggered: actions=%v", 
				policy.GetPolicyType(), actions)
		}
	}

	return requiredActions
}

// Trust Factor Implementations

// DeviceTrustFactor calculates trust based on device verification
type DeviceTrustFactor struct{}

func (f *DeviceTrustFactor) CalculateScore(ctx context.Context, input *TrustCalculationInput) (int, error) {
	if input.VerificationResult == nil {
		return 25, nil // Default score
	}

	baseScore := input.VerificationResult.TrustScore

	// Adjust based on verification level
	switch input.VerificationResult.VerificationLevel {
	case "hardware":
		baseScore += 20
	case "software":
		baseScore += 10
	case "biometric":
		baseScore += 30
	}

	// Penalize for risk factors
	riskPenalty := len(input.VerificationResult.RiskFactors) * 10
	finalScore := baseScore - riskPenalty

	return finalScore, nil
}

func (f *DeviceTrustFactor) GetWeight() float64 { return 1.5 }
func (f *DeviceTrustFactor) GetType() string   { return "device_trust" }
func (f *DeviceTrustFactor) IsEnabled() bool   { return true }

// BiometricTrustFactor calculates trust based on biometric verification
type BiometricTrustFactor struct{}

func (f *BiometricTrustFactor) CalculateScore(ctx context.Context, input *TrustCalculationInput) (int, error) {
	if input.BiometricData == nil {
		return 0, nil // No biometric data
	}

	if !input.BiometricData.IsAuthentic {
		return 0, nil
	}

	// Base score from verification confidence
	baseScore := int(input.BiometricData.VerificationScore * 100)

	// Adjust for quality
	qualityBonus := int(input.BiometricData.QualityScore * 20)
	
	// Adjust for false acceptance rate (lower is better)
	farPenalty := int(input.BiometricData.FalseAcceptanceRate * 50)

	finalScore := baseScore + qualityBonus - farPenalty

	return finalScore, nil
}

func (f *BiometricTrustFactor) GetWeight() float64 { return 2.0 }
func (f *BiometricTrustFactor) GetType() string   { return "biometric_trust" }
func (f *BiometricTrustFactor) IsEnabled() bool   { return true }

// Placeholder implementations for other trust factors
type BehaviorTrustFactor struct{}
func (f *BehaviorTrustFactor) CalculateScore(ctx context.Context, input *TrustCalculationInput) (int, error) {
	return 50, nil // Placeholder
}
func (f *BehaviorTrustFactor) GetWeight() float64 { return 1.2 }
func (f *BehaviorTrustFactor) GetType() string   { return "behavior_trust" }
func (f *BehaviorTrustFactor) IsEnabled() bool   { return true }

type LocationTrustFactor struct{}
func (f *LocationTrustFactor) CalculateScore(ctx context.Context, input *TrustCalculationInput) (int, error) {
	return 50, nil // Placeholder
}
func (f *LocationTrustFactor) GetWeight() float64 { return 1.0 }
func (f *LocationTrustFactor) GetType() string   { return "location_trust" }
func (f *LocationTrustFactor) IsEnabled() bool   { return true }

type AuthMethodTrustFactor struct{}
func (f *AuthMethodTrustFactor) CalculateScore(ctx context.Context, input *TrustCalculationInput) (int, error) {
	switch input.AuthenticationMethod {
	case "mfa":
		return 80, nil
	case "biometric":
		return 90, nil
	case "password":
		return 40, nil
	default:
		return 25, nil
	}
}
func (f *AuthMethodTrustFactor) GetWeight() float64 { return 1.3 }
func (f *AuthMethodTrustFactor) GetType() string   { return "auth_method_trust" }
func (f *AuthMethodTrustFactor) IsEnabled() bool   { return true }

type HistoricalTrustFactor struct{}
func (f *HistoricalTrustFactor) CalculateScore(ctx context.Context, input *TrustCalculationInput) (int, error) {
	return input.PreviousTrustLevel, nil
}
func (f *HistoricalTrustFactor) GetWeight() float64 { return 0.8 }
func (f *HistoricalTrustFactor) GetType() string   { return "historical_trust" }
func (f *HistoricalTrustFactor) IsEnabled() bool   { return true }

// Trust Decay Rule Implementations

// TimeBasedDecayRule applies decay based on time since last activity
type TimeBasedDecayRule struct{}

func (r *TimeBasedDecayRule) ApplyDecay(currentScore int, timeSince time.Duration, context *TrustDecayContext) int {
	// Decay 1 point per hour of inactivity, with minimum of 25
	hoursInactive := int(timeSince.Hours())
	decayAmount := hoursInactive
	
	newScore := currentScore - decayAmount
	if newScore < 25 {
		newScore = 25
	}
	
	return newScore
}

func (r *TimeBasedDecayRule) GetDecayType() string { return "time_based" }
func (r *TimeBasedDecayRule) IsApplicable(context *TrustDecayContext) bool { return true }

// Placeholder implementations for other decay rules
type ActivityBasedDecayRule struct{}
func (r *ActivityBasedDecayRule) ApplyDecay(currentScore int, timeSince time.Duration, context *TrustDecayContext) int {
	return currentScore // Placeholder
}
func (r *ActivityBasedDecayRule) GetDecayType() string { return "activity_based" }
func (r *ActivityBasedDecayRule) IsApplicable(context *TrustDecayContext) bool { return false }

type SecurityEventDecayRule struct{}
func (r *SecurityEventDecayRule) ApplyDecay(currentScore int, timeSince time.Duration, context *TrustDecayContext) int {
	return currentScore // Placeholder
}
func (r *SecurityEventDecayRule) GetDecayType() string { return "security_event" }
func (r *SecurityEventDecayRule) IsApplicable(context *TrustDecayContext) bool { return false }

// Adaptive Policy Implementations

// HighRiskAdaptivePolicy triggers for high-risk scenarios
type HighRiskAdaptivePolicy struct{}

func (p *HighRiskAdaptivePolicy) ShouldApply(ctx context.Context, trustLevel int, riskScore int) bool {
	return riskScore >= 75 || trustLevel < 25
}

func (p *HighRiskAdaptivePolicy) GetRequiredActions() []string {
	return []string{"require_mfa", "increase_verification_frequency", "limit_access_scope"}
}

func (p *HighRiskAdaptivePolicy) GetPolicyType() string { return "high_risk" }

// Placeholder implementations for other adaptive policies
type LowTrustAdaptivePolicy struct{}
func (p *LowTrustAdaptivePolicy) ShouldApply(ctx context.Context, trustLevel int, riskScore int) bool {
	return trustLevel < 50
}
func (p *LowTrustAdaptivePolicy) GetRequiredActions() []string {
	return []string{"require_additional_verification"}
}
func (p *LowTrustAdaptivePolicy) GetPolicyType() string { return "low_trust" }

type ComplianceAdaptivePolicy struct{}
func (p *ComplianceAdaptivePolicy) ShouldApply(ctx context.Context, trustLevel int, riskScore int) bool {
	return false // Placeholder
}
func (p *ComplianceAdaptivePolicy) GetRequiredActions() []string {
	return []string{"compliance_verification"}
}
func (p *ComplianceAdaptivePolicy) GetPolicyType() string { return "compliance" }

// NewContinuousVerificationService creates a new continuous verification service
func NewContinuousVerificationService(config *types.ZeroTrustConfig) *ContinuousVerificationService {
	return &ContinuousVerificationService{
		config:               config,
		verificationTriggers: make([]VerificationTrigger, 0),
		verificationChecks:   make([]VerificationCheck, 0),
		scheduler:            &VerificationScheduler{
			scheduledTasks: make(map[string]*ScheduledVerification),
			taskQueue:      make(chan *VerificationTask, 100),
		},
	}
}