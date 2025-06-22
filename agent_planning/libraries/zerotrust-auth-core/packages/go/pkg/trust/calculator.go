// Package trust provides trust level calculation for Zero Trust authentication.
package trust

import (
	"context"
	"fmt"
	"time"
)

// Level represents trust levels in Zero Trust architecture
type Level int

const (
	None   Level = 0   // Untrusted - failed authentication, suspicious activity
	Low    Level = 25  // Basic authentication - new devices, minimal verification
	Medium Level = 50  // Known device - standard authentication with known device
	High   Level = 75  // Verified device + location - trusted environment
	Full   Level = 100 // Hardware attestation - TPM, secure enclave, biometrics
)

// String returns the string representation of the trust level
func (l Level) String() string {
	switch l {
	case None:
		return "None"
	case Low:
		return "Low"
	case Medium:
		return "Medium"
	case High:
		return "High"
	case Full:
		return "Full"
	default:
		return fmt.Sprintf("Unknown(%d)", int(l))
	}
}

// Value returns the numeric value of the trust level
func (l Level) Value() int {
	return int(l)
}

// FromValue creates a trust level from an integer value
func FromValue(value int) Level {
	switch {
	case value >= 100:
		return Full
	case value >= 75:
		return High
	case value >= 50:
		return Medium
	case value >= 25:
		return Low
	default:
		return None
	}
}

// MeetsRequirement checks if this trust level meets the required minimum
func (l Level) MeetsRequirement(required Level) bool {
	return l >= required
}

// Factors represents factors used in trust calculation
type Factors struct {
	DeviceVerified      bool      `json:"device_verified"`
	LocationVerified    bool      `json:"location_verified"`
	BehaviorNormal      bool      `json:"behavior_normal"`
	RecentActivity      bool      `json:"recent_activity"`
	HardwareAttestation bool      `json:"hardware_attestation"`
	BiometricVerified   bool      `json:"biometric_verified"`
	NetworkTrusted      bool      `json:"network_trusted"`
	SessionAge          time.Time `json:"session_age"`
	PreviousTrustLevel  Level     `json:"previous_trust_level"`
}

// CalculationRequest represents a trust level calculation request
type CalculationRequest struct {
	UserID       string     `json:"user_id"`
	DeviceID     string     `json:"device_id,omitempty"`
	Location     *Location  `json:"location,omitempty"`
	Action       string     `json:"action,omitempty"`
	LastActivity time.Time  `json:"last_activity"`
	SessionStart time.Time  `json:"session_start"`
	IPAddress    string     `json:"ip_address,omitempty"`
	UserAgent    string     `json:"user_agent,omitempty"`
	Factors      *Factors   `json:"factors,omitempty"`
}

// Location represents a geographic location for trust calculation
type Location struct {
	Country   string  `json:"country"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	IPAddress string  `json:"ip_address"`
}

// DeviceHistory represents historical information about a device
type DeviceHistory struct {
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	LoginCount     int       `json:"login_count"`
	FailureCount   int       `json:"failure_count"`
	IsTrusted      bool      `json:"is_trusted"`
	RiskScore      int       `json:"risk_score"`
	Platform       string    `json:"platform"`
	UserAgent      string    `json:"user_agent"`
	LastTrustLevel Level     `json:"last_trust_level"`
}

// BehaviorAnalysis represents user behavior analysis results
type BehaviorAnalysis struct {
	IsSuspicious       bool      `json:"is_suspicious"`
	AnomalyScore       float64   `json:"anomaly_score"`
	TypicalLoginTimes  []int     `json:"typical_login_times"` // Hours of day
	TypicalLocations   []string  `json:"typical_locations"`
	UnusualActivity    []string  `json:"unusual_activity"`
	LastAnalyzed       time.Time `json:"last_analyzed"`
	ConfidenceScore    float64   `json:"confidence_score"`
}

// Calculator calculates trust levels based on various factors
type Calculator struct {
	deviceService   DeviceService
	behaviorService BehaviorService
	locationService LocationService
	config          *CalculatorConfig
}

// CalculatorConfig represents configuration for trust calculation
type CalculatorConfig struct {
	BaseScore              int           `json:"base_score"`               // Base score for authenticated user
	DeviceWeight           int           `json:"device_weight"`            // Weight for device verification
	LocationWeight         int           `json:"location_weight"`          // Weight for location verification
	BehaviorWeight         int           `json:"behavior_weight"`          // Weight for behavior analysis
	ActivityWeight         int           `json:"activity_weight"`          // Weight for recent activity
	HardwareWeight         int           `json:"hardware_weight"`          // Weight for hardware attestation
	BiometricWeight        int           `json:"biometric_weight"`         // Weight for biometric verification
	NetworkWeight          int           `json:"network_weight"`           // Weight for trusted network
	MaxInactivityDuration  time.Duration `json:"max_inactivity_duration"`  // Max time for recent activity
	SuspiciousActivityPenalty int        `json:"suspicious_activity_penalty"` // Penalty for suspicious activity
	NewDevicePenalty       int           `json:"new_device_penalty"`       // Penalty for new devices
}

// DefaultCalculatorConfig returns default configuration for trust calculation
func DefaultCalculatorConfig() *CalculatorConfig {
	return &CalculatorConfig{
		BaseScore:                 10,
		DeviceWeight:              25,
		LocationWeight:            20,
		BehaviorWeight:            15,
		ActivityWeight:            10,
		HardwareWeight:            15,
		BiometricWeight:           10,
		NetworkWeight:             5,
		MaxInactivityDuration:     30 * time.Minute,
		SuspiciousActivityPenalty: 50,
		NewDevicePenalty:          15,
	}
}

// Service interfaces for trust calculation dependencies

// DeviceService interface for device verification
type DeviceService interface {
	VerifyDevice(ctx context.Context, deviceID string) (bool, error)
	GetDeviceHistory(ctx context.Context, deviceID string) (*DeviceHistory, error)
	CheckHardwareAttestation(ctx context.Context, deviceID string) (bool, error)
	IsDeviceTrusted(ctx context.Context, deviceID string) (bool, error)
	MarkDeviceAsTrusted(ctx context.Context, deviceID string) error
}

// BehaviorService interface for behavior analysis
type BehaviorService interface {
	AnalyzeBehavior(ctx context.Context, userID string, action string) (*BehaviorAnalysis, error)
	IsActionSuspicious(ctx context.Context, userID string, action string) (bool, error)
	UpdateBehaviorProfile(ctx context.Context, userID string, action string, timestamp time.Time) error
	GetTypicalPatterns(ctx context.Context, userID string) (*BehaviorAnalysis, error)
}

// LocationService interface for location verification
type LocationService interface {
	VerifyLocation(ctx context.Context, userID string, location *Location) (bool, error)
	IsLocationTrusted(ctx context.Context, location *Location) (bool, error)
	GetLocationFromIP(ctx context.Context, ipAddress string) (*Location, error)
	AddTrustedLocation(ctx context.Context, userID string, location *Location) error
}

// NewCalculator creates a new trust calculator
func NewCalculator(deviceSvc DeviceService, behaviorSvc BehaviorService, locationSvc LocationService) *Calculator {
	return &Calculator{
		deviceService:   deviceSvc,
		behaviorService: behaviorSvc,
		locationService: locationSvc,
		config:          DefaultCalculatorConfig(),
	}
}

// NewCalculatorWithConfig creates a new trust calculator with custom configuration
func NewCalculatorWithConfig(deviceSvc DeviceService, behaviorSvc BehaviorService, locationSvc LocationService, config *CalculatorConfig) *Calculator {
	return &Calculator{
		deviceService:   deviceSvc,
		behaviorService: behaviorSvc,
		locationService: locationSvc,
		config:          config,
	}
}

// Calculate computes trust level based on provided factors
func (c *Calculator) Calculate(ctx context.Context, factors *Factors) Level {
	if factors == nil {
		return None
	}

	score := c.config.BaseScore

	// Device verification
	if factors.DeviceVerified {
		score += c.config.DeviceWeight
	} else {
		score -= c.config.NewDevicePenalty
	}

	// Location verification
	if factors.LocationVerified {
		score += c.config.LocationWeight
	}

	// Behavior analysis
	if factors.BehaviorNormal {
		score += c.config.BehaviorWeight
	} else {
		score -= c.config.SuspiciousActivityPenalty
	}

	// Recent activity
	if factors.RecentActivity {
		score += c.config.ActivityWeight
	}

	// Hardware attestation (high security feature)
	if factors.HardwareAttestation {
		score += c.config.HardwareWeight
	}

	// Biometric verification
	if factors.BiometricVerified {
		score += c.config.BiometricWeight
	}

	// Trusted network
	if factors.NetworkTrusted {
		score += c.config.NetworkWeight
	}

	// Session age consideration
	if !factors.SessionAge.IsZero() {
		sessionDuration := time.Since(factors.SessionAge)
		if sessionDuration > 4*time.Hour {
			score -= 10 // Reduce trust for very old sessions
		} else if sessionDuration > 8*time.Hour {
			score -= 20 // Significant reduction for very stale sessions
		}
	}

	// Consider previous trust level for gradual changes
	if factors.PreviousTrustLevel > None {
		// Smooth trust level changes to avoid dramatic swings
		previousScore := factors.PreviousTrustLevel.Value()
		if abs(score-previousScore) > 25 {
			// Limit trust level changes to 25 points per calculation
			if score > previousScore {
				score = previousScore + 25
			} else {
				score = previousScore - 25
			}
		}
	}

	// Ensure score is within bounds
	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}

	return FromValue(score)
}

// CalculateForUser performs comprehensive trust calculation for a user
func (c *Calculator) CalculateForUser(ctx context.Context, req *CalculationRequest) (Level, error) {
	if req == nil {
		return None, fmt.Errorf("calculation request cannot be nil")
	}

	factors := &Factors{}

	// Use provided factors if available
	if req.Factors != nil {
		*factors = *req.Factors
	}

	// Device verification
	if req.DeviceID != "" && c.deviceService != nil {
		verified, err := c.deviceService.VerifyDevice(ctx, req.DeviceID)
		if err != nil {
			return None, fmt.Errorf("device verification failed: %w", err)
		}
		factors.DeviceVerified = verified

		// Check hardware attestation
		if verified {
			hwAttested, err := c.deviceService.CheckHardwareAttestation(ctx, req.DeviceID)
			if err == nil { // Non-critical, continue if it fails
				factors.HardwareAttestation = hwAttested
			}
		}

		// Get device history for additional context
		history, err := c.deviceService.GetDeviceHistory(ctx, req.DeviceID)
		if err == nil && history != nil {
			// Consider device trust history
			if history.IsTrusted && history.FailureCount < 3 {
				factors.DeviceVerified = true
			}
			// Use previous trust level for continuity
			factors.PreviousTrustLevel = history.LastTrustLevel
		}
	}

	// Location verification
	if req.Location != nil && c.locationService != nil {
		verified, err := c.locationService.VerifyLocation(ctx, req.UserID, req.Location)
		if err != nil {
			return None, fmt.Errorf("location verification failed: %w", err)
		}
		factors.LocationVerified = verified

		// Check if location is on trusted network
		trusted, err := c.locationService.IsLocationTrusted(ctx, req.Location)
		if err == nil {
			factors.NetworkTrusted = trusted
		}
	} else if req.IPAddress != "" && c.locationService != nil {
		// Derive location from IP address
		location, err := c.locationService.GetLocationFromIP(ctx, req.IPAddress)
		if err == nil && location != nil {
			verified, err := c.locationService.VerifyLocation(ctx, req.UserID, location)
			if err == nil {
				factors.LocationVerified = verified
			}

			trusted, err := c.locationService.IsLocationTrusted(ctx, location)
			if err == nil {
				factors.NetworkTrusted = trusted
			}
		}
	}

	// Behavior analysis
	if req.Action != "" && c.behaviorService != nil {
		suspicious, err := c.behaviorService.IsActionSuspicious(ctx, req.UserID, req.Action)
		if err != nil {
			return None, fmt.Errorf("behavior analysis failed: %w", err)
		}
		factors.BehaviorNormal = !suspicious

		// Update behavior profile for future analysis
		if !req.LastActivity.IsZero() {
			c.behaviorService.UpdateBehaviorProfile(ctx, req.UserID, req.Action, req.LastActivity)
		}
	}

	// Recent activity check
	if !req.LastActivity.IsZero() {
		factors.RecentActivity = time.Since(req.LastActivity) < c.config.MaxInactivityDuration
	}

	// Session age
	if !req.SessionStart.IsZero() {
		factors.SessionAge = req.SessionStart
	}

	return c.Calculate(ctx, factors), nil
}

// CalculateForAuthentication calculates trust level during authentication
func (c *Calculator) CalculateForAuthentication(ctx context.Context, userID, deviceID, ipAddress string) (Level, error) {
	req := &CalculationRequest{
		UserID:       userID,
		DeviceID:     deviceID,
		IPAddress:    ipAddress,
		LastActivity: time.Now(),
		SessionStart: time.Now(),
		Action:       "login",
	}

	return c.CalculateForUser(ctx, req)
}

// RequireTrustLevel creates a requirement checker for a minimum trust level
func RequireTrustLevel(required Level) func(Level) bool {
	return func(actual Level) bool {
		return actual.MeetsRequirement(required)
	}
}

// GetTrustLevelForOperation returns the required trust level for different operations
func GetTrustLevelForOperation(operation string) Level {
	switch operation {
	case "login", "read_profile", "view_dashboard":
		return Low
	case "update_profile", "create_resource", "view_reports":
		return Medium
	case "delete_resource", "admin_action", "financial_transaction":
		return High
	case "system_admin", "security_settings", "user_management":
		return Full
	default:
		return Medium // Default to medium for unknown operations
	}
}

// ValidateFactors validates trust calculation factors
func ValidateFactors(factors *Factors) error {
	if factors == nil {
		return fmt.Errorf("factors cannot be nil")
	}

	// Check for logical inconsistencies
	if factors.HardwareAttestation && !factors.DeviceVerified {
		return fmt.Errorf("hardware attestation requires device verification")
	}

	if factors.BiometricVerified && !factors.DeviceVerified {
		return fmt.Errorf("biometric verification requires device verification")
	}

	return nil
}

// Helper function for absolute value
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}