package auth

// TrustLevel represents the trust level of a device or session.
// Trust levels range from 0 (no trust) to 100 (full trust).
// Higher values indicate greater confidence in the device's identity and security posture.
type TrustLevel int

const (
	// TrustLevelNone indicates no trust - device is unknown or compromised
	TrustLevelNone TrustLevel = 0
	
	// TrustLevelMinimal indicates minimal trust - basic device identification only
	TrustLevelMinimal TrustLevel = 10
	
	// TrustLevelLow indicates low trust - unverified device, first-time login
	TrustLevelLow TrustLevel = 25
	
	// TrustLevelMedium indicates medium trust - known device, no attestation
	TrustLevelMedium TrustLevel = 50
	
	// TrustLevelHigh indicates high trust - attested device, recent verification
	TrustLevelHigh TrustLevel = 75
	
	// TrustLevelFull indicates full trust - hardware-attested, compliant device
	TrustLevelFull TrustLevel = 100
)

// TrustLevelThresholds define minimum trust levels required for different operations
var TrustLevelThresholds = map[string]TrustLevel{
	"read:public":     TrustLevelLow,
	"read:private":    TrustLevelMedium,
	"write:private":   TrustLevelMedium,
	"admin:read":      TrustLevelHigh,
	"admin:write":     TrustLevelHigh,
	"admin:delete":    TrustLevelFull,
	"security:config": TrustLevelFull,
}

// CalculateTrustLevel calculates the trust level based on various factors
func CalculateTrustLevel(factors TrustFactors) TrustLevel {
	trustScore := 0
	
	// Base score from device attestation
	if factors.HardwareAttested {
		trustScore += 50
	} else if factors.DeviceKnown {
		trustScore += 25
	}
	
	// Bonus for recent successful authentications
	if factors.RecentSuccessfulAuth {
		trustScore += 15
	}
	
	// Bonus for consistent location
	if factors.ConsistentLocation {
		trustScore += 10
	}
	
	// Bonus for strong authentication method
	if factors.MFAUsed {
		trustScore += 15
	}
	
	// Penalties for risk factors
	if factors.SuspiciousActivity {
		trustScore -= 25
	}
	
	if factors.UnknownNetwork {
		trustScore -= 10
	}
	
	if factors.AnomalousTime {
		trustScore -= 5
	}
	
	// Ensure trust level is within valid range
	if trustScore < 0 {
		return TrustLevelNone
	}
	if trustScore > 100 {
		return TrustLevelFull
	}
	
	return TrustLevel(trustScore)
}

// TrustFactors contains various factors that influence trust level calculation
type TrustFactors struct {
	// Positive factors
	HardwareAttested     bool // Device has valid hardware attestation
	DeviceKnown         bool // Device has been seen before
	RecentSuccessfulAuth bool // Recent successful authentication from this device
	ConsistentLocation   bool // Login from usual location
	MFAUsed             bool // Multi-factor authentication was used
	
	// Negative factors
	SuspiciousActivity bool // Suspicious patterns detected
	UnknownNetwork     bool // Login from unknown network
	AnomalousTime      bool // Login at unusual time
}

// String returns a human-readable description of the trust level
func (t TrustLevel) String() string {
	switch {
	case t == TrustLevelNone:
		return "None (Untrusted)"
	case t <= TrustLevelMinimal:
		return "Minimal"
	case t <= TrustLevelLow:
		return "Low"
	case t <= TrustLevelMedium:
		return "Medium"
	case t <= TrustLevelHigh:
		return "High"
	case t >= TrustLevelFull:
		return "Full (Hardware Attested)"
	default:
		return "Unknown"
	}
}

// IsAdequateFor checks if the trust level is adequate for a given operation
func (t TrustLevel) IsAdequateFor(operation string) bool {
	required, exists := TrustLevelThresholds[operation]
	if !exists {
		// Default to medium trust for unknown operations
		required = TrustLevelMedium
	}
	return t >= required
}