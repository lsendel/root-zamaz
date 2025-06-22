package auth

import (
	"context"
	"time"
	
	"github.com/lsendel/root-zamaz/pkg/domain/models"
	"github.com/lsendel/root-zamaz/pkg/utils/errors"
)

// GenerateTokenWithTrust generates a JWT token with calculated trust level based on device and context factors
func (j *JWTService) GenerateTokenWithTrust(ctx context.Context, user *models.User, roles []string, permissions []string, factors TrustFactors) (*LoginResponse, error) {
	if j == nil {
		return nil, errors.Internal("JWT service is nil")
	}
	if j.config == nil {
		return nil, errors.Internal("JWT config is nil")
	}
	if user == nil {
		return nil, errors.Validation("User is required")
	}
	
	// Calculate trust level based on provided factors
	trustLevel := CalculateTrustLevel(factors)
	
	// Log trust level calculation for audit
	j.logTrustLevelCalculation(ctx, user.ID.String(), factors, trustLevel)
	
	// Check if trust level is adequate for basic authentication
	if trustLevel < TrustLevelLow {
		return nil, errors.Forbidden("Insufficient trust level for authentication")
	}
	
	now := time.Now()
	expiresAt := now.Add(j.expiryDuration)
	
	// Adjust token expiry based on trust level
	// Lower trust = shorter token lifetime
	if trustLevel < TrustLevelMedium {
		expiresAt = now.Add(j.expiryDuration / 2) // Half the normal duration
	} else if trustLevel >= TrustLevelHigh {
		expiresAt = now.Add(j.expiryDuration * 2) // Double for high trust
	}
	
	// Generate device ID from factors (could be enhanced with actual device fingerprinting)
	deviceID := factors.generateDeviceID()
	
	claims := j.buildAccessTokenClaims(user, roles, permissions, deviceID, int(trustLevel), expiresAt)
	
	// Add trust level to claims
	claims["trust_level"] = int(trustLevel)
	claims["trust_factors"] = map[string]interface{}{
		"hardware_attested": factors.HardwareAttested,
		"mfa_used":         factors.MFAUsed,
		"device_known":     factors.DeviceKnown,
	}
	
	// Get current signing key
	currentKey := j.keyManager.GetCurrentKey()
	if currentKey == nil {
		return nil, errors.Internal("No active signing key available")
	}
	
	tokenString, err := j.generateTokenFromClaims(claims, currentKey.Key, currentKey.ID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to sign JWT token")
	}
	
	// Generate refresh token
	refreshToken, err := j.GenerateRefreshToken(user.ID.String())
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to generate refresh token")
	}
	
	return &LoginResponse{
		Token:        tokenString,
		RefreshToken: refreshToken,
		User:         user,
		ExpiresAt:    expiresAt,
	}, nil
}

// ValidateTokenWithTrustCheck validates a token and checks if trust level is adequate for the requested operation
func (j *JWTService) ValidateTokenWithTrustCheck(tokenString string, requiredOperation string) (*JWTClaims, error) {
	// First validate the token normally
	claims, err := j.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}
	
	// Extract trust level from claims
	trustLevelValue, ok := claims.AdditionalClaims["trust_level"].(float64)
	if !ok {
		// Default to medium trust for tokens without explicit trust level
		trustLevelValue = float64(TrustLevelMedium)
	}
	
	trustLevel := TrustLevel(trustLevelValue)
	
	// Check if trust level is adequate for the operation
	if !trustLevel.IsAdequateFor(requiredOperation) {
		return nil, errors.Forbidden("Insufficient trust level for operation: %s (current: %s)", 
			requiredOperation, trustLevel.String())
	}
	
	return claims, nil
}

// logTrustLevelCalculation logs the trust level calculation for audit purposes
func (j *JWTService) logTrustLevelCalculation(ctx context.Context, userID string, factors TrustFactors, result TrustLevel) {
	// This should integrate with the audit service
	// For now, we'll use structured logging
	logger := j.getLogger(ctx)
	logger.Info().
		Str("user_id", userID).
		Int("trust_level", int(result)).
		Bool("hardware_attested", factors.HardwareAttested).
		Bool("device_known", factors.DeviceKnown).
		Bool("mfa_used", factors.MFAUsed).
		Bool("suspicious_activity", factors.SuspiciousActivity).
		Msg("Trust level calculated for authentication")
}

// generateDeviceID creates a device identifier from trust factors
func (f *TrustFactors) generateDeviceID() string {
	// In a real implementation, this would use actual device fingerprinting
	// For now, we'll use a simple placeholder
	if f.HardwareAttested {
		return "hw-attested-device"
	} else if f.DeviceKnown {
		return "known-device"
	}
	return "unknown-device"
}

// getLogger retrieves the logger from context or returns a default logger
func (j *JWTService) getLogger(ctx context.Context) interface{ 
	Info() interface{ 
		Str(string, string) interface{ 
			Int(string, int) interface{ 
				Bool(string, bool) interface{ 
					Msg(string) 
				} 
			} 
		} 
	} 
} {
	// This is a placeholder - should integrate with the observability package
	// Return a no-op logger for now
	return &noOpLogger{}
}

// noOpLogger is a placeholder logger that does nothing
type noOpLogger struct{}

func (n *noOpLogger) Info() interface{ 
	Str(string, string) interface{ 
		Int(string, int) interface{ 
			Bool(string, bool) interface{ 
				Msg(string) 
			} 
		} 
	} 
} {
	return n
}

func (n *noOpLogger) Str(string, string) interface{ 
	Int(string, int) interface{ 
		Bool(string, bool) interface{ 
			Msg(string) 
		} 
	} 
} {
	return n
}

func (n *noOpLogger) Int(string, int) interface{ 
	Bool(string, bool) interface{ 
		Msg(string) 
	} 
} {
	return n
}

func (n *noOpLogger) Bool(string, bool) interface{ 
	Msg(string) 
} {
	return n
}

func (n *noOpLogger) Msg(string) {
	// No-op
}