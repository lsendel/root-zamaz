// Package auth provides JWT token generation utilities
package auth

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"mvp.local/pkg/models"
	"time"
)

// buildBaseRegisteredClaims creates common JWT registered claims
func (j *JWTService) buildBaseRegisteredClaims(subject string, expiresAt time.Time) jwt.RegisteredClaims {
	now := time.Now()
	return jwt.RegisteredClaims{
		Subject:   subject,
		Audience:  jwt.ClaimStrings{j.config.Audience},
		Issuer:    j.config.Issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		NotBefore: jwt.NewNumericDate(now),
	}
}

// buildAccessTokenClaims creates claims for access tokens
func (j *JWTService) buildAccessTokenClaims(user *models.User, roles, permissions []string, deviceID string, trustLevel int, expiresAt time.Time) *JWTClaims {
	now := time.Now()
	baseClaims := j.buildBaseRegisteredClaims(user.ID.String(), expiresAt)
	baseClaims.ID = fmt.Sprintf("%s-%d", user.ID.String(), now.Unix())

	return &JWTClaims{
		UserID:           user.ID.String(),
		Username:         user.Username,
		Email:            user.Email,
		Roles:            roles,
		Permissions:      permissions,
		DeviceID:         deviceID,
		TrustLevel:       trustLevel,
		RegisteredClaims: baseClaims,
	}
}

// buildRefreshTokenClaims creates claims for refresh tokens
func (j *JWTService) buildRefreshTokenClaims(userID string, expiresAt time.Time) *jwt.RegisteredClaims {
	now := time.Now()
	baseClaims := j.buildBaseRegisteredClaims(userID, expiresAt)
	baseClaims.ID = fmt.Sprintf("refresh-%s-%d", userID, now.Unix())
	return &baseClaims
}

// generateTokenFromClaims creates and signs a JWT token from claims
func (j *JWTService) generateTokenFromClaims(claims jwt.Claims, secret []byte, keyID string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Add key ID to token header if provided
	if keyID != "" {
		token.Header["kid"] = keyID
	}

	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT token: %w", err)
	}

	return tokenString, nil
}

// extractTokenMetadata extracts common metadata from token claims
func extractTokenMetadata(claims *JWTClaims) map[string]interface{} {
	return map[string]interface{}{
		"user_id":     claims.UserID,
		"username":    claims.Username,
		"email":       claims.Email,
		"device_id":   claims.DeviceID,
		"trust_level": claims.TrustLevel,
		"issued_at":   claims.IssuedAt.Time,
		"expires_at":  claims.ExpiresAt.Time,
		"roles":       claims.Roles,
		"permissions": claims.Permissions,
	}
}
