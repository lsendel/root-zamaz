// Package auth provides JWT authentication services for the MVP Zero Trust Auth system.
// It includes token generation, validation, refresh, and claims management.
package auth

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"mvp.local/pkg/config"
	"mvp.local/pkg/errors"
	"mvp.local/pkg/models"
)

// JWTClaims represents the JWT token claims
type JWTClaims struct {
	UserID      uint     `json:"user_id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	DeviceID    string   `json:"device_id"`
	TrustLevel  int      `json:"trust_level"`
	jwt.RegisteredClaims
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
	DeviceID string `json:"device_id"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Token        string      `json:"token"`
	RefreshToken string      `json:"refresh_token"`
	User         *models.User `json:"user"`
	ExpiresAt    time.Time   `json:"expires_at"`
}

// RefreshRequest represents a token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// JWTService handles JWT operations
type JWTService struct {
	config            *config.JWTConfig
	authzService      AuthorizationInterface
	secret            []byte
	refreshSecret     []byte
	expiryDuration    time.Duration
	refreshExpiry     time.Duration
}

// JWTServiceInterface defines the contract for JWT operations
type JWTServiceInterface interface {
	GenerateToken(user *models.User, deviceID string, trustLevel int, roles []string, permissions []string) (string, error)
	GenerateRefreshToken(userID uint) (string, error)
	ValidateToken(tokenString string) (*JWTClaims, error)
	ValidateRefreshToken(tokenString string) (uint, error)
	RefreshAccessToken(refreshToken string, user *models.User, roles []string, permissions []string) (*LoginResponse, error)
	HashPassword(password string) (string, error)
	CheckPassword(hashedPassword, password string) error
	GetUserRolesAndPermissions(userID uint) ([]string, []string, error)
}

// NewJWTService creates a new JWT service
func NewJWTService(config *config.JWTConfig, authzService AuthorizationInterface) *JWTService {
	secret := []byte(config.Secret)
	if len(secret) == 0 {
		// Use a default secret for development (should be set in production)
		secret = []byte("your-development-secret-key-change-in-production")
	}

	refreshSecret := []byte(config.Secret + "-refresh")

	return &JWTService{
		config:            config,
		authzService:      authzService,
		secret:            secret,
		refreshSecret:     refreshSecret,
		expiryDuration:    config.ExpiryDuration,
		refreshExpiry:     time.Hour * 24 * 7, // 7 days for refresh token
	}
}

// GenerateToken generates a new JWT access token
func (j *JWTService) GenerateToken(user *models.User, deviceID string, trustLevel int, roles []string, permissions []string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(j.expiryDuration)

	claims := &JWTClaims{
		UserID:      user.ID,
		Username:    user.Username,
		Email:       user.Email,
		Roles:       roles,
		Permissions: permissions,
		DeviceID:    deviceID,
		TrustLevel:  trustLevel,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        fmt.Sprintf("%d-%d", user.ID, now.Unix()),
			Subject:   strconv.FormatUint(uint64(user.ID), 10),
			Audience:  jwt.ClaimStrings{j.config.Audience},
			Issuer:    j.config.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(j.secret)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "Failed to sign JWT token")
	}

	return tokenString, nil
}

// GenerateRefreshToken generates a new JWT refresh token
func (j *JWTService) GenerateRefreshToken(userID uint) (string, error) {
	now := time.Now()
	expiresAt := now.Add(j.refreshExpiry)

	claims := &jwt.RegisteredClaims{
		ID:        fmt.Sprintf("refresh-%d-%d", userID, now.Unix()),
		Subject:   strconv.FormatUint(uint64(userID), 10),
		Audience:  jwt.ClaimStrings{j.config.Audience},
		Issuer:    j.config.Issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		NotBefore: jwt.NewNumericDate(now),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(j.refreshSecret)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "Failed to sign JWT refresh token")
	}

	return tokenString, nil
}

// ValidateToken validates and parses a JWT access token
func (j *JWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secret, nil
	})

	if err != nil {
		// JWT v5 simplified error handling - check error message patterns
		errMsg := err.Error()
		if strings.Contains(errMsg, "expired") {
			return nil, errors.Unauthorized("Token expired")
		} else if strings.Contains(errMsg, "not valid yet") {
			return nil, errors.Unauthorized("Token not valid yet")
		} else if strings.Contains(errMsg, "malformed") {
			return nil, errors.Unauthorized("Malformed token")
		}
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "Invalid token")
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.Unauthorized("Invalid token claims")
}

// ValidateRefreshToken validates and parses a JWT refresh token
func (j *JWTService) ValidateRefreshToken(tokenString string) (uint, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.refreshSecret, nil
	})

	if err != nil {
		return 0, errors.Wrap(err, errors.CodeUnauthorized, "Invalid refresh token")
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		userID, err := strconv.ParseUint(claims.Subject, 10, 32)
		if err != nil {
			return 0, errors.Unauthorized("Invalid user ID in refresh token")
		}
		return uint(userID), nil
	}

	return 0, errors.Unauthorized("Invalid refresh token claims")
}

// RefreshAccessToken generates a new access token using a valid refresh token
func (j *JWTService) RefreshAccessToken(refreshToken string, user *models.User, roles []string, permissions []string) (*LoginResponse, error) {
	// Validate refresh token
	userID, err := j.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	if userID != user.ID {
		return nil, errors.Unauthorized("Refresh token user mismatch")
	}

	// Generate new access token
	accessToken, err := j.GenerateToken(user, "", 0, roles, permissions)
	if err != nil {
		return nil, err
	}

	// Generate new refresh token
	newRefreshToken, err := j.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, err
	}

	return &LoginResponse{
		Token:        accessToken,
		RefreshToken: newRefreshToken,
		User:         user,
		ExpiresAt:    time.Now().Add(j.expiryDuration),
	}, nil
}

// HashPassword hashes a password using bcrypt
func (j *JWTService) HashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "Failed to hash password")
	}
	return string(hashedBytes), nil
}

// CheckPassword verifies a password against its hash
func (j *JWTService) CheckPassword(hashedPassword, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return errors.Unauthorized("Invalid password")
	}
	return nil
}

// ExtractTokenFromHeader extracts JWT token from Authorization header
func ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.Unauthorized("Authorization header required")
	}

	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		return "", errors.Unauthorized("Invalid authorization header format")
	}

	return authHeader[len(bearerPrefix):], nil
}

// GetUserRolesAndPermissions retrieves user roles and permissions
func (j *JWTService) GetUserRolesAndPermissions(userID uint) ([]string, []string, error) {
	if j.authzService == nil {
		return nil, nil, errors.Internal("Authorization service not available")
	}

	// Get user roles
	roles, err := j.authzService.GetRolesForUser(userID)
	if err != nil {
		return nil, nil, err
	}

	// Get user permissions
	permissions, err := j.authzService.GetUserPermissions(userID)
	if err != nil {
		return nil, nil, err
	}

	return roles, permissions, nil
}