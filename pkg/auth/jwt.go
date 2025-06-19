// Package auth provides JWT authentication services for the MVP Zero Trust Auth system.
// It includes token generation, validation, refresh, and claims management.
package auth

import (
	"fmt"
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
	UserID      string   `json:"user_id"`
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
	Token        string       `json:"token"`
	RefreshToken string       `json:"refresh_token"`
	User         *models.User `json:"user"`
	ExpiresAt    time.Time    `json:"expires_at"`
}

// RefreshRequest represents a token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// JWTService handles JWT operations
type JWTService struct {
	config         *config.JWTConfig
	authzService   AuthorizationInterface
	secret         []byte
	refreshSecret  []byte
	expiryDuration time.Duration
	refreshExpiry  time.Duration
}

// JWTServiceInterface defines the contract for JWT operations
type JWTServiceInterface interface {
	GenerateToken(user *models.User, roles []string, permissions []string) (*LoginResponse, error)
	GenerateRefreshToken(userID string) (string, error)
	ValidateToken(tokenString string) (*JWTClaims, error)
	ValidateRefreshToken(tokenString string) (string, error)
	RefreshAccessToken(refreshToken string, user *models.User, roles []string, permissions []string) (*LoginResponse, error)
	HashPassword(password string) (string, error)
	CheckPassword(hashedPassword, password string) error
	GetUserRolesAndPermissions(userID string) ([]string, []string, error)
}

// NewJWTService creates a new JWT service
func NewJWTService(config *config.JWTConfig, authzService AuthorizationInterface) *JWTService {
	secret := []byte(config.Secret)
	if len(secret) == 0 {
		panic("JWT secret is required and must be set via JWT_SECRET environment variable")
	}

	refreshSecret := []byte(config.Secret + "-refresh")

	return &JWTService{
		config:         config,
		authzService:   authzService,
		secret:         secret,
		refreshSecret:  refreshSecret,
		expiryDuration: config.ExpiryDuration,
		refreshExpiry:  time.Hour * 24 * 7, // 7 days for refresh token
	}
}

// GenerateToken generates a new JWT access token and returns a complete login response
func (j *JWTService) GenerateToken(user *models.User, roles []string, permissions []string) (*LoginResponse, error) {
	if j == nil {
		return nil, fmt.Errorf("JWT service is nil")
	}
	if j.config == nil {
		return nil, fmt.Errorf("JWT config is nil")
	}
	if user == nil {
		return nil, fmt.Errorf("user is nil")
	}

	now := time.Now()
	expiresAt := now.Add(j.expiryDuration)

	// Default device ID and trust level if not provided
	deviceID := ""
	trustLevel := 50

	claims := &JWTClaims{
		UserID:      user.ID,
		Username:    user.Username,
		Email:       user.Email,
		Roles:       roles,
		Permissions: permissions,
		DeviceID:    deviceID,
		TrustLevel:  trustLevel,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        fmt.Sprintf("%s-%d", user.ID, now.Unix()),
			Subject:   user.ID,
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
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to sign JWT token")
	}

	// Generate refresh token
	refreshToken, err := j.GenerateRefreshToken(user.ID)
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

// GenerateRefreshToken generates a new JWT refresh token
func (j *JWTService) GenerateRefreshToken(userID string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(j.refreshExpiry)

	claims := &jwt.RegisteredClaims{
		ID:        fmt.Sprintf("refresh-%s-%d", userID, now.Unix()),
		Subject:   userID,
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
func (j *JWTService) ValidateRefreshToken(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.refreshSecret, nil
	})

	if err != nil {
		return "", errors.Wrap(err, errors.CodeUnauthorized, "Invalid refresh token")
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		return claims.Subject, nil
	}

	return "", errors.Unauthorized("Invalid refresh token claims")
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
	tokenResponse, err := j.GenerateToken(user, roles, permissions)
	if err != nil {
		return nil, err
	}

	return tokenResponse, nil
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
func (j *JWTService) GetUserRolesAndPermissions(userID string) ([]string, []string, error) {
	if j == nil {
		return nil, nil, fmt.Errorf("JWT service is nil")
	}
	if j.authzService == nil {
		// Return empty roles and permissions when authorization service is disabled
		return []string{}, []string{}, nil
	}

	// Check if the interface contains a nil pointer using type assertion
	// This happens when a nil *AuthorizationService is assigned to the interface
	if authz, ok := j.authzService.(*AuthorizationService); ok && authz == nil {
		// Return empty roles and permissions when authorization service is disabled
		return []string{}, []string{}, nil
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
