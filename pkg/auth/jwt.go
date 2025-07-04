// Package auth provides JWT authentication services for the MVP Zero Trust Auth system.
// It includes token generation, validation, refresh, and claims management.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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

// JWTKey represents a JWT signing key with metadata
type JWTKey struct {
	ID        string    `json:"id"`
	Key       []byte    `json:"-"` // Never marshal the actual key
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IsActive  bool      `json:"is_active"`
}

// JWTKeyManager manages multiple JWT keys for rotation
type JWTKeyManager struct {
	mu           sync.RWMutex
	keys         map[string]*JWTKey
	currentKeyID string
	rotationDur  time.Duration
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
	keyManager     *JWTKeyManager
	refreshSecret  []byte
	expiryDuration time.Duration
	refreshExpiry  time.Duration
	blacklist      *JWTBlacklist
}

// JWTServiceInterface defines the contract for JWT operations
type JWTServiceInterface interface {
	GenerateToken(user *models.User, roles []string, permissions []string) (*LoginResponse, error)
	GenerateTokenPair(userID, email string, roles []models.Role) (*LoginResponse, error)
	GenerateRefreshToken(userID string) (string, error)
	ValidateToken(tokenString string) (*JWTClaims, error)
	ValidateRefreshToken(tokenString string) (string, error)
	RefreshAccessToken(refreshToken string, user *models.User, roles []string, permissions []string) (*LoginResponse, error)
	HashPassword(password string) (string, error)
	CheckPassword(hashedPassword, password string) error
	GetUserRolesAndPermissions(userID string) ([]string, []string, error)
	RotateKey() error
	GetKeyManagerStats() map[string]interface{}
	SetBlacklist(blacklist *JWTBlacklist)
	BlacklistToken(ctx context.Context, tokenString, userID, reason string, expiresAt time.Time) error
	BlacklistUserTokens(ctx context.Context, userID, reason string) error
	IsTokenBlacklisted(ctx context.Context, tokenString string) (bool, error)
}

// NewJWTKeyManager creates a new JWT key manager with rotation support
func NewJWTKeyManager(initialSecret []byte, rotationDur time.Duration) *JWTKeyManager {
	keyID := generateKeyID()
	now := time.Now()

	key := &JWTKey{
		ID:        keyID,
		Key:       initialSecret,
		CreatedAt: now,
		ExpiresAt: now.Add(rotationDur * 2), // Allow overlap for token validation
		IsActive:  true,
	}

	return &JWTKeyManager{
		keys:         map[string]*JWTKey{keyID: key},
		currentKeyID: keyID,
		rotationDur:  rotationDur,
	}
}

// generateKeyID creates a unique key identifier
func generateKeyID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

// NewJWTService creates a new JWT service
func NewJWTService(config *config.JWTConfig, authzService AuthorizationInterface) (*JWTService, error) {
	secret := []byte(config.Secret)
	if len(secret) == 0 {
		return nil, fmt.Errorf("JWT secret is required and must be set via JWT_SECRET environment variable")
	}

	refreshSecret := []byte(config.Secret + "-refresh")

	// Initialize key manager with 24-hour rotation
	keyManager := NewJWTKeyManager(secret, 24*time.Hour)

	return &JWTService{
		config:         config,
		authzService:   authzService,
		keyManager:     keyManager,
		refreshSecret:  refreshSecret,
		expiryDuration: config.ExpiryDuration,
		refreshExpiry:  time.Hour * 24 * 7, // 7 days for refresh token
	}, nil
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
	// For backward compatibility, use medium trust level when no factors are provided
	// New code should use GenerateTokenWithTrust for proper trust calculation
	deviceID := ""
	trustLevel := int(TrustLevelMedium) // 50 - Known device, no attestation

	claims := j.buildAccessTokenClaims(user, roles, permissions, deviceID, trustLevel, expiresAt)

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

// GenerateTokenPair generates a JWT token pair (access + refresh) for a user
func (j *JWTService) GenerateTokenPair(userID, email string, roles []models.Role) (*LoginResponse, error) {
	// Parse UUID
	parsedID, err := uuid.Parse(userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "Invalid user ID format")
	}

	// Create a User object for the existing GenerateToken method
	user := &models.User{
		ID:    parsedID,
		Email: email,
		Roles: roles,
	}

	// Extract role names and permissions
	roleNames := make([]string, len(roles))
	var allPermissions []string
	permissionSet := make(map[string]bool)

	for i, role := range roles {
		roleNames[i] = role.Name
		for _, perm := range role.Permissions {
			permKey := perm.Resource + ":" + perm.Action
			if !permissionSet[permKey] {
				allPermissions = append(allPermissions, permKey)
				permissionSet[permKey] = true
			}
		}
	}

	return j.GenerateToken(user, roleNames, allPermissions)
}

// GenerateRefreshToken generates a new JWT refresh token
func (j *JWTService) GenerateRefreshToken(userID string) (string, error) {
	expiresAt := time.Now().Add(j.refreshExpiry)
	claims := j.buildRefreshTokenClaims(userID, expiresAt)

	tokenString, err := j.generateTokenFromClaims(claims, j.refreshSecret, "")
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "Failed to sign JWT refresh token")
	}

	return tokenString, nil
}

// ValidateToken validates and parses a JWT access token
func (j *JWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	// Check blacklist first (if available)
	if j.blacklist != nil {
		ctx := context.Background()
		if blacklisted, err := j.blacklist.IsTokenBlacklisted(ctx, tokenString); err == nil && blacklisted {
			return nil, errors.Unauthorized("Token has been revoked")
		}
	}

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Check for key ID in token header
		if kidInterface, ok := token.Header["kid"]; ok {
			if kid, ok := kidInterface.(string); ok {
				// Look up key by ID
				if key := j.keyManager.GetKey(kid); key != nil {
					return key.Key, nil
				}
			}
		}

		// Fallback to current key for tokens without key ID (backward compatibility)
		if currentKey := j.keyManager.GetCurrentKey(); currentKey != nil {
			return currentKey.Key, nil
		}

		return nil, fmt.Errorf("no valid signing key found")
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
		// Additional blacklist check for user-wide blacklisting
		if j.blacklist != nil {
			ctx := context.Background()
			if userBlacklisted, err := j.blacklist.IsUserTokensBlacklisted(ctx, claims.UserID); err == nil && userBlacklisted {
				return nil, errors.Unauthorized("All user tokens have been revoked")
			}
		}

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

	if userID != user.ID.String() {
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

// Key Manager Methods

// GetCurrentKey returns the current active signing key
func (km *JWTKeyManager) GetCurrentKey() *JWTKey {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if key, exists := km.keys[km.currentKeyID]; exists {
		return key
	}
	return nil
}

// GetKey returns a specific key by ID for token validation
func (km *JWTKeyManager) GetKey(keyID string) *JWTKey {
	km.mu.RLock()
	defer km.mu.RUnlock()

	return km.keys[keyID]
}

// RotateKey creates a new signing key and marks it as current
func (km *JWTKeyManager) RotateKey() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Generate new key
	newKeyBytes := make([]byte, 32)
	if _, err := rand.Read(newKeyBytes); err != nil {
		return fmt.Errorf("failed to generate new key: %w", err)
	}

	newKeyID := generateKeyID()
	now := time.Now()

	newKey := &JWTKey{
		ID:        newKeyID,
		Key:       newKeyBytes,
		CreatedAt: now,
		ExpiresAt: now.Add(km.rotationDur * 2), // Allow overlap for token validation
		IsActive:  true,
	}

	// Mark current key as inactive
	if currentKey, exists := km.keys[km.currentKeyID]; exists {
		currentKey.IsActive = false
	}

	// Add new key and update current
	km.keys[newKeyID] = newKey
	km.currentKeyID = newKeyID

	// Clean up expired keys
	km.cleanupExpiredKeys()

	return nil
}

// cleanupExpiredKeys removes keys that are past their expiration time
func (km *JWTKeyManager) cleanupExpiredKeys() {
	now := time.Now()
	for keyID, key := range km.keys {
		if now.After(key.ExpiresAt) && keyID != km.currentKeyID {
			delete(km.keys, keyID)
		}
	}
}

// GetStats returns statistics about the key manager
func (km *JWTKeyManager) GetStats() map[string]interface{} {
	km.mu.RLock()
	defer km.mu.RUnlock()

	activeKeys := 0
	expiredKeys := 0
	now := time.Now()

	for _, key := range km.keys {
		if key.IsActive && now.Before(key.ExpiresAt) {
			activeKeys++
		} else if now.After(key.ExpiresAt) {
			expiredKeys++
		}
	}

	return map[string]interface{}{
		"total_keys":      len(km.keys),
		"active_keys":     activeKeys,
		"expired_keys":    expiredKeys,
		"current_key_id":  km.currentKeyID,
		"rotation_period": km.rotationDur.String(),
	}
}

// JWT Service key rotation methods

// RotateKey rotates the JWT signing key
func (j *JWTService) RotateKey() error {
	return j.keyManager.RotateKey()
}

// GetKeyManagerStats returns key manager statistics
func (j *JWTService) GetKeyManagerStats() map[string]interface{} {
	return j.keyManager.GetStats()
}

// Blacklist methods

// SetBlacklist sets the JWT blacklist service
func (j *JWTService) SetBlacklist(blacklist *JWTBlacklist) {
	j.blacklist = blacklist
}

// BlacklistToken adds a token to the blacklist
func (j *JWTService) BlacklistToken(ctx context.Context, tokenString, userID, reason string, expiresAt time.Time) error {
	if j.blacklist == nil {
		return errors.Internal("JWT blacklist not configured")
	}

	return j.blacklist.BlacklistToken(ctx, tokenString, userID, reason, expiresAt)
}

// BlacklistUserTokens blacklists all tokens for a user
func (j *JWTService) BlacklistUserTokens(ctx context.Context, userID, reason string) error {
	if j.blacklist == nil {
		return errors.Internal("JWT blacklist not configured")
	}

	// Calculate maximum possible token expiry (current time + max token lifetime)
	maxTokenExpiry := time.Now().Add(j.expiryDuration)

	return j.blacklist.BlacklistUserTokens(ctx, userID, reason, maxTokenExpiry)
}

// IsTokenBlacklisted checks if a token is blacklisted
func (j *JWTService) IsTokenBlacklisted(ctx context.Context, tokenString string) (bool, error) {
	if j.blacklist == nil {
		return false, nil
	}

	return j.blacklist.IsTokenBlacklisted(ctx, tokenString)
}
