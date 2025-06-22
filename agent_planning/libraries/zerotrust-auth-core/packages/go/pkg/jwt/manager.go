// Package jwt provides JWT authentication services with Zero Trust principles.
package jwt

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
)

// Manager handles JWT operations with Zero Trust capabilities
type Manager struct {
	keyManager *KeyManager
	blacklist  Blacklist
	config     *Config
}

// Config represents JWT configuration
type Config struct {
	Secret           string        `json:"-"` // Never serialize secrets
	ExpiryDuration   time.Duration `json:"expiry_duration"`
	RefreshDuration  time.Duration `json:"refresh_duration"`
	Issuer           string        `json:"issuer"`
	RotationDuration time.Duration `json:"rotation_duration"`
}

// Claims represents JWT claims with Zero Trust attributes
type Claims struct {
	UserID      string   `json:"user_id"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	DeviceID    string   `json:"device_id,omitempty"`
	TrustLevel  int      `json:"trust_level"`
	jwt.RegisteredClaims
}

// Token represents a complete token response
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	TrustLevel   int       `json:"trust_level"`
}

// TokenRequest represents a token generation request
type TokenRequest struct {
	UserID      string   `json:"user_id" validate:"required"`
	Email       string   `json:"email" validate:"required,email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	DeviceID    string   `json:"device_id,omitempty"`
	TrustLevel  int      `json:"trust_level" validate:"min=0,max=100"`
}

// Key represents a JWT signing key with metadata
type Key struct {
	ID        string    `json:"id"`
	Key       []byte    `json:"-"` // Never serialize the actual key
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IsActive  bool      `json:"is_active"`
}

// KeyManager manages JWT signing keys with rotation support
type KeyManager struct {
	mu           sync.RWMutex
	keys         map[string]*Key
	currentKeyID string
	rotationDur  time.Duration
}

// Blacklist interface for token blacklisting
type Blacklist interface {
	Add(ctx context.Context, jti, reason string, expiresAt time.Time) error
	IsBlacklisted(ctx context.Context, tokenString string) (bool, error)
	Remove(ctx context.Context, jti string) error
	Cleanup(ctx context.Context) error
}

// Custom errors
var (
	ErrTokenBlacklisted = fmt.Errorf("token has been blacklisted")
	ErrInvalidToken     = fmt.Errorf("invalid token")
	ErrExpiredToken     = fmt.Errorf("token has expired")
	ErrTokenNotActive   = fmt.Errorf("token not yet active")
)

// NewManager creates a new JWT manager with Zero Trust capabilities
func NewManager(config *Config) (*Manager, error) {
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	keyManager := NewKeyManager([]byte(config.Secret), config.RotationDuration)
	blacklist := NewMemoryBlacklist() // Default implementation

	return &Manager{
		keyManager: keyManager,
		blacklist:  blacklist,
		config:     config,
	}, nil
}

// validateConfig validates the JWT configuration
func validateConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	if len(config.Secret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 characters")
	}
	if config.ExpiryDuration <= 0 {
		return fmt.Errorf("expiry duration must be positive")
	}
	if config.RefreshDuration <= 0 {
		return fmt.Errorf("refresh duration must be positive")
	}
	if config.Issuer == "" {
		return fmt.Errorf("issuer cannot be empty")
	}
	if config.RotationDuration <= 0 {
		config.RotationDuration = 24 * time.Hour // Default to 24 hours
	}
	return nil
}

// GenerateToken creates a new JWT token with trust level
func (m *Manager) GenerateToken(ctx context.Context, req *TokenRequest) (*Token, error) {
	if err := m.validateTokenRequest(req); err != nil {
		return nil, fmt.Errorf("invalid token request: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(m.config.ExpiryDuration)
	jti := uuid.New().String()

	claims := &Claims{
		UserID:      req.UserID,
		Email:       req.Email,
		Roles:       req.Roles,
		Permissions: req.Permissions,
		DeviceID:    req.DeviceID,
		TrustLevel:  req.TrustLevel,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.config.Issuer,
			Subject:   req.UserID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        jti,
		},
	}

	// Get current signing key
	currentKey := m.keyManager.GetCurrentKey()
	if currentKey == nil {
		return nil, fmt.Errorf("no active signing key available")
	}

	// Create token with key ID in header
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = currentKey.ID

	tokenString, err := token.SignedString(currentKey.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := m.generateRefreshToken(req.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &Token{
		AccessToken:  tokenString,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresAt:    expiresAt,
		TrustLevel:   req.TrustLevel,
	}, nil
}

// validateTokenRequest validates the token generation request
func (m *Manager) validateTokenRequest(req *TokenRequest) error {
	if req == nil {
		return fmt.Errorf("token request cannot be nil")
	}
	if req.UserID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}
	if req.Email == "" {
		return fmt.Errorf("email cannot be empty")
	}
	if req.TrustLevel < 0 || req.TrustLevel > 100 {
		return fmt.Errorf("trust level must be between 0 and 100")
	}
	return nil
}

// ValidateToken validates a JWT token and returns claims
func (m *Manager) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, ErrInvalidToken
	}

	// Check blacklist first
	if blacklisted, err := m.blacklist.IsBlacklisted(ctx, tokenString); err != nil {
		return nil, fmt.Errorf("blacklist check failed: %w", err)
	} else if blacklisted {
		return nil, ErrTokenBlacklisted
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Check for key ID in token header
		if kidInterface, ok := token.Header["kid"]; ok {
			if kid, ok := kidInterface.(string); ok {
				if key := m.keyManager.GetKey(kid); key != nil {
					return key.Key, nil
				}
			}
		}

		// Fallback to current key for tokens without key ID (backward compatibility)
		if currentKey := m.keyManager.GetCurrentKey(); currentKey != nil {
			return currentKey.Key, nil
		}

		return nil, fmt.Errorf("no valid signing key found")
	})

	if err != nil {
		return nil, m.parseJWTError(err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}

// parseJWTError converts JWT errors to custom errors
func (m *Manager) parseJWTError(err error) error {
	errMsg := err.Error()
	if strings.Contains(errMsg, "expired") {
		return ErrExpiredToken
	} else if strings.Contains(errMsg, "not valid yet") {
		return ErrTokenNotActive
	} else if strings.Contains(errMsg, "malformed") {
		return ErrInvalidToken
	}
	return fmt.Errorf("token validation failed: %w", err)
}

// BlacklistToken adds a token to the blacklist
func (m *Manager) BlacklistToken(ctx context.Context, tokenString, reason string) error {
	if tokenString == "" {
		return fmt.Errorf("token string cannot be empty")
	}
	if reason == "" {
		return fmt.Errorf("reason cannot be empty")
	}

	// Extract JTI and expiration from token for efficient blacklisting
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// We don't validate signature here, just extract claims
		return []byte("dummy"), nil
	})

	if err != nil && !strings.Contains(err.Error(), "signature is invalid") {
		return fmt.Errorf("failed to parse token for blacklisting: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		jti, _ := claims["jti"].(string)
		expUnix, _ := claims["exp"].(float64)
		
		if jti == "" {
			return fmt.Errorf("token missing JTI claim")
		}
		
		exp := time.Unix(int64(expUnix), 0)
		return m.blacklist.Add(ctx, jti, reason, exp)
	}

	return fmt.Errorf("failed to extract claims for blacklisting")
}

// generateRefreshToken creates a refresh token
func (m *Manager) generateRefreshToken(userID string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(m.config.RefreshDuration)

	claims := jwt.MapClaims{
		"user_id": userID,
		"type":    "refresh",
		"exp":     expiresAt.Unix(),
		"iat":     now.Unix(),
		"jti":     uuid.New().String(),
	}

	currentKey := m.keyManager.GetCurrentKey()
	if currentKey == nil {
		return "", fmt.Errorf("no active signing key available")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(currentKey.Key)
}

// RefreshToken validates a refresh token and generates new access token
func (m *Manager) RefreshToken(ctx context.Context, refreshToken string, req *TokenRequest) (*Token, error) {
	// Validate refresh token
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		
		currentKey := m.keyManager.GetCurrentKey()
		if currentKey == nil {
			return nil, fmt.Errorf("no active signing key available")
		}
		return currentKey.Key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		tokenType, _ := claims["type"].(string)
		userID, _ := claims["user_id"].(string)
		
		if tokenType != "refresh" {
			return nil, fmt.Errorf("not a refresh token")
		}
		
		if userID != req.UserID {
			return nil, fmt.Errorf("user ID mismatch")
		}

		// Generate new access token
		return m.GenerateToken(ctx, req)
	}

	return nil, fmt.Errorf("invalid refresh token claims")
}

// SetBlacklist sets the blacklist implementation
func (m *Manager) SetBlacklist(blacklist Blacklist) {
	m.blacklist = blacklist
}

// GetConfig returns a copy of the configuration (without secrets)
func (m *Manager) GetConfig() Config {
	return Config{
		ExpiryDuration:   m.config.ExpiryDuration,
		RefreshDuration:  m.config.RefreshDuration,
		Issuer:           m.config.Issuer,
		RotationDuration: m.config.RotationDuration,
	}
}

// KeyManager Implementation

// NewKeyManager creates a new key manager with rotation support
func NewKeyManager(initialSecret []byte, rotationDur time.Duration) *KeyManager {
	keyID := generateKeyID()
	now := time.Now()

	key := &Key{
		ID:        keyID,
		Key:       initialSecret,
		CreatedAt: now,
		ExpiresAt: now.Add(rotationDur * 2), // Allow overlap for token validation
		IsActive:  true,
	}

	return &KeyManager{
		keys:         map[string]*Key{keyID: key},
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

// GetCurrentKey returns the current active signing key
func (km *KeyManager) GetCurrentKey() *Key {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if key, exists := km.keys[km.currentKeyID]; exists && key.IsActive {
		return key
	}
	return nil
}

// GetKey returns a specific key by ID for token validation
func (km *KeyManager) GetKey(keyID string) *Key {
	km.mu.RLock()
	defer km.mu.RUnlock()

	return km.keys[keyID]
}

// RotateKey creates a new signing key and marks it as current
func (km *KeyManager) RotateKey() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Generate new key
	newKeyBytes := make([]byte, 32)
	if _, err := rand.Read(newKeyBytes); err != nil {
		return fmt.Errorf("failed to generate new key: %w", err)
	}

	newKeyID := generateKeyID()
	now := time.Now()

	newKey := &Key{
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
func (km *KeyManager) cleanupExpiredKeys() {
	now := time.Now()
	for keyID, key := range km.keys {
		if now.After(key.ExpiresAt) && keyID != km.currentKeyID {
			delete(km.keys, keyID)
		}
	}
}

// GetStats returns statistics about the key manager
func (km *KeyManager) GetStats() map[string]interface{} {
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