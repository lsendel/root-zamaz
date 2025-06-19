package sdk

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TokenUtils provides utilities for token management
type TokenUtils struct{}

// NewTokenUtils creates a new TokenUtils instance
func NewTokenUtils() *TokenUtils {
	return &TokenUtils{}
}

// IsTokenExpired checks if a token is expired based on expiration time
func (tu *TokenUtils) IsTokenExpired(expiresAt time.Time) bool {
	return time.Now().After(expiresAt)
}

// IsTokenExpiringSoon checks if a token will expire within the specified duration
func (tu *TokenUtils) IsTokenExpiringSoon(expiresAt time.Time, threshold time.Duration) bool {
	return time.Now().Add(threshold).After(expiresAt)
}

// GenerateState generates a random state parameter for OAuth flows
func (tu *TokenUtils) GenerateState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate random state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GenerateCodeVerifier generates a code verifier for PKCE
func (tu *TokenUtils) GenerateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %w", err)
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}

// GenerateCodeChallenge generates a code challenge from a code verifier for PKCE
func (tu *TokenUtils) GenerateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}

// URLUtils provides utilities for URL manipulation
type URLUtils struct{}

// NewURLUtils creates a new URLUtils instance
func NewURLUtils() *URLUtils {
	return &URLUtils{}
}

// BuildAuthURL builds an authorization URL for OAuth flows
func (uu *URLUtils) BuildAuthURL(baseURL, clientID, redirectURI, state string, scopes []string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	u.Path = "/oauth/authorize"
	
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("state", state)
	if len(scopes) > 0 {
		params.Set("scope", strings.Join(scopes, " "))
	}
	
	u.RawQuery = params.Encode()
	return u.String(), nil
}

// BuildAuthURLWithPKCE builds an authorization URL with PKCE for OAuth flows
func (uu *URLUtils) BuildAuthURLWithPKCE(baseURL, clientID, redirectURI, state, codeChallenge string, scopes []string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	u.Path = "/oauth/authorize"
	
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	if len(scopes) > 0 {
		params.Set("scope", strings.Join(scopes, " "))
	}
	
	u.RawQuery = params.Encode()
	return u.String(), nil
}

// ExtractAuthCode extracts authorization code from callback URL
func (uu *URLUtils) ExtractAuthCode(callbackURL string) (code, state string, err error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid callback URL: %w", err)
	}

	params := u.Query()
	
	if errorCode := params.Get("error"); errorCode != "" {
		errorDesc := params.Get("error_description")
		return "", "", fmt.Errorf("authorization error: %s - %s", errorCode, errorDesc)
	}

	code = params.Get("code")
	state = params.Get("state")
	
	if code == "" {
		return "", "", fmt.Errorf("authorization code not found in callback URL")
	}

	return code, state, nil
}

// SecurityUtils provides security-related utilities
type SecurityUtils struct{}

// NewSecurityUtils creates a new SecurityUtils instance
func NewSecurityUtils() *SecurityUtils {
	return &SecurityUtils{}
}

// HashPassword creates a SHA-256 hash of a password (for client-side hashing)
func (su *SecurityUtils) HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// GenerateFingerprint generates a device fingerprint
func (su *SecurityUtils) GenerateFingerprint(userAgent, ip string, additionalData ...string) string {
	data := userAgent + "|" + ip
	for _, extra := range additionalData {
		data += "|" + extra
	}
	
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// SanitizeEmail normalizes an email address
func (su *SecurityUtils) SanitizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// ValidateEmail performs basic email validation
func (su *SecurityUtils) ValidateEmail(email string) bool {
	email = su.SanitizeEmail(email)
	parts := strings.Split(email, "@")
	return len(parts) == 2 && len(parts[0]) > 0 && len(parts[1]) > 0 && strings.Contains(parts[1], ".")
}

// CacheUtils provides caching utilities
type CacheUtils struct{}

// NewCacheUtils creates a new CacheUtils instance
func NewCacheUtils() *CacheUtils {
	return &CacheUtils{}
}

// GenerateCacheKey generates a cache key for token storage
func (cu *CacheUtils) GenerateCacheKey(prefix, userID string) string {
	return fmt.Sprintf("%s:%s", prefix, userID)
}

// GenerateTokenCacheKey generates a cache key for access tokens
func (cu *CacheUtils) GenerateTokenCacheKey(userID string) string {
	return cu.GenerateCacheKey("access_token", userID)
}

// GenerateRefreshTokenCacheKey generates a cache key for refresh tokens
func (cu *CacheUtils) GenerateRefreshTokenCacheKey(userID string) string {
	return cu.GenerateCacheKey("refresh_token", userID)
}

// GenerateSessionCacheKey generates a cache key for session data
func (cu *CacheUtils) GenerateSessionCacheKey(sessionID string) string {
	return cu.GenerateCacheKey("session", sessionID)
}

// ErrorUtils provides error handling utilities
type ErrorUtils struct{}

// NewErrorUtils creates a new ErrorUtils instance
func NewErrorUtils() *ErrorUtils {
	return &ErrorUtils{}
}

// IsAuthenticationError checks if an error is an authentication error
func (eu *ErrorUtils) IsAuthenticationError(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return strings.Contains(strings.ToLower(apiErr.Code), "auth") ||
			   strings.Contains(strings.ToLower(apiErr.Code), "token") ||
			   strings.Contains(strings.ToLower(apiErr.Code), "unauthorized")
	}
	return false
}

// IsRetryableError checks if an error is retryable
func (eu *ErrorUtils) IsRetryableError(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		// Don't retry client errors except rate limiting
		return apiErr.Code == "RATE_LIMITED" || 
			   strings.Contains(strings.ToLower(apiErr.Code), "timeout") ||
			   strings.Contains(strings.ToLower(apiErr.Code), "network")
	}
	return true // Retry non-API errors
}

// GetErrorCode extracts error code from an error
func (eu *ErrorUtils) GetErrorCode(err error) string {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.Code
	}
	return "UNKNOWN_ERROR"
}

// GetErrorMessage extracts error message from an error
func (eu *ErrorUtils) GetErrorMessage(err error) string {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.Message
	}
	return err.Error()
}

// Utils provides a collection of utility functions
type Utils struct {
	Token    *TokenUtils
	URL      *URLUtils
	Security *SecurityUtils
	Cache    *CacheUtils
	Error    *ErrorUtils
}

// NewUtils creates a new Utils instance with all utility collections
func NewUtils() *Utils {
	return &Utils{
		Token:    NewTokenUtils(),
		URL:      NewURLUtils(),
		Security: NewSecurityUtils(),
		Cache:    NewCacheUtils(),
		Error:    NewErrorUtils(),
	}
}