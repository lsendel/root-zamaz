package security

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"net/http"
	"strings"
	"sync"
	"time"

	"mvp.local/pkg/cache"
	"mvp.local/pkg/config"
	"mvp.local/pkg/errors"
	"mvp.local/pkg/observability"
)

// Constants for signature headers
const (
	SignatureHeader          = "X-Signature"
	SignatureTimestampHeader = "X-Signature-Timestamp"
	SignatureKeyIDHeader     = "X-Signature-Key"
	SignatureAlgorithmHeader = "X-Signature-Algorithm"
	SignatureNonceHeader     = "X-Signature-Nonce"

	// Cache key prefix for replay protection
	ReplayCachePrefix = "request_signature_replay:"

	// Default algorithm constants
	AlgorithmHMACSHA256 = "HMAC-SHA256"
	AlgorithmHMACSHA512 = "HMAC-SHA512"
)

// RequestSigner signs HTTP requests using HMAC algorithms
type RequestSigner struct {
	Algorithm string
	KeyID     string
	Key       []byte
	Headers   []string
	obs       *observability.Observability
}

// SigningConfig contains configuration for request signing
type SigningConfig struct {
	KeyID        string
	Secret       string
	Algorithm    string
	Headers      []string
	MaxClockSkew time.Duration
	ReplayWindow time.Duration
}

// SignatureValidation contains validation configuration
type SignatureValidation struct {
	MaxClockSkew time.Duration
	ReplayWindow time.Duration
}

// SignatureValidator verifies signed requests with enhanced security features
type SignatureValidator struct {
	Keys           map[string][]byte
	Headers        []string
	MaxClockSkew   time.Duration
	ReplayWindow   time.Duration
	obs            *observability.Observability
	cache          cache.Cache
	replayProtector *ReplayProtector

	// Deprecated: Use replayProtector instead
	mu   sync.RWMutex
	seen map[string]time.Time
}

// RequestSigningManager manages request signing and validation
type RequestSigningManager struct {
	signer    *RequestSigner
	validator *SignatureValidator
	config    *config.RequestSigningConfig
	obs       *observability.Observability
}

// NewRequestSigner creates a new RequestSigner
func NewRequestSigner(keyID string, key []byte, headers []string) *RequestSigner {
	return &RequestSigner{
		Algorithm: AlgorithmHMACSHA256,
		KeyID:     keyID,
		Key:       key,
		Headers:   headers,
	}
}

// NewRequestSignerWithConfig creates a new RequestSigner from config
func NewRequestSignerWithConfig(config SigningConfig, obs *observability.Observability) *RequestSigner {
	algorithm := config.Algorithm
	if algorithm == "" {
		algorithm = AlgorithmHMACSHA256
	}

	return &RequestSigner{
		Algorithm: algorithm,
		KeyID:     config.KeyID,
		Key:       []byte(config.Secret),
		Headers:   config.Headers,
		obs:       obs,
	}
}

// NewRequestSigningManager creates a new request signing manager
func NewRequestSigningManager(config *config.RequestSigningConfig, obs *observability.Observability, cache cache.Cache) *RequestSigningManager {
	if !config.Enabled {
		return nil
	}

	// Default headers if none specified
	headers := config.Headers
	if len(headers) == 0 {
		headers = []string{"Content-Type", "Content-Length", "Host"}
	}

	// Create signer
	signer := NewRequestSignerWithConfig(SigningConfig{
		KeyID:     config.KeyID,
		Secret:    config.Secret,
		Algorithm: config.Algorithm,
		Headers:   headers,
	}, obs)

	// Create validator with multiple keys support
	keys := map[string][]byte{
		config.KeyID: []byte(config.Secret),
	}

	validator := NewSignatureValidatorWithCache(keys, headers, SignatureValidation{
		MaxClockSkew: config.MaxClockSkew,
		ReplayWindow: config.ReplayWindow,
	}, obs, cache)

	return &RequestSigningManager{
		signer:    signer,
		validator: validator,
		config:    config,
		obs:       obs,
	}
}

// Sign adds signature headers to the request with enhanced security
func (s *RequestSigner) Sign(req *http.Request) error {
	start := time.Now()

	// Generate timestamp and nonce
	ts := time.Now().UTC().Format(time.RFC3339)
	nonce := generateNonce()

	// Add signature headers first so they're included in canonical string
	req.Header.Set(SignatureTimestampHeader, ts)
	req.Header.Set(SignatureKeyIDHeader, s.KeyID)
	req.Header.Set(SignatureAlgorithmHeader, s.Algorithm)
	req.Header.Set(SignatureNonceHeader, nonce)

	// Build canonical string including new headers
	canonical := s.buildCanonicalString(req, ts, nonce)

	// Select hash function based on algorithm
	hasher, err := s.getHashFunc()
	if err != nil {
		return errors.Internal("unsupported signature algorithm").WithDetails(s.Algorithm)
	}

	// Generate HMAC signature
	mac := hmac.New(hasher, s.Key)
	if _, err := mac.Write([]byte(canonical)); err != nil {
		return errors.Internal("failed to generate signature").WithDetails(err.Error())
	}

	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	req.Header.Set(SignatureHeader, sig)

	// Log signing operation if observability is available
	if s.obs != nil {
		duration := time.Since(start)
		s.obs.Logger.Debug().
			Str("key_id", s.KeyID).
			Str("algorithm", s.Algorithm).
			Dur("duration", duration).
			Msg("Request signed successfully")
	}

	return nil
}

// getHashFunc returns the appropriate hash function for the algorithm
func (s *RequestSigner) getHashFunc() (func() hash.Hash, error) {
	switch s.Algorithm {
	case AlgorithmHMACSHA256:
		return sha256.New, nil
	case AlgorithmHMACSHA512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", s.Algorithm)
	}
}

// buildCanonicalString creates the canonical representation for signing
func (s *RequestSigner) buildCanonicalString(req *http.Request, ts, nonce string) string {
	var b strings.Builder

	// HTTP method
	b.WriteString(strings.ToUpper(req.Method))
	b.WriteString("\n")

	// Request URI (path + query)
	b.WriteString(req.URL.RequestURI())
	b.WriteString("\n")

	// Timestamp
	b.WriteString(ts)
	b.WriteString("\n")

	// Nonce
	b.WriteString(nonce)
	b.WriteString("\n")

	// Host header (always include for security)
	b.WriteString("host:")
	b.WriteString(strings.ToLower(req.Host))
	b.WriteString("\n")

	// Include specified headers in canonical form
	for _, header := range s.Headers {
		headerName := strings.ToLower(header)
		headerValue := strings.TrimSpace(req.Header.Get(header))
		b.WriteString(headerName)
		b.WriteString(":")
		b.WriteString(headerValue)
		b.WriteString("\n")
	}

	return b.String()
}

// NewSignatureValidator creates a validator for signed requests
func NewSignatureValidator(keys map[string][]byte, headers []string, v SignatureValidation) *SignatureValidator {
	return &SignatureValidator{
		Keys:         keys,
		Headers:      headers,
		MaxClockSkew: v.MaxClockSkew,
		ReplayWindow: v.ReplayWindow,
		seen:         make(map[string]time.Time),
	}
}

// NewSignatureValidatorWithCache creates a validator with caching support for replay protection
func NewSignatureValidatorWithCache(keys map[string][]byte, headers []string, v SignatureValidation, obs *observability.Observability, cache cache.Cache) *SignatureValidator {
	validator := &SignatureValidator{
		Keys:         keys,
		Headers:      headers,
		MaxClockSkew: v.MaxClockSkew,
		ReplayWindow: v.ReplayWindow,
		obs:          obs,
		cache:        cache,
		seen:         make(map[string]time.Time), // Kept for backward compatibility
	}
	
	// Create replay protector with automatic cleanup
	if v.ReplayWindow > 0 {
		validator.replayProtector = NewReplayProtector(cache, v.ReplayWindow, obs)
	}
	
	return validator
}

// Validate checks the signature on the request with enhanced security
func (v *SignatureValidator) Validate(req *http.Request) error {
	start := time.Now()

	// Extract and validate all required headers
	headers := v.extractSignatureHeaders(req)
	if err := v.validateHeaders(headers); err != nil {
		v.logValidationFailure("header_validation_failed", err)
		return err
	}

	// Validate timestamp and clock skew
	if err := v.validateTimestamp(headers.Timestamp); err != nil {
		v.logValidationFailure("timestamp_validation_failed", err)
		return err
	}

	// Get signing key
	key, ok := v.Keys[headers.KeyID]
	if !ok {
		err := errors.Authentication("unknown signature key").WithDetails(headers.KeyID)
		v.logValidationFailure("unknown_key", err)
		return err
	}

	// Check for replay attacks
	if err := v.checkReplayAttack(headers.Signature, headers.Nonce); err != nil {
		v.logValidationFailure("replay_attack_detected", err)
		return err
	}

	// Validate signature
	if err := v.validateSignature(req, headers, key); err != nil {
		v.logValidationFailure("signature_validation_failed", err)
		return err
	}

	// Record successful validation
	v.recordValidationSuccess(start, headers.KeyID, headers.Algorithm)

	return nil
}

// SignatureHeaders contains extracted signature headers
type SignatureHeaders struct {
	Signature string
	Timestamp string
	KeyID     string
	Algorithm string
	Nonce     string
}

// extractSignatureHeaders extracts all signature-related headers
func (v *SignatureValidator) extractSignatureHeaders(req *http.Request) SignatureHeaders {
	return SignatureHeaders{
		Signature: req.Header.Get(SignatureHeader),
		Timestamp: req.Header.Get(SignatureTimestampHeader),
		KeyID:     req.Header.Get(SignatureKeyIDHeader),
		Algorithm: req.Header.Get(SignatureAlgorithmHeader),
		Nonce:     req.Header.Get(SignatureNonceHeader),
	}
}

// validateHeaders validates that all required headers are present
func (v *SignatureValidator) validateHeaders(headers SignatureHeaders) error {
	if headers.Signature == "" {
		return errors.Authentication("missing signature header")
	}
	if headers.Timestamp == "" {
		return errors.Authentication("missing signature timestamp")
	}
	if headers.KeyID == "" {
		return errors.Authentication("missing signature key ID")
	}
	if headers.Algorithm == "" {
		return errors.Authentication("missing signature algorithm")
	}
	if headers.Nonce == "" {
		return errors.Authentication("missing signature nonce")
	}

	// Validate algorithm
	if headers.Algorithm != AlgorithmHMACSHA256 && headers.Algorithm != AlgorithmHMACSHA512 {
		return errors.Authentication("unsupported signature algorithm").WithDetails(headers.Algorithm)
	}

	return nil
}

// validateTimestamp checks timestamp validity and clock skew
func (v *SignatureValidator) validateTimestamp(tsStr string) error {
	ts, err := time.Parse(time.RFC3339, tsStr)
	if err != nil {
		return errors.Authentication("invalid signature timestamp format").WithDetails(err.Error())
	}

	now := time.Now().UTC()

	// Check if timestamp is within acceptable clock skew
	if ts.Before(now.Add(-v.MaxClockSkew)) {
		return errors.Authentication("signature timestamp too old")
	}
	if ts.After(now.Add(v.MaxClockSkew)) {
		return errors.Authentication("signature timestamp too far in future")
	}

	return nil
}

// checkReplayAttack checks for replay attacks using the replay protector
func (v *SignatureValidator) checkReplayAttack(signature, nonce string) error {
	if v.ReplayWindow <= 0 {
		return nil // Replay protection disabled
	}

	// Create unique key for this request (signature + nonce combination)
	replayKey := fmt.Sprintf("%s:%s", signature, nonce)

	// Use replay protector if available (preferred)
	if v.replayProtector != nil {
		ctx := context.Background()
		return v.replayProtector.CheckAndStore(ctx, replayKey)
	}

	// Fallback to legacy implementation for backward compatibility
	// This path should rarely be used in practice
	return v.checkReplayAttackLegacy(replayKey)
}

// checkReplayAttackLegacy is the legacy replay protection implementation
// Deprecated: Use replayProtector instead
func (v *SignatureValidator) checkReplayAttackLegacy(replayKey string) error {
	// Try cache-based replay protection first
	if v.cache != nil {
		ctx := context.Background()
		cacheKey := ReplayCachePrefix + replayKey

		exists, err := v.cache.Exists(ctx, cacheKey)
		if err == nil {
			if exists {
				return errors.Authentication("replay attack detected")
			}
			// Store in cache for replay window duration
			_ = v.cache.Set(ctx, cacheKey, []byte("1"), v.ReplayWindow)
			return nil
		}
		// Fall through to in-memory protection if cache fails
	}

	// Fallback to in-memory replay protection
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()

	// Clean up old entries first
	for key, timestamp := range v.seen {
		if now.Sub(timestamp) > v.ReplayWindow {
			delete(v.seen, key)
		}
	}

	// Check if this request was seen before
	if timestamp, found := v.seen[replayKey]; found && now.Sub(timestamp) < v.ReplayWindow {
		return errors.Authentication("replay attack detected")
	}

	// Record this request
	v.seen[replayKey] = now

	return nil
}

// validateSignature validates the HMAC signature
func (v *SignatureValidator) validateSignature(req *http.Request, headers SignatureHeaders, key []byte) error {
	// Get hash function for the specified algorithm
	hasher, err := v.getHashFunc(headers.Algorithm)
	if err != nil {
		return errors.Authentication("unsupported signature algorithm").WithDetails(headers.Algorithm)
	}

	// Rebuild canonical string
	canonical := v.buildCanonicalString(req, headers.Timestamp, headers.Nonce)

	// Generate expected signature
	mac := hmac.New(hasher, key)
	if _, err := mac.Write([]byte(canonical)); err != nil {
		return errors.Internal("failed to generate expected signature").WithDetails(err.Error())
	}

	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// Compare signatures using constant-time comparison
	if !hmac.Equal([]byte(headers.Signature), []byte(expected)) {
		return errors.Authentication("invalid request signature")
	}

	return nil
}

// getHashFunc returns the hash function for the specified algorithm
func (v *SignatureValidator) getHashFunc(algorithm string) (func() hash.Hash, error) {
	switch algorithm {
	case AlgorithmHMACSHA256:
		return sha256.New, nil
	case AlgorithmHMACSHA512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// buildCanonicalString builds the canonical string for validation (same as signer)
func (v *SignatureValidator) buildCanonicalString(req *http.Request, ts, nonce string) string {
	var b strings.Builder

	// HTTP method
	b.WriteString(strings.ToUpper(req.Method))
	b.WriteString("\n")

	// Request URI (path + query)
	b.WriteString(req.URL.RequestURI())
	b.WriteString("\n")

	// Timestamp
	b.WriteString(ts)
	b.WriteString("\n")

	// Nonce
	b.WriteString(nonce)
	b.WriteString("\n")

	// Host header (always include for security)
	b.WriteString("host:")
	b.WriteString(strings.ToLower(req.Host))
	b.WriteString("\n")

	// Include specified headers in canonical form
	for _, header := range v.Headers {
		headerName := strings.ToLower(header)
		headerValue := strings.TrimSpace(req.Header.Get(header))
		b.WriteString(headerName)
		b.WriteString(":")
		b.WriteString(headerValue)
		b.WriteString("\n")
	}

	return b.String()
}

// logValidationFailure logs validation failures with observability
func (v *SignatureValidator) logValidationFailure(reason string, err error) {
	if v.obs != nil {
		v.obs.Logger.Warn().
			Str("reason", reason).
			Err(err).
			Msg("Request signature validation failed")
	}
}

// recordValidationSuccess logs successful validations
func (v *SignatureValidator) recordValidationSuccess(start time.Time, keyID, algorithm string) {
	if v.obs != nil {
		duration := time.Since(start)
		v.obs.Logger.Debug().
			Str("key_id", keyID).
			Str("algorithm", algorithm).
			Dur("duration", duration).
			Msg("Request signature validated successfully")
	}
}

// Manager methods

// GetSigner returns the request signer
func (m *RequestSigningManager) GetSigner() *RequestSigner {
	return m.signer
}

// GetValidator returns the signature validator
func (m *RequestSigningManager) GetValidator() *SignatureValidator {
	return m.validator
}

// SignRequest signs an HTTP request
func (m *RequestSigningManager) SignRequest(req *http.Request) error {
	if m.signer == nil {
		return errors.Internal("request signer not initialized")
	}
	return m.signer.Sign(req)
}

// ValidateRequest validates a signed HTTP request
func (m *RequestSigningManager) ValidateRequest(req *http.Request) error {
	if m.validator == nil {
		return errors.Internal("signature validator not initialized")
	}
	return m.validator.Validate(req)
}

// IsEnabled returns whether request signing is enabled
func (m *RequestSigningManager) IsEnabled() bool {
	return m.config != nil && m.config.Enabled
}

// GetConfig returns the request signing configuration
func (m *RequestSigningManager) GetConfig() *config.RequestSigningConfig {
	return m.config
}

// AddKey adds a new signing key to the validator
func (m *RequestSigningManager) AddKey(keyID string, key []byte) {
	if m.validator != nil {
		m.validator.mu.Lock()
		defer m.validator.mu.Unlock()
		m.validator.Keys[keyID] = key
	}
}

// RemoveKey removes a signing key from the validator
func (m *RequestSigningManager) RemoveKey(keyID string) {
	if m.validator != nil {
		m.validator.mu.Lock()
		defer m.validator.mu.Unlock()
		delete(m.validator.Keys, keyID)
	}
}

// ClearReplayCache clears the replay protection cache
func (m *RequestSigningManager) ClearReplayCache() error {
	if m.validator == nil {
		return nil
	}

	// Clear cache-based replay protection
	if m.validator.cache != nil {
		ctx := context.Background()
		pattern := ReplayCachePrefix + "*"
		if keys, err := m.validator.cache.Keys(ctx, pattern); err == nil {
			for _, key := range keys {
				_ = m.validator.cache.Delete(ctx, key)
			}
		}
	}

	// Clear in-memory replay protection
	m.validator.mu.Lock()
	defer m.validator.mu.Unlock()
	m.validator.seen = make(map[string]time.Time)

	return nil
}

// GetSigningStats returns statistics about request signing
func (m *RequestSigningManager) GetSigningStats() map[string]interface{} {
	stats := map[string]interface{}{
		"enabled": m.IsEnabled(),
	}

	if m.config != nil {
		stats["algorithm"] = m.config.Algorithm
		stats["key_id"] = m.config.KeyID
		stats["max_clock_skew"] = m.config.MaxClockSkew.String()
		stats["replay_window"] = m.config.ReplayWindow.String()
		stats["headers"] = m.config.Headers
	}

	if m.validator != nil {
		m.validator.mu.RLock()
		stats["num_keys"] = len(m.validator.Keys)
		stats["num_replay_entries"] = len(m.validator.seen)
		m.validator.mu.RUnlock()
	}

	return stats
}

// Utility functions

// generateNonce generates a cryptographically secure nonce
func generateNonce() string {
	// Use current time in nanoseconds plus a simple counter for uniqueness
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
