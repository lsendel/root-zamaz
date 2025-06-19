package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"

	"mvp.local/pkg/errors"
)

// Constants for signature headers
const (
	SignatureHeader          = "X-Signature"
	SignatureTimestampHeader = "X-Signature-Timestamp"
	SignatureKeyIDHeader     = "X-Signature-Key"
)

// RequestSigner signs HTTP requests using HMAC-SHA256.
type RequestSigner struct {
	Algorithm string
	KeyID     string
	Key       []byte
	Headers   []string
}

// SignatureValidation defines validation parameters.
type SignatureValidation struct {
	MaxClockSkew time.Duration
	ReplayWindow time.Duration
}

// SignatureValidator verifies signed requests.
type SignatureValidator struct {
	Keys         map[string][]byte
	Headers      []string
	MaxClockSkew time.Duration
	ReplayWindow time.Duration

	mu   sync.Mutex
	seen map[string]time.Time
}

// NewRequestSigner creates a new RequestSigner.
func NewRequestSigner(keyID string, key []byte, headers []string) *RequestSigner {
	return &RequestSigner{
		Algorithm: "HMAC-SHA256",
		KeyID:     keyID,
		Key:       key,
		Headers:   headers,
	}
}

// Sign adds signature headers to the request.
func (s *RequestSigner) Sign(req *http.Request) error {
	ts := time.Now().UTC().Format(time.RFC3339)
	canonical := buildCanonicalString(req, ts, s.Headers)

	mac := hmac.New(sha256.New, s.Key)
	_, err := mac.Write([]byte(canonical))
	if err != nil {
		return errors.Internal("failed to sign request")
	}
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	req.Header.Set(SignatureHeader, sig)
	req.Header.Set(SignatureTimestampHeader, ts)
	req.Header.Set(SignatureKeyIDHeader, s.KeyID)
	return nil
}

// NewSignatureValidator creates a validator for signed requests.
func NewSignatureValidator(keys map[string][]byte, headers []string, v SignatureValidation) *SignatureValidator {
	return &SignatureValidator{
		Keys:         keys,
		Headers:      headers,
		MaxClockSkew: v.MaxClockSkew,
		ReplayWindow: v.ReplayWindow,
		seen:         make(map[string]time.Time),
	}
}

// Validate checks the signature on the request.
func (v *SignatureValidator) Validate(req *http.Request) error {
	tsStr := req.Header.Get(SignatureTimestampHeader)
	if tsStr == "" {
		return errors.Authentication("missing signature timestamp")
	}
	ts, err := time.Parse(time.RFC3339, tsStr)
	if err != nil {
		return errors.Authentication("invalid signature timestamp")
	}
	now := time.Now().UTC()
	if ts.Before(now.Add(-v.MaxClockSkew)) || ts.After(now.Add(v.MaxClockSkew)) {
		return errors.Authentication("signature timestamp out of range")
	}

	keyID := req.Header.Get(SignatureKeyIDHeader)
	key, ok := v.Keys[keyID]
	if !ok {
		return errors.Authentication("unknown signature key")
	}

	sig := req.Header.Get(SignatureHeader)
	if sig == "" {
		return errors.Authentication("missing signature header")
	}

	canonical := buildCanonicalString(req, tsStr, v.Headers)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(canonical))
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return errors.Authentication("invalid request signature")
	}

	// Replay protection
	if v.ReplayWindow > 0 {
		v.mu.Lock()
		defer v.mu.Unlock()
		if t, found := v.seen[sig]; found && now.Sub(t) < v.ReplayWindow {
			return errors.Authentication("replay attack detected")
		}
		v.seen[sig] = now
	}

	return nil
}

func buildCanonicalString(req *http.Request, ts string, headers []string) string {
	var b strings.Builder
	b.WriteString(req.Method)
	b.WriteString("\n")
	b.WriteString(req.URL.RequestURI())
	b.WriteString("\n")
	b.WriteString(ts)
	b.WriteString("\n")
	for _, h := range headers {
		b.WriteString(strings.ToLower(h))
		b.WriteString(":")
		b.WriteString(req.Header.Get(h))
		b.WriteString("\n")
	}
	return b.String()
}
