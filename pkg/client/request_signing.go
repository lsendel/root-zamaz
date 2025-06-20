// Package client provides HTTP client utilities with request signing support for the MVP Zero Trust Auth system.
package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"mvp.local/pkg/config"
	"mvp.local/pkg/observability"
	"mvp.local/pkg/security"
)

// SigningHTTPClient is an HTTP client that automatically signs requests
type SigningHTTPClient struct {
	client *http.Client
	signer *security.RequestSigner
	obs    *observability.Observability
}

// ClientConfig contains configuration for the signing HTTP client
type ClientConfig struct {
	KeyID      string
	Secret     string
	Algorithm  string
	Headers    []string
	Timeout    time.Duration
	MaxRetries int
	RetryDelay time.Duration
}

// NewSigningHTTPClient creates a new HTTP client with request signing capability
func NewSigningHTTPClient(config ClientConfig, obs *observability.Observability) *SigningHTTPClient {
	// Set defaults
	if config.Algorithm == "" {
		config.Algorithm = security.AlgorithmHMACSHA256
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if len(config.Headers) == 0 {
		config.Headers = []string{"Content-Type", "Content-Length", "Host"}
	}

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: config.Timeout,
	}

	// Create signer
	signingConfig := security.SigningConfig{
		KeyID:     config.KeyID,
		Secret:    config.Secret,
		Algorithm: config.Algorithm,
		Headers:   config.Headers,
	}
	signer := security.NewRequestSignerWithConfig(signingConfig, obs)

	return &SigningHTTPClient{
		client: httpClient,
		signer: signer,
		obs:    obs,
	}
}

// NewSigningHTTPClientFromConfig creates a client from request signing config
func NewSigningHTTPClientFromConfig(config *config.RequestSigningConfig, obs *observability.Observability) *SigningHTTPClient {
	if !config.Enabled {
		return nil
	}

	clientConfig := ClientConfig{
		KeyID:     config.KeyID,
		Secret:    config.Secret,
		Algorithm: config.Algorithm,
		Headers:   config.Headers,
		Timeout:   30 * time.Second,
	}

	return NewSigningHTTPClient(clientConfig, obs)
}

// Do performs an HTTP request with automatic signing
func (c *SigningHTTPClient) Do(req *http.Request) (*http.Response, error) {
	start := time.Now()

	// Sign the request
	if err := c.signer.Sign(req); err != nil {
		if c.obs != nil {
			c.obs.Logger.Error().
				Err(err).
				Str("method", req.Method).
				Str("url", req.URL.String()).
				Msg("Failed to sign HTTP request")
		}
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	// Perform the request
	resp, err := c.client.Do(req)

	// Log request metrics
	if c.obs != nil {
		duration := time.Since(start)
		logger := c.obs.Logger.Debug()
		if err != nil {
			logger = c.obs.Logger.Error().Err(err)
		}

		statusCode := 0
		if resp != nil {
			statusCode = resp.StatusCode
		}

		logger.
			Str("method", req.Method).
			Str("url", req.URL.String()).
			Int("status_code", statusCode).
			Dur("duration", duration).
			Msg("HTTP request completed")
	}

	return resp, err
}

// Get performs a GET request with signing
func (c *SigningHTTPClient) Get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post performs a POST request with signing
func (c *SigningHTTPClient) Post(ctx context.Context, url string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		return nil, err
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	return c.Do(req)
}

// PostJSON performs a POST request with JSON body and signing
func (c *SigningHTTPClient) PostJSON(ctx context.Context, url string, body []byte) (*http.Response, error) {
	return c.Post(ctx, url, "application/json", bytes.NewReader(body))
}

// Put performs a PUT request with signing
func (c *SigningHTTPClient) Put(ctx context.Context, url string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "PUT", url, body)
	if err != nil {
		return nil, err
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	return c.Do(req)
}

// PutJSON performs a PUT request with JSON body and signing
func (c *SigningHTTPClient) PutJSON(ctx context.Context, url string, body []byte) (*http.Response, error) {
	return c.Put(ctx, url, "application/json", bytes.NewReader(body))
}

// Delete performs a DELETE request with signing
func (c *SigningHTTPClient) Delete(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Patch performs a PATCH request with signing
func (c *SigningHTTPClient) Patch(ctx context.Context, url string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "PATCH", url, body)
	if err != nil {
		return nil, err
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	return c.Do(req)
}

// PatchJSON performs a PATCH request with JSON body and signing
func (c *SigningHTTPClient) PatchJSON(ctx context.Context, url string, body []byte) (*http.Response, error) {
	return c.Patch(ctx, url, "application/json", bytes.NewReader(body))
}

// SetTimeout sets the HTTP client timeout
func (c *SigningHTTPClient) SetTimeout(timeout time.Duration) {
	c.client.Timeout = timeout
}

// GetClient returns the underlying HTTP client
func (c *SigningHTTPClient) GetClient() *http.Client {
	return c.client
}

// GetSigner returns the request signer
func (c *SigningHTTPClient) GetSigner() *security.RequestSigner {
	return c.signer
}

// SigningRoundTripper is a http.RoundTripper that signs requests
type SigningRoundTripper struct {
	base   http.RoundTripper
	signer *security.RequestSigner
	obs    *observability.Observability
}

// NewSigningRoundTripper creates a new signing round tripper
func NewSigningRoundTripper(base http.RoundTripper, signer *security.RequestSigner, obs *observability.Observability) *SigningRoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}

	return &SigningRoundTripper{
		base:   base,
		signer: signer,
		obs:    obs,
	}
}

// RoundTrip implements http.RoundTripper interface
func (rt *SigningRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()

	// Clone the request to avoid modifying the original
	clonedReq := req.Clone(req.Context())

	// Sign the cloned request
	if err := rt.signer.Sign(clonedReq); err != nil {
		if rt.obs != nil {
			rt.obs.Logger.Error().
				Err(err).
				Str("method", req.Method).
				Str("url", req.URL.String()).
				Msg("Failed to sign HTTP request in round tripper")
		}
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	// Perform the request
	resp, err := rt.base.RoundTrip(clonedReq)

	// Log request metrics
	if rt.obs != nil {
		duration := time.Since(start)
		logger := rt.obs.Logger.Debug()
		if err != nil {
			logger = rt.obs.Logger.Error().Err(err)
		}

		statusCode := 0
		if resp != nil {
			statusCode = resp.StatusCode
		}

		logger.
			Str("method", req.Method).
			Str("url", req.URL.String()).
			Int("status_code", statusCode).
			Dur("duration", duration).
			Msg("HTTP request completed via round tripper")
	}

	return resp, err
}

// NewHTTPClientWithSigning creates a standard http.Client with signing round tripper
func NewHTTPClientWithSigning(config ClientConfig, obs *observability.Observability) *http.Client {
	signingConfig := security.SigningConfig{
		KeyID:     config.KeyID,
		Secret:    config.Secret,
		Algorithm: config.Algorithm,
		Headers:   config.Headers,
	}
	signer := security.NewRequestSignerWithConfig(signingConfig, obs)

	transport := NewSigningRoundTripper(nil, signer, obs)

	return &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}
}
