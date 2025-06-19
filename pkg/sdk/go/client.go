// Package sdk provides a comprehensive Go SDK for the MVP Zero Trust Auth system.
// It offers a simple, typed interface for integrating Zero Trust authentication
// into Go applications with automatic token management, retry logic, and observability.
//
// Example usage:
//
//	client, err := sdk.NewClient(sdk.Config{
//	    BaseURL: "https://auth.example.com",
//	    APIKey:  "your-api-key",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Authenticate user
//	token, err := client.Authenticate(ctx, "user@example.com", "password")
//	if err != nil {
//	    log.Printf("Authentication failed: %v", err)
//	    return
//	}
//
//	// Validate token
//	claims, err := client.ValidateToken(ctx, token.AccessToken)
//	if err != nil {
//	    log.Printf("Token validation failed: %v", err)
//	    return
//	}
//
//	log.Printf("User authenticated: %s", claims.Subject)
package sdk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
)

// Client represents the Zero Trust Auth SDK client
type Client struct {
	config     *Config
	httpClient *http.Client
	baseURL    *url.URL
}

// Config holds configuration for the SDK client
type Config struct {
	// BaseURL is the base URL of the Zero Trust Auth service
	BaseURL string `json:"base_url" yaml:"base_url"`

	// APIKey for authenticating SDK requests
	APIKey string `json:"api_key" yaml:"api_key"`

	// Timeout for HTTP requests (default: 30s)
	Timeout time.Duration `json:"timeout" yaml:"timeout"`

	// MaxRetries for failed requests (default: 3)
	MaxRetries int `json:"max_retries" yaml:"max_retries"`

	// RetryDelay between retry attempts (default: 1s)
	RetryDelay time.Duration `json:"retry_delay" yaml:"retry_delay"`

	// InsecureSkipVerify skips TLS verification (development only)
	InsecureSkipVerify bool `json:"insecure_skip_verify" yaml:"insecure_skip_verify"`

	// UserAgent for SDK requests
	UserAgent string `json:"user_agent" yaml:"user_agent"`

	// Debug enables debug logging
	Debug bool `json:"debug" yaml:"debug"`
}

// AuthenticationRequest represents a user authentication request
type AuthenticationRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	MFA      string `json:"mfa,omitempty"`
	Remember bool   `json:"remember,omitempty"`
}

// AuthenticationResponse represents the response from authentication
type AuthenticationResponse struct {
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	TokenType             string    `json:"token_type"`
	ExpiresIn             int       `json:"expires_in"`
	ExpiresAt             time.Time `json:"expires_at"`
	Scope                 string    `json:"scope"`
	RequiresMFA           bool      `json:"requires_mfa"`
	MFAChallenge          string    `json:"mfa_challenge,omitempty"`
	PartialToken          string    `json:"partial_token,omitempty"`
	User                  *User     `json:"user"`
	SessionID             string    `json:"session_id"`
	TrustScore            float64   `json:"trust_score"`
	RiskFactors           []string  `json:"risk_factors,omitempty"`
	RecommendedActions    []string  `json:"recommended_actions,omitempty"`
}

// TokenValidationRequest represents a token validation request
type TokenValidationRequest struct {
	Token     string `json:"token" validate:"required"`
	Audience  string `json:"audience,omitempty"`
	RequiredScopes []string `json:"required_scopes,omitempty"`
}

// TokenValidationResponse represents the response from token validation
type TokenValidationResponse struct {
	Valid       bool      `json:"valid"`
	Claims      *Claims   `json:"claims,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	IssuedAt    time.Time `json:"issued_at"`
	TrustScore  float64   `json:"trust_score"`
	Permissions []string  `json:"permissions"`
	Roles       []string  `json:"roles"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Claims represents JWT token claims
type Claims struct {
	Subject   string                 `json:"sub"`
	Audience  []string              `json:"aud"`
	Issuer    string                `json:"iss"`
	ExpiresAt time.Time             `json:"exp"`
	IssuedAt  time.Time             `json:"iat"`
	NotBefore time.Time             `json:"nbf"`
	JTI       string                `json:"jti"`
	Email     string                `json:"email"`
	Roles     []string              `json:"roles"`
	Permissions []string            `json:"permissions"`
	TrustScore float64              `json:"trust_score"`
	SessionID  string               `json:"session_id"`
	Custom     map[string]interface{} `json:"custom,omitempty"`
}

// User represents a user in the system
type User struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	FirstName     string                 `json:"first_name"`
	LastName      string                 `json:"last_name"`
	DisplayName   string                 `json:"display_name"`
	Avatar        string                 `json:"avatar,omitempty"`
	Roles         []string              `json:"roles"`
	Permissions   []string              `json:"permissions"`
	TrustScore    float64               `json:"trust_score"`
	LastLoginAt   *time.Time            `json:"last_login_at,omitempty"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
	IsActive      bool                  `json:"is_active"`
	IsVerified    bool                  `json:"is_verified"`
	MFAEnabled    bool                  `json:"mfa_enabled"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// RefreshTokenRequest represents a token refresh request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// LogoutRequest represents a logout request
type LogoutRequest struct {
	Token     string `json:"token,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Everywhere bool  `json:"everywhere,omitempty"`
}

// APIError represents an error response from the API
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
	TraceID string `json:"trace_id,omitempty"`
}

func (e *APIError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// NewClient creates a new SDK client with the given configuration
func NewClient(config Config) (*Client, error) {
	// Set defaults
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = time.Second
	}
	if config.UserAgent == "" {
		config.UserAgent = "MVP-ZeroTrust-SDK/1.0.0 (Go)"
	}

	// Validate required fields
	if config.BaseURL == "" {
		return nil, fmt.Errorf("base_url is required")
	}
	if config.APIKey == "" {
		return nil, fmt.Errorf("api_key is required")
	}

	// Parse base URL
	baseURL, err := url.Parse(config.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base_url: %w", err)
	}

	// Create HTTP client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.InsecureSkipVerify,
		},
	}

	httpClient := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
	}

	return &Client{
		config:     &config,
		httpClient: httpClient,
		baseURL:    baseURL,
	}, nil
}

// Authenticate authenticates a user with email/password
func (c *Client) Authenticate(ctx context.Context, req AuthenticationRequest) (*AuthenticationResponse, error) {
	var resp AuthenticationResponse
	err := c.makeRequest(ctx, "POST", "/api/v1/auth/login", req, &resp)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	return &resp, nil
}

// ValidateToken validates an access token
func (c *Client) ValidateToken(ctx context.Context, req TokenValidationRequest) (*TokenValidationResponse, error) {
	var resp TokenValidationResponse
	err := c.makeRequest(ctx, "POST", "/api/v1/auth/validate", req, &resp)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	return &resp, nil
}

// RefreshToken refreshes an access token using a refresh token
func (c *Client) RefreshToken(ctx context.Context, req RefreshTokenRequest) (*AuthenticationResponse, error) {
	var resp AuthenticationResponse
	err := c.makeRequest(ctx, "POST", "/api/v1/auth/refresh", req, &resp)
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}
	return &resp, nil
}

// Logout logs out a user session
func (c *Client) Logout(ctx context.Context, req LogoutRequest) error {
	err := c.makeRequest(ctx, "POST", "/api/v1/auth/logout", req, nil)
	if err != nil {
		return fmt.Errorf("logout failed: %w", err)
	}
	return nil
}

// GetUserProfile retrieves the current user's profile
func (c *Client) GetUserProfile(ctx context.Context, token string) (*User, error) {
	var user User
	err := c.makeRequestWithAuth(ctx, "GET", "/api/v1/user/profile", nil, &user, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get user profile: %w", err)
	}
	return &user, nil
}

// UpdateUserProfile updates the current user's profile
func (c *Client) UpdateUserProfile(ctx context.Context, token string, user User) (*User, error) {
	var updatedUser User
	err := c.makeRequestWithAuth(ctx, "PUT", "/api/v1/user/profile", user, &updatedUser, token)
	if err != nil {
		return nil, fmt.Errorf("failed to update user profile: %w", err)
	}
	return &updatedUser, nil
}

// makeRequest makes an HTTP request to the API
func (c *Client) makeRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	return c.makeRequestWithAuth(ctx, method, path, body, result, "")
}

// makeRequestWithAuth makes an authenticated HTTP request to the API
func (c *Client) makeRequestWithAuth(ctx context.Context, method, path string, body interface{}, result interface{}, token string) error {
	url := c.baseURL.ResolveReference(&url.URL{Path: path})

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	var lastErr error
	for i := 0; i <= c.config.MaxRetries; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(c.config.RetryDelay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, method, url.String(), bodyReader)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		// Set headers
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.config.UserAgent)
		req.Header.Set("X-API-Key", c.config.APIKey)
		req.Header.Set("X-Request-ID", uuid.New().String())

		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		if c.config.Debug {
			fmt.Printf("SDK Request: %s %s\n", method, url.String())
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		defer resp.Body.Close()

		// Read response body
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read response body: %w", err)
			continue
		}

		if c.config.Debug {
			fmt.Printf("SDK Response: %d %s\n", resp.StatusCode, string(respBody))
		}

		// Handle error responses
		if resp.StatusCode >= 400 {
			var apiErr APIError
			if err := json.Unmarshal(respBody, &apiErr); err != nil {
				lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
			} else {
				lastErr = &apiErr
			}

			// Don't retry client errors (4xx) except 429
			if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
				return lastErr
			}
			continue
		}

		// Parse successful response
		if result != nil && len(respBody) > 0 {
			if err := json.Unmarshal(respBody, result); err != nil {
				return fmt.Errorf("failed to unmarshal response: %w", err)
			}
		}

		return nil
	}

	return fmt.Errorf("max retries exceeded, last error: %w", lastErr)
}

// HealthCheck checks the health of the Zero Trust Auth service
func (c *Client) HealthCheck(ctx context.Context) error {
	url := c.baseURL.ResolveReference(&url.URL{Path: "/health"})
	
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	req.Header.Set("User-Agent", c.config.UserAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed with status: %d", resp.StatusCode)
	}

	return nil
}

// SetDebug enables or disables debug logging
func (c *Client) SetDebug(debug bool) {
	c.config.Debug = debug
}

// GetConfig returns a copy of the client configuration
func (c *Client) GetConfig() Config {
	return *c.config
}

// Close closes the client and cleans up resources
func (c *Client) Close() error {
	c.httpClient.CloseIdleConnections()
	return nil
}