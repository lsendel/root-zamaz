package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"mvp.local/pkg/auth"
	"mvp.local/pkg/handlers"
)

// APIClient provides simplified access to the Zero Trust Auth API
// It is intended for developer tooling and SDK generation.
type APIClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// New creates a new API client with the given base URL.
func New(baseURL string) *APIClient {
	return &APIClient{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// Login authenticates a user and returns JWT tokens.
func (c *APIClient) Login(ctx context.Context, username, password string) (*auth.LoginResponse, error) {
	reqBody, _ := json.Marshal(auth.LoginRequest{Username: username, Password: password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/auth/login", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("login failed: %s", resp.Status)
	}

	var lr auth.LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return nil, err
	}
	return &lr, nil
}

// Register creates a new user account.
func (c *APIClient) Register(ctx context.Context, r handlers.RegisterRequest) (*handlers.UserResponse, error) {
	reqBody, _ := json.Marshal(r)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/auth/register", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("registration failed: %s", resp.Status)
	}

	var ur handlers.UserResponse
	if err := json.NewDecoder(resp.Body).Decode(&ur); err != nil {
		return nil, err
	}
	return &ur, nil
}

// Me returns the currently authenticated user's information.
func (c *APIClient) Me(ctx context.Context, token string) (*handlers.UserResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/auth/me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed: %s", resp.Status)
	}

	var ur handlers.UserResponse
	if err := json.NewDecoder(resp.Body).Decode(&ur); err != nil {
		return nil, err
	}
	return &ur, nil
}
