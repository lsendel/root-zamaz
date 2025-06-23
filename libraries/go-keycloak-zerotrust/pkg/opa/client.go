package opa

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

// OPAClient represents an OPA client
type OPAClient struct {
    baseURL string
    client  *http.Client
}

// AuthorizationRequest represents a request to OPA
type AuthorizationRequest struct {
    JWT      string `json:"jwt_token"`
    Resource string `json:"resource"`
    Action   string `json:"action"`
    UserID   string `json:"user_id"`
    DeviceID string `json:"device_id"`
}

// AuthorizationResponse represents OPA's response
type AuthorizationResponse struct {
    Result struct {
        Allow     bool     `json:"allow"`
        Reasons   []string `json:"reasons"`
        TrustLevel int     `json:"trust_level"`
        UserRoles []string `json:"user_roles"`
        Timestamp int64    `json:"timestamp"`
    } `json:"result"`
}

// NewOPAClient creates a new OPA client
func NewOPAClient(baseURL string) *OPAClient {
    return &OPAClient{
        baseURL: baseURL,
        client: &http.Client{
            Timeout: 5 * time.Second,
        },
    }
}

// Authorize checks authorization with OPA
func (c *OPAClient) Authorize(ctx context.Context, req AuthorizationRequest) (*AuthorizationResponse, error) {
    input := map[string]interface{}{
        "input": req,
    }
    
    jsonData, err := json.Marshal(input)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }
    
    url := fmt.Sprintf("%s/v1/data/zero_trust/authz/decision", c.baseURL)
    httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }
    
    httpReq.Header.Set("Content-Type", "application/json")
    
    resp, err := c.client.Do(httpReq)
    if err != nil {
        return nil, fmt.Errorf("failed to send request: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("OPA returned status %d", resp.StatusCode)
    }
    
    var opaResp AuthorizationResponse
    if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }
    
    return &opaResp, nil
}

// HealthCheck checks OPA health
func (c *OPAClient) HealthCheck(ctx context.Context) error {
    url := fmt.Sprintf("%s/health", c.baseURL)
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return fmt.Errorf("failed to create health check request: %w", err)
    }
    
    resp, err := c.client.Do(req)
    if err != nil {
        return fmt.Errorf("failed to send health check: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("OPA health check failed with status %d", resp.StatusCode)
    }
    
    return nil
}
