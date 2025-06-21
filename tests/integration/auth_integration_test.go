//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"mvp.local/pkg/auth"
)

// AuthTestScenario represents a test scenario for authentication
type AuthTestScenario struct {
	Name          string
	Username      string
	Password      string
	TenantID      string
	ExpectSuccess bool
	ExpectedError string
	CheckResponse func(t *testing.T, resp map[string]interface{})
}

// TestAuthenticationScenarios tests various authentication scenarios
func TestAuthenticationScenarios(t *testing.T) {
	// Ensure the server is running
	baseURL := "http://localhost:8080"

	// Wait for server to be ready
	waitForServer(t, baseURL)

	scenarios := []AuthTestScenario{
		{
			Name:          "Admin user login with correct credentials",
			Username:      "admin",
			Password:      "password",
			ExpectSuccess: true,
			CheckResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.NotEmpty(t, resp["token"])
				assert.NotEmpty(t, resp["refresh_token"])
				assert.NotNil(t, resp["user"])

				user := resp["user"].(map[string]interface{})
				assert.Equal(t, "admin", user["username"])
				assert.Equal(t, true, user["is_admin"])
				assert.Contains(t, user["roles"], "admin")
			},
		},
		{
			Name:          "Admin user login with wrong password",
			Username:      "admin",
			Password:      "wrongpassword",
			ExpectSuccess: false,
			ExpectedError: "Invalid credentials",
		},
		{
			Name:          "Non-existent user login",
			Username:      "nonexistent",
			Password:      "password",
			ExpectSuccess: false,
			ExpectedError: "Invalid credentials",
		},
		{
			Name:          "Empty username",
			Username:      "",
			Password:      "password",
			ExpectSuccess: false,
			ExpectedError: "Username and password are required",
		},
		{
			Name:          "Empty password",
			Username:      "admin",
			Password:      "",
			ExpectSuccess: false,
			ExpectedError: "Username and password are required",
		},
		{
			Name:          "Login with email instead of username",
			Username:      "admin@localhost",
			Password:      "password",
			ExpectSuccess: true,
			CheckResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.NotEmpty(t, resp["token"])
				user := resp["user"].(map[string]interface{})
				assert.Equal(t, "admin", user["username"])
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			resp, err := performLogin(baseURL, scenario.Username, scenario.Password, scenario.TenantID)

			if scenario.ExpectSuccess {
				require.NoError(t, err)
				require.NotNil(t, resp)

				// Verify successful response
				assert.NotEmpty(t, resp["token"])
				assert.NotEmpty(t, resp["refresh_token"])

				// Run custom checks
				if scenario.CheckResponse != nil {
					scenario.CheckResponse(t, resp)
				}

				// Test token validity
				token := resp["token"].(string)
				testTokenValidity(t, baseURL, token)
			} else {
				// Verify error response
				require.NotNil(t, resp)
				assert.Equal(t, scenario.ExpectedError, resp["message"])
			}
		})
	}
}

// TestAdminUserFullFlow tests the complete authentication flow for admin user
func TestAdminUserFullFlow(t *testing.T) {
	baseURL := "http://localhost:8080"

	// Wait for server to be ready
	waitForServer(t, baseURL)

	// Step 1: Login
	loginResp, err := performLogin(baseURL, "admin", "password", "")
	require.NoError(t, err)
	require.NotNil(t, loginResp)

	token := loginResp["token"].(string)
	refreshToken := loginResp["refresh_token"].(string)

	assert.NotEmpty(t, token)
	assert.NotEmpty(t, refreshToken)

	// Step 2: Get current user info
	userInfo, err := getCurrentUser(baseURL, token)
	require.NoError(t, err)
	assert.Equal(t, "admin", userInfo["username"])
	assert.Equal(t, true, userInfo["is_admin"])

	// Step 3: Refresh token
	newTokens, err := refreshAccessToken(baseURL, refreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, newTokens["token"])
	assert.NotEmpty(t, newTokens["refresh_token"])

	newToken := newTokens["token"].(string)

	// Step 4: Use new token to access protected endpoint
	userInfo2, err := getCurrentUser(baseURL, newToken)
	require.NoError(t, err)
	assert.Equal(t, "admin", userInfo2["username"])

	// Step 5: Logout
	err = performLogout(baseURL, newToken)
	require.NoError(t, err)

	// Step 6: Verify old token is invalid
	_, err = getCurrentUser(baseURL, token)
	assert.Error(t, err)
}

// TestPasswordChangeFlow tests the password change functionality
func TestPasswordChangeFlow(t *testing.T) {
	baseURL := "http://localhost:8080"

	// Wait for server to be ready
	waitForServer(t, baseURL)

	// Create a test user
	testUsername := fmt.Sprintf("testuser_%d", time.Now().Unix())
	testPassword := "testpassword123"
	newPassword := "newpassword456"

	// Register new user
	err := registerUser(baseURL, testUsername, testUsername+"@test.com", testPassword)
	require.NoError(t, err)

	// Login with original password
	loginResp, err := performLogin(baseURL, testUsername, testPassword, "")
	require.NoError(t, err)
	token := loginResp["token"].(string)

	// Change password
	err = changePassword(baseURL, token, testPassword, newPassword)
	require.NoError(t, err)

	// Try to login with old password (should fail)
	_, err = performLogin(baseURL, testUsername, testPassword, "")
	assert.Error(t, err)

	// Login with new password (should succeed)
	loginResp2, err := performLogin(baseURL, testUsername, newPassword, "")
	require.NoError(t, err)
	assert.NotEmpty(t, loginResp2["token"])
}

// Helper functions

func waitForServer(t *testing.T, baseURL string) {
	maxRetries := 30
	for i := 0; i < maxRetries; i++ {
		resp, err := http.Get(baseURL + "/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatal("Server did not become ready in time")
}

func performLogin(baseURL, username, password, tenantID string) (map[string]interface{}, error) {
	loginReq := auth.LoginRequest{
		Username: username,
		Password: password,
		TenantID: tenantID,
	}

	body, _ := json.Marshal(loginReq)
	resp, err := http.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("login failed with status %d", resp.StatusCode)
	}

	return result, nil
}

func getCurrentUser(baseURL, token string) (map[string]interface{}, error) {
	req, _ := http.NewRequest("GET", baseURL+"/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get current user: status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

func refreshAccessToken(baseURL, refreshToken string) (map[string]interface{}, error) {
	refreshReq := auth.RefreshRequest{
		RefreshToken: refreshToken,
	}

	body, _ := json.Marshal(refreshReq)
	resp, err := http.Post(baseURL+"/api/auth/refresh", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh failed with status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

func performLogout(baseURL, token string) error {
	req, _ := http.NewRequest("POST", baseURL+"/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("logout failed with status %d", resp.StatusCode)
	}

	return nil
}

func registerUser(baseURL, username, email, password string) error {
	regReq := map[string]string{
		"username":   username,
		"email":      email,
		"password":   password,
		"first_name": "Test",
		"last_name":  "User",
	}

	body, _ := json.Marshal(regReq)
	resp, err := http.Post(baseURL+"/api/auth/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("registration failed with status %d", resp.StatusCode)
	}

	return nil
}

func changePassword(baseURL, token, currentPassword, newPassword string) error {
	changeReq := map[string]string{
		"current_password": currentPassword,
		"new_password":     newPassword,
	}

	body, _ := json.Marshal(changeReq)
	req, _ := http.NewRequest("POST", baseURL+"/api/auth/change-password", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("password change failed with status %d", resp.StatusCode)
	}

	return nil
}

func testTokenValidity(t *testing.T, baseURL, token string) {
	// Try to access a protected endpoint
	req, _ := http.NewRequest("GET", baseURL+"/api/devices", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should get 200 OK for valid token
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
