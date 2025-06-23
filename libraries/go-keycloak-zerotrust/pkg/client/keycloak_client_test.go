package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

func TestNewKeycloakClient(t *testing.T) {
	tests := []struct {
		name      string
		config    *types.Config
		wantError bool
		errorType string
	}{
		{
			name:      "nil config",
			config:    nil,
			wantError: true,
			errorType: types.ErrCodeConfigurationError,
		},
		{
			name: "missing base URL",
			config: &types.Config{
				Realm:        "test",
				ClientID:     "test-client",
				ClientSecret: "secret",
			},
			wantError: true,
			errorType: types.ErrCodeConfigurationError,
		},
		{
			name: "missing realm",
			config: &types.Config{
				BaseURL:      "http://localhost:8080",
				ClientID:     "test-client",
				ClientSecret: "secret",
			},
			wantError: true,
			errorType: types.ErrCodeConfigurationError,
		},
		{
			name: "missing client ID",
			config: &types.Config{
				BaseURL:      "http://localhost:8080",
				Realm:        "test",
				ClientSecret: "secret",
			},
			wantError: true,
			errorType: types.ErrCodeConfigurationError,
		},
		{
			name: "missing client secret",
			config: &types.Config{
				BaseURL:  "http://localhost:8080",
				Realm:    "test",
				ClientID: "test-client",
			},
			wantError: true,
			errorType: types.ErrCodeConfigurationError,
		},
		{
			name: "valid minimal config",
			config: &types.Config{
				BaseURL:      "http://localhost:8080",
				Realm:        "test",
				ClientID:     "test-client",
				ClientSecret: "secret",
			},
			wantError: false,
		},
		{
			name: "valid full config",
			config: &types.Config{
				BaseURL:       "http://localhost:8080",
				Realm:         "test",
				ClientID:      "test-client",
				ClientSecret:  "secret",
				AdminUser:     "admin",
				AdminPass:     "admin-pass",
				Timeout:       30 * time.Second,
				RetryAttempts: 3,
				Cache: &types.CacheConfig{
					Enabled:  true,
					Provider: "memory",
					TTL:      15 * time.Minute,
					MaxSize:  1000,
					Prefix:   "test",
				},
				ZeroTrust: &types.ZeroTrustConfig{
					DefaultTrustLevel:      25,
					DeviceAttestation:      true,
					RiskAssessment:         true,
					ContinuousVerification: true,
					VerificationInterval:   4 * time.Hour,
				},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewKeycloakClient(tt.config)

			if tt.wantError {
				require.Error(t, err)
				assert.Nil(t, client)
				
				if authErr, ok := err.(*types.AuthError); ok {
					assert.Equal(t, tt.errorType, authErr.Code)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, client)
				
				// Clean up
				if client != nil {
					err := client.Close()
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    *types.Config
		wantError bool
	}{
		{
			name:      "nil config",
			config:    nil,
			wantError: true,
		},
		{
			name: "empty base URL",
			config: &types.Config{
				Realm:        "test",
				ClientID:     "test-client",
				ClientSecret: "secret",
			},
			wantError: true,
		},
		{
			name: "valid config",
			config: &types.Config{
				BaseURL:      "http://localhost:8080",
				Realm:        "test",
				ClientID:     "test-client",
				ClientSecret: "secret",
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMemoryCache(t *testing.T) {
	cache := newMemoryCache(2) // Small size for testing eviction
	ctx := context.Background()

	// Test set and get
	err := cache.Set(ctx, "key1", "value1", time.Hour)
	require.NoError(t, err)

	value, err := cache.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, "value1", value)

	// Test non-existent key
	value, err = cache.Get(ctx, "nonexistent")
	require.NoError(t, err)
	assert.Empty(t, value)

	// Test expiration
	err = cache.Set(ctx, "key2", "value2", time.Millisecond)
	require.NoError(t, err)
	
	time.Sleep(10 * time.Millisecond) // Wait for expiration
	
	value, err = cache.Get(ctx, "key2")
	require.NoError(t, err)
	assert.Empty(t, value) // Should be expired

	// Test eviction (cache size is 2)
	err = cache.Set(ctx, "key3", "value3", time.Hour)
	require.NoError(t, err)
	
	err = cache.Set(ctx, "key4", "value4", time.Hour)
	require.NoError(t, err)
	
	err = cache.Set(ctx, "key5", "value5", time.Hour) // Should trigger eviction
	require.NoError(t, err)

	// Test delete
	err = cache.Delete(ctx, "key5")
	require.NoError(t, err)
	
	value, err = cache.Get(ctx, "key5")
	require.NoError(t, err)
	assert.Empty(t, value)

	// Test close
	err = cache.Close()
	assert.NoError(t, err)
}

func TestExtractZeroTrustClaims(t *testing.T) {
	// This is a placeholder test for the claims extraction logic
	// In a real implementation, this would test the JWT parsing and claims extraction
	
	client := &keycloakClient{
		config: &types.Config{
			ZeroTrust: &types.ZeroTrustConfig{
				DefaultTrustLevel: 25,
			},
		},
	}

	claims := &types.ZeroTrustClaims{}
	
	// Test default trust level assignment
	jwtClaims := map[string]interface{}{}
	client.extractZeroTrustClaims(jwtClaims, claims)
	
	assert.Equal(t, 25, claims.TrustLevel)
}

func TestCreateAuthenticatedUser(t *testing.T) {
	middleware := &keycloakClient{}
	
	claims := &types.ZeroTrustClaims{
		UserID:           "user-123",
		Email:            "test@example.com",
		PreferredUsername: "testuser",
		GivenName:        "Test",
		FamilyName:       "User",
		Roles:            []string{"user", "admin"},
		TrustLevel:       75,
		DeviceID:         "device-456",
		DeviceVerified:   true,
		SessionState:     "session-789",
		RiskScore:        25,
	}

	user := middleware.createAuthenticatedUser(claims)
	
	assert.Equal(t, "user-123", user.UserID)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "Test", user.FirstName)
	assert.Equal(t, "User", user.LastName)
	assert.Equal(t, []string{"user", "admin"}, user.Roles)
	assert.Equal(t, 75, user.TrustLevel)
	assert.Equal(t, "device-456", user.DeviceID)
	assert.True(t, user.DeviceVerified)
	assert.Equal(t, "session-789", user.SessionState)
	assert.Equal(t, 25, user.RiskScore)
}

// Mock implementations for testing

type MockKeycloakClient struct {
	validateTokenFunc    func(ctx context.Context, token string) (*types.ZeroTrustClaims, error)
	refreshTokenFunc     func(ctx context.Context, refreshToken string) (*types.TokenPair, error)
	getUserInfoFunc      func(ctx context.Context, userID string) (*types.UserInfo, error)
	registerUserFunc     func(ctx context.Context, req *types.UserRegistrationRequest) (*types.User, error)
	updateTrustLevelFunc func(ctx context.Context, req *types.TrustLevelUpdateRequest) error
	revokeSessionsFunc   func(ctx context.Context, userID string) error
	healthFunc           func(ctx context.Context) error
	getMetricsFunc       func(ctx context.Context) (*types.ClientMetrics, error)
	closeFunc            func() error
}

func (m *MockKeycloakClient) ValidateToken(ctx context.Context, token string) (*types.ZeroTrustClaims, error) {
	if m.validateTokenFunc != nil {
		return m.validateTokenFunc(ctx, token)
	}
	return nil, nil
}

func (m *MockKeycloakClient) RefreshToken(ctx context.Context, refreshToken string) (*types.TokenPair, error) {
	if m.refreshTokenFunc != nil {
		return m.refreshTokenFunc(ctx, refreshToken)
	}
	return nil, nil
}

func (m *MockKeycloakClient) GetUserInfo(ctx context.Context, userID string) (*types.UserInfo, error) {
	if m.getUserInfoFunc != nil {
		return m.getUserInfoFunc(ctx, userID)
	}
	return nil, nil
}

func (m *MockKeycloakClient) RegisterUser(ctx context.Context, req *types.UserRegistrationRequest) (*types.User, error) {
	if m.registerUserFunc != nil {
		return m.registerUserFunc(ctx, req)
	}
	return nil, nil
}

func (m *MockKeycloakClient) UpdateUserTrustLevel(ctx context.Context, req *types.TrustLevelUpdateRequest) error {
	if m.updateTrustLevelFunc != nil {
		return m.updateTrustLevelFunc(ctx, req)
	}
	return nil
}

func (m *MockKeycloakClient) RevokeUserSessions(ctx context.Context, userID string) error {
	if m.revokeSessionsFunc != nil {
		return m.revokeSessionsFunc(ctx, userID)
	}
	return nil
}

func (m *MockKeycloakClient) Health(ctx context.Context) error {
	if m.healthFunc != nil {
		return m.healthFunc(ctx)
	}
	return nil
}

func (m *MockKeycloakClient) GetMetrics(ctx context.Context) (*types.ClientMetrics, error) {
	if m.getMetricsFunc != nil {
		return m.getMetricsFunc(ctx)
	}
	return &types.ClientMetrics{}, nil
}

func (m *MockKeycloakClient) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}