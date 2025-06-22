// Unit tests for Keycloak authentication component
package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"your-project/pkg/auth"
)

// MockKeycloakClient mocks the Keycloak client interface
type MockKeycloakClient struct {
	mock.Mock
}

func (m *MockKeycloakClient) Login(ctx context.Context, clientID, clientSecret, realm, username, password string) (*string, error) {
	args := m.Called(ctx, clientID, clientSecret, realm, username, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*string), args.Error(1)
}

func (m *MockKeycloakClient) RetrospectToken(ctx context.Context, accessToken, clientID, clientSecret, realm string) (*map[string]interface{}, error) {
	args := m.Called(ctx, accessToken, clientID, clientSecret, realm)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*map[string]interface{}), args.Error(1)
}

// KeycloakTestSuite contains unit tests for Keycloak authentication
type KeycloakTestSuite struct {
	suite.Suite
	mockClient *MockKeycloakClient
	config     *auth.KeycloakConfig
}

func (suite *KeycloakTestSuite) SetupTest() {
	suite.mockClient = new(MockKeycloakClient)
	suite.config = &auth.KeycloakConfig{
		BaseURL:      "http://localhost:8080",
		Realm:        "zero-trust",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}
}

func (suite *KeycloakTestSuite) TestValidateToken_Success() {
	// Test successful token validation
	validToken := "valid-jwt-token"
	expectedClaims := map[string]interface{}{
		"active":     true,
		"sub":        "user-123",
		"email":      "test@example.com",
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"user", "admin"},
		},
		"trust_level": float64(75),
		"device_id":   "device-123",
		"exp":         float64(time.Now().Add(time.Hour).Unix()),
	}

	suite.mockClient.On("RetrospectToken", 
		mock.Anything, 
		validToken, 
		suite.config.ClientID, 
		suite.config.ClientSecret, 
		suite.config.Realm,
	).Return(&expectedClaims, nil)

	// Create authenticator with mock client
	authenticator := &auth.KeycloakAuthenticator{
		Client: suite.mockClient,
		Config: suite.config,
	}

	claims, err := authenticator.ValidateToken(context.Background(), validToken)
	
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), claims)
	assert.Equal(suite.T(), "user-123", claims.UserID)
	assert.Equal(suite.T(), "test@example.com", claims.Email)
	assert.Equal(suite.T(), 75, claims.TrustLevel)
	assert.Equal(suite.T(), "device-123", claims.DeviceID)
	assert.Contains(suite.T(), claims.Roles, "user")
	assert.Contains(suite.T(), claims.Roles, "admin")

	suite.mockClient.AssertExpectations(suite.T())
}

func (suite *KeycloakTestSuite) TestValidateToken_InvalidToken() {
	// Test invalid token
	invalidToken := "invalid-token"
	expectedClaims := map[string]interface{}{
		"active": false,
	}

	suite.mockClient.On("RetrospectToken",
		mock.Anything,
		invalidToken,
		suite.config.ClientID,
		suite.config.ClientSecret,
		suite.config.Realm,
	).Return(&expectedClaims, nil)

	authenticator := &auth.KeycloakAuthenticator{
		Client: suite.mockClient,
		Config: suite.config,
	}

	claims, err := authenticator.ValidateToken(context.Background(), invalidToken)
	
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), claims)
	assert.Contains(suite.T(), err.Error(), "token is not active")
}

func (suite *KeycloakTestSuite) TestValidateToken_ExpiredToken() {
	// Test expired token
	expiredToken := "expired-token"
	expectedClaims := map[string]interface{}{
		"active": true,
		"sub":    "user-123",
		"exp":    float64(time.Now().Add(-time.Hour).Unix()), // Expired
	}

	suite.mockClient.On("RetrospectToken",
		mock.Anything,
		expiredToken,
		suite.config.ClientID,
		suite.config.ClientSecret,
		suite.config.Realm,
	).Return(&expectedClaims, nil)

	authenticator := &auth.KeycloakAuthenticator{
		Client: suite.mockClient,
		Config: suite.config,
	}

	claims, err := authenticator.ValidateToken(context.Background(), expiredToken)
	
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), claims)
	assert.Contains(suite.T(), err.Error(), "token has expired")
}

func (suite *KeycloakTestSuite) TestExtractTrustLevel() {
	testCases := []struct {
		name           string
		claims         map[string]interface{}
		expectedTrust  int
	}{
		{
			name: "Explicit trust level",
			claims: map[string]interface{}{
				"trust_level": float64(100),
			},
			expectedTrust: 100,
		},
		{
			name: "Device verified user",
			claims: map[string]interface{}{
				"device_id": "device-123",
				"realm_access": map[string]interface{}{
					"roles": []interface{}{"user"},
				},
			},
			expectedTrust: 50,
		},
		{
			name: "Admin role",
			claims: map[string]interface{}{
				"realm_access": map[string]interface{}{
					"roles": []interface{}{"admin"},
				},
			},
			expectedTrust: 75,
		},
		{
			name: "Finance role",
			claims: map[string]interface{}{
				"realm_access": map[string]interface{}{
					"roles": []interface{}{"finance"},
				},
			},
			expectedTrust: 100,
		},
		{
			name: "Default trust level",
			claims: map[string]interface{}{},
			expectedTrust: 25,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			authenticator := &auth.KeycloakAuthenticator{
				Config: suite.config,
			}
			
			trustLevel := authenticator.ExtractTrustLevel(tc.claims)
			assert.Equal(suite.T(), tc.expectedTrust, trustLevel)
		})
	}
}

func (suite *KeycloakTestSuite) TestLogin_Success() {
	username := "testuser"
	password := "testpass"
	expectedToken := "jwt-token-12345"

	suite.mockClient.On("Login",
		mock.Anything,
		suite.config.ClientID,
		suite.config.ClientSecret,
		suite.config.Realm,
		username,
		password,
	).Return(&expectedToken, nil)

	authenticator := &auth.KeycloakAuthenticator{
		Client: suite.mockClient,
		Config: suite.config,
	}

	token, err := authenticator.Login(context.Background(), username, password)
	
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), expectedToken, token)
}

func (suite *KeycloakTestSuite) TestRefreshToken_Success() {
	refreshToken := "refresh-token-123"
	expectedNewToken := "new-jwt-token-456"

	// Mock refresh token call
	suite.mockClient.On("RefreshToken",
		mock.Anything,
		refreshToken,
		suite.config.ClientID,
		suite.config.ClientSecret,
		suite.config.Realm,
	).Return(&expectedNewToken, nil)

	authenticator := &auth.KeycloakAuthenticator{
		Client: suite.mockClient,
		Config: suite.config,
	}

	newToken, err := authenticator.RefreshToken(context.Background(), refreshToken)
	
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), expectedNewToken, newToken)
}

// Test configuration validation
func TestKeycloakConfigValidation(t *testing.T) {
	testCases := []struct {
		name        string
		config      *auth.KeycloakConfig
		shouldError bool
	}{
		{
			name:        "Nil config",
			config:      nil,
			shouldError: true,
		},
		{
			name: "Missing base URL",
			config: &auth.KeycloakConfig{
				Realm:        "test",
				ClientID:     "test",
				ClientSecret: "test",
			},
			shouldError: true,
		},
		{
			name: "Missing realm",
			config: &auth.KeycloakConfig{
				BaseURL:      "http://localhost:8080",
				ClientID:     "test",
				ClientSecret: "test",
			},
			shouldError: true,
		},
		{
			name: "Valid config",
			config: &auth.KeycloakConfig{
				BaseURL:      "http://localhost:8080",
				Realm:        "test",
				ClientID:     "test",
				ClientSecret: "test",
			},
			shouldError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := auth.ValidateKeycloakConfig(tc.config)
			if tc.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Benchmark token validation
func BenchmarkTokenValidation(b *testing.B) {
	mockClient := new(MockKeycloakClient)
	config := &auth.KeycloakConfig{
		BaseURL:      "http://localhost:8080",
		Realm:        "zero-trust",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	validClaims := map[string]interface{}{
		"active": true,
		"sub":    "user-123",
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
	}

	mockClient.On("RetrospectToken",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(&validClaims, nil)

	authenticator := &auth.KeycloakAuthenticator{
		Client: mockClient,
		Config: config,
	}

	ctx := context.Background()
	token := "benchmark-token"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = authenticator.ValidateToken(ctx, token)
	}
}

// Test suite runner
func TestKeycloakTestSuite(t *testing.T) {
	suite.Run(t, new(KeycloakTestSuite))
}

// Example test showing how to use the authenticator
func ExampleKeycloakAuthenticator_ValidateToken() {
	// Create config
	config := &auth.KeycloakConfig{
		BaseURL:      "http://localhost:8080",
		Realm:        "zero-trust",
		ClientID:     "my-app",
		ClientSecret: "secret",
	}

	// Create authenticator
	authenticator, err := auth.NewKeycloakAuthenticator(config)
	if err != nil {
		panic(err)
	}
	defer authenticator.Close()

	// Validate token
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
	claims, err := authenticator.ValidateToken(context.Background(), token)
	if err != nil {
		// Handle invalid token
		return
	}

	// Use claims
	fmt.Printf("User: %s, Trust Level: %d\n", claims.UserID, claims.TrustLevel)
}