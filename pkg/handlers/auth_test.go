package handlers

import (
	"testing"

	"mvp.local/pkg/config"
	"mvp.local/pkg/testutil"
)

func TestAuthHandlerCreation(t *testing.T) {
	// Setup test database
	db := testutil.SetupTestDB(t)

	// Setup mocks
	jwtMock := new(testutil.MockJWTService)
	authzMock := new(testutil.MockAuthorizationService)
	lockoutMock := new(testutil.MockLockoutService)
	obs := testutil.NewMockObservability()
	cfg := &config.Config{}

	// Create handler - this should not panic
	handler := NewAuthHandler(db, jwtMock, authzMock, lockoutMock, obs, cfg)

	if handler == nil {
		t.Fatal("AuthHandler should not be nil")
	}
}
