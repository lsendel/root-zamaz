//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gorm.io/gorm"

	"mvp.local/pkg/auth"
	"mvp.local/pkg/config"
	"mvp.local/pkg/handlers"
	"mvp.local/pkg/models"
	"mvp.local/pkg/security"
	"mvp.local/pkg/testutil"
	"mvp.local/pkg/validation"
)

// setupAuthTestServer creates a Fiber app with authentication routes backed by
// an in-memory SQLite database. It returns the app instance and JWT service so
// tests can generate hashed passwords.
func setupAuthTestServer(t *testing.T) (*fiber.App, auth.JWTServiceInterface, *gorm.DB) {
	t.Helper()

	// In-memory DB and observability
	db := testutil.SetupTestDB(t)
	obs := testutil.SetupTestObservability(t)

	jwtCfg := &config.JWTConfig{Secret: "test-secret", ExpiryDuration: time.Hour}
	jwtService, err := auth.NewJWTService(jwtCfg, nil)
	require.NoError(t, err)

	lockoutService := security.NewLockoutService(db, obs, nil)
	cfg := &config.Config{Security: config.SecurityConfig{JWT: *jwtCfg}, HTTP: config.HTTPConfig{TLS: config.TLSConfig{Enabled: false}}}

	authHandler := handlers.NewAuthHandler(db, jwtService, nil, lockoutService, nil, nil, obs, cfg)
	authMiddleware := auth.NewAuthMiddleware(jwtService, nil, db, obs, cfg)
	validationMW := validation.NewValidationMiddleware(obs)

	app := fiber.New()
	app.Use(validationMW.ValidationMiddleware())

	api := app.Group("/api")
	authRoutes := api.Group("/auth")
	authRoutes.Post("/login", validationMW.ValidateRequest(auth.LoginRequest{}), authHandler.Login)
	authRoutes.Post("/refresh", validationMW.ValidateRequest(auth.RefreshRequest{}), authHandler.RefreshToken)

	protected := authRoutes.Group("", authMiddleware.RequireAuth())
	protected.Get("/me", authHandler.GetCurrentUser)
	protected.Post("/logout", authHandler.Logout)

	return app, jwtService, db
}

// createTestUser inserts a user with the given credentials into the database.
func createTestUser(t *testing.T, jwtSvc auth.JWTServiceInterface, db *gorm.DB, username, password string) {
	t.Helper()

	hashed, err := jwtSvc.HashPassword(password)
	require.NoError(t, err)

	user := models.User{
		ID:           uuid.New(),
		Username:     username,
		Email:        username + "@example.com",
		PasswordHash: hashed,
		IsActive:     true,
		IsAdmin:      true,
	}
	require.NoError(t, db.Create(&user).Error)
}

func TestAuthenticationFlow(t *testing.T) {
	app, jwtSvc, db := setupAuthTestServer(t)
	createTestUser(t, jwtSvc, db, "admin", "password")

	// Successful login
	loginReq := auth.LoginRequest{Username: "admin", Password: "password"}
	body, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var loginResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&loginResp)
	require.NoError(t, err)
	token := loginResp["token"].(string)
	refreshToken := loginResp["refresh_token"].(string)

	// Access protected endpoint
	req = httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Refresh token
	refreshReq := auth.RefreshRequest{RefreshToken: refreshToken}
	body, _ = json.Marshal(refreshReq)
	req = httptest.NewRequest(http.MethodPost, "/api/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err = app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var refreshResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&refreshResp)
	require.NoError(t, err)
	newToken := refreshResp["token"].(string)

	// Logout using new token
	req = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+newToken)
	resp, err = app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Old token should now be invalid
	req = httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Invalid credentials
	loginReq = auth.LoginRequest{Username: "admin", Password: "wrong"}
	body, _ = json.Marshal(loginReq)
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err = app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
