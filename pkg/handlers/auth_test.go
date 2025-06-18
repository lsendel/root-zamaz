package handlers

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"

	"mvp.local/pkg/auth"
	"mvp.local/pkg/config"
	"mvp.local/pkg/models"
	"mvp.local/pkg/testutil"
)

// MockDB is a mock database for testing
type MockDB struct {
	mock.Mock
}

func (m *MockDB) Where(query interface{}, args ...interface{}) *gorm.DB {
	args = append([]interface{}{query}, args...)
	mockArgs := m.Called(args...)
	return mockArgs.Get(0).(*gorm.DB)
}

func (m *MockDB) First(dest interface{}, conds ...interface{}) *gorm.DB {
	args := append([]interface{}{dest}, conds...)
	mockArgs := m.Called(args...)
	return mockArgs.Get(0).(*gorm.DB)
}

func (m *MockDB) Create(value interface{}) *gorm.DB {
	args := m.Called(value)
	return args.Get(0).(*gorm.DB)
}

func (m *MockDB) Model(value interface{}) *gorm.DB {
	args := m.Called(value)
	return args.Get(0).(*gorm.DB)
}

func (m *MockDB) Update(column string, value interface{}) *gorm.DB {
	args := m.Called(column, value)
	return args.Get(0).(*gorm.DB)
}

// Test helper to create a test fiber app
func setupTestApp() *fiber.App {
	app := fiber.New()
	return app
}

func TestAuthHandler_Login(t *testing.T) {
	tests := []struct {
		name         string
		requestBody  auth.LoginRequest
		setupMocks   func(*testutil.MockJWTService, *testutil.MockAuthorizationService, *gorm.DB)
		expectedCode int
		checkBody    func(t *testing.T, body map[string]interface{})
	}{
		{
			name: "successful login with admin user",
			requestBody: auth.LoginRequest{
				Username: "admin",
				Password: "password",
			},
			setupMocks: func(jwtMock *testutil.MockJWTService, authzMock *testutil.MockAuthorizationService, db *gorm.DB) {
				// Create test user
				user := models.User{
					ID:           "test-user-id",
					Username:     "admin",
					Email:        "admin@example.com",
					PasswordHash: "hashed_password",
					IsActive:     true,
					IsAdmin:      true,
					FirstName:    "Admin",
					LastName:     "User",
					CreatedAt:    time.Now(),
					UpdatedAt:    time.Now(),
				}
				db.Create(&user)

				// Mock password check
				jwtMock.On("CheckPassword", "hashed_password", "password").Return(nil)
				
				// Mock getting roles and permissions
				jwtMock.On("GetUserRolesAndPermissions", "test-user-id").Return(
					[]string{"admin", "user"},
					[]string{"system:admin", "user:read"},
					nil,
				)
				
				// Mock token generation
				jwtMock.On("GenerateToken", mock.AnythingOfType("*models.User"), "", 0, 
					[]string{"admin", "user"}, 
					[]string{"system:admin", "user:read"},
				).Return("test-access-token", nil)
				
				// Mock refresh token generation
				jwtMock.On("GenerateRefreshToken", "test-user-id").Return("test-refresh-token", nil)
			},
			expectedCode: fiber.StatusOK,
			checkBody: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "test-access-token", body["token"])
				assert.Equal(t, "test-refresh-token", body["refresh_token"])
				assert.NotNil(t, body["user"])
				
				user := body["user"].(map[string]interface{})
				assert.Equal(t, "admin", user["username"])
				assert.Equal(t, "admin@example.com", user["email"])
				assert.Equal(t, true, user["is_admin"])
				assert.Contains(t, user["roles"], "admin")
			},
		},
		{
			name: "failed login with wrong password",
			requestBody: auth.LoginRequest{
				Username: "admin",
				Password: "wrongpassword",
			},
			setupMocks: func(jwtMock *testutil.MockJWTService, authzMock *testutil.MockAuthorizationService, db *gorm.DB) {
				// Create test user
				user := models.User{
					ID:           "test-user-id",
					Username:     "admin",
					Email:        "admin@example.com",
					PasswordHash: "hashed_password",
					IsActive:     true,
					IsAdmin:      true,
				}
				db.Create(&user)

				// Mock password check failure
				jwtMock.On("CheckPassword", "hashed_password", "wrongpassword").Return(assert.AnError)
			},
			expectedCode: fiber.StatusUnauthorized,
			checkBody: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "Unauthorized", body["error"])
				assert.Equal(t, "Invalid credentials", body["message"])
			},
		},
		{
			name: "failed login with non-existent user",
			requestBody: auth.LoginRequest{
				Username: "nonexistent",
				Password: "password",
			},
			setupMocks: func(jwtMock *testutil.MockJWTService, authzMock *testutil.MockAuthorizationService, db *gorm.DB) {
				// No user created, so query will return not found
			},
			expectedCode: fiber.StatusUnauthorized,
			checkBody: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "Unauthorized", body["error"])
				assert.Equal(t, "Invalid credentials", body["message"])
			},
		},
		{
			name: "failed login with inactive user",
			requestBody: auth.LoginRequest{
				Username: "inactive",
				Password: "password",
			},
			setupMocks: func(jwtMock *testutil.MockJWTService, authzMock *testutil.MockAuthorizationService, db *gorm.DB) {
				// Create inactive user
				user := models.User{
					ID:           "test-user-id",
					Username:     "inactive",
					Email:        "inactive@example.com",
					PasswordHash: "hashed_password",
					IsActive:     false,
				}
				err := db.Create(&user).Error
				assert.NoError(t, err)
				
				// For SQLite, we need to explicitly update the boolean field
				err = db.Model(&models.User{}).Where("username = ?", "inactive").Update("is_active", 0).Error
				assert.NoError(t, err)
			},
			expectedCode: fiber.StatusUnauthorized,
			checkBody: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "Unauthorized", body["error"])
				assert.Equal(t, "Account is disabled", body["message"])
			},
		},
		{
			name: "invalid request with empty credentials",
			requestBody: auth.LoginRequest{
				Username: "",
				Password: "",
			},
			setupMocks:   func(jwtMock *testutil.MockJWTService, authzMock *testutil.MockAuthorizationService, db *gorm.DB) {},
			expectedCode: fiber.StatusBadRequest,
			checkBody: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "Bad Request", body["error"])
				assert.Equal(t, "Username and password are required", body["message"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test database
			db := testutil.SetupTestDB(t)
			
			// Setup mocks
			jwtMock := new(testutil.MockJWTService)
			authzMock := new(testutil.MockAuthorizationService)
			obs := testutil.NewMockObservability()
			cfg := &config.Config{
				Security: config.SecurityConfig{
					DisableAuth: false,
				},
			}
			
			// Setup test data
			tt.setupMocks(jwtMock, authzMock, db)
			
			// Create handler
			handler := NewAuthHandler(db, jwtMock, authzMock, obs, cfg)
			
			// Setup request
			app := setupTestApp()
			app.Post("/auth/login", handler.Login)
			
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			
			// Perform request
			resp, err := app.Test(req)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedCode, resp.StatusCode)
			
			// Check response body
			var responseBody map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&responseBody)
			assert.NoError(t, err)
			
			tt.checkBody(t, responseBody)
			
			// Verify mock expectations
			jwtMock.AssertExpectations(t)
			authzMock.AssertExpectations(t)
		})
	}
}

func TestAuthHandler_Register(t *testing.T) {
	tests := []struct {
		name         string
		requestBody  RegisterRequest
		setupMocks   func(*testutil.MockJWTService, *testutil.MockAuthorizationService, *gorm.DB)
		expectedCode int
		checkBody    func(t *testing.T, body interface{})
	}{
		{
			name: "successful registration",
			requestBody: RegisterRequest{
				Username:  "newuser",
				Email:     "newuser@example.com",
				Password:  "securepassword123",
				FirstName: "New",
				LastName:  "User",
			},
			setupMocks: func(jwtMock *testutil.MockJWTService, authzMock *testutil.MockAuthorizationService, db *gorm.DB) {
				// Mock password hashing
				jwtMock.On("HashPassword", "securepassword123").Return("hashed_password", nil)
				
				// Mock authorization setup - using AddRoleForUser which is the actual interface method
				authzMock.On("AddRoleForUser", mock.AnythingOfType("string"), "user").Return(nil)
			},
			expectedCode: fiber.StatusCreated,
			checkBody: func(t *testing.T, body interface{}) {
				user := body.(map[string]interface{})
				assert.Equal(t, "newuser", user["username"])
				assert.Equal(t, "newuser@example.com", user["email"])
				assert.Equal(t, "New", user["first_name"])
				assert.Equal(t, "User", user["last_name"])
				assert.Equal(t, true, user["is_active"])
				assert.Contains(t, user["roles"], "user")
			},
		},
		{
			name: "registration with existing username",
			requestBody: RegisterRequest{
				Username:  "existinguser",
				Email:     "new@example.com",
				Password:  "password123",
				FirstName: "Test",
				LastName:  "User",
			},
			setupMocks: func(jwtMock *testutil.MockJWTService, authzMock *testutil.MockAuthorizationService, db *gorm.DB) {
				// Create existing user
				existingUser := models.User{
					ID:       "existing-id",
					Username: "existinguser",
					Email:    "existing@example.com",
				}
				db.Create(&existingUser)
			},
			expectedCode: fiber.StatusConflict,
			checkBody: func(t *testing.T, body interface{}) {
				resp := body.(map[string]interface{})
				assert.Equal(t, "Conflict", resp["error"])
				assert.Equal(t, "User already exists", resp["message"])
			},
		},
		{
			name: "registration with existing email",
			requestBody: RegisterRequest{
				Username:  "newuser",
				Email:     "existing@example.com",
				Password:  "password123",
				FirstName: "Test",
				LastName:  "User",
			},
			setupMocks: func(jwtMock *testutil.MockJWTService, authzMock *testutil.MockAuthorizationService, db *gorm.DB) {
				// Create existing user with email
				existingUser := models.User{
					ID:       "existing-id",
					Username: "existinguser",
					Email:    "existing@example.com",
				}
				db.Create(&existingUser)
			},
			expectedCode: fiber.StatusConflict,
			checkBody: func(t *testing.T, body interface{}) {
				resp := body.(map[string]interface{})
				assert.Equal(t, "Conflict", resp["error"])
				assert.Equal(t, "User already exists", resp["message"])
			},
		},
		{
			name: "invalid registration with empty fields",
			requestBody: RegisterRequest{
				Username: "",
				Email:    "",
				Password: "",
			},
			setupMocks:   func(jwtMock *testutil.MockJWTService, authzMock *testutil.MockAuthorizationService, db *gorm.DB) {},
			expectedCode: fiber.StatusBadRequest,
			checkBody: func(t *testing.T, body interface{}) {
				resp := body.(map[string]interface{})
				assert.Equal(t, "Bad Request", resp["error"])
				assert.Equal(t, "Username, email, and password are required", resp["message"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test database
			db := testutil.SetupTestDB(t)
			
			// Setup mocks
			jwtMock := new(testutil.MockJWTService)
			authzMock := new(testutil.MockAuthorizationService)
			obs := testutil.NewMockObservability()
			cfg := &config.Config{}
			
			// Setup test data
			tt.setupMocks(jwtMock, authzMock, db)
			
			// Create handler
			handler := NewAuthHandler(db, jwtMock, authzMock, obs, cfg)
			
			// Setup request
			app := setupTestApp()
			app.Post("/auth/register", handler.Register)
			
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/auth/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			
			// Perform request
			resp, err := app.Test(req)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedCode, resp.StatusCode)
			
			// Check response body
			var responseBody interface{}
			err = json.NewDecoder(resp.Body).Decode(&responseBody)
			assert.NoError(t, err)
			
			tt.checkBody(t, responseBody)
			
			// Verify mock expectations
			jwtMock.AssertExpectations(t)
			authzMock.AssertExpectations(t)
		})
	}
}

func TestAuthHandler_GetCurrentUser(t *testing.T) {
	// Setup test database
	db := testutil.SetupTestDB(t)
	
	// Create test user
	testUser := models.User{
		ID:        "test-user-id",
		Username:  "testuser",
		Email:     "test@example.com",
		FirstName: "Test",
		LastName:  "User",
		IsActive:  true,
		IsAdmin:   false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	db.Create(&testUser)
	
	// Setup mocks
	jwtMock := new(testutil.MockJWTService)
	authzMock := new(testutil.MockAuthorizationService)
	obs := testutil.NewMockObservability()
	cfg := &config.Config{}
	
	// Create handler
	handler := NewAuthHandler(db, jwtMock, authzMock, obs, cfg)
	
	// Setup request with authenticated context
	app := setupTestApp()
	app.Get("/auth/me", func(c *fiber.Ctx) error {
		// Simulate authenticated user context
		c.Locals("user", &testUser)
		c.Locals("roles", []string{"user"})
		return handler.GetCurrentUser(c)
	})
	
	req := httptest.NewRequest("GET", "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	
	// Perform request
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	
	// Check response
	var userResp UserResponse
	err = json.NewDecoder(resp.Body).Decode(&userResp)
	assert.NoError(t, err)
	
	assert.Equal(t, "test-user-id", userResp.ID)
	assert.Equal(t, "testuser", userResp.Username)
	assert.Equal(t, "test@example.com", userResp.Email)
	assert.Equal(t, "Test", userResp.FirstName)
	assert.Equal(t, "User", userResp.LastName)
	assert.Equal(t, true, userResp.IsActive)
	assert.Equal(t, false, userResp.IsAdmin)
	assert.Contains(t, userResp.Roles, "user")
}

func TestAuthHandler_ChangePassword(t *testing.T) {
	tests := []struct {
		name         string
		requestBody  ChangePasswordRequest
		setupMocks   func(*testutil.MockJWTService, *models.User)
		expectedCode int
		checkBody    func(t *testing.T, body map[string]interface{})
	}{
		{
			name: "successful password change",
			requestBody: ChangePasswordRequest{
				CurrentPassword: "oldpassword",
				NewPassword:     "newpassword123",
			},
			setupMocks: func(jwtMock *testutil.MockJWTService, user *models.User) {
				// Mock password verification
				jwtMock.On("CheckPassword", user.PasswordHash, "oldpassword").Return(nil)
				
				// Mock password hashing
				jwtMock.On("HashPassword", "newpassword123").Return("new_hashed_password", nil)
			},
			expectedCode: fiber.StatusOK,
			checkBody: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "Password changed successfully", body["message"])
			},
		},
		{
			name: "failed with wrong current password",
			requestBody: ChangePasswordRequest{
				CurrentPassword: "wrongpassword",
				NewPassword:     "newpassword123",
			},
			setupMocks: func(jwtMock *testutil.MockJWTService, user *models.User) {
				// Mock password verification failure
				jwtMock.On("CheckPassword", user.PasswordHash, "wrongpassword").Return(assert.AnError)
			},
			expectedCode: fiber.StatusUnauthorized,
			checkBody: func(t *testing.T, body map[string]interface{}) {
				assert.Equal(t, "Unauthorized", body["error"])
				assert.Equal(t, "Invalid current password", body["message"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test database
			db := testutil.SetupTestDB(t)
			
			// Create test user
			testUser := models.User{
				ID:           "test-user-id",
				Username:     "testuser",
				Email:        "test@example.com",
				PasswordHash: "old_hashed_password",
				IsActive:     true,
			}
			db.Create(&testUser)
			
			// Setup mocks
			jwtMock := new(testutil.MockJWTService)
			authzMock := new(testutil.MockAuthorizationService)
			obs := testutil.NewMockObservability()
			cfg := &config.Config{}
			
			// Setup test-specific mocks
			tt.setupMocks(jwtMock, &testUser)
			
			// Create handler
			handler := NewAuthHandler(db, jwtMock, authzMock, obs, cfg)
			
			// Setup request with authenticated context
			app := setupTestApp()
			app.Post("/auth/change-password", func(c *fiber.Ctx) error {
				// Simulate authenticated user context
				c.Locals("user", &testUser)
				return handler.ChangePassword(c)
			})
			
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/auth/change-password", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer test-token")
			
			// Perform request
			resp, err := app.Test(req)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedCode, resp.StatusCode)
			
			// Check response body
			var responseBody map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&responseBody)
			assert.NoError(t, err)
			
			tt.checkBody(t, responseBody)
			
			// Verify mock expectations
			jwtMock.AssertExpectations(t)
		})
	}
}