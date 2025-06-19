package testutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"mvp.local/pkg/auth"
	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
	"mvp.local/pkg/security"
)

// MockJWTService is a mock implementation of auth.JWTServiceInterface
type MockJWTService struct {
	mock.Mock
}

func (m *MockJWTService) GenerateToken(user *models.User, roles []string, permissions []string) (*auth.LoginResponse, error) {
	args := m.Called(user, roles, permissions)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.LoginResponse), args.Error(1)
}

func (m *MockJWTService) GenerateRefreshToken(userID string) (string, error) {
	args := m.Called(userID)
	return args.String(0), args.Error(1)
}

func (m *MockJWTService) ValidateToken(tokenString string) (*auth.JWTClaims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.JWTClaims), args.Error(1)
}

func (m *MockJWTService) ValidateRefreshToken(tokenString string) (string, error) {
	args := m.Called(tokenString)
	return args.String(0), args.Error(1)
}

func (m *MockJWTService) RefreshAccessToken(refreshToken string, user *models.User, roles []string, permissions []string) (*auth.LoginResponse, error) {
	args := m.Called(refreshToken, user, roles, permissions)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.LoginResponse), args.Error(1)
}

func (m *MockJWTService) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *MockJWTService) CheckPassword(hashedPassword, password string) error {
	args := m.Called(hashedPassword, password)
	return args.Error(0)
}

func (m *MockJWTService) GetUserRolesAndPermissions(userID string) ([]string, []string, error) {
	args := m.Called(userID)
	roles := args.Get(0).([]string)
	permissions := args.Get(1).([]string)
	return roles, permissions, args.Error(2)
}

func (m *MockJWTService) RotateKey() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockJWTService) GetKeyManagerStats() map[string]interface{} {
	args := m.Called()
	if args.Get(0) == nil {
		return make(map[string]interface{})
	}
	return args.Get(0).(map[string]interface{})
}

// MockAuthorizationService is a mock implementation of auth.AuthorizationInterface
type MockAuthorizationService struct {
	mock.Mock
}

func (m *MockAuthorizationService) Initialize(db *gorm.DB, modelPath string) error {
	args := m.Called(db, modelPath)
	return args.Error(0)
}

func (m *MockAuthorizationService) Enforce(userID string, resource, action string) (bool, error) {
	args := m.Called(userID, resource, action)
	return args.Bool(0), args.Error(1)
}

func (m *MockAuthorizationService) AddRoleForUser(userID string, role string) error {
	args := m.Called(userID, role)
	return args.Error(0)
}

func (m *MockAuthorizationService) RemoveRoleForUser(userID string, role string) error {
	args := m.Called(userID, role)
	return args.Error(0)
}

func (m *MockAuthorizationService) GetRolesForUser(userID string) ([]string, error) {
	args := m.Called(userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockAuthorizationService) GetUsersForRole(role string) ([]string, error) {
	args := m.Called(role)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockAuthorizationService) AddPermissionForRole(role, resource, action string) error {
	args := m.Called(role, resource, action)
	return args.Error(0)
}

func (m *MockAuthorizationService) RemovePermissionForRole(role, resource, action string) error {
	args := m.Called(role, resource, action)
	return args.Error(0)
}

func (m *MockAuthorizationService) GetPermissionsForRole(role string) ([][]string, error) {
	args := m.Called(role)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([][]string), args.Error(1)
}

func (m *MockAuthorizationService) GetUserPermissions(userID string) ([]string, error) {
	args := m.Called(userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockAuthorizationService) CheckPermission(userID string, resource, action string) error {
	args := m.Called(userID, resource, action)
	return args.Error(0)
}

func (m *MockAuthorizationService) LoadPolicy() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockAuthorizationService) SavePolicy() error {
	args := m.Called()
	return args.Error(0)
}

// SetupTestDB creates an in-memory SQLite database for testing
func SetupTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	// Use SQLite in-memory database for tests
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Create simplified test tables for SQLite
	// We need to manually create tables because SQLite doesn't support gen_random_uuid()
	err = db.Exec(`
		CREATE TABLE users (
			id TEXT PRIMARY KEY,
			created_at DATETIME,
			updated_at DATETIME,
			deleted_at DATETIME,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			first_name TEXT,
			last_name TEXT,
			is_active INTEGER DEFAULT 1,
			is_admin INTEGER DEFAULT 0
		);
		
		CREATE TABLE roles (
			id TEXT PRIMARY KEY,
			created_at DATETIME,
			updated_at DATETIME,
			deleted_at DATETIME,
			name TEXT UNIQUE NOT NULL,
			description TEXT,
			is_active BOOLEAN DEFAULT 1
		);
		
		CREATE TABLE permissions (
			id TEXT PRIMARY KEY,
			created_at DATETIME,
			updated_at DATETIME,
			deleted_at DATETIME,
			name TEXT UNIQUE NOT NULL,
			resource TEXT NOT NULL,
			action TEXT NOT NULL,
			description TEXT,
			is_active BOOLEAN DEFAULT 1
		);
		
		CREATE TABLE user_sessions (
			id TEXT PRIMARY KEY,
			created_at DATETIME,
			updated_at DATETIME,
			deleted_at DATETIME,
			user_id TEXT NOT NULL,
			session_token TEXT UNIQUE NOT NULL,
			expires_at DATETIME NOT NULL,
			is_active BOOLEAN DEFAULT 1,
			device_id TEXT,
			ip_address TEXT,
			user_agent TEXT,
			trust_level INTEGER DEFAULT 0
		);
		
		CREATE TABLE device_attestations (
			id TEXT PRIMARY KEY,
			created_at DATETIME,
			updated_at DATETIME,
			deleted_at DATETIME,
			user_id TEXT NOT NULL,
			device_id TEXT NOT NULL,
			attestation_data TEXT,
			is_verified BOOLEAN DEFAULT 0,
			trust_level INTEGER DEFAULT 0,
			last_verified_at DATETIME,
			UNIQUE(user_id, device_id)
		);
		
		CREATE TABLE audit_logs (
			id TEXT PRIMARY KEY,
			created_at DATETIME,
			updated_at DATETIME,
			deleted_at DATETIME,
			user_id TEXT,
			action TEXT NOT NULL,
			resource TEXT NOT NULL,
			details TEXT,
			ip_address TEXT,
			user_agent TEXT,
			request_id TEXT,
			success BOOLEAN DEFAULT 1,
			error_message TEXT
		);
		
		CREATE TABLE user_roles (
			user_id TEXT NOT NULL,
			role_id TEXT NOT NULL,
			PRIMARY KEY (user_id, role_id)
		);
		
		CREATE TABLE role_permissions (
			role_id TEXT NOT NULL,
			permission_id TEXT NOT NULL,
			PRIMARY KEY (role_id, permission_id)
		);
	`).Error
	if err != nil {
		t.Fatalf("Failed to create test tables: %v", err)
	}

	// Clean up on test completion
	t.Cleanup(func() {
		sqlDB, err := db.DB()
		if err == nil {
			sqlDB.Close()
		}
	})

	return db
}

// NewMockObservability creates a mock observability instance for testing
func NewMockObservability() *observability.Observability {
	// Use the existing test observability setup
	obs, _ := observability.New(observability.Config{
		ServiceName:    "test-service",
		ServiceVersion: "test",
		Environment:    "test",
		LogLevel:       "error", // Use error level to reduce noise in tests
		LogFormat:      "console",
		PrometheusPort: 0, // Use random port
	})
	return obs
}

// AssignUserRole is a helper method name fix for the mock
func (m *MockAuthorizationService) AssignUserRole(userID string, role string) error {
	// This is an alias for AddRoleForUser to match the test expectations
	return m.AddRoleForUser(userID, role)
}

// MockLockoutService is a mock implementation of security.LockoutServiceInterface
type MockLockoutService struct {
	mock.Mock
}

func (m *MockLockoutService) CheckAccountLockout(username string) (*security.LockoutStatus, error) {
	args := m.Called(username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*security.LockoutStatus), args.Error(1)
}

func (m *MockLockoutService) RecordFailedAttempt(username, ipAddress, userAgent, requestID, reason string) error {
	args := m.Called(username, ipAddress, userAgent, requestID, reason)
	return args.Error(0)
}

func (m *MockLockoutService) RecordSuccessfulAttempt(username, ipAddress, userAgent, requestID string) error {
	args := m.Called(username, ipAddress, userAgent, requestID)
	return args.Error(0)
}

func (m *MockLockoutService) UnlockAccount(username string) error {
	args := m.Called(username)
	return args.Error(0)
}

func (m *MockLockoutService) CheckIPLockout(ipAddress string) (*security.IPLockoutStatus, error) {
	args := m.Called(ipAddress)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*security.IPLockoutStatus), args.Error(1)
}

func (m *MockLockoutService) CalculateDelay(attemptCount int) time.Duration {
	args := m.Called(attemptCount)
	return args.Get(0).(time.Duration)
}

func (m *MockLockoutService) DetectSuspiciousActivity(username, ipAddress string) (*security.SuspiciousActivityReport, error) {
	args := m.Called(username, ipAddress)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*security.SuspiciousActivityReport), args.Error(1)
}
