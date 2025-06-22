package auth

import (
	"context"
	"time"
	
	"mvp.local/pkg/domain/models"
)

// This file demonstrates a refactored interface design following the Interface Segregation Principle
// The large JWTServiceInterface is broken down into smaller, focused interfaces

// TokenGenerator handles token generation operations
type TokenGenerator interface {
	GenerateToken(user *models.User, roles []string, permissions []string) (*LoginResponse, error)
	GenerateTokenWithTrust(ctx context.Context, user *models.User, roles []string, permissions []string, factors TrustFactors) (*LoginResponse, error)
	GenerateRefreshToken(userID string) (string, error)
}

// TokenValidator handles token validation operations
type TokenValidator interface {
	ValidateToken(tokenString string) (*JWTClaims, error)
	ValidateTokenWithTrustCheck(tokenString string, requiredOperation string) (*JWTClaims, error)
	ValidateRefreshToken(tokenString string) (string, error)
}

// TokenManager handles token lifecycle management
type TokenManager interface {
	RefreshAccessToken(refreshToken string, user *models.User, roles []string, permissions []string) (*LoginResponse, error)
	BlacklistToken(ctx context.Context, tokenString, userID, reason string, expiresAt time.Time) error
	BlacklistUserTokens(ctx context.Context, userID, reason string) error
	IsTokenBlacklisted(ctx context.Context, tokenString string) (bool, error)
}

// PasswordService handles password operations
type PasswordService interface {
	HashPassword(password string) (string, error)
	CheckPassword(hashedPassword, password string) error
}

// KeyManager handles JWT key rotation
type KeyManager interface {
	RotateKey() error
	GetKeyManagerStats() map[string]interface{}
}

// UserPermissionService handles user permissions and roles
type UserPermissionService interface {
	GetUserRolesAndPermissions(userID string) ([]string, []string, error)
}

// Complete JWT service would implement all interfaces
type CompleteJWTService interface {
	TokenGenerator
	TokenValidator
	TokenManager
	PasswordService
	KeyManager
	UserPermissionService
}

// Similarly, break down AuthorizationInterface into smaller interfaces

// RoleManager handles role operations
type RoleManager interface {
	AddRoleForUser(userID string, role string) error
	RemoveRoleForUser(userID string, role string) error
	GetRolesForUser(userID string) ([]string, error)
	GetUsersForRole(role string) ([]string, error)
}

// PermissionManager handles permission operations
type PermissionManager interface {
	AddPermissionForRole(role, resource, action string) error
	RemovePermissionForRole(role, resource, action string) error
	GetPermissionsForRole(role string) ([][]string, error)
	GetPermissionsForRoleOptimized(role string, limit, offset int) ([][]string, int64, error)
}

// AccessControl handles access control checks
type AccessControl interface {
	Enforce(userID string, resource, action string) (bool, error)
	CheckPermission(userID string, resource, action string) error
	CheckPermissionWithContext(ctx context.Context, userID string, resource, action string) error
	HasPermission(userID string, permission string) bool
}

// CacheManager handles authorization caching
type CacheManager interface {
	InvalidateUserCache(userID string) error
	InvalidateRoleCache(role string) error
	InvalidateAllCache() error
}

// Complete authorization service would implement all interfaces
type CompleteAuthorizationService interface {
	RoleManager
	PermissionManager
	AccessControl
	CacheManager
}

// Example of how to use these smaller interfaces in practice:

// UserController only needs access control, not role management
type UserController struct {
	auth AccessControl
}

// AdminController needs both role management and access control
type AdminController struct {
	roleManager RoleManager
	accessControl AccessControl
}

// TokenRefreshHandler only needs token validation and generation
type TokenRefreshHandler struct {
	validator TokenValidator
	generator TokenGenerator
}

// This approach provides several benefits:
// 1. Easier to test - mock only what you need
// 2. Better separation of concerns
// 3. Reduced coupling between components
// 4. More flexible dependency injection
// 5. Clearer understanding of component responsibilities

// Example mock for testing:
type MockTokenValidator struct {
	ValidateFunc func(tokenString string) (*JWTClaims, error)
}

func (m *MockTokenValidator) ValidateToken(tokenString string) (*JWTClaims, error) {
	if m.ValidateFunc != nil {
		return m.ValidateFunc(tokenString)
	}
	return nil, nil
}

func (m *MockTokenValidator) ValidateTokenWithTrustCheck(tokenString string, requiredOperation string) (*JWTClaims, error) {
	// Simple mock implementation
	return m.ValidateToken(tokenString)
}

func (m *MockTokenValidator) ValidateRefreshToken(tokenString string) (string, error) {
	// Simple mock implementation
	return "", nil
}