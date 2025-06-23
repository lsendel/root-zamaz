// Package keycloak provides Zero Trust authentication integration with Keycloak
// This is the main entry point for the go-keycloak-zerotrust library
package keycloak

import (
	"github.com/yourorg/go-keycloak-zerotrust/pkg/client"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/config"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// New creates a new Keycloak Zero Trust client with the provided configuration
func New(cfg *types.Config) (types.KeycloakClient, error) {
	// Validate configuration
	if err := config.Validate(cfg); err != nil {
		return nil, err
	}

	// Create the client
	return client.NewKeycloakClient(cfg)
}

// NewWithDefaults creates a new Keycloak client with default configuration
// and overrides from the provided configuration
func NewWithDefaults(overrides *types.Config) (types.KeycloakClient, error) {
	// Merge with defaults
	cfg := config.Merge(config.DefaultConfig(), overrides)
	
	return New(cfg)
}

// NewFromFile creates a new Keycloak client from a configuration file
func NewFromFile(filePath string) (types.KeycloakClient, error) {
	cfg, err := config.LoadFromFile(filePath)
	if err != nil {
		return nil, err
	}

	return New(cfg)
}

// NewFromEnv creates a new Keycloak client from environment variables
func NewFromEnv() (types.KeycloakClient, error) {
	cfg := config.LoadFromEnv()
	
	return New(cfg)
}

// DefaultConfig returns the default configuration
func DefaultConfig() *types.Config {
	return config.DefaultConfig()
}

// ValidateConfig validates a configuration
func ValidateConfig(cfg *types.Config) error {
	return config.Validate(cfg)
}

// Re-export commonly used types for convenience
type (
	// Core types
	Config              = types.Config
	ZeroTrustClaims     = types.ZeroTrustClaims
	AuthenticatedUser   = types.AuthenticatedUser
	KeycloakClient      = types.KeycloakClient
	
	// Configuration types
	CacheConfig         = types.CacheConfig
	ZeroTrustConfig     = types.ZeroTrustConfig
	MiddlewareConfig    = types.MiddlewareConfig
	TrustLevelMap       = types.TrustLevelMap
	RiskThresholdMap    = types.RiskThresholdMap
	TenantResolverFunc  = types.TenantResolverFunc
	ErrorHandlerFunc    = types.ErrorHandlerFunc
	
	// Request/Response types
	UserRegistrationRequest = types.UserRegistrationRequest
	TrustLevelUpdateRequest = types.TrustLevelUpdateRequest
	TokenPair              = types.TokenPair
	UserInfo               = types.UserInfo
	User                   = types.User
	ClientMetrics          = types.ClientMetrics
	LocationInfo           = types.LocationInfo
	
	// Error types
	AuthError = types.AuthError
)

// Re-export error constants for convenience
const (
	ErrCodeInvalidToken       = types.ErrCodeInvalidToken
	ErrCodeExpiredToken       = types.ErrCodeExpiredToken
	ErrCodeInsufficientTrust  = types.ErrCodeInsufficientTrust
	ErrCodeDeviceNotVerified  = types.ErrCodeDeviceNotVerified
	ErrCodeInsufficientRole   = types.ErrCodeInsufficientRole
	ErrCodeConfigurationError = types.ErrCodeConfigurationError
	ErrCodeConnectionError    = types.ErrCodeConnectionError
	ErrCodeUnauthorized       = types.ErrCodeUnauthorized
	ErrCodeForbidden          = types.ErrCodeForbidden
)

// Re-export predefined errors for convenience
var (
	ErrMissingToken        = types.ErrMissingToken
	ErrInvalidToken        = types.ErrInvalidToken
	ErrInsufficientTrust   = types.ErrInsufficientTrust
	ErrDeviceNotVerified   = types.ErrDeviceNotVerified
	ErrInsufficientRole    = types.ErrInsufficientRole
	ErrConfigurationError  = types.ErrConfigurationError
	ErrConnectionError     = types.ErrConnectionError
)