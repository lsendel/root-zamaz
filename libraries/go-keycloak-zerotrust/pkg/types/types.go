// Package types defines core types and interfaces for the go-keycloak-zerotrust library
package types

import (
	"context"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// KeycloakClient defines the core Keycloak operations interface
type KeycloakClient interface {
	// Token operations
	ValidateToken(ctx context.Context, token string) (*ZeroTrustClaims, error)
	RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error)

	// User management
	GetUserInfo(ctx context.Context, userID string) (*UserInfo, error)
	RegisterUser(ctx context.Context, req *UserRegistrationRequest) (*User, error)
	UpdateUserTrustLevel(ctx context.Context, req *TrustLevelUpdateRequest) error
	RevokeUserSessions(ctx context.Context, userID string) error

	// Health and monitoring
	Health(ctx context.Context) error
	GetMetrics(ctx context.Context) (*ClientMetrics, error)
	Close() error
}

// ZeroTrustClaims represents JWT claims with Zero Trust attributes from Keycloak
type ZeroTrustClaims struct {
	// Standard OIDC claims
	UserID            string `json:"sub"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`

	// Authorization claims
	Roles  []string `json:"realm_access.roles"`
	Groups []string `json:"groups,omitempty"`

	// Zero Trust claims
	TrustLevel         int    `json:"trust_level"`
	DeviceID           string `json:"device_id,omitempty"`
	DeviceVerified     bool   `json:"device_verified"`
	LastVerification   string `json:"last_verification,omitempty"`
	RequiresDeviceAuth bool   `json:"requires_device_auth"`

	// Session information
	SessionState   string `json:"session_state"`
	SessionTimeout int    `json:"session_timeout,omitempty"`

	// Risk assessment
	RiskScore      int    `json:"risk_score,omitempty"`
	RiskFactors    []string `json:"risk_factors,omitempty"`
	LocationInfo   *LocationInfo `json:"location_info,omitempty"`

	// Standard JWT claims
	jwt.RegisteredClaims
}

// Config represents the complete library configuration
type Config struct {
	// Keycloak connection
	BaseURL      string `yaml:"base_url" json:"baseUrl"`
	Realm        string `yaml:"realm" json:"realm"`
	ClientID     string `yaml:"client_id" json:"clientId"`
	ClientSecret string `yaml:"client_secret" json:"clientSecret"`

	// Admin credentials (for user management)
	AdminUser string `yaml:"admin_user" json:"adminUser,omitempty"`
	AdminPass string `yaml:"admin_pass" json:"adminPass,omitempty"`

	// HTTP client configuration
	Timeout       time.Duration `yaml:"timeout" json:"timeout"`
	RetryAttempts int           `yaml:"retry_attempts" json:"retryAttempts"`

	// Caching configuration
	Cache *CacheConfig `yaml:"cache" json:"cache,omitempty"`

	// Zero Trust configuration
	ZeroTrust *ZeroTrustConfig `yaml:"zero_trust" json:"zeroTrust,omitempty"`

	// Multi-tenant configuration
	MultiTenant    bool               `yaml:"multi_tenant" json:"multiTenant"`
	TenantResolver TenantResolverFunc `yaml:"-" json:"-"`

	// Framework-specific middleware config
	Middleware *MiddlewareConfig `yaml:"middleware" json:"middleware,omitempty"`

	// Plugin configuration
	Plugins map[string]map[string]interface{} `yaml:"plugins" json:"plugins,omitempty"`
}

// CacheConfig configures the caching layer
type CacheConfig struct {
	Enabled    bool          `yaml:"enabled" json:"enabled"`
	Provider   string        `yaml:"provider" json:"provider"` // "memory", "redis"
	TTL        time.Duration `yaml:"ttl" json:"ttl"`
	MaxSize    int           `yaml:"max_size" json:"maxSize"`
	RedisURL   string        `yaml:"redis_url" json:"redisUrl,omitempty"`
	Prefix     string        `yaml:"prefix" json:"prefix"`
}

// ZeroTrustConfig contains Zero Trust specific configuration
type ZeroTrustConfig struct {
	// Trust level configuration
	DefaultTrustLevel    int           `yaml:"default_trust_level" json:"defaultTrustLevel"`
	TrustLevelThresholds TrustLevelMap `yaml:"trust_level_thresholds" json:"trustLevelThresholds"`

	// Device attestation
	DeviceAttestation     bool          `yaml:"device_attestation" json:"deviceAttestation"`
	DeviceVerificationTTL time.Duration `yaml:"device_verification_ttl" json:"deviceVerificationTTL"`

	// Risk assessment
	RiskAssessment bool             `yaml:"risk_assessment" json:"riskAssessment"`
	RiskThresholds RiskThresholdMap `yaml:"risk_thresholds" json:"riskThresholds"`

	// Continuous verification
	ContinuousVerification bool          `yaml:"continuous_verification" json:"continuousVerification"`
	VerificationInterval   time.Duration `yaml:"verification_interval" json:"verificationInterval"`

	// Geolocation
	GeolocationEnabled bool   `yaml:"geolocation_enabled" json:"geolocationEnabled"`
	GeolocationAPI     string `yaml:"geolocation_api" json:"geolocationApi,omitempty"`
}

// TrustLevelMap defines operation-specific trust level requirements
type TrustLevelMap struct {
	Read   int `yaml:"read" json:"read"`
	Write  int `yaml:"write" json:"write"`
	Admin  int `yaml:"admin" json:"admin"`
	Delete int `yaml:"delete" json:"delete"`
}

// RiskThresholdMap defines risk assessment thresholds
type RiskThresholdMap struct {
	Low       int `yaml:"low" json:"low"`
	Medium    int `yaml:"medium" json:"medium"`
	High      int `yaml:"high" json:"high"`
	Critical  int `yaml:"critical" json:"critical"`
}

// TenantResolverFunc extracts tenant ID from HTTP request
type TenantResolverFunc func(r *http.Request) string

// MiddlewareConfig configures authentication middleware
type MiddlewareConfig struct {
	TokenHeader     string           `yaml:"token_header" json:"tokenHeader"`
	ContextUserKey  string           `yaml:"context_user_key" json:"contextUserKey"`
	SkipPaths       []string         `yaml:"skip_paths" json:"skipPaths"`
	RequestTimeout  time.Duration    `yaml:"request_timeout" json:"requestTimeout"`
	ErrorHandler    ErrorHandlerFunc `yaml:"-" json:"-"`
	CorsEnabled     bool             `yaml:"cors_enabled" json:"corsEnabled"`
	CorsOrigins     []string         `yaml:"cors_origins" json:"corsOrigins"`
}

// ErrorHandlerFunc handles authentication errors
type ErrorHandlerFunc func(ctx context.Context, err error) error

// User management types
type UserRegistrationRequest struct {
	Username   string            `json:"username" validate:"required,min=3,max=50"`
	Email      string            `json:"email" validate:"required,email"`
	FirstName  string            `json:"firstName" validate:"required,min=1,max=50"`
	LastName   string            `json:"lastName" validate:"required,min=1,max=50"`
	Password   string            `json:"password" validate:"required,min=8"`
	TrustLevel int               `json:"trustLevel" validate:"min=0,max=100"`
	DeviceID   string            `json:"deviceId,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type TrustLevelUpdateRequest struct {
	UserID     string `json:"userId" validate:"required"`
	TrustLevel int    `json:"trustLevel" validate:"min=0,max=100"`
	Reason     string `json:"reason" validate:"required"`
	DeviceID   string `json:"deviceId,omitempty"`
	AdminID    string `json:"adminId" validate:"required"`
}

type User struct {
	ID         string                   `json:"id"`
	Username   string                   `json:"username"`
	Email      string                   `json:"email"`
	FirstName  string                   `json:"firstName,omitempty"`
	LastName   string                   `json:"lastName,omitempty"`
	Enabled    bool                     `json:"enabled"`
	Attributes map[string][]string      `json:"attributes,omitempty"`
	CreatedAt  time.Time                `json:"createdAt,omitempty"`
	UpdatedAt  time.Time                `json:"updatedAt,omitempty"`
}

type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresIn    int       `json:"expires_in"`
	TokenType    string    `json:"token_type"`
	IssuedAt     time.Time `json:"issued_at"`
}

type UserInfo struct {
	UserID    string   `json:"sub"`
	Email     string   `json:"email"`
	Username  string   `json:"preferred_username"`
	FirstName string   `json:"given_name"`
	LastName  string   `json:"family_name"`
	Roles     []string `json:"roles"`
}

// AuthenticatedUser represents an authenticated user in the request context
type AuthenticatedUser struct {
	UserID           string    `json:"userId"`
	Email            string    `json:"email"`
	Username         string    `json:"username"`
	FirstName        string    `json:"firstName"`
	LastName         string    `json:"lastName"`
	Roles            []string  `json:"roles"`
	TrustLevel       int       `json:"trustLevel"`
	DeviceID         string    `json:"deviceId,omitempty"`
	DeviceVerified   bool      `json:"deviceVerified"`
	LastVerification string    `json:"lastVerification,omitempty"`
	SessionState     string    `json:"sessionState"`
	ExpiresAt        time.Time `json:"expiresAt"`
	RiskScore        int       `json:"riskScore,omitempty"`
	LocationInfo     *LocationInfo `json:"locationInfo,omitempty"`
}

// ClientMetrics provides operational metrics about the client
type ClientMetrics struct {
	TokenValidations    int64         `json:"tokenValidations"`
	CacheHits          int64         `json:"cacheHits"`
	CacheMisses        int64         `json:"cacheMisses"`
	ErrorCount         int64         `json:"errorCount"`
	AverageLatency     time.Duration `json:"averageLatency"`
	ActiveConnections  int           `json:"activeConnections"`
	HealthStatus       string        `json:"healthStatus"`
	LastHealthCheck    time.Time     `json:"lastHealthCheck"`
}

// LocationInfo contains geolocation data
type LocationInfo struct {
	Country   string  `json:"country,omitempty"`
	Region    string  `json:"region,omitempty"`
	City      string  `json:"city,omitempty"`
	Latitude  float64 `json:"latitude,omitempty"`
	Longitude float64 `json:"longitude,omitempty"`
	ISP       string  `json:"isp,omitempty"`
	Timezone  string  `json:"timezone,omitempty"`
}

// Common error types
type AuthError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *AuthError) Error() string {
	return e.Message
}

// Error codes
const (
	ErrCodeInvalidToken       = "INVALID_TOKEN"
	ErrCodeExpiredToken       = "EXPIRED_TOKEN"
	ErrCodeInsufficientTrust  = "INSUFFICIENT_TRUST_LEVEL"
	ErrCodeDeviceNotVerified  = "DEVICE_NOT_VERIFIED"
	ErrCodeInsufficientRole   = "INSUFFICIENT_ROLE"
	ErrCodeConfigurationError = "CONFIGURATION_ERROR"
	ErrCodeConnectionError    = "CONNECTION_ERROR"
	ErrCodeUnauthorized       = "UNAUTHORIZED"
	ErrCodeForbidden          = "FORBIDDEN"
)

// Predefined errors
var (
	ErrMissingToken        = &AuthError{Code: ErrCodeUnauthorized, Message: "Missing or invalid authorization header"}
	ErrInvalidToken        = &AuthError{Code: ErrCodeInvalidToken, Message: "Invalid or expired token"}
	ErrInsufficientTrust   = &AuthError{Code: ErrCodeInsufficientTrust, Message: "Insufficient trust level"}
	ErrDeviceNotVerified   = &AuthError{Code: ErrCodeDeviceNotVerified, Message: "Device verification required"}
	ErrInsufficientRole    = &AuthError{Code: ErrCodeInsufficientRole, Message: "Insufficient privileges"}
	ErrConfigurationError  = &AuthError{Code: ErrCodeConfigurationError, Message: "Configuration error"}
	ErrConnectionError     = &AuthError{Code: ErrCodeConnectionError, Message: "Connection to Keycloak failed"}
)