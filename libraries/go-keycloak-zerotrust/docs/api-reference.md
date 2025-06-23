# API Reference

## Core Types and Interfaces

### KeycloakClient Interface

The main client interface for interacting with Keycloak and Zero Trust features.

```go
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
```

### Configuration Types

#### ZeroTrustConfig

Main configuration structure for the Zero Trust library.

```go
type ZeroTrustConfig struct {
    BaseURL      string               `json:"base_url" yaml:"base_url"`
    Realm        string               `json:"realm" yaml:"realm"`
    ClientID     string               `json:"client_id" yaml:"client_id"`
    ClientSecret string               `json:"client_secret" yaml:"client_secret"`
    AdminUser    string               `json:"admin_user,omitempty" yaml:"admin_user,omitempty"`
    AdminPass    string               `json:"admin_pass,omitempty" yaml:"admin_pass,omitempty"`
    Timeout      time.Duration        `json:"timeout" yaml:"timeout"`
    
    ZeroTrust     *ZeroTrustSettings  `json:"zero_trust,omitempty" yaml:"zero_trust,omitempty"`
    Cache         *CacheConfig        `json:"cache,omitempty" yaml:"cache,omitempty"`
    Observability *ObservabilityConfig `json:"observability,omitempty" yaml:"observability,omitempty"`
}
```

#### ZeroTrustSettings

Configuration for Zero Trust specific features.

```go
type ZeroTrustSettings struct {
    EnableDeviceAttestation   bool                  `json:"enable_device_attestation" yaml:"enable_device_attestation"`
    EnableRiskAssessment      bool                  `json:"enable_risk_assessment" yaml:"enable_risk_assessment"`
    EnableContinuousAuth      bool                  `json:"enable_continuous_auth" yaml:"enable_continuous_auth"`
    DeviceVerificationTTL     time.Duration         `json:"device_verification_ttl" yaml:"device_verification_ttl"`
    TrustDecayInterval        time.Duration         `json:"trust_decay_interval" yaml:"trust_decay_interval"`
    TrustLevelThresholds      TrustLevelThresholds  `json:"trust_level_thresholds" yaml:"trust_level_thresholds"`
    RiskThresholds            RiskThresholds        `json:"risk_thresholds" yaml:"risk_thresholds"`
}
```

### Claims and User Types

#### ZeroTrustClaims

Enhanced JWT claims with Zero Trust information.

```go
type ZeroTrustClaims struct {
    UserID            string            `json:"user_id"`
    Username          string            `json:"username"`
    Email             string            `json:"email"`
    Roles             []string          `json:"roles"`
    TrustLevel        int               `json:"trust_level"`
    DeviceID          string            `json:"device_id,omitempty"`
    DeviceVerified    bool              `json:"device_verified"`
    RiskScore         float64           `json:"risk_score"`
    LastVerification  time.Time         `json:"last_verification"`
    SessionContext    *SessionContext   `json:"session_context,omitempty"`
    CustomClaims      map[string]interface{} `json:"custom_claims,omitempty"`
    
    // Standard JWT claims
    jwt.RegisteredClaims
}
```

#### UserInfo

Detailed user information.

```go
type UserInfo struct {
    UserID       string            `json:"user_id"`
    Username     string            `json:"username"`
    Email        string            `json:"email"`
    FirstName    string            `json:"first_name"`
    LastName     string            `json:"last_name"`
    Roles        []string          `json:"roles"`
    Groups       []string          `json:"groups"`
    Attributes   map[string]interface{} `json:"attributes"`
    TrustLevel   int               `json:"trust_level"`
    DeviceID     string            `json:"device_id,omitempty"`
    RiskScore    float64           `json:"risk_score"`
    CreatedAt    time.Time         `json:"created_at"`
    UpdatedAt    time.Time         `json:"updated_at"`
}
```

## Device Attestation

### DeviceAttestationService

Service for managing device attestation and verification.

```go
type DeviceAttestationService struct {
    config  *ZeroTrustConfig
    storage DeviceStorage
    cache   cache.CacheProvider
}

func NewDeviceAttestationService(config *ZeroTrustConfig, storage DeviceStorage) *DeviceAttestationService

func (s *DeviceAttestationService) AttestDevice(ctx context.Context, attestation *DeviceAttestation) (*VerificationResult, error)
func (s *DeviceAttestationService) VerifyDevice(ctx context.Context, deviceID, userID string) (*VerificationResult, error)
func (s *DeviceAttestationService) GenerateNonce() (string, error)
func (s *DeviceAttestationService) GetDeviceInfo(ctx context.Context, deviceID string) (*Device, error)
func (s *DeviceAttestationService) RevokeDevice(ctx context.Context, deviceID string) error
```

### DeviceAttestation

Structure for device attestation requests.

```go
type DeviceAttestation struct {
    DeviceID          string                 `json:"device_id"`
    UserID            string                 `json:"user_id"`
    Platform          string                 `json:"platform"` // android, ios, web, windows, macos, linux
    DeviceFingerprint string                 `json:"device_fingerprint"`
    HardwareData      map[string]interface{} `json:"hardware_data"`
    SoftwareData      map[string]interface{} `json:"software_data"`
    Timestamp         time.Time              `json:"timestamp"`
    Nonce             string                 `json:"nonce"`
    Signature         string                 `json:"signature"`
    AttestationData   []byte                 `json:"attestation_data,omitempty"`
}
```

### Platform-Specific Attestation

#### Android SafetyNet

```go
type AndroidAttestationData struct {
    SafetyNetToken    string `json:"safetynet_token"`
    CtsProfileMatch   bool   `json:"cts_profile_match"`
    BasicIntegrity    bool   `json:"basic_integrity"`
    EvaluationType    string `json:"evaluation_type"`
    Error             string `json:"error,omitempty"`
}
```

#### iOS DeviceCheck

```go
type IOSAttestationData struct {
    DeviceToken     string `json:"device_token"`
    KeyID           string `json:"key_id"`
    Receipt         []byte `json:"receipt"`
    Challenge       []byte `json:"challenge"`
    AttestationData []byte `json:"attestation_data"`
}
```

#### WebAuthn

```go
type WebAuthnAttestationData struct {
    CredentialID       []byte                 `json:"credential_id"`
    AttestationObject  []byte                 `json:"attestation_object"`
    ClientDataJSON     []byte                 `json:"client_data_json"`
    AuthenticatorData  []byte                 `json:"authenticator_data"`
    Format             string                 `json:"format"`
    PublicKey          []byte                 `json:"public_key"`
    AAGUID             []byte                 `json:"aaguid"`
}
```

## Risk Assessment

### RiskAssessmentEngine

Engine for evaluating session and user risk.

```go
type RiskAssessmentEngine struct {
    config              *ZeroTrustConfig
    behaviorAnalyzer    UserBehaviorAnalyzer
    geolocationService  *GeolocationService
    threatIntelligence  ThreatIntelligenceService
    deviceService       *DeviceAttestationService
    baselineStorage     BaselineStorage
}

func NewRiskAssessmentEngine(
    config *ZeroTrustConfig,
    behaviorAnalyzer UserBehaviorAnalyzer,
    geolocationService *GeolocationService,
    threatIntelligence ThreatIntelligenceService,
    deviceService *DeviceAttestationService,
    baselineStorage BaselineStorage,
) *RiskAssessmentEngine

func (e *RiskAssessmentEngine) AssessRisk(ctx context.Context, session *SessionContext) (*RiskAssessmentResult, error)
func (e *RiskAssessmentEngine) UpdateBaseline(ctx context.Context, userID string, session *SessionContext) error
func (e *RiskAssessmentEngine) GetRiskHistory(ctx context.Context, userID string, limit int) ([]*RiskAssessmentResult, error)
```

### SessionContext

Context information for risk assessment.

```go
type SessionContext struct {
    UserID        string    `json:"user_id"`
    SessionID     string    `json:"session_id"`
    IPAddress     string    `json:"ip_address"`
    UserAgent     string    `json:"user_agent"`
    DeviceID      string    `json:"device_id"`
    Timestamp     time.Time `json:"timestamp"`
    RequestPath   string    `json:"request_path"`
    RequestMethod string    `json:"request_method"`
    Headers       map[string]string `json:"headers"`
    Geolocation   *LocationInfo `json:"geolocation,omitempty"`
    AuthMethod    string    `json:"auth_method"`
    PreviousLogin time.Time `json:"previous_login,omitempty"`
}
```

### RiskAssessmentResult

Result of risk assessment analysis.

```go
type RiskAssessmentResult struct {
    UserID             string                 `json:"user_id"`
    SessionID          string                 `json:"session_id"`
    Timestamp          time.Time              `json:"timestamp"`
    OverallRiskScore   float64                `json:"overall_risk_score"`
    RiskLevel          string                 `json:"risk_level"` // low, medium, high, critical
    RiskFactors        []RiskFactor           `json:"risk_factors"`
    RecommendedActions []string               `json:"recommended_actions"`
    DeviceRisk         *DeviceRiskAssessment  `json:"device_risk,omitempty"`
    BehaviorRisk       *BehaviorRiskAssessment `json:"behavior_risk,omitempty"`
    LocationRisk       *LocationRiskAssessment `json:"location_risk,omitempty"`
    ThreatRisk         *ThreatRiskAssessment  `json:"threat_risk,omitempty"`
}
```

## Trust Engine

### TrustEngine

Engine for calculating and managing trust scores.

```go
type TrustEngine struct {
    config *ZeroTrustConfig
    cache  cache.CacheProvider
}

func NewTrustEngine(config *ZeroTrustConfig) *TrustEngine

func (e *TrustEngine) CalculateTrustScore(ctx context.Context, input *TrustCalculationInput) int
func (e *TrustEngine) DecayTrustScore(currentScore int, timeSinceLastVerification time.Duration) int
func (e *TrustEngine) UpdateTrustScore(ctx context.Context, userID string, newScore int) error
func (e *TrustEngine) GetTrustHistory(ctx context.Context, userID string) ([]*TrustHistoryEntry, error)
```

### TrustCalculationInput

Input parameters for trust score calculation.

```go
type TrustCalculationInput struct {
    UserID               string                      `json:"user_id"`
    VerificationResult   *VerificationResult         `json:"verification_result"`
    AuthenticationMethod string                      `json:"authentication_method"`
    PreviousTrustLevel   int                         `json:"previous_trust_level"`
    RiskScore           float64                     `json:"risk_score"`
    BiometricData       *BiometricVerificationData  `json:"biometric_data,omitempty"`
    DeviceInfo          *Device                     `json:"device_info,omitempty"`
    SessionContext      *SessionContext             `json:"session_context,omitempty"`
}
```

## Middleware

### Gin Middleware

```go
type KeycloakMiddleware struct {
    client types.KeycloakClient
    config *MiddlewareConfig
}

func NewKeycloakMiddleware(client types.KeycloakClient) *KeycloakMiddleware

func (m *KeycloakMiddleware) Authenticate() gin.HandlerFunc
func (m *KeycloakMiddleware) RequireRole(role string) gin.HandlerFunc
func (m *KeycloakMiddleware) RequireTrustLevel(level int) gin.HandlerFunc
func (m *KeycloakMiddleware) RequireDeviceVerification() gin.HandlerFunc
func (m *KeycloakMiddleware) RequireRiskLevel(maxRisk float64) gin.HandlerFunc

// Helper functions
func GetClaims(c *gin.Context) *types.ZeroTrustClaims
func GetUserID(c *gin.Context) string
func GetTrustLevel(c *gin.Context) int
```

### Echo Middleware

```go
func NewEchoMiddleware(client types.KeycloakClient) *EchoKeycloakMiddleware

func (m *EchoKeycloakMiddleware) Authenticate() echo.MiddlewareFunc
func (m *EchoKeycloakMiddleware) RequireRole(role string) echo.MiddlewareFunc
func (m *EchoKeycloakMiddleware) RequireTrustLevel(level int) echo.MiddlewareFunc

// Helper functions
func GetClaimsFromEcho(c echo.Context) *types.ZeroTrustClaims
func GetUserIDFromEcho(c echo.Context) string
```

### Fiber Middleware

```go
func NewFiberMiddleware(client types.KeycloakClient) *FiberKeycloakMiddleware

func (m *FiberKeycloakMiddleware) Authenticate() fiber.Handler
func (m *FiberKeycloakMiddleware) RequireRole(role string) fiber.Handler
func (m *FiberKeycloakMiddleware) RequireTrustLevel(level int) fiber.Handler

// Helper functions
func GetClaimsFromFiber(c *fiber.Ctx) *types.ZeroTrustClaims
func GetUserIDFromFiber(c *fiber.Ctx) string
```

### gRPC Interceptors

```go
func NewGRPCKeycloakInterceptor(client types.KeycloakClient) *GRPCKeycloakInterceptor

func (i *GRPCKeycloakInterceptor) UnaryInterceptor() grpc.UnaryServerInterceptor
func (i *GRPCKeycloakInterceptor) StreamInterceptor() grpc.StreamServerInterceptor

// Helper functions
func GetClaimsFromGRPCContext(ctx context.Context) (*types.ZeroTrustClaims, error)
func GetUserIDFromGRPCContext(ctx context.Context) (string, error)
```

## Configuration Management

### ConfigLoader

Advanced configuration loading with validation and transformation.

```go
type ConfigLoader struct {
    options    LoaderOptions
    validators []ConfigValidator
    transformers []ConfigTransformer
}

func NewConfigLoader(options LoaderOptions) *ConfigLoader

func (l *ConfigLoader) LoadFromFile(filename string) (*types.ZeroTrustConfig, error)
func (l *ConfigLoader) LoadFromBytes(data []byte, format string) (*types.ZeroTrustConfig, error)
func (l *ConfigLoader) LoadFromEnv() (*types.ZeroTrustConfig, error)
func (l *ConfigLoader) ValidateConfig(config *types.ZeroTrustConfig) error
func (l *ConfigLoader) WatchConfig(ctx context.Context, callback func(*types.ZeroTrustConfig)) error
```

### Environment Variable Mapping

```go
// Core Keycloak settings
ZEROTRUST_KEYCLOAK_BASE_URL
ZEROTRUST_KEYCLOAK_REALM
ZEROTRUST_KEYCLOAK_CLIENT_ID
ZEROTRUST_KEYCLOAK_CLIENT_SECRET
ZEROTRUST_KEYCLOAK_ADMIN_USER
ZEROTRUST_KEYCLOAK_ADMIN_PASS

// Zero Trust settings
ZEROTRUST_ZERO_TRUST_ENABLE_DEVICE_ATTESTATION
ZEROTRUST_ZERO_TRUST_ENABLE_RISK_ASSESSMENT
ZEROTRUST_ZERO_TRUST_TRUST_LEVEL_THRESHOLDS_READ
ZEROTRUST_ZERO_TRUST_TRUST_LEVEL_THRESHOLDS_WRITE
ZEROTRUST_ZERO_TRUST_TRUST_LEVEL_THRESHOLDS_ADMIN
ZEROTRUST_ZERO_TRUST_TRUST_LEVEL_THRESHOLDS_DELETE

// Cache settings
ZEROTRUST_CACHE_TYPE
ZEROTRUST_CACHE_DEFAULT_TTL
ZEROTRUST_CACHE_REDIS_HOST
ZEROTRUST_CACHE_REDIS_PORT
ZEROTRUST_CACHE_REDIS_PASSWORD
```

## Plugin System

### Plugin Interface

```go
type Plugin interface {
    GetName() string
    GetVersion() string
    GetDescription() string
    Initialize(ctx context.Context, config map[string]interface{}) error
    Cleanup(ctx context.Context) error
    GetMetadata() PluginMetadata
}

type HookPlugin interface {
    Plugin
    ExecuteHook(ctx context.Context, hookType HookType, data map[string]interface{}) error
    GetHookTypes() []HookType
}
```

### PluginManager

```go
type PluginManager struct {
    config   *PluginConfig
    plugins  map[string]Plugin
    hooks    map[HookType][]HookPlugin
    eventBus *EventBus
}

func NewPluginManager(config *PluginConfig) *PluginManager

func (m *PluginManager) RegisterPlugin(ctx context.Context, plugin Plugin) error
func (m *PluginManager) UnregisterPlugin(ctx context.Context, name string) error
func (m *PluginManager) ExecuteHook(ctx context.Context, hookType HookType, data map[string]interface{}) error
func (m *PluginManager) GetPlugin(name string) (Plugin, bool)
func (m *PluginManager) ListPlugins() []PluginInfo
func (m *PluginManager) Shutdown(ctx context.Context) error
```

## Error Types

```go
var (
    ErrInvalidToken        = errors.New("invalid token")
    ErrTokenExpired        = errors.New("token expired")
    ErrInsufficientTrust   = errors.New("insufficient trust level")
    ErrDeviceNotVerified   = errors.New("device not verified")
    ErrHighRiskSession     = errors.New("high risk session detected")
    ErrUserNotFound        = errors.New("user not found")
    ErrInvalidConfiguration = errors.New("invalid configuration")
    ErrServiceUnavailable  = errors.New("service unavailable")
)

type AuthenticationError struct {
    Code    string `json:"code"`
    Message string `json:"message"`
    Details map[string]interface{} `json:"details,omitempty"`
}

func (e *AuthenticationError) Error() string

type ValidationError struct {
    Field   string `json:"field"`
    Value   interface{} `json:"value"`
    Message string `json:"message"`
}

func (e *ValidationError) Error() string
```

## Metrics and Observability

### Metrics Types

```go
type ClientMetrics struct {
    TokenValidations    int64         `json:"token_validations"`
    TokenValidationErrs int64         `json:"token_validation_errors"`
    CacheHits           int64         `json:"cache_hits"`
    CacheMisses         int64         `json:"cache_misses"`
    RequestCount        int64         `json:"request_count"`
    ErrorCount          int64         `json:"error_count"`
    AverageLatency      time.Duration `json:"average_latency"`
    ActiveSessions      int64         `json:"active_sessions"`
    DeviceAttestations  int64         `json:"device_attestations"`
    RiskAssessments     int64         `json:"risk_assessments"`
}
```

### Prometheus Metrics

```go
// Available Prometheus metrics:
keycloak_zerotrust_token_validations_total
keycloak_zerotrust_token_validation_duration_seconds
keycloak_zerotrust_cache_operations_total
keycloak_zerotrust_device_attestations_total
keycloak_zerotrust_risk_assessments_total
keycloak_zerotrust_trust_score_calculations_total
keycloak_zerotrust_plugin_executions_total
keycloak_zerotrust_active_sessions
```

## Constants

### Trust Levels

```go
const (
    TrustLevelNone   = 0
    TrustLevelLow    = 25
    TrustLevelMedium = 50
    TrustLevelHigh   = 75
    TrustLevelMax    = 100
)
```

### Risk Levels

```go
const (
    RiskLevelLow      = "low"
    RiskLevelMedium   = "medium"
    RiskLevelHigh     = "high"
    RiskLevelCritical = "critical"
)
```

### Platform Types

```go
const (
    PlatformAndroid = "android"
    PlatformIOS     = "ios"
    PlatformWeb     = "web"
    PlatformWindows = "windows"
    PlatformMacOS   = "macos"
    PlatformLinux   = "linux"
)
```

### Authentication Methods

```go
const (
    AuthMethodPassword    = "password"
    AuthMethodMFA        = "mfa"
    AuthMethodBiometric  = "biometric"
    AuthMethodCertificate = "certificate"
    AuthMethodSSO        = "sso"
)
```