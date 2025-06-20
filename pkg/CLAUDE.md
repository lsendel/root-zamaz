# Claude Notes: Go Backend Architecture

> **Context**: Go package organization and domain-driven design  
> **Last Updated**: 2025-06-20  
> **Focus**: Zero Trust authentication with comprehensive security

## 🏗️ **Package Architecture Overview**

### **Domain-Driven Design Structure**
The backend follows Clean Architecture principles with domain-driven design:

```
pkg/
├── auth/           # Authentication & JWT management
├── audit/          # GDPR compliance & audit logging  
├── observability/  # Metrics, logging, tracing
├── domain/         # Core business entities & events
├── security/       # Security policies & enforcement
├── resilience/     # Circuit breakers & fault tolerance
└── utils/          # Shared utilities & helpers
```

### **Zero Trust Implementation**
- **Never Trust, Always Verify**: Every request validated
- **Device Attestation**: Hardware-based trust verification
- **Continuous Monitoring**: Real-time security assessment
- **Least Privilege**: Minimal access permissions

## 🔐 **Authentication Package (`auth/`)**

### **Core Components**
- **JWT Handler**: Token generation, validation, blacklisting
- **Middleware**: Request authentication & authorization
- **Session Manager**: Redis-backed session storage
- **Device Attestation**: Hardware trust verification

### **Key Files & Patterns**
```go
// JWT Token Management
type TokenService interface {
    Generate(userID string, claims map[string]interface{}) (*Token, error)
    Validate(tokenString string) (*Claims, error)
    Blacklist(tokenString string) error
    Refresh(refreshToken string) (*Token, error)
}

// Authentication Middleware
func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Extract and validate JWT
        // Check blacklist status
        // Set user context
        // Continue or reject
    }
}
```

### **Security Features**
- **Token Blacklisting**: Immediate revocation capability
- **Refresh Token Rotation**: Enhanced security model
- **Rate Limiting**: Brute force protection
- **Account Lockout**: Progressive security measures

## 📋 **Audit Package (`audit/`)**

### **GDPR Compliance Features**
- **Complete Audit Trail**: Every action logged with context
- **Data Subject Requests**: Right to access, rectify, delete
- **Consent Management**: Granular permission tracking
- **Data Retention**: Automatic policy enforcement

### **Audit Event Structure**
```go
type AuditEvent struct {
    ID           string                 `json:"id"`
    UserID       *string               `json:"user_id,omitempty"`
    Action       string                `json:"action"`
    Resource     string                `json:"resource"`
    Outcome      AuditOutcome          `json:"outcome"`
    Timestamp    time.Time             `json:"timestamp"`
    IPAddress    string                `json:"ip_address"`
    UserAgent    string                `json:"user_agent"`
    RequestID    string                `json:"request_id"`
    Metadata     map[string]interface{} `json:"metadata"`
    RiskLevel    RiskLevel             `json:"risk_level"`
    ComplianceTag *string              `json:"compliance_tag,omitempty"`
}
```

### **Risk Assessment Integration**
- **Automated Risk Scoring**: Pattern-based risk calculation
- **Anomaly Detection**: Unusual behavior flagging
- **Compliance Tagging**: Regulatory requirement tracking
- **Real-time Alerting**: Security incident notification

## 📊 **Observability Package (`observability/`)**

### **Comprehensive Monitoring**
- **Business Metrics**: User engagement, feature usage
- **Performance Metrics**: Response times, throughput
- **Security Metrics**: Failed logins, suspicious activity
- **SLA Monitoring**: Service level objectives tracking

### **Metrics Categories**
```go
// Business Metrics
var (
    UserLoginsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "user_logins_total",
            Help: "Total number of user login attempts",
        },
        []string{"outcome", "user_type"},
    )
    
    ActiveSessionsGauge = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "active_sessions_current",
            Help: "Current number of active user sessions",
        },
        []string{"user_type"},
    )
)

// Security Metrics
var (
    SecurityEventsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "security_events_total",
            Help: "Total number of security events",
        },
        []string{"event_type", "severity"},
    )
)
```

### **Distributed Tracing**
- **Request Correlation**: End-to-end trace tracking
- **Service Dependencies**: Inter-service call mapping
- **Performance Analysis**: Bottleneck identification
- **Error Attribution**: Failure source tracking

## 🏢 **Domain Package (`domain/`)**

### **Core Entities**
```go
// User Domain Entity
type User struct {
    ID              UserID
    Email           EmailAddress
    HashedPassword  HashedPassword
    Profile         UserProfile
    Roles          []Role
    DeviceFingerprint *DeviceFingerprint
    TrustScore     TrustScore
    CreatedAt      time.Time
    UpdatedAt      time.Time
}

// Device Attestation Entity
type DeviceAttestation struct {
    ID              AttestationID
    UserID          UserID
    DeviceFingerprint DeviceFingerprint
    TrustLevel      TrustLevel
    PlatformData    PlatformData
    AttestationTime time.Time
    ExpiresAt       time.Time
}
```

### **Domain Events**
```go
type UserLoggedIn struct {
    UserID       UserID
    SessionID    SessionID
    IPAddress    IPAddress
    UserAgent    UserAgent
    TrustScore   TrustScore
    OccurredAt   time.Time
}

type SuspiciousActivity struct {
    UserID      UserID
    ActivityType ActivityType
    RiskScore   RiskScore
    Details     map[string]interface{}
    DetectedAt  time.Time
}
```

## 🛡️ **Security Package (`security/`)**

### **Security Policies**
- **Password Policies**: Complexity, rotation, history
- **Session Policies**: Timeout, concurrent sessions
- **Access Policies**: Resource-based permissions
- **Risk Policies**: Adaptive security measures

### **Security Implementation**
```go
// Password Policy Enforcement
type PasswordPolicy struct {
    MinLength        int
    RequireUppercase bool
    RequireLowercase bool
    RequireNumbers   bool
    RequireSymbols   bool
    MaxAge          time.Duration
    HistoryCount    int
}

// Request Signing Validation
func ValidateRequestSignature(req *http.Request, secret []byte) error {
    // Extract signature from headers
    // Reconstruct payload
    // Verify HMAC signature
    // Check timestamp to prevent replay
}
```

### **Zero Trust Features**
- **Continuous Verification**: Every request authenticated
- **Context-Aware Access**: Location, device, behavior
- **Adaptive Policies**: Risk-based access decisions
- **Network Segmentation**: Service-level isolation

## 🔄 **Resilience Package (`resilience/`)**

### **Fault Tolerance Patterns**
```go
// Circuit Breaker Implementation
type CircuitBreaker struct {
    name        string
    maxFailures int
    timeout     time.Duration
    state       CircuitState
    failureCount int
    lastFailureTime time.Time
}

// Retry Logic with Exponential Backoff
func WithRetry(operation func() error, maxRetries int) error {
    backoff := time.Second
    for i := 0; i < maxRetries; i++ {
        if err := operation(); err == nil {
            return nil
        }
        time.Sleep(backoff)
        backoff *= 2
    }
    return errors.New("max retries exceeded")
}
```

### **Service Health Monitoring**
- **Health Check Endpoints**: Service availability verification
- **Dependency Monitoring**: External service health tracking
- **Graceful Degradation**: Partial functionality preservation
- **Load Shedding**: Traffic management under stress

## 🔧 **Development Patterns**

### **Dependency Injection**
```go
// Service Dependencies
type Services struct {
    AuthService   auth.Service
    AuditService  audit.Service
    UserRepo      domain.UserRepository
    SessionStore  auth.SessionStore
    MetricsClient observability.MetricsClient
}

// Constructor Pattern
func NewUserService(deps Services) *UserService {
    return &UserService{
        authService:   deps.AuthService,
        auditService:  deps.AuditService,
        userRepo:     deps.UserRepo,
        metricsClient: deps.MetricsClient,
    }
}
```

### **Error Handling Strategy**
```go
// Domain-specific Errors
type DomainError struct {
    Code    ErrorCode
    Message string
    Details map[string]interface{}
    Cause   error
}

// Error Wrapping for Context
func (s *UserService) CreateUser(ctx context.Context, req CreateUserRequest) error {
    if err := s.validateUser(req); err != nil {
        return fmt.Errorf("user validation failed: %w", err)
    }
    
    if err := s.userRepo.Save(ctx, user); err != nil {
        s.auditService.LogError(ctx, "user_creation_failed", err)
        return fmt.Errorf("failed to save user: %w", err)
    }
    
    return nil
}
```

### **Testing Patterns**
```go
// Table-driven Tests
func TestUserService_CreateUser(t *testing.T) {
    tests := []struct {
        name    string
        request CreateUserRequest
        mocks   func(*mocks.MockUserRepo)
        wantErr bool
    }{
        {
            name: "valid user creation",
            request: CreateUserRequest{
                Email:    "test@example.com",
                Password: "SecurePass123!",
            },
            mocks: func(repo *mocks.MockUserRepo) {
                repo.EXPECT().Save(gomock.Any(), gomock.Any()).Return(nil)
            },
            wantErr: false,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

## 🚨 **Critical Security Considerations**

### **Authentication Security**
- **Token Security**: Secure generation, storage, transmission
- **Session Security**: Secure session management, timeout handling
- **Rate Limiting**: Brute force attack protection
- **Account Lockout**: Progressive security measures

### **Data Protection**
- **Encryption**: At rest and in transit
- **PII Handling**: Careful personal data management
- **Audit Compliance**: Complete action trail
- **Data Retention**: Policy-based data lifecycle

### **API Security**
- **Input Validation**: Comprehensive request validation
- **Output Sanitization**: Response data protection
- **CORS Configuration**: Cross-origin security
- **Rate Limiting**: API abuse protection

## 📚 **Related Documentation**

### **Authentication Specific**
- See `pkg/auth/CLAUDE.md` for detailed authentication patterns
- Review JWT implementation in `auth/jwt.go`
- Check middleware configuration in `auth/middleware.go`

### **Security Guidelines**
- Security policies in `pkg/security/`
- Audit requirements in `pkg/audit/`
- Compliance documentation in `/docs/compliance/`

### **Testing & Quality**
- Unit test patterns in `*_test.go` files
- Integration tests in `/tests/integration/`
- Security testing in `/tests/security/`

**Remember**: This backend implements Zero Trust principles throughout. Every component should verify authenticity, maintain audit trails, and implement defense in depth security measures.