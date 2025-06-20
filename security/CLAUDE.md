# Claude Notes: Security Architecture & Compliance

> **Context**: Zero Trust security implementation and compliance framework  
> **Last Updated**: 2025-06-20  
> **Focus**: Comprehensive security controls and regulatory compliance

## 🛡️ **Zero Trust Security Architecture**

### **Core Zero Trust Principles**
1. **Never Trust, Always Verify**: Every request authenticated and authorized
2. **Least Privilege Access**: Minimum necessary permissions granted
3. **Assume Breach**: Design for containment and rapid response
4. **Verify Explicitly**: Multi-factor authentication and continuous validation
5. **Network Segmentation**: Micro-perimeters around critical assets

### **Security Layers Implementation**
```
┌─────────────────────────────────────────────────────┐
│                 Identity Layer                      │
│  ├─ JWT Authentication + Refresh Tokens             │
│  ├─ SPIRE/SPIFFE Workload Identity                 │
│  ├─ Device Attestation & Trust Scoring             │
│  └─ Continuous Authentication Validation           │
├─────────────────────────────────────────────────────┤
│                 Network Layer                       │
│  ├─ Istio Service Mesh with mTLS                   │
│  ├─ Network Policies (Default Deny)                │
│  ├─ Envoy Proxy Security Filters                   │
│  └─ Traffic Encryption & Inspection                │
├─────────────────────────────────────────────────────┤
│               Application Layer                     │
│  ├─ Input Validation & Sanitization                │
│  ├─ Output Encoding & CSRF Protection              │
│  ├─ Rate Limiting & DDoS Protection                │
│  └─ Security Headers & Content Policies            │
├─────────────────────────────────────────────────────┤
│                 Data Layer                          │
│  ├─ Encryption at Rest (AES-256)                   │
│  ├─ Encryption in Transit (TLS 1.3)                │
│  ├─ Key Management & Rotation                      │
│  └─ Data Classification & Protection               │
└─────────────────────────────────────────────────────┘
```

## 🔐 **Identity & Access Management**

### **Authentication Architecture**
```go
// Multi-Factor Authentication Flow
type AuthenticationFlow struct {
    PrimaryAuth    PrimaryAuthenticator   // Username/Password
    DeviceAttest   DeviceAttestator      // Hardware attestation
    TrustScore     TrustCalculator       // Behavioral analysis
    TokenIssuer    JWTTokenService       // Token generation
    SessionMgr     SessionManager        // Session lifecycle
}

// Device Attestation
type DeviceAttestation struct {
    DeviceFingerprint string        `json:"device_fingerprint"`
    PlatformData      PlatformInfo  `json:"platform_data"`
    TrustLevel        TrustLevel    `json:"trust_level"`
    AttestationTime   time.Time     `json:"attestation_time"`
    ExpiresAt         time.Time     `json:"expires_at"`
    
    // Hardware attestation data
    TPMData          *TPMAttestation `json:"tpm_data,omitempty"`
    SELinuxContext   string          `json:"selinux_context,omitempty"`
    NetworkContext   NetworkInfo     `json:"network_context"`
}

// Trust Level Calculation
type TrustCalculator interface {
    CalculateTrust(ctx context.Context, factors []TrustFactor) TrustScore
    UpdateTrustScore(userID string, event SecurityEvent) error
    GetTrustHistory(userID string) ([]TrustEvent, error)
}

type TrustFactor struct {
    Type      TrustFactorType `json:"type"`
    Value     float64         `json:"value"`
    Weight    float64         `json:"weight"`
    Source    string          `json:"source"`
    Timestamp time.Time       `json:"timestamp"`
}
```

### **Authorization Model (Casbin RBAC)**
```go
// RBAC Policy Configuration
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _
g2 = _, _  // Domain inheritance

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act

// Policy Examples
p, admin, *, *
p, manager, user:*, read
p, manager, user:*, update
p, user, user:self, read
p, user, user:self, update

g, alice, admin
g, bob, manager
g, charlie, user

// Dynamic Policy Enforcement
type PolicyEnforcer struct {
    enforcer    *casbin.Enforcer
    auditLogger audit.Logger
    metrics     metrics.Collector
}

func (pe *PolicyEnforcer) Enforce(subject, object, action string) (bool, error) {
    // Log authorization attempt
    start := time.Now()
    
    allowed, err := pe.enforcer.Enforce(subject, object, action)
    
    // Audit the decision
    pe.auditLogger.LogAuthorizationDecision(audit.AuthzEvent{
        Subject:   subject,
        Object:    object,
        Action:    action,
        Allowed:   allowed,
        Timestamp: start,
        Duration:  time.Since(start),
    })
    
    // Record metrics
    pe.metrics.RecordAuthzDecision(subject, object, action, allowed)
    
    return allowed, err
}
```

## 🔒 **Cryptographic Security**

### **Encryption Standards**
```go
// Data Encryption Service
type EncryptionService struct {
    keyManager KeyManager
    cipher     cipher.AEAD
}

// AES-256-GCM for data at rest
func (es *EncryptionService) EncryptData(plaintext []byte) ([]byte, error) {
    // Generate random nonce
    nonce := make([]byte, es.cipher.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, fmt.Errorf("failed to generate nonce: %w", err)
    }
    
    // Encrypt with authenticated encryption
    ciphertext := es.cipher.Seal(nonce, nonce, plaintext, nil)
    
    return ciphertext, nil
}

func (es *EncryptionService) DecryptData(ciphertext []byte) ([]byte, error) {
    if len(ciphertext) < es.cipher.NonceSize() {
        return nil, errors.New("ciphertext too short")
    }
    
    nonce, ciphertext := ciphertext[:es.cipher.NonceSize()], ciphertext[es.cipher.NonceSize():]
    
    plaintext, err := es.cipher.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, fmt.Errorf("decryption failed: %w", err)
    }
    
    return plaintext, nil
}

// Key Management
type KeyManager interface {
    GenerateKey() ([]byte, error)
    RotateKey(keyID string) error
    GetKey(keyID string) ([]byte, error)
    DeleteKey(keyID string) error
}

// Hardware Security Module Integration
type HSMKeyManager struct {
    client   hsm.Client
    keyStore map[string]hsm.KeyHandle
}
```

### **TLS/mTLS Configuration**
```yaml
# TLS Security Configuration
apiVersion: v1
kind: Secret
metadata:
  name: tls-certificates
  namespace: zamaz-auth
type: kubernetes.io/tls
data:
  tls.crt: # Base64 encoded certificate
  tls.key: # Base64 encoded private key
  ca.crt:  # Certificate Authority

---
# Istio TLS Policy
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: strict-mtls
  namespace: zamaz-auth
spec:
  mtls:
    mode: STRICT  # Enforce mutual TLS

---
# TLS Configuration for Applications
apiVersion: v1
kind: ConfigMap
metadata:
  name: tls-config
data:
  tls.conf: |
    # TLS 1.3 only
    ssl_protocols TLSv1.3;
    
    # Strong cipher suites
    ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    
    # Additional security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
```

## 📋 **Compliance Framework**

### **GDPR Compliance Implementation**
```go
// GDPR Compliance Service
type GDPRService struct {
    auditLogger    audit.Logger
    dataProcessor  DataProcessor
    consentManager ConsentManager
    retentionMgr   RetentionManager
}

// Data Subject Rights Implementation
func (gs *GDPRService) HandleDataSubjectRequest(req DataSubjectRequest) error {
    switch req.Type {
    case RightToAccess:
        return gs.handleAccessRequest(req)
    case RightToRectification:
        return gs.handleRectificationRequest(req)
    case RightToErasure:
        return gs.handleErasureRequest(req)
    case RightToPortability:
        return gs.handlePortabilityRequest(req)
    default:
        return fmt.Errorf("unsupported request type: %v", req.Type)
    }
}

// Consent Management
type ConsentRecord struct {
    UserID       string            `json:"user_id"`
    Purposes     []ConsentPurpose  `json:"purposes"`
    Timestamp    time.Time         `json:"timestamp"`
    IPAddress    string            `json:"ip_address"`
    UserAgent    string            `json:"user_agent"`
    Granular     bool              `json:"granular"`
    Withdrawable bool              `json:"withdrawable"`
    ExpiresAt    *time.Time        `json:"expires_at,omitempty"`
}

type ConsentPurpose struct {
    Purpose     string    `json:"purpose"`
    Legal       string    `json:"legal_basis"`
    Granted     bool      `json:"granted"`
    Timestamp   time.Time `json:"timestamp"`
    Description string    `json:"description"`
}

// Data Retention Policies
type RetentionPolicy struct {
    DataType        string        `json:"data_type"`
    RetentionPeriod time.Duration `json:"retention_period"`
    PurgeAfter      time.Duration `json:"purge_after"`
    ArchiveRules    []ArchiveRule `json:"archive_rules"`
    ComplianceTags  []string      `json:"compliance_tags"`
}

// Automated Data Lifecycle Management
func (rm *RetentionManager) EnforceRetentionPolicies(ctx context.Context) error {
    policies, err := rm.GetActivePolicies()
    if err != nil {
        return fmt.Errorf("failed to get policies: %w", err)
    }
    
    for _, policy := range policies {
        expiredData, err := rm.FindExpiredData(policy)
        if err != nil {
            continue
        }
        
        for _, data := range expiredData {
            if err := rm.ArchiveOrDelete(data, policy); err != nil {
                rm.logger.Error("failed to process expired data", 
                    "error", err, "data_id", data.ID)
            }
        }
    }
    
    return nil
}
```

### **Audit Logging & Compliance**
```go
// Comprehensive Audit Event
type AuditEvent struct {
    // Core fields
    ID           string                 `json:"id"`
    Timestamp    time.Time              `json:"timestamp"`
    Version      string                 `json:"version"`
    
    // Identity & context
    UserID       *string               `json:"user_id,omitempty"`
    SessionID    *string               `json:"session_id,omitempty"`
    IPAddress    string                `json:"ip_address"`
    UserAgent    string                `json:"user_agent"`
    RequestID    string                `json:"request_id"`
    
    // Action details
    Action       string                `json:"action"`
    Resource     string                `json:"resource"`
    ResourceID   *string               `json:"resource_id,omitempty"`
    Outcome      AuditOutcome          `json:"outcome"`
    
    // Security context
    RiskLevel    RiskLevel             `json:"risk_level"`
    TrustScore   *float64              `json:"trust_score,omitempty"`
    DeviceID     *string               `json:"device_id,omitempty"`
    
    // Compliance
    ComplianceTag *string              `json:"compliance_tag,omitempty"`
    DataCategory  []DataCategory       `json:"data_category,omitempty"`
    
    // Additional context
    Metadata     map[string]interface{} `json:"metadata"`
    Error        *ErrorDetails         `json:"error,omitempty"`
}

// Risk Assessment Integration
type RiskAssessment struct {
    calculator RiskCalculator
    alerter    SecurityAlerter
    metrics    MetricsCollector
}

func (ra *RiskAssessment) AssessRisk(event AuditEvent) RiskLevel {
    factors := []RiskFactor{
        ra.calculateLocationRisk(event.IPAddress),
        ra.calculateTimeRisk(event.Timestamp),
        ra.calculateActionRisk(event.Action),
        ra.calculateFrequencyRisk(event.UserID, event.Action),
    }
    
    risk := ra.calculator.Calculate(factors)
    
    if risk >= RiskLevelHigh {
        ra.alerter.SendSecurityAlert(SecurityAlert{
            Type:      "HighRiskActivity",
            UserID:    event.UserID,
            Risk:      risk,
            Event:     event,
            Timestamp: time.Now(),
        })
    }
    
    ra.metrics.RecordRiskScore(event.Action, risk)
    
    return risk
}
```

## 🚨 **Security Monitoring & Incident Response**

### **Real-time Security Monitoring**
```go
// Security Event Processing Pipeline
type SecurityMonitor struct {
    eventStream   chan SecurityEvent
    processors    []EventProcessor
    alertManager  AlertManager
    correlator    EventCorrelator
}

func (sm *SecurityMonitor) ProcessEvents(ctx context.Context) {
    for {
        select {
        case event := <-sm.eventStream:
            // Process through security filters
            for _, processor := range sm.processors {
                if alert := processor.Process(event); alert != nil {
                    sm.alertManager.Send(alert)
                }
            }
            
            // Correlate with other events
            if incident := sm.correlator.Correlate(event); incident != nil {
                sm.handleSecurityIncident(incident)
            }
            
        case <-ctx.Done():
            return
        }
    }
}

// Anomaly Detection
type AnomalyDetector struct {
    baseline    BaselineModel
    threshold   float64
    alerter     Alerter
}

func (ad *AnomalyDetector) DetectAnomalies(metrics []SecurityMetric) []Anomaly {
    var anomalies []Anomaly
    
    for _, metric := range metrics {
        score := ad.baseline.Score(metric)
        if score > ad.threshold {
            anomaly := Anomaly{
                Type:      "SecurityMetricAnomaly",
                Metric:    metric,
                Score:     score,
                Severity:  ad.calculateSeverity(score),
                Timestamp: time.Now(),
            }
            anomalies = append(anomalies, anomaly)
            
            // Immediate alerting for high severity
            if anomaly.Severity >= SeverityHigh {
                ad.alerter.SendImmediate(anomaly)
            }
        }
    }
    
    return anomalies
}

// Automated Incident Response
type IncidentResponse struct {
    playbooks map[string]ResponsePlaybook
    executor  ActionExecutor
    notifier  NotificationService
}

func (ir *IncidentResponse) HandleIncident(incident SecurityIncident) error {
    playbook, exists := ir.playbooks[incident.Type]
    if !exists {
        return fmt.Errorf("no playbook for incident type: %s", incident.Type)
    }
    
    // Execute automated response actions
    for _, action := range playbook.AutomatedActions {
        if err := ir.executor.Execute(action); err != nil {
            log.Printf("Failed to execute action %s: %v", action.Name, err)
        }
    }
    
    // Notify security team
    return ir.notifier.NotifySecurityTeam(incident, playbook.EscalationLevel)
}
```

### **Security Metrics & KPIs**
```yaml
# Prometheus Security Metrics
groups:
- name: security_metrics
  rules:
  # Authentication metrics
  - record: auth:login_success_rate
    expr: |
      rate(auth_login_attempts_total{status="success"}[5m]) /
      rate(auth_login_attempts_total[5m])
  
  - record: auth:failed_login_rate
    expr: |
      rate(auth_login_attempts_total{status="failed"}[5m])
  
  - record: auth:account_lockout_rate
    expr: |
      rate(auth_account_lockouts_total[5m])
  
  # Security event metrics
  - record: security:high_risk_events_rate
    expr: |
      rate(security_events_total{risk_level="high"}[5m])
  
  - record: security:anomaly_detection_rate
    expr: |
      rate(security_anomalies_total[5m])
  
  # Compliance metrics
  - record: compliance:audit_events_rate
    expr: |
      rate(audit_events_total[5m])
  
  - record: compliance:gdpr_requests_rate
    expr: |
      rate(gdpr_requests_total[5m])

# Security Alerts
- name: security_alerts
  rules:
  - alert: HighFailedLoginRate
    expr: auth:failed_login_rate > 0.1
    for: 2m
    labels:
      severity: warning
      category: authentication
    annotations:
      summary: "High failed login rate detected"
      description: "Failed login rate is {{ $value }} per second"
  
  - alert: SecurityIncidentDetected
    expr: security:high_risk_events_rate > 0.01
    for: 1m
    labels:
      severity: critical
      category: security_incident
    annotations:
      summary: "High risk security events detected"
      description: "High risk events rate: {{ $value }} per second"
  
  - alert: AnomalyDetected
    expr: security:anomaly_detection_rate > 0.005
    for: 5m
    labels:
      severity: warning
      category: anomaly
    annotations:
      summary: "Security anomalies detected"
      description: "Anomaly detection rate: {{ $value }} per second"
```

## 🔧 **Security Configuration Management**

### **Security Headers & Policies**
```go
// Security Headers Middleware
func SecurityHeadersMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // HSTS
        c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        
        // Content Security Policy
        csp := "default-src 'self'; " +
               "script-src 'self' 'unsafe-inline'; " +
               "style-src 'self' 'unsafe-inline'; " +
               "img-src 'self' data: https:; " +
               "font-src 'self' https:; " +
               "connect-src 'self' https://api.zamaz.dev; " +
               "frame-ancestors 'none';"
        c.Header("Content-Security-Policy", csp)
        
        // XSS Protection
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("X-Frame-Options", "DENY")
        c.Header("X-XSS-Protection", "1; mode=block")
        c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
        
        // Remove server information
        c.Header("Server", "")
        c.Header("X-Powered-By", "")
        
        c.Next()
    }
}

// Rate Limiting Configuration
type RateLimitConfig struct {
    Global    RateLimit `yaml:"global"`
    PerUser   RateLimit `yaml:"per_user"`
    PerIP     RateLimit `yaml:"per_ip"`
    Endpoints map[string]RateLimit `yaml:"endpoints"`
}

type RateLimit struct {
    Requests int           `yaml:"requests"`
    Window   time.Duration `yaml:"window"`
    Burst    int           `yaml:"burst"`
}

// DDoS Protection
func DDosProtectionMiddleware(config RateLimitConfig) gin.HandlerFunc {
    limiter := ratelimit.New(config.Global.Requests, config.Global.Window)
    
    return func(c *gin.Context) {
        clientIP := c.ClientIP()
        
        // Check global rate limit
        if !limiter.Allow() {
            c.JSON(http.StatusTooManyRequests, gin.H{
                "error": "rate limit exceeded",
                "retry_after": config.Global.Window.Seconds(),
            })
            c.Abort()
            return
        }
        
        // Check per-IP rate limit
        if !checkIPRateLimit(clientIP, config.PerIP) {
            c.JSON(http.StatusTooManyRequests, gin.H{
                "error": "IP rate limit exceeded",
            })
            c.Abort()
            return
        }
        
        c.Next()
    }
}
```

## 📚 **Security Best Practices**

### **Secure Development Guidelines**
1. **Input Validation**: Validate all input at application boundaries
2. **Output Encoding**: Encode output based on context (HTML, JavaScript, SQL)
3. **Authentication**: Use strong authentication with MFA
4. **Authorization**: Implement fine-grained access controls
5. **Session Management**: Secure session handling and timeout
6. **Error Handling**: Don't leak sensitive information in errors
7. **Logging**: Log security events without sensitive data
8. **Encryption**: Encrypt sensitive data at rest and in transit

### **Security Testing Requirements**
- **Static Analysis**: Code scanning for security vulnerabilities
- **Dynamic Analysis**: Runtime security testing
- **Dependency Scanning**: Third-party vulnerability assessment
- **Penetration Testing**: Regular security assessments
- **Security Code Review**: Manual security-focused reviews

### **Incident Response Procedures**
1. **Detection**: Automated and manual security monitoring
2. **Analysis**: Determine scope and impact of incident
3. **Containment**: Isolate affected systems and limit damage
4. **Eradication**: Remove threat and fix vulnerabilities
5. **Recovery**: Restore systems and verify security
6. **Lessons Learned**: Document and improve security measures

## 🔄 **Related Documentation**

### **Implementation References**
- **Authentication**: See `pkg/auth/CLAUDE.md` for authentication patterns
- **Backend Security**: See `pkg/security/` for security implementations
- **Frontend Security**: See `frontend/CLAUDE.md` for client-side security
- **Infrastructure**: See `deployments/CLAUDE.md` for infrastructure security

### **Compliance Documentation**
- **GDPR Compliance**: Complete data protection implementation
- **SOC 2**: Security controls and audit procedures
- **ISO 27001**: Information security management system
- **NIST Framework**: Cybersecurity framework implementation

**Remember**: Security is not a feature, it's a foundation. Every component, every decision, and every line of code must consider security implications. The Zero Trust model requires continuous verification and assumes that threats exist both inside and outside the network perimeter.