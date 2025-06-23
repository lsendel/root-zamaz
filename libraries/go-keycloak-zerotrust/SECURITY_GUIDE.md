# Security Guide for impl-zamaz Projects

> **🔐 Critical**: This guide ensures your impl-zamaz projects maintain the highest security standards when using root-zamaz Zero Trust components.

## 📋 **Security Checklist**

### ✅ **Environment Security**

#### 1. `.gitignore` Configuration
```bash
# CRITICAL: Ensure these files are NEVER committed
.env
.env.*
*.key
*.pem
*.secret
secrets/
```

#### 2. Environment Variables
```bash
# ❌ NEVER do this
KEYCLOAK_CLIENT_SECRET=zerotrust-secret-12345  # Default/weak secret

# ✅ ALWAYS do this
KEYCLOAK_CLIENT_SECRET=$(openssl rand -base64 32)  # Strong generated secret
```

#### 3. File Permissions
```bash
# Set proper permissions on sensitive files
chmod 600 .env
chmod 600 *.key
chmod 700 secrets/
```

### ✅ **Keycloak Security**

#### 1. Admin Credentials
```bash
# ❌ NEVER use defaults in production
KEYCLOAK_ADMIN_USER=admin
KEYCLOAK_ADMIN_PASS=admin

# ✅ ALWAYS use strong credentials
KEYCLOAK_ADMIN_USER=keycloak-admin-$(uuidgen | cut -d'-' -f1)
KEYCLOAK_ADMIN_PASS=$(openssl rand -base64 24)
```

#### 2. Client Secrets
```bash
# Generate strong client secrets
KEYCLOAK_CLIENT_SECRET=$(openssl rand -base64 32)
```

#### 3. SSL/TLS Configuration
```bash
# Production Keycloak MUST use HTTPS
KEYCLOAK_URL=https://keycloak.yourdomain.com  # ✅ Secure
KEYCLOAK_URL=http://localhost:8082            # ❌ Development only
```

### ✅ **Database Security**

#### 1. Connection Security
```bash
# ✅ Use strong passwords
DATABASE_URL=postgresql://user:$(openssl rand -base64 24)@host:5432/db

# ✅ Use SSL connections in production
DATABASE_URL=postgresql://user:pass@host:5432/db?sslmode=require
```

#### 2. Credential Rotation
```bash
# Rotate database passwords regularly (recommended: every 90 days)
./scripts/rotate-db-password.sh
```

### ✅ **Redis Security**

#### 1. Authentication
```bash
# ✅ Always use Redis AUTH
REDIS_URL=redis://:$(openssl rand -base64 24)@localhost:6379

# ✅ Use TLS for Redis in production
REDIS_URL=rediss://:password@redis.yourdomain.com:6380
```

#### 2. Network Security
```bash
# Bind Redis to localhost only
bind 127.0.0.1
protected-mode yes
```

## 🔧 **Configuration Security**

### Trust Level Configuration
```go
// ✅ Secure trust level configuration
config := &types.ZeroTrustConfig{
    DefaultTrustLevel:       25,  // Start with LOW trust
    DeviceAttestation:      true, // Enable in production
    RiskAssessment:         true, // Enable in production
    ContinuousVerification: true, // Enable in production
    VerificationInterval:   4 * time.Hour, // Reasonable interval
}
```

### Cache Configuration
```go
// ✅ Secure cache configuration
Cache: &types.CacheConfig{
    Enabled:  true,
    Provider: "redis",
    RedisURL: os.Getenv("REDIS_URL"), // From environment
    TTL:      30 * time.Minute,       // Reasonable TTL
    Prefix:   "zt:",                  // Namespace cache keys
}
```

### CORS Configuration
```go
// ✅ Secure CORS configuration
middlewareConfig := &types.MiddlewareConfig{
    CorsEnabled: true,
    CorsOrigins: []string{
        "https://yourdomain.com",      // ✅ Specific domains
        "https://app.yourdomain.com",  // ✅ Specific subdomains
        // "http://localhost:3000",    // ❌ Remove in production
        // "*",                        // ❌ NEVER use wildcard
    },
}
```

## 🛡️ **Runtime Security**

### Token Validation
```go
// ✅ Always validate tokens thoroughly
claims, err := keycloakClient.ValidateToken(ctx, token)
if err != nil {
    // Log security event
    log.Warn("Token validation failed", "error", err, "ip", clientIP)
    return handleAuthError(c, err)
}

// ✅ Check token expiration
if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time) {
    return handleAuthError(c, types.ErrExpiredToken)
}
```

### Trust Level Enforcement
```go
// ✅ Enforce trust levels consistently
router.POST("/financial/transfer",
    authMiddleware.RequireRole("admin"),           // Role check
    authMiddleware.RequireTrustLevel(100),         // FULL trust required
    authMiddleware.RequireDeviceVerification(),    // Device verification
    handleFinancialTransfer)
```

### OPA Policy Security
```go
// ✅ Always check OPA authorization for sensitive operations
authzResp, err := opaClient.Authorize(ctx, opa.AuthorizationRequest{
    JWT:      token,
    Resource: "financial_data",
    Action:   "transact",
    UserID:   user.UserID,
    DeviceID: user.DeviceID,
})

if err != nil || !authzResp.Result.Allow {
    // Log security denial
    log.Warn("OPA authorization denied", 
        "user", user.UserID, 
        "resource", "financial_data",
        "reasons", authzResp.Result.Reasons)
    return handleForbidden(c)
}
```

## 🔍 **Security Monitoring**

### Audit Logging
```go
// ✅ Log all security events
type SecurityEvent struct {
    Timestamp   time.Time `json:"timestamp"`
    UserID      string    `json:"user_id"`
    Action      string    `json:"action"`
    Resource    string    `json:"resource"`
    TrustLevel  int       `json:"trust_level"`
    Result      string    `json:"result"`
    IPAddress   string    `json:"ip_address"`
    UserAgent   string    `json:"user_agent"`
}

func logSecurityEvent(event SecurityEvent) {
    log.Info("security_event", "event", event)
}
```

### Rate Limiting
```go
// ✅ Implement rate limiting for all endpoints
router.Use(rateLimitMiddleware(100, time.Minute)) // 100 requests per minute
```

### Failed Authentication Monitoring
```go
// ✅ Monitor and alert on failed authentications
if authErr != nil {
    // Increment failed attempt counter
    incrementFailedAttempts(clientIP, userID)
    
    // Check for brute force attacks
    if getFailedAttempts(clientIP) > 10 {
        // Block IP temporarily
        blockIP(clientIP, 15*time.Minute)
        // Send security alert
        sendSecurityAlert("Potential brute force attack", clientIP)
    }
}
```

## 🚨 **Incident Response**

### Security Event Response
```go
// ✅ Implement security event handlers
func handleSecurityIncident(event SecurityEvent) {
    switch event.Severity {
    case "critical":
        // Immediate action required
        notifySecurityTeam(event)
        if event.Type == "token_abuse" {
            revokeUserTokens(event.UserID)
        }
    case "high":
        // Escalate to security team
        logSecurityIncident(event)
        notifySecurityTeam(event)
    case "medium":
        // Log and monitor
        logSecurityIncident(event)
    }
}
```

### Automatic Response Actions
```go
// ✅ Implement automatic security responses
func enforceSecurityPolicy(user *types.AuthenticatedUser, violation string) {
    switch violation {
    case "suspicious_login":
        // Require re-authentication
        revokeUserSessions(user.UserID)
        requireMFA(user.UserID)
    case "trust_level_violation":
        // Lower trust level
        updateTrustLevel(user.UserID, user.TrustLevel-25, violation)
    case "device_compromise":
        // Block device and require verification
        blockDevice(user.DeviceID)
        requireDeviceReverification(user.UserID)
    }
}
```

## 📊 **Security Metrics**

### Key Security Metrics to Monitor
```go
type SecurityMetrics struct {
    AuthenticationAttempts   int64
    FailedAuthentications   int64
    TokenValidations        int64
    TrustLevelViolations    int64
    DeviceVerificationFails int64
    OPADenials             int64
    SecurityIncidents       int64
}
```

### Alerting Thresholds
```yaml
# Security alerting configuration
security_alerts:
  failed_auth_rate: 10%      # Alert if failed auth rate > 10%
  trust_violations: 5        # Alert if >5 trust violations/hour
  opa_denials: 20            # Alert if >20 OPA denials/hour
  new_device_rate: 50%       # Alert if >50% requests from new devices
```

## 🔒 **Production Deployment Security**

### Environment Separation
```bash
# ✅ Use separate environments
development:   # Local development only
  KEYCLOAK_URL=http://localhost:8082
  
staging:       # Staging environment
  KEYCLOAK_URL=https://keycloak-staging.yourdomain.com
  
production:    # Production environment
  KEYCLOAK_URL=https://keycloak.yourdomain.com
```

### Secret Management
```bash
# ✅ Use proper secret management
# Option 1: Kubernetes secrets
kubectl create secret generic app-secrets \
  --from-literal=keycloak-secret=$(openssl rand -base64 32) \
  --from-literal=database-password=$(openssl rand -base64 32)

# Option 2: HashiCorp Vault
vault kv put secret/myapp \
  keycloak-secret=$(openssl rand -base64 32) \
  database-password=$(openssl rand -base64 32)

# Option 3: AWS Secrets Manager
aws secretsmanager create-secret \
  --name "myapp/keycloak-secret" \
  --secret-string $(openssl rand -base64 32)
```

### TLS Configuration
```go
// ✅ Enforce TLS in production
if os.Getenv("ENVIRONMENT") == "production" {
    // Redirect HTTP to HTTPS
    router.Use(func(c *gin.Context) {
        if c.GetHeader("X-Forwarded-Proto") != "https" {
            httpsURL := "https://" + c.Request.Host + c.Request.RequestURI
            c.Redirect(http.StatusMovedPermanently, httpsURL)
            return
        }
        c.Next()
    })
    
    // Set security headers
    router.Use(func(c *gin.Context) {
        c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("X-Frame-Options", "DENY")
        c.Header("X-XSS-Protection", "1; mode=block")
        c.Next()
    })
}
```

## ✅ **Security Verification Checklist**

Before deploying to production, verify:

- [ ] All default passwords changed
- [ ] Strong secrets generated and stored securely
- [ ] `.env` files excluded from version control
- [ ] TLS enabled for all external communications
- [ ] CORS properly configured (no wildcards)
- [ ] Rate limiting enabled
- [ ] Security headers configured
- [ ] Audit logging enabled
- [ ] Monitoring and alerting configured
- [ ] Incident response procedures documented
- [ ] Security team contacts updated
- [ ] Backup and recovery procedures tested
- [ ] Penetration testing completed
- [ ] Security review completed

## 🆘 **Emergency Procedures**

### Security Breach Response
```bash
# 1. Immediate actions
./scripts/emergency-lockdown.sh        # Disable all access
./scripts/revoke-all-sessions.sh      # Revoke all user sessions
./scripts/rotate-all-secrets.sh       # Rotate all secrets

# 2. Investigation
./scripts/collect-security-logs.sh    # Collect evidence
./scripts/analyze-breach.sh           # Analyze the incident

# 3. Recovery
./scripts/restore-secure-state.sh     # Restore to secure state
./scripts/notify-stakeholders.sh      # Notify affected parties
```

### Contact Information
```yaml
# Keep this information updated and accessible
security_contacts:
  primary: security-team@yourdomain.com
  secondary: ciso@yourdomain.com
  emergency: +1-555-SECURITY
  
incident_response:
  slack_channel: "#security-incidents"
  pagerduty: security-team-pd
  runbook: https://internal.yourdomain.com/security-runbook
```

Remember: **Security is not a feature, it's a fundamental requirement**. Always err on the side of caution and regularly review and update your security measures.