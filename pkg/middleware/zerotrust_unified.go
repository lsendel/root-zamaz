// Package middleware provides unified Zero Trust middleware integrating Keycloak, SPIRE, and OPA
package middleware

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	
	"your-project/pkg/auth"
)

// ZeroTrustUnifiedMiddleware provides comprehensive Zero Trust authorization
// combining user identity (Keycloak), workload identity (SPIRE), and policy decisions (OPA)
type ZeroTrustUnifiedMiddleware struct {
	keycloak *auth.KeycloakAuthenticator
	spire    *auth.SPIREAuthenticator
	opa      *auth.OPAAuthorizer
	config   *UnifiedMiddlewareConfig
}

// UnifiedMiddlewareConfig configures the unified Zero Trust middleware
type UnifiedMiddlewareConfig struct {
	// Authentication settings
	SkipPaths          []string      `json:"skipPaths"`
	TokenHeader        string        `json:"tokenHeader"`
	ContextUserKey     string        `json:"contextUserKey"`
	RequestTimeout     time.Duration `json:"requestTimeout"`
	
	// Authorization settings
	DefaultTrustLevel  int           `json:"defaultTrustLevel"`
	RequireWorkloadID  bool          `json:"requireWorkloadId"`
	AuditAllDecisions  bool          `json:"auditAllDecisions"`
	
	// Rate limiting
	RateLimitEnabled   bool          `json:"rateLimitEnabled"`
	RateLimitRequests  int           `json:"rateLimitRequests"`
	RateLimitWindow    time.Duration `json:"rateLimitWindow"`
	
	// Security features
	GeoLocationCheck   bool          `json:"geoLocationCheck"`
	DeviceFingerprint  bool          `json:"deviceFingerprint"`
	SessionIntegrity   bool          `json:"sessionIntegrity"`
	
	// Metrics and monitoring
	MetricsEnabled     bool          `json:"metricsEnabled"`
	DetailedLogging    bool          `json:"detailedLogging"`
}

// NewZeroTrustUnifiedMiddleware creates a new unified Zero Trust middleware
func NewZeroTrustUnifiedMiddleware(
	keycloak *auth.KeycloakAuthenticator,
	spire *auth.SPIREAuthenticator,
	opa *auth.OPAAuthorizer,
	config *UnifiedMiddlewareConfig,
) *ZeroTrustUnifiedMiddleware {
	if config == nil {
		config = &UnifiedMiddlewareConfig{
			TokenHeader:       "Authorization",
			ContextUserKey:    "user",
			RequestTimeout:    10 * time.Second,
			DefaultTrustLevel: 25,
			RateLimitRequests: 100,
			RateLimitWindow:   time.Minute,
			MetricsEnabled:    true,
		}
	}

	return &ZeroTrustUnifiedMiddleware{
		keycloak: keycloak,
		spire:    spire,
		opa:      opa,
		config:   config,
	}
}

// Authenticate provides comprehensive Zero Trust authentication and authorization
func (m *ZeroTrustUnifiedMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()
		requestID := uuid.New().String()
		
		// Set request ID for tracing
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		// Check if path should be skipped
		if m.shouldSkipPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Create context with timeout
		ctx, cancel := context.WithTimeout(c.Request.Context(), m.config.RequestTimeout)
		defer cancel()

		// Step 1: Extract and validate JWT token from Keycloak
		userClaims, err := m.authenticateUser(ctx, c)
		if err != nil {
			m.respondError(c, http.StatusUnauthorized, "Authentication failed", err.Error())
			return
		}

		// Step 2: Get workload identity from SPIRE (if required/available)
		workloadIdentity, err := m.getWorkloadIdentity(ctx)
		if err != nil && m.config.RequireWorkloadID {
			m.respondError(c, http.StatusUnauthorized, "Workload identity required", err.Error())
			return
		}

		// Step 3: Build authorization request context
		authRequest := m.buildAuthorizationRequest(c, userClaims, workloadIdentity, requestID)

		// Step 4: Make authorization decision with OPA
		authResponse, err := m.opa.Authorize(ctx, authRequest)
		if err != nil {
			m.respondError(c, http.StatusInternalServerError, "Authorization check failed", err.Error())
			return
		}

		// Step 5: Check authorization result
		if !authResponse.Allow {
			reasons := "Access denied"
			if len(authResponse.Reasons) > 0 {
				reasons = strings.Join(authResponse.Reasons, ", ")
			}
			m.respondError(c, http.StatusForbidden, "Access denied", reasons)
			return
		}

		// Step 6: Store authentication and authorization context
		m.setRequestContext(c, userClaims, workloadIdentity, authResponse, requestID)

		// Step 7: Log metrics if enabled
		if m.config.MetricsEnabled {
			processingTime := time.Since(startTime)
			m.logMetrics(requestID, processingTime, authResponse)
		}

		c.Next()
	}
}

// authenticateUser validates JWT token with Keycloak
func (m *ZeroTrustUnifiedMiddleware) authenticateUser(ctx context.Context, c *gin.Context) (*auth.ZeroTrustClaims, error) {
	// Extract token from header
	token := m.extractToken(c)
	if token == "" {
		return nil, fmt.Errorf("missing or invalid authorization header")
	}

	// Validate token with Keycloak
	claims, err := m.keycloak.ValidateToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	return claims, nil
}

// getWorkloadIdentity retrieves workload identity from SPIRE
func (m *ZeroTrustUnifiedMiddleware) getWorkloadIdentity(ctx context.Context) (*auth.WorkloadIdentity, error) {
	if m.spire == nil {
		return nil, fmt.Errorf("SPIRE not configured")
	}

	return m.spire.GetWorkloadIdentity(ctx)
}

// buildAuthorizationRequest creates a comprehensive authorization request
func (m *ZeroTrustUnifiedMiddleware) buildAuthorizationRequest(
	c *gin.Context,
	userClaims *auth.ZeroTrustClaims,
	workloadIdentity *auth.WorkloadIdentity,
	requestID string,
) *auth.AuthorizationRequest {
	// Extract resource and action from request
	resource, action := m.extractResourceAction(c)

	// Build user context
	userContext := auth.UserContext{
		UserID:             userClaims.UserID,
		Email:              userClaims.Email,
		Roles:              userClaims.Roles,
		TrustLevel:         userClaims.TrustLevel,
		DeviceID:           userClaims.DeviceID,
		DeviceVerified:     userClaims.DeviceID != "",
		LastVerification:   userClaims.LastVerification,
		SessionFingerprint: m.generateSessionFingerprint(c),
		ExpiresAt:          userClaims.ExpiresAt.Unix(),
	}

	// Build workload context (if available)
	var workloadContext *auth.WorkloadContext
	if workloadIdentity != nil {
		workloadContext = &auth.WorkloadContext{
			SpiffeID:         workloadIdentity.SpiffeID,
			TrustLevel:       workloadIdentity.TrustLevel,
			Attested:         true,
			AttestationType:  workloadIdentity.AttestationType,
			HardwareVerified: workloadIdentity.HardwareVerified,
			CertExpiry:       workloadIdentity.ExpiresAt.Format(time.RFC3339),
		}
	}

	// Build request context
	requestContext := m.buildRequestContext(c, requestID)

	// Build data context (if applicable)
	var dataContext *auth.DataContext
	if purpose := c.Query("purpose"); purpose != "" {
		dataContext = &auth.DataContext{
			Type:       m.inferDataType(resource),
			Scope:      "single_record",
			Attributes: map[string]string{
				"request_method": c.Request.Method,
				"content_type":   c.GetHeader("Content-Type"),
			},
		}
	}

	return &auth.AuthorizationRequest{
		User:     userContext,
		Workload: workloadContext,
		Resource: resource,
		Action:   action,
		Purpose:  c.Query("purpose"),
		Context:  requestContext,
		Data:     dataContext,
	}
}

// buildRequestContext creates detailed request context
func (m *ZeroTrustUnifiedMiddleware) buildRequestContext(c *gin.Context, requestID string) auth.RequestContext {
	// Get client IP address
	clientIP := m.getClientIP(c)

	// Extract country from IP (simplified - would use GeoIP service)
	country := m.getCountryFromIP(clientIP)

	// Build headers map
	headers := make(map[string]string)
	for key, values := range c.Request.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	return auth.RequestContext{
		IPAddress:                clientIP,
		UserAgent:                c.GetHeader("User-Agent"),
		RequestID:                requestID,
		SessionID:                m.extractSessionID(c),
		Country:                  country,
		VPNVerified:              m.isVPNVerified(c),
		FailedAttempts:           m.getFailedAttempts(c),
		UnusualAccessPattern:     m.detectUnusualPattern(c),
		RateLimitExceeded:        m.checkRateLimit(c),
		SensitiveOperationsCount: m.getSensitiveOperationsCount(c),
		Emergency:                c.GetHeader("X-Emergency") == "true",
		Protocol:                 strings.ToLower(c.Request.Proto),
		EnvoyProxy:               c.GetHeader("X-Envoy-Original-Path") != "",
		Headers:                  headers,
	}
}

// Resource and action extraction
func (m *ZeroTrustUnifiedMiddleware) extractResourceAction(c *gin.Context) (string, string) {
	path := c.Request.URL.Path
	method := strings.ToLower(c.Request.Method)

	// Extract resource from path
	resource := "unknown"
	if strings.HasPrefix(path, "/api/") {
		parts := strings.Split(strings.TrimPrefix(path, "/api/"), "/")
		if len(parts) > 0 && parts[0] != "" {
			resource = parts[0]
		}
	}

	// Map HTTP method to action
	action := method
	switch method {
	case "get":
		action = "read"
	case "post":
		if strings.Contains(path, "/search") {
			action = "search"
		} else {
			action = "create"
		}
	case "put", "patch":
		action = "update"
	case "delete":
		action = "delete"
	}

	return resource, action
}

// Session fingerprinting for session integrity
func (m *ZeroTrustUnifiedMiddleware) generateSessionFingerprint(c *gin.Context) string {
	if !m.config.SessionIntegrity {
		return ""
	}

	// Simple fingerprint based on User-Agent and Accept headers
	userAgent := c.GetHeader("User-Agent")
	accept := c.GetHeader("Accept")
	acceptLang := c.GetHeader("Accept-Language")
	
	fingerprint := fmt.Sprintf("%s|%s|%s", userAgent, accept, acceptLang)
	return fingerprint
}

// IP address extraction with proxy support
func (m *ZeroTrustUnifiedMiddleware) getClientIP(c *gin.Context) string {
	// Check X-Forwarded-For header first
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := c.GetHeader("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to remote address
	host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return c.Request.RemoteAddr
	}
	return host
}

// Geographic location check (simplified)
func (m *ZeroTrustUnifiedMiddleware) getCountryFromIP(ip string) string {
	if !m.config.GeoLocationCheck {
		return ""
	}

	// In production, this would use a GeoIP service like MaxMind
	// For now, return a placeholder
	return "US"
}

// Security checks
func (m *ZeroTrustUnifiedMiddleware) isVPNVerified(c *gin.Context) bool {
	// Check for VPN verification header
	return c.GetHeader("X-VPN-Verified") == "true"
}

func (m *ZeroTrustUnifiedMiddleware) getFailedAttempts(c *gin.Context) int {
	// Would integrate with rate limiting/attempt tracking service
	if attempts := c.GetHeader("X-Failed-Attempts"); attempts != "" {
		if count, err := strconv.Atoi(attempts); err == nil {
			return count
		}
	}
	return 0
}

func (m *ZeroTrustUnifiedMiddleware) detectUnusualPattern(c *gin.Context) bool {
	// Simple check for unusual patterns
	userAgent := c.GetHeader("User-Agent")
	
	// Check for suspicious user agents
	suspiciousAgents := []string{"curl", "wget", "python", "bot", "scanner"}
	for _, agent := range suspiciousAgents {
		if strings.Contains(strings.ToLower(userAgent), agent) {
			return true
		}
	}
	
	return false
}

func (m *ZeroTrustUnifiedMiddleware) checkRateLimit(c *gin.Context) bool {
	if !m.config.RateLimitEnabled {
		return false
	}

	// Would integrate with Redis-based rate limiter
	return c.GetHeader("X-Rate-Limit-Exceeded") == "true"
}

func (m *ZeroTrustUnifiedMiddleware) getSensitiveOperationsCount(c *gin.Context) int {
	// Would track sensitive operations in session
	if count := c.GetHeader("X-Sensitive-Ops-Count"); count != "" {
		if num, err := strconv.Atoi(count); err == nil {
			return num
		}
	}
	return 0
}

func (m *ZeroTrustUnifiedMiddleware) extractSessionID(c *gin.Context) string {
	// Try session cookie first
	if cookie, err := c.Cookie("session_id"); err == nil {
		return cookie
	}
	
	// Try header
	return c.GetHeader("X-Session-ID")
}

func (m *ZeroTrustUnifiedMiddleware) inferDataType(resource string) string {
	// Map resource to data type for classification
	dataTypes := map[string]string{
		"users":     "user_profiles",
		"financial": "financial_transactions",
		"health":    "personal_health_information",
		"admin":     "system_configuration",
		"audit":     "audit_logs",
	}

	if dataType, exists := dataTypes[resource]; exists {
		return dataType
	}
	return "general_data"
}

// Context management
func (m *ZeroTrustUnifiedMiddleware) setRequestContext(
	c *gin.Context,
	userClaims *auth.ZeroTrustClaims,
	workloadIdentity *auth.WorkloadIdentity,
	authResponse *auth.AuthorizationResponse,
	requestID string,
) {
	// Set user context
	c.Set(m.config.ContextUserKey, userClaims)
	c.Set("user_id", userClaims.UserID)
	c.Set("user_email", userClaims.Email)
	c.Set("user_roles", userClaims.Roles)
	c.Set("trust_level", userClaims.TrustLevel)
	c.Set("device_id", userClaims.DeviceID)

	// Set workload context
	if workloadIdentity != nil {
		c.Set("workload_spiffe_id", workloadIdentity.SpiffeID)
		c.Set("workload_trust_level", workloadIdentity.TrustLevel)
		c.Set("workload_attested", true)
	}

	// Set authorization context
	c.Set("auth_decision_id", authResponse.DecisionID)
	c.Set("auth_evaluation_time", authResponse.EvaluationTimeMS)
	c.Set("audit_required", authResponse.AuditRequired)
	c.Set("required_trust_level", authResponse.RequiredTrustLevel)

	// Set request context
	c.Set("request_id", requestID)
}

// Utility functions
func (m *ZeroTrustUnifiedMiddleware) extractToken(c *gin.Context) string {
	authHeader := c.GetHeader(m.config.TokenHeader)
	if authHeader == "" {
		return ""
	}

	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	return authHeader
}

func (m *ZeroTrustUnifiedMiddleware) shouldSkipPath(path string) bool {
	for _, skipPath := range m.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

func (m *ZeroTrustUnifiedMiddleware) logMetrics(requestID string, processingTime time.Duration, authResponse *auth.AuthorizationResponse) {
	if m.config.DetailedLogging {
		fmt.Printf("ZeroTrust: request_id=%s processing_time=%dms decision=%t trust_check=%dms\n",
			requestID,
			processingTime.Milliseconds(),
			authResponse.Allow,
			authResponse.EvaluationTimeMS,
		)
	}
}

func (m *ZeroTrustUnifiedMiddleware) respondError(c *gin.Context, status int, message, details string) {
	response := gin.H{
		"error":     message,
		"timestamp": time.Now().Unix(),
	}

	if m.config.DetailedLogging {
		response["details"] = details
	}

	if requestID, exists := c.Get("request_id"); exists {
		response["request_id"] = requestID
	}

	c.JSON(status, response)
	c.Abort()
}

// Authorization helpers for specific requirements

// RequireFullTrust creates middleware that requires FULL trust level (100)
func (m *ZeroTrustUnifiedMiddleware) RequireFullTrust() gin.HandlerFunc {
	return m.RequireTrustLevel(100)
}

// RequireHighTrust creates middleware that requires HIGH trust level (75+)
func (m *ZeroTrustUnifiedMiddleware) RequireHighTrust() gin.HandlerFunc {
	return m.RequireTrustLevel(75)
}

// RequireTrustLevel creates middleware that requires minimum trust level
func (m *ZeroTrustUnifiedMiddleware) RequireTrustLevel(minTrust int) gin.HandlerFunc {
	return func(c *gin.Context) {
		trustLevel, exists := c.Get("trust_level")
		if !exists {
			m.respondError(c, http.StatusUnauthorized, "Authentication required", "No trust level available")
			return
		}

		if trustLevel.(int) < minTrust {
			m.respondError(c, http.StatusForbidden, "Insufficient trust level", 
				fmt.Sprintf("Required: %d, Current: %d", minTrust, trustLevel.(int)))
			return
		}

		c.Next()
	}
}

// RequireRole creates middleware that requires specific roles
func (m *ZeroTrustUnifiedMiddleware) RequireRole(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRoles, exists := c.Get("user_roles")
		if !exists {
			m.respondError(c, http.StatusUnauthorized, "Authentication required", "No roles available")
			return
		}

		roles := userRoles.([]string)
		hasRole := false
		for _, required := range requiredRoles {
			for _, role := range roles {
				if role == required {
					hasRole = true
					break
				}
			}
			if hasRole {
				break
			}
		}

		if !hasRole {
			m.respondError(c, http.StatusForbidden, "Insufficient privileges", 
				fmt.Sprintf("Required roles: %v", requiredRoles))
			return
		}

		c.Next()
	}
}

// RequireWorkloadAttestation creates middleware that requires workload attestation
func (m *ZeroTrustUnifiedMiddleware) RequireWorkloadAttestation() gin.HandlerFunc {
	return func(c *gin.Context) {
		attested, exists := c.Get("workload_attested")
		if !exists || !attested.(bool) {
			m.respondError(c, http.StatusForbidden, "Workload attestation required", 
				"Valid SPIFFE workload identity required")
			return
		}

		c.Next()
	}
}

// GetCurrentContext retrieves the current Zero Trust context
func GetCurrentZeroTrustContext(c *gin.Context) map[string]interface{} {
	context := make(map[string]interface{})

	// User context
	if userID, exists := c.Get("user_id"); exists {
		context["user_id"] = userID
	}
	if userEmail, exists := c.Get("user_email"); exists {
		context["user_email"] = userEmail
	}
	if userRoles, exists := c.Get("user_roles"); exists {
		context["user_roles"] = userRoles
	}
	if trustLevel, exists := c.Get("trust_level"); exists {
		context["trust_level"] = trustLevel
	}

	// Workload context
	if spiffeID, exists := c.Get("workload_spiffe_id"); exists {
		context["workload_spiffe_id"] = spiffeID
	}
	if workloadTrust, exists := c.Get("workload_trust_level"); exists {
		context["workload_trust_level"] = workloadTrust
	}

	// Authorization context
	if decisionID, exists := c.Get("auth_decision_id"); exists {
		context["auth_decision_id"] = decisionID
	}
	if auditRequired, exists := c.Get("audit_required"); exists {
		context["audit_required"] = auditRequired
	}

	return context
}