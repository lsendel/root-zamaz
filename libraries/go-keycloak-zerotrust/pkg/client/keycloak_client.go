// Package client provides the core Keycloak client implementation for Zero Trust authentication
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// keycloakClient implements the KeycloakClient interface
type keycloakClient struct {
	// Core Keycloak client
	client *gocloak.GoCloak
	config *types.Config
	
	// Admin token management
	adminToken   *gocloak.JWT
	tokenExpiry  time.Time
	tokenMutex   sync.RWMutex
	
	// Caching layer
	cache    Cache
	
	// Metrics
	metrics  *ClientMetrics
	
	// Shutdown channel
	shutdown chan struct{}
	once     sync.Once
}

// Cache interface for token and user info caching
type Cache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Close() error
}

// memoryCache implements Cache using in-memory storage
type memoryCache struct {
	data   map[string]cacheItem
	mutex  sync.RWMutex
	maxSize int
}

type cacheItem struct {
	value     string
	expiresAt time.Time
}

// redisCache implements Cache using Redis
type redisCache struct {
	client *redis.Client
	prefix string
}

// ClientMetrics tracks operational metrics
type ClientMetrics struct {
	TokenValidations    int64         `json:"tokenValidations"`
	CacheHits          int64         `json:"cacheHits"`
	CacheMisses        int64         `json:"cacheMisses"`
	ErrorCount         int64         `json:"errorCount"`
	AverageLatency     time.Duration `json:"averageLatency"`
	ActiveConnections  int           `json:"activeConnections"`
	HealthStatus       string        `json:"healthStatus"`
	LastHealthCheck    time.Time     `json:"lastHealthCheck"`
	mutex              sync.RWMutex
}

// NewKeycloakClient creates a new Keycloak client with Zero Trust features
func NewKeycloakClient(config *types.Config) (types.KeycloakClient, error) {
	if config == nil {
		return nil, &types.AuthError{
			Code:    types.ErrCodeConfigurationError,
			Message: "configuration cannot be nil",
		}
	}

	// Validate required configuration
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	// Initialize Keycloak client
	gocloakClient := gocloak.NewClient(config.BaseURL)
	if config.Timeout > 0 {
		gocloakClient.SetTimeout(config.Timeout)
	}

	// Initialize cache
	cache, err := initializeCache(config.Cache)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cache: %w", err)
	}

	client := &keycloakClient{
		client:   gocloakClient,
		config:   config,
		cache:    cache,
		metrics:  &ClientMetrics{},
		shutdown: make(chan struct{}),
	}

	// Get initial admin token if admin credentials provided
	if config.AdminUser != "" && config.AdminPass != "" {
		if err := client.refreshAdminToken(context.Background()); err != nil {
			if closeErr := cache.Close(); closeErr != nil {
				fmt.Printf("Warning: failed to close cache during cleanup: %v\n", closeErr)
			}
			return nil, fmt.Errorf("failed to get initial admin token: %w", err)
		}
	}

	// Start background token refresh if admin credentials available
	if config.AdminUser != "" && config.AdminPass != "" {
		go client.tokenRefreshLoop()
	}

	return client, nil
}

// validateConfig validates the client configuration
func validateConfig(config *types.Config) error {
	if config.BaseURL == "" {
		return &types.AuthError{
			Code:    types.ErrCodeConfigurationError,
			Message: "baseURL is required",
		}
	}
	if config.Realm == "" {
		return &types.AuthError{
			Code:    types.ErrCodeConfigurationError,
			Message: "realm is required",
		}
	}
	if config.ClientID == "" {
		return &types.AuthError{
			Code:    types.ErrCodeConfigurationError,
			Message: "clientID is required",
		}
	}
	if config.ClientSecret == "" {
		return &types.AuthError{
			Code:    types.ErrCodeConfigurationError,
			Message: "clientSecret is required",
		}
	}
	return nil
}

// initializeCache creates and configures the caching layer
func initializeCache(config *types.CacheConfig) (Cache, error) {
	if config == nil || !config.Enabled {
		return newMemoryCache(1000), nil // Default memory cache
	}

	switch config.Provider {
	case "redis":
		if config.RedisURL == "" {
			return nil, fmt.Errorf("redis URL required for redis cache provider")
		}
		return newRedisCache(config.RedisURL, config.Prefix)
	case "memory", "":
		maxSize := config.MaxSize
		if maxSize <= 0 {
			maxSize = 1000
		}
		return newMemoryCache(maxSize), nil
	default:
		return nil, fmt.Errorf("unsupported cache provider: %s", config.Provider)
	}
}

// ValidateToken validates a JWT token using Keycloak token introspection
func (k *keycloakClient) ValidateToken(ctx context.Context, token string) (*types.ZeroTrustClaims, error) {
	start := time.Now()
	defer func() {
		k.metrics.mutex.Lock()
		k.metrics.TokenValidations++
		k.metrics.AverageLatency = (k.metrics.AverageLatency + time.Since(start)) / 2
		k.metrics.mutex.Unlock()
	}()

	if token == "" {
		k.incrementErrorCount()
		return nil, types.ErrMissingToken
	}

	// Remove Bearer prefix if present
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}

	// Check cache first
	cacheKey := k.getCacheKey("token", token)
	if cached, err := k.cache.Get(ctx, cacheKey); err == nil && cached != "" {
		k.metrics.mutex.Lock()
		k.metrics.CacheHits++
		k.metrics.mutex.Unlock()
		
		var claims types.ZeroTrustClaims
		if err := json.Unmarshal([]byte(cached), &claims); err == nil {
			// Check if cached token is still valid
			if claims.ExpiresAt != nil && time.Now().Before(claims.ExpiresAt.Time) {
				return &claims, nil
			}
		}
	}

	k.metrics.mutex.Lock()
	k.metrics.CacheMisses++
	k.metrics.mutex.Unlock()

	// Introspect token with Keycloak
	rptResult, err := k.client.RetrospectToken(ctx, token, k.config.ClientID, k.config.ClientSecret, k.config.Realm)
	if err != nil {
		k.incrementErrorCount()
		return nil, &types.AuthError{
			Code:    types.ErrCodeConnectionError,
			Message: "token introspection failed",
			Details: err.Error(),
		}
	}

	if !*rptResult.Active {
		k.incrementErrorCount()
		return nil, types.ErrInvalidToken
	}

	// Get user info for additional claims
	userInfo, err := k.client.GetUserInfo(ctx, token, k.config.Realm)
	if err != nil {
		k.incrementErrorCount()
		return nil, &types.AuthError{
			Code:    types.ErrCodeConnectionError,
			Message: "failed to get user info",
			Details: err.Error(),
		}
	}

	// Parse JWT to extract all claims
	claims, err := k.parseJWTClaims(token, userInfo)
	if err != nil {
		k.incrementErrorCount()
		return nil, err
	}

	// Apply Zero Trust policy evaluation
	if k.config.ZeroTrust != nil {
		if err := k.evaluateZeroTrustPolicy(claims); err != nil {
			k.incrementErrorCount()
			return nil, err
		}
	}

	// Cache the validated claims
	if claimsJSON, err := json.Marshal(claims); err == nil {
		ttl := time.Hour // Default cache TTL
		if k.config.Cache != nil && k.config.Cache.TTL > 0 {
			ttl = k.config.Cache.TTL
		}
		if err := k.cache.Set(ctx, cacheKey, string(claimsJSON), ttl); err != nil {
			// Log the cache error but don't fail the validation
			fmt.Printf("Warning: failed to cache token claims: %v\n", err)
		}
	}

	return claims, nil
}

// RefreshToken refreshes an access token using the refresh token
func (k *keycloakClient) RefreshToken(ctx context.Context, refreshToken string) (*types.TokenPair, error) {
	if refreshToken == "" {
		k.incrementErrorCount()
		return nil, &types.AuthError{
			Code:    types.ErrCodeInvalidToken,
			Message: "refresh token cannot be empty",
		}
	}

	// Use Keycloak client to refresh the token
	jwt, err := k.client.RefreshToken(ctx, refreshToken, k.config.ClientID, k.config.ClientSecret, k.config.Realm)
	if err != nil {
		k.incrementErrorCount()
		return nil, &types.AuthError{
			Code:    types.ErrCodeInvalidToken,
			Message: "failed to refresh token",
			Details: err.Error(),
		}
	}

	return &types.TokenPair{
		AccessToken:  jwt.AccessToken,
		RefreshToken: jwt.RefreshToken,
		ExpiresIn:    jwt.ExpiresIn,
		TokenType:    jwt.TokenType,
		IssuedAt:     time.Now(),
	}, nil
}

// GetUserInfo retrieves user information by user ID
func (k *keycloakClient) GetUserInfo(ctx context.Context, userID string) (*types.UserInfo, error) {
	if err := k.ensureValidAdminToken(ctx); err != nil {
		return nil, err
	}

	user, err := k.client.GetUserByID(ctx, k.adminToken.AccessToken, k.config.Realm, userID)
	if err != nil {
		k.incrementErrorCount()
		return nil, &types.AuthError{
			Code:    types.ErrCodeConnectionError,
			Message: "failed to get user",
			Details: err.Error(),
		}
	}

	userInfo := &types.UserInfo{
		UserID:    *user.ID,
		Email:     getStringPtr(user.Email),
		Username:  getStringPtr(user.Username),
		FirstName: getStringPtr(user.FirstName),
		LastName:  getStringPtr(user.LastName),
	}

	// Get user roles
	roles, err := k.client.GetRealmRolesByUserID(ctx, k.adminToken.AccessToken, k.config.Realm, userID)
	if err == nil {
		for _, role := range roles {
			userInfo.Roles = append(userInfo.Roles, *role.Name)
		}
	}

	return userInfo, nil
}

// RegisterUser creates a new user in Keycloak with Zero Trust attributes
func (k *keycloakClient) RegisterUser(ctx context.Context, req *types.UserRegistrationRequest) (*types.User, error) {
	if err := k.ensureValidAdminToken(ctx); err != nil {
		return nil, err
	}

	// Prepare user attributes with Zero Trust data
	attributes := map[string][]string{
		"trust_level":       {strconv.Itoa(req.TrustLevel)},
		"last_verification": {time.Now().Format(time.RFC3339)},
	}

	if req.DeviceID != "" {
		attributes["device_id"] = []string{req.DeviceID}
	}

	// Add any additional attributes
	for key, value := range req.Attributes {
		attributes[key] = []string{value}
	}

	user := gocloak.User{
		Username:      &req.Username,
		Email:         &req.Email,
		FirstName:     &req.FirstName,
		LastName:      &req.LastName,
		Enabled:       gocloak.BoolP(true),
		EmailVerified: gocloak.BoolP(false),
		Attributes:    &attributes,
		RequiredActions: &[]string{
			"VERIFY_EMAIL",
		},
	}

	// Create user
	userID, err := k.client.CreateUser(ctx, k.adminToken.AccessToken, k.config.Realm, user)
	if err != nil {
		k.incrementErrorCount()
		return nil, &types.AuthError{
			Code:    types.ErrCodeConnectionError,
			Message: "failed to create user",
			Details: err.Error(),
		}
	}

	// Set password
	err = k.client.SetPassword(ctx, k.adminToken.AccessToken, k.config.Realm, userID, req.Password, false)
	if err != nil {
		// Cleanup: delete the created user if password setting fails
		k.client.DeleteUser(ctx, k.adminToken.AccessToken, k.config.Realm, userID)
		k.incrementErrorCount()
		return nil, &types.AuthError{
			Code:    types.ErrCodeConnectionError,
			Message: "failed to set password",
			Details: err.Error(),
		}
	}

	// Assign default user role
	userRole, err := k.client.GetRealmRole(ctx, k.adminToken.AccessToken, k.config.Realm, "user")
	if err != nil {
		log.Printf("Warning: could not get user role: %v", err)
	} else {
		err = k.client.AddRealmRoleToUser(ctx, k.adminToken.AccessToken, k.config.Realm, userID, []gocloak.Role{*userRole})
		if err != nil {
			log.Printf("Warning: could not assign user role: %v", err)
		}
	}

	// Get the created user to return
	createdUser, err := k.client.GetUserByID(ctx, k.adminToken.AccessToken, k.config.Realm, userID)
	if err != nil {
		k.incrementErrorCount()
		return nil, &types.AuthError{
			Code:    types.ErrCodeConnectionError,
			Message: "failed to retrieve created user",
			Details: err.Error(),
		}
	}

	return &types.User{
		ID:         *createdUser.ID,
		Username:   getStringPtr(createdUser.Username),
		Email:      getStringPtr(createdUser.Email),
		FirstName:  getStringPtr(createdUser.FirstName),
		LastName:   getStringPtr(createdUser.LastName),
		Enabled:    getBoolPtr(createdUser.Enabled),
		Attributes: createdUser.Attributes,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}, nil
}

// UpdateUserTrustLevel updates a user's trust level with audit logging
func (k *keycloakClient) UpdateUserTrustLevel(ctx context.Context, req *types.TrustLevelUpdateRequest) error {
	if err := k.ensureValidAdminToken(ctx); err != nil {
		return err
	}

	// Get current user
	user, err := k.client.GetUserByID(ctx, k.adminToken.AccessToken, k.config.Realm, req.UserID)
	if err != nil {
		k.incrementErrorCount()
		return &types.AuthError{
			Code:    types.ErrCodeConnectionError,
			Message: "failed to get user",
			Details: err.Error(),
		}
	}

	// Get current trust level for audit
	oldTrustLevel := k.config.ZeroTrust.DefaultTrustLevel
	if oldTrustLevel == 0 {
		oldTrustLevel = 25 // Default
	}
	
	if user.Attributes != nil {
		if levels, exists := (*user.Attributes)["trust_level"]; exists && len(levels) > 0 {
			if level, err := strconv.Atoi(levels[0]); err == nil {
				oldTrustLevel = level
			}
		}
	}

	// Update user attributes
	if user.Attributes == nil {
		user.Attributes = &map[string][]string{}
	}

	(*user.Attributes)["trust_level"] = []string{strconv.Itoa(req.TrustLevel)}
	(*user.Attributes)["last_verification"] = []string{time.Now().Format(time.RFC3339)}
	
	if req.DeviceID != "" {
		(*user.Attributes)["device_id"] = []string{req.DeviceID}
	}

	// Update user in Keycloak
	err = k.client.UpdateUser(ctx, k.adminToken.AccessToken, k.config.Realm, *user)
	if err != nil {
		k.incrementErrorCount()
		return &types.AuthError{
			Code:    types.ErrCodeConnectionError,
			Message: "failed to update user",
			Details: err.Error(),
		}
	}

	// Invalidate cached tokens for this user
	k.invalidateUserCache(req.UserID)

	// Log audit trail
	k.logTrustLevelAudit(req.UserID, oldTrustLevel, req.TrustLevel, req.Reason, req.AdminID, req.DeviceID)

	return nil
}

// RevokeUserSessions revokes all active sessions for a user
func (k *keycloakClient) RevokeUserSessions(ctx context.Context, userID string) error {
	if err := k.ensureValidAdminToken(ctx); err != nil {
		return err
	}

	// Get user sessions
	sessions, err := k.client.GetUserSessions(ctx, k.adminToken.AccessToken, k.config.Realm, userID)
	if err != nil {
		k.incrementErrorCount()
		return &types.AuthError{
			Code:    types.ErrCodeConnectionError,
			Message: "failed to get user sessions",
			Details: err.Error(),
		}
	}

	// Revoke each session
	for _, session := range sessions {
		err = k.client.LogoutUserSession(ctx, k.adminToken.AccessToken, k.config.Realm, *session.ID)
		if err != nil {
			log.Printf("Warning: failed to logout session %s: %v", *session.ID, err)
		}
	}

	// Invalidate cached tokens for this user
	k.invalidateUserCache(userID)

	return nil
}

// Health checks the health of the Keycloak connection
func (k *keycloakClient) Health(ctx context.Context) error {
	start := time.Now()
	defer func() {
		k.metrics.mutex.Lock()
		k.metrics.LastHealthCheck = time.Now()
		if time.Since(start) > 5*time.Second {
			k.metrics.HealthStatus = "degraded"
		} else {
			k.metrics.HealthStatus = "healthy"
		}
		k.metrics.mutex.Unlock()
	}()

	// Simple health check by getting realm info
	_, err := k.client.GetRealm(ctx, k.adminToken.AccessToken, k.config.Realm)
	if err != nil {
		k.incrementErrorCount()
		k.metrics.mutex.Lock()
		k.metrics.HealthStatus = "unhealthy"
		k.metrics.mutex.Unlock()
		return &types.AuthError{
			Code:    types.ErrCodeConnectionError,
			Message: "keycloak health check failed",
			Details: err.Error(),
		}
	}

	return nil
}

// GetMetrics returns current client metrics
func (k *keycloakClient) GetMetrics(ctx context.Context) (*types.ClientMetrics, error) {
	k.metrics.mutex.RLock()
	defer k.metrics.mutex.RUnlock()

	return &types.ClientMetrics{
		TokenValidations:   k.metrics.TokenValidations,
		CacheHits:         k.metrics.CacheHits,
		CacheMisses:       k.metrics.CacheMisses,
		ErrorCount:        k.metrics.ErrorCount,
		AverageLatency:    k.metrics.AverageLatency,
		ActiveConnections: k.metrics.ActiveConnections,
		HealthStatus:      k.metrics.HealthStatus,
		LastHealthCheck:   k.metrics.LastHealthCheck,
	}, nil
}

// Close gracefully shuts down the client
func (k *keycloakClient) Close() error {
	k.once.Do(func() {
		close(k.shutdown)
		if k.cache != nil {
			if err := k.cache.Close(); err != nil {
				// Log the error but don't fail the shutdown process
				// In a real implementation, this would use a logger
				fmt.Printf("Warning: failed to close cache during shutdown: %v\n", err)
			}
		}
		// Clear sensitive data
		k.tokenMutex.Lock()
		k.adminToken = nil
		k.tokenMutex.Unlock()
		k.config.ClientSecret = ""
		k.config.AdminPass = ""
	})
	return nil
}

// Helper methods

// refreshAdminToken gets a fresh admin token from Keycloak
func (k *keycloakClient) refreshAdminToken(ctx context.Context) error {
	token, err := k.client.LoginAdmin(ctx, k.config.AdminUser, k.config.AdminPass, "master")
	if err != nil {
		return fmt.Errorf("admin login failed: %w", err)
	}

	k.tokenMutex.Lock()
	k.adminToken = token
	k.tokenExpiry = time.Now().Add(time.Duration(token.ExpiresIn-60) * time.Second) // Refresh 60s early
	k.tokenMutex.Unlock()
	
	return nil
}

// ensureValidAdminToken ensures we have a valid admin token
func (k *keycloakClient) ensureValidAdminToken(ctx context.Context) error {
	k.tokenMutex.RLock()
	needsRefresh := k.adminToken == nil || time.Now().After(k.tokenExpiry)
	k.tokenMutex.RUnlock()

	if needsRefresh {
		if k.config.AdminUser == "" || k.config.AdminPass == "" {
			return &types.AuthError{
				Code:    types.ErrCodeConfigurationError,
				Message: "admin credentials required for user management operations",
			}
		}
		return k.refreshAdminToken(ctx)
	}
	return nil
}

// tokenRefreshLoop periodically refreshes the admin token
func (k *keycloakClient) tokenRefreshLoop() {
	ticker := time.NewTicker(10 * time.Minute) // Check every 10 minutes
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			k.tokenMutex.RLock()
			needsRefresh := k.adminToken != nil && time.Now().Add(5*time.Minute).After(k.tokenExpiry)
			k.tokenMutex.RUnlock()

			if needsRefresh {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := k.refreshAdminToken(ctx); err != nil {
					log.Printf("Failed to refresh admin token: %v", err)
				}
				cancel()
			}
		case <-k.shutdown:
			return
		}
	}
}

// parseJWTClaims extracts Zero Trust claims from JWT token and user info
func (k *keycloakClient) parseJWTClaims(token string, userInfo map[string]interface{}) (*types.ZeroTrustClaims, error) {
	// Parse JWT to get all claims
	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// We don't validate signature here since Keycloak already did introspection
		return []byte("dummy"), nil
	})

	if err != nil && !strings.Contains(err.Error(), "signature is invalid") {
		return nil, &types.AuthError{
			Code:    types.ErrCodeInvalidToken,
			Message: "failed to parse token",
			Details: err.Error(),
		}
	}

	claims := &types.ZeroTrustClaims{}
	
	// Extract standard claims from user info
	if sub, ok := userInfo["sub"].(string); ok {
		claims.UserID = sub
	}
	if email, ok := userInfo["email"].(string); ok {
		claims.Email = email
	}
	if username, ok := userInfo["preferred_username"].(string); ok {
		claims.PreferredUsername = username
	}
	if firstName, ok := userInfo["given_name"].(string); ok {
		claims.GivenName = firstName
	}
	if lastName, ok := userInfo["family_name"].(string); ok {
		claims.FamilyName = lastName
	}

	// Extract custom Zero Trust claims from JWT
	if jwtClaims, ok := jwtToken.Claims.(jwt.MapClaims); ok {
		k.extractZeroTrustClaims(jwtClaims, claims)
		k.extractStandardJWTClaims(jwtClaims, claims)
	}

	return claims, nil
}

// extractZeroTrustClaims extracts Zero Trust specific claims
func (k *keycloakClient) extractZeroTrustClaims(jwtClaims jwt.MapClaims, claims *types.ZeroTrustClaims) {
	// Extract trust level
	if trustLevelRaw, exists := jwtClaims["trust_level"]; exists {
		switch tl := trustLevelRaw.(type) {
		case float64:
			claims.TrustLevel = int(tl)
		case int:
			claims.TrustLevel = tl
		case string:
			if level, err := strconv.Atoi(tl); err == nil {
				claims.TrustLevel = level
			}
		}
	} else {
		claims.TrustLevel = k.config.ZeroTrust.DefaultTrustLevel
		if claims.TrustLevel == 0 {
			claims.TrustLevel = 25 // Default to LOW if not specified
		}
	}

	// Extract device information
	if deviceID, ok := jwtClaims["device_id"].(string); ok {
		claims.DeviceID = deviceID
	}
	if deviceVerified, ok := jwtClaims["device_verified"].(bool); ok {
		claims.DeviceVerified = deviceVerified
	}
	if requiresDeviceAuth, ok := jwtClaims["requires_device_auth"].(bool); ok {
		claims.RequiresDeviceAuth = requiresDeviceAuth
	}

	// Extract verification information
	if lastVerif, ok := jwtClaims["last_verification"].(string); ok {
		claims.LastVerification = lastVerif
	}
	if sessionState, ok := jwtClaims["session_state"].(string); ok {
		claims.SessionState = sessionState
	}
	if sessionTimeout, ok := jwtClaims["session_timeout"].(float64); ok {
		claims.SessionTimeout = int(sessionTimeout)
	}

	// Extract risk assessment
	if riskScore, ok := jwtClaims["risk_score"].(float64); ok {
		claims.RiskScore = int(riskScore)
	}
	if riskFactors, ok := jwtClaims["risk_factors"].([]interface{}); ok {
		for _, factor := range riskFactors {
			if factorStr, ok := factor.(string); ok {
				claims.RiskFactors = append(claims.RiskFactors, factorStr)
			}
		}
	}

	// Extract location information
	if locationInfo, ok := jwtClaims["location_info"].(map[string]interface{}); ok {
		claims.LocationInfo = &types.LocationInfo{}
		if country, ok := locationInfo["country"].(string); ok {
			claims.LocationInfo.Country = country
		}
		if region, ok := locationInfo["region"].(string); ok {
			claims.LocationInfo.Region = region
		}
		if city, ok := locationInfo["city"].(string); ok {
			claims.LocationInfo.City = city
		}
		if lat, ok := locationInfo["latitude"].(float64); ok {
			claims.LocationInfo.Latitude = lat
		}
		if lng, ok := locationInfo["longitude"].(float64); ok {
			claims.LocationInfo.Longitude = lng
		}
		if isp, ok := locationInfo["isp"].(string); ok {
			claims.LocationInfo.ISP = isp
		}
		if timezone, ok := locationInfo["timezone"].(string); ok {
			claims.LocationInfo.Timezone = timezone
		}
	}

	// Extract roles from realm_access
	if realmAccess, ok := jwtClaims["realm_access"].(map[string]interface{}); ok {
		if rolesInterface, ok := realmAccess["roles"].([]interface{}); ok {
			for _, role := range rolesInterface {
				if roleStr, ok := role.(string); ok {
					claims.Roles = append(claims.Roles, roleStr)
				}
			}
		}
	}

	// Extract groups
	if groups, ok := jwtClaims["groups"].([]interface{}); ok {
		for _, group := range groups {
			if groupStr, ok := group.(string); ok {
				claims.Groups = append(claims.Groups, groupStr)
			}
		}
	}
}

// extractStandardJWTClaims extracts standard JWT claims
func (k *keycloakClient) extractStandardJWTClaims(jwtClaims jwt.MapClaims, claims *types.ZeroTrustClaims) {
	if exp, ok := jwtClaims["exp"].(float64); ok {
		claims.ExpiresAt = jwt.NewNumericDate(time.Unix(int64(exp), 0))
	}
	if iat, ok := jwtClaims["iat"].(float64); ok {
		claims.IssuedAt = jwt.NewNumericDate(time.Unix(int64(iat), 0))
	}
	if iss, ok := jwtClaims["iss"].(string); ok {
		claims.Issuer = iss
	}
	if aud, ok := jwtClaims["aud"].(string); ok {
		claims.Audience = []string{aud}
	} else if auds, ok := jwtClaims["aud"].([]interface{}); ok {
		for _, aud := range auds {
			if audStr, ok := aud.(string); ok {
				claims.Audience = append(claims.Audience, audStr)
			}
		}
	}
}

// evaluateZeroTrustPolicy evaluates Zero Trust policies against claims
func (k *keycloakClient) evaluateZeroTrustPolicy(claims *types.ZeroTrustClaims) error {
	if k.config.ZeroTrust == nil {
		return nil
	}

	// Check device attestation requirement
	if k.config.ZeroTrust.DeviceAttestation && !claims.DeviceVerified {
		return types.ErrDeviceNotVerified
	}

	// Check risk assessment
	if k.config.ZeroTrust.RiskAssessment && k.config.ZeroTrust.RiskThresholds.Critical > 0 {
		if claims.RiskScore >= k.config.ZeroTrust.RiskThresholds.Critical {
			return &types.AuthError{
				Code:    types.ErrCodeForbidden,
				Message: "risk score too high for access",
			}
		}
	}

	// Check continuous verification
	if k.config.ZeroTrust.ContinuousVerification && claims.LastVerification != "" {
		if lastVerif, err := time.Parse(time.RFC3339, claims.LastVerification); err == nil {
			if time.Since(lastVerif) > k.config.ZeroTrust.VerificationInterval {
				return &types.AuthError{
					Code:    types.ErrCodeInsufficientTrust,
					Message: "verification interval exceeded",
				}
			}
		}
	}

	return nil
}

// Helper utility functions
func (k *keycloakClient) getCacheKey(prefix, key string) string {
	if k.config.Cache != nil && k.config.Cache.Prefix != "" {
		return fmt.Sprintf("%s:%s:%s", k.config.Cache.Prefix, prefix, key)
	}
	return fmt.Sprintf("%s:%s", prefix, key)
}

func (k *keycloakClient) incrementErrorCount() {
	k.metrics.mutex.Lock()
	k.metrics.ErrorCount++
	k.metrics.mutex.Unlock()
}

func (k *keycloakClient) invalidateUserCache(userID string) {
	// Implementation would depend on cache structure
	// For now, we'll just log the action
	log.Printf("Invalidating cache for user: %s", userID)
}

func (k *keycloakClient) logTrustLevelAudit(userID string, oldLevel, newLevel int, reason, adminID, deviceID string) {
	auditData := map[string]interface{}{
		"user_id":         userID,
		"old_trust_level": oldLevel,
		"new_trust_level": newLevel,
		"reason":          reason,
		"changed_by":      adminID,
		"changed_at":      time.Now().Format(time.RFC3339),
		"device_id":       deviceID,
	}

	auditJSON, _ := json.Marshal(auditData)
	log.Printf("Trust level updated: %s", string(auditJSON))
}

func getStringPtr(ptr *string) string {
	if ptr == nil {
		return ""
	}
	return *ptr
}

func getBoolPtr(ptr *bool) bool {
	if ptr == nil {
		return false
	}
	return *ptr
}