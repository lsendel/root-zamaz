// Package auth provides authentication services integrated with Keycloak
// This replaces custom JWT implementation with Keycloak OIDC integration
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/golang-jwt/jwt/v5"
)

// KeycloakAuthenticator integrates with Keycloak for Zero Trust authentication
type KeycloakAuthenticator struct {
	client       *gocloak.GoCloak
	realm        string
	clientId     string
	clientSecret string
	adminToken   *gocloak.JWT
	tokenExpiry  time.Time
}

// ZeroTrustClaims represents JWT claims with Zero Trust attributes from Keycloak
type ZeroTrustClaims struct {
	UserID           string   `json:"sub"`
	Email            string   `json:"email"`
	PreferredUsername string   `json:"preferred_username"`
	GivenName        string   `json:"given_name"`
	FamilyName       string   `json:"family_name"`
	Roles            []string `json:"realm_access.roles"`
	TrustLevel       int      `json:"trust_level"`
	DeviceID         string   `json:"device_id,omitempty"`
	LastVerification string   `json:"last_verification,omitempty"`
	SessionState     string   `json:"session_state"`
	jwt.RegisteredClaims
}

// UserRegistrationRequest represents a new user registration
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

// TrustLevelUpdateRequest represents a trust level change request
type TrustLevelUpdateRequest struct {
	UserID     string `json:"userId" validate:"required"`
	TrustLevel int    `json:"trustLevel" validate:"min=0,max=100"`
	Reason     string `json:"reason" validate:"required"`
	DeviceID   string `json:"deviceId,omitempty"`
	AdminID    string `json:"adminId" validate:"required"`
}

// KeycloakConfig holds Keycloak connection configuration
type KeycloakConfig struct {
	BaseURL      string `json:"baseUrl"`
	Realm        string `json:"realm"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	AdminUser    string `json:"adminUser"`
	AdminPass    string `json:"adminPass"`
}

// NewKeycloakAuthenticator creates a new Keycloak authenticator
func NewKeycloakAuthenticator(config *KeycloakConfig) (*KeycloakAuthenticator, error) {
	if config == nil {
		return nil, fmt.Errorf("keycloak config cannot be nil")
	}

	client := gocloak.NewClient(config.BaseURL)
	
	auth := &KeycloakAuthenticator{
		client:       client,
		realm:        config.Realm,
		clientId:     config.ClientID,
		clientSecret: config.ClientSecret,
	}

	// Get initial admin token
	if err := auth.refreshAdminToken(config.AdminUser, config.AdminPass); err != nil {
		return nil, fmt.Errorf("failed to get admin token: %w", err)
	}

	return auth, nil
}

// refreshAdminToken gets a fresh admin token from Keycloak
func (k *KeycloakAuthenticator) refreshAdminToken(adminUser, adminPass string) error {
	ctx := context.Background()
	
	token, err := k.client.LoginAdmin(ctx, adminUser, adminPass, "master")
	if err != nil {
		return fmt.Errorf("admin login failed: %w", err)
	}

	k.adminToken = token
	k.tokenExpiry = time.Now().Add(time.Duration(token.ExpiresIn-60) * time.Second) // Refresh 60s early
	
	return nil
}

// ensureValidAdminToken ensures we have a valid admin token
func (k *KeycloakAuthenticator) ensureValidAdminToken() error {
	if k.adminToken == nil || time.Now().After(k.tokenExpiry) {
		// Token expired or missing, need to refresh
		// In production, you would store admin credentials securely
		return fmt.Errorf("admin token expired, manual refresh required")
	}
	return nil
}

// ValidateToken validates a JWT token using Keycloak token introspection
func (k *KeycloakAuthenticator) ValidateToken(ctx context.Context, accessToken string) (*ZeroTrustClaims, error) {
	if accessToken == "" {
		return nil, fmt.Errorf("access token cannot be empty")
	}

	// Remove Bearer prefix if present
	if strings.HasPrefix(accessToken, "Bearer ") {
		accessToken = strings.TrimPrefix(accessToken, "Bearer ")
	}

	// Introspect token with Keycloak
	rptResult, err := k.client.RetrospectToken(ctx, accessToken, k.clientId, k.clientSecret, k.realm)
	if err != nil {
		return nil, fmt.Errorf("token introspection failed: %w", err)
	}

	if !*rptResult.Active {
		return nil, fmt.Errorf("token is not active")
	}

	// Get user info for additional claims
	userInfo, err := k.client.GetUserInfo(ctx, accessToken, k.realm)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Parse JWT to get all claims (for roles and custom claims)
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		// We don't validate signature here since Keycloak already did introspection
		// This is just to extract claims
		return []byte("dummy"), nil
	})

	if err != nil && !strings.Contains(err.Error(), "signature is invalid") {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims := &ZeroTrustClaims{}
	
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
	if jwtClaims, ok := token.Claims.(jwt.MapClaims); ok {
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
			claims.TrustLevel = 25 // Default to LOW if not specified
		}

		// Extract device ID
		if deviceID, ok := jwtClaims["device_id"].(string); ok {
			claims.DeviceID = deviceID
		}

		// Extract last verification
		if lastVerif, ok := jwtClaims["last_verification"].(string); ok {
			claims.LastVerification = lastVerif
		}

		// Extract session state
		if sessionState, ok := jwtClaims["session_state"].(string); ok {
			claims.SessionState = sessionState
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

		// Extract standard JWT claims
		if exp, ok := jwtClaims["exp"].(float64); ok {
			claims.ExpiresAt = jwt.NewNumericDate(time.Unix(int64(exp), 0))
		}
		if iat, ok := jwtClaims["iat"].(float64); ok {
			claims.IssuedAt = jwt.NewNumericDate(time.Unix(int64(iat), 0))
		}
		if iss, ok := jwtClaims["iss"].(string); ok {
			claims.Issuer = iss
		}
	}

	return claims, nil
}

// RegisterUser creates a new user in Keycloak with Zero Trust attributes
func (k *KeycloakAuthenticator) RegisterUser(ctx context.Context, req *UserRegistrationRequest) (*gocloak.User, error) {
	if err := k.ensureValidAdminToken(); err != nil {
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
		EmailVerified: gocloak.BoolP(false), // Require email verification
		Attributes:    &attributes,
		RequiredActions: &[]string{
			"VERIFY_EMAIL",
		},
	}

	// Create user
	userID, err := k.client.CreateUser(ctx, k.adminToken.AccessToken, k.realm, user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Set password
	err = k.client.SetPassword(ctx, k.adminToken.AccessToken, k.realm, userID, req.Password, false)
	if err != nil {
		// Cleanup: delete the created user if password setting fails
		k.client.DeleteUser(ctx, k.adminToken.AccessToken, k.realm, userID)
		return nil, fmt.Errorf("failed to set password: %w", err)
	}

	// Assign default user role
	userRole, err := k.client.GetRealmRole(ctx, k.adminToken.AccessToken, k.realm, "user")
	if err != nil {
		log.Printf("Warning: could not get user role: %v", err)
	} else {
		err = k.client.AddRealmRoleToUser(ctx, k.adminToken.AccessToken, k.realm, userID, []gocloak.Role{*userRole})
		if err != nil {
			log.Printf("Warning: could not assign user role: %v", err)
		}
	}

	// Get the created user to return
	createdUser, err := k.client.GetUserByID(ctx, k.adminToken.AccessToken, k.realm, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve created user: %w", err)
	}

	return createdUser, nil
}

// UpdateUserTrustLevel updates a user's trust level in Keycloak
func (k *KeycloakAuthenticator) UpdateUserTrustLevel(ctx context.Context, req *TrustLevelUpdateRequest) error {
	if err := k.ensureValidAdminToken(); err != nil {
		return err
	}

	// Get current user
	user, err := k.client.GetUserByID(ctx, k.adminToken.AccessToken, k.realm, req.UserID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Get current trust level for audit
	oldTrustLevel := 25 // Default
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
	err = k.client.UpdateUser(ctx, k.adminToken.AccessToken, k.realm, *user)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Log audit trail (this could be enhanced to use a proper audit service)
	auditData := map[string]interface{}{
		"user_id":         req.UserID,
		"old_trust_level": oldTrustLevel,
		"new_trust_level": req.TrustLevel,
		"reason":          req.Reason,
		"changed_by":      req.AdminID,
		"changed_at":      time.Now().Format(time.RFC3339),
		"device_id":       req.DeviceID,
	}

	auditJSON, _ := json.Marshal(auditData)
	log.Printf("Trust level updated: %s", string(auditJSON))

	return nil
}

// RevokeUserSessions revokes all active sessions for a user
func (k *KeycloakAuthenticator) RevokeUserSessions(ctx context.Context, userID string) error {
	if err := k.ensureValidAdminToken(); err != nil {
		return err
	}

	// Get user sessions
	sessions, err := k.client.GetUserSessions(ctx, k.adminToken.AccessToken, k.realm, userID)
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	// Revoke each session
	for _, session := range sessions {
		err = k.client.LogoutUserSession(ctx, k.adminToken.AccessToken, k.realm, *session.ID)
		if err != nil {
			log.Printf("Warning: failed to logout session %s: %v", *session.ID, err)
		}
	}

	return nil
}

// GetUserTrustLevel retrieves the current trust level for a user
func (k *KeycloakAuthenticator) GetUserTrustLevel(ctx context.Context, userID string) (int, error) {
	if err := k.ensureValidAdminToken(); err != nil {
		return 0, err
	}

	user, err := k.client.GetUserByID(ctx, k.adminToken.AccessToken, k.realm, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to get user: %w", err)
	}

	if user.Attributes == nil {
		return 25, nil // Default trust level
	}

	if levels, exists := (*user.Attributes)["trust_level"]; exists && len(levels) > 0 {
		if level, err := strconv.Atoi(levels[0]); err == nil {
			return level, nil
		}
	}

	return 25, nil // Default trust level
}

// HealthCheck verifies Keycloak connectivity and realm status
func (k *KeycloakAuthenticator) HealthCheck(ctx context.Context) error {
	// Simple health check by getting realm info
	_, err := k.client.GetRealm(ctx, k.adminToken.AccessToken, k.realm)
	if err != nil {
		return fmt.Errorf("keycloak health check failed: %w", err)
	}
	return nil
}

// GetStats returns Keycloak integration statistics
func (k *KeycloakAuthenticator) GetStats(ctx context.Context) (map[string]interface{}, error) {
	if err := k.ensureValidAdminToken(); err != nil {
		return nil, err
	}

	// Get realm info
	realm, err := k.client.GetRealm(ctx, k.adminToken.AccessToken, k.realm)
	if err != nil {
		return nil, fmt.Errorf("failed to get realm info: %w", err)
	}

	// Get user count (this is a simplified approach)
	users, err := k.client.GetUsers(ctx, k.adminToken.AccessToken, k.realm, gocloak.GetUsersParams{
		Max: gocloak.IntP(1), // Just to get total count
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}

	stats := map[string]interface{}{
		"realm":              *realm.Realm,
		"realm_enabled":      *realm.Enabled,
		"login_with_email":   *realm.LoginWithEmailAllowed,
		"registration":       *realm.RegistrationAllowed,
		"brute_force_protection": *realm.BruteForceProtected,
		"user_count_sample":  len(users),
		"token_lifespan":     *realm.AccessTokenLifespan,
		"admin_token_valid":  time.Now().Before(k.tokenExpiry),
	}

	return stats, nil
}

// Close cleans up the Keycloak authenticator
func (k *KeycloakAuthenticator) Close() error {
	// Keycloak client doesn't require explicit cleanup
	// but we can clear sensitive data
	k.adminToken = nil
	k.clientSecret = ""
	return nil
}