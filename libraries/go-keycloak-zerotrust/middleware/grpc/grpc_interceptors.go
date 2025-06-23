// Package grpc provides gRPC interceptors for Keycloak Zero Trust authentication
package grpc

import (
	"context"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// Interceptor provides gRPC-specific interceptor functions
type Interceptor struct {
	client types.KeycloakClient
	config *InterceptorConfig
}

// InterceptorConfig configures the gRPC interceptors
type InterceptorConfig struct {
	TokenMetadataKey   string        `yaml:"token_metadata_key"`
	ContextUserKey     string        `yaml:"context_user_key"`
	SkipMethods        []string      `yaml:"skip_methods"`
	RequestTimeout     time.Duration `yaml:"request_timeout"`
	ErrorHandler       func(ctx context.Context, err error) error `yaml:"-"`
	RequireAuth        bool          `yaml:"require_auth"`
	TrustLevelRequired int           `yaml:"trust_level_required"`
}

// UserContextKey is the type for user context keys
type UserContextKey string

const (
	// DefaultUserContextKey is the default context key for storing user information
	DefaultUserContextKey UserContextKey = "keycloak_user"
	// DefaultTokenMetadataKey is the default metadata key for JWT tokens
	DefaultTokenMetadataKey = "authorization"
)

// NewInterceptor creates a new gRPC interceptor instance
func NewInterceptor(client types.KeycloakClient, config *InterceptorConfig) *Interceptor {
	if config == nil {
		config = &InterceptorConfig{
			TokenMetadataKey: DefaultTokenMetadataKey,
			ContextUserKey:   string(DefaultUserContextKey),
			SkipMethods:      []string{"/grpc.health.v1.Health/"},
			RequestTimeout:   30 * time.Second,
			RequireAuth:      true,
		}
	}
	
	return &Interceptor{
		client: client,
		config: config,
	}
}

// UnaryInterceptor provides authentication for unary gRPC calls
func (i *Interceptor) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip authentication for configured methods
		if i.shouldSkipMethod(info.FullMethod) {
			return handler(ctx, req)
		}

		// Authenticate the request
		authCtx, err := i.authenticateRequest(ctx)
		if err != nil {
			return nil, err
		}

		// Call the handler with authenticated context
		return handler(authCtx, req)
	}
}

// StreamInterceptor provides authentication for streaming gRPC calls
func (i *Interceptor) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Skip authentication for configured methods
		if i.shouldSkipMethod(info.FullMethod) {
			return handler(srv, stream)
		}

		// Authenticate the request
		authCtx, err := i.authenticateRequest(stream.Context())
		if err != nil {
			return err
		}

		// Create a new stream with authenticated context
		authStream := &authenticatedStream{
			ServerStream: stream,
			ctx:          authCtx,
		}

		// Call the handler with authenticated stream
		return handler(srv, authStream)
	}
}

// RequireRole creates an interceptor that requires a specific role
func (i *Interceptor) RequireRole(requiredRole string) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		user, err := i.GetUserFromContext(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "authentication required: %v", err)
		}

		if !i.hasRole(user, requiredRole) {
			return nil, status.Errorf(codes.PermissionDenied, "insufficient role: required %s", requiredRole)
		}

		return handler(ctx, req)
	}
}

// RequireAnyRole creates an interceptor that requires any of the specified roles
func (i *Interceptor) RequireAnyRole(roles ...string) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		user, err := i.GetUserFromContext(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "authentication required: %v", err)
		}

		hasAnyRole := false
		for _, role := range roles {
			if i.hasRole(user, role) {
				hasAnyRole = true
				break
			}
		}

		if !hasAnyRole {
			return nil, status.Errorf(codes.PermissionDenied, "insufficient role: required one of %v", roles)
		}

		return handler(ctx, req)
	}
}

// RequireTrustLevel creates an interceptor that requires a minimum trust level
func (i *Interceptor) RequireTrustLevel(minTrustLevel int) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		user, err := i.GetUserFromContext(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "authentication required: %v", err)
		}

		if user.TrustLevel < minTrustLevel {
			return nil, status.Errorf(codes.PermissionDenied, 
				"insufficient trust level: required %d, current %d", 
				minTrustLevel, user.TrustLevel)
		}

		return handler(ctx, req)
	}
}

// RequireDeviceVerification creates an interceptor that requires device verification
func (i *Interceptor) RequireDeviceVerification() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		user, err := i.GetUserFromContext(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "authentication required: %v", err)
		}

		if !user.DeviceVerified {
			return nil, status.Errorf(codes.PermissionDenied, "device verification required")
		}

		return handler(ctx, req)
	}
}

// ChainUnaryInterceptors chains multiple unary interceptors together
func (i *Interceptor) ChainUnaryInterceptors(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Chain interceptors in reverse order
		for i := len(interceptors) - 1; i >= 0; i-- {
			interceptor := interceptors[i]
			currentHandler := handler
			handler = func(ctx context.Context, req interface{}) (interface{}, error) {
				return interceptor(ctx, req, info, currentHandler)
			}
		}
		return handler(ctx, req)
	}
}

// GetUserFromContext extracts the authenticated user from context
func (i *Interceptor) GetUserFromContext(ctx context.Context) (*types.AuthenticatedUser, error) {
	user := ctx.Value(UserContextKey(i.config.ContextUserKey))
	if user == nil {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user in context")
	}

	authUser, ok := user.(*types.AuthenticatedUser)
	if !ok {
		return nil, status.Error(codes.Internal, "invalid user type in context")
	}

	return authUser, nil
}

// Helper methods

// authenticateRequest performs authentication for a gRPC request
func (i *Interceptor) authenticateRequest(ctx context.Context) (context.Context, error) {
	if !i.config.RequireAuth {
		return ctx, nil
	}

	// Create context with timeout
	authCtx, cancel := context.WithTimeout(ctx, i.config.RequestTimeout)
	defer cancel()

	// Extract token from metadata
	token, err := i.extractTokenFromMetadata(ctx)
	if err != nil {
		return nil, i.handleAuthError(err)
	}

	if token == "" {
		return nil, i.handleAuthError(types.ErrMissingToken)
	}

	// Validate token
	claims, err := i.client.ValidateToken(authCtx, token)
	if err != nil {
		return nil, i.handleAuthError(err)
	}

	// Check minimum trust level if configured
	if i.config.TrustLevelRequired > 0 && claims.TrustLevel < i.config.TrustLevelRequired {
		return nil, status.Errorf(codes.PermissionDenied, 
			"insufficient trust level: required %d, current %d", 
			i.config.TrustLevelRequired, claims.TrustLevel)
	}

	// Create authenticated user and add to context
	user := i.createAuthenticatedUser(claims)
	userCtx := context.WithValue(ctx, UserContextKey(i.config.ContextUserKey), user)

	return userCtx, nil
}

// shouldSkipMethod checks if the method should skip authentication
func (i *Interceptor) shouldSkipMethod(method string) bool {
	for _, skipMethod := range i.config.SkipMethods {
		if method == skipMethod || strings.HasPrefix(method, skipMethod) {
			return true
		}
	}
	return false
}

// extractTokenFromMetadata extracts the JWT token from gRPC metadata
func (i *Interceptor) extractTokenFromMetadata(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no metadata in context")
	}

	// Try the configured metadata key
	tokens := md.Get(i.config.TokenMetadataKey)
	if len(tokens) == 0 {
		// Try alternative keys
		altKeys := []string{"authorization", "bearer", "token"}
		for _, key := range altKeys {
			if key != i.config.TokenMetadataKey {
				tokens = md.Get(key)
				if len(tokens) > 0 {
					break
				}
			}
		}
	}

	if len(tokens) == 0 {
		return "", status.Error(codes.Unauthenticated, "no token in metadata")
	}

	token := tokens[0]
	
	// Remove "Bearer " prefix if present
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}

	return token, nil
}

// createAuthenticatedUser creates an AuthenticatedUser from claims
func (i *Interceptor) createAuthenticatedUser(claims *types.ZeroTrustClaims) *types.AuthenticatedUser {
	user := &types.AuthenticatedUser{
		UserID:           claims.UserID,
		Email:            claims.Email,
		Username:         claims.PreferredUsername,
		FirstName:        claims.GivenName,
		LastName:         claims.FamilyName,
		Roles:            claims.Roles,
		TrustLevel:       claims.TrustLevel,
		DeviceID:         claims.DeviceID,
		DeviceVerified:   claims.DeviceVerified,
		LastVerification: claims.LastVerification,
		SessionState:     claims.SessionState,
		RiskScore:        claims.RiskScore,
		LocationInfo:     claims.LocationInfo,
	}

	// Set expiration time
	if claims.ExpiresAt != nil {
		user.ExpiresAt = claims.ExpiresAt.Time
	}

	return user
}

// hasRole checks if the user has a specific role
func (i *Interceptor) hasRole(user *types.AuthenticatedUser, requiredRole string) bool {
	for _, role := range user.Roles {
		if role == requiredRole {
			return true
		}
	}
	return false
}

// handleAuthError converts authentication errors to gRPC status errors
func (i *Interceptor) handleAuthError(err error) error {
	// If a custom error handler is configured, use it
	if i.config.ErrorHandler != nil {
		if handledErr := i.config.ErrorHandler(context.Background(), err); handledErr != nil {
			err = handledErr
		}
	}

	if authErr, ok := err.(*types.AuthError); ok {
		switch authErr.Code {
		case types.ErrCodeUnauthorized, types.ErrCodeInvalidToken, types.ErrCodeExpiredToken:
			return status.Error(codes.Unauthenticated, authErr.Message)
		case types.ErrCodeForbidden, types.ErrCodeInsufficientTrust, types.ErrCodeInsufficientRole, types.ErrCodeDeviceNotVerified:
			return status.Error(codes.PermissionDenied, authErr.Message)
		case types.ErrCodeConnectionError:
			return status.Error(codes.Unavailable, authErr.Message)
		case types.ErrCodeConfigurationError:
			return status.Error(codes.Internal, authErr.Message)
		default:
			return status.Error(codes.Unauthenticated, authErr.Message)
		}
	}

	// Generic error
	return status.Error(codes.Unauthenticated, err.Error())
}

// authenticatedStream wraps a grpc.ServerStream with authenticated context
type authenticatedStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the authenticated context
func (s *authenticatedStream) Context() context.Context {
	return s.ctx
}

// GRPCInterceptor creates a new gRPC interceptor instance from the client
func GRPCInterceptor(client types.KeycloakClient, config ...*InterceptorConfig) *Interceptor {
	var cfg *InterceptorConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	return NewInterceptor(client, cfg)
}

// DefaultUnaryInterceptor creates a default unary interceptor with authentication
func DefaultUnaryInterceptor(client types.KeycloakClient) grpc.UnaryServerInterceptor {
	interceptor := NewInterceptor(client, nil)
	return interceptor.UnaryInterceptor()
}

// DefaultStreamInterceptor creates a default stream interceptor with authentication
func DefaultStreamInterceptor(client types.KeycloakClient) grpc.StreamServerInterceptor {
	interceptor := NewInterceptor(client, nil)
	return interceptor.StreamInterceptor()
}

// HighSecurityUnaryInterceptor creates a high-security unary interceptor
func HighSecurityUnaryInterceptor(client types.KeycloakClient, minTrustLevel int) grpc.UnaryServerInterceptor {
	interceptor := NewInterceptor(client, &InterceptorConfig{
		TokenMetadataKey:   DefaultTokenMetadataKey,
		ContextUserKey:     string(DefaultUserContextKey),
		SkipMethods:        []string{"/grpc.health.v1.Health/"},
		RequestTimeout:     30 * time.Second,
		RequireAuth:        true,
		TrustLevelRequired: minTrustLevel,
	})

	return interceptor.ChainUnaryInterceptors(
		interceptor.UnaryInterceptor(),
		interceptor.RequireTrustLevel(minTrustLevel),
		interceptor.RequireDeviceVerification(),
	)
}