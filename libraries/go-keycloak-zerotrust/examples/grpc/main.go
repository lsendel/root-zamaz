// Package main demonstrates gRPC integration with go-keycloak-zerotrust
package main

import (
	"context"
	"log"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	keycloak "github.com/yourorg/go-keycloak-zerotrust"
	grpcMiddleware "github.com/yourorg/go-keycloak-zerotrust/middleware/grpc"
)

// Example service definition (normally this would be generated from protobuf)
type UserService struct {
	auth keycloak.KeycloakClient
	grpcMiddleware.UnimplementedUserServiceServer
}

type ProfileRequest struct {
	// Request fields would be defined in protobuf
}

type ProfileResponse struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Roles     []string `json:"roles"`
	TrustLevel int    `json:"trust_level"`
}

type TransferRequest struct {
	Amount    float64 `json:"amount"`
	ToAccount string  `json:"to_account"`
	Currency  string  `json:"currency"`
}

type TransferResponse struct {
	TransactionID string  `json:"transaction_id"`
	Amount        float64 `json:"amount"`
	Status        string  `json:"status"`
	Timestamp     string  `json:"timestamp"`
}

type AdminRequest struct {
	Operation string `json:"operation"`
}

type AdminResponse struct {
	Result  string `json:"result"`
	AdminID string `json:"admin_id"`
}

type HealthRequest struct{}

type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

// Helper function to get environment variable with default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetProfile returns the authenticated user's profile
func (s *UserService) GetProfile(ctx context.Context, req *ProfileRequest) (*ProfileResponse, error) {
	// Extract authenticated user from context
	user, err := grpcMiddleware.GetUserFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "authentication required: %v", err)
	}

	return &ProfileResponse{
		UserID:     user.UserID,
		Email:      user.Email,
		Username:   user.Username,
		FirstName:  user.FirstName,
		LastName:   user.LastName,
		Roles:      user.Roles,
		TrustLevel: user.TrustLevel,
	}, nil
}

// Transfer processes a financial transfer (requires high trust level and device verification)
func (s *UserService) Transfer(ctx context.Context, req *TransferRequest) (*TransferResponse, error) {
	// Extract authenticated user from context
	user, err := grpcMiddleware.GetUserFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "authentication required: %v", err)
	}

	// Additional validation for transfer
	if req.Amount <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "transfer amount must be positive")
	}

	if req.ToAccount == "" {
		return nil, status.Errorf(codes.InvalidArgument, "destination account required")
	}

	// Check if user has sufficient trust level for transfer
	if user.TrustLevel < 75 {
		return nil, status.Errorf(codes.PermissionDenied, 
			"insufficient trust level for transfer: required 75, current %d", 
			user.TrustLevel)
	}

	// Check device verification
	if !user.DeviceVerified {
		return nil, status.Errorf(codes.PermissionDenied, "device verification required for transfers")
	}

	// Simulate transfer processing
	transactionID := generateTransactionID()
	
	log.Printf("Transfer processed: %s -> %s, Amount: %.2f %s, User: %s, Trust: %d", 
		user.UserID, req.ToAccount, req.Amount, req.Currency, user.Username, user.TrustLevel)

	return &TransferResponse{
		TransactionID: transactionID,
		Amount:        req.Amount,
		Status:        "completed",
		Timestamp:     time.Now().Format(time.RFC3339),
	}, nil
}

// AdminOperation performs administrative operations (requires admin role and maximum trust)
func (s *UserService) AdminOperation(ctx context.Context, req *AdminRequest) (*AdminResponse, error) {
	// Extract authenticated user from context
	user, err := grpcMiddleware.GetUserFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "authentication required: %v", err)
	}

	// Check admin role
	hasAdminRole := false
	for _, role := range user.Roles {
		if role == "admin" || role == "super-admin" {
			hasAdminRole = true
			break
		}
	}

	if !hasAdminRole {
		return nil, status.Errorf(codes.PermissionDenied, "admin role required")
	}

	// Check maximum trust level
	if user.TrustLevel < 100 {
		return nil, status.Errorf(codes.PermissionDenied, 
			"maximum trust level required for admin operations: required 100, current %d", 
			user.TrustLevel)
	}

	// Process admin operation
	log.Printf("Admin operation executed: %s by %s (trust: %d)", 
		req.Operation, user.Username, user.TrustLevel)

	return &AdminResponse{
		Result:  "Operation completed successfully",
		AdminID: user.UserID,
	}, nil
}

// Health check endpoint (no authentication required)
func (s *UserService) Health(ctx context.Context, req *HealthRequest) (*HealthResponse, error) {
	// Check Keycloak health
	if err := s.auth.Health(ctx); err != nil {
		return &HealthResponse{
			Status:    "unhealthy",
			Timestamp: time.Now().Format(time.RFC3339),
		}, nil
	}

	return &HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().Format(time.RFC3339),
	}, nil
}

// Streaming endpoint example
func (s *UserService) StreamData(req *ProfileRequest, stream grpc.ServerStream) error {
	// Extract authenticated user from context
	user, err := grpcMiddleware.GetUserFromContext(stream.Context())
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "authentication required: %v", err)
	}

	// Check minimum trust level for streaming
	if user.TrustLevel < 30 {
		return status.Errorf(codes.PermissionDenied, 
			"insufficient trust level for streaming: required 30, current %d", 
			user.TrustLevel)
	}

	// Simulate streaming data
	for i := 0; i < 5; i++ {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		default:
			// Send data chunk
			response := &ProfileResponse{
				UserID:     user.UserID,
				Username:   user.Username,
				TrustLevel: user.TrustLevel,
			}
			
			if err := stream.SendMsg(response); err != nil {
				return err
			}
			
			time.Sleep(time.Second) // Simulate processing delay
		}
	}

	return nil
}

// generateTransactionID generates a simple transaction ID
func generateTransactionID() string {
	return "txn_" + time.Now().Format("20060102150405")
}

// grpcMiddleware.GetUserFromContext extracts user from gRPC context (placeholder implementation)
func GetUserFromContext(ctx context.Context) (*keycloak.AuthenticatedUser, error) {
	// This would be implemented in the actual middleware
	// For now, return a placeholder error
	return nil, status.Error(codes.Unauthenticated, "user extraction not implemented")
}

func main() {
	// Initialize Keycloak client
	config := &keycloak.Config{
		BaseURL:      getEnvOrDefault("KEYCLOAK_BASE_URL", "http://localhost:8080"),
		Realm:        getEnvOrDefault("KEYCLOAK_REALM", "demo"),
		ClientID:     getEnvOrDefault("KEYCLOAK_CLIENT_ID", "demo-client"),
		ClientSecret: getEnvOrDefault("KEYCLOAK_CLIENT_SECRET", "demo-secret"),
		AdminUser:    getEnvOrDefault("KEYCLOAK_ADMIN_USER", "admin"),
		AdminPass:    getEnvOrDefault("KEYCLOAK_ADMIN_PASS", "admin"),
		ZeroTrust: &keycloak.ZeroTrustConfig{
			DefaultTrustLevel:      25,
			DeviceAttestation:      true,
			RiskAssessment:         true,
			ContinuousVerification: true,
		},
	}

	// Create Keycloak client
	auth, err := keycloak.New(config)
	if err != nil {
		log.Fatalf("Failed to create Keycloak client: %v", err)
	}
	defer auth.Close()

	// Test connection
	if err := auth.Health(context.Background()); err != nil {
		log.Printf("Warning: Keycloak health check failed: %v", err)
	} else {
		log.Println("✅ Connected to Keycloak successfully")
	}

	// Create gRPC interceptors
	interceptor := grpcMiddleware.GRPCInterceptor(auth, &grpcMiddleware.InterceptorConfig{
		TokenMetadataKey: "authorization",
		ContextUserKey:   "user",
		SkipMethods: []string{
			"/UserService/Health", // Health check doesn't require auth
		},
		RequestTimeout: 30 * time.Second,
		RequireAuth:    true,
	})

	// Create gRPC server with interceptors
	server := grpc.NewServer(
		grpc.UnaryInterceptor(interceptor.UnaryInterceptor()),
		grpc.StreamInterceptor(interceptor.StreamInterceptor()),
	)

	// Create service instance
	userService := &UserService{
		auth: auth,
	}

	// Register services (normally done with generated protobuf code)
	// server.RegisterUserServiceServer(server, userService)

	// Enable reflection for grpcurl testing
	reflection.Register(server)

	// Create listener
	port := getEnvOrDefault("GRPC_PORT", "50051")
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Failed to listen on port %s: %v", port, err)
	}

	log.Printf("🚀 Starting gRPC server on port %s", port)
	log.Printf("🛡️  Zero Trust gRPC Configuration:")
	log.Printf("   - Authentication: Required for all endpoints except Health")
	log.Printf("   - Trust Level Validation: Enabled")
	log.Printf("   - Device Verification: Required for transfers")
	log.Printf("   - Role-Based Access: Admin operations require admin role")
	log.Printf("")
	log.Printf("📖 Available Services:")
	log.Printf("   - GetProfile: Basic user profile (any authenticated user)")
	log.Printf("   - Transfer: Financial transfer (trust level 75+, device verified)")
	log.Printf("   - AdminOperation: Admin functions (admin role, trust level 100)")
	log.Printf("   - Health: Health check (no authentication required)")
	log.Printf("   - StreamData: Streaming data (trust level 30+)")
	log.Printf("")
	log.Printf("🔧 Testing with grpcurl:")
	log.Printf("   grpcurl -plaintext -H 'authorization: Bearer <token>' localhost:%s list", port)
	log.Printf("   grpcurl -plaintext localhost:%s UserService.Health", port)
	log.Printf("")
	log.Printf("🔑 Authentication: Include 'authorization: Bearer <token>' in metadata")
	log.Printf("🛡️  Zero Trust: Real-time validation for every gRPC call")

	// Create a demo handler for testing (since we don't have protobuf generated code)
	// This simulates what the actual service would look like
	
	// Create a simple HTTP handler for demonstration
	go func() {
		httpPort := getEnvOrDefault("HTTP_PORT", "8083")
		log.Printf("📡 Starting HTTP demo server on port %s for gRPC simulation", httpPort)
		
		// This would normally be handled by the gRPC-Gateway or similar
		// For demo purposes, we'll create simple HTTP endpoints that simulate gRPC calls
		
		// Placeholder implementation - in real scenarios, use proper gRPC services
		log.Printf("⚠️  This is a demonstration server. In production, use proper gRPC services.")
	}()

	// Start gRPC server
	log.Printf("🔄 Server listening on %s...", listener.Addr())
	if err := server.Serve(listener); err != nil {
		log.Fatalf("Failed to serve gRPC: %v", err)
	}
}

// Mock protobuf service registration (normally generated)
// This demonstrates the typical structure of a gRPC service with Zero Trust

/*
Example .proto file that would generate the service interface:

syntax = "proto3";

package userservice;

option go_package = "./userservice";

service UserService {
  rpc GetProfile(ProfileRequest) returns (ProfileResponse);
  rpc Transfer(TransferRequest) returns (TransferResponse);
  rpc AdminOperation(AdminRequest) returns (AdminResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
  rpc StreamData(ProfileRequest) returns (stream ProfileResponse);
}

message ProfileRequest {}

message ProfileResponse {
  string user_id = 1;
  string email = 2;
  string username = 3;
  string first_name = 4;
  string last_name = 5;
  repeated string roles = 6;
  int32 trust_level = 7;
}

message TransferRequest {
  double amount = 1;
  string to_account = 2;
  string currency = 3;
}

message TransferResponse {
  string transaction_id = 1;
  double amount = 2;
  string status = 3;
  string timestamp = 4;
}

message AdminRequest {
  string operation = 1;
}

message AdminResponse {
  string result = 1;
  string admin_id = 2;
}

message HealthRequest {}

message HealthResponse {
  string status = 1;
  string timestamp = 2;
}

Then generate with:
protoc --go_out=. --go-grpc_out=. userservice.proto
*/