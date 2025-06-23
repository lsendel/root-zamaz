// Example implementation demonstrating how to use root-zamaz Zero Trust components
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	
	// Import root-zamaz reusable components
	"github.com/yourorg/go-keycloak-zerotrust/pkg/client"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
	ginmiddleware "github.com/yourorg/go-keycloak-zerotrust/middleware/gin"
	"github.com/yourorg/go-keycloak-zerotrust/pkg/opa"
)

func main() {
	// Initialize Keycloak client using root-zamaz components
	config := &types.Config{
		BaseURL:      getEnv("KEYCLOAK_URL", "http://localhost:8082"),
		Realm:        getEnv("KEYCLOAK_REALM", "zerotrust-test"),
		ClientID:     getEnv("KEYCLOAK_CLIENT_ID", "zerotrust-client"),
		ClientSecret: getEnv("KEYCLOAK_CLIENT_SECRET", "zerotrust-secret-12345"),
		AdminUser:    getEnv("KEYCLOAK_ADMIN_USER", "admin"),
		AdminPass:    getEnv("KEYCLOAK_ADMIN_PASS", "admin"),
		Timeout:      30 * time.Second,
		Cache: &types.CacheConfig{
			Enabled:  true,
			Provider: "memory",
			TTL:      1 * time.Hour,
			MaxSize:  1000,
		},
		ZeroTrust: &types.ZeroTrustConfig{
			DefaultTrustLevel:        25,
			DeviceAttestation:       false, // Simplified for demo
			RiskAssessment:          false, // Simplified for demo
			ContinuousVerification:  false, // Simplified for demo
			VerificationInterval:    24 * time.Hour,
		},
	}

	// Create Keycloak client using root-zamaz library
	keycloakClient, err := client.NewKeycloakClient(config)
	if err != nil {
		log.Fatalf("Failed to create Keycloak client: %v", err)
	}
	defer keycloakClient.Close()

	// Initialize OPA client using root-zamaz components
	opaClient := opa.NewOPAClient(getEnv("OPA_URL", "http://localhost:8181"))

	// Test connections
	log.Println("Testing component connections...")
	
	// Test Keycloak
	ctx := context.Background()
	if err := keycloakClient.Health(ctx); err != nil {
		log.Printf("Keycloak health check failed: %v", err)
	} else {
		log.Println("✅ Keycloak connection successful")
	}

	// Test OPA
	if err := opaClient.HealthCheck(ctx); err != nil {
		log.Printf("OPA health check failed: %v", err)
	} else {
		log.Println("✅ OPA connection successful")
	}

	// Create Gin middleware using root-zamaz components
	middlewareConfig := &types.MiddlewareConfig{
		TokenHeader:    "Authorization",
		ContextUserKey: "user",
		SkipPaths:      []string{"/health", "/metrics", "/login"},
		RequestTimeout: 30 * time.Second,
		CorsEnabled:    true,
		CorsOrigins:    []string{"http://localhost:3000", "http://localhost:5173"},
	}

	authMiddleware := ginmiddleware.NewMiddleware(keycloakClient, middlewareConfig)

	// Setup Gin router
	router := gin.Default()

	// Apply CORS middleware
	router.Use(authMiddleware.CORS())

	// Public endpoints (no authentication required)
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"timestamp": time.Now().Unix(),
			"components": gin.H{
				"keycloak": "connected",
				"opa":      "connected",
			},
		})
	})

	router.GET("/metrics", func(c *gin.Context) {
		metrics, err := keycloakClient.GetMetrics(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, metrics)
	})

	// Authentication endpoint using Keycloak
	router.POST("/login", func(c *gin.Context) {
		var loginReq struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}

		if err := c.ShouldBindJSON(&loginReq); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// This would integrate with Keycloak's OAuth2 flow
		// For demo purposes, we'll return a placeholder response
		c.JSON(http.StatusOK, gin.H{
			"message": "Login endpoint ready",
			"redirect_url": config.BaseURL + "/realms/" + config.Realm + "/protocol/openid-connect/auth",
		})
	})

	// Protected endpoints with Zero Trust authentication
	protected := router.Group("/api")
	protected.Use(authMiddleware.Authenticate())
	{
		// Basic protected endpoint (LOW trust level)
		protected.GET("/profile", func(c *gin.Context) {
			user := authMiddleware.GetCurrentUser(c)
			if user == nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"user_id":     user.UserID,
				"email":       user.Email,
				"trust_level": user.TrustLevel,
				"roles":       user.Roles,
			})
		})

		// Medium trust level endpoint
		protected.PUT("/profile", authMiddleware.RequireTrustLevel(50), func(c *gin.Context) {
			user := authMiddleware.GetCurrentUser(c)
			
			// Test OPA authorization
			authzReq := opa.AuthorizationRequest{
				JWT:      c.GetHeader("Authorization"),
				Resource: "user_profile",
				Action:   "write",
				UserID:   user.UserID,
				DeviceID: user.DeviceID,
			}

			authzResp, err := opaClient.Authorize(ctx, authzReq)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "authorization check failed"})
				return
			}

			if !authzResp.Result.Allow {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "access denied by policy",
					"reasons": authzResp.Result.Reasons,
				})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "Profile update authorized",
				"trust_level": authzResp.Result.TrustLevel,
			})
		})

		// High trust level endpoint
		protected.GET("/admin/users", 
			authMiddleware.RequireRole("admin"),
			authMiddleware.RequireTrustLevel(75),
			func(c *gin.Context) {
				user := authMiddleware.GetCurrentUser(c)
				
				c.JSON(http.StatusOK, gin.H{
					"message": "Admin access granted",
					"admin_user": user.Email,
					"trust_level": user.TrustLevel,
				})
			})

		// Full trust level endpoint with device verification
		protected.POST("/financial/transfer",
			authMiddleware.RequireRole("admin"),
			authMiddleware.RequireTrustLevel(100),
			authMiddleware.RequireDeviceVerification(),
			func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"message": "Financial transfer authorized",
					"security": "full trust + device verification required",
				})
			})
	}

	// Start server
	port := getEnv("PORT", "8080")
	log.Printf("🚀 Starting Zero Trust application on port %s", port)
	log.Printf("🔐 Using Keycloak: %s", config.BaseURL)
	log.Printf("🔍 Using OPA: %s", getEnv("OPA_URL", "http://localhost:8181"))
	log.Printf("📋 Endpoints:")
	log.Printf("   GET  /health - Health check")
	log.Printf("   GET  /metrics - Metrics")
	log.Printf("   POST /login - Authentication")
	log.Printf("   GET  /api/profile - User profile (trust level 25+)")
	log.Printf("   PUT  /api/profile - Update profile (trust level 50+)")
	log.Printf("   GET  /api/admin/users - Admin users (role: admin, trust level 75+)")
	log.Printf("   POST /api/financial/transfer - Financial ops (role: admin, trust level 100+, device verified)")

	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// Helper function to get environment variables with defaults
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}