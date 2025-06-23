// Package main demonstrates basic usage of the go-keycloak-zerotrust library
package main

import (
	"context"
	"log"
	"os"

	"github.com/gin-gonic/gin"

	keycloak "github.com/yourorg/go-keycloak-zerotrust"
	ginMiddleware "github.com/yourorg/go-keycloak-zerotrust/middleware/gin"
)

// Helper function to create context
func ctx() context.Context {
	return context.Background()
}

// Helper function to get environment variable with default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	// Initialize Keycloak client from environment variables
	config := &keycloak.Config{
		BaseURL:      getEnvOrDefault("KEYCLOAK_BASE_URL", "http://localhost:8080"),
		Realm:        getEnvOrDefault("KEYCLOAK_REALM", "demo"),
		ClientID:     getEnvOrDefault("KEYCLOAK_CLIENT_ID", "demo-client"),
		ClientSecret: getEnvOrDefault("KEYCLOAK_CLIENT_SECRET", "demo-secret"),
		AdminUser:    getEnvOrDefault("KEYCLOAK_ADMIN_USER", "admin"),
		AdminPass:    getEnvOrDefault("KEYCLOAK_ADMIN_PASS", "admin"),
	}

	// Create Keycloak client
	auth, err := keycloak.New(config)
	if err != nil {
		log.Fatalf("Failed to create Keycloak client: %v", err)
	}
	defer auth.Close()

	// Test connection
	if err := auth.Health(ctx()); err != nil {
		log.Printf("Warning: Keycloak health check failed: %v", err)
	} else {
		log.Println("✅ Connected to Keycloak successfully")
	}

	// Create Gin router
	r := gin.Default()

	// Create middleware
	middleware := ginMiddleware.GinMiddleware(auth)

	// Add CORS middleware if needed
	r.Use(middleware.CORS())

	// Public endpoints (no authentication required)
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Welcome to the Zero Trust API",
			"version": "1.0.0",
		})
	})

	r.GET("/health", func(c *gin.Context) {
		if err := auth.Health(c.Request.Context()); err != nil {
			c.JSON(503, gin.H{
				"status": "unhealthy",
				"error":  err.Error(),
			})
			return
		}
		c.JSON(200, gin.H{"status": "healthy"})
	})

	// Protected API routes
	api := r.Group("/api/v1")
	api.Use(middleware.Authenticate()) // Require authentication for all /api/v1 routes

	// Basic authenticated endpoint
	api.GET("/profile", func(c *gin.Context) {
		user := middleware.GetCurrentUser(c)
		c.JSON(200, gin.H{
			"user": user,
		})
	})

	// Role-based access control
	api.GET("/users", middleware.RequireRole("admin"), func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "List of users (admin only)",
			"users":   []string{"user1", "user2", "user3"},
		})
	})

	// Trust level based access control
	api.GET("/sensitive", middleware.RequireTrustLevel(50), func(c *gin.Context) {
		user := middleware.GetCurrentUser(c)
		c.JSON(200, gin.H{
			"message":     "Sensitive data access granted",
			"trust_level": user.TrustLevel,
			"data":        "This is sensitive information",
		})
	})

	// High security endpoint requiring device verification
	api.POST("/transfer", 
		middleware.RequireTrustLevel(75),
		middleware.RequireDeviceVerification(),
		func(c *gin.Context) {
			user := middleware.GetCurrentUser(c)
			c.JSON(200, gin.H{
				"message":         "Transfer authorized",
				"user_id":         user.UserID,
				"device_verified": user.DeviceVerified,
				"trust_level":     user.TrustLevel,
			})
		},
	)

	// Admin-only endpoint with multiple requirements
	api.DELETE("/admin/users/:id",
		middleware.RequireAnyRole("admin", "super-admin"),
		middleware.RequireTrustLevel(100),
		func(c *gin.Context) {
			userID := c.Param("id")
			user := middleware.GetCurrentUser(c)
			
			c.JSON(200, gin.H{
				"message":    "User deletion authorized",
				"target_id":  userID,
				"admin_user": user.Username,
			})
		},
	)

	// Metrics endpoint for monitoring
	api.GET("/metrics", middleware.RequireRole("admin"), func(c *gin.Context) {
		metrics, err := auth.GetMetrics(c.Request.Context())
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, metrics)
	})

	// User management endpoints
	userAPI := api.Group("/users")
	userAPI.Use(middleware.RequireRole("admin"))

	userAPI.POST("/", func(c *gin.Context) {
		var req keycloak.UserRegistrationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		user, err := auth.RegisterUser(c.Request.Context(), &req)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(201, user)
	})

	userAPI.PUT("/:id/trust-level", func(c *gin.Context) {
		var req keycloak.TrustLevelUpdateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		req.UserID = c.Param("id")
		currentUser := middleware.GetCurrentUser(c)
		req.AdminID = currentUser.UserID

		if err := auth.UpdateUserTrustLevel(c.Request.Context(), &req); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, gin.H{"message": "Trust level updated successfully"})
	})

	userAPI.POST("/:id/revoke-sessions", func(c *gin.Context) {
		userID := c.Param("id")
		
		if err := auth.RevokeUserSessions(c.Request.Context(), userID); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, gin.H{"message": "User sessions revoked successfully"})
	})

	// Start server
	port := getEnvOrDefault("PORT", "8080")
	log.Printf("🚀 Starting server on port %s", port)
	log.Printf("📖 API Documentation:")
	log.Printf("   GET  /                     - Welcome message")
	log.Printf("   GET  /health               - Health check")
	log.Printf("   GET  /api/v1/profile       - User profile (authenticated)")
	log.Printf("   GET  /api/v1/users         - List users (admin role)")
	log.Printf("   GET  /api/v1/sensitive     - Sensitive data (trust level 50+)")
	log.Printf("   POST /api/v1/transfer      - Transfer funds (trust level 75+, device verified)")
	log.Printf("   GET  /api/v1/metrics       - System metrics (admin role)")
	log.Printf("")
	log.Printf("🔑 Authentication: Include 'Authorization: Bearer <token>' header")
	log.Printf("🛡️  Zero Trust: Different endpoints require different trust levels")
	
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}