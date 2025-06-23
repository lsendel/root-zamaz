// Package main demonstrates Echo framework integration with go-keycloak-zerotrust
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	keycloak "github.com/yourorg/go-keycloak-zerotrust"
	echoMiddleware "github.com/yourorg/go-keycloak-zerotrust/middleware/echo"
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
	if err := auth.Health(ctx()); err != nil {
		log.Printf("Warning: Keycloak health check failed: %v", err)
	} else {
		log.Println("✅ Connected to Keycloak successfully")
	}

	// Create Echo instance
	e := echo.New()

	// Built-in Echo middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Create authentication middleware
	authMiddleware := echoMiddleware.EchoMiddleware(auth, &keycloak.MiddlewareConfig{
		CorsEnabled: true,
		CorsOrigins: []string{"http://localhost:3000", "https://app.example.com"},
	})

	// Add CORS middleware
	e.Use(authMiddleware.CORS())

	// Public routes
	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message":   "Welcome to Echo Zero Trust API",
			"version":   "1.0.0",
			"framework": "Echo",
		})
	})

	e.GET("/health", func(c echo.Context) error {
		if err := auth.Health(c.Request().Context()); err != nil {
			return c.JSON(http.StatusServiceUnavailable, map[string]interface{}{
				"status": "unhealthy",
				"error":  err.Error(),
			})
		}
		return c.JSON(http.StatusOK, map[string]interface{}{"status": "healthy"})
	})

	// Protected API routes
	api := e.Group("/api/v1")
	api.Use(authMiddleware.Authenticate()) // Require authentication for all /api/v1 routes

	// Basic authenticated endpoint
	api.GET("/profile", func(c echo.Context) error {
		user := authMiddleware.GetCurrentUser(c)
		return c.JSON(http.StatusOK, map[string]interface{}{
			"user": user,
		})
	})

	// Role-based access control
	api.GET("/admin", authMiddleware.RequireRole("admin"), func(c echo.Context) error {
		user := authMiddleware.GetCurrentUser(c)
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message":    "Admin access granted",
			"admin_user": user.Username,
			"roles":      user.Roles,
		})
	})

	// Trust level based access control
	api.GET("/sensitive", authMiddleware.RequireTrustLevel(50), func(c echo.Context) error {
		user := authMiddleware.GetCurrentUser(c)
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message":     "Sensitive data access granted",
			"trust_level": user.TrustLevel,
			"user_id":     user.UserID,
		})
	})

	// High security endpoint requiring device verification
	api.POST("/transfer", 
		authMiddleware.RequireTrustLevel(75),
		authMiddleware.RequireDeviceVerification(),
		func(c echo.Context) error {
			user := authMiddleware.GetCurrentUser(c)
			
			// Parse request body
			var transferReq struct {
				Amount    float64 `json:"amount"`
				ToAccount string  `json:"to_account"`
			}
			
			if err := c.Bind(&transferReq); err != nil {
				return c.JSON(http.StatusBadRequest, map[string]interface{}{
					"error": "Invalid request body",
				})
			}

			return c.JSON(http.StatusOK, map[string]interface{}{
				"message":         "Transfer authorized",
				"amount":          transferReq.Amount,
				"to_account":      transferReq.ToAccount,
				"user_id":         user.UserID,
				"device_verified": user.DeviceVerified,
				"trust_level":     user.TrustLevel,
			})
		},
	)

	// Multiple role requirements
	api.DELETE("/admin/users/:id",
		authMiddleware.RequireAnyRole("admin", "super-admin"),
		authMiddleware.RequireTrustLevel(100),
		func(c echo.Context) error {
			userID := c.Param("id")
			currentUser := authMiddleware.GetCurrentUser(c)
			
			return c.JSON(http.StatusOK, map[string]interface{}{
				"message":    "User deletion authorized",
				"target_id":  userID,
				"admin_user": currentUser.Username,
				"admin_roles": currentUser.Roles,
			})
		},
	)

	// Metrics endpoint
	api.GET("/metrics", authMiddleware.RequireRole("admin"), func(c echo.Context) error {
		metrics, err := auth.GetMetrics(c.Request().Context())
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{
				"error": err.Error(),
			})
		}
		return c.JSON(http.StatusOK, metrics)
	})

	// User management endpoints
	userAPI := api.Group("/users")
	userAPI.Use(authMiddleware.RequireRole("admin"))

	userAPI.POST("", func(c echo.Context) error {
		var req keycloak.UserRegistrationRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"error": "Invalid request body",
			})
		}

		user, err := auth.RegisterUser(c.Request().Context(), &req)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{
				"error": err.Error(),
			})
		}

		return c.JSON(http.StatusCreated, user)
	})

	userAPI.PUT("/:id/trust-level", func(c echo.Context) error {
		var req keycloak.TrustLevelUpdateRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"error": "Invalid request body",
			})
		}

		req.UserID = c.Param("id")
		currentUser := authMiddleware.GetCurrentUser(c)
		req.AdminID = currentUser.UserID

		if err := auth.UpdateUserTrustLevel(c.Request().Context(), &req); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{
				"error": err.Error(),
			})
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "Trust level updated successfully",
		})
	})

	// Risk assessment demonstration
	api.GET("/risk-assessment", authMiddleware.RequireTrustLevel(25), func(c echo.Context) error {
		user := authMiddleware.GetCurrentUser(c)
		
		// Simulate risk assessment logic
		riskLevel := "low"
		if user.RiskScore > 50 {
			riskLevel = "medium"
		}
		if user.RiskScore > 75 {
			riskLevel = "high"
		}

		recommendations := []string{}
		if user.RiskScore > 50 {
			recommendations = append(recommendations, "Consider additional verification")
		}
		if !user.DeviceVerified {
			recommendations = append(recommendations, "Device verification recommended")
		}
		if user.TrustLevel < 50 {
			recommendations = append(recommendations, "Increase trust level for enhanced access")
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"user_id":         user.UserID,
			"risk_score":      user.RiskScore,
			"risk_level":      riskLevel,
			"trust_level":     user.TrustLevel,
			"device_verified": user.DeviceVerified,
			"recommendations": recommendations,
			"location":        user.LocationInfo,
		})
	})

	// Device verification endpoint
	api.POST("/verify-device", authMiddleware.RequireTrustLevel(25), func(c echo.Context) error {
		user := authMiddleware.GetCurrentUser(c)
		
		var verifyReq struct {
			DeviceFingerprint string `json:"device_fingerprint"`
			Platform          string `json:"platform"`
		}
		
		if err := c.Bind(&verifyReq); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"error": "Invalid request body",
			})
		}

		// In a real implementation, this would:
		// 1. Validate device fingerprint
		// 2. Update user's device verification status
		// 3. Potentially increase trust level

		return c.JSON(http.StatusOK, map[string]interface{}{
			"message":            "Device verification initiated",
			"user_id":            user.UserID,
			"device_fingerprint": verifyReq.DeviceFingerprint,
			"platform":           verifyReq.Platform,
			"status":             "pending_verification",
		})
	})

	// Error handling example
	api.GET("/protected-error", authMiddleware.RequireTrustLevel(90), func(c echo.Context) error {
		// This endpoint requires high trust level and will demonstrate error handling
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "You have very high trust level access!",
		})
	})

	// Start server
	port := getEnvOrDefault("PORT", "8081")
	log.Printf("🚀 Starting Echo server on port %s", port)
	log.Printf("📖 API Documentation:")
	log.Printf("   GET  /                           - Welcome message")
	log.Printf("   GET  /health                     - Health check")
	log.Printf("   GET  /api/v1/profile             - User profile (authenticated)")
	log.Printf("   GET  /api/v1/admin               - Admin access (admin role)")
	log.Printf("   GET  /api/v1/sensitive           - Sensitive data (trust level 50+)")
	log.Printf("   POST /api/v1/transfer            - Transfer funds (trust level 75+, device verified)")
	log.Printf("   GET  /api/v1/risk-assessment     - Risk assessment demo")
	log.Printf("   POST /api/v1/verify-device       - Device verification demo")
	log.Printf("   GET  /api/v1/metrics             - System metrics (admin role)")
	log.Printf("")
	log.Printf("🔑 Authentication: Include 'Authorization: Bearer <token>' header")
	log.Printf("🛡️  Zero Trust: Different endpoints require different trust levels")
	log.Printf("📍 Framework: Echo v4 with Zero Trust middleware")
	
	if err := e.Start(":" + port); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to start server: %v", err)
	}
}