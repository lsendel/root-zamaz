// Package main demonstrates Fiber framework integration with go-keycloak-zerotrust
package main

import (
	"context"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	keycloak "github.com/yourorg/go-keycloak-zerotrust"
	fiberMiddleware "github.com/yourorg/go-keycloak-zerotrust/middleware/fiber"
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
	// Initialize Keycloak client with high-performance configuration
	config := &keycloak.Config{
		BaseURL:      getEnvOrDefault("KEYCLOAK_BASE_URL", "http://localhost:8080"),
		Realm:        getEnvOrDefault("KEYCLOAK_REALM", "demo"),
		ClientID:     getEnvOrDefault("KEYCLOAK_CLIENT_ID", "demo-client"),
		ClientSecret: getEnvOrDefault("KEYCLOAK_CLIENT_SECRET", "demo-secret"),
		AdminUser:    getEnvOrDefault("KEYCLOAK_ADMIN_USER", "admin"),
		AdminPass:    getEnvOrDefault("KEYCLOAK_ADMIN_PASS", "admin"),
		Cache: &keycloak.CacheConfig{
			Enabled:  true,
			Provider: "memory", // Use Redis in production
			TTL:      300000000000, // 5 minutes in nanoseconds
			MaxSize:  10000,
			Prefix:   "fiber_demo",
		},
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

	// Create Fiber app with optimized config
	app := fiber.New(fiber.Config{
		Prefork:       false, // Enable for production with multiple CPU cores
		CaseSensitive: true,
		StrictRouting: false,
		ServerHeader:  "Fiber/Zero-Trust",
		AppName:       "Zero Trust API v1.0.0",
	})

	// Built-in Fiber middleware
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${method} ${path} - ${latency}\n",
	}))
	app.Use(recover.New())

	// Create authentication middleware
	authMiddleware := fiberMiddleware.FiberMiddleware(auth, &keycloak.MiddlewareConfig{
		CorsEnabled: true,
		CorsOrigins: []string{"http://localhost:3000", "https://app.example.com"},
	})

	// Add custom middleware
	app.Use(authMiddleware.CORS())
	app.Use(authMiddleware.RequestID())

	// Public routes
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message":     "Welcome to Fiber Zero Trust API",
			"version":     "1.0.0",
			"framework":   "Fiber",
			"performance": "optimized",
			"request_id":  authMiddleware.GetRequestID(c),
		})
	})

	app.Get("/health", func(c *fiber.Ctx) error {
		if err := auth.Health(c.Context()); err != nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
				"status": "unhealthy",
				"error":  err.Error(),
			})
		}
		return c.JSON(fiber.Map{
			"status":     "healthy",
			"request_id": authMiddleware.GetRequestID(c),
		})
	})

	// Performance benchmark endpoint
	app.Get("/ping", func(c *fiber.Ctx) error {
		return c.SendString("pong")
	})

	// Protected API routes
	api := app.Group("/api/v1")
	api.Use(authMiddleware.Authenticate()) // Require authentication for all /api/v1 routes

	// Basic authenticated endpoint
	api.Get("/profile", func(c *fiber.Ctx) error {
		user := authMiddleware.GetCurrentUser(c)
		return c.JSON(fiber.Map{
			"user":       user,
			"request_id": authMiddleware.GetRequestID(c),
		})
	})

	// High-performance endpoint with minimal processing
	api.Get("/fast", func(c *fiber.Ctx) error {
		user := authMiddleware.GetCurrentUser(c)
		return c.JSON(fiber.Map{
			"user_id":    user.UserID,
			"trust":      user.TrustLevel,
			"request_id": authMiddleware.GetRequestID(c),
		})
	})

	// Role-based access control
	api.Get("/admin", authMiddleware.RequireRole("admin"), func(c *fiber.Ctx) error {
		user := authMiddleware.GetCurrentUser(c)
		return c.JSON(fiber.Map{
			"message":    "Admin access granted",
			"admin_user": user.Username,
			"roles":      user.Roles,
			"request_id": authMiddleware.GetRequestID(c),
		})
	})

	// Trust level based access control
	api.Get("/sensitive", authMiddleware.RequireTrustLevel(50), func(c *fiber.Ctx) error {
		user := authMiddleware.GetCurrentUser(c)
		return c.JSON(fiber.Map{
			"message":     "Sensitive data access granted",
			"trust_level": user.TrustLevel,
			"user_id":     user.UserID,
			"request_id":  authMiddleware.GetRequestID(c),
		})
	})

	// High security endpoint with multiple requirements
	api.Post("/transfer", 
		authMiddleware.RequireTrustLevel(75),
		authMiddleware.RequireDeviceVerification(),
		func(c *fiber.Ctx) error {
			user := authMiddleware.GetCurrentUser(c)
			
			// Parse request body efficiently
			var transferReq struct {
				Amount    float64 `json:"amount"`
				ToAccount string  `json:"to_account"`
				Currency  string  `json:"currency"`
			}
			
			if err := c.BodyParser(&transferReq); err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":      "Invalid request body",
					"request_id": authMiddleware.GetRequestID(c),
				})
			}

			// Validate transfer amount
			if transferReq.Amount <= 0 {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":      "Transfer amount must be positive",
					"request_id": authMiddleware.GetRequestID(c),
				})
			}

			return c.JSON(fiber.Map{
				"message":         "Transfer authorized",
				"amount":          transferReq.Amount,
				"currency":        transferReq.Currency,
				"to_account":      transferReq.ToAccount,
				"user_id":         user.UserID,
				"device_verified": user.DeviceVerified,
				"trust_level":     user.TrustLevel,
				"request_id":      authMiddleware.GetRequestID(c),
			})
		},
	)

	// Batch processing endpoint
	api.Post("/batch", 
		authMiddleware.RequireAnyRole("admin", "batch-processor"),
		authMiddleware.RequireTrustLevel(60),
		func(c *fiber.Ctx) error {
			user := authMiddleware.GetCurrentUser(c)
			
			var batchReq struct {
				Operations []map[string]interface{} `json:"operations"`
			}
			
			if err := c.BodyParser(&batchReq); err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error":      "Invalid request body",
					"request_id": authMiddleware.GetRequestID(c),
				})
			}

			// Process operations (simulation)
			processed := len(batchReq.Operations)
			
			return c.JSON(fiber.Map{
				"message":           "Batch processing completed",
				"operations_count":  processed,
				"processor_user":    user.Username,
				"trust_level":       user.TrustLevel,
				"request_id":        authMiddleware.GetRequestID(c),
			})
		},
	)

	// Real-time data endpoint with streaming response
	api.Get("/stream", authMiddleware.RequireTrustLevel(30), func(c *fiber.Ctx) error {
		user := authMiddleware.GetCurrentUser(c)
		
		// Set headers for streaming
		c.Set("Content-Type", "text/plain")
		c.Set("Cache-Control", "no-cache")
		c.Set("Connection", "keep-alive")
		
		// Simulate streaming data
		data := make([]string, 5)
		for i := 0; i < 5; i++ {
			data[i] = "Data chunk " + string(rune(i+48)) // Convert to ASCII
		}
		
		return c.JSON(fiber.Map{
			"user_id":    user.UserID,
			"stream_data": data,
			"request_id": authMiddleware.GetRequestID(c),
		})
	})

	// Metrics endpoint with detailed performance metrics
	api.Get("/metrics", authMiddleware.RequireRole("admin"), func(c *fiber.Ctx) error {
		metrics, err := auth.GetMetrics(c.Context())
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":      err.Error(),
				"request_id": authMiddleware.GetRequestID(c),
			})
		}
		
		// Add Fiber-specific metrics
		fiberMetrics := fiber.Map{
			"framework":    "fiber",
			"keycloak":     metrics,
			"request_id":   authMiddleware.GetRequestID(c),
		}
		
		return c.JSON(fiberMetrics)
	})

	// User management endpoints
	userAPI := api.Group("/users")
	userAPI.Use(authMiddleware.RequireRole("admin"))

	userAPI.Post("/", func(c *fiber.Ctx) error {
		var req keycloak.UserRegistrationRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":      "Invalid request body",
				"request_id": authMiddleware.GetRequestID(c),
			})
		}

		user, err := auth.RegisterUser(c.Context(), &req)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":      err.Error(),
				"request_id": authMiddleware.GetRequestID(c),
			})
		}

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"user":       user,
			"request_id": authMiddleware.GetRequestID(c),
		})
	})

	userAPI.Put("/:id/trust-level", func(c *fiber.Ctx) error {
		var req keycloak.TrustLevelUpdateRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":      "Invalid request body",
				"request_id": authMiddleware.GetRequestID(c),
			})
		}

		req.UserID = c.Params("id")
		currentUser := authMiddleware.GetCurrentUser(c)
		req.AdminID = currentUser.UserID

		if err := auth.UpdateUserTrustLevel(c.Context(), &req); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":      err.Error(),
				"request_id": authMiddleware.GetRequestID(c),
			})
		}

		return c.JSON(fiber.Map{
			"message":    "Trust level updated successfully",
			"request_id": authMiddleware.GetRequestID(c),
		})
	})

	// Device verification endpoints
	deviceAPI := api.Group("/device")
	deviceAPI.Use(authMiddleware.RequireTrustLevel(25))

	deviceAPI.Post("/verify", func(c *fiber.Ctx) error {
		user := authMiddleware.GetCurrentUser(c)
		
		var verifyReq struct {
			DeviceFingerprint string `json:"device_fingerprint"`
			Platform          string `json:"platform"`
			BiometricData     string `json:"biometric_data,omitempty"`
		}
		
		if err := c.BodyParser(&verifyReq); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":      "Invalid request body",
				"request_id": authMiddleware.GetRequestID(c),
			})
		}

		// Simulate device verification process
		verificationScore := 85 // Simulated score
		
		return c.JSON(fiber.Map{
			"message":              "Device verification completed",
			"user_id":              user.UserID,
			"device_fingerprint":   verifyReq.DeviceFingerprint,
			"platform":             verifyReq.Platform,
			"verification_score":   verificationScore,
			"verification_status":  "verified",
			"request_id":           authMiddleware.GetRequestID(c),
		})
	})

	deviceAPI.Get("/status", func(c *fiber.Ctx) error {
		user := authMiddleware.GetCurrentUser(c)
		
		return c.JSON(fiber.Map{
			"user_id":         user.UserID,
			"device_id":       user.DeviceID,
			"device_verified": user.DeviceVerified,
			"trust_level":     user.TrustLevel,
			"last_verification": user.LastVerification,
			"request_id":      authMiddleware.GetRequestID(c),
		})
	})

	// Error handling demonstration
	api.Get("/test-errors/:level", func(c *fiber.Ctx) error {
		level := c.Params("level")
		
		switch level {
		case "low":
			// Should work for most users
			return authMiddleware.RequireTrustLevel(25)(c)
		case "medium":
			// Requires higher trust
			return authMiddleware.RequireTrustLevel(50)(c)
		case "high":
			// Requires high trust + device verification
			return authMiddleware.RequireTrustLevel(75)(c)
		case "ultra":
			// Requires maximum trust
			return authMiddleware.RequireTrustLevel(100)(c)
		default:
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":      "Invalid level. Use: low, medium, high, ultra",
				"request_id": authMiddleware.GetRequestID(c),
			})
		}
	})

	// Start server
	port := getEnvOrDefault("PORT", "8082")
	log.Printf("🚀 Starting Fiber server on port %s", port)
	log.Printf("⚡ Fiber Configuration:")
	log.Printf("   - High Performance Mode: Enabled")
	log.Printf("   - Zero Trust Security: Active")
	log.Printf("   - Request ID Tracking: Enabled")
	log.Printf("   - Cache Layer: %s", config.Cache.Provider)
	log.Printf("")
	log.Printf("📖 API Documentation:")
	log.Printf("   GET  /                           - Welcome message")
	log.Printf("   GET  /health                     - Health check")
	log.Printf("   GET  /ping                       - Performance test")
	log.Printf("   GET  /api/v1/profile             - User profile")
	log.Printf("   GET  /api/v1/fast                - High-performance endpoint")
	log.Printf("   GET  /api/v1/admin               - Admin access")
	log.Printf("   POST /api/v1/transfer            - Transfer funds")
	log.Printf("   POST /api/v1/batch               - Batch processing")
	log.Printf("   GET  /api/v1/stream              - Streaming data")
	log.Printf("   POST /api/v1/device/verify       - Device verification")
	log.Printf("   GET  /api/v1/test-errors/:level  - Error testing")
	log.Printf("")
	log.Printf("🔑 Authentication: Include 'Authorization: Bearer <token>' header")
	log.Printf("🛡️  Zero Trust: Real-time trust level validation")
	log.Printf("⚡ Performance: Optimized for high-throughput scenarios")
	
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}