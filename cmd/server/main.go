// Package main provides the main entry point for the MVP Zero Trust Auth server.
// It sets up the HTTP server with Fiber, initializes all services, and starts the application.
//
// @title Zero Trust Auth API
// @version 1.0
// @description Zero Trust Authentication MVP API documentation
// @termsOfService http://swagger.io/terms/
//
// @contact.name API Support
// @contact.email support@example.com
//
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
//
// @host localhost:8080
// @BasePath /api
//
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Bearer token authentication. Format: "Bearer {token}"
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/swagger"
	"github.com/redis/go-redis/v9"
	_ "mvp.local/docs" // Import generated docs

	"mvp.local/pkg/auth"
	"mvp.local/pkg/config"
	"mvp.local/pkg/database"
	"mvp.local/pkg/handlers"
	"mvp.local/pkg/middleware"
	"mvp.local/pkg/observability"
	"mvp.local/pkg/security"
)

// Server represents the main application server
type Server struct {
	app            *fiber.App
	config         *config.Config
	db             *database.Database
	redisClient    *redis.Client
	obs            *observability.Observability
	authzService   *auth.AuthorizationService
	jwtService     *auth.JWTService
	lockoutService *security.LockoutService
}

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize server
	server, err := NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		log.Println("Shutting down server...")
		cancel()
	}()

	// Start server
	if err := server.Start(ctx); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// NewServer creates a new server instance
func NewServer(cfg *config.Config) (*Server, error) {
	// Initialize observability
	obsConfig := observability.Config{
		ServiceName:    cfg.Observability.ServiceName,
		ServiceVersion: cfg.Observability.ServiceVersion,
		Environment:    cfg.Observability.Environment,
		JaegerEndpoint: cfg.Observability.JaegerEndpoint,
		PrometheusPort: cfg.Observability.PrometheusPort,
		LogLevel:       cfg.Observability.LogLevel,
		LogFormat:      cfg.Observability.LogFormat,
	}
	obs, err := observability.New(obsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize observability: %w", err)
	}

	// Security metrics will be initialized in middleware setup

	// Initialize database
	db := database.NewDatabase(&cfg.Database)
	if err := db.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Run database migrations
	if err := db.Migrate(); err != nil {
		return nil, fmt.Errorf("failed to run database migrations: %w", err)
	}

	// Initialize Redis client
	var redisClient *redis.Client
	if cfg.Redis.Host != "" {
		redisClient = redis.NewClient(&redis.Options{
			Addr:         cfg.Redis.RedisAddr(),
			Password:     cfg.Redis.Password,
			DB:           cfg.Redis.Database,
			PoolSize:     cfg.Redis.PoolSize,
			DialTimeout:  cfg.Redis.DialTimeout,
			ReadTimeout:  cfg.Redis.ReadTimeout,
			WriteTimeout: cfg.Redis.WriteTimeout,
		})

		// Test Redis connection
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := redisClient.Ping(ctx).Err(); err != nil {
			obs.Logger.Warn().Err(err).Msg("Redis connection failed, continuing without Redis")
			redisClient = nil
		}
	}

	// Initialize authorization service (temporarily disabled for UUID migration)
	var authzService *auth.AuthorizationService
	// authzService := auth.NewAuthorizationService()

	// Get the absolute path to the RBAC model
	// modelPath, err := filepath.Abs("configs/rbac_model.conf")
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to get absolute path for RBAC model: %w", err)
	// }

	// if err := authzService.Initialize(db.GetDB(), modelPath); err != nil {
	// 	return nil, fmt.Errorf("failed to initialize authorization service: %w", err)
	// }

	// Initialize JWT service
	jwtService := auth.NewJWTService(&cfg.Security.JWT, authzService)

	// Initialize lockout service
	lockoutService := security.NewLockoutService(db.GetDB(), obs, &cfg.Security.Lockout)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		ReadTimeout:  cfg.HTTP.ReadTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout,
		IdleTimeout:  cfg.HTTP.IdleTimeout,
		ErrorHandler: errorHandler(obs),
	})

	server := &Server{
		app:            app,
		config:         cfg,
		db:             db,
		redisClient:    redisClient,
		obs:            obs,
		authzService:   authzService,
		jwtService:     jwtService,
		lockoutService: lockoutService,
	}

	server.setupMiddleware()
	server.setupRoutes()

	return server, nil
}

// setupMiddleware configures global middleware
func (s *Server) setupMiddleware() {
	// Recovery middleware
	s.app.Use(recover.New())

	// CORS middleware
	if s.config.Security.CORS.Enabled {
		s.app.Use(cors.New(cors.Config{
			AllowOrigins:     joinStrings(s.config.Security.CORS.AllowedOrigins, ","),
			AllowMethods:     joinStrings(s.config.Security.CORS.AllowedMethods, ","),
			AllowHeaders:     joinStrings(s.config.Security.CORS.AllowedHeaders, ","),
			ExposeHeaders:    joinStrings(s.config.Security.CORS.ExposedHeaders, ","),
			AllowCredentials: s.config.Security.CORS.AllowCredentials,
			MaxAge:           s.config.Security.CORS.MaxAge,
		}))
	}

	// Correlation ID middleware
	s.app.Use(middleware.CorrelationIDMiddleware())

	// Tracing middleware (must come before observability middleware)
	s.app.Use(middleware.TracingMiddleware(s.obs.Tracer))

	// Tenant context middleware
	s.app.Use(middleware.TenantContextMiddleware())

	// Observability middleware
	securityMetrics, _ := observability.NewSecurityMetrics(s.obs.Meter)
	s.app.Use(middleware.ObservabilityMiddleware(s.obs, securityMetrics))

	// Authentication middleware for audit logging
	authMiddleware := auth.NewAuthMiddleware(s.jwtService, s.authzService, s.db.GetDB(), s.obs, s.config)
	s.app.Use(authMiddleware.AuditMiddleware())
}

// setupRoutes configures all application routes
func (s *Server) setupRoutes() {
	// Initialize handlers
	authHandler := handlers.NewAuthHandler(s.db.GetDB(), s.jwtService, s.authzService, s.lockoutService, s.obs, s.config)
	deviceHandler := handlers.NewDeviceHandler(s.db.GetDB(), s.authzService, s.obs)
	systemHandler := handlers.NewSystemHandler(s.db, s.redisClient, s.authzService, s.obs)
	adminHandler := handlers.NewAdminHandler(s.db.GetDB(), s.authzService, s.obs)

	// Initialize middleware
	authMiddleware := auth.NewAuthMiddleware(s.jwtService, s.authzService, s.db.GetDB(), s.obs, s.config)

	// Public routes
	s.app.Get("/health", systemHandler.Health)
	s.app.Get("/metrics", systemHandler.Metrics)

	// API routes
	api := s.app.Group("/api")

	// Authentication routes (public)
	authRoutes := api.Group("/auth")
	authRoutes.Post("/login", authHandler.Login)
	authRoutes.Post("/register", authHandler.Register)
	authRoutes.Post("/refresh", authHandler.RefreshToken)

	// Protected authentication routes
	authProtected := authRoutes.Group("", authMiddleware.RequireAuth())
	authProtected.Get("/me", authHandler.GetCurrentUser)
	authProtected.Post("/logout", authHandler.Logout)
	authProtected.Post("/change-password", authHandler.ChangePassword)

	// Device routes (protected)
	deviceRoutes := api.Group("/devices", authMiddleware.RequireAuth())
	deviceRoutes.Get("/", deviceHandler.GetDevices)
	deviceRoutes.Post("/", deviceHandler.AttestDevice)
	deviceRoutes.Get("/:id", deviceHandler.GetDeviceById)
	deviceRoutes.Put("/:id", deviceHandler.UpdateDevice)
	deviceRoutes.Delete("/:id", deviceHandler.DeleteDevice)
	if s.authzService != nil {
		deviceRoutes.Post("/:id/verify", authMiddleware.RequirePermission("device", "verify"), deviceHandler.VerifyDevice)
	} else {
		// Simplified device verify route when authorization service is disabled
		deviceRoutes.Post("/:id/verify", deviceHandler.VerifyDevice)
	}

	// System routes (protected)
	systemRoutes := api.Group("/system", authMiddleware.RequireAuth())
	systemRoutes.Get("/health", systemHandler.SystemHealth)
	if s.authzService != nil {
		systemRoutes.Get("/stats", authMiddleware.RequirePermission("system", "admin"), systemHandler.DatabaseStats)
	} else {
		// Simplified stats route when authorization service is disabled
		systemRoutes.Get("/stats", systemHandler.DatabaseStats)
	}

	// Admin routes (protected, admin only)
	// Note: Using RequireAuth only while authorization service is disabled
	var adminRoutes fiber.Router
	if s.authzService != nil {
		adminRoutes = api.Group("/admin", authMiddleware.RequireAuth(), authMiddleware.RequirePermission("system", "admin"))
	} else {
		// Simplified admin routes when authorization service is disabled
		adminRoutes = api.Group("/admin", authMiddleware.RequireAuth())
	}

	// Role management
	adminRoutes.Get("/roles", adminHandler.GetRoles)
	adminRoutes.Post("/roles", adminHandler.CreateRole)
	adminRoutes.Put("/roles/:id", adminHandler.UpdateRole)
	adminRoutes.Delete("/roles/:id", adminHandler.DeleteRole)

	// Permission management
	adminRoutes.Get("/permissions", adminHandler.GetPermissions)
	adminRoutes.Post("/roles/:roleId/permissions/:permissionId", adminHandler.AssignPermissionToRole)
	adminRoutes.Delete("/roles/:roleId/permissions/:permissionId", adminHandler.RemovePermissionFromRole)

	// User management
	adminRoutes.Get("/users", adminHandler.GetUsers)
	adminRoutes.Get("/users/:id", adminHandler.GetUserById)
	adminRoutes.Put("/users/:id", adminHandler.UpdateUser)
	adminRoutes.Delete("/users/:id", adminHandler.DeleteUser)
	adminRoutes.Post("/users/:userId/roles/:roleId", adminHandler.AssignRoleToUser)
	adminRoutes.Delete("/users/:userId/roles/:roleId", adminHandler.RemoveRoleFromUser)

	// Swagger documentation
	s.app.Get("/swagger/*", swagger.HandlerDefault)

	// Frontend routes (serve static files)
	s.app.Static("/", "./frontend/dist")

	// Catch-all for SPA routing
	s.app.Get("/*", func(c *fiber.Ctx) error {
		return c.SendFile("./frontend/dist/index.html")
	})
}

// Start starts the server
func (s *Server) Start(ctx context.Context) error {
	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		addr := s.config.HTTP.HTTPAddr()
		s.obs.Logger.Info().Str("address", addr).Msg("Starting HTTP server")

		if s.config.HTTP.TLS.Enabled {
			errChan <- s.app.ListenTLS(addr, s.config.HTTP.TLS.CertFile, s.config.HTTP.TLS.KeyFile)
		} else {
			errChan <- s.app.Listen(addr)
		}
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		s.obs.Logger.Info().Msg("Shutting down server gracefully")

		// Graceful shutdown with timeout
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.app.ShutdownWithContext(shutdownCtx); err != nil {
			s.obs.Logger.Error().Err(err).Msg("Server forced to shutdown")
		}

		// Close database connection
		if err := s.db.Close(); err != nil {
			s.obs.Logger.Error().Err(err).Msg("Failed to close database connection")
		}

		// Close Redis connection
		if s.redisClient != nil {
			if err := s.redisClient.Close(); err != nil {
				s.obs.Logger.Error().Err(err).Msg("Failed to close Redis connection")
			}
		}

		s.obs.Logger.Info().Msg("Server shutdown complete")
		return nil

	case err := <-errChan:
		if err != nil {
			s.obs.Logger.Error().Err(err).Msg("Server error")
			return err
		}
		return nil
	}
}

// errorHandler provides custom error handling for Fiber
func errorHandler(obs *observability.Observability) fiber.ErrorHandler {
	return func(c *fiber.Ctx, err error) error {
		code := fiber.StatusInternalServerError
		message := "Internal Server Error"

		// Check if it's a Fiber error
		if e, ok := err.(*fiber.Error); ok {
			code = e.Code
			message = e.Message
		}

		// Log error
		obs.Logger.Error().
			Err(err).
			Int("status_code", code).
			Str("method", c.Method()).
			Str("path", c.Path()).
			Msg("Request error")

		// Return error response
		return c.Status(code).JSON(fiber.Map{
			"error":   message,
			"message": err.Error(),
		})
	}
}

// joinStrings joins a slice of strings with a separator
func joinStrings(slice []string, sep string) string {
	if len(slice) == 0 {
		return ""
	}
	result := slice[0]
	for i := 1; i < len(slice); i++ {
		result += sep + slice[i]
	}
	return result
}
