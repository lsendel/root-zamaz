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
	"path/filepath"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/redis/go-redis/v9"
	_ "mvp.local/docs" // Import generated docs for Swagger UI
	docspkg "mvp.local/pkg/docs"

	"mvp.local/pkg/auth"
	"mvp.local/pkg/cache"
	"mvp.local/pkg/config"
	"mvp.local/pkg/database"
	"mvp.local/pkg/handlers"
	"mvp.local/pkg/middleware"
	"mvp.local/pkg/observability"
	"mvp.local/pkg/security"
	"mvp.local/pkg/session"
	"mvp.local/pkg/validation"
)

// Server represents the main application server
type Server struct {
	app                   *fiber.App
	config                *config.Config
	db                    *database.Database
	redisClient           *redis.Client
	obs                   *observability.Observability
	authzService          *auth.AuthorizationService
	jwtService            *auth.JWTService
	lockoutService        *security.LockoutService
	requestSigningManager *security.RequestSigningManager
	validationMiddleware  *validation.ValidationMiddleware
	slaMetrics            *observability.SLAMetrics
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

	slaMetrics, _ := observability.NewSLAMetrics(obs.Meter)
	slaMetrics.StartUptimeCollection(context.Background(), time.Second)

	// Security metrics will be initialized in middleware setup

	// Initialize database
	db := database.NewDatabase(&cfg.Database, obs)
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

	// Initialize authorization service
	authzService := auth.NewAuthorizationService()

	// Get the absolute path to the RBAC model
	modelPath, err := filepath.Abs(cfg.App.RBACModelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for RBAC model (%s): %w", cfg.App.RBACModelPath, err)
	}

	if err := authzService.Initialize(db.GetDB(), modelPath); err != nil {
		return nil, fmt.Errorf("failed to initialize authorization service: %w", err)
	}

	// Set up caching for authorization service if Redis is available
	if redisClient != nil {
		redisCache := cache.NewRedisCache(redisClient, &cfg.Redis, obs, "auth")
		authzService.SetCache(redisCache)
		obs.Logger.Info().Msg("Authorization caching enabled with Redis")
	}

	// Initialize JWT service
	jwtService, err := auth.NewJWTService(&cfg.Security.JWT, authzService)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize JWT service: %w", err)
	}

	// Set up JWT blacklist if Redis is available
	if redisClient != nil {
		redisCache := cache.NewRedisCache(redisClient, &cfg.Redis, obs, "jwt_blacklist")
		jwtBlacklist := auth.NewJWTBlacklist(redisCache)
		jwtService.SetBlacklist(jwtBlacklist)
		obs.Logger.Info().Msg("JWT blacklist enabled with Redis")
	}

	// Initialize lockout service
	lockoutService := security.NewLockoutService(db.GetDB(), obs, &cfg.Security.Lockout)

	// Initialize request signing manager
	var requestSigningManager *security.RequestSigningManager
	if cfg.Security.RequestSigning.Enabled {
		var signingCache cache.Cache
		if redisClient != nil {
			signingCache = cache.NewRedisCache(redisClient, &cfg.Redis, obs, "request_signing")
		}
		requestSigningManager = security.NewRequestSigningManager(&cfg.Security.RequestSigning, obs, signingCache)
		if requestSigningManager != nil {
			obs.Logger.Info().
				Str("algorithm", cfg.Security.RequestSigning.Algorithm).
				Str("key_id", cfg.Security.RequestSigning.KeyID).
				Msg("Request signing enabled")
		}
	}

	// Create Fiber app
	app := fiber.New(fiber.Config{
		ReadTimeout:  cfg.HTTP.ReadTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout,
		IdleTimeout:  cfg.HTTP.IdleTimeout,
		ErrorHandler: middleware.ErrorHandlerMiddleware(obs),
	})

	server := &Server{
		app:                   app,
		config:                cfg,
		db:                    db,
		redisClient:           redisClient,
		obs:                   obs,
		authzService:          authzService,
		jwtService:            jwtService,
		lockoutService:        lockoutService,
		requestSigningManager: requestSigningManager,
		slaMetrics:            slaMetrics,
	}

	server.setupMiddleware()
	server.setupRoutes()

	return server, nil
}

// setupMiddleware configures global middleware in optimal order for performance
func (s *Server) setupMiddleware() {
	// 1. Recovery middleware (first for safety - catches panics from all subsequent middleware)
	s.app.Use(middleware.RecoveryMiddleware(s.obs))

	// 2. Rate limiting (early rejection of excessive requests)
	if s.redisClient != nil {
		rateLimiter := middleware.NewRateLimiter(s.redisClient, s.obs)
		s.app.Use(rateLimiter.RateLimitMiddleware())
	}

	// 3. CORS middleware (handle preflight requests early)
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

	// 4. Correlation ID middleware (required for tracing and logging)
	s.app.Use(middleware.CorrelationIDMiddleware())

	// 5. Tracing middleware (must come before observability middleware)
	s.app.Use(middleware.TracingMiddleware(s.obs.Tracer))

	// 6. Tenant context middleware (lightweight context setup)
	s.app.Use(middleware.TenantContextMiddleware())

	// 7. Observability middleware (metrics and monitoring)
	securityMetrics, _ := observability.NewSecurityMetrics(s.obs.Meter)
	s.app.Use(middleware.ObservabilityMiddleware(s.obs, securityMetrics, s.slaMetrics))

	// 8. Request signing middleware (validate signatures before processing)
	if s.requestSigningManager != nil && s.requestSigningManager.IsEnabled() {
		signingConfig := middleware.RequestSigningConfig{
			SkipPaths:   []string{"/health", "/metrics"}, // Skip health/metrics endpoints
			SkipMethods: []string{"OPTIONS"},             // Skip CORS preflight
		}
		s.app.Use(middleware.RequestSigningMiddlewareWithConfig(s.requestSigningManager, signingConfig))
	}

	// 9. Validation middleware (validate requests before processing)
	s.validationMiddleware = validation.NewValidationMiddleware(s.obs)
	s.app.Use(s.validationMiddleware.ValidationMiddleware())

	// 10. Request/Response logging middleware (after validation, before auth)
	s.app.Use(middleware.LoggingMiddleware(s.obs))

	// 11. Authentication middleware for audit logging (last - for complete context)
	authMiddleware := auth.NewAuthMiddleware(s.jwtService, s.authzService, s.db.GetDB(), s.obs, s.config)
	s.app.Use(authMiddleware.AuditMiddleware())
}

// setupRoutes configures all application routes
func (s *Server) setupRoutes() {
	// Initialize session manager
	var sessionManager *session.SessionManager
	if s.redisClient != nil {
		cacheLayer, err := cache.NewCacheLayer(s.redisClient, cache.CacheConfig{TTL: 24 * time.Hour})
		if err != nil {
			s.obs.Logger.Warn().Err(err).Msg("Failed to initialize cache layer")
			sessionManager = session.NewSessionManager(s.redisClient, nil)
		} else {
			sessionManager = session.NewSessionManager(s.redisClient, cacheLayer)
		}
	}

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(s.db.GetDB(), s.jwtService, s.authzService, s.lockoutService, nil, sessionManager, s.obs, s.config)
	deviceHandler := handlers.NewDeviceHandler(s.db.GetDB(), s.authzService, s.obs)
	systemHandler := handlers.NewSystemHandler(s.db, s.redisClient, nil, s.authzService, s.obs)
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
	authRoutes.Post("/login",
		s.validationMiddleware.ValidateRequest(auth.LoginRequest{}),
		authHandler.Login)
	authRoutes.Post("/register",
		s.validationMiddleware.ValidateRequest(handlers.RegisterRequest{}),
		authHandler.Register)
	authRoutes.Post("/refresh",
		s.validationMiddleware.ValidateRequest(auth.RefreshRequest{}),
		authHandler.RefreshToken)

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
	deviceRoutes.Post("/:id/verify", authMiddleware.RequirePermission("device", "verify"), deviceHandler.VerifyDevice)

	// System routes (protected)
	systemRoutes := api.Group("/system", authMiddleware.RequireAuth())
	systemRoutes.Get("/health", systemHandler.SystemHealth)
	systemRoutes.Get("/stats", authMiddleware.RequirePermission("system", "admin"), systemHandler.DatabaseStats)

	// Admin routes (protected, admin only)
	adminRoutes := api.Group("/admin", authMiddleware.RequireAuth(), authMiddleware.RequirePermission("system", "admin"))

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
	docspkg.SetupSwagger(s.app)

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
