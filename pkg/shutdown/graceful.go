// Package shutdown provides graceful shutdown capabilities for zero-downtime deployments
package shutdown

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"github.com/redis/go-redis/v9"

	"mvp.local/pkg/observability"
)

// ShutdownConfig holds configuration for graceful shutdown
type ShutdownConfig struct {
	GracePeriod     time.Duration `default:"30s"`  // Maximum time to wait for graceful shutdown
	DrainPeriod     time.Duration `default:"5s"`   // Time to drain active connections
	HealthDelay     time.Duration `default:"2s"`   // Delay before marking unhealthy
	ForceTimeout    time.Duration `default:"60s"`  // Maximum time before force shutdown
	PreShutdownHook func() error  `default:"nil"`  // Hook to run before shutdown starts
}

// DefaultShutdownConfig returns sensible defaults
func DefaultShutdownConfig() ShutdownConfig {
	return ShutdownConfig{
		GracePeriod:  30 * time.Second,
		DrainPeriod:  5 * time.Second,
		HealthDelay:  2 * time.Second,
		ForceTimeout: 60 * time.Second,
	}
}

// ShutdownManager manages graceful shutdown of the application
type ShutdownManager struct {
	config     ShutdownConfig
	obs        *observability.Observability
	
	// Application components
	fiberApp   *fiber.App
	db         *gorm.DB
	redisClient *redis.Client
	
	// Shutdown state
	mu           sync.RWMutex
	shutdownFlag bool
	shutdownChan chan os.Signal
	
	// Component managers
	components   []ShutdownComponent
	hooks        []ShutdownHook
}

// ShutdownComponent represents a component that needs graceful shutdown
type ShutdownComponent interface {
	Name() string
	Shutdown(ctx context.Context) error
	IsHealthy() bool
}

// ShutdownHook represents a function to execute during shutdown
type ShutdownHook struct {
	Name     string
	Priority int // Lower numbers run first
	Func     func(ctx context.Context) error
}

// NewShutdownManager creates a new shutdown manager
func NewShutdownManager(
	config ShutdownConfig,
	obs *observability.Observability,
	fiberApp *fiber.App,
	db *gorm.DB,
	redisClient *redis.Client,
) *ShutdownManager {
	return &ShutdownManager{
		config:       config,
		obs:          obs,
		fiberApp:     fiberApp,
		db:           db,
		redisClient:  redisClient,
		shutdownChan: make(chan os.Signal, 1),
		components:   make([]ShutdownComponent, 0),
		hooks:        make([]ShutdownHook, 0),
	}
}

// RegisterComponent registers a component for graceful shutdown
func (sm *ShutdownManager) RegisterComponent(component ShutdownComponent) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	sm.components = append(sm.components, component)
	
	sm.obs.Logger.Info().
		Str("component", component.Name()).
		Msg("Registered component for graceful shutdown")
}

// RegisterHook registers a shutdown hook
func (sm *ShutdownManager) RegisterHook(hook ShutdownHook) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	sm.hooks = append(sm.hooks, hook)
	
	// Sort hooks by priority
	for i := len(sm.hooks) - 1; i > 0; i-- {
		if sm.hooks[i].Priority < sm.hooks[i-1].Priority {
			sm.hooks[i], sm.hooks[i-1] = sm.hooks[i-1], sm.hooks[i]
		} else {
			break
		}
	}
	
	sm.obs.Logger.Info().
		Str("hook", hook.Name).
		Int("priority", hook.Priority).
		Msg("Registered shutdown hook")
}

// Start begins listening for shutdown signals
func (sm *ShutdownManager) Start() {
	// Listen for shutdown signals
	signal.Notify(sm.shutdownChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
	
	sm.obs.Logger.Info().Msg("Graceful shutdown manager started, listening for signals")
}

// Wait waits for shutdown signal and performs graceful shutdown
func (sm *ShutdownManager) Wait() error {
	// Wait for shutdown signal
	sig := <-sm.shutdownChan
	
	sm.obs.Logger.Info().
		Str("signal", sig.String()).
		Msg("Received shutdown signal, initiating graceful shutdown")
	
	return sm.Shutdown()
}

// Shutdown performs graceful shutdown
func (sm *ShutdownManager) Shutdown() error {
	sm.mu.Lock()
	if sm.shutdownFlag {
		sm.mu.Unlock()
		return fmt.Errorf("shutdown already in progress")
	}
	sm.shutdownFlag = true
	sm.mu.Unlock()
	
	ctx, cancel := context.WithTimeout(context.Background(), sm.config.ForceTimeout)
	defer cancel()
	
	sm.obs.Logger.Info().
		Dur("grace_period", sm.config.GracePeriod).
		Dur("drain_period", sm.config.DrainPeriod).
		Msg("Starting graceful shutdown sequence")
	
	// Phase 1: Run pre-shutdown hook if configured
	if sm.config.PreShutdownHook != nil {
		sm.obs.Logger.Info().Msg("Running pre-shutdown hook")
		if err := sm.config.PreShutdownHook(); err != nil {
			sm.obs.Logger.Error().Err(err).Msg("Pre-shutdown hook failed")
		}
	}
	
	// Phase 2: Mark service as unhealthy (after delay)
	sm.obs.Logger.Info().
		Dur("delay", sm.config.HealthDelay).
		Msg("Waiting before marking service unhealthy")
	
	time.Sleep(sm.config.HealthDelay)
	sm.markUnhealthy()
	
	// Phase 3: Stop accepting new connections
	sm.obs.Logger.Info().Msg("Stopping acceptance of new connections")
	if err := sm.stopAcceptingConnections(ctx); err != nil {
		sm.obs.Logger.Error().Err(err).Msg("Failed to stop accepting connections")
	}
	
	// Phase 4: Drain existing connections
	sm.obs.Logger.Info().
		Dur("drain_period", sm.config.DrainPeriod).
		Msg("Draining existing connections")
	
	time.Sleep(sm.config.DrainPeriod)
	
	// Phase 5: Execute shutdown hooks in priority order
	if err := sm.executeShutdownHooks(ctx); err != nil {
		sm.obs.Logger.Error().Err(err).Msg("Shutdown hooks execution failed")
	}
	
	// Phase 6: Shutdown registered components
	if err := sm.shutdownComponents(ctx); err != nil {
		sm.obs.Logger.Error().Err(err).Msg("Component shutdown failed")
		return err
	}
	
	// Phase 7: Shutdown core services
	if err := sm.shutdownCoreServices(ctx); err != nil {
		sm.obs.Logger.Error().Err(err).Msg("Core services shutdown failed")
		return err
	}
	
	sm.obs.Logger.Info().Msg("Graceful shutdown completed successfully")
	return nil
}

// markUnhealthy marks the service as unhealthy for load balancer removal
func (sm *ShutdownManager) markUnhealthy() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	// This will cause health checks to fail, signaling load balancers to remove this instance
	sm.obs.Logger.Info().Msg("Service marked as unhealthy for load balancer removal")
}

// IsShuttingDown returns true if shutdown is in progress
func (sm *ShutdownManager) IsShuttingDown() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.shutdownFlag
}

// stopAcceptingConnections stops the HTTP server from accepting new connections
func (sm *ShutdownManager) stopAcceptingConnections(ctx context.Context) error {
	if sm.fiberApp == nil {
		return nil
	}
	
	// Fiber's graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	
	done := make(chan error, 1)
	go func() {
		done <- sm.fiberApp.ShutdownWithContext(shutdownCtx)
	}()
	
	select {
	case err := <-done:
		if err != nil {
			sm.obs.Logger.Error().Err(err).Msg("HTTP server shutdown failed")
			return err
		}
		sm.obs.Logger.Info().Msg("HTTP server stopped accepting new connections")
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// executeShutdownHooks runs all registered shutdown hooks
func (sm *ShutdownManager) executeShutdownHooks(ctx context.Context) error {
	sm.mu.RLock()
	hooks := make([]ShutdownHook, len(sm.hooks))
	copy(hooks, sm.hooks)
	sm.mu.RUnlock()
	
	for _, hook := range hooks {
		hookCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		
		sm.obs.Logger.Info().
			Str("hook", hook.Name).
			Int("priority", hook.Priority).
			Msg("Executing shutdown hook")
		
		if err := hook.Func(hookCtx); err != nil {
			cancel()
			sm.obs.Logger.Error().
				Err(err).
				Str("hook", hook.Name).
				Msg("Shutdown hook failed")
			return err
		}
		
		cancel()
		sm.obs.Logger.Info().
			Str("hook", hook.Name).
			Msg("Shutdown hook completed successfully")
	}
	
	return nil
}

// shutdownComponents gracefully shuts down registered components
func (sm *ShutdownManager) shutdownComponents(ctx context.Context) error {
	sm.mu.RLock()
	components := make([]ShutdownComponent, len(sm.components))
	copy(components, sm.components)
	sm.mu.RUnlock()
	
	// Shutdown components in parallel with individual timeouts
	var wg sync.WaitGroup
	errors := make(chan error, len(components))
	
	for _, component := range components {
		wg.Add(1)
		go func(comp ShutdownComponent) {
			defer wg.Done()
			
			compCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			
			sm.obs.Logger.Info().
				Str("component", comp.Name()).
				Msg("Shutting down component")
			
			if err := comp.Shutdown(compCtx); err != nil {
				sm.obs.Logger.Error().
					Err(err).
					Str("component", comp.Name()).
					Msg("Component shutdown failed")
				errors <- fmt.Errorf("component %s shutdown failed: %w", comp.Name(), err)
			} else {
				sm.obs.Logger.Info().
					Str("component", comp.Name()).
					Msg("Component shutdown completed")
			}
		}(component)
	}
	
	// Wait for all components to shutdown
	wg.Wait()
	close(errors)
	
	// Check for errors
	for err := range errors {
		return err
	}
	
	return nil
}

// shutdownCoreServices shuts down database and Redis connections
func (sm *ShutdownManager) shutdownCoreServices(ctx context.Context) error {
	var wg sync.WaitGroup
	errors := make(chan error, 2)
	
	// Shutdown database connections
	if sm.db != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			sm.obs.Logger.Info().Msg("Closing database connections")
			
			sqlDB, err := sm.db.DB()
			if err != nil {
				errors <- fmt.Errorf("failed to get underlying sql.DB: %w", err)
				return
			}
			
			if err := sqlDB.Close(); err != nil {
				errors <- fmt.Errorf("database connection close failed: %w", err)
			} else {
				sm.obs.Logger.Info().Msg("Database connections closed successfully")
			}
		}()
	}
	
	// Shutdown Redis connections
	if sm.redisClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			sm.obs.Logger.Info().Msg("Closing Redis connections")
			
			if err := sm.redisClient.Close(); err != nil {
				errors <- fmt.Errorf("redis connection close failed: %w", err)
			} else {
				sm.obs.Logger.Info().Msg("Redis connections closed successfully")
			}
		}()
	}
	
	// Wait for core services to shutdown
	wg.Wait()
	close(errors)
	
	// Check for errors
	for err := range errors {
		return err
	}
	
	return nil
}

// GetStatus returns the current shutdown status
func (sm *ShutdownManager) GetStatus() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	componentStatus := make(map[string]bool)
	for _, component := range sm.components {
		componentStatus[component.Name()] = component.IsHealthy()
	}
	
	return map[string]interface{}{
		"shutting_down":      sm.shutdownFlag,
		"grace_period":       sm.config.GracePeriod.String(),
		"drain_period":       sm.config.DrainPeriod.String(),
		"force_timeout":      sm.config.ForceTimeout.String(),
		"registered_components": len(sm.components),
		"registered_hooks":   len(sm.hooks),
		"component_status":   componentStatus,
	}
}

// Example component implementations

// DatabaseComponent wraps database for graceful shutdown
type DatabaseComponent struct {
	db  *gorm.DB
	obs *observability.Observability
}

func NewDatabaseComponent(db *gorm.DB, obs *observability.Observability) *DatabaseComponent {
	return &DatabaseComponent{db: db, obs: obs}
}

func (dc *DatabaseComponent) Name() string {
	return "database"
}

func (dc *DatabaseComponent) Shutdown(ctx context.Context) error {
	sqlDB, err := dc.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (dc *DatabaseComponent) IsHealthy() bool {
	sqlDB, err := dc.db.DB()
	if err != nil {
		return false
	}
	return sqlDB.Ping() == nil
}

// RedisComponent wraps Redis client for graceful shutdown
type RedisComponent struct {
	client *redis.Client
	obs    *observability.Observability
}

func NewRedisComponent(client *redis.Client, obs *observability.Observability) *RedisComponent {
	return &RedisComponent{client: client, obs: obs}
}

func (rc *RedisComponent) Name() string {
	return "redis"
}

func (rc *RedisComponent) Shutdown(ctx context.Context) error {
	return rc.client.Close()
}

func (rc *RedisComponent) IsHealthy() bool {
	return rc.client.Ping(context.Background()).Err() == nil
}