// Package database provides advanced connection pool management for optimized database performance
package database

import (
	"context"
	"database/sql"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"mvp.local/pkg/config"
	"mvp.local/pkg/errors"
	"mvp.local/pkg/observability"
)

// OptimizationProfile defines different connection pool optimization strategies
type OptimizationProfile string

const (
	ProfileDevelopment        OptimizationProfile = "development"
	ProfileTesting            OptimizationProfile = "testing"
	ProfileBalanced           OptimizationProfile = "balanced"
	ProfileHighThroughput     OptimizationProfile = "high_throughput"
	ProfileLowLatency         OptimizationProfile = "low_latency"
	ProfileResourceConstrained OptimizationProfile = "resource_constrained"
)

// PoolManager manages advanced database connection pool optimization
type PoolManager struct {
	config    *config.DatabaseConfig
	db        *gorm.DB
	sqlDB     *sql.DB
	obs       *observability.Observability
	
	// Monitoring and metrics
	stats          *PoolStats
	statsCollector *StatsCollector
	healthChecker  *HealthChecker
	leakDetector   *LeakDetector
	
	// Circuit breaker
	circuitBreaker *CircuitBreaker
	
	// Runtime optimization
	autoTuner    *AutoTuner
	
	// Synchronization
	mu sync.RWMutex
	
	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// PoolStats tracks comprehensive connection pool statistics
type PoolStats struct {
	// Connection statistics
	MaxOpenConnections int32 `json:"max_open_connections"`
	OpenConnections    int32 `json:"open_connections"`
	InUse             int32 `json:"in_use"`
	Idle              int32 `json:"idle"`
	WaitCount         int64 `json:"wait_count"`
	WaitDuration      int64 `json:"wait_duration_ms"`
	
	// Pool health metrics
	MaxIdleClosed      int64 `json:"max_idle_closed"`
	MaxIdleTimeClosed  int64 `json:"max_idle_time_closed"`
	MaxLifetimeClosed  int64 `json:"max_lifetime_closed"`
	
	// Performance metrics
	AverageQueryTime   int64 `json:"average_query_time_ms"`
	SlowQueries        int64 `json:"slow_queries"`
	FailedConnections  int64 `json:"failed_connections"`
	TotalQueries       int64 `json:"total_queries"`
	
	// Resource utilization
	CPUCores          int     `json:"cpu_cores"`
	MemoryUsage       int64   `json:"memory_usage_bytes"`
	ConnectionUtilization float64 `json:"connection_utilization"`
	
	// Optimization metrics
	OptimizationProfile string    `json:"optimization_profile"`
	LastOptimization    time.Time `json:"last_optimization"`
	TuningEnabled       bool      `json:"tuning_enabled"`
	
	// Error tracking
	ConnectionLeaks   int64 `json:"connection_leaks"`
	TimeoutErrors     int64 `json:"timeout_errors"`
	CircuitBreakerTrips int64 `json:"circuit_breaker_trips"`
}

// StatsCollector continuously monitors pool performance
type StatsCollector struct {
	manager  *PoolManager
	interval time.Duration
	enabled  bool
}

// HealthChecker monitors database connection health
type HealthChecker struct {
	manager  *PoolManager
	interval time.Duration
	enabled  bool
}

// LeakDetector identifies potential connection leaks
type LeakDetector struct {
	manager   *PoolManager
	threshold time.Duration
	enabled   bool
	
	// Connection tracking
	connections map[uintptr]*ConnectionInfo
	mu         sync.RWMutex
}

// ConnectionInfo tracks individual connection metrics
type ConnectionInfo struct {
	CreatedAt   time.Time
	LastUsed    time.Time
	QueryCount  int64
	IsIdle      bool
	ThreadID    uint64
}

// AutoTuner automatically optimizes pool settings based on workload
type AutoTuner struct {
	manager         *PoolManager
	enabled         bool
	analysisWindow  time.Duration
	optimizationCooldown time.Duration
	lastOptimization time.Time
	
	// Performance history
	performanceHistory []PerformanceSnapshot
	mu                sync.RWMutex
}

// PerformanceSnapshot captures pool performance at a point in time
type PerformanceSnapshot struct {
	Timestamp           time.Time
	QueriesPerSecond    float64
	AverageQueryTime    time.Duration
	ConnectionUtilization float64
	WaitTime            time.Duration
	ErrorRate           float64
}

// CircuitBreaker prevents cascade failures
type CircuitBreaker struct {
	manager          *PoolManager
	enabled          bool
	failureThreshold int
	resetTimeout     time.Duration
	
	// State management
	state        CircuitBreakerState
	failures     int64
	lastFailure  time.Time
	mu          sync.RWMutex
}

// CircuitBreakerState represents the current state of the circuit breaker
type CircuitBreakerState int

const (
	StateClose CircuitBreakerState = iota
	StateOpen
	StateHalfOpen
)

// NewPoolManager creates a new advanced pool manager
func NewPoolManager(config *config.DatabaseConfig, db *gorm.DB, obs *observability.Observability) (*PoolManager, error) {
	if db == nil {
		return nil, errors.Internal("Database connection required")
	}
	
	sqlDB, err := db.DB()
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to get underlying SQL DB")
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	pm := &PoolManager{
		config: config,
		db:     db,
		sqlDB:  sqlDB,
		obs:    obs,
		ctx:    ctx,
		cancel: cancel,
		stats:  &PoolStats{
			OptimizationProfile: config.OptimizationProfile,
			TuningEnabled:       config.AutoTuning,
			CPUCores:           runtime.NumCPU(),
		},
	}
	
	// Initialize components
	pm.statsCollector = &StatsCollector{
		manager:  pm,
		interval: config.MonitoringInterval,
		enabled:  config.EnableMetrics,
	}
	
	pm.healthChecker = &HealthChecker{
		manager:  pm,
		interval: config.HealthCheckInterval,
		enabled:  true,
	}
	
	pm.leakDetector = &LeakDetector{
		manager:     pm,
		threshold:   config.LeakThreshold,
		enabled:     config.LeakDetection,
		connections: make(map[uintptr]*ConnectionInfo),
	}
	
	pm.circuitBreaker = &CircuitBreaker{
		manager:          pm,
		enabled:          config.CircuitBreaker,
		failureThreshold: config.FailureThreshold,
		resetTimeout:     time.Minute * 5,
		state:           StateClose,
	}
	
	pm.autoTuner = &AutoTuner{
		manager:              pm,
		enabled:              config.AutoTuning,
		analysisWindow:       time.Minute * 5,
		optimizationCooldown: time.Minute * 10,
		performanceHistory:   make([]PerformanceSnapshot, 0, 100),
	}
	
	// Apply initial optimization
	if err := pm.optimizeForProfile(OptimizationProfile(config.OptimizationProfile)); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to apply optimization profile")
	}
	
	return pm, nil
}

// Start begins the pool manager's monitoring and optimization routines
func (pm *PoolManager) Start() error {
	if pm.statsCollector.enabled {
		pm.wg.Add(1)
		go pm.runStatsCollection()
	}
	
	if pm.healthChecker.enabled {
		pm.wg.Add(1)
		go pm.runHealthChecking()
	}
	
	if pm.leakDetector.enabled {
		pm.wg.Add(1)
		go pm.runLeakDetection()
	}
	
	if pm.autoTuner.enabled {
		pm.wg.Add(1)
		go pm.runAutoTuning()
	}
	
	pm.obs.Logger.Info().
		Str("profile", pm.config.OptimizationProfile).
		Bool("auto_tuning", pm.config.AutoTuning).
		Bool("leak_detection", pm.config.LeakDetection).
		Msg("Database pool manager started")
	
	return nil
}

// Stop gracefully shuts down the pool manager
func (pm *PoolManager) Stop() error {
	pm.cancel()
	pm.wg.Wait()
	
	pm.obs.Logger.Info().Msg("Database pool manager stopped")
	return nil
}

// GetStats returns current pool statistics
func (pm *PoolManager) GetStats() *PoolStats {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	// Update with current database stats
	dbStats := pm.sqlDB.Stats()
	
	atomic.StoreInt32(&pm.stats.MaxOpenConnections, int32(dbStats.MaxOpenConnections))
	atomic.StoreInt32(&pm.stats.OpenConnections, int32(dbStats.OpenConnections))
	atomic.StoreInt32(&pm.stats.InUse, int32(dbStats.InUse))
	atomic.StoreInt32(&pm.stats.Idle, int32(dbStats.Idle))
	atomic.StoreInt64(&pm.stats.WaitCount, dbStats.WaitCount)
	atomic.StoreInt64(&pm.stats.WaitDuration, dbStats.WaitDuration.Milliseconds())
	atomic.StoreInt64(&pm.stats.MaxIdleClosed, dbStats.MaxIdleClosed)
	atomic.StoreInt64(&pm.stats.MaxIdleTimeClosed, dbStats.MaxIdleTimeClosed)
	atomic.StoreInt64(&pm.stats.MaxLifetimeClosed, dbStats.MaxLifetimeClosed)
	
	// Calculate utilization
	if dbStats.MaxOpenConnections > 0 {
		pm.stats.ConnectionUtilization = float64(dbStats.OpenConnections) / float64(dbStats.MaxOpenConnections)
	}
	
	// Copy stats for return
	statsCopy := *pm.stats
	return &statsCopy
}

// optimizeForProfile applies optimization settings based on the specified profile
func (pm *PoolManager) optimizeForProfile(profile OptimizationProfile) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	numCPU := runtime.NumCPU()
	
	var maxConns, maxIdle int
	var connLifetime, idleTime time.Duration
	
	switch profile {
	case ProfileDevelopment:
		// Conservative settings for development
		maxConns = numCPU * 2
		maxIdle = 2
		connLifetime = 10 * time.Minute
		idleTime = 2 * time.Minute
		
	case ProfileTesting:
		// Minimal settings for testing
		maxConns = numCPU
		maxIdle = 1
		connLifetime = 5 * time.Minute
		idleTime = 1 * time.Minute
		
	case ProfileBalanced:
		// Balanced settings for general use
		maxConns = numCPU * 3
		maxIdle = maxConns / 4
		connLifetime = 15 * time.Minute
		idleTime = 5 * time.Minute
		
	case ProfileHighThroughput:
		// High connection count for throughput
		maxConns = numCPU * 6
		maxIdle = maxConns / 3
		connLifetime = 30 * time.Minute
		idleTime = 10 * time.Minute
		
	case ProfileLowLatency:
		// Optimized for low latency
		maxConns = numCPU * 4
		maxIdle = maxConns / 2 // Keep more connections warm
		connLifetime = 20 * time.Minute
		idleTime = 3 * time.Minute
		
	case ProfileResourceConstrained:
		// Minimal resource usage
		maxConns = numCPU
		maxIdle = 1
		connLifetime = 5 * time.Minute
		idleTime = 30 * time.Second
		
	default:
		return errors.Validation(fmt.Sprintf("Unknown optimization profile: %s", profile))
	}
	
	// Apply bounds checking
	if maxIdle < 1 {
		maxIdle = 1
	}
	if maxIdle > maxConns {
		maxIdle = maxConns
	}
	
	// Apply the optimized settings
	pm.sqlDB.SetMaxOpenConns(maxConns)
	pm.sqlDB.SetMaxIdleConns(maxIdle)
	pm.sqlDB.SetConnMaxLifetime(connLifetime)
	pm.sqlDB.SetConnMaxIdleTime(idleTime)
	
	pm.stats.LastOptimization = time.Now()
	
	pm.obs.Logger.Info().
		Str("profile", string(profile)).
		Int("max_connections", maxConns).
		Int("max_idle", maxIdle).
		Dur("conn_lifetime", connLifetime).
		Dur("idle_time", idleTime).
		Msg("Applied database optimization profile")
	
	return nil
}

// runStatsCollection continuously collects and exports pool statistics
func (pm *PoolManager) runStatsCollection() {
	defer pm.wg.Done()
	
	ticker := time.NewTicker(pm.statsCollector.interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.collectAndExportStats()
		}
	}
}

// collectAndExportStats gathers current statistics and exports them
func (pm *PoolManager) collectAndExportStats() {
	stats := pm.GetStats()
	
	// Export metrics to observability system
	if pm.obs != nil {
		// Connection pool metrics
		if gauge, err := pm.obs.Meter.Int64Gauge("db_max_open_connections"); err == nil {
			gauge.Record(pm.ctx, int64(stats.MaxOpenConnections))
		}
		
		if gauge, err := pm.obs.Meter.Int64Gauge("db_open_connections"); err == nil {
			gauge.Record(pm.ctx, int64(stats.OpenConnections))
		}
		
		if gauge, err := pm.obs.Meter.Int64Gauge("db_connections_in_use"); err == nil {
			gauge.Record(pm.ctx, int64(stats.InUse))
		}
		
		if gauge, err := pm.obs.Meter.Int64Gauge("db_idle_connections"); err == nil {
			gauge.Record(pm.ctx, int64(stats.Idle))
		}
		
		if gauge, err := pm.obs.Meter.Float64Gauge("db_connection_utilization"); err == nil {
			gauge.Record(pm.ctx, stats.ConnectionUtilization)
		}
		
		// Wait metrics
		if counter, err := pm.obs.Meter.Int64Counter("db_connection_waits_total"); err == nil {
			counter.Add(pm.ctx, stats.WaitCount)
		}
		
		if gauge, err := pm.obs.Meter.Int64Gauge("db_connection_wait_duration_ms"); err == nil {
			gauge.Record(pm.ctx, stats.WaitDuration)
		}
		
		// Health metrics
		if counter, err := pm.obs.Meter.Int64Counter("db_connection_leaks_total"); err == nil {
			counter.Add(pm.ctx, stats.ConnectionLeaks)
		}
		
		if counter, err := pm.obs.Meter.Int64Counter("db_timeout_errors_total"); err == nil {
			counter.Add(pm.ctx, stats.TimeoutErrors)
		}
	}
}

// runHealthChecking continuously monitors database health
func (pm *PoolManager) runHealthChecking() {
	defer pm.wg.Done()
	
	ticker := time.NewTicker(pm.healthChecker.interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.performHealthCheck()
		}
	}
}

// performHealthCheck checks database connectivity and performance
func (pm *PoolManager) performHealthCheck() {
	ctx, cancel := context.WithTimeout(pm.ctx, 10*time.Second)
	defer cancel()
	
	start := time.Now()
	err := pm.sqlDB.PingContext(ctx)
	duration := time.Since(start)
	
	if err != nil {
		atomic.AddInt64(&pm.stats.FailedConnections, 1)
		pm.circuitBreaker.recordFailure()
		
		pm.obs.Logger.Warn().
			Err(err).
			Dur("duration", duration).
			Msg("Database health check failed")
	} else {
		pm.circuitBreaker.recordSuccess()
		
		if duration > pm.config.SlowQueryThreshold {
			pm.obs.Logger.Warn().
				Dur("duration", duration).
				Msg("Slow database health check")
		}
	}
}

// runLeakDetection monitors for potential connection leaks
func (pm *PoolManager) runLeakDetection() {
	defer pm.wg.Done()
	
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.detectLeaks()
		}
	}
}

// detectLeaks identifies connections that may have leaked
func (pm *PoolManager) detectLeaks() {
	pm.leakDetector.mu.RLock()
	defer pm.leakDetector.mu.RUnlock()
	
	now := time.Now()
	leakCount := int64(0)
	
	for _, conn := range pm.leakDetector.connections {
		if now.Sub(conn.LastUsed) > pm.leakDetector.threshold {
			leakCount++
		}
	}
	
	if leakCount > 0 {
		atomic.AddInt64(&pm.stats.ConnectionLeaks, leakCount)
		
		pm.obs.Logger.Warn().
			Int64("leak_count", leakCount).
			Dur("threshold", pm.leakDetector.threshold).
			Msg("Potential connection leaks detected")
	}
}

// runAutoTuning continuously optimizes pool settings based on performance
func (pm *PoolManager) runAutoTuning() {
	defer pm.wg.Done()
	
	ticker := time.NewTicker(pm.autoTuner.analysisWindow)
	defer ticker.Stop()
	
	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.performAutoTuning()
		}
	}
}

// performAutoTuning analyzes performance and adjusts pool settings
func (pm *PoolManager) performAutoTuning() {
	if !pm.autoTuner.enabled {
		return
	}
	
	// Check cooldown period
	if time.Since(pm.autoTuner.lastOptimization) < pm.autoTuner.optimizationCooldown {
		return
	}
	
	pm.autoTuner.mu.Lock()
	defer pm.autoTuner.mu.Unlock()
	
	// Capture current performance snapshot
	stats := pm.GetStats()
	snapshot := PerformanceSnapshot{
		Timestamp:             time.Now(),
		ConnectionUtilization: stats.ConnectionUtilization,
		WaitTime:             time.Duration(stats.WaitDuration) * time.Millisecond,
	}
	
	// Add to history
	pm.autoTuner.performanceHistory = append(pm.autoTuner.performanceHistory, snapshot)
	
	// Keep only recent history
	if len(pm.autoTuner.performanceHistory) > 100 {
		pm.autoTuner.performanceHistory = pm.autoTuner.performanceHistory[1:]
	}
	
	// Analyze and optimize if we have enough data
	if len(pm.autoTuner.performanceHistory) >= 10 {
		pm.analyzeAndOptimize()
	}
}

// analyzeAndOptimize analyzes performance trends and applies optimizations
func (pm *PoolManager) analyzeAndOptimize() {
	// Calculate average metrics from recent history
	recentHistory := pm.autoTuner.performanceHistory[len(pm.autoTuner.performanceHistory)-10:]
	
	avgUtilization := 0.0
	avgWaitTime := time.Duration(0)
	
	for _, snapshot := range recentHistory {
		avgUtilization += snapshot.ConnectionUtilization
		avgWaitTime += snapshot.WaitTime
	}
	
	avgUtilization /= float64(len(recentHistory))
	avgWaitTime /= time.Duration(len(recentHistory))
	
	// Determine if optimization is needed
	needsOptimization := false
	var suggestedProfile OptimizationProfile
	
	if avgUtilization > 0.8 && avgWaitTime > 100*time.Millisecond {
		// High utilization and wait times - need more connections
		suggestedProfile = ProfileHighThroughput
		needsOptimization = true
	} else if avgUtilization < 0.2 {
		// Low utilization - can reduce connections
		suggestedProfile = ProfileResourceConstrained
		needsOptimization = true
	} else if avgWaitTime > 50*time.Millisecond {
		// High wait times but reasonable utilization
		suggestedProfile = ProfileLowLatency
		needsOptimization = true
	}
	
	if needsOptimization && suggestedProfile != OptimizationProfile(pm.config.OptimizationProfile) {
		pm.obs.Logger.Info().
			Float64("avg_utilization", avgUtilization).
			Dur("avg_wait_time", avgWaitTime).
			Str("current_profile", pm.config.OptimizationProfile).
			Str("suggested_profile", string(suggestedProfile)).
			Msg("Auto-tuning database pool")
		
		if err := pm.optimizeForProfile(suggestedProfile); err == nil {
			pm.autoTuner.lastOptimization = time.Now()
		}
	}
}

// recordFailure records a failure for circuit breaker logic
func (cb *CircuitBreaker) recordFailure() {
	if !cb.enabled {
		return
	}
	
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	cb.failures++
	cb.lastFailure = time.Now()
	
	if cb.failures >= int64(cb.failureThreshold) && cb.state == StateClose {
		cb.state = StateOpen
		atomic.AddInt64(&cb.manager.stats.CircuitBreakerTrips, 1)
		
		cb.manager.obs.Logger.Warn().
			Int64("failures", cb.failures).
			Msg("Database circuit breaker opened")
	}
}

// recordSuccess records a success for circuit breaker logic
func (cb *CircuitBreaker) recordSuccess() {
	if !cb.enabled {
		return
	}
	
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	if cb.state == StateHalfOpen {
		cb.state = StateClose
		cb.failures = 0
		
		cb.manager.obs.Logger.Info().Msg("Database circuit breaker closed")
	}
	
	// Reset failure count on sustained success
	if time.Since(cb.lastFailure) > cb.resetTimeout {
		cb.failures = 0
		if cb.state == StateOpen {
			cb.state = StateHalfOpen
		}
	}
}

// IsOpen returns true if the circuit breaker is open
func (cb *CircuitBreaker) IsOpen() bool {
	if !cb.enabled {
		return false
	}
	
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	
	return cb.state == StateOpen
}