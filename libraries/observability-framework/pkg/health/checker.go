// Package health provides comprehensive health checking for Zero Trust services
package health

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// HealthStatus represents the health status of a component
type HealthStatus string

const (
	HealthyStatus   HealthStatus = "healthy"
	UnhealthyStatus HealthStatus = "unhealthy"
	UnknownStatus   HealthStatus = "unknown"
	DegradedStatus  HealthStatus = "degraded"
)

// HealthResult represents the result of a health check
type HealthResult struct {
	Status    HealthStatus           `json:"status"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Duration  time.Duration          `json:"duration"`
}

// CheckFunc is a function that performs a health check
type CheckFunc func(ctx context.Context) HealthResult

// DependencyCheck interface for checking external dependencies
type DependencyCheck interface {
	Check(ctx context.Context) HealthResult
	Name() string
	Critical() bool
}

// HealthChecker manages health checks for multiple dependencies
type HealthChecker struct {
	checks       map[string]CheckFunc
	dependencies map[string]DependencyCheck
	config       *HealthConfig
	mutex        sync.RWMutex
}

// HealthConfig configures the health checker
type HealthConfig struct {
	Timeout         time.Duration
	CheckInterval   time.Duration
	GracePeriod     time.Duration
	MaxFailures     int
	EnableCaching   bool
	CacheTTL        time.Duration
}

// OverallStatus represents the overall health status
type OverallStatus struct {
	Overall      HealthStatus                    `json:"overall"`
	Dependencies map[string]HealthResult         `json:"dependencies"`
	Summary      map[HealthStatus]int            `json:"summary"`
	Timestamp    time.Time                       `json:"timestamp"`
	Checks       map[string]HealthResult         `json:"checks,omitempty"`
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(config ...*HealthConfig) *HealthChecker {
	var cfg *HealthConfig
	if len(config) > 0 && config[0] != nil {
		cfg = config[0]
	} else {
		cfg = &HealthConfig{
			Timeout:       5 * time.Second,
			CheckInterval: 30 * time.Second,
			GracePeriod:   10 * time.Second,
			MaxFailures:   3,
			EnableCaching: true,
			CacheTTL:      10 * time.Second,
		}
	}

	return &HealthChecker{
		checks:       make(map[string]CheckFunc),
		dependencies: make(map[string]DependencyCheck),
		config:       cfg,
	}
}

// RegisterCheck registers a custom health check
func (h *HealthChecker) RegisterCheck(name string, check CheckFunc) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	h.checks[name] = check
}

// RegisterDependency registers a dependency check
func (h *HealthChecker) RegisterDependency(name string, dep DependencyCheck) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	h.dependencies[name] = dep
}

// GetStatus returns the overall health status
func (h *HealthChecker) GetStatus() OverallStatus {
	ctx, cancel := context.WithTimeout(context.Background(), h.config.Timeout)
	defer cancel()

	return h.RunChecks(ctx)
}

// RunChecks executes all registered health checks
func (h *HealthChecker) RunChecks(ctx context.Context) OverallStatus {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	status := OverallStatus{
		Dependencies: make(map[string]HealthResult),
		Summary:      make(map[HealthStatus]int),
		Timestamp:    time.Now(),
		Checks:       make(map[string]HealthResult),
	}

	var wg sync.WaitGroup
	resultChan := make(chan struct {
		name   string
		result HealthResult
		isCheck bool
	}, len(h.dependencies)+len(h.checks))

	// Run dependency checks
	for name, dep := range h.dependencies {
		wg.Add(1)
		go func(n string, d DependencyCheck) {
			defer wg.Done()
			result := d.Check(ctx)
			resultChan <- struct {
				name   string
				result HealthResult
				isCheck bool
			}{n, result, false}
		}(name, dep)
	}

	// Run custom checks
	for name, check := range h.checks {
		wg.Add(1)
		go func(n string, c CheckFunc) {
			defer wg.Done()
			result := c(ctx)
			resultChan <- struct {
				name   string
				result HealthResult
				isCheck bool
			}{n, result, true}
		}(name, check)
	}

	// Wait for all checks to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	hasUnhealthy := false
	hasDegraded := false
	hasCriticalFailure := false

	for result := range resultChan {
		if result.isCheck {
			status.Checks[result.name] = result.result
		} else {
			status.Dependencies[result.name] = result.result
			
			// Check if this is a critical dependency
			if dep, exists := h.dependencies[result.name]; exists && dep.Critical() {
				if result.result.Status == UnhealthyStatus {
					hasCriticalFailure = true
				}
			}
		}

		// Update summary
		status.Summary[result.result.Status]++

		// Track overall status
		switch result.result.Status {
		case UnhealthyStatus:
			hasUnhealthy = true
		case DegradedStatus:
			hasDegraded = true
		}
	}

	// Determine overall status
	if hasCriticalFailure {
		status.Overall = UnhealthyStatus
	} else if hasUnhealthy {
		status.Overall = DegradedStatus
	} else if hasDegraded {
		status.Overall = DegradedStatus
	} else {
		status.Overall = HealthyStatus
	}

	return status
}

// KeycloakCheck checks Keycloak health
type KeycloakCheck struct {
	BaseURL string
	Realm   string
	Timeout time.Duration
	client  *http.Client
}

// Name returns the check name
func (k *KeycloakCheck) Name() string {
	return "keycloak"
}

// Critical returns whether this check is critical
func (k *KeycloakCheck) Critical() bool {
	return true
}

// Check performs the Keycloak health check
func (k *KeycloakCheck) Check(ctx context.Context) HealthResult {
	start := time.Now()
	
	if k.client == nil {
		timeout := k.Timeout
		if timeout == 0 {
			timeout = 5 * time.Second
		}
		k.client = &http.Client{Timeout: timeout}
	}

	// Check Keycloak health endpoint
	healthURL := fmt.Sprintf("%s/health/ready", k.BaseURL)
	
	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return HealthResult{
			Status:    UnhealthyStatus,
			Message:   fmt.Sprintf("Failed to create request: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}
	}

	resp, err := k.client.Do(req)
	if err != nil {
		return HealthResult{
			Status:    UnhealthyStatus,
			Message:   fmt.Sprintf("Health check failed: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}
	}
	defer resp.Body.Close()

	details := map[string]interface{}{
		"url":         healthURL,
		"status_code": resp.StatusCode,
		"realm":       k.Realm,
	}

	if resp.StatusCode == 200 {
		return HealthResult{
			Status:    HealthyStatus,
			Message:   "Keycloak is healthy",
			Details:   details,
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}
	}

	return HealthResult{
		Status:    UnhealthyStatus,
		Message:   fmt.Sprintf("Keycloak health check failed with status %d", resp.StatusCode),
		Details:   details,
		Timestamp: time.Now(),
		Duration:  time.Since(start),
	}
}

// RedisCheck checks Redis connectivity
type RedisCheck struct {
	URL      string
	Password string
	DB       int
	Timeout  time.Duration
	client   *redis.Client
}

// Name returns the check name
func (r *RedisCheck) Name() string {
	return "redis"
}

// Critical returns whether this check is critical
func (r *RedisCheck) Critical() bool {
	return false // Redis is typically used for caching, not critical
}

// Check performs the Redis health check
func (r *RedisCheck) Check(ctx context.Context) HealthResult {
	start := time.Now()
	
	if r.client == nil {
		r.client = redis.NewClient(&redis.Options{
			Addr:     r.URL,
			Password: r.Password,
			DB:       r.DB,
		})
	}

	// Ping Redis
	pong, err := r.client.Ping(ctx).Result()
	if err != nil {
		return HealthResult{
			Status:    UnhealthyStatus,
			Message:   fmt.Sprintf("Redis ping failed: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}
	}

	// Get Redis info
	info, err := r.client.Info(ctx, "server").Result()
	details := map[string]interface{}{
		"url":  r.URL,
		"ping": pong,
	}
	
	if err == nil {
		details["info"] = info
	}

	return HealthResult{
		Status:    HealthyStatus,
		Message:   "Redis is healthy",
		Details:   details,
		Timestamp: time.Now(),
		Duration:  time.Since(start),
	}
}

// DatabaseCheck checks database connectivity
type DatabaseCheck struct {
	DSN         string
	DriverName  string
	HealthQuery string
	Timeout     time.Duration
	Critical    bool
}

// Name returns the check name
func (d *DatabaseCheck) Name() string {
	return "database"
}

// Critical returns whether this check is critical
func (d *DatabaseCheck) Critical() bool {
	return d.Critical
}

// Check performs the database health check
func (d *DatabaseCheck) Check(ctx context.Context) HealthResult {
	start := time.Now()
	
	driverName := d.DriverName
	if driverName == "" {
		driverName = "postgres"
	}
	
	healthQuery := d.HealthQuery
	if healthQuery == "" {
		healthQuery = "SELECT 1"
	}

	db, err := sql.Open(driverName, d.DSN)
	if err != nil {
		return HealthResult{
			Status:    UnhealthyStatus,
			Message:   fmt.Sprintf("Failed to open database: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}
	}
	defer db.Close()

	// Set connection timeout
	if d.Timeout > 0 {
		db.SetConnMaxLifetime(d.Timeout)
	}

	// Test connection with health query
	var result int
	err = db.QueryRowContext(ctx, healthQuery).Scan(&result)
	if err != nil {
		return HealthResult{
			Status:    UnhealthyStatus,
			Message:   fmt.Sprintf("Health query failed: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}
	}

	// Get database stats
	stats := db.Stats()
	details := map[string]interface{}{
		"driver":            driverName,
		"health_query":      healthQuery,
		"open_connections":  stats.OpenConnections,
		"in_use":           stats.InUse,
		"idle":             stats.Idle,
	}

	return HealthResult{
		Status:    HealthyStatus,
		Message:   "Database is healthy",
		Details:   details,
		Timestamp: time.Now(),
		Duration:  time.Since(start),
	}
}

// Close cleans up resources
func (h *HealthChecker) Close() error {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	
	// Close any resources held by dependencies
	for _, dep := range h.dependencies {
		if closer, ok := dep.(interface{ Close() error }); ok {
			closer.Close()
		}
	}
	
	return nil
}