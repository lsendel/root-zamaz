// Package cache provides Redis health checking and monitoring
package cache

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisHealthChecker provides comprehensive Redis health monitoring
type RedisHealthChecker struct {
	client    *redis.Client
	essential bool
	name      string
}

// HealthCheckResult represents the result of a Redis health check
type HealthCheckResult struct {
	Name      string                 `json:"name"`
	Status    HealthStatus           `json:"status"`
	Message   string                 `json:"message,omitempty"`
	Duration  time.Duration          `json:"duration"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

// HealthStatus represents the health status of Redis
type HealthStatus string

const (
	StatusHealthy   HealthStatus = "healthy"
	StatusUnhealthy HealthStatus = "unhealthy"
	StatusDegraded  HealthStatus = "degraded"
	StatusUnknown   HealthStatus = "unknown"
)

// NewRedisHealthChecker creates a new Redis health checker
func NewRedisHealthChecker(client *redis.Client, essential bool, name string) *RedisHealthChecker {
	if name == "" {
		name = "redis"
	}
	
	return &RedisHealthChecker{
		client:    client,
		essential: essential,
		name:      name,
	}
}

// Name returns the name of this health checker
func (rhc *RedisHealthChecker) Name() string {
	return rhc.name
}

// IsEssential returns whether this checker is essential for readiness
func (rhc *RedisHealthChecker) IsEssential() bool {
	return rhc.essential
}

// Check performs a comprehensive Redis health check
func (rhc *RedisHealthChecker) Check(ctx context.Context) HealthCheckResult {
	start := time.Now()
	
	result := HealthCheckResult{
		Name:      rhc.Name(),
		Timestamp: start,
		Metadata:  make(map[string]interface{}),
	}
	
	if rhc.client == nil {
		result.Status = StatusUnhealthy
		result.Error = "Redis client not initialized"
		result.Duration = time.Since(start)
		return result
	}
	
	// Test basic connectivity
	if err := rhc.testConnectivity(ctx, &result); err != nil {
		result.Status = StatusUnhealthy
		result.Error = fmt.Sprintf("Redis connectivity failed: %v", err)
		result.Duration = time.Since(start)
		return result
	}
	
	// Collect comprehensive metrics
	rhc.collectRedisMetrics(ctx, &result)
	
	// Test read/write operations
	rhc.testReadWriteOperations(ctx, &result)
	
	// Evaluate overall health
	rhc.evaluateRedisHealth(&result)
	
	result.Duration = time.Since(start)
	return result
}

// testConnectivity tests basic Redis connectivity
func (rhc *RedisHealthChecker) testConnectivity(ctx context.Context, result *HealthCheckResult) error {
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	
	_, err := rhc.client.Ping(pingCtx).Result()
	if err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}
	
	result.Metadata["connectivity"] = "ok"
	return nil
}

// collectRedisMetrics gathers comprehensive Redis metrics
func (rhc *RedisHealthChecker) collectRedisMetrics(ctx context.Context, result *HealthCheckResult) {
	// Get Redis INFO command output
	infoCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	
	if infoCmd := rhc.client.Info(infoCtx); infoCmd.Err() == nil {
		info := infoCmd.Val()
		result.Metadata["info_available"] = true
		
		// Parse memory information
		if memInfo := rhc.parseRedisInfoSection(info, "memory"); len(memInfo) > 0 {
			result.Metadata["memory"] = memInfo
		}
		
		// Parse server information
		if serverInfo := rhc.parseRedisInfoSection(info, "server"); len(serverInfo) > 0 {
			result.Metadata["server"] = serverInfo
		}
		
		// Parse stats information
		if statsInfo := rhc.parseRedisInfoSection(info, "stats"); len(statsInfo) > 0 {
			result.Metadata["stats"] = statsInfo
		}
		
		// Parse clients information
		if clientsInfo := rhc.parseRedisInfoSection(info, "clients"); len(clientsInfo) > 0 {
			result.Metadata["clients"] = clientsInfo
		}
		
		// Parse replication information
		if replInfo := rhc.parseRedisInfoSection(info, "replication"); len(replInfo) > 0 {
			result.Metadata["replication"] = replInfo
		}
		
		// Parse persistence information
		if persistInfo := rhc.parseRedisInfoSection(info, "persistence"); len(persistInfo) > 0 {
			result.Metadata["persistence"] = persistInfo
		}
	} else {
		result.Metadata["info_error"] = infoCmd.Err().Error()
	}
	
	// Get database keyspace info
	if dbSizeCmd := rhc.client.DBSize(infoCtx); dbSizeCmd.Err() == nil {
		result.Metadata["db_size"] = dbSizeCmd.Val()
	}
	
	// Get last save time
	if lastSaveCmd := rhc.client.LastSave(infoCtx); lastSaveCmd.Err() == nil {
		lastSave := lastSaveCmd.Val()
		result.Metadata["last_save"] = lastSave
		lastSaveTime := time.Unix(lastSave, 0)
		result.Metadata["last_save_ago"] = time.Since(lastSaveTime).String()
	}
}

// testReadWriteOperations tests basic Redis operations
func (rhc *RedisHealthChecker) testReadWriteOperations(ctx context.Context, result *HealthCheckResult) {
	testCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	
	testKey := fmt.Sprintf("health_check_test_%d", time.Now().UnixNano())
	testValue := fmt.Sprintf("test_value_%d", time.Now().Unix())
	
	// Test SET operation
	setStart := time.Now()
	if setCmd := rhc.client.Set(testCtx, testKey, testValue, time.Minute); setCmd.Err() == nil {
		setDuration := time.Since(setStart)
		result.Metadata["set_test"] = map[string]interface{}{
			"status":   "passed",
			"duration": setDuration.String(),
		}
		
		// Test GET operation
		getStart := time.Now()
		if getCmd := rhc.client.Get(testCtx, testKey); getCmd.Err() == nil && getCmd.Val() == testValue {
			getDuration := time.Since(getStart)
			result.Metadata["get_test"] = map[string]interface{}{
				"status":   "passed",
				"duration": getDuration.String(),
			}
			
			// Test DEL operation
			delStart := time.Now()
			if delCmd := rhc.client.Del(testCtx, testKey); delCmd.Err() == nil {
				delDuration := time.Since(delStart)
				result.Metadata["del_test"] = map[string]interface{}{
					"status":   "passed",
					"duration": delDuration.String(),
				}
				result.Metadata["read_write_test"] = "passed"
			} else {
				result.Metadata["del_test"] = map[string]interface{}{
					"status": "failed",
					"error":  delCmd.Err().Error(),
				}
				result.Metadata["read_write_test"] = "partially_failed"
			}
		} else {
			result.Metadata["get_test"] = map[string]interface{}{
				"status": "failed",
				"error":  getCmd.Err().Error(),
			}
			result.Metadata["read_write_test"] = "failed"
			// Clean up on failure
			rhc.client.Del(testCtx, testKey)
		}
	} else {
		result.Metadata["set_test"] = map[string]interface{}{
			"status": "failed",
			"error":  setCmd.Err().Error(),
		}
		result.Metadata["read_write_test"] = "failed"
	}
}

// parseRedisInfoSection parses specific sections from Redis INFO output
func (rhc *RedisHealthChecker) parseRedisInfoSection(info, section string) map[string]interface{} {
	result := make(map[string]interface{})
	lines := strings.Split(info, "\n")
	inSection := false
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Check for section headers
		if strings.HasPrefix(line, "# ") {
			sectionName := strings.ToLower(strings.TrimSpace(line[2:]))
			inSection = sectionName == section
			continue
		}
		
		// Skip comments and empty lines
		if !inSection || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Parse key:value pairs
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				
				// Try to convert to appropriate type
				if intVal, err := strconv.ParseInt(value, 10, 64); err == nil {
					result[key] = intVal
				} else if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
					result[key] = floatVal
				} else {
					result[key] = value
				}
			}
		}
	}
	
	return result
}

// evaluateRedisHealth determines the health status based on collected metrics
func (rhc *RedisHealthChecker) evaluateRedisHealth(result *HealthCheckResult) {
	// Start with healthy status
	result.Status = StatusHealthy
	result.Message = "Redis is healthy"
	
	// Check if basic read/write test failed
	if readWriteTest, ok := result.Metadata["read_write_test"].(string); ok {
		switch readWriteTest {
		case "failed":
			result.Status = StatusUnhealthy
			result.Message = "Redis read/write operations failing"
			return
		case "partially_failed":
			result.Status = StatusDegraded
			result.Message = "Redis read/write operations partially failing"
		}
	}
	
	// Check memory usage if available
	if memoryInfo, ok := result.Metadata["memory"].(map[string]interface{}); ok {
		rhc.evaluateMemoryHealth(memoryInfo, result)
	}
	
	// Check client connections if available
	if clientsInfo, ok := result.Metadata["clients"].(map[string]interface{}); ok {
		rhc.evaluateClientHealth(clientsInfo, result)
	}
	
	// Check replication health if available
	if replInfo, ok := result.Metadata["replication"].(map[string]interface{}); ok {
		rhc.evaluateReplicationHealth(replInfo, result)
	}
	
	// Check persistence health if available
	if persistInfo, ok := result.Metadata["persistence"].(map[string]interface{}); ok {
		rhc.evaluatePersistenceHealth(persistInfo, result)
	}
	
	// Check if info command failed
	if _, hasInfoError := result.Metadata["info_error"]; hasInfoError && result.Status == StatusHealthy {
		result.Status = StatusDegraded
		result.Message = "Redis ping successful but info command failed"
	}
}

// evaluateMemoryHealth checks memory-related health metrics
func (rhc *RedisHealthChecker) evaluateMemoryHealth(memoryInfo map[string]interface{}, result *HealthCheckResult) {
	if usedMemory, exists := memoryInfo["used_memory"].(int64); exists {
		// Check against max memory if configured
		if maxMemory, maxExists := memoryInfo["maxmemory"].(int64); maxExists && maxMemory > 0 {
			memoryUsagePercent := float64(usedMemory) / float64(maxMemory) * 100
			result.Metadata["memory_usage_percent"] = memoryUsagePercent
			
			if memoryUsagePercent > 95 {
				result.Status = StatusUnhealthy
				result.Message = fmt.Sprintf("Redis memory usage critical: %.1f%%", memoryUsagePercent)
			} else if memoryUsagePercent > 85 {
				if result.Status == StatusHealthy {
					result.Status = StatusDegraded
					result.Message = fmt.Sprintf("Redis memory usage high: %.1f%%", memoryUsagePercent)
				}
			}
		}
		
		// Check memory fragmentation ratio
		if fragRatio, fragExists := memoryInfo["mem_fragmentation_ratio"].(float64); fragExists {
			result.Metadata["memory_fragmentation_ratio"] = fragRatio
			
			if fragRatio > 2.0 {
				if result.Status == StatusHealthy {
					result.Status = StatusDegraded
					result.Message = fmt.Sprintf("Redis memory fragmentation high: %.2f", fragRatio)
				}
			}
		}
	}
}

// evaluateClientHealth checks client connection health
func (rhc *RedisHealthChecker) evaluateClientHealth(clientsInfo map[string]interface{}, result *HealthCheckResult) {
	if connectedClients, exists := clientsInfo["connected_clients"].(int64); exists {
		result.Metadata["connected_clients"] = connectedClients
		
		// Alert on high client connections (configurable threshold)
		if connectedClients > 1000 {
			if result.Status == StatusHealthy {
				result.Status = StatusDegraded
				result.Message = fmt.Sprintf("Redis high client connections: %d", connectedClients)
			}
		}
	}
	
	// Check for blocked clients
	if blockedClients, exists := clientsInfo["blocked_clients"].(int64); exists && blockedClients > 0 {
		result.Metadata["blocked_clients"] = blockedClients
		if result.Status == StatusHealthy {
			result.Status = StatusDegraded
			result.Message = fmt.Sprintf("Redis has blocked clients: %d", blockedClients)
		}
	}
}

// evaluateReplicationHealth checks replication status
func (rhc *RedisHealthChecker) evaluateReplicationHealth(replInfo map[string]interface{}, result *HealthCheckResult) {
	if role, exists := replInfo["role"].(string); exists {
		result.Metadata["redis_role"] = role
		
		if role == "slave" {
			// Check slave status
			if masterLinkStatus, linkExists := replInfo["master_link_status"].(string); linkExists {
				result.Metadata["master_link_status"] = masterLinkStatus
				if masterLinkStatus != "up" {
					result.Status = StatusUnhealthy
					result.Message = "Redis slave disconnected from master"
					return
				}
			}
			
			// Check replication lag
			if masterLastIOSecondsAgo, lagExists := replInfo["master_last_io_seconds_ago"].(int64); lagExists {
				result.Metadata["master_last_io_seconds_ago"] = masterLastIOSecondsAgo
				if masterLastIOSecondsAgo > 30 { // 30 seconds lag threshold
					if result.Status == StatusHealthy {
						result.Status = StatusDegraded
						result.Message = fmt.Sprintf("Redis replication lag: %d seconds", masterLastIOSecondsAgo)
					}
				}
			}
		}
	}
}

// evaluatePersistenceHealth checks persistence configuration and status
func (rhc *RedisHealthChecker) evaluatePersistenceHealth(persistInfo map[string]interface{}, result *HealthCheckResult) {
	// Check RDB status
	if rdbLastBgsaveStatus, exists := persistInfo["rdb_last_bgsave_status"].(string); exists {
		result.Metadata["rdb_last_bgsave_status"] = rdbLastBgsaveStatus
		if rdbLastBgsaveStatus != "ok" {
			if result.Status == StatusHealthy {
				result.Status = StatusDegraded
				result.Message = "Redis RDB background save failed"
			}
		}
	}
	
	// Check AOF status if enabled
	if aofEnabled, exists := persistInfo["aof_enabled"].(int64); exists && aofEnabled == 1 {
		if aofLastBgrewriteStatus, aofExists := persistInfo["aof_last_bgrewrite_status"].(string); aofExists {
			result.Metadata["aof_last_bgrewrite_status"] = aofLastBgrewriteStatus
			if aofLastBgrewriteStatus != "ok" {
				if result.Status == StatusHealthy {
					result.Status = StatusDegraded
					result.Message = "Redis AOF background rewrite failed"
				}
			}
		}
	}
}

// GetSlowQueries returns recent slow queries
func (rhc *RedisHealthChecker) GetSlowQueries(ctx context.Context, count int64) ([]map[string]interface{}, error) {
	if count <= 0 {
		count = 10
	}
	
	slowLogCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	
	slowLog, err := rhc.client.SlowLogGet(slowLogCtx, count).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get slow log: %w", err)
	}
	
	var queries []map[string]interface{}
	for _, entry := range slowLog {
		queryInfo := map[string]interface{}{
			"id":        entry.ID,
			"timestamp": entry.Time.Unix(),
			"duration":  entry.Duration.String(),
			"command":   strings.Join(entry.Args, " "),
		}
		queries = append(queries, queryInfo)
	}
	
	return queries, nil
}

// GetDetailedStats returns comprehensive Redis statistics
func (rhc *RedisHealthChecker) GetDetailedStats(ctx context.Context) (map[string]interface{}, error) {
	statsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	
	result := rhc.Check(statsCtx)
	
	stats := map[string]interface{}{
		"health_status": string(result.Status),
		"health_message": result.Message,
		"check_duration": result.Duration.String(),
		"metadata": result.Metadata,
	}
	
	// Add slow queries
	if slowQueries, err := rhc.GetSlowQueries(statsCtx, 5); err == nil {
		stats["slow_queries"] = slowQueries
	}
	
	return stats, nil
}