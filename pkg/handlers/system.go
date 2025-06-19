// Package handlers provides system health and monitoring handlers for the MVP Zero Trust Auth system.
package handlers

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"

	"mvp.local/pkg/auth"
	"mvp.local/pkg/database"
	"mvp.local/pkg/messaging"
	"mvp.local/pkg/observability"
)

// SystemHandler handles system-related HTTP requests
type SystemHandler struct {
	db           *database.Database
	redisClient  *redis.Client
	natsClient   *messaging.Client
	authzService auth.AuthorizationInterface
	obs          *observability.Observability
}

// SystemHandlerInterface defines the contract for system handlers
type SystemHandlerInterface interface {
	Health(c *fiber.Ctx) error
	SystemHealth(c *fiber.Ctx) error
	DatabaseStats(c *fiber.Ctx) error
	Metrics(c *fiber.Ctx) error
}

// HealthResponse represents a health check response
type HealthResponse struct {
	Status    string                 `json:"status"`
	Timestamp time.Time              `json:"timestamp"`
	Services  map[string]ServiceInfo `json:"services"`
}

// ServiceInfo represents service health information
type ServiceInfo struct {
	Status       string                 `json:"status"`
	LastCheck    time.Time              `json:"last_check"`
	ResponseTime string                 `json:"response_time"`
	Details      map[string]interface{} `json:"details,omitempty"`
}

// SystemStatsResponse represents system statistics
type SystemStatsResponse struct {
	Database map[string]interface{} `json:"database"`
	Redis    map[string]interface{} `json:"redis"`
	Memory   map[string]interface{} `json:"memory"`
	Uptime   string                 `json:"uptime"`
}

// NewSystemHandler creates a new system handler
func NewSystemHandler(
	db *database.Database,
	redisClient *redis.Client,
	natsClient *messaging.Client,
	authzService auth.AuthorizationInterface,
	obs *observability.Observability,
) *SystemHandler {
	return &SystemHandler{
		db:           db,
		redisClient:  redisClient,
		natsClient:   natsClient,
		authzService: authzService,
		obs:          obs,
	}
}

// Health provides a basic health check endpoint
// @Summary Health check
// @Description Get the health status of the system
// @Tags system
// @Accept json
// @Produce json
// @Success 200 {object} HealthResponse "System is healthy"
// @Success 503 {object} HealthResponse "System is degraded or unhealthy"
// @Router /health [get]
func (h *SystemHandler) Health(c *fiber.Ctx) error {
	start := time.Now()

	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Services:  make(map[string]ServiceInfo),
	}

	// Check database
	dbStart := time.Now()
	dbStatus := "healthy"
	var dbDetails map[string]interface{}

	if err := h.db.Health(); err != nil {
		dbStatus = "unhealthy"
		dbDetails = map[string]interface{}{
			"error": err.Error(),
		}
		response.Status = "degraded"
	}

	response.Services["database"] = ServiceInfo{
		Status:       dbStatus,
		LastCheck:    time.Now(),
		ResponseTime: time.Since(dbStart).String(),
		Details:      dbDetails,
	}

	// Check Redis if available
	if h.redisClient != nil {
		redisStart := time.Now()
		redisStatus := "healthy"
		var redisDetails map[string]interface{}

		ctx := c.Context()
		if err := h.redisClient.Ping(ctx).Err(); err != nil {
			redisStatus = "unhealthy"
			redisDetails = map[string]interface{}{
				"error": err.Error(),
			}
			if response.Status == "healthy" {
				response.Status = "degraded"
			}
		}

		response.Services["redis"] = ServiceInfo{
			Status:       redisStatus,
			LastCheck:    time.Now(),
			ResponseTime: time.Since(redisStart).String(),
			Details:      redisDetails,
		}
	}

	// Overall health check took too long
	if time.Since(start) > 5*time.Second {
		response.Status = "degraded"
	}

	statusCode := fiber.StatusOK
	if response.Status == "degraded" {
		statusCode = fiber.StatusServiceUnavailable
	} else if response.Status == "unhealthy" {
		statusCode = fiber.StatusServiceUnavailable
	}

	return c.Status(statusCode).JSON(response)
}

// SystemHealth provides detailed system health information (requires authentication)
// @Summary Detailed system health
// @Description Get detailed health information about all system components
// @Tags system
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} HealthResponse "Detailed system health"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden - insufficient permissions"
// @Router /system/health [get]
func (h *SystemHandler) SystemHealth(c *fiber.Ctx) error {
	userID, err := auth.GetCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Not authenticated",
		})
	}

	// Check permission
	if err := h.authzService.CheckPermission(userID, "system", "read"); err != nil {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":   "Forbidden",
			"message": "Insufficient permissions",
		})
	}

	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Services:  make(map[string]ServiceInfo),
	}

	// Database health with details
	dbStart := time.Now()
	dbStatus := "healthy"
	var dbDetails map[string]interface{}

	if err := h.db.Health(); err != nil {
		dbStatus = "unhealthy"
		dbDetails = map[string]interface{}{
			"error": err.Error(),
		}
		response.Status = "degraded"
	} else {
		// Get database stats
		if stats, err := h.db.GetStats(); err == nil {
			dbDetails = stats
		}
	}

	response.Services["database"] = ServiceInfo{
		Status:       dbStatus,
		LastCheck:    time.Now(),
		ResponseTime: time.Since(dbStart).String(),
		Details:      dbDetails,
	}

	// Redis health with details
	if h.redisClient != nil {
		redisStart := time.Now()
		redisStatus := "healthy"
		var redisDetails map[string]interface{}

		ctx := c.Context()
		if err := h.redisClient.Ping(ctx).Err(); err != nil {
			redisStatus = "unhealthy"
			redisDetails = map[string]interface{}{
				"error": err.Error(),
			}
			if response.Status == "healthy" {
				response.Status = "degraded"
			}
		} else {
			// Get Redis info
			if info, err := h.redisClient.Info(ctx).Result(); err == nil {
				dbDetails = map[string]interface{}{
					"info": info[:500], // Truncate for brevity
				}
			}
		}

		response.Services["redis"] = ServiceInfo{
			Status:       redisStatus,
			LastCheck:    time.Now(),
			ResponseTime: time.Since(redisStart).String(),
			Details:      redisDetails,
		}
	}

	// NATS health check
	if h.natsClient != nil {
		natsStart := time.Now()
		natsStatus := "healthy"
		var natsDetails map[string]interface{}

		if err := h.natsClient.Health(); err != nil {
			natsStatus = "unhealthy"
			natsDetails = map[string]interface{}{
				"error": err.Error(),
			}
			if response.Status == "healthy" {
				response.Status = "degraded"
			}
		} else {
			natsDetails = h.natsClient.Stats()
		}

		response.Services["nats"] = ServiceInfo{
			Status:       natsStatus,
			LastCheck:    time.Now(),
			ResponseTime: time.Since(natsStart).String(),
			Details:      natsDetails,
		}
	}

	// SPIRE health (mock for now)
	response.Services["spire"] = ServiceInfo{
		Status:       "degraded",
		LastCheck:    time.Now(),
		ResponseTime: "5ms",
		Details: map[string]interface{}{
			"note": "SPIRE integration not fully implemented",
		},
	}

	return c.JSON(response)
}

// DatabaseStats provides detailed database statistics (admin only)
func (h *SystemHandler) DatabaseStats(c *fiber.Ctx) error {
	userID, err := auth.GetCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Not authenticated",
		})
	}

	// Check admin permission
	if err := h.authzService.CheckPermission(userID, "system", "admin"); err != nil {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":   "Forbidden",
			"message": "Admin permissions required",
		})
	}

	stats, err := h.db.GetStats()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to get database stats",
		})
	}

	// Add table counts
	gormDB := h.db.GetDB()
	tableCounts := make(map[string]int64)

	tables := []string{"users", "user_sessions", "device_attestations", "roles", "permissions", "audit_logs"}
	for _, table := range tables {
		var count int64
		if err := gormDB.Table(table).Count(&count).Error; err == nil {
			tableCounts[table] = count
		} else {
			h.obs.Logger.Warn().Err(err).Str("table", table).Msg("Failed to get count for table in DatabaseStats")
		}
	}

	response := map[string]interface{}{
		"connection_stats": stats,
		"table_counts":     tableCounts,
		"timestamp":        time.Now(),
	}

	return c.JSON(response)
}

// Metrics returns Prometheus metrics (if observability is enabled)
func (h *SystemHandler) Metrics(c *fiber.Ctx) error {
	// This would typically serve Prometheus metrics
	// For now, return a simple response
	return c.SendString(`# HELP mvp_auth_requests_total Total number of requests
# TYPE mvp_auth_requests_total counter
mvp_auth_requests_total{method="GET",status="200"} 100
mvp_auth_requests_total{method="POST",status="200"} 50
mvp_auth_requests_total{method="POST",status="400"} 5

# HELP mvp_auth_users_total Total number of users
# TYPE mvp_auth_users_total gauge
mvp_auth_users_total 10

# HELP mvp_auth_devices_total Total number of device attestations
# TYPE mvp_auth_devices_total gauge
mvp_auth_devices_total 25

# HELP mvp_auth_sessions_active Active user sessions
# TYPE mvp_auth_sessions_active gauge
mvp_auth_sessions_active 8
`)
}
