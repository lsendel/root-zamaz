// Package middleware provides framework-agnostic middleware for observability
package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// MetricsCollector interface for middleware metrics
type MetricsCollector interface {
	IncrementCounter(name string, labels map[string]string)
	RecordHistogram(name string, value float64, labels map[string]string)
	SetGauge(name string, value float64, labels map[string]string)
	RecordDuration(name string, duration time.Duration, labels map[string]string)
	RecordHTTPRequest(method, endpoint string, statusCode int, duration time.Duration)
	RecordError(errorType, component string)
}

// Logger interface for middleware logging
type Logger interface {
	Debug(msg string, keysAndValues ...interface{})
	Info(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	With(keysAndValues ...interface{}) Logger
}

// GinMetricsMiddleware creates a Gin middleware for metrics collection
func GinMetricsMiddleware(metrics MetricsCollector) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		
		// Track in-flight requests
		metrics.SetGauge("http_requests_in_flight", 1, map[string]string{
			"method": c.Request.Method,
			"path":   c.FullPath(),
		})
		
		// Process request
		c.Next()
		
		duration := time.Since(start)
		
		// Record metrics
		metrics.RecordHTTPRequest(
			c.Request.Method,
			c.FullPath(),
			c.Writer.Status(),
			duration,
		)
		
		// Record response size if available
		if size := c.Writer.Size(); size > 0 {
			metrics.RecordHistogram("response_size_bytes", float64(size), map[string]string{
				"method":   c.Request.Method,
				"endpoint": c.FullPath(),
			})
		}
		
		// Record errors if any
		if len(c.Errors) > 0 {
			for _, err := range c.Errors {
				metrics.RecordError(err.Type.String(), "gin_middleware")
			}
		}
		
		// Update in-flight counter
		metrics.SetGauge("http_requests_in_flight", -1, map[string]string{
			"method": c.Request.Method,
			"path":   c.FullPath(),
		})
	}
}

// GinLoggingMiddleware creates a Gin middleware for structured logging
func GinLoggingMiddleware(logger Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		
		// Process request
		c.Next()
		
		duration := time.Since(start)
		
		// Log request details
		fields := []interface{}{
			"method", c.Request.Method,
			"path", path,
			"status", c.Writer.Status(),
			"duration", duration.String(),
			"ip", c.ClientIP(),
			"user_agent", c.Request.UserAgent(),
			"size", c.Writer.Size(),
		}
		
		// Add user context if available
		if userID, exists := c.Get("user_id"); exists {
			fields = append(fields, "user_id", userID)
		}
		
		if trustScore, exists := c.Get("trust_score"); exists {
			fields = append(fields, "trust_score", trustScore)
		}
		
		// Log based on status code
		status := c.Writer.Status()
		if status >= 500 {
			logger.Error("HTTP request completed", fields...)
		} else if status >= 400 {
			logger.Warn("HTTP request completed", fields...)
		} else {
			logger.Info("HTTP request completed", fields...)
		}
		
		// Log errors if any
		if len(c.Errors) > 0 {
			for _, err := range c.Errors {
				logger.Error("Request error", 
					"error", err.Error(),
					"type", err.Type.String(),
					"path", path,
					"method", c.Request.Method,
				)
			}
		}
	}
}

// GinZeroTrustMiddleware creates middleware for Zero Trust metrics
func GinZeroTrustMiddleware(metrics MetricsCollector) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		
		// Record Zero Trust specific metrics
		if userID, exists := c.Get("user_id"); exists {
			metrics.IncrementCounter("user_requests_total", map[string]string{
				"user_id":  userID.(string),
				"endpoint": c.FullPath(),
				"method":   c.Request.Method,
			})
		}
		
		if trustScore, exists := c.Get("trust_score"); exists {
			if score, ok := trustScore.(int); ok {
				var trustLevel string
				switch {
				case score >= 80:
					trustLevel = "high"
				case score >= 60:
					trustLevel = "medium"
				default:
					trustLevel = "low"
				}
				
				metrics.IncrementCounter("requests_by_trust_level", map[string]string{
					"trust_level": trustLevel,
					"endpoint":    c.FullPath(),
					"status":      strconv.Itoa(c.Writer.Status()),
				})
			}
		}
		
		// Track authentication events
		if authMethod, exists := c.Get("auth_method"); exists {
			success := c.Writer.Status() < 400
			metrics.IncrementCounter("auth_events_total", map[string]string{
				"method":  authMethod.(string),
				"success": strconv.FormatBool(success),
				"endpoint": c.FullPath(),
			})
		}
	}
}

// GinCORSMiddleware creates CORS middleware with observability
func GinCORSMiddleware(metrics MetricsCollector, logger Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		// Set CORS headers
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Requested-With")
		c.Header("Access-Control-Max-Age", "86400")
		
		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			metrics.IncrementCounter("cors_preflight_total", map[string]string{
				"origin": origin,
			})
			logger.Debug("CORS preflight request", "origin", origin)
			c.AbortWithStatus(204)
			return
		}
		
		// Track CORS requests
		if origin != "" {
			metrics.IncrementCounter("cors_requests_total", map[string]string{
				"origin": origin,
				"method": c.Request.Method,
			})
		}
		
		c.Next()
	}
}

// GinRecoveryMiddleware creates recovery middleware with observability
func GinRecoveryMiddleware(metrics MetricsCollector, logger Logger) gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		// Record panic metric
		metrics.IncrementCounter("panics_total", map[string]string{
			"endpoint": c.FullPath(),
			"method":   c.Request.Method,
		})
		
		// Log panic details
		logger.Error("Panic recovered",
			"error", recovered,
			"path", c.Request.URL.Path,
			"method", c.Request.Method,
			"ip", c.ClientIP(),
		)
		
		// Return error response
		c.JSON(500, gin.H{
			"error":   "Internal server error",
			"code":    "INTERNAL_ERROR",
			"message": "An unexpected error occurred",
		})
	})
}