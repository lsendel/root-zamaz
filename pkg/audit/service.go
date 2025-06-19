// Package audit provides centralized audit logging functionality
package audit

import (
	"context"
	"encoding/json"
	"time"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
)

// Service provides audit logging functionality
type Service struct {
	db  *gorm.DB
	obs *observability.Observability
}

// LogEntry represents an audit log entry
type LogEntry struct {
	UserID    string
	Action    string
	Resource  string
	Details   map[string]interface{}
	Success   bool
	Context   *fiber.Ctx
}

// NewService creates a new audit service
func NewService(db *gorm.DB, obs *observability.Observability) *Service {
	return &Service{db: db, obs: obs}
}

// LogEvent logs an audit event
func (s *Service) LogEvent(entry LogEntry) {
	detailsJSON, _ := json.Marshal(entry.Details)
	
	var userIDPtr *uuid.UUID
	if entry.UserID != "" {
		if parsed, err := uuid.Parse(entry.UserID); err == nil {
			userIDPtr = &parsed
		}
	}
	
	auditLog := models.AuditLog{
		UserID:    userIDPtr,
		Action:    entry.Action,
		Resource:  entry.Resource,
		Details:   string(detailsJSON),
		IPAddress: entry.Context.IP(),
		UserAgent: entry.Context.Get("User-Agent"),
		RequestID: entry.Context.Get("X-Correlation-ID"),
		Success:   entry.Success,
	}
	
	// Save audit log (non-blocking) with timeout protection
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		if err := s.db.WithContext(ctx).Create(&auditLog).Error; err != nil {
			s.obs.Logger.Error().Err(err).Msg("Failed to save audit log")
		}
	}()
}

// LogAuthEvent logs authentication-related events
func (s *Service) LogAuthEvent(ctx *fiber.Ctx, userID, event string, success bool, details map[string]interface{}) {
	s.LogEvent(LogEntry{
		UserID:   userID,
		Action:   event,
		Resource: "auth",
		Details:  details,
		Success:  success,
		Context:  ctx,
	})
}

// LogDeviceEvent logs device-related events
func (s *Service) LogDeviceEvent(ctx *fiber.Ctx, userID, deviceID, event string, success bool, details map[string]interface{}) {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["device_id"] = deviceID
	
	s.LogEvent(LogEntry{
		UserID:   userID,
		Action:   event,
		Resource: "device", 
		Details:  details,
		Success:  success,
		Context:  ctx,
	})
}

// LogAdminEvent logs admin-related events
func (s *Service) LogAdminEvent(ctx *fiber.Ctx, userID, event string, success bool, details map[string]interface{}) {
	s.LogEvent(LogEntry{
		UserID:   userID,
		Action:   event,
		Resource: "admin",
		Details:  details,
		Success:  success,
		Context:  ctx,
	})
}

// LogSystemEvent logs system-related events
func (s *Service) LogSystemEvent(ctx *fiber.Ctx, userID, event string, success bool, details map[string]interface{}) {
	s.LogEvent(LogEntry{
		UserID:   userID,
		Action:   event,
		Resource: "system",
		Details:  details,
		Success:  success,
		Context:  ctx,
	})
}