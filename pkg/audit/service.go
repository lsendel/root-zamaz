// Package audit provides centralized audit logging functionality
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
	"time"
)

// Service provides audit logging functionality with compliance integration
type Service struct {
	db                *gorm.DB
	obs               *observability.Observability
	complianceService *ComplianceService
	gdprService       *GDPRService
	reportingService  *ReportingService
}

// LogEntry represents an audit log entry
type LogEntry struct {
	UserID        string
	Action        string
	Resource      string
	Details       map[string]interface{}
	Success       bool
	Context       *fiber.Ctx
	ComplianceTag string
	Retention     time.Duration
}

// NewService creates a new audit service with compliance integration
func NewService(db *gorm.DB, obs *observability.Observability) *Service {
	service := &Service{
		db:  db,
		obs: obs,
	}

	// Initialize compliance services
	service.complianceService = NewComplianceService(db, obs)
	service.gdprService = NewGDPRService(db, obs, service.complianceService)
	service.reportingService = NewReportingService(db, obs)

	return service
}

// GetComplianceService returns the compliance service
func (s *Service) GetComplianceService() *ComplianceService {
	return s.complianceService
}

// GetGDPRService returns the GDPR service
func (s *Service) GetGDPRService() *GDPRService {
	return s.gdprService
}

// GetReportingService returns the reporting service
func (s *Service) GetReportingService() *ReportingService {
	return s.reportingService
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

	var retainUntil *time.Time
	if entry.Retention > 0 {
		t := time.Now().Add(entry.Retention)
		retainUntil = &t
	}

	auditLog := models.AuditLog{
		UserID:        userIDPtr,
		Action:        entry.Action,
		Resource:      entry.Resource,
		Details:       string(detailsJSON),
		IPAddress:     entry.Context.IP(),
		UserAgent:     entry.Context.Get("User-Agent"),
		RequestID:     entry.Context.Get("X-Correlation-ID"),
		Success:       entry.Success,
		ComplianceTag: entry.ComplianceTag,
		RetainUntil:   retainUntil,
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

// LogComplianceEvent logs compliance-aware audit events
func (s *Service) LogComplianceEvent(ctx context.Context, entry ComplianceLogEntry) error {
	if s.complianceService != nil {
		return s.complianceService.LogComplianceEvent(ctx, entry)
	}
	return nil
}

// LogGDPREvent logs GDPR-specific events
func (s *Service) LogGDPREvent(ctx context.Context, userID, action, dataSubject string, legalBasis LegalBasis, details map[string]interface{}) error {
	if s.complianceService != nil {
		return s.complianceService.LogGDPREvent(ctx, userID, action, dataSubject, legalBasis, details)
	}
	return nil
}

// LogDataAccess logs data access events with compliance context
func (s *Service) LogDataAccess(ctx context.Context, userID, resource string, classification DataClassification, dataSubjects []string, purpose string) error {
	if s.complianceService != nil {
		return s.complianceService.LogDataAccess(ctx, userID, resource, classification, dataSubjects, purpose)
	}
	return nil
}

// LogSecurityEvent logs security events with compliance context
func (s *Service) LogSecurityEvent(ctx context.Context, userID, action string, severity int, controls []string, details map[string]interface{}) error {
	if s.complianceService != nil {
		return s.complianceService.LogSecurityEvent(ctx, userID, action, severity, controls, details)
	}
	return nil
}

// ProcessDataSubjectRequest processes GDPR data subject requests
func (s *Service) ProcessDataSubjectRequest(ctx context.Context, requestType DataSubjectRequestType, dataSubject, requestorID string, details map[string]interface{}) (*models.DataSubjectRequest, error) {
	if s.gdprService != nil {
		return s.gdprService.ProcessDataSubjectRequest(ctx, requestType, dataSubject, requestorID, details)
	}
	return nil, fmt.Errorf("GDPR service not available")
}

// GenerateComplianceDashboard generates compliance dashboard
func (s *Service) GenerateComplianceDashboard(ctx context.Context, period Period) (*ComplianceDashboard, error) {
	if s.reportingService != nil {
		return s.reportingService.GenerateComplianceDashboard(ctx, period)
	}
	return nil, fmt.Errorf("reporting service not available")
}
