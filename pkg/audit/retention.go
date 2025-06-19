// Package audit provides automated data retention and lifecycle management
package audit

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
)

// RetentionManager handles automated data retention and lifecycle management
type RetentionManager struct {
	db                *gorm.DB
	obs               *observability.Observability
	retentionPolicies map[RetentionCategory]time.Duration
	purgeEnabled      bool
	archiveEnabled    bool
}

// RetentionStats provides statistics about retention operations
type RetentionStats struct {
	TotalRecords     int64     `json:"total_records"`
	ArchivedRecords  int64     `json:"archived_records"`
	PurgedRecords    int64     `json:"purged_records"`
	LastArchive      time.Time `json:"last_archive"`
	LastPurge        time.Time `json:"last_purge"`
	NextScheduled    time.Time `json:"next_scheduled"`
}

// RetentionOperation represents a retention operation result
type RetentionOperation struct {
	Category        RetentionCategory `json:"category"`
	Operation       string            `json:"operation"` // "archive" or "purge"
	RecordsAffected int64             `json:"records_affected"`
	StartTime       time.Time         `json:"start_time"`
	EndTime         time.Time         `json:"end_time"`
	Duration        time.Duration     `json:"duration"`
	Errors          []string          `json:"errors,omitempty"`
}

// NewRetentionManager creates a new retention manager
func NewRetentionManager(db *gorm.DB, obs *observability.Observability, policies map[RetentionCategory]time.Duration) *RetentionManager {
	return &RetentionManager{
		db:                db,
		obs:               obs,
		retentionPolicies: policies,
		purgeEnabled:      true,
		archiveEnabled:    true,
	}
}

// SetArchiveEnabled enables or disables archiving
func (rm *RetentionManager) SetArchiveEnabled(enabled bool) {
	rm.archiveEnabled = enabled
}

// SetPurgeEnabled enables or disables purging (for safety)
func (rm *RetentionManager) SetPurgeEnabled(enabled bool) {
	rm.purgeEnabled = enabled
}

// RunRetentionCycle runs a complete retention cycle (archive + purge)
func (rm *RetentionManager) RunRetentionCycle(ctx context.Context) ([]RetentionOperation, error) {
	rm.obs.Logger.Info().Msg("Starting retention cycle")
	
	var operations []RetentionOperation
	
	// Run archive operations first
	if rm.archiveEnabled {
		archiveOps, err := rm.RunArchiveOperations(ctx)
		if err != nil {
			rm.obs.Logger.Error().Err(err).Msg("Archive operations failed")
		}
		operations = append(operations, archiveOps...)
	}
	
	// Run purge operations
	if rm.purgeEnabled {
		purgeOps, err := rm.RunPurgeOperations(ctx)
		if err != nil {
			rm.obs.Logger.Error().Err(err).Msg("Purge operations failed")
		}
		operations = append(operations, purgeOps...)
	}
	
	rm.obs.Logger.Info().
		Int("total_operations", len(operations)).
		Msg("Retention cycle completed")
	
	return operations, nil
}

// RunArchiveOperations archives records that are ready for archival
func (rm *RetentionManager) RunArchiveOperations(ctx context.Context) ([]RetentionOperation, error) {
	var operations []RetentionOperation
	now := time.Now()
	
	// Archive compliance audit logs
	archiveCount, err := rm.archiveComplianceAuditLogs(ctx, now)
	if err != nil {
		rm.obs.Logger.Error().Err(err).Msg("Failed to archive compliance audit logs")
	} else {
		operations = append(operations, RetentionOperation{
			Category:        "compliance_audit_logs",
			Operation:       "archive",
			RecordsAffected: archiveCount,
			StartTime:       now,
			EndTime:         time.Now(),
			Duration:        time.Since(now),
		})
	}
	
	// Archive regular audit logs
	regularArchiveCount, err := rm.archiveRegularAuditLogs(ctx, now)
	if err != nil {
		rm.obs.Logger.Error().Err(err).Msg("Failed to archive regular audit logs")
	} else {
		operations = append(operations, RetentionOperation{
			Category:        "audit_logs",
			Operation:       "archive",
			RecordsAffected: regularArchiveCount,
			StartTime:       now,
			EndTime:         time.Now(),
			Duration:        time.Since(now),
		})
	}
	
	return operations, nil
}

// RunPurgeOperations purges records that have exceeded their retention period
func (rm *RetentionManager) RunPurgeOperations(ctx context.Context) ([]RetentionOperation, error) {
	var operations []RetentionOperation
	now := time.Now()
	
	// Purge compliance audit logs
	purgeCount, err := rm.purgeComplianceAuditLogs(ctx, now)
	if err != nil {
		rm.obs.Logger.Error().Err(err).Msg("Failed to purge compliance audit logs")
	} else {
		operations = append(operations, RetentionOperation{
			Category:        "compliance_audit_logs",
			Operation:       "purge",
			RecordsAffected: purgeCount,
			StartTime:       now,
			EndTime:         time.Now(),
			Duration:        time.Since(now),
		})
	}
	
	// Purge regular audit logs
	regularPurgeCount, err := rm.purgeRegularAuditLogs(ctx, now)
	if err != nil {
		rm.obs.Logger.Error().Err(err).Msg("Failed to purge regular audit logs")
	} else {
		operations = append(operations, RetentionOperation{
			Category:        "audit_logs",
			Operation:       "purge",
			RecordsAffected: regularPurgeCount,
			StartTime:       now,
			EndTime:         time.Now(),
			Duration:        time.Since(now),
		})
	}
	
	// Purge login attempts
	loginPurgeCount, err := rm.purgeLoginAttempts(ctx, now)
	if err != nil {
		rm.obs.Logger.Error().Err(err).Msg("Failed to purge login attempts")
	} else {
		operations = append(operations, RetentionOperation{
			Category:        "login_attempts",
			Operation:       "purge",
			RecordsAffected: loginPurgeCount,
			StartTime:       now,
			EndTime:         time.Now(),
			Duration:        time.Since(now),
		})
	}
	
	return operations, nil
}

// archiveComplianceAuditLogs archives compliance audit logs ready for archival
func (rm *RetentionManager) archiveComplianceAuditLogs(ctx context.Context, now time.Time) (int64, error) {
	// Find records ready for archive
	var count int64
	result := rm.db.WithContext(ctx).
		Model(&models.ComplianceAuditLog{}).
		Where("archive_date <= ? AND archived = false", now).
		Count(&count)
	
	if result.Error != nil {
		return 0, fmt.Errorf("failed to count records for archival: %w", result.Error)
	}
	
	if count == 0 {
		return 0, nil
	}
	
	// Update records to archived status
	result = rm.db.WithContext(ctx).
		Model(&models.ComplianceAuditLog{}).
		Where("archive_date <= ? AND archived = false", now).
		Updates(map[string]interface{}{
			"archived":    true,
			"archived_at": now,
		})
	
	if result.Error != nil {
		return 0, fmt.Errorf("failed to archive compliance audit logs: %w", result.Error)
	}
	
	rm.obs.Logger.Info().
		Int64("archived_count", result.RowsAffected).
		Msg("Archived compliance audit logs")
	
	return result.RowsAffected, nil
}

// archiveRegularAuditLogs archives regular audit logs ready for archival
func (rm *RetentionManager) archiveRegularAuditLogs(ctx context.Context, now time.Time) (int64, error) {
	// Archive logs older than 1 year by default
	archiveThreshold := now.AddDate(-1, 0, 0)
	
	var count int64
	result := rm.db.WithContext(ctx).
		Model(&models.AuditLog{}).
		Where("created_at <= ? AND retain_until IS NULL", archiveThreshold).
		Count(&count)
	
	if result.Error != nil {
		return 0, fmt.Errorf("failed to count audit logs for archival: %w", result.Error)
	}
	
	if count == 0 {
		return 0, nil
	}
	
	// For regular audit logs, we'll add a retention date if missing
	retainUntil := now.Add(rm.retentionPolicies[RetentionCategoryLongTerm])
	result = rm.db.WithContext(ctx).
		Model(&models.AuditLog{}).
		Where("created_at <= ? AND retain_until IS NULL", archiveThreshold).
		Update("retain_until", retainUntil)
	
	if result.Error != nil {
		return 0, fmt.Errorf("failed to set retention for audit logs: %w", result.Error)
	}
	
	rm.obs.Logger.Info().
		Int64("processed_count", result.RowsAffected).
		Msg("Set retention for regular audit logs")
	
	return result.RowsAffected, nil
}

// purgeComplianceAuditLogs purges compliance audit logs that have exceeded retention
func (rm *RetentionManager) purgeComplianceAuditLogs(ctx context.Context, now time.Time) (int64, error) {
	// Find records ready for purge
	var count int64
	result := rm.db.WithContext(ctx).
		Model(&models.ComplianceAuditLog{}).
		Where("purge_date <= ?", now).
		Count(&count)
	
	if result.Error != nil {
		return 0, fmt.Errorf("failed to count records for purge: %w", result.Error)
	}
	
	if count == 0 {
		return 0, nil
	}
	
	// Delete records
	result = rm.db.WithContext(ctx).
		Where("purge_date <= ?", now).
		Delete(&models.ComplianceAuditLog{})
	
	if result.Error != nil {
		return 0, fmt.Errorf("failed to purge compliance audit logs: %w", result.Error)
	}
	
	rm.obs.Logger.Info().
		Int64("purged_count", result.RowsAffected).
		Msg("Purged compliance audit logs")
	
	return result.RowsAffected, nil
}

// purgeRegularAuditLogs purges regular audit logs that have exceeded retention
func (rm *RetentionManager) purgeRegularAuditLogs(ctx context.Context, now time.Time) (int64, error) {
	var count int64
	result := rm.db.WithContext(ctx).
		Model(&models.AuditLog{}).
		Where("retain_until <= ?", now).
		Count(&count)
	
	if result.Error != nil {
		return 0, fmt.Errorf("failed to count audit logs for purge: %w", result.Error)
	}
	
	if count == 0 {
		return 0, nil
	}
	
	// Delete records
	result = rm.db.WithContext(ctx).
		Where("retain_until <= ?", now).
		Delete(&models.AuditLog{})
	
	if result.Error != nil {
		return 0, fmt.Errorf("failed to purge audit logs: %w", result.Error)
	}
	
	rm.obs.Logger.Info().
		Int64("purged_count", result.RowsAffected).
		Msg("Purged regular audit logs")
	
	return result.RowsAffected, nil
}

// purgeLoginAttempts purges old login attempts
func (rm *RetentionManager) purgeLoginAttempts(ctx context.Context, now time.Time) (int64, error) {
	// Keep login attempts for 90 days
	purgeThreshold := now.AddDate(0, 0, -90)
	
	var count int64
	result := rm.db.WithContext(ctx).
		Model(&models.LoginAttempt{}).
		Where("created_at <= ?", purgeThreshold).
		Count(&count)
	
	if result.Error != nil {
		return 0, fmt.Errorf("failed to count login attempts for purge: %w", result.Error)
	}
	
	if count == 0 {
		return 0, nil
	}
	
	// Delete old login attempts
	result = rm.db.WithContext(ctx).
		Where("created_at <= ?", purgeThreshold).
		Delete(&models.LoginAttempt{})
	
	if result.Error != nil {
		return 0, fmt.Errorf("failed to purge login attempts: %w", result.Error)
	}
	
	rm.obs.Logger.Info().
		Int64("purged_count", result.RowsAffected).
		Msg("Purged login attempts")
	
	return result.RowsAffected, nil
}

// GetRetentionStats returns statistics about retention operations
func (rm *RetentionManager) GetRetentionStats(ctx context.Context) (*RetentionStats, error) {
	stats := &RetentionStats{}
	
	// Count total compliance audit records
	rm.db.WithContext(ctx).Model(&models.ComplianceAuditLog{}).Count(&stats.TotalRecords)
	
	// Count archived records
	rm.db.WithContext(ctx).Model(&models.ComplianceAuditLog{}).Where("archived = true").Count(&stats.ArchivedRecords)
	
	// Get last archive timestamp
	var lastArchived models.ComplianceAuditLog
	if err := rm.db.WithContext(ctx).
		Where("archived = true").
		Order("archived_at DESC").
		First(&lastArchived).Error; err == nil && lastArchived.ArchivedAt != nil {
		stats.LastArchive = *lastArchived.ArchivedAt
	}
	
	// Calculate next scheduled operation (daily at 2 AM)
	now := time.Now()
	nextRun := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())
	if now.After(nextRun) {
		nextRun = nextRun.AddDate(0, 0, 1)
	}
	stats.NextScheduled = nextRun
	
	return stats, nil
}

// ScheduleRetentionJobs sets up scheduled retention operations
func (rm *RetentionManager) ScheduleRetentionJobs(ctx context.Context) {
	// This would typically integrate with a job scheduler
	// For now, we'll just log that scheduling would occur
	rm.obs.Logger.Info().Msg("Retention job scheduling would be configured here")
	
	// Example: Run daily at 2 AM
	// This would be implemented with a proper job scheduler in production
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				if now.Hour() == 2 { // Run at 2 AM
					if _, err := rm.RunRetentionCycle(ctx); err != nil {
						rm.obs.Logger.Error().Err(err).Msg("Scheduled retention cycle failed")
					}
				}
			}
		}
	}()
}

// ValidateRetentionPolicies validates that retention policies are properly configured
func (rm *RetentionManager) ValidateRetentionPolicies() error {
	required := []RetentionCategory{
		RetentionCategoryShortTerm,
		RetentionCategoryMediumTerm,
		RetentionCategoryLongTerm,
		RetentionCategoryCompliance,
	}
	
	for _, category := range required {
		if _, exists := rm.retentionPolicies[category]; !exists {
			return fmt.Errorf("missing retention policy for category: %s", category)
		}
	}
	
	return nil
}