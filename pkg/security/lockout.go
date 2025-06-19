// Package security provides security-related services for brute force protection,
// account lockout mechanisms, and suspicious activity detection.
package security

import (
	"fmt"
	"time"

	"gorm.io/gorm"

	"mvp.local/pkg/config"
	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
)


// LockoutService handles account lockout and brute force protection
type LockoutService struct {
	db     *gorm.DB
	obs    *observability.Observability
	config *config.LockoutConfig
}

// LockoutServiceInterface defines the contract for lockout services
type LockoutServiceInterface interface {
	// Account lockout methods
	CheckAccountLockout(username string) (*LockoutStatus, error)
	RecordFailedAttempt(username, ipAddress, userAgent, requestID, reason string) error
	RecordSuccessfulAttempt(username, ipAddress, userAgent, requestID string) error
	UnlockAccount(username string) error
	
	// IP-based protection
	CheckIPLockout(ipAddress string) (*IPLockoutStatus, error)
	
	// Progressive delay
	CalculateDelay(attemptCount int) time.Duration
	
	// Suspicious activity detection
	DetectSuspiciousActivity(username, ipAddress string) (*SuspiciousActivityReport, error)
}

// LockoutStatus represents the current lockout status of an account
type LockoutStatus struct {
	IsLocked           bool
	LockedAt           *time.Time
	LockedUntil        *time.Time
	FailedAttempts     int
	RemainingLockTime  time.Duration
	NextAttemptDelay   time.Duration
	RequiresDelay      bool
}

// IPLockoutStatus represents the lockout status of an IP address
type IPLockoutStatus struct {
	IsLocked          bool
	FailedAttempts    int
	RemainingLockTime time.Duration
}

// SuspiciousActivityReport contains details about suspicious activity
type SuspiciousActivityReport struct {
	IsSuspicious       bool
	FailedAttempts     int
	UniqueIPCount      int
	RecentAttemptCount int
	TimeWindow         time.Duration
	Reasons            []string
}

// NewLockoutService creates a new lockout service
func NewLockoutService(db *gorm.DB, obs *observability.Observability, lockoutConfig *config.LockoutConfig) *LockoutService {
	if lockoutConfig == nil {
		defaultConfig := config.LockoutConfig{
			MaxFailedAttempts:   5,
			LockoutDuration:     15 * time.Minute,
			ResetWindow:         1 * time.Hour,
			ProgressiveDelay:    true,
			BaseDelay:          1 * time.Second,
			MaxDelay:           30 * time.Second,
			EnableNotifications: true,
			IPLockoutEnabled:   true,
			IPLockoutThreshold: 10,
			IPLockoutDuration:  1 * time.Hour,
		}
		lockoutConfig = &defaultConfig
	}
	
	return &LockoutService{
		db:     db,
		obs:    obs,
		config: lockoutConfig,
	}
}

// CheckAccountLockout checks if an account is currently locked
func (s *LockoutService) CheckAccountLockout(username string) (*LockoutStatus, error) {
	var user models.User
	err := s.db.Where("username = ? OR email = ?", username, username).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			// User doesn't exist, but still apply delay to prevent user enumeration
			return &LockoutStatus{
				IsLocked:         false,
				RequiresDelay:    true,
				NextAttemptDelay: s.config.BaseDelay,
			}, nil
		}
		return nil, fmt.Errorf("failed to check user: %w", err)
	}

	now := time.Now()
	status := &LockoutStatus{
		FailedAttempts: user.FailedLoginAttempts,
	}

	// Check if account is currently locked
	if user.AccountLockedUntil != nil && now.Before(*user.AccountLockedUntil) {
		status.IsLocked = true
		status.LockedAt = user.AccountLockedAt
		status.LockedUntil = user.AccountLockedUntil
		status.RemainingLockTime = user.AccountLockedUntil.Sub(now)
		
		s.obs.Logger.Info().
			Str("username", username).
			Time("locked_until", *user.AccountLockedUntil).
			Dur("remaining_time", status.RemainingLockTime).
			Msg("Account is currently locked")
		
		return status, nil
	}

	// Check if we need to reset failed attempts due to time window
	if user.LastFailedLoginAt != nil && 
		now.Sub(*user.LastFailedLoginAt) > s.config.ResetWindow {
		// Reset failed attempts counter
		err = s.db.Model(&user).Updates(map[string]interface{}{
			"failed_login_attempts": 0,
			"last_failed_login_at":  nil,
		}).Error
		if err != nil {
			s.obs.Logger.Error().Err(err).Msg("Failed to reset failed login attempts")
		} else {
			status.FailedAttempts = 0
			s.obs.Logger.Info().
				Str("username", username).
				Msg("Reset failed login attempts due to time window")
		}
	}

	// Calculate progressive delay if enabled
	if s.config.ProgressiveDelay && status.FailedAttempts > 0 {
		status.RequiresDelay = true
		status.NextAttemptDelay = s.CalculateDelay(status.FailedAttempts)
	}

	return status, nil
}

// RecordFailedAttempt records a failed login attempt and applies lockout if necessary
func (s *LockoutService) RecordFailedAttempt(username, ipAddress, userAgent, requestID, reason string) error {
	now := time.Now()
	
	// Record the login attempt
	loginAttempt := models.LoginAttempt{
		Username:      username,
		IPAddress:     ipAddress,
		UserAgent:     userAgent,
		Success:       false,
		FailureReason: reason,
		RequestID:     requestID,
	}

	// Check if this is suspicious activity
	suspiciousReport, err := s.DetectSuspiciousActivity(username, ipAddress)
	if err != nil {
		s.obs.Logger.Error().Err(err).Msg("Failed to detect suspicious activity")
	} else if suspiciousReport.IsSuspicious {
		loginAttempt.IsSuspicious = true
		s.obs.Logger.Warn().
			Str("username", username).
			Str("ip_address", ipAddress).
			Strs("reasons", suspiciousReport.Reasons).
			Msg("Suspicious login activity detected")
	}

	// Find the user to update failed attempts
	var user models.User
	err = s.db.Where("username = ? OR email = ?", username, username).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			// Still record the attempt even if user doesn't exist
			loginAttempt.UserID = nil
		} else {
			return fmt.Errorf("failed to find user: %w", err)
		}
	} else {
		loginAttempt.UserID = &user.ID
		loginAttempt.User = &user
		
		// Update user's failed attempt counter
		newFailedAttempts := user.FailedLoginAttempts + 1
		updates := map[string]interface{}{
			"failed_login_attempts": newFailedAttempts,
			"last_failed_login_at":  &now,
		}

		// Check if we need to lock the account
		if newFailedAttempts >= s.config.MaxFailedAttempts {
			lockedUntil := now.Add(s.config.LockoutDuration)
			updates["account_locked_at"] = &now
			updates["account_locked_until"] = &lockedUntil
			
			s.obs.Logger.Warn().
				Str("username", username).
				Int("failed_attempts", newFailedAttempts).
				Time("locked_until", lockedUntil).
				Msg("Account locked due to too many failed attempts")
			
			// TODO: Send notification about account lockout
			if s.config.EnableNotifications {
				go s.sendLockoutNotification(username, ipAddress, newFailedAttempts)
			}
		}

		err = s.db.Model(&user).Updates(updates).Error
		if err != nil {
			return fmt.Errorf("failed to update user failed attempts: %w", err)
		}
	}

	// Save the login attempt record
	err = s.db.Create(&loginAttempt).Error
	if err != nil {
		return fmt.Errorf("failed to record login attempt: %w", err)
	}

	return nil
}

// RecordSuccessfulAttempt records a successful login and resets failed attempts
func (s *LockoutService) RecordSuccessfulAttempt(username, ipAddress, userAgent, requestID string) error {
	now := time.Now()
	
	// Find the user
	var user models.User
	err := s.db.Where("username = ? OR email = ?", username, username).First(&user).Error
	if err != nil {
		return fmt.Errorf("failed to find user: %w", err)
	}

	// Record the successful login attempt
	loginAttempt := models.LoginAttempt{
		Username:  username,
		UserID:    &user.ID,
		User:      &user,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   true,
		RequestID: requestID,
	}

	err = s.db.Create(&loginAttempt).Error
	if err != nil {
		s.obs.Logger.Error().Err(err).Msg("Failed to record successful login attempt")
		// Don't fail the login for this
	}

	// Reset failed attempts and clear any lockout
	updates := map[string]interface{}{
		"failed_login_attempts": 0,
		"last_failed_login_at":  nil,
		"account_locked_at":     nil,
		"account_locked_until":  nil,
		"last_login_at":         &now,
		"last_login_ip":         ipAddress,
	}

	err = s.db.Model(&user).Updates(updates).Error
	if err != nil {
		return fmt.Errorf("failed to reset user failed attempts: %w", err)
	}

	s.obs.Logger.Info().
		Str("username", username).
		Str("ip_address", ipAddress).
		Msg("Successful login recorded and failed attempts reset")

	return nil
}

// UnlockAccount manually unlocks a locked account
func (s *LockoutService) UnlockAccount(username string) error {
	updates := map[string]interface{}{
		"failed_login_attempts": 0,
		"last_failed_login_at":  nil,
		"account_locked_at":     nil,
		"account_locked_until":  nil,
	}

	result := s.db.Model(&models.User{}).
		Where("username = ? OR email = ?", username, username).
		Updates(updates)
	
	if result.Error != nil {
		return fmt.Errorf("failed to unlock account: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("user not found: %s", username)
	}

	s.obs.Logger.Info().
		Str("username", username).
		Msg("Account manually unlocked")

	return nil
}

// CheckIPLockout checks if an IP address is currently locked
func (s *LockoutService) CheckIPLockout(ipAddress string) (*IPLockoutStatus, error) {
	if !s.config.IPLockoutEnabled {
		return &IPLockoutStatus{IsLocked: false}, nil
	}

	// Count failed attempts from this IP in the last hour
	since := time.Now().Add(-s.config.IPLockoutDuration)
	var count int64
	
	err := s.db.Model(&models.LoginAttempt{}).
		Where("ip_address = ? AND success = false AND created_at > ?", ipAddress, since).
		Count(&count).Error
	
	if err != nil {
		return nil, fmt.Errorf("failed to count IP attempts: %w", err)
	}

	status := &IPLockoutStatus{
		FailedAttempts: int(count),
	}

	if int(count) >= s.config.IPLockoutThreshold {
		status.IsLocked = true
		// Calculate remaining time based on the oldest attempt in the window
		var oldestAttempt models.LoginAttempt
		err = s.db.Where("ip_address = ? AND success = false AND created_at > ?", ipAddress, since).
			Order("created_at ASC").
			First(&oldestAttempt).Error
		
		if err == nil {
			lockExpiry := oldestAttempt.CreatedAt.Add(s.config.IPLockoutDuration)
			if lockExpiry.After(time.Now()) {
				status.RemainingLockTime = lockExpiry.Sub(time.Now())
			}
		}
		
		s.obs.Logger.Warn().
			Str("ip_address", ipAddress).
			Int("failed_attempts", int(count)).
			Msg("IP address is locked due to too many failed attempts")
	}

	return status, nil
}

// CalculateDelay calculates progressive delay based on attempt count
func (s *LockoutService) CalculateDelay(attemptCount int) time.Duration {
	if !s.config.ProgressiveDelay || attemptCount <= 0 {
		return 0
	}

	// Exponential backoff: baseDelay * 2^(attemptCount-1)
	delay := s.config.BaseDelay * time.Duration(1<<uint(attemptCount-1))
	
	if delay > s.config.MaxDelay {
		delay = s.config.MaxDelay
	}

	return delay
}

// DetectSuspiciousActivity analyzes login patterns for suspicious behavior
func (s *LockoutService) DetectSuspiciousActivity(username, ipAddress string) (*SuspiciousActivityReport, error) {
	now := time.Now()
	timeWindow := 10 * time.Minute
	since := now.Add(-timeWindow)
	
	report := &SuspiciousActivityReport{
		TimeWindow: timeWindow,
		Reasons:    []string{},
	}

	// Count recent failed attempts for this username
	var userFailedCount int64
	err := s.db.Model(&models.LoginAttempt{}).
		Where("username = ? AND success = false AND created_at > ?", username, since).
		Count(&userFailedCount).Error
	if err != nil {
		return nil, fmt.Errorf("failed to count user attempts: %w", err)
	}
	report.RecentAttemptCount = int(userFailedCount)

	// Count unique IPs trying this username
	var uniqueIPs []string
	err = s.db.Model(&models.LoginAttempt{}).
		Where("username = ? AND created_at > ?", username, since).
		Distinct("ip_address").
		Pluck("ip_address", &uniqueIPs).Error
	if err != nil {
		return nil, fmt.Errorf("failed to count unique IPs: %w", err)
	}
	report.UniqueIPCount = len(uniqueIPs)

	// Count total failed attempts from this IP
	var ipFailedCount int64
	err = s.db.Model(&models.LoginAttempt{}).
		Where("ip_address = ? AND success = false AND created_at > ?", ipAddress, since).
		Count(&ipFailedCount).Error
	if err != nil {
		return nil, fmt.Errorf("failed to count IP attempts: %w", err)
	}
	report.FailedAttempts = int(ipFailedCount)

	// Apply suspicious activity rules
	if report.RecentAttemptCount >= 3 {
		report.IsSuspicious = true
		report.Reasons = append(report.Reasons, fmt.Sprintf("High frequency attempts (%d in %v)", report.RecentAttemptCount, timeWindow))
	}

	if report.UniqueIPCount >= 3 {
		report.IsSuspicious = true
		report.Reasons = append(report.Reasons, fmt.Sprintf("Multiple IPs attempting same username (%d IPs)", report.UniqueIPCount))
	}

	if report.FailedAttempts >= 5 {
		report.IsSuspicious = true
		report.Reasons = append(report.Reasons, fmt.Sprintf("High failure rate from IP (%d attempts)", report.FailedAttempts))
	}

	return report, nil
}

// sendLockoutNotification sends a notification about account lockout
func (s *LockoutService) sendLockoutNotification(username, ipAddress string, attempts int) {
	// TODO: Implement actual notification logic (email, webhook, etc.)
	s.obs.Logger.Warn().
		Str("username", username).
		Str("ip_address", ipAddress).
		Int("failed_attempts", attempts).
		Msg("SECURITY ALERT: Account locked due to multiple failed login attempts")
}