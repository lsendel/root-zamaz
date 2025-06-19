// Package audit provides GDPR-specific compliance functionality
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
)

// GDPRService provides GDPR-specific compliance functionality
type GDPRService struct {
	db  *gorm.DB
	obs *observability.Observability
	complianceService *ComplianceService
}

// DataSubjectRequestType represents GDPR data subject request types
type DataSubjectRequestType string

const (
	RequestTypeAccess        DataSubjectRequestType = "ACCESS"        // Article 15
	RequestTypeRectification DataSubjectRequestType = "RECTIFICATION" // Article 16
	RequestTypeErasure       DataSubjectRequestType = "ERASURE"       // Article 17
	RequestTypeRestriction   DataSubjectRequestType = "RESTRICTION"   // Article 18
	RequestTypePortability   DataSubjectRequestType = "PORTABILITY"   // Article 20
	RequestTypeObjection     DataSubjectRequestType = "OBJECTION"     // Article 21
)

// DataPortabilityRequest represents a data portability request
type DataPortabilityRequest struct {
	DataSubject    string                 `json:"data_subject"`
	RequestedData  []string              `json:"requested_data"`
	Format         string                `json:"format"` // JSON, CSV, XML
	DeliveryMethod string                `json:"delivery_method"` // EMAIL, DOWNLOAD, API
	Metadata       map[string]interface{} `json:"metadata"`
}

// DataErasureRequest represents a data erasure request
type DataErasureRequest struct {
	DataSubject     string   `json:"data_subject"`
	ErasureScope    string   `json:"erasure_scope"` // FULL, PARTIAL
	DataCategories  []string `json:"data_categories"`
	RetainLegal     bool     `json:"retain_legal"`      // Retain for legal obligations
	RetainLegitimate bool    `json:"retain_legitimate"` // Retain for legitimate interests
	Reason          string   `json:"reason"`
}

// GDPRDataMap represents the mapping of personal data across systems
type GDPRDataMap struct {
	DataSubject    string                            `json:"data_subject"`
	DataCategories map[string]GDPRDataCategoryInfo   `json:"data_categories"`
	ProcessingActivities []GDPRProcessingActivity    `json:"processing_activities"`
	LegalBases     map[string]string                `json:"legal_bases"`
	ThirdPartySharing []GDPRThirdPartySharing        `json:"third_party_sharing"`
}

// GDPRDataCategoryInfo represents information about a data category
type GDPRDataCategoryInfo struct {
	Category        string    `json:"category"`
	Description     string    `json:"description"`
	SensitivityLevel int      `json:"sensitivity_level"`
	Storage         []string  `json:"storage"`        // Where data is stored
	Retention       string    `json:"retention"`      // Retention period
	LastUpdated     time.Time `json:"last_updated"`
	LegalBasis      string    `json:"legal_basis"`
}

// GDPRProcessingActivity represents a processing activity
type GDPRProcessingActivity struct {
	Activity        string    `json:"activity"`
	Purpose         string    `json:"purpose"`
	LegalBasis      string    `json:"legal_basis"`
	DataCategories  []string  `json:"data_categories"`
	Recipients      []string  `json:"recipients"`
	RetentionPeriod string    `json:"retention_period"`
	LastProcessed   time.Time `json:"last_processed"`
}

// GDPRThirdPartySharing represents third-party data sharing
type GDPRThirdPartySharing struct {
	Recipient       string    `json:"recipient"`
	Purpose         string    `json:"purpose"`
	LegalBasis      string    `json:"legal_basis"`
	DataCategories  []string  `json:"data_categories"`
	Safeguards      []string  `json:"safeguards"`
	Country         string    `json:"country"`
	LastShared      time.Time `json:"last_shared"`
}

// NewGDPRService creates a new GDPR service
func NewGDPRService(db *gorm.DB, obs *observability.Observability, complianceService *ComplianceService) *GDPRService {
	return &GDPRService{
		db:                db,
		obs:               obs,
		complianceService: complianceService,
	}
}

// ProcessDataSubjectRequest processes a GDPR data subject request
func (gs *GDPRService) ProcessDataSubjectRequest(ctx context.Context, requestType DataSubjectRequestType, dataSubject, requestorID string, details map[string]interface{}) (*models.DataSubjectRequest, error) {
	// Create the request record
	request := &models.DataSubjectRequest{
		RequestType: string(requestType),
		DataSubject: dataSubject,
		RequestorID: requestorID,
		Status:      "RECEIVED",
		Priority:    "NORMAL",
		DueDate:     calculateDueDate(requestType),
		Description: fmt.Sprintf("GDPR %s request for data subject: %s", requestType, dataSubject),
	}
	
	// Set data categories and purposes from details
	if dataCategories, ok := details["data_categories"].([]string); ok {
		if categoriesJSON, err := json.Marshal(dataCategories); err == nil {
			request.DataCategories = string(categoriesJSON)
		}
	}
	
	if purposes, ok := details["purposes"].([]string); ok {
		if purposesJSON, err := json.Marshal(purposes); err == nil {
			request.ProcessingPurposes = string(purposesJSON)
		}
	}
	
	// Save the request
	if err := gs.db.WithContext(ctx).Create(request).Error; err != nil {
		return nil, fmt.Errorf("failed to create data subject request: %w", err)
	}
	
	// Log the compliance event
	err := gs.complianceService.LogGDPREvent(ctx, requestorID, fmt.Sprintf("gdpr_%s_request", strings.ToLower(string(requestType))), dataSubject, LegalBasisLegalObligation, map[string]interface{}{
		"request_id":   request.ID,
		"request_type": requestType,
		"details":      details,
	})
	if err != nil {
		gs.obs.Logger.Warn().Err(err).Msg("Failed to log GDPR compliance event")
	}
	
	gs.obs.Logger.Info().
		Str("request_type", string(requestType)).
		Str("data_subject", dataSubject).
		Str("request_id", request.ID.String()).
		Msg("GDPR data subject request created")
	
	return request, nil
}

// ProcessAccessRequest handles GDPR Article 15 access requests
func (gs *GDPRService) ProcessAccessRequest(ctx context.Context, dataSubject string) (*GDPRDataMap, error) {
	dataMap := &GDPRDataMap{
		DataSubject:          dataSubject,
		DataCategories:       make(map[string]GDPRDataCategoryInfo),
		ProcessingActivities: []GDPRProcessingActivity{},
		LegalBases:          make(map[string]string),
		ThirdPartySharing:   []GDPRThirdPartySharing{},
	}
	
	// Find user by email/identifier
	var user models.User
	if err := gs.db.WithContext(ctx).Where("email = ? OR username = ?", dataSubject, dataSubject).First(&user).Error; err != nil {
		return nil, fmt.Errorf("data subject not found: %w", err)
	}
	
	// Map personal data categories
	dataMap.DataCategories["identity"] = GDPRDataCategoryInfo{
		Category:         "Identity Data",
		Description:      "Basic identity information (name, email, username)",
		SensitivityLevel: 3,
		Storage:         []string{"users_table"},
		Retention:       "7_years",
		LastUpdated:     user.UpdatedAt,
		LegalBasis:      "CONTRACT",
	}
	
	dataMap.DataCategories["authentication"] = GDPRDataCategoryInfo{
		Category:         "Authentication Data",
		Description:      "Login credentials and authentication history",
		SensitivityLevel: 4,
		Storage:         []string{"users_table", "login_attempts", "audit_logs"},
		Retention:       "3_years",
		LastUpdated:     user.UpdatedAt,
		LegalBasis:      "CONTRACT",
	}
	
	// Get device attestations
	var deviceCount int64
	gs.db.WithContext(ctx).Model(&models.DeviceAttestation{}).Where("user_id = ?", user.ID).Count(&deviceCount)
	if deviceCount > 0 {
		dataMap.DataCategories["device_attestation"] = GDPRDataCategoryInfo{
			Category:         "Device Attestation Data",
			Description:      "Device trust and attestation information",
			SensitivityLevel: 3,
			Storage:         []string{"device_attestations"},
			Retention:       "2_years",
			LastUpdated:     time.Now(),
			LegalBasis:      "LEGITIMATE_INTEREST",
		}
	}
	
	// Get audit logs
	var auditCount int64
	gs.db.WithContext(ctx).Model(&models.AuditLog{}).Where("user_id = ?", user.ID).Count(&auditCount)
	if auditCount > 0 {
		dataMap.DataCategories["audit_logs"] = GDPRDataCategoryInfo{
			Category:         "Audit and Security Logs",
			Description:      "Security and activity audit logs",
			SensitivityLevel: 3,
			Storage:         []string{"audit_logs", "compliance_audit_logs"},
			Retention:       "7_years",
			LastUpdated:     time.Now(),
			LegalBasis:      "LEGAL_OBLIGATION",
		}
	}
	
	// Map processing activities
	dataMap.ProcessingActivities = []GDPRProcessingActivity{
		{
			Activity:        "User Authentication",
			Purpose:         "Verify user identity and provide secure access",
			LegalBasis:      "CONTRACT",
			DataCategories:  []string{"identity", "authentication"},
			Recipients:      []string{"internal_systems"},
			RetentionPeriod: "account_lifetime_plus_7_years",
			LastProcessed:   time.Now(),
		},
		{
			Activity:        "Security Monitoring",
			Purpose:         "Monitor for security threats and compliance",
			LegalBasis:      "LEGITIMATE_INTEREST",
			DataCategories:  []string{"audit_logs", "device_attestation"},
			Recipients:      []string{"security_team"},
			RetentionPeriod: "7_years",
			LastProcessed:   time.Now(),
		},
	}
	
	// Map legal bases
	dataMap.LegalBases["authentication"] = "Performance of contract - user account services"
	dataMap.LegalBases["security_monitoring"] = "Legitimate interest - security and fraud prevention"
	dataMap.LegalBases["compliance"] = "Legal obligation - regulatory compliance requirements"
	
	// Log the access request
	err := gs.complianceService.LogGDPREvent(ctx, user.ID.String(), "gdpr_access_request_processed", dataSubject, LegalBasisLegalObligation, map[string]interface{}{
		"data_categories_count": len(dataMap.DataCategories),
		"activities_count":      len(dataMap.ProcessingActivities),
	})
	if err != nil {
		gs.obs.Logger.Warn().Err(err).Msg("Failed to log GDPR access event")
	}
	
	return dataMap, nil
}

// ProcessErasureRequest handles GDPR Article 17 erasure requests
func (gs *GDPRService) ProcessErasureRequest(ctx context.Context, request DataErasureRequest) error {
	// Find user
	var user models.User
	if err := gs.db.WithContext(ctx).Where("email = ? OR username = ?", request.DataSubject, request.DataSubject).First(&user).Error; err != nil {
		return fmt.Errorf("data subject not found: %w", err)
	}
	
	// Begin transaction for data erasure
	return gs.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var eraseCount int64
		
		// Erase user data based on scope
		if request.ErasureScope == "FULL" {
			// Anonymize user record (keep for audit/legal purposes but remove PII)
			anonymizedEmail := fmt.Sprintf("anonymized_%d@deleted.local", time.Now().Unix())
			anonymizedUsername := fmt.Sprintf("anonymized_%d", time.Now().Unix())
			
			result := tx.Model(&user).Updates(map[string]interface{}{
				"email":      anonymizedEmail,
				"username":   anonymizedUsername,
				"first_name": "[ERASED]",
				"last_name":  "[ERASED]",
				"is_active":  false,
			})
			eraseCount += result.RowsAffected
			
			// Delete device attestations if not needed for legal/security purposes
			if !request.RetainLegal {
				result = tx.Where("user_id = ?", user.ID).Delete(&models.DeviceAttestation{})
				eraseCount += result.RowsAffected
			}
			
			// Delete user sessions
			result = tx.Where("user_id = ?", user.ID).Delete(&models.UserSession{})
			eraseCount += result.RowsAffected
			
		} else {
			// Partial erasure based on data categories
			for _, category := range request.DataCategories {
				switch category {
				case "contact_info":
					result := tx.Model(&user).Updates(map[string]interface{}{
						"email": fmt.Sprintf("erased_%d@deleted.local", time.Now().Unix()),
					})
					eraseCount += result.RowsAffected
				case "profile_data":
					result := tx.Model(&user).Updates(map[string]interface{}{
						"first_name": "[ERASED]",
						"last_name":  "[ERASED]",
					})
					eraseCount += result.RowsAffected
				}
			}
		}
		
		// Log the erasure event
		err := gs.complianceService.LogGDPREvent(ctx, user.ID.String(), "gdpr_erasure_processed", request.DataSubject, LegalBasisLegalObligation, map[string]interface{}{
			"erasure_scope":   request.ErasureScope,
			"data_categories": request.DataCategories,
			"records_erased":  eraseCount,
			"reason":         request.Reason,
		})
		if err != nil {
			gs.obs.Logger.Warn().Err(err).Msg("Failed to log GDPR erasure event")
		}
		
		gs.obs.Logger.Info().
			Str("data_subject", request.DataSubject).
			Str("erasure_scope", request.ErasureScope).
			Int64("records_erased", eraseCount).
			Msg("GDPR erasure request processed")
		
		return nil
	})
}

// ProcessPortabilityRequest handles GDPR Article 20 data portability requests
func (gs *GDPRService) ProcessPortabilityRequest(ctx context.Context, request DataPortabilityRequest) (map[string]interface{}, error) {
	// Find user
	var user models.User
	if err := gs.db.WithContext(ctx).Where("email = ? OR username = ?", request.DataSubject, request.DataSubject).First(&user).Error; err != nil {
		return nil, fmt.Errorf("data subject not found: %w", err)
	}
	
	exportData := map[string]interface{}{
		"export_metadata": map[string]interface{}{
			"data_subject":    request.DataSubject,
			"export_date":     time.Now(),
			"format":          request.Format,
			"requested_data":  request.RequestedData,
		},
		"personal_data": map[string]interface{}{},
	}
	
	// Export requested data categories
	for _, dataType := range request.RequestedData {
		switch dataType {
		case "profile":
			exportData["personal_data"].(map[string]interface{})["profile"] = map[string]interface{}{
				"user_id":    user.ID,
				"username":   user.Username,
				"email":      user.Email,
				"first_name": user.FirstName,
				"last_name":  user.LastName,
				"created_at": user.CreatedAt,
				"updated_at": user.UpdatedAt,
			}
			
		case "devices":
			var devices []models.DeviceAttestation
			gs.db.WithContext(ctx).Where("user_id = ?", user.ID).Find(&devices)
			exportData["personal_data"].(map[string]interface{})["devices"] = devices
			
		case "sessions":
			var sessions []models.UserSession
			gs.db.WithContext(ctx).Where("user_id = ?", user.ID).Find(&sessions)
			exportData["personal_data"].(map[string]interface{})["sessions"] = sessions
			
		case "audit_logs":
			var auditLogs []models.AuditLog
			gs.db.WithContext(ctx).Where("user_id = ?", user.ID).Limit(1000).Find(&auditLogs) // Limit for performance
			exportData["personal_data"].(map[string]interface{})["audit_logs"] = auditLogs
		}
	}
	
	// Log the portability request
	err := gs.complianceService.LogGDPREvent(ctx, user.ID.String(), "gdpr_portability_processed", request.DataSubject, LegalBasisLegalObligation, map[string]interface{}{
		"requested_data": request.RequestedData,
		"format":        request.Format,
		"delivery_method": request.DeliveryMethod,
	})
	if err != nil {
		gs.obs.Logger.Warn().Err(err).Msg("Failed to log GDPR portability event")
	}
	
	gs.obs.Logger.Info().
		Str("data_subject", request.DataSubject).
		Strs("requested_data", request.RequestedData).
		Str("format", request.Format).
		Msg("GDPR portability request processed")
	
	return exportData, nil
}

// RecordConsentGiven records consent for data processing
func (gs *GDPRService) RecordConsentGiven(ctx context.Context, dataSubject, consentType, purpose, method string, userID *uuid.UUID, ipAddress, userAgent string) error {
	consent := &models.ConsentRecord{
		DataSubject:    dataSubject,
		UserID:        userID,
		ConsentType:   consentType,
		Purpose:       purpose,
		LegalBasis:    string(LegalBasisConsent),
		Status:        "GIVEN",
		ConsentGiven:  true,
		ConsentDate:   time.Now(),
		ConsentMethod: method,
		IPAddress:     ipAddress,
		UserAgent:     userAgent,
		ConsentVersion: "1.0",
	}
	
	if err := gs.db.WithContext(ctx).Create(consent).Error; err != nil {
		return fmt.Errorf("failed to record consent: %w", err)
	}
	
	// Log the consent event
	err := gs.complianceService.LogGDPREvent(ctx, userID.String(), "gdpr_consent_given", dataSubject, LegalBasisConsent, map[string]interface{}{
		"consent_id":   consent.ID,
		"consent_type": consentType,
		"purpose":      purpose,
		"method":       method,
	})
	if err != nil {
		gs.obs.Logger.Warn().Err(err).Msg("Failed to log GDPR consent event")
	}
	
	return nil
}

// RecordConsentWithdrawn records withdrawal of consent
func (gs *GDPRService) RecordConsentWithdrawn(ctx context.Context, consentID uuid.UUID, method, reason string) error {
	now := time.Now()
	
	result := gs.db.WithContext(ctx).Model(&models.ConsentRecord{}).
		Where("id = ?", consentID).
		Updates(map[string]interface{}{
			"status":            "WITHDRAWN",
			"consent_given":     false,
			"withdrawn_date":    now,
			"withdrawal_method": method,
			"withdrawal_reason": reason,
		})
	
	if result.Error != nil {
		return fmt.Errorf("failed to record consent withdrawal: %w", result.Error)
	}
	
	if result.RowsAffected == 0 {
		return fmt.Errorf("consent record not found")
	}
	
	// Get consent record for logging
	var consent models.ConsentRecord
	if err := gs.db.WithContext(ctx).First(&consent, consentID).Error; err == nil {
		err := gs.complianceService.LogGDPREvent(ctx, consent.UserID.String(), "gdpr_consent_withdrawn", consent.DataSubject, LegalBasisLegalObligation, map[string]interface{}{
			"consent_id":        consentID,
			"consent_type":      consent.ConsentType,
			"withdrawal_method": method,
			"withdrawal_reason": reason,
		})
		if err != nil {
			gs.obs.Logger.Warn().Err(err).Msg("Failed to log GDPR consent withdrawal event")
		}
	}
	
	return nil
}

// Helper functions

func calculateDueDate(requestType DataSubjectRequestType) *time.Time {
	// GDPR Article 12 - respond within one month (30 days)
	dueDate := time.Now().AddDate(0, 0, 30)
	return &dueDate
}