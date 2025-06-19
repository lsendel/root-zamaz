// Package handlers provides device attestation handlers for the MVP Zero Trust Auth system.
package handlers

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"mvp.local/pkg/auth"
	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
)

// DeviceHandler handles device attestation-related HTTP requests
type DeviceHandler struct {
	db           *gorm.DB
	authzService auth.AuthorizationInterface
	obs          *observability.Observability
}

// DeviceHandlerInterface defines the contract for device handlers
type DeviceHandlerInterface interface {
	GetDevices(c *fiber.Ctx) error
	AttestDevice(c *fiber.Ctx) error
	VerifyDevice(c *fiber.Ctx) error
	GetDeviceById(c *fiber.Ctx) error
	UpdateDevice(c *fiber.Ctx) error
	DeleteDevice(c *fiber.Ctx) error
}

// AttestDeviceRequest represents a device attestation request
type AttestDeviceRequest struct {
	DeviceID         string                 `json:"device_id" validate:"required"`
	DeviceName       string                 `json:"device_name" validate:"required"`
	Platform         string                 `json:"platform" validate:"required"`
	AttestationData  map[string]interface{} `json:"attestation_data"`
	SPIFFEID         string                 `json:"spiffe_id"`
	WorkloadSelector string                 `json:"workload_selector"`
}

// VerifyDeviceRequest represents a device verification request
type VerifyDeviceRequest struct {
	TrustLevel int `json:"trust_level" validate:"min=0,max=100"`
}

// DeviceResponse represents a device attestation response
type DeviceResponse struct {
	ID               string                 `json:"id"`
	DeviceID         string                 `json:"device_id"`
	DeviceName       string                 `json:"device_name"`
	TrustLevel       int                    `json:"trust_level"`
	IsVerified       bool                   `json:"is_verified"`
	VerifiedAt       *time.Time             `json:"verified_at"`
	AttestationData  map[string]interface{} `json:"attestation_data"`
	Platform         string                 `json:"platform"`
	SPIFFEID         string                 `json:"spiffe_id"`
	WorkloadSelector string                 `json:"workload_selector"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
}

// NewDeviceHandler creates a new device handler
func NewDeviceHandler(
	db *gorm.DB,
	authzService auth.AuthorizationInterface,
	obs *observability.Observability,
) *DeviceHandler {
	return &DeviceHandler{
		db:           db,
		authzService: authzService,
		obs:          obs,
	}
}

// GetDevices returns all device attestations for the current user
// @Summary Get user devices
// @Description Get all device attestations for the authenticated user
// @Tags devices
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {array} DeviceResponse "List of devices"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /devices [get]
func (h *DeviceHandler) GetDevices(c *fiber.Ctx) error {
	userID, err := auth.GetCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Not authenticated",
		})
	}

	var devices []models.DeviceAttestation
	if err := h.db.Where("user_id = ?", userID).Find(&devices).Error; err != nil {
		h.obs.Logger.Error().Err(err).Str("user_id", userID).Msg("Failed to fetch devices")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to fetch devices",
		})
	}

	var response []DeviceResponse
	for _, device := range devices {
		deviceResp := h.convertToDeviceResponse(&device)
		response = append(response, deviceResp)
	}

	return c.JSON(response)
}

// AttestDevice creates a new device attestation
// @Summary Attest a device
// @Description Create a new device attestation for zero trust verification
// @Tags devices
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param device body AttestDeviceRequest true "Device attestation data"
// @Success 201 {object} DeviceResponse "Created device attestation"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 409 {object} map[string]interface{} "Device already exists"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /devices [post]
func (h *DeviceHandler) AttestDevice(c *fiber.Ctx) error {
	userID, err := auth.GetCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Not authenticated",
		})
	}

	var req AttestDeviceRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
	}

	// Basic validation
	if req.DeviceID == "" || req.DeviceName == "" || req.Platform == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Device ID, name, and platform are required",
		})
	}

	// Check if device already exists for this user
	var existingDevice models.DeviceAttestation
	err = h.db.Where("user_id = ? AND device_id = ?", userID, req.DeviceID).First(&existingDevice).Error
	if err == nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":   "Conflict",
			"message": "Device already exists",
		})
	} else if err != gorm.ErrRecordNotFound {
		h.obs.Logger.Error().Err(err).Msg("Database error during device attestation")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Database error",
		})
	}

	// Convert attestation data to JSON
	attestationJSON, err := json.Marshal(req.AttestationData)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid attestation data",
		})
	}

	// Parse userID to UUID
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid user ID format",
		})
	}

	// Create device attestation
	device := models.DeviceAttestation{
		UserID:           userUUID,
		DeviceID:         req.DeviceID,
		DeviceName:       req.DeviceName,
		TrustLevel:       h.calculateInitialTrustLevel(req.Platform, req.AttestationData),
		IsVerified:       false,
		AttestationData:  string(attestationJSON),
		Platform:         req.Platform,
		SPIFFEID:         req.SPIFFEID,
		WorkloadSelector: req.WorkloadSelector,
	}

	if err := h.db.Create(&device).Error; err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to create device attestation")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to create device attestation",
		})
	}

	h.logDeviceEvent(c, userID, device.ID.String(), "device_attested", true, "")

	response := h.convertToDeviceResponse(&device)
	return c.Status(fiber.StatusCreated).JSON(response)
}

// VerifyDevice verifies a device attestation (requires device.verify permission)
// @Summary Verify a device
// @Description Verify a device attestation and set trust level
// @Tags devices
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Device ID"
// @Param verification body VerifyDeviceRequest true "Verification data"
// @Success 200 {object} DeviceResponse "Verified device"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden - insufficient permissions"
// @Failure 404 {object} map[string]interface{} "Device not found"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /devices/{id}/verify [post]
func (h *DeviceHandler) VerifyDevice(c *fiber.Ctx) error {
	userID, err := auth.GetCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Not authenticated",
		})
	}

	// Check permission
	if err := h.authzService.CheckPermission(userID, "device", "verify"); err != nil {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":   "Forbidden",
			"message": "Insufficient permissions",
		})
	}

	deviceIDStr := c.Params("id")
	deviceID, err := strconv.ParseUint(deviceIDStr, 10, 32)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid device ID",
		})
	}

	var req VerifyDeviceRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
	}

	// Validate trust level
	if req.TrustLevel < 0 || req.TrustLevel > 100 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Trust level must be between 0 and 100",
		})
	}

	// Find device
	var device models.DeviceAttestation
	if err := h.db.First(&device, uint(deviceID)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error":   "Not Found",
				"message": "Device not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Database error",
		})
	}

	// Update device verification
	now := time.Now()
	device.IsVerified = true
	device.VerifiedAt = &now
	device.TrustLevel = req.TrustLevel

	if err := h.db.Save(&device).Error; err != nil {
		h.obs.Logger.Error().Err(err).Uint("device_id", uint(deviceID)).Msg("Failed to verify device")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to verify device",
		})
	}

	h.logDeviceEvent(c, userID, device.ID.String(), "device_verified", true, "")

	response := h.convertToDeviceResponse(&device)
	return c.JSON(response)
}

// GetDeviceById returns a specific device by ID
// @Summary Get device by ID
// @Description Get a specific device attestation by ID
// @Tags devices
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Device ID"
// @Success 200 {object} DeviceResponse "Device details"
// @Failure 400 {object} map[string]interface{} "Invalid device ID"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Device not found"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /devices/{id} [get]
func (h *DeviceHandler) GetDeviceById(c *fiber.Ctx) error {
	userID, err := auth.GetCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Not authenticated",
		})
	}

	deviceIDStr := c.Params("id")
	deviceID, err := strconv.ParseUint(deviceIDStr, 10, 32)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid device ID",
		})
	}

	var device models.DeviceAttestation

	// Check if user can read all devices or just their own
	canReadAll, _ := h.authzService.Enforce(userID, "device", "admin")
	if canReadAll {
		// Admin can read any device
		if err := h.db.First(&device, uint(deviceID)).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error":   "Not Found",
					"message": "Device not found",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   "Internal Server Error",
				"message": "Database error",
			})
		}
	} else {
		// Regular user can only read their own devices
		if err := h.db.Where("id = ? AND user_id = ?", uint(deviceID), userID).First(&device).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error":   "Not Found",
					"message": "Device not found",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   "Internal Server Error",
				"message": "Database error",
			})
		}
	}

	response := h.convertToDeviceResponse(&device)
	return c.JSON(response)
}

// UpdateDevice updates a device attestation
// @Summary Update device
// @Description Update a device attestation
// @Tags devices
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Device ID"
// @Param device body AttestDeviceRequest true "Updated device data"
// @Success 200 {object} DeviceResponse "Updated device"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Device not found"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /devices/{id} [put]
func (h *DeviceHandler) UpdateDevice(c *fiber.Ctx) error {
	userID, err := auth.GetCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Not authenticated",
		})
	}

	deviceIDStr := c.Params("id")
	deviceID, err := strconv.ParseUint(deviceIDStr, 10, 32)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid device ID",
		})
	}

	var req AttestDeviceRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
	}

	// Find device (user can only update their own devices)
	var device models.DeviceAttestation
	if err := h.db.Where("id = ? AND user_id = ?", uint(deviceID), userID).First(&device).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error":   "Not Found",
				"message": "Device not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Database error",
		})
	}

	// Update device fields
	if req.DeviceName != "" {
		device.DeviceName = req.DeviceName
	}
	if req.Platform != "" {
		device.Platform = req.Platform
	}
	if req.SPIFFEID != "" {
		device.SPIFFEID = req.SPIFFEID
	}
	if req.WorkloadSelector != "" {
		device.WorkloadSelector = req.WorkloadSelector
	}
	if req.AttestationData != nil {
		attestationJSON, err := json.Marshal(req.AttestationData)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   "Bad Request",
				"message": "Invalid attestation data",
			})
		}
		device.AttestationData = string(attestationJSON)
	}

	if err := h.db.Save(&device).Error; err != nil {
		h.obs.Logger.Error().Err(err).Uint("device_id", uint(deviceID)).Msg("Failed to update device")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to update device",
		})
	}

	h.logDeviceEvent(c, userID, device.ID.String(), "device_updated", true, "")

	response := h.convertToDeviceResponse(&device)
	return c.JSON(response)
}

// DeleteDevice deletes a device attestation
// @Summary Delete device
// @Description Delete a device attestation
// @Tags devices
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Device ID"
// @Success 204 "Device deleted successfully"
// @Failure 400 {object} map[string]interface{} "Invalid device ID"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Device not found"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /devices/{id} [delete]
func (h *DeviceHandler) DeleteDevice(c *fiber.Ctx) error {
	userID, err := auth.GetCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Not authenticated",
		})
	}

	deviceIDStr := c.Params("id")
	deviceID, err := strconv.ParseUint(deviceIDStr, 10, 32)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid device ID",
		})
	}

	// Check permission - user can delete their own devices, or admin can delete any
	canDeleteAll, _ := h.authzService.Enforce(userID, "device", "delete")

	var device models.DeviceAttestation
	if canDeleteAll {
		if err := h.db.First(&device, uint(deviceID)).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error":   "Not Found",
					"message": "Device not found",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   "Internal Server Error",
				"message": "Database error",
			})
		}
	} else {
		if err := h.db.Where("id = ? AND user_id = ?", uint(deviceID), userID).First(&device).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error":   "Not Found",
					"message": "Device not found",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   "Internal Server Error",
				"message": "Database error",
			})
		}
	}

	if err := h.db.Delete(&device).Error; err != nil {
		h.obs.Logger.Error().Err(err).Uint("device_id", uint(deviceID)).Msg("Failed to delete device")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to delete device",
		})
	}

	h.logDeviceEvent(c, userID, device.ID.String(), "device_deleted", true, "")

	return c.JSON(fiber.Map{
		"message": "Device deleted successfully",
	})
}

// Helper methods

func (h *DeviceHandler) convertToDeviceResponse(device *models.DeviceAttestation) DeviceResponse {
	var attestationData map[string]interface{}
	if device.AttestationData != "" {
		json.Unmarshal([]byte(device.AttestationData), &attestationData)
	}

	return DeviceResponse{
		ID:               device.ID.String(),
		DeviceID:         device.DeviceID,
		DeviceName:       device.DeviceName,
		TrustLevel:       device.TrustLevel,
		IsVerified:       device.IsVerified,
		VerifiedAt:       device.VerifiedAt,
		AttestationData:  attestationData,
		Platform:         device.Platform,
		SPIFFEID:         device.SPIFFEID,
		WorkloadSelector: device.WorkloadSelector,
		CreatedAt:        device.CreatedAt,
		UpdatedAt:        device.UpdatedAt,
	}
}

func (h *DeviceHandler) calculateInitialTrustLevel(platform string, attestationData map[string]interface{}) int {
	// Basic trust level calculation based on platform and attestation data
	baseTrust := 30

	// Platform-based adjustments
	switch platform {
	case "Windows 11", "macOS", "Linux":
		baseTrust += 20
	case "iOS", "Android":
		baseTrust += 15
	}

	// Attestation data-based adjustments
	if attestationData != nil {
		if tpm, ok := attestationData["tpm"]; ok && tpm == "enabled" {
			baseTrust += 20
		}
		if biometric, ok := attestationData["biometric"]; ok && biometric == "enabled" {
			baseTrust += 15
		}
		if secureBoot, ok := attestationData["secure_boot"]; ok && secureBoot == "enabled" {
			baseTrust += 10
		}
	}

	// Cap at 85 for initial attestation (requires verification for higher trust)
	if baseTrust > 85 {
		baseTrust = 85
	}

	return baseTrust
}

func (h *DeviceHandler) logDeviceEvent(c *fiber.Ctx, userID, deviceID string, event string, success bool, details string) {
	auditDetails := map[string]interface{}{
		"event":     event,
		"device_id": deviceID,
		"details":   details,
	}
	detailsJSON, _ := json.Marshal(auditDetails)

	var userIDPtr *uuid.UUID
	if userID != "" {
		if parsed, err := uuid.Parse(userID); err == nil {
			userIDPtr = &parsed
		}
	}

	auditLog := models.AuditLog{
		UserID:    userIDPtr,
		Action:    event,
		Resource:  "device",
		Details:   string(detailsJSON),
		IPAddress: c.IP(),
		UserAgent: c.Get("User-Agent"),
		RequestID: c.Get("X-Correlation-ID"),
		Success:   success,
	}

	// Save audit log (non-blocking)
	go func() {
		if err := h.db.Create(&auditLog).Error; err != nil {
			h.obs.Logger.Error().Err(err).Msg("Failed to save device audit log")
		}
	}()
}
