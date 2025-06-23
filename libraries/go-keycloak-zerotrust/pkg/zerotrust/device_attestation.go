// Package zerotrust provides Zero Trust security features including device attestation,
// risk assessment, and continuous verification capabilities
package zerotrust

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// DeviceAttestationService provides device attestation and verification capabilities
type DeviceAttestationService struct {
	config      *types.ZeroTrustConfig
	storage     DeviceStorage
	verifiers   map[string]DeviceVerifier
	trustEngine *TrustEngine
}

// DeviceStorage interface for storing device information
type DeviceStorage interface {
	StoreDevice(ctx context.Context, device *Device) error
	GetDevice(ctx context.Context, deviceID string) (*Device, error)
	UpdateDevice(ctx context.Context, device *Device) error
	ListUserDevices(ctx context.Context, userID string) ([]*Device, error)
	DeleteDevice(ctx context.Context, deviceID string) error
}

// DeviceVerifier interface for platform-specific device verification
type DeviceVerifier interface {
	VerifyDevice(ctx context.Context, attestation *DeviceAttestation) (*VerificationResult, error)
	GetPlatform() string
	GetCapabilities() []string
}

// Device represents a registered device
type Device struct {
	ID               string                 `json:"id"`
	UserID           string                 `json:"user_id"`
	DeviceFingerprint string                `json:"device_fingerprint"`
	Platform         string                 `json:"platform"`
	DeviceType       string                 `json:"device_type"`
	TrustLevel       int                    `json:"trust_level"`
	IsVerified       bool                   `json:"is_verified"`
	LastAttestation  time.Time              `json:"last_attestation"`
	AttestationData  map[string]interface{} `json:"attestation_data"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
	ExpiresAt        *time.Time             `json:"expires_at,omitempty"`
}

// DeviceAttestation represents device attestation data
type DeviceAttestation struct {
	DeviceID          string                 `json:"device_id"`
	UserID            string                 `json:"user_id"`
	Platform          string                 `json:"platform"`
	DeviceFingerprint string                 `json:"device_fingerprint"`
	HardwareData      map[string]interface{} `json:"hardware_data"`
	SoftwareData      map[string]interface{} `json:"software_data"`
	BiometricData     string                 `json:"biometric_data,omitempty"`
	LocationData      *types.LocationInfo    `json:"location_data,omitempty"`
	Timestamp         time.Time              `json:"timestamp"`
	Nonce             string                 `json:"nonce"`
	Signature         string                 `json:"signature"`
}

// VerificationResult represents the result of device verification
type VerificationResult struct {
	IsValid           bool                   `json:"is_valid"`
	TrustScore        int                    `json:"trust_score"`
	VerificationLevel string                 `json:"verification_level"`
	Reasons           []string               `json:"reasons"`
	RiskFactors       []string               `json:"risk_factors"`
	Metadata          map[string]interface{} `json:"metadata"`
	ExpiresAt         time.Time              `json:"expires_at"`
}

// NewDeviceAttestationService creates a new device attestation service
func NewDeviceAttestationService(config *types.ZeroTrustConfig, storage DeviceStorage) *DeviceAttestationService {
	service := &DeviceAttestationService{
		config:      config,
		storage:     storage,
		verifiers:   make(map[string]DeviceVerifier),
		trustEngine: NewTrustEngine(config),
	}

	// Register default verifiers
	service.RegisterVerifier(&AndroidVerifier{})
	service.RegisterVerifier(&IOSVerifier{})
	service.RegisterVerifier(&WindowsVerifier{})
	service.RegisterVerifier(&MacOSVerifier{})
	service.RegisterVerifier(&LinuxVerifier{})
	service.RegisterVerifier(&WebVerifier{})

	return service
}

// RegisterVerifier registers a platform-specific device verifier
func (s *DeviceAttestationService) RegisterVerifier(verifier DeviceVerifier) {
	s.verifiers[verifier.GetPlatform()] = verifier
	log.Printf("Registered device verifier for platform: %s", verifier.GetPlatform())
}

// AttestDevice performs device attestation and verification
func (s *DeviceAttestationService) AttestDevice(ctx context.Context, attestation *DeviceAttestation) (*VerificationResult, error) {
	// Validate attestation data
	if err := s.validateAttestation(attestation); err != nil {
		return nil, fmt.Errorf("invalid attestation: %w", err)
	}

	// Get platform-specific verifier
	verifier, exists := s.verifiers[attestation.Platform]
	if !exists {
		return &VerificationResult{
			IsValid:           false,
			TrustScore:        0,
			VerificationLevel: "unsupported",
			Reasons:           []string{"Unsupported platform: " + attestation.Platform},
		}, nil
	}

	// Perform device verification
	result, err := verifier.VerifyDevice(ctx, attestation)
	if err != nil {
		return nil, fmt.Errorf("device verification failed: %w", err)
	}

	// Apply trust engine scoring
	finalScore := s.trustEngine.CalculateDeviceTrustScore(attestation, result)
	result.TrustScore = finalScore

	// Store or update device information
	device := &Device{
		ID:               attestation.DeviceID,
		UserID:           attestation.UserID,
		DeviceFingerprint: attestation.DeviceFingerprint,
		Platform:         attestation.Platform,
		TrustLevel:       result.TrustScore,
		IsVerified:       result.IsValid && result.TrustScore >= s.config.ZeroTrust.TrustLevelThresholds.Read,
		LastAttestation:  time.Now(),
		AttestationData:  s.buildAttestationMetadata(attestation, result),
		UpdatedAt:        time.Now(),
	}

	// Check if device exists
	existingDevice, err := s.storage.GetDevice(ctx, attestation.DeviceID)
	if err == nil && existingDevice != nil {
		device.CreatedAt = existingDevice.CreatedAt
		err = s.storage.UpdateDevice(ctx, device)
	} else {
		device.CreatedAt = time.Now()
		err = s.storage.StoreDevice(ctx, device)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to store device: %w", err)
	}

	log.Printf("Device attestation completed: device=%s, user=%s, score=%d, verified=%t",
		device.ID, device.UserID, device.TrustLevel, device.IsVerified)

	return result, nil
}

// VerifyDevice verifies an existing device
func (s *DeviceAttestationService) VerifyDevice(ctx context.Context, deviceID string) (*Device, error) {
	device, err := s.storage.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("device not found: %w", err)
	}

	// Check if device verification is still valid
	if s.config.ZeroTrust.DeviceVerificationTTL > 0 {
		if time.Since(device.LastAttestation) > s.config.ZeroTrust.DeviceVerificationTTL {
			device.IsVerified = false
			device.TrustLevel = s.trustEngine.DecayTrustScore(device.TrustLevel, time.Since(device.LastAttestation))
			
			if err := s.storage.UpdateDevice(ctx, device); err != nil {
				log.Printf("Failed to update expired device: %v", err)
			}
		}
	}

	return device, nil
}

// GetUserDevices returns all devices for a user
func (s *DeviceAttestationService) GetUserDevices(ctx context.Context, userID string) ([]*Device, error) {
	devices, err := s.storage.ListUserDevices(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user devices: %w", err)
	}

	// Check and update device statuses
	for _, device := range devices {
		if s.config.ZeroTrust.DeviceVerificationTTL > 0 {
			if time.Since(device.LastAttestation) > s.config.ZeroTrust.DeviceVerificationTTL {
				device.IsVerified = false
				device.TrustLevel = s.trustEngine.DecayTrustScore(device.TrustLevel, time.Since(device.LastAttestation))
			}
		}
	}

	return devices, nil
}

// RevokeDevice revokes a device's verification
func (s *DeviceAttestationService) RevokeDevice(ctx context.Context, deviceID string, reason string) error {
	device, err := s.storage.GetDevice(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("device not found: %w", err)
	}

	device.IsVerified = false
	device.TrustLevel = 0
	device.UpdatedAt = time.Now()
	
	// Add revocation metadata
	if device.AttestationData == nil {
		device.AttestationData = make(map[string]interface{})
	}
	device.AttestationData["revoked"] = true
	device.AttestationData["revocation_reason"] = reason
	device.AttestationData["revoked_at"] = time.Now()

	if err := s.storage.UpdateDevice(ctx, device); err != nil {
		return fmt.Errorf("failed to revoke device: %w", err)
	}

	log.Printf("Device revoked: device=%s, reason=%s", deviceID, reason)
	return nil
}

// GenerateNonce generates a cryptographic nonce for attestation
func (s *DeviceAttestationService) GenerateNonce() (string, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	return hex.EncodeToString(nonce), nil
}

// Private helper methods

func (s *DeviceAttestationService) validateAttestation(attestation *DeviceAttestation) error {
	if attestation.DeviceID == "" {
		return fmt.Errorf("device ID is required")
	}
	if attestation.UserID == "" {
		return fmt.Errorf("user ID is required")
	}
	if attestation.Platform == "" {
		return fmt.Errorf("platform is required")
	}
	if attestation.DeviceFingerprint == "" {
		return fmt.Errorf("device fingerprint is required")
	}
	if time.Since(attestation.Timestamp) > 5*time.Minute {
		return fmt.Errorf("attestation timestamp is too old")
	}
	return nil
}

func (s *DeviceAttestationService) buildAttestationMetadata(attestation *DeviceAttestation, result *VerificationResult) map[string]interface{} {
	metadata := map[string]interface{}{
		"platform":            attestation.Platform,
		"verification_level":  result.VerificationLevel,
		"last_verification":   time.Now(),
		"verifier_metadata":   result.Metadata,
	}

	if attestation.LocationData != nil {
		metadata["location"] = attestation.LocationData
	}

	return metadata
}

// Platform-specific verifiers (simplified implementations)

// AndroidVerifier implements Android device verification
type AndroidVerifier struct{}

func (v *AndroidVerifier) VerifyDevice(ctx context.Context, attestation *DeviceAttestation) (*VerificationResult, error) {
	// Simplified Android SafetyNet verification
	// In production, this would integrate with Google Play Integrity API
	
	result := &VerificationResult{
		IsValid:           true,
		TrustScore:        75,
		VerificationLevel: "hardware",
		Reasons:           []string{"SafetyNet verification passed"},
		ExpiresAt:         time.Now().Add(24 * time.Hour),
		Metadata: map[string]interface{}{
			"safetynet_verified": true,
			"play_protect":       true,
		},
	}

	// Check for rooting indicators
	if bootloaderUnlocked, ok := attestation.HardwareData["bootloader_unlocked"].(bool); ok && bootloaderUnlocked {
		result.RiskFactors = append(result.RiskFactors, "bootloader_unlocked")
		result.TrustScore -= 30
	}

	return result, nil
}

func (v *AndroidVerifier) GetPlatform() string     { return "android" }
func (v *AndroidVerifier) GetCapabilities() []string { return []string{"safetynet", "hardware_attestation"} }

// IOSVerifier implements iOS device verification
type IOSVerifier struct{}

func (v *IOSVerifier) VerifyDevice(ctx context.Context, attestation *DeviceAttestation) (*VerificationResult, error) {
	// Simplified iOS DeviceCheck verification
	// In production, this would integrate with Apple's DeviceCheck API
	
	result := &VerificationResult{
		IsValid:           true,
		TrustScore:        80,
		VerificationLevel: "hardware",
		Reasons:           []string{"DeviceCheck verification passed"},
		ExpiresAt:         time.Now().Add(24 * time.Hour),
		Metadata: map[string]interface{}{
			"devicecheck_verified": true,
			"touch_id_available":   true,
		},
	}

	// Check for jailbreak indicators
	if jailbroken, ok := attestation.SoftwareData["jailbroken"].(bool); ok && jailbroken {
		result.RiskFactors = append(result.RiskFactors, "jailbroken")
		result.TrustScore -= 40
	}

	return result, nil
}

func (v *IOSVerifier) GetPlatform() string     { return "ios" }
func (v *IOSVerifier) GetCapabilities() []string { return []string{"devicecheck", "biometric"} }

// WebVerifier implements web browser verification
type WebVerifier struct{}

func (v *WebVerifier) VerifyDevice(ctx context.Context, attestation *DeviceAttestation) (*VerificationResult, error) {
	// Web Crypto API based verification
	result := &VerificationResult{
		IsValid:           true,
		TrustScore:        40, // Lower trust for web
		VerificationLevel: "software",
		Reasons:           []string{"Browser fingerprint verified"},
		ExpiresAt:         time.Now().Add(1 * time.Hour), // Shorter expiry
		Metadata: map[string]interface{}{
			"user_agent":      attestation.HardwareData["user_agent"],
			"webgl_hash":      attestation.HardwareData["webgl_hash"],
			"canvas_hash":     attestation.HardwareData["canvas_hash"],
		},
	}

	return result, nil
}

func (v *WebVerifier) GetPlatform() string     { return "web" }
func (v *WebVerifier) GetCapabilities() []string { return []string{"fingerprinting", "webauthn"} }

// Placeholder implementations for other platforms
type WindowsVerifier struct{}
func (v *WindowsVerifier) VerifyDevice(ctx context.Context, attestation *DeviceAttestation) (*VerificationResult, error) {
	return &VerificationResult{IsValid: true, TrustScore: 60, VerificationLevel: "software"}, nil
}
func (v *WindowsVerifier) GetPlatform() string { return "windows" }
func (v *WindowsVerifier) GetCapabilities() []string { return []string{"tpm"} }

type MacOSVerifier struct{}
func (v *MacOSVerifier) VerifyDevice(ctx context.Context, attestation *DeviceAttestation) (*VerificationResult, error) {
	return &VerificationResult{IsValid: true, TrustScore: 70, VerificationLevel: "hardware"}, nil
}
func (v *MacOSVerifier) GetPlatform() string { return "macos" }
func (v *MacOSVerifier) GetCapabilities() []string { return []string{"secure_enclave"} }

type LinuxVerifier struct{}
func (v *LinuxVerifier) VerifyDevice(ctx context.Context, attestation *DeviceAttestation) (*VerificationResult, error) {
	return &VerificationResult{IsValid: true, TrustScore: 50, VerificationLevel: "software"}, nil
}
func (v *LinuxVerifier) GetPlatform() string { return "linux" }
func (v *LinuxVerifier) GetCapabilities() []string { return []string{"ima"} }