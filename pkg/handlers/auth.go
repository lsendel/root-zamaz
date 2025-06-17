// Package handlers provides HTTP handlers for the MVP Zero Trust Auth system.
// It includes authentication endpoints, user management, and device attestation handlers.
package handlers

import (
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"mvp.local/pkg/auth"
	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
)

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	db           *gorm.DB
	jwtService   auth.JWTServiceInterface
	authzService auth.AuthorizationInterface
	obs          *observability.Observability
}

// AuthHandlerInterface defines the contract for authentication handlers
type AuthHandlerInterface interface {
	Login(c *fiber.Ctx) error
	Register(c *fiber.Ctx) error
	RefreshToken(c *fiber.Ctx) error
	Logout(c *fiber.Ctx) error
	GetCurrentUser(c *fiber.Ctx) error
	ChangePassword(c *fiber.Ctx) error
}

// RegisterRequest represents a user registration request
type RegisterRequest struct {
	Username  string `json:"username" validate:"required,min=3,max=50"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	FirstName string `json:"first_name" validate:"max=50"`
	LastName  string `json:"last_name" validate:"max=50"`
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
}

// UserResponse represents a user response (without sensitive data)
type UserResponse struct {
	ID        uint      `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	IsActive  bool      `json:"is_active"`
	IsAdmin   bool      `json:"is_admin"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Roles     []string  `json:"roles"`
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(
	db *gorm.DB,
	jwtService auth.JWTServiceInterface,
	authzService auth.AuthorizationInterface,
	obs *observability.Observability,
) *AuthHandler {
	return &AuthHandler{
		db:           db,
		jwtService:   jwtService,
		authzService: authzService,
		obs:          obs,
	}
}

// Login handles user login requests
func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var req auth.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
	}

	// Validate request
	if req.Username == "" || req.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Username and password are required",
		})
	}

	// Find user by username or email
	var user models.User
	err := h.db.Where("username = ? OR email = ?", req.Username, req.Username).First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			h.logAuthEvent(c, 0, "login_failed", false, "User not found")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "Unauthorized",
				"message": "Invalid credentials",
			})
		}
		h.obs.Logger.Error().Err(err).Msg("Database error during login")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Database error",
		})
	}

	// Check if user is active
	if !user.IsActive {
		h.logAuthEvent(c, user.ID, "login_failed", false, "User account disabled")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Account is disabled",
		})
	}

	// Verify password
	if err := h.jwtService.CheckPassword(user.PasswordHash, req.Password); err != nil {
		h.logAuthEvent(c, user.ID, "login_failed", false, "Invalid password")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Invalid credentials",
		})
	}

	// Get user roles and permissions
	roles, permissions, err := h.jwtService.GetUserRolesAndPermissions(user.ID)
	if err != nil {
		h.obs.Logger.Error().Err(err).Uint("user_id", user.ID).Msg("Failed to get user roles and permissions")
		// Continue with empty roles/permissions rather than failing
		roles = []string{}
		permissions = []string{}
	}

	// Determine trust level based on device attestation
	trustLevel := h.calculateTrustLevel(&user, req.DeviceID)

	// Generate tokens
	accessToken, err := h.jwtService.GenerateToken(&user, req.DeviceID, trustLevel, roles, permissions)
	if err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to generate access token")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to generate token",
		})
	}

	refreshToken, err := h.jwtService.GenerateRefreshToken(user.ID)
	if err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to generate refresh token")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to generate refresh token",
		})
	}

	// Create session record
	session := models.UserSession{
		UserID:       user.ID,
		SessionToken: accessToken, // Store token hash in production
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		IsActive:     true,
		DeviceID:     req.DeviceID,
		IPAddress:    c.IP(),
		UserAgent:    c.Get("User-Agent"),
		TrustLevel:   trustLevel,
	}

	if err := h.db.Create(&session).Error; err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to create session")
		// Continue without failing the login
	}

	h.logAuthEvent(c, user.ID, "login_success", true, "")

	response := auth.LoginResponse{
		Token:        accessToken,
		RefreshToken: refreshToken,
		User:         &user,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}

	return c.JSON(response)
}

// Register handles user registration requests
func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var req RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
	}

	// Basic validation
	if req.Username == "" || req.Email == "" || req.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Username, email, and password are required",
		})
	}

	// Check if user already exists
	var existingUser models.User
	err := h.db.Where("username = ? OR email = ?", req.Username, req.Email).First(&existingUser).Error
	if err == nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":   "Conflict",
			"message": "User already exists",
		})
	} else if err != gorm.ErrRecordNotFound {
		h.obs.Logger.Error().Err(err).Msg("Database error during registration")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Database error",
		})
	}

	// Hash password
	hashedPassword, err := h.jwtService.HashPassword(req.Password)
	if err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to hash password")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to process password",
		})
	}

	// Create user
	user := models.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: hashedPassword,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		IsActive:     true,
		IsAdmin:      false,
	}

	if err := h.db.Create(&user).Error; err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to create user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to create user",
		})
	}

	// Assign default user role
	if err := h.authzService.AddRoleForUser(user.ID, "user"); err != nil {
		h.obs.Logger.Error().Err(err).Uint("user_id", user.ID).Msg("Failed to assign default role")
		// Continue without failing registration
	}

	h.logAuthEvent(c, user.ID, "user_registered", true, "")

	// Return user response (without password)
	userResponse := UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		IsActive:  user.IsActive,
		IsAdmin:   user.IsAdmin,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Roles:     []string{"user"},
	}

	return c.Status(fiber.StatusCreated).JSON(userResponse)
}

// RefreshToken handles token refresh requests
func (h *AuthHandler) RefreshToken(c *fiber.Ctx) error {
	var req auth.RefreshRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
	}

	// Validate refresh token and get user ID
	userID, err := h.jwtService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Invalid refresh token",
		})
	}

	// Get user
	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "Unauthorized",
				"message": "User not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Database error",
		})
	}

	// Check if user is still active
	if !user.IsActive {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Account is disabled",
		})
	}

	// Get user roles and permissions
	roles, permissions, err := h.jwtService.GetUserRolesAndPermissions(user.ID)
	if err != nil {
		h.obs.Logger.Error().Err(err).Uint("user_id", user.ID).Msg("Failed to get user roles and permissions")
		roles = []string{}
		permissions = []string{}
	}

	// Generate new tokens
	response, err := h.jwtService.RefreshAccessToken(req.RefreshToken, &user, roles, permissions)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Failed to refresh token",
		})
	}

	h.logAuthEvent(c, user.ID, "token_refreshed", true, "")

	return c.JSON(response)
}

// Logout handles user logout requests
func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	userID, err := auth.GetCurrentUserID(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Not authenticated",
		})
	}

	// Invalidate active sessions
	if err := h.db.Model(&models.UserSession{}).
		Where("user_id = ? AND is_active = ?", userID, true).
		Update("is_active", false).Error; err != nil {
		h.obs.Logger.Error().Err(err).Uint("user_id", userID).Msg("Failed to invalidate sessions")
	}

	h.logAuthEvent(c, userID, "logout", true, "")

	return c.JSON(fiber.Map{
		"message": "Logged out successfully",
	})
}

// GetCurrentUser returns the current authenticated user's information
func (h *AuthHandler) GetCurrentUser(c *fiber.Ctx) error {
	user, err := auth.GetCurrentUser(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Not authenticated",
		})
	}

	roles, err := auth.GetCurrentUserRoles(c)
	if err != nil {
		roles = []string{}
	}

	userResponse := UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		IsActive:  user.IsActive,
		IsAdmin:   user.IsAdmin,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Roles:     roles,
	}

	return c.JSON(userResponse)
}

// ChangePassword handles password change requests
func (h *AuthHandler) ChangePassword(c *fiber.Ctx) error {
	user, err := auth.GetCurrentUser(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Not authenticated",
		})
	}

	var req ChangePasswordRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": "Invalid request body",
		})
	}

	// Verify current password
	if err := h.jwtService.CheckPassword(user.PasswordHash, req.CurrentPassword); err != nil {
		h.logAuthEvent(c, user.ID, "password_change_failed", false, "Invalid current password")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Invalid current password",
		})
	}

	// Hash new password
	hashedPassword, err := h.jwtService.HashPassword(req.NewPassword)
	if err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to hash new password")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to process new password",
		})
	}

	// Update password
	if err := h.db.Model(user).Update("password_hash", hashedPassword).Error; err != nil {
		h.obs.Logger.Error().Err(err).Uint("user_id", user.ID).Msg("Failed to update password")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to update password",
		})
	}

	// Invalidate all existing sessions
	if err := h.db.Model(&models.UserSession{}).
		Where("user_id = ? AND is_active = ?", user.ID, true).
		Update("is_active", false).Error; err != nil {
		h.obs.Logger.Error().Err(err).Uint("user_id", user.ID).Msg("Failed to invalidate sessions after password change")
	}

	h.logAuthEvent(c, user.ID, "password_changed", true, "")

	return c.JSON(fiber.Map{
		"message": "Password changed successfully",
	})
}

// Helper methods

func (h *AuthHandler) calculateTrustLevel(user *models.User, deviceID string) int {
	if deviceID == "" {
		return 30 // Low trust for unidentified devices
	}

	// Check if device is attested
	var attestation models.DeviceAttestation
	err := h.db.Where("user_id = ? AND device_id = ? AND is_verified = ?", user.ID, deviceID, true).
		First(&attestation).Error
	
	if err == nil {
		return attestation.TrustLevel
	}

	return 50 // Medium trust for identified but unverified devices
}

func (h *AuthHandler) logAuthEvent(c *fiber.Ctx, userID uint, event string, success bool, details string) {
	auditDetails := map[string]interface{}{
		"event":   event,
		"details": details,
	}
	detailsJSON, _ := json.Marshal(auditDetails)

	auditLog := models.AuditLog{
		UserID:    &userID,
		Action:    event,
		Resource:  "auth",
		Details:   string(detailsJSON),
		IPAddress: c.IP(),
		UserAgent: c.Get("User-Agent"),
		RequestID: c.Get("X-Correlation-ID"),
		Success:   success,
	}

	// Save audit log (non-blocking)
	go func() {
		if err := h.db.Create(&auditLog).Error; err != nil {
			h.obs.Logger.Error().Err(err).Msg("Failed to save audit log")
		}
	}()
}