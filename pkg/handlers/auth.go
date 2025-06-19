// Package handlers provides HTTP handlers for the MVP Zero Trust Auth system.
// It includes authentication endpoints, user management, and device attestation handlers.
package handlers

import (
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"mvp.local/pkg/auth"
	"mvp.local/pkg/config"
	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
	"mvp.local/pkg/security"
)

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	db            *gorm.DB
	jwtService    auth.JWTServiceInterface
	authzService  auth.AuthorizationInterface
	lockoutService security.LockoutServiceInterface
	obs           *observability.Observability
	config        *config.Config
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
	ID        string    `json:"id"`
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
	lockoutService security.LockoutServiceInterface,
	obs *observability.Observability,
	config *config.Config,
) *AuthHandler {
	return &AuthHandler{
		db:            db,
		jwtService:    jwtService,
		authzService:  authzService,
		lockoutService: lockoutService,
		obs:           obs,
		config:        config,
	}
}

// Login handles user login requests with comprehensive security protections
// @Summary User login
// @Description Authenticate user and return JWT tokens with brute force protection
// @Tags auth
// @Accept json
// @Produce json
// @Param login body auth.LoginRequest true "Login credentials"
// @Success 200 {object} auth.LoginResponse "Login successful"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Invalid credentials"
// @Failure 423 {object} map[string]interface{} "Account locked"
// @Failure 429 {object} map[string]interface{} "Too many requests"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /auth/login [post]
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

	// Get request context for security tracking
	ipAddress := c.IP()
	userAgent := c.Get("User-Agent")
	requestID := c.Get("X-Correlation-ID")

	// Check IP-based lockout first
	ipStatus, err := h.lockoutService.CheckIPLockout(ipAddress)
	if err != nil {
		h.obs.Logger.Error().Err(err).Str("ip_address", ipAddress).Msg("Failed to check IP lockout")
		// Continue with login attempt even if lockout check fails
	} else if ipStatus.IsLocked {
		h.obs.Logger.Warn().
			Str("ip_address", ipAddress).
			Int("failed_attempts", ipStatus.FailedAttempts).
			Dur("remaining_time", ipStatus.RemainingLockTime).
			Msg("IP address is locked")
		
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error":   "Too Many Requests",
			"message": "Too many failed login attempts from this IP address. Please try again later.",
			"retry_after": int(ipStatus.RemainingLockTime.Seconds()),
		})
	}

	// Check account-specific lockout
	lockoutStatus, err := h.lockoutService.CheckAccountLockout(req.Username)
	if err != nil {
		h.obs.Logger.Error().Err(err).Str("username", req.Username).Msg("Failed to check account lockout")
		// Continue with login attempt even if lockout check fails
	} else if lockoutStatus.IsLocked {
		h.obs.Logger.Warn().
			Str("username", req.Username).
			Time("locked_until", *lockoutStatus.LockedUntil).
			Dur("remaining_time", lockoutStatus.RemainingLockTime).
			Msg("Account is locked")
		
		// Record the blocked attempt
		_ = h.lockoutService.RecordFailedAttempt(req.Username, ipAddress, userAgent, requestID, "Account locked")
		
		return c.Status(fiber.StatusLocked).JSON(fiber.Map{
			"error":   "Account Locked",
			"message": "Account is temporarily locked due to multiple failed login attempts. Please try again later.",
			"locked_until": lockoutStatus.LockedUntil.Unix(),
			"retry_after": int(lockoutStatus.RemainingLockTime.Seconds()),
		})
	}

	// Apply progressive delay if configured
	if lockoutStatus.RequiresDelay && lockoutStatus.NextAttemptDelay > 0 {
		h.obs.Logger.Info().
			Str("username", req.Username).
			Dur("delay", lockoutStatus.NextAttemptDelay).
			Msg("Applying progressive delay")
		time.Sleep(lockoutStatus.NextAttemptDelay)
	}

	// Find user by username or email
	var user models.User
	err = h.db.Where("username = ? OR email = ?", req.Username, req.Username).First(&user).Error
	if err != nil {
		failureReason := "User not found"
		if err != gorm.ErrRecordNotFound {
			failureReason = "Database error"
			h.obs.Logger.Error().Err(err).Msg("Database error during login")
		} else {
			h.obs.Logger.Info().Str("username", req.Username).Msg("User not found in database")
		}
		
		// Record failed attempt (protects against user enumeration)
		_ = h.lockoutService.RecordFailedAttempt(req.Username, ipAddress, userAgent, requestID, failureReason)
		h.logAuthEvent(c, "", "login_failed", false, failureReason)
		
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Invalid credentials",
		})
	}
	
	h.obs.Logger.Info().
		Str("user_id", user.ID).
		Str("username", user.Username).
		Bool("is_active", user.IsActive).
		Msg("User found in database")

	// Check if user is active
	if !user.IsActive {
		h.obs.Logger.Info().Msg("User account is disabled")
		_ = h.lockoutService.RecordFailedAttempt(req.Username, ipAddress, userAgent, requestID, "Account disabled")
		h.logAuthEvent(c, user.ID, "login_failed", false, "Account disabled")
		
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Account is disabled",
		})
	}

	// Ensure JWT service is available
	if h.jwtService == nil {
		h.obs.Logger.Error().Msg("JWT service is nil - authentication system misconfigured")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Authentication system is not properly configured",
		})
	}

	// Verify password using JWT service
	h.obs.Logger.Info().Msg("Verifying password with JWT service")
	if err := h.jwtService.CheckPassword(user.PasswordHash, req.Password); err != nil {
		h.obs.Logger.Info().
			Err(err).
			Str("user_id", user.ID).
			Msg("Password verification failed")
		
		// Record failed attempt
		_ = h.lockoutService.RecordFailedAttempt(req.Username, ipAddress, userAgent, requestID, "Invalid password")
		h.logAuthEvent(c, user.ID, "login_failed", false, "Invalid password")
		
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Invalid credentials",
		})
	}
	h.obs.Logger.Info().Msg("Password verified successfully")

	// Get user roles and permissions
	roles, permissions, err := h.jwtService.GetUserRolesAndPermissions(user.ID)
	if err != nil {
		h.obs.Logger.Error().Err(err).Str("user_id", user.ID).Msg("Failed to get user roles and permissions")
		// Set default roles if authorization service fails
		roles = []string{"user"}
		permissions = []string{}
		if user.IsAdmin {
			roles = append(roles, "admin")
		}
	}

	// Generate JWT tokens
	tokenResponse, err := h.jwtService.GenerateToken(&user, roles, permissions)
	if err != nil {
		h.obs.Logger.Error().Err(err).Str("user_id", user.ID).Msg("Failed to generate JWT token")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to generate authentication token",
		})
	}

	// Record successful login (this resets failed attempts)
	err = h.lockoutService.RecordSuccessfulAttempt(req.Username, ipAddress, userAgent, requestID)
	if err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to record successful login attempt")
		// Don't fail the login for this error
	}

	// Log successful authentication
	h.logAuthEvent(c, user.ID, "login_success", true, "")

	return c.JSON(tokenResponse)
}

// Register handles user registration requests
// @Summary User registration
// @Description Create a new user account
// @Tags auth
// @Accept json
// @Produce json
// @Param register body RegisterRequest true "Registration details"
// @Success 201 {object} UserResponse "User created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 409 {object} map[string]interface{} "User already exists"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /auth/register [post]
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
		h.obs.Logger.Error().Err(err).Str("user_id", user.ID).Msg("Failed to assign default role")
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
// @Summary Refresh access token
// @Description Exchange refresh token for new access token
// @Tags auth
// @Accept json
// @Produce json
// @Param refresh body auth.RefreshRequest true "Refresh token"
// @Success 200 {object} map[string]interface{} "New tokens"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Invalid refresh token"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /auth/refresh [post]
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
		h.obs.Logger.Error().Err(err).Str("user_id", user.ID).Msg("Failed to get user roles and permissions")
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
// @Summary User logout
// @Description Invalidate current session and tokens
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Logout successful"
// @Failure 401 {object} map[string]interface{} "Not authenticated"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /auth/logout [post]
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
		h.obs.Logger.Error().Err(err).Str("user_id", userID).Msg("Failed to invalidate sessions")
	}

	h.logAuthEvent(c, userID, "logout", true, "")

	return c.JSON(fiber.Map{
		"message": "Logged out successfully",
	})
}

// GetCurrentUser returns the current authenticated user's information
// @Summary Get current user
// @Description Get information about the currently authenticated user
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} UserResponse "User information"
// @Failure 401 {object} map[string]interface{} "Not authenticated"
// @Router /auth/me [get]
func (h *AuthHandler) GetCurrentUser(c *fiber.Ctx) error {
	// Get current user from JWT token
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
// @Summary Change password
// @Description Change the current user's password
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param password body ChangePasswordRequest true "Password change details"
// @Success 200 {object} map[string]interface{} "Password changed successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Invalid current password"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /auth/change-password [post]
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
		h.obs.Logger.Error().Err(err).Str("user_id", user.ID).Msg("Failed to update password")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to update password",
		})
	}

	// Invalidate all existing sessions
	if err := h.db.Model(&models.UserSession{}).
		Where("user_id = ? AND is_active = ?", user.ID, true).
		Update("is_active", false).Error; err != nil {
		h.obs.Logger.Error().Err(err).Str("user_id", user.ID).Msg("Failed to invalidate sessions after password change")
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

func (h *AuthHandler) logAuthEvent(c *fiber.Ctx, userID string, event string, success bool, details string) {
	auditDetails := map[string]interface{}{
		"event":   event,
		"details": details,
	}
	detailsJSON, _ := json.Marshal(auditDetails)

	var userIDPtr *string
	if userID != "" {
		userIDPtr = &userID
	}

	auditLog := models.AuditLog{
		UserID:    userIDPtr,
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