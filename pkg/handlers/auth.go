// Package handlers provides HTTP handlers for the MVP Zero Trust Auth system.
// It includes authentication endpoints, user management, and device attestation handlers.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"mvp.local/pkg/auth"
	"mvp.local/pkg/config"
	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
	"mvp.local/pkg/security"
	"mvp.local/pkg/session"
	"mvp.local/pkg/validation"
)

// Timing protection constants
const (
	// Minimum processing time to prevent timing attacks
	minimumProcessingTime = 200 * time.Millisecond
)

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	db                *gorm.DB
	jwtService        auth.JWTServiceInterface
	authzService      auth.AuthorizationInterface
	lockoutService    security.LockoutServiceInterface
	passwordValidator security.PasswordPolicyInterface
	sessionManager    *session.SessionManager
	obs               *observability.Observability
	config            *config.Config
}

// AuthHandlerInterface defines the contract for authentication handlers
type AuthHandlerInterface interface {
	Login(c *fiber.Ctx) error
	Register(c *fiber.Ctx) error
	RefreshToken(c *fiber.Ctx) error
	Logout(c *fiber.Ctx) error
	GetCurrentUser(c *fiber.Ctx) error
	ChangePassword(c *fiber.Ctx) error
	GetPasswordRequirements(c *fiber.Ctx) error
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
	passwordValidator security.PasswordPolicyInterface,
	sessionManager *session.SessionManager,
	obs *observability.Observability,
	config *config.Config,
) *AuthHandler {
	// Use default password validator if none provided
	if passwordValidator == nil {
		passwordValidator = security.NewPasswordValidator()
	}

	return &AuthHandler{
		db:                db,
		jwtService:        jwtService,
		authzService:      authzService,
		lockoutService:    lockoutService,
		passwordValidator: passwordValidator,
		sessionManager:    sessionManager,
		obs:               obs,
		config:            config,
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
	// Start timing to prevent timing-based user enumeration attacks
	startTime := time.Now()
	defer func() {
		elapsed := time.Since(startTime)
		if elapsed < minimumProcessingTime {
			time.Sleep(minimumProcessingTime - elapsed)
		}
	}()

	// Get validated request from middleware
	validatedReq := validation.GetValidatedRequest(c)
	if validatedReq == nil {
		return HandleValidationError(c, fmt.Errorf("no validated request found"))
	}

	req, ok := validatedReq.(*auth.LoginRequest)
	if !ok {
		return HandleValidationError(c, fmt.Errorf("invalid request type"))
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
			"error":       "Too Many Requests",
			"message":     "Too many failed login attempts from this IP address. Please try again later.",
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
		if err := h.lockoutService.RecordFailedAttempt(req.Username, ipAddress, userAgent, requestID, "Account locked"); err != nil {
			h.obs.Logger.Error().Err(err).Str("username", req.Username).Str("ip_address", ipAddress).Str("user_agent", userAgent).Str("request_id", requestID).Msg("Failed to record failed login attempt")
		}

		return c.Status(fiber.StatusLocked).JSON(fiber.Map{
			"error":        "Account Locked",
			"message":      "Account is temporarily locked due to multiple failed login attempts. Please try again later.",
			"locked_until": lockoutStatus.LockedUntil.Unix(),
			"retry_after":  int(lockoutStatus.RemainingLockTime.Seconds()),
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

		// Perform dummy password check to maintain constant timing
		// This prevents timing-based user enumeration attacks
		dummyHash := "$2a$12$dummy.hash.for.timing.protection.only.fake.hash.value.here"
		_ = h.jwtService.CheckPassword(dummyHash, req.Password)

		// Record failed attempt (protects against user enumeration)
		if err := h.lockoutService.RecordFailedAttempt(req.Username, ipAddress, userAgent, requestID, failureReason); err != nil {
			h.obs.Logger.Error().Err(err).Str("username", req.Username).Str("ip_address", ipAddress).Str("user_agent", userAgent).Str("request_id", requestID).Msg("Failed to record failed login attempt")
		}
		h.logAuthEvent(c, "", "login_failed", false, failureReason)

		return HandleAuthenticationError(c, ErrMsgInvalidCredentials)
	}

	h.obs.Logger.Info().
		Str("user_id", user.ID.String()).
		Str("username", user.Username).
		Bool("is_active", user.IsActive).
		Msg("User found in database")

	// Check if user is active
	if !user.IsActive {
		h.obs.Logger.Info().Msg("User account is disabled")
		if err := h.lockoutService.RecordFailedAttempt(req.Username, ipAddress, userAgent, requestID, "Account disabled"); err != nil {
			h.obs.Logger.Error().Err(err).Str("username", req.Username).Str("ip_address", ipAddress).Str("user_agent", userAgent).Str("request_id", requestID).Msg("Failed to record failed login attempt")
		}
		h.logAuthEvent(c, user.ID.String(), "login_failed", false, "Account disabled")

		// Use generic error message to prevent user enumeration
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Invalid credentials",
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
			Str("user_id", user.ID.String()).
			Msg("Password verification failed")

		// Record failed attempt
		if err := h.lockoutService.RecordFailedAttempt(req.Username, ipAddress, userAgent, requestID, "Invalid password"); err != nil {
			h.obs.Logger.Error().Err(err).Str("username", req.Username).Str("ip_address", ipAddress).Str("user_agent", userAgent).Str("request_id", requestID).Msg("Failed to record failed login attempt")
		}
		h.logAuthEvent(c, user.ID.String(), "login_failed", false, "Invalid password")

		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Invalid credentials",
		})
	}
	h.obs.Logger.Info().Msg("Password verified successfully")

	// Get user roles and permissions
	roles, permissions, err := h.jwtService.GetUserRolesAndPermissions(user.ID.String())
	if err != nil {
		h.obs.Logger.Error().Err(err).Str("user_id", user.ID.String()).Msg("Failed to get user roles and permissions")
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
		h.obs.Logger.Error().Err(err).Str("user_id", user.ID.String()).Msg("Failed to generate JWT token")
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

	// Create new session for security (session regeneration after login)
	if h.sessionManager != nil {
		sessionData := session.SessionData{
			UserID:      user.ID.String(),
			Email:       user.Email,
			Username:    user.Username,
			Roles:       roles,
			Permissions: permissions,
			IPAddress:   ipAddress,
			UserAgent:   userAgent,
			DeviceID:    "", // Could be extracted from headers
			IsActive:    true,
			Metadata: map[string]interface{}{
				"login_method": "password",
				"trust_level":  "trusted",
			},
		}

		createdSession, err := h.sessionManager.CreateSession(c.Context(), user.ID.String(), sessionData)
		if err != nil {
			h.obs.Logger.Error().Err(err).Str("user_id", user.ID.String()).Msg("Failed to create session after login")
			// Don't fail the login for session creation failure
		} else {
			// Set secure session cookie
			c.Cookie(&fiber.Cookie{
				Name:     "session_id",
				Value:    createdSession.SessionID,
				Expires:  createdSession.ExpiresAt,
				HTTPOnly: true,
				Secure:   h.config.HTTP.TLS.Enabled,
				SameSite: "Strict",
				Path:     "/",
			})

			h.obs.Logger.Info().
				Str("user_id", user.ID.String()).
				Str("session_id", createdSession.SessionID).
				Msg("Session created after successful login")
		}
	}

	// Log successful authentication
	h.logAuthEvent(c, user.ID.String(), "login_success", true, "")

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

	// Validate password policy
	if err := h.passwordValidator.ValidatePassword(req.Password, req.Username, req.Email, req.FirstName, req.LastName); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": err.Error(),
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
	if err := h.authzService.AddRoleForUser(user.ID.String(), "user"); err != nil {
		h.obs.Logger.Error().Err(err).Str("user_id", user.ID.String()).Msg("Failed to assign default role")
		// Continue without failing registration
	}

	h.logAuthEvent(c, user.ID.String(), "user_registered", true, "")

	// Return user response (without password)
	userResponse := UserResponse{
		ID:        user.ID.String(),
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
	roles, permissions, err := h.jwtService.GetUserRolesAndPermissions(user.ID.String())
	if err != nil {
		h.obs.Logger.Error().Err(err).Str("user_id", user.ID.String()).Msg("Failed to get user roles and permissions")
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

	h.logAuthEvent(c, user.ID.String(), "token_refreshed", true, "")

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

	// Invalidate active database sessions
	if err := h.db.Model(&models.UserSession{}).
		Where("user_id = ? AND is_active = ?", userID, true).
		Update("is_active", false).Error; err != nil {
		h.obs.Logger.Error().Err(err).Str("user_id", userID).Msg("Failed to invalidate database sessions")
	}

	// Invalidate Redis session if present
	if h.sessionManager != nil {
		sessionID := c.Cookies("session_id")
		if sessionID != "" {
			err := h.sessionManager.DeleteSession(c.Context(), sessionID)
			if err != nil {
				h.obs.Logger.Error().Err(err).Str("session_id", sessionID).Msg("Failed to delete Redis session")
			} else {
				h.obs.Logger.Info().Str("session_id", sessionID).Msg("Redis session deleted during logout")
			}
		}

		// Clear session cookie
		c.Cookie(&fiber.Cookie{
			Name:     "session_id",
			Value:    "",
			Expires:  time.Now().Add(-24 * time.Hour), // Expire in the past
			HTTPOnly: true,
			Secure:   h.config.HTTP.TLS.Enabled,
			SameSite: "Strict",
			Path:     "/",
		})
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
		ID:        user.ID.String(),
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
		h.logAuthEvent(c, user.ID.String(), "password_change_failed", false, "Invalid current password")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "Unauthorized",
			"message": "Invalid current password",
		})
	}

	// Validate new password policy
	if err := h.passwordValidator.ValidatePassword(req.NewPassword, user.Username, user.Email, user.FirstName, user.LastName); err != nil {
		h.logAuthEvent(c, user.ID.String(), "password_change_failed", false, "New password does not meet policy requirements")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": err.Error(),
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
		h.obs.Logger.Error().Err(err).Str("user_id", user.ID.String()).Msg("Failed to update password")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "Internal Server Error",
			"message": "Failed to update password",
		})
	}

	// Invalidate all existing sessions
	if err := h.db.Model(&models.UserSession{}).
		Where("user_id = ? AND is_active = ?", user.ID, true).
		Update("is_active", false).Error; err != nil {
		h.obs.Logger.Error().Err(err).Str("user_id", user.ID.String()).Msg("Failed to invalidate sessions after password change")
	}

	// Regenerate session after password change for security
	if h.sessionManager != nil {
		// Get client info for new session
		ipAddress := c.IP()
		userAgent := c.Get("User-Agent")

		// Get user roles and permissions for new session
		roles, permissions, err := h.jwtService.GetUserRolesAndPermissions(user.ID.String())
		if err != nil {
			h.obs.Logger.Error().Err(err).Str("user_id", user.ID.String()).Msg("Failed to get user roles for session regeneration")
			// Set default roles if authorization service fails
			roles = []string{"user"}
			permissions = []string{}
			if user.IsAdmin {
				roles = append(roles, "admin")
			}
		}

		sessionData := session.SessionData{
			UserID:      user.ID.String(),
			Email:       user.Email,
			Username:    user.Username,
			Roles:       roles,
			Permissions: permissions,
			IPAddress:   ipAddress,
			UserAgent:   userAgent,
			DeviceID:    "", // Could be extracted from headers
			IsActive:    true,
			Metadata: map[string]interface{}{
				"regenerated_reason": "password_change",
				"trust_level":        "trusted",
			},
		}

		createdSession, err := h.sessionManager.CreateSession(c.Context(), user.ID.String(), sessionData)
		if err != nil {
			h.obs.Logger.Error().Err(err).Str("user_id", user.ID.String()).Msg("Failed to regenerate session after password change")
			// Don't fail the password change for session creation failure
		} else {
			// Update session cookie
			c.Cookie(&fiber.Cookie{
				Name:     "session_id",
				Value:    createdSession.SessionID,
				Expires:  createdSession.ExpiresAt,
				HTTPOnly: true,
				Secure:   h.config.HTTP.TLS.Enabled,
				SameSite: "Strict",
				Path:     "/",
			})

			h.obs.Logger.Info().
				Str("user_id", user.ID.String()).
				Str("session_id", createdSession.SessionID).
				Msg("Session regenerated after password change")
		}
	}

	h.logAuthEvent(c, user.ID.String(), "password_changed", true, "")

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

	var userIDPtr *uuid.UUID
	if userID != "" {
		if parsed, err := uuid.Parse(userID); err == nil {
			userIDPtr = &parsed
		}
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

	// Save audit log (non-blocking) with timeout protection
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := h.db.WithContext(ctx).Create(&auditLog).Error; err != nil {
			h.obs.Logger.Error().Err(err).Msg("Failed to save audit log")
		}
	}()
}

// GetPasswordRequirements returns the password policy requirements
// @Summary Get password requirements
// @Description Get the current password policy requirements
// @Tags auth
// @Produce json
// @Success 200 {object} map[string]interface{} "Password requirements"
// @Router /auth/password-requirements [get]
func (h *AuthHandler) GetPasswordRequirements(c *fiber.Ctx) error {
	requirements := h.passwordValidator.GetPasswordRequirements()

	return c.JSON(fiber.Map{
		"success":      true,
		"requirements": requirements,
		"message":      "Password policy requirements",
	})
}
