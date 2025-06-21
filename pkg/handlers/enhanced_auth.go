package handlers

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"mvp.local/pkg/auth"
	"mvp.local/pkg/common/errors"
	"mvp.local/pkg/common/repository"
	"mvp.local/pkg/config"
	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
	"mvp.local/pkg/security"
	"mvp.local/pkg/session"
	"mvp.local/pkg/validation"
)

// EnhancedAuthHandler provides authentication handling with standardized error handling and repository patterns
type EnhancedAuthHandler struct {
	userRepo          *repository.BaseRepository[models.User]
	sessionRepo       *repository.BaseRepository[models.UserSession]
	errorHandler      *errors.Handler
	jwtService        auth.JWTServiceInterface
	authzService      auth.AuthorizationInterface
	lockoutService    security.LockoutServiceInterface
	passwordValidator security.PasswordPolicyInterface
	sessionManager    *session.SessionManager
	obs               *observability.Observability
	config            *config.Config
	logger            zerolog.Logger
}

// NewEnhancedAuthHandler creates a new enhanced authentication handler
func NewEnhancedAuthHandler(
	userRepo *repository.BaseRepository[models.User],
	sessionRepo *repository.BaseRepository[models.UserSession],
	errorHandler *errors.Handler,
	jwtService auth.JWTServiceInterface,
	authzService auth.AuthorizationInterface,
	lockoutService security.LockoutServiceInterface,
	passwordValidator security.PasswordPolicyInterface,
	sessionManager *session.SessionManager,
	obs *observability.Observability,
	config *config.Config,
	logger zerolog.Logger,
) *EnhancedAuthHandler {
	return &EnhancedAuthHandler{
		userRepo:          userRepo,
		sessionRepo:       sessionRepo,
		errorHandler:      errorHandler,
		jwtService:        jwtService,
		authzService:      authzService,
		lockoutService:    lockoutService,
		passwordValidator: passwordValidator,
		sessionManager:    sessionManager,
		obs:               obs,
		config:            config,
		logger:            logger,
	}
}

// LoginRequest represents the login request payload
type LoginRequest struct {
	Username string `json:"username" validate:"required" example:"user@example.com"`
	Password string `json:"password" validate:"required" example:"securepassword"`
}

// LoginResponse represents the login response
type LoginResponse struct {
	User         *models.User `json:"user"`
	Token        string       `json:"token"`
	RefreshToken string       `json:"refresh_token"`
	ExpiresAt    time.Time    `json:"expires_at"`
}

// Login handles user authentication with enhanced error handling
func (h *EnhancedAuthHandler) Login(c *fiber.Ctx) error {
	ctx := c.Context()
	startTime := time.Now()

	// Ensure minimum processing time to prevent timing attacks
	defer func() {
		elapsed := time.Since(startTime)
		if elapsed < minimumProcessingTime {
			time.Sleep(minimumProcessingTime - elapsed)
		}
	}()

	// Parse and validate request
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.Warn().Err(err).Msg("Invalid login request body")
		return h.errorHandler.HandleValidationError(c, "Invalid request format", nil)
	}

	// Validate request fields
	if err := validation.ValidateStruct(req); err != nil {
		fields := validation.ExtractValidationErrors(err)
		fieldMap := make(map[string]string)
		for _, field := range fields {
			fieldMap[field.Field] = field.Message
		}
		return h.errorHandler.HandleValidationError(c, "Validation failed", fieldMap)
	}

	// Check account lockout before attempting authentication
	if isLocked := h.lockoutService.IsAccountLocked(req.Username); isLocked {
		h.obs.RecordSecurityEvent("account_locked_login_attempt", "high", req.Username, map[string]string{
			"ip_address": c.IP(),
		})
		return h.errorHandler.HandleError(c, errors.NewForbiddenError("Account is temporarily locked"))
	}

	// Find user by username (email)
	user, err := h.userRepo.GetByField(ctx, "email", req.Username, "Roles")
	if err != nil {
		// Record failed login attempt
		h.lockoutService.RecordFailedAttempt(req.Username, c.IP(), c.Get("User-Agent"), c.Locals("requestId").(string), "user not found")
		h.obs.RecordSecurityEvent("login_failed_user_not_found", "medium", req.Username, map[string]string{
			"ip_address": c.IP(),
		})

		// Return generic error to prevent user enumeration
		return h.errorHandler.HandleError(c, errors.NewUnauthorizedError("Invalid credentials"))
	}

	// Verify password
	if !h.passwordValidator.VerifyPassword(req.Password, user.PasswordHash) {
		// Record failed login attempt
		h.lockoutService.RecordFailedAttempt(req.Username, c.IP(), c.Get("User-Agent"), c.Locals("requestId").(string), "wrong password")
		h.obs.RecordSecurityEvent("login_failed_wrong_password", "medium", req.Username, map[string]string{
			"ip_address": c.IP(),
		})

		return h.errorHandler.HandleError(c, errors.NewUnauthorizedError("Invalid credentials"))
	}

	// Check if user account is active
	if !user.IsActive {
		h.obs.RecordSecurityEvent("login_attempt_inactive_user", "medium", req.Username, map[string]string{
			"ip_address": c.IP(),
		})
		return h.errorHandler.HandleError(c, errors.NewForbiddenError("Account is disabled"))
	}

	// Generate JWT tokens
	tokenPair, err := h.jwtService.GenerateTokenPair(user.ID.String(), user.Email, user.Roles)
	if err != nil {
		h.logger.Error().Err(err).Str("user_id", user.ID.String()).Msg("Failed to generate JWT tokens")
		return h.errorHandler.HandleError(c, errors.NewInternalError("Authentication failed", err))
	}

	// Create session record
	userSession := &models.UserSession{
		UserID:       user.ID,
		SessionToken: tokenPair.Token,
		IPAddress:    c.IP(),
		UserAgent:    c.Get("User-Agent"),
		ExpiresAt:    tokenPair.ExpiresAt,
		IsActive:     true,
	}

	if err := h.sessionRepo.Create(ctx, userSession); err != nil {
		h.logger.Error().Err(err).Str("user_id", user.ID.String()).Msg("Failed to create session")
		return h.errorHandler.HandleError(c, errors.NewInternalError("Session creation failed", err))
	}

	// Update user's last login
	updateData := map[string]interface{}{
		"last_login_at": time.Now(),
		"last_login_ip": c.IP(),
	}
	if err := h.userRepo.Update(ctx, user.ID.String(), updateData); err != nil {
		h.logger.Warn().Err(err).Str("user_id", user.ID.String()).Msg("Failed to update last login")
		// Don't fail the login for this
	}

	// Clear any lockout state on successful login
	h.lockoutService.ClearFailedAttempts(req.Username)

	// Record successful login
	h.obs.RecordBusinessMetric("user_login_success", 1, map[string]string{
		"user_id": user.ID,
		"method":  "password",
	})

	// Prepare response (exclude sensitive fields)
	sanitizedUser := *user
	sanitizedUser.PasswordHash = ""

	response := LoginResponse{
		User:         &sanitizedUser,
		Token:        tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    tokenPair.ExpiresAt,
	}

	return c.JSON(fiber.Map{
		"data":       response,
		"message":    "Login successful",
		"request_id": c.Locals("requestId"),
	})
}

// RefreshToken handles JWT token refresh with enhanced error handling
func (h *EnhancedAuthHandler) RefreshToken(c *fiber.Ctx) error {
	ctx := c.Context()

	type RefreshRequest struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	var req RefreshRequest
	if err := c.BodyParser(&req); err != nil {
		return h.errorHandler.HandleValidationError(c, "Invalid request format", nil)
	}

	if err := validation.ValidateStruct(req); err != nil {
		fields := validation.ExtractValidationErrors(err)
		fieldMap := make(map[string]string)
		for _, field := range fields {
			fieldMap[field.Field] = field.Message
		}
		return h.errorHandler.HandleValidationError(c, "Validation failed", fieldMap)
	}

	// Validate refresh token
	claims, err := h.jwtService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		h.obs.RecordSecurityEvent("refresh_token_invalid", "medium", "", map[string]string{
			"ip_address": c.IP(),
		})
		return h.errorHandler.HandleError(c, errors.NewUnauthorizedError("Invalid refresh token"))
	}

	// Get user by ID
	user, err := h.userRepo.GetByID(ctx, claims.UserID, "Roles")
	if err != nil {
		return h.errorHandler.HandleError(c, err)
	}

	// Check if user is still active
	if !user.IsActive {
		return h.errorHandler.HandleError(c, errors.NewForbiddenError("Account is disabled"))
	}

	// Generate new token pair
	tokenPair, err := h.jwtService.GenerateTokenPair(user.ID, user.Email, user.Roles)
	if err != nil {
		h.logger.Error().Err(err).Str("user_id", user.ID).Msg("Failed to generate new token pair")
		return h.errorHandler.HandleError(c, errors.NewInternalError("Token generation failed", err))
	}

	// Blacklist old refresh token
	if err := h.jwtService.BlacklistToken(req.RefreshToken); err != nil {
		h.logger.Warn().Err(err).Msg("Failed to blacklist old refresh token")
	}

	response := LoginResponse{
		User:         user,
		Token:        tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    tokenPair.ExpiresAt,
	}

	return c.JSON(fiber.Map{
		"data":       response,
		"message":    "Token refreshed successfully",
		"request_id": c.Locals("requestId"),
	})
}

// Logout handles user logout with enhanced error handling
func (h *EnhancedAuthHandler) Logout(c *fiber.Ctx) error {
	ctx := c.Context()

	// Get user from context (set by auth middleware)
	userID := c.Locals("userId")
	if userID == nil {
		return h.errorHandler.HandleError(c, errors.NewUnauthorizedError("Not authenticated"))
	}

	// Get token from header
	token := c.Get("Authorization")
	if token == "" {
		return h.errorHandler.HandleError(c, errors.NewUnauthorizedError("No token provided"))
	}

	// Remove "Bearer " prefix
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	// Blacklist the token
	if err := h.jwtService.BlacklistToken(token); err != nil {
		h.logger.Error().Err(err).Str("user_id", userID.(string)).Msg("Failed to blacklist token")
		return h.errorHandler.HandleError(c, errors.NewInternalError("Logout failed", err))
	}

	// Deactivate session
	sessionHash := h.jwtService.HashToken(token)
	updateData := map[string]interface{}{
		"is_active":  false,
		"ended_at":   time.Now(),
		"end_reason": "logout",
	}

	// Find and update session
	if err := h.sessionRepo.Update(ctx, sessionHash, updateData); err != nil {
		h.logger.Warn().Err(err).Str("user_id", userID.(string)).Msg("Failed to update session")
		// Don't fail logout for this
	}

	// Record logout event
	h.obs.RecordBusinessMetric("user_logout", 1, map[string]string{
		"user_id": userID.(string),
	})

	return c.JSON(fiber.Map{
		"message":    "Logout successful",
		"request_id": c.Locals("requestId"),
	})
}

// GetCurrentUser returns the current authenticated user with enhanced error handling
func (h *EnhancedAuthHandler) GetCurrentUser(c *fiber.Ctx) error {
	ctx := c.Context()

	// Get user ID from context (set by auth middleware)
	userID := c.Locals("userId")
	if userID == nil {
		return h.errorHandler.HandleError(c, errors.NewUnauthorizedError("Not authenticated"))
	}

	// Get user from repository
	user, err := h.userRepo.GetByID(ctx, userID.(string), "Roles")
	if err != nil {
		return h.errorHandler.HandleError(c, err)
	}

	// Sanitize user data
	sanitizedUser := *user
	sanitizedUser.PasswordHash = ""

	return c.JSON(fiber.Map{
		"data":       sanitizedUser,
		"request_id": c.Locals("requestId"),
	})
}

// ChangePassword handles password change with enhanced error handling
func (h *EnhancedAuthHandler) ChangePassword(c *fiber.Ctx) error {
	ctx := c.Context()

	type ChangePasswordRequest struct {
		CurrentPassword string `json:"current_password" validate:"required"`
		NewPassword     string `json:"new_password" validate:"required,min=8"`
	}

	var req ChangePasswordRequest
	if err := c.BodyParser(&req); err != nil {
		return h.errorHandler.HandleValidationError(c, "Invalid request format", nil)
	}

	if err := validation.ValidateStruct(req); err != nil {
		fields := validation.ExtractValidationErrors(err)
		fieldMap := make(map[string]string)
		for _, field := range fields {
			fieldMap[field.Field] = field.Message
		}
		return h.errorHandler.HandleValidationError(c, "Validation failed", fieldMap)
	}

	// Get user ID from context
	userID := c.Locals("userId")
	if userID == nil {
		return h.errorHandler.HandleError(c, errors.NewUnauthorizedError("Not authenticated"))
	}

	// Get user from repository
	user, err := h.userRepo.GetByID(ctx, userID.(string))
	if err != nil {
		return h.errorHandler.HandleError(c, err)
	}

	// Verify current password
	if !h.passwordValidator.VerifyPassword(req.CurrentPassword, user.PasswordHash) {
		h.obs.RecordSecurityEvent("password_change_wrong_current", "medium", userID.(string), map[string]string{
			"ip_address": c.IP(),
		})
		return h.errorHandler.HandleError(c, errors.NewUnauthorizedError("Current password is incorrect"))
	}

	// Validate new password policy
	if err := h.passwordValidator.ValidatePassword(req.NewPassword); err != nil {
		return h.errorHandler.HandleValidationError(c, "Password policy violation", map[string]string{
			"password": err.Error(),
		})
	}

	// Hash new password
	hashedPassword, err := h.passwordValidator.HashPassword(req.NewPassword)
	if err != nil {
		h.logger.Error().Err(err).Str("user_id", userID.(string)).Msg("Failed to hash password")
		return h.errorHandler.HandleError(c, errors.NewInternalError("Password processing failed", err))
	}

	// Update password
	updateData := map[string]interface{}{
		"password_hash":    hashedPassword,
		"password_changed": time.Now(),
	}

	if err := h.userRepo.Update(ctx, userID.(string), updateData); err != nil {
		return h.errorHandler.HandleError(c, err)
	}

	// Record password change event
	h.obs.RecordSecurityEvent("password_changed", "low", userID.(string), map[string]string{
		"ip_address": c.IP(),
	})

	return c.JSON(fiber.Map{
		"message":    "Password changed successfully",
		"request_id": c.Locals("requestId"),
	})
}

// GetPasswordRequirements returns the current password policy requirements
func (h *EnhancedAuthHandler) GetPasswordRequirements(c *fiber.Ctx) error {
	requirements := h.passwordValidator.GetRequirements()

	return c.JSON(fiber.Map{
		"data":       requirements,
		"request_id": c.Locals("requestId"),
	})
}
