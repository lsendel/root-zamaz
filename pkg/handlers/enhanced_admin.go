package handlers

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"gorm.io/gorm"

	"mvp.local/pkg/auth"
	"mvp.local/pkg/common/errors"
	"mvp.local/pkg/common/repository"
	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
	"mvp.local/pkg/validation"
)

// EnhancedAdminHandler provides admin operations with standardized error handling and repository patterns
type EnhancedAdminHandler struct {
	userRepo     *repository.BaseRepository[models.User]
	roleRepo     *repository.BaseRepository[models.Role]
	permRepo     *repository.BaseRepository[models.Permission]
	errorHandler *errors.Handler
	authzService auth.AuthorizationInterface
	obs          *observability.Observability
	logger       zerolog.Logger
}

// NewEnhancedAdminHandler creates a new enhanced admin handler
func NewEnhancedAdminHandler(
	userRepo *repository.BaseRepository[models.User],
	roleRepo *repository.BaseRepository[models.Role],
	permRepo *repository.BaseRepository[models.Permission],
	errorHandler *errors.Handler,
	authzService auth.AuthorizationInterface,
	obs *observability.Observability,
	logger zerolog.Logger,
) *EnhancedAdminHandler {
	return &EnhancedAdminHandler{
		userRepo:     userRepo,
		roleRepo:     roleRepo,
		permRepo:     permRepo,
		errorHandler: errorHandler,
		authzService: authzService,
		obs:          obs,
		logger:       logger,
	}
}

// GetUsers retrieves all users with pagination and enhanced error handling
func (h *EnhancedAdminHandler) GetUsers(c *fiber.Ctx) error {
	ctx := c.Context()

	// Check authorization
	if !h.checkAdminPermission(c, "users:read") {
		return h.errorHandler.HandleError(c, errors.NewForbiddenError("Insufficient permissions"))
	}

	// Parse pagination parameters
	params, err := h.parsePaginationParams(c)
	if err != nil {
		return h.errorHandler.HandleError(c, err)
	}

	// Get users with pagination
	result, err := h.userRepo.List(ctx, params, "Roles")
	if err != nil {
		return h.errorHandler.HandleError(c, err)
	}

	// Sanitize user data (remove password hashes)
	for i := range result.Data {
		result.Data[i].PasswordHash = ""
	}

	adminID := ""
	if userID := c.Locals("userId"); userID != nil {
		adminID = userID.(string)
	}

	h.obs.RecordBusinessMetric("admin_users_listed", adminID, map[string]string{
		"count": strconv.Itoa(len(result.Data)),
	})

	return c.JSON(fiber.Map{
		"data":       result,
		"request_id": c.Locals("requestId"),
	})
}

// GetUserByID retrieves a specific user by ID with enhanced error handling
func (h *EnhancedAdminHandler) GetUserByID(c *fiber.Ctx) error {
	ctx := c.Context()

	// Check authorization
	if !h.checkAdminPermission(c, "users:read") {
		return h.errorHandler.HandleError(c, errors.NewForbiddenError("Insufficient permissions"))
	}

	userID := c.Params("id")
	if userID == "" {
		return h.errorHandler.HandleValidationError(c, "User ID is required", nil)
	}

	// Get user by ID
	user, err := h.userRepo.GetByID(ctx, userID, "Roles")
	if err != nil {
		return h.errorHandler.HandleError(c, err)
	}

	// Sanitize user data
	user.PasswordHash = ""

	return c.JSON(fiber.Map{
		"data":       user,
		"request_id": c.Locals("requestId"),
	})
}

// UpdateUser updates a user with enhanced error handling
func (h *EnhancedAdminHandler) UpdateUser(c *fiber.Ctx) error {
	ctx := c.Context()

	// Check authorization
	if !h.checkAdminPermission(c, "users:update") {
		return h.errorHandler.HandleError(c, errors.NewForbiddenError("Insufficient permissions"))
	}

	userID := c.Params("id")
	if userID == "" {
		return h.errorHandler.HandleValidationError(c, "User ID is required", nil)
	}

	type UpdateUserRequest struct {
		Email     *string `json:"email,omitempty" validate:"omitempty,email"`
		FirstName *string `json:"first_name,omitempty"`
		LastName  *string `json:"last_name,omitempty"`
		IsActive  *bool   `json:"is_active,omitempty"`
		IsAdmin   *bool   `json:"is_admin,omitempty"`
	}

	var req UpdateUserRequest
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

	// Verify user exists
	existingUser, err := h.userRepo.GetByID(ctx, userID)
	if err != nil {
		return h.errorHandler.HandleError(c, err)
	}

	// Prepare update data
	updateData := make(map[string]interface{})
	if req.Email != nil {
		// Check if email is already taken
		exists, err := h.userRepo.ExistsByField(ctx, "email", *req.Email)
		if err != nil {
			return h.errorHandler.HandleError(c, err)
		}
		if exists && *req.Email != existingUser.Email {
			return h.errorHandler.HandleError(c, errors.NewConflictError("User", map[string]interface{}{
				"email": "Email already exists",
			}))
		}
		updateData["email"] = *req.Email
	}
	if req.FirstName != nil {
		updateData["first_name"] = *req.FirstName
	}
	if req.LastName != nil {
		updateData["last_name"] = *req.LastName
	}
	if req.IsActive != nil {
		updateData["is_active"] = *req.IsActive
	}
	if req.IsAdmin != nil {
		updateData["is_admin"] = *req.IsAdmin
	}

	// Update user
	if err := h.userRepo.Update(ctx, userID, updateData); err != nil {
		return h.errorHandler.HandleError(c, err)
	}

	// Record admin action
	adminID := ""
	if userID := c.Locals("userId"); userID != nil {
		adminID = userID.(string)
	}
	h.obs.RecordSecurityEvent("admin_user_updated", "medium", adminID, map[string]string{
		"target_user": userID,
		"ip_address":  c.IP(),
	})

	return c.JSON(fiber.Map{
		"message":    "User updated successfully",
		"request_id": c.Locals("requestId"),
	})
}

// DeleteUser deletes a user with enhanced error handling
func (h *EnhancedAdminHandler) DeleteUser(c *fiber.Ctx) error {
	ctx := c.Context()

	// Check authorization
	if !h.checkAdminPermission(c, "users:delete") {
		return h.errorHandler.HandleError(c, errors.NewForbiddenError("Insufficient permissions"))
	}

	userID := c.Params("id")
	if userID == "" {
		return h.errorHandler.HandleValidationError(c, "User ID is required", nil)
	}

	// Prevent self-deletion
	if userID == c.Locals("userId").(string) {
		return h.errorHandler.HandleError(c, errors.NewForbiddenError("Cannot delete your own account"))
	}

	// Verify user exists
	_, err := h.userRepo.GetByID(ctx, userID)
	if err != nil {
		return h.errorHandler.HandleError(c, err)
	}

	// Soft delete user
	if err := h.userRepo.SoftDelete(ctx, userID); err != nil {
		return h.errorHandler.HandleError(c, err)
	}

	// Record admin action
	adminID := ""
	if userID := c.Locals("userId"); userID != nil {
		adminID = userID.(string)
	}
	h.obs.RecordSecurityEvent("admin_user_deleted", "high", adminID, map[string]string{
		"target_user": userID,
		"ip_address":  c.IP(),
	})

	return c.JSON(fiber.Map{
		"message":    "User deleted successfully",
		"request_id": c.Locals("requestId"),
	})
}

// GetRoles retrieves all roles with enhanced error handling
func (h *EnhancedAdminHandler) GetRoles(c *fiber.Ctx) error {
	ctx := c.Context()

	// Check authorization
	if !h.checkAdminPermission(c, "roles:read") {
		return h.errorHandler.HandleError(c, errors.NewForbiddenError("Insufficient permissions"))
	}

	// Parse pagination parameters
	params, err := h.parsePaginationParams(c)
	if err != nil {
		return h.errorHandler.HandleError(c, err)
	}

	// Get roles with pagination
	result, err := h.roleRepo.List(ctx, params, "Permissions")
	if err != nil {
		return h.errorHandler.HandleError(c, err)
	}

	return c.JSON(fiber.Map{
		"data":       result,
		"request_id": c.Locals("requestId"),
	})
}

// CreateRole creates a new role with enhanced error handling
func (h *EnhancedAdminHandler) CreateRole(c *fiber.Ctx) error {
	ctx := c.Context()

	// Check authorization
	if !h.checkAdminPermission(c, "roles:create") {
		return h.errorHandler.HandleError(c, errors.NewForbiddenError("Insufficient permissions"))
	}

	type CreateRoleRequest struct {
		Name        string `json:"name" validate:"required,min=2,max=50"`
		Description string `json:"description" validate:"required,min=5,max=200"`
	}

	var req CreateRoleRequest
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

	// Check if role name already exists
	exists, err := h.roleRepo.ExistsByField(ctx, "name", req.Name)
	if err != nil {
		return h.errorHandler.HandleError(c, err)
	}
	if exists {
		return h.errorHandler.HandleError(c, errors.NewConflictError("Role", map[string]interface{}{
			"name": "Role name already exists",
		}))
	}

	// Create role
	role := &models.Role{
		Name:        req.Name,
		Description: req.Description,
		IsActive:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := h.roleRepo.Create(ctx, role); err != nil {
		return h.errorHandler.HandleError(c, err)
	}

	// Record admin action
	adminID := ""
	if userID := c.Locals("userId"); userID != nil {
		adminID = userID.(string)
	}
	h.obs.RecordSecurityEvent("admin_role_created", "medium", adminID, map[string]string{
		"role_name":  req.Name,
		"ip_address": c.IP(),
	})

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"data":       role,
		"message":    "Role created successfully",
		"request_id": c.Locals("requestId"),
	})
}

// AssignRoleToUser assigns a role to a user with enhanced error handling
func (h *EnhancedAdminHandler) AssignRoleToUser(c *fiber.Ctx) error {
	ctx := c.Context()

	// Check authorization
	if !h.checkAdminPermission(c, "users:update") {
		return h.errorHandler.HandleError(c, errors.NewForbiddenError("Insufficient permissions"))
	}

	userID := c.Params("userId")
	roleID := c.Params("roleId")

	if userID == "" || roleID == "" {
		return h.errorHandler.HandleValidationError(c, "User ID and Role ID are required", nil)
	}

	// Verify user exists
	_, err := h.userRepo.GetByID(ctx, userID)
	if err != nil {
		return h.errorHandler.HandleError(c, err)
	}

	// Verify role exists
	_, err = h.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return h.errorHandler.HandleError(c, err)
	}

	// Assign role using repository transaction
	err = h.userRepo.Transaction(ctx, func(tx *gorm.DB) error {
		// Create user-role association
		return tx.Exec("INSERT INTO user_roles (user_id, role_id, created_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
			userID, roleID, time.Now()).Error
	})
	if err != nil {
		return h.errorHandler.HandleError(c, errors.NewDatabaseError("assign_role", "user_roles", err))
	}

	// Record admin action
	adminID := ""
	if userID := c.Locals("userId"); userID != nil {
		adminID = userID.(string)
	}
	h.obs.RecordSecurityEvent("admin_role_assigned", "medium", adminID, map[string]string{
		"target_user": userID,
		"role_id":     roleID,
		"ip_address":  c.IP(),
	})

	return c.JSON(fiber.Map{
		"message":    "Role assigned successfully",
		"request_id": c.Locals("requestId"),
	})
}

// RemoveRoleFromUser removes a role from a user with enhanced error handling
func (h *EnhancedAdminHandler) RemoveRoleFromUser(c *fiber.Ctx) error {
	ctx := c.Context()

	// Check authorization
	if !h.checkAdminPermission(c, "users:update") {
		return h.errorHandler.HandleError(c, errors.NewForbiddenError("Insufficient permissions"))
	}

	userID := c.Params("userId")
	roleID := c.Params("roleId")

	if userID == "" || roleID == "" {
		return h.errorHandler.HandleValidationError(c, "User ID and Role ID are required", nil)
	}

	// Remove role using repository transaction
	err := h.userRepo.Transaction(ctx, func(tx *gorm.DB) error {
		return tx.Exec("DELETE FROM user_roles WHERE user_id = ? AND role_id = ?", userID, roleID).Error
	})
	if err != nil {
		return h.errorHandler.HandleError(c, errors.NewDatabaseError("remove_role", "user_roles", err))
	}

	// Record admin action
	adminID := ""
	if userID := c.Locals("userId"); userID != nil {
		adminID = userID.(string)
	}
	h.obs.RecordSecurityEvent("admin_role_removed", "medium", adminID, map[string]string{
		"target_user": userID,
		"role_id":     roleID,
		"ip_address":  c.IP(),
	})

	return c.JSON(fiber.Map{
		"message":    "Role removed successfully",
		"request_id": c.Locals("requestId"),
	})
}

// Helper methods

// checkAdminPermission verifies if the user has admin permissions
func (h *EnhancedAdminHandler) checkAdminPermission(c *fiber.Ctx, permission string) bool {
	userID := c.Locals("userId")
	if userID == nil {
		return false
	}

	// Check if user is admin or has specific permission
	return h.authzService.HasPermission(userID.(string), permission)
}

// parsePaginationParams parses and validates pagination parameters
func (h *EnhancedAdminHandler) parsePaginationParams(c *fiber.Ctx) (repository.PaginationParams, error) {
	params := repository.PaginationParams{
		Page:  1,
		Limit: 20,
		Sort:  "created_at",
		Order: "desc",
	}

	// Parse page
	if pageStr := c.Query("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			params.Page = page
		}
	}

	// Parse limit
	if limitStr := c.Query("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 100 {
			params.Limit = limit
		}
	}

	// Parse sort
	if sort := c.Query("sort"); sort != "" {
		params.Sort = sort
	}

	// Parse order
	if order := c.Query("order"); order == "asc" || order == "desc" {
		params.Order = order
	}

	// Parse filters
	params.Filters = make(map[string]interface{})
	if isActive := c.Query("is_active"); isActive != "" {
		if active, err := strconv.ParseBool(isActive); err == nil {
			params.Filters["is_active"] = active
		}
	}

	return params, nil
}
