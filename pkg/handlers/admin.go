// Package handlers provides HTTP handlers for the MVP Zero Trust Auth system.
// This file contains admin endpoints for role and user management.
package handlers

import (
	"fmt"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"mvp.local/pkg/auth"
	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
	"mvp.local/pkg/utils"
)

// AdminHandler handles admin-related HTTP requests for role and user management
type AdminHandler struct {
	db           *gorm.DB
	authzService auth.AuthorizationInterface
	obs          *observability.Observability
}

// NewAdminHandler creates a new admin handler instance
func NewAdminHandler(db *gorm.DB, authzService auth.AuthorizationInterface, obs *observability.Observability) *AdminHandler {
	return &AdminHandler{
		db:           db,
		authzService: authzService,
		obs:          obs,
	}
}

// GetRoles returns all roles in the system
// @Summary List all roles
// @Description Get a list of all roles in the system
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {array} models.Role "List of roles"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /admin/roles [get]
func (h *AdminHandler) GetRoles(c *fiber.Ctx) error {
	// Test with hardcoded data first
	testRoles := []map[string]interface{}{
		{
			"id":          1,
			"name":        "admin",
			"description": "Administrator role",
			"is_active":   true,
		},
		{
			"id":          2,
			"name":        "user",
			"description": "Standard user role",
			"is_active":   true,
		},
	}

	return c.JSON(testRoles)
}

// CreateRole creates a new role
// @Summary Create a new role
// @Description Create a new role in the system
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param role body object{name=string,description=string} true "Role data"
// @Success 201 {object} models.Role "Created role"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 409 {object} map[string]interface{} "Role already exists"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /admin/roles [post]
func (h *AdminHandler) CreateRole(c *fiber.Ctx) error {
	var req struct {
		Name        string `json:"name" validate:"required,min=1,max=50"`
		Description string `json:"description" validate:"max=200"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Check if role already exists
	var existingRole models.Role
	if err := h.db.Where("name = ?", req.Name).First(&existingRole).Error; err == nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "Role already exists",
		})
	}

	role := models.Role{
		Name:        req.Name,
		Description: req.Description,
		IsActive:    true,
	}

	if err := h.db.Create(&role).Error; err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to create role")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create role",
		})
	}

	h.obs.Logger.Info().Str("role_name", role.Name).Msg("Role created")
	return c.Status(fiber.StatusCreated).JSON(role)
}

// fetchRole is a helper to fetch a role by ID and handle common errors
func (h *AdminHandler) fetchRole(c *fiber.Ctx, roleID uint64) (*models.Role, error) {
	var role models.Role
	if err := h.db.First(&role, uint(roleID)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Role not found"})
		}
		h.obs.Logger.Error().Err(err).Uint64("role_id", roleID).Msg("Failed to fetch role")
		return nil, c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch role"})
	}
	return &role, nil
}

// fetchPermission is a helper to fetch a permission by ID and handle common errors
func (h *AdminHandler) fetchPermission(c *fiber.Ctx, permissionID uint64) (*models.Permission, error) {
	var permission models.Permission
	if err := h.db.First(&permission, uint(permissionID)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Permission not found"})
		}
		h.obs.Logger.Error().Err(err).Uint64("permission_id", permissionID).Msg("Failed to fetch permission")
		return nil, c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch permission"})
	}
	return &permission, nil
}

// fetchUser is a helper to fetch a user by ID and handle common errors
func (h *AdminHandler) fetchUser(c *fiber.Ctx, userID uint64) (*models.User, error) {
	var user models.User
	if err := h.db.First(&user, uint(userID)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		h.obs.Logger.Error().Err(err).Uint64("user_id", userID).Msg("Failed to fetch user")
		return nil, c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch user"})
	}
	return &user, nil
}

// UpdateRole updates an existing role
// @Summary Update a role
// @Description Update an existing role
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Role ID"
// @Param role body object{name=string,description=string,is_active=bool} true "Updated role data"
// @Success 200 {object} models.Role "Updated role"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 404 {object} map[string]interface{} "Role not found"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /admin/roles/{id} [put]
func (h *AdminHandler) UpdateRole(c *fiber.Ctx) error {
	roleID, err := utils.ParseUintParam(c, "id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var req struct {
		Name        *string `json:"name,omitempty" validate:"omitempty,min=1,max=50"`
		Description *string `json:"description,omitempty" validate:"omitempty,max=200"`
		IsActive    *bool   `json:"is_active,omitempty"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	role, err := h.fetchRole(c, roleID)
	if err != nil {
		return err // Error is already a Fiber response
	role, err := h.fetchRole(c, roleID)
	if err != nil {
		return err // Error is already a Fiber response
	}

	// Update fields if provided
	if req.Name != nil {
		role.Name = *req.Name
	}
	if req.Description != nil {
		role.Description = *req.Description
	}
	if req.IsActive != nil {
		role.IsActive = *req.IsActive
	}

	if err := h.db.Save(&role).Error; err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to update role")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update role",
		})
	}

	h.obs.Logger.Info().Str("role_name", role.Name).Int64("role_id", role.ID).Msg("Role updated")
	return c.JSON(role)
}

// DeleteRole deletes a role
// @Summary Delete a role
// @Description Delete a role from the system
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Role ID"
// @Success 200 {object} map[string]interface{} "Role deleted successfully"
// @Failure 400 {object} map[string]interface{} "Invalid role ID"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 404 {object} map[string]interface{} "Role not found"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /admin/roles/{id} [delete]
func (h *AdminHandler) DeleteRole(c *fiber.Ctx) error {
	roleID, err := utils.ParseUintParam(c, "id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var role models.Role
	if err := h.db.First(&role, uint(roleID)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Role not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch role",
		})
	}

	// Prevent deletion of system roles
	if role.Name == "admin" || role.Name == "user" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Cannot delete system roles",
		})
	}

	if err := h.db.Delete(&role).Error; err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to delete role")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete role",
		})
	}

	h.obs.Logger.Info().Str("role_name", role.Name).Int64("role_id", role.ID).Msg("Role deleted")
	return c.SendStatus(fiber.StatusNoContent)
}

// GetPermissions returns all permissions in the system
func (h *AdminHandler) GetPermissions(c *fiber.Ctx) error {
	var permissions []models.Permission
	if err := h.db.Find(&permissions).Error; err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to fetch permissions")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch permissions",
		})
	}

	return c.JSON(permissions)
}

// AssignPermissionToRole assigns a permission to a role
func (h *AdminHandler) AssignPermissionToRole(c *fiber.Ctx) error {
	roleID, err := utils.ParseUintParam(c, "roleId")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	permissionID, err := utils.ParseUintParam(c, "permissionId")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Verify role exists
	role, err := h.fetchRole(c, roleID)
	if err != nil {
		return err // Error is already a Fiber response
	role, err := h.fetchRole(c, roleID)
	if err != nil {
		return err // Error is already a Fiber response
	}

	// Verify permission exists
	permission, err := h.fetchPermission(c, permissionID)
	if err != nil {
		return err // Error is already a Fiber response
	permission, err := h.fetchPermission(c, permissionID)
	if err != nil {
		return err // Error is already a Fiber response
	}

	// Assign permission to role
	if err := h.db.Model(&role).Association("Permissions").Append(&permission); err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to assign permission to role")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to assign permission to role",
		})
	}

	h.obs.Logger.Info().
		Str("role_name", role.Name).
		Str("permission_name", permission.Name).
		Msg("Permission assigned to role")

	return c.SendStatus(fiber.StatusNoContent)
}

// RemovePermissionFromRole removes a permission from a role
func (h *AdminHandler) RemovePermissionFromRole(c *fiber.Ctx) error {
	roleID, err := utils.ParseUintParam(c, "roleId")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	permissionID, err := utils.ParseUintParam(c, "permissionId")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Verify role exists
	var role models.Role
	if err := h.db.First(&role, uint(roleID)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Role not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch role",
		})
	}

	// Verify permission exists
	var permission models.Permission
	if err := h.db.First(&permission, uint(permissionID)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Permission not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch permission",
		})
	}

	// Remove permission from role
	if err := h.db.Model(&role).Association("Permissions").Delete(&permission); err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to remove permission from role")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to remove permission from role",
		})
	}

	h.obs.Logger.Info().
		Str("role_name", role.Name).
		Str("permission_name", permission.Name).
		Msg("Permission removed from role")

	return c.SendStatus(fiber.StatusNoContent)
}

// GetUsers returns all users with their roles
// @Summary List all users
// @Description Get a list of all users in the system
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {array} models.User "List of users"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 500 {object} map[string]interface{} "Server error"
// @Router /admin/users [get]
func (h *AdminHandler) GetUsers(c *fiber.Ctx) error {
	var users []models.User
	if err := h.db.Find(&users).Error; err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to fetch users")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch users",
		})
	}

	// Simple response without complex relationships for now
	return c.JSON(users)
}

// GetUserById returns a specific user with their roles
func (h *AdminHandler) GetUserById(c *fiber.Ctx) error {
	userID, err := utils.ParseUintParam(c, "id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var user models.User
	if err := h.db.Preload("Roles").First(&user, uint(userID)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "User not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch user",
		})
	}

	return c.JSON(user)
}

// UpdateUser updates user information
func (h *AdminHandler) UpdateUser(c *fiber.Ctx) error {
	userID, err := utils.ParseUintParam(c, "id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var req struct {
		Username  *string `json:"username,omitempty" validate:"omitempty,min=1,max=50"`
		Email     *string `json:"email,omitempty" validate:"omitempty,email,max=100"`
		FirstName *string `json:"first_name,omitempty" validate:"omitempty,max=50"`
		LastName  *string `json:"last_name,omitempty" validate:"omitempty,max=50"`
		IsActive  *bool   `json:"is_active,omitempty"`
		IsAdmin   *bool   `json:"is_admin,omitempty"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	user, err := h.fetchUser(c, userID)
	if err != nil {
		return err // Error is already a Fiber response
	user, err := h.fetchUser(c, userID)
	if err != nil {
		return err // Error is already a Fiber response
	}

	// Update fields if provided
	if req.Username != nil {
		user.Username = *req.Username
	}
	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.FirstName != nil {
		user.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		user.LastName = *req.LastName
	}
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}
	if req.IsAdmin != nil {
		user.IsAdmin = *req.IsAdmin
	}

	if err := h.db.Save(&user).Error; err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to update user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update user",
		})
	}

	h.obs.Logger.Info().Str("username", user.Username).Str("user_id", user.ID.String()).Msg("User updated")
	return c.JSON(user)
}

// DeleteUser deletes a user
func (h *AdminHandler) DeleteUser(c *fiber.Ctx) error {
	userID, err := utils.ParseUintParam(c, "id")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Get current user from context (set by auth middleware)
	currentUserID := c.Locals("user_id").(uint)
	if uint(userID) == currentUserID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Cannot delete your own user account",
		})
	}

	var user models.User
	if err := h.db.First(&user, uint(userID)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "User not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch user",
		})
	}

	if err := h.db.Delete(&user).Error; err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to delete user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete user",
		})
	}

	h.obs.Logger.Info().Str("username", user.Username).Str("user_id", user.ID.String()).Msg("User deleted")
	return c.SendStatus(fiber.StatusNoContent)
}

// AssignRoleToUser assigns a role to a user
func (h *AdminHandler) AssignRoleToUser(c *fiber.Ctx) error {
	userID := c.Params("userId") // UserID from authzService is string (likely UUID)
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "userId parameter is missing",
		})
	}

	roleID, err := utils.ParseUintParam(c, "roleId")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Get role name from roleID
	role, err := h.fetchRole(c, roleID)
	if err != nil {
		return err // Error is already a Fiber response
	role, err := h.fetchRole(c, roleID)
	if err != nil {
		return err // Error is already a Fiber response
	}

	// Use authorization service to assign role by name
	if err := h.authzService.AddRoleForUser(userID, role.Name); err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to assign role to user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to assign role to user",
		})
	}

	h.obs.Logger.Info().
		Str("user_id", userID).
		Str("role_name", role.Name).
		Msg("Role assigned to user")

	return c.SendStatus(fiber.StatusNoContent)
}

// RemoveRoleFromUser removes a role from a user
func (h *AdminHandler) RemoveRoleFromUser(c *fiber.Ctx) error {
	userID := c.Params("userId") // UserID from authzService is string (likely UUID)
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "userId parameter is missing",
		})
	}

	roleID, err := utils.ParseUintParam(c, "roleId")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Get role name from roleID
	var role models.Role
	if err := h.db.First(&role, uint(roleID)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Role not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch role",
		})
	}

	// Use authorization service to remove role by name
	if err := h.authzService.RemoveRoleForUser(userID, role.Name); err != nil {
		h.obs.Logger.Error().Err(err).Msg("Failed to remove role from user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to remove role from user",
		})
	}

	h.obs.Logger.Info().
		Str("user_id", userID).
		Str("role_name", role.Name).
		Msg("Role removed from user")

	return c.SendStatus(fiber.StatusNoContent)
}
