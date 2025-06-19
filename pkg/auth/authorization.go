// Package auth provides authentication and authorization services for the MVP Zero Trust Auth system.
// It includes Casbin RBAC integration, JWT token management, and database-backed authorization.
package auth

import (
	"fmt"

	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/gorm"

	"mvp.local/pkg/errors"
	"mvp.local/pkg/models"
)

// AuthorizationService handles RBAC authorization using Casbin
type AuthorizationService struct {
	enforcer *casbin.Enforcer
	db       *gorm.DB
}

// AuthorizationInterface defines the contract for authorization operations
type AuthorizationInterface interface {
	Initialize(db *gorm.DB, modelPath string) error
	Enforce(userID string, resource, action string) (bool, error)
	AddRoleForUser(userID string, role string) error
	RemoveRoleForUser(userID string, role string) error
	GetRolesForUser(userID string) ([]string, error)
	GetUsersForRole(role string) ([]string, error)
	AddPermissionForRole(role, resource, action string) error
	RemovePermissionForRole(role, resource, action string) error
	GetPermissionsForRole(role string) ([][]string, error)
	GetUserPermissions(userID string) ([]string, error)
	CheckPermission(userID string, resource, action string) error
	LoadPolicy() error
	SavePolicy() error
}

// NewAuthorizationService creates a new authorization service
func NewAuthorizationService() *AuthorizationService {
	return &AuthorizationService{}
}

// Initialize sets up the Casbin enforcer with GORM adapter
func (a *AuthorizationService) Initialize(db *gorm.DB, modelPath string) error {
	// Initialize GORM adapter for Casbin
	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to create Casbin GORM adapter")
	}

	// Create Casbin enforcer
	enforcer, err := casbin.NewEnforcer(modelPath, adapter)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to create Casbin enforcer")
	}

	// Load policy from database
	if err := enforcer.LoadPolicy(); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to load Casbin policy")
	}

	a.enforcer = enforcer
	a.db = db

	// Sync database roles and permissions to Casbin
	if err := a.syncDatabaseToPolicy(); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to sync database to Casbin policy")
	}

	return nil
}

// Enforce checks if a user has permission to perform an action on a resource
func (a *AuthorizationService) Enforce(userID string, resource, action string) (bool, error) {
	if a.enforcer == nil {
		return false, errors.Internal("Authorization service not initialized")
	}

	allowed, err := a.enforcer.Enforce(userID, resource, action)
	if err != nil {
		return false, errors.Wrap(err, errors.CodeInternal, "Failed to enforce authorization")
	}

	return allowed, nil
}

// AddRoleForUser assigns a role to a user
func (a *AuthorizationService) AddRoleForUser(userID string, role string) error {
	if a.enforcer == nil {
		return errors.Internal("Authorization service not initialized")
	}

	_, err := a.enforcer.AddRoleForUser(userID, role)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to add role for user")
	}

	// Update database
	if err := a.updateUserRoleInDB(userID, role, true); err != nil {
		return err
	}

	return a.enforcer.SavePolicy()
}

// RemoveRoleForUser removes a role from a user
func (a *AuthorizationService) RemoveRoleForUser(userID string, role string) error {
	if a.enforcer == nil {
		return errors.Internal("Authorization service not initialized")
	}

	_, err := a.enforcer.DeleteRoleForUser(userID, role)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to remove role for user")
	}

	// Update database
	if err := a.updateUserRoleInDB(userID, role, false); err != nil {
		return err
	}

	return a.enforcer.SavePolicy()
}

// GetRolesForUser gets all roles for a user
func (a *AuthorizationService) GetRolesForUser(userID string) ([]string, error) {
	if a.enforcer == nil {
		return nil, errors.Internal("Authorization service not initialized")
	}

	roles, err := a.enforcer.GetRolesForUser(userID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to get roles for user")
	}

	return roles, nil
}

// GetUsersForRole gets all users with a specific role
func (a *AuthorizationService) GetUsersForRole(role string) ([]string, error) {
	if a.enforcer == nil {
		return nil, errors.Internal("Authorization service not initialized")
	}

	users, err := a.enforcer.GetUsersForRole(role)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to get users for role")
	}

	return users, nil
}

// AddPermissionForRole adds a permission to a role
func (a *AuthorizationService) AddPermissionForRole(role, resource, action string) error {
	if a.enforcer == nil {
		return errors.Internal("Authorization service not initialized")
	}

	_, err := a.enforcer.AddPermissionForUser(role, resource, action)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to add permission for role")
	}

	return a.enforcer.SavePolicy()
}

// RemovePermissionForRole removes a permission from a role
func (a *AuthorizationService) RemovePermissionForRole(role, resource, action string) error {
	if a.enforcer == nil {
		return errors.Internal("Authorization service not initialized")
	}

	_, err := a.enforcer.DeletePermissionForUser(role, resource, action)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to remove permission for role")
	}

	return a.enforcer.SavePolicy()
}

// GetPermissionsForRole gets all permissions for a role
func (a *AuthorizationService) GetPermissionsForRole(role string) ([][]string, error) {
	if a.enforcer == nil {
		return nil, errors.Internal("Authorization service not initialized")
	}

	permissions, err := a.enforcer.GetPermissionsForUser(role)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to get permissions for role")
	}
	return permissions, nil
}

// LoadPolicy reloads policy from database
func (a *AuthorizationService) LoadPolicy() error {
	if a.enforcer == nil {
		return errors.Internal("Authorization service not initialized")
	}

	if err := a.enforcer.LoadPolicy(); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to load policy")
	}

	return nil
}

// SavePolicy saves policy to database
func (a *AuthorizationService) SavePolicy() error {
	if a.enforcer == nil {
		return errors.Internal("Authorization service not initialized")
	}

	if err := a.enforcer.SavePolicy(); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to save policy")
	}

	return nil
}

// syncDatabaseToPolicy synchronizes database roles and permissions to Casbin policy
func (a *AuthorizationService) syncDatabaseToPolicy() error {
	// Load existing policy from database instead of clearing
	if err := a.enforcer.LoadPolicy(); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to load existing policy")
	}

	// Load roles and permissions from database
	var roles []models.Role
	if err := a.db.Preload("Permissions").Find(&roles).Error; err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to load roles from database")
	}

	// Add permissions for each role (only if not already present)
	for _, role := range roles {
		for _, permission := range role.Permissions {
			if permission.IsActive {
				// Check if permission already exists to avoid duplicates
				hasPermission, _ := a.enforcer.HasPermissionForUser(role.Name, permission.Resource, permission.Action)
				if !hasPermission {
					_, err := a.enforcer.AddPermissionForUser(role.Name, permission.Resource, permission.Action)
					if err != nil {
						return errors.Wrap(err, errors.CodeInternal, fmt.Sprintf("Failed to add permission %s for role %s", permission.Name, role.Name))
					}
				}
			}
		}
	}

	// Load user roles from database
	var users []models.User
	if err := a.db.Preload("Roles").Find(&users).Error; err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to load users from database")
	}

	// Add role assignments for each user (only if not already present)
	for _, user := range users {
		for _, role := range user.Roles {
			if role.IsActive {
				// Check if role assignment already exists to avoid duplicates
				hasRole, _ := a.enforcer.HasRoleForUser(user.ID, role.Name)
				if !hasRole {
					_, err := a.enforcer.AddRoleForUser(user.ID, role.Name)
					if err != nil {
						return errors.Wrap(err, errors.CodeInternal, fmt.Sprintf("Failed to add role %s for user %s", role.Name, user.ID))
					}
				}
			}
		}
	}

	// Save policy only if there were changes
	return a.enforcer.SavePolicy()
}

// updateUserRoleInDB updates user role assignment in the database
func (a *AuthorizationService) updateUserRoleInDB(userID string, roleName string, add bool) error {
	var user models.User
	if err := a.db.Preload("Roles").Where("id = ?", userID).First(&user).Error; err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "User not found")
	}

	var role models.Role
	if err := a.db.Where("name = ?", roleName).First(&role).Error; err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "Role not found")
	}

	if add {
		// Add role to user
		if err := a.db.Model(&user).Association("Roles").Append(&role); err != nil {
			return errors.Wrap(err, errors.CodeInternal, "Failed to add role to user")
		}
	} else {
		// Remove role from user
		if err := a.db.Model(&user).Association("Roles").Delete(&role); err != nil {
			return errors.Wrap(err, errors.CodeInternal, "Failed to remove role from user")
		}
	}

	return nil
}

// CheckPermission is a convenience method to check user permissions
func (a *AuthorizationService) CheckPermission(userID string, resource, action string) error {
	allowed, err := a.Enforce(userID, resource, action)
	if err != nil {
		return err
	}

	if !allowed {
		return errors.Forbidden(fmt.Sprintf("User %s does not have permission to %s %s", userID, action, resource))
	}

	return nil
}

// GetUserPermissions returns all permissions for a user (through their roles)
func (a *AuthorizationService) GetUserPermissions(userID string) ([]string, error) {
	roles, err := a.GetRolesForUser(userID)
	if err != nil {
		return nil, err
	}

	var allPermissions []string
	permissionSet := make(map[string]bool)

	for _, role := range roles {
		permissions, err := a.GetPermissionsForRole(role)
		if err != nil {
			return nil, err
		}

		for _, permission := range permissions {
			if len(permission) >= 3 {
				permStr := fmt.Sprintf("%s:%s", permission[1], permission[2]) // resource:action
				if !permissionSet[permStr] {
					allPermissions = append(allPermissions, permStr)
					permissionSet[permStr] = true
				}
			}
		}
	}

	return allPermissions, nil
}
