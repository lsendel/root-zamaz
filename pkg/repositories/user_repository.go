// Package repositories provides data access layer optimizations for the MVP Zero Trust Auth system.
package repositories

import (
	"gorm.io/gorm"

	"mvp.local/pkg/errors"
	"mvp.local/pkg/models"
)

// UserRepository provides optimized user data access methods
type UserRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// GetUserWithRolesAndPermissions fetches user with all related data in a single query
func (r *UserRepository) GetUserWithRolesAndPermissions(userID string) (*models.User, error) {
	var user models.User
	err := r.db.
		Preload("Roles", "is_active = ?", true).
		Preload("Roles.Permissions", "is_active = ?", true).
		Where("id = ? AND is_active = ?", userID, true).
		First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.NotFound("User not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to fetch user with roles and permissions")
	}

	return &user, nil
}

// GetUserByEmailWithRoles fetches user by email with roles preloaded
func (r *UserRepository) GetUserByEmailWithRoles(email string) (*models.User, error) {
	var user models.User
	err := r.db.
		Preload("Roles", "is_active = ?", true).
		Where("email = ? AND is_active = ?", email, true).
		First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.NotFound("User not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to fetch user by email")
	}

	return &user, nil
}

// GetUserByUsernameWithRoles fetches user by username with roles preloaded
func (r *UserRepository) GetUserByUsernameWithRoles(username string) (*models.User, error) {
	var user models.User
	err := r.db.
		Preload("Roles", "is_active = ?", true).
		Where("username = ? AND is_active = ?", username, true).
		First(&user).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.NotFound("User not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to fetch user by username")
	}

	return &user, nil
}

// GetUsersWithRolesPaginated fetches users with pagination and preloaded roles
func (r *UserRepository) GetUsersWithRolesPaginated(offset, limit int) ([]models.User, int64, error) {
	var users []models.User
	var total int64

	// Get total count
	if err := r.db.Model(&models.User{}).Where("is_active = ?", true).Count(&total).Error; err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeInternal, "Failed to count users")
	}

	// Get users with roles
	err := r.db.
		Preload("Roles", "is_active = ?", true).
		Where("is_active = ?", true).
		Offset(offset).
		Limit(limit).
		Order("created_at DESC").
		Find(&users).Error
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeInternal, "Failed to fetch users")
	}

	return users, total, nil
}

// GetUserSessionsWithDeviceInfo fetches user sessions with device information
func (r *UserRepository) GetUserSessionsWithDeviceInfo(userID string) ([]models.UserSession, error) {
	var sessions []models.UserSession
	err := r.db.
		Where("user_id = ? AND is_active = ?", userID, true).
		Order("created_at DESC").
		Find(&sessions).Error
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to fetch user sessions")
	}

	return sessions, nil
}

// GetUserDeviceAttestations fetches user device attestations
func (r *UserRepository) GetUserDeviceAttestations(userID string) ([]models.DeviceAttestation, error) {
	var attestations []models.DeviceAttestation
	err := r.db.
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&attestations).Error
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to fetch device attestations")
	}

	return attestations, nil
}

// BulkGetUserRoles fetches roles for multiple users efficiently
func (r *UserRepository) BulkGetUserRoles(userIDs []string) (map[string][]models.Role, error) {
	if len(userIDs) == 0 {
		return make(map[string][]models.Role), nil
	}

	type UserRole struct {
		UserID string      `json:"user_id"`
		RoleID int64       `json:"role_id"`
		Role   models.Role `json:"role"`
	}

	var userRoles []UserRole
	err := r.db.
		Table("user_roles").
		Select("user_roles.user_id, user_roles.role_id, roles.*").
		Joins("JOIN roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id IN ? AND roles.is_active = ?", userIDs, true).
		Scan(&userRoles).Error
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to bulk fetch user roles")
	}

	// Group roles by user ID
	result := make(map[string][]models.Role)
	for _, ur := range userRoles {
		result[ur.UserID] = append(result[ur.UserID], ur.Role)
	}

	return result, nil
}

// BulkGetRolePermissions fetches permissions for multiple roles efficiently
func (r *UserRepository) BulkGetRolePermissions(roleIDs []int64) (map[int64][]models.Permission, error) {
	if len(roleIDs) == 0 {
		return make(map[int64][]models.Permission), nil
	}

	type RolePermission struct {
		RoleID       int64             `json:"role_id"`
		PermissionID int64             `json:"permission_id"`
		Permission   models.Permission `json:"permission"`
	}

	var rolePermissions []RolePermission
	err := r.db.
		Table("role_permissions").
		Select("role_permissions.role_id, role_permissions.permission_id, permissions.*").
		Joins("JOIN permissions ON permissions.id = role_permissions.permission_id").
		Where("role_permissions.role_id IN ? AND permissions.is_active = ?", roleIDs, true).
		Scan(&rolePermissions).Error
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to bulk fetch role permissions")
	}

	// Group permissions by role ID
	result := make(map[int64][]models.Permission)
	for _, rp := range rolePermissions {
		result[rp.RoleID] = append(result[rp.RoleID], rp.Permission)
	}

	return result, nil
}

// GetRecentAuditLogs fetches recent audit logs with pagination and user info
func (r *UserRepository) GetRecentAuditLogs(offset, limit int) ([]models.AuditLog, int64, error) {
	var auditLogs []models.AuditLog
	var total int64

	// Get total count
	if err := r.db.Model(&models.AuditLog{}).Count(&total).Error; err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeInternal, "Failed to count audit logs")
	}

	// Get audit logs with user information
	err := r.db.
		Preload("User").
		Offset(offset).
		Limit(limit).
		Order("created_at DESC").
		Find(&auditLogs).Error
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeInternal, "Failed to fetch audit logs")
	}

	return auditLogs, total, nil
}

// GetLoginAttemptsByUser fetches login attempts for a user with pagination
func (r *UserRepository) GetLoginAttemptsByUser(userID string, offset, limit int) ([]models.LoginAttempt, int64, error) {
	var attempts []models.LoginAttempt
	var total int64

	// Get total count
	if err := r.db.Model(&models.LoginAttempt{}).Where("user_id = ?", userID).Count(&total).Error; err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeInternal, "Failed to count login attempts")
	}

	// Get login attempts
	err := r.db.
		Where("user_id = ?", userID).
		Offset(offset).
		Limit(limit).
		Order("created_at DESC").
		Find(&attempts).Error
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeInternal, "Failed to fetch login attempts")
	}

	return attempts, total, nil
}

// GetSuspiciousLoginAttempts fetches suspicious login attempts with user info
func (r *UserRepository) GetSuspiciousLoginAttempts(offset, limit int) ([]models.LoginAttempt, int64, error) {
	var attempts []models.LoginAttempt
	var total int64

	// Get total count
	if err := r.db.Model(&models.LoginAttempt{}).Where("is_suspicious = ?", true).Count(&total).Error; err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeInternal, "Failed to count suspicious login attempts")
	}

	// Get suspicious login attempts with user information
	err := r.db.
		Preload("User").
		Where("is_suspicious = ?", true).
		Offset(offset).
		Limit(limit).
		Order("created_at DESC").
		Find(&attempts).Error
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeInternal, "Failed to fetch suspicious login attempts")
	}

	return attempts, total, nil
}

// UserRepositoryInterface defines the contract for user repository operations
type UserRepositoryInterface interface {
	GetUserWithRolesAndPermissions(userID string) (*models.User, error)
	GetUserByEmailWithRoles(email string) (*models.User, error)
	GetUserByUsernameWithRoles(username string) (*models.User, error)
	GetUsersWithRolesPaginated(offset, limit int) ([]models.User, int64, error)
	GetUserSessionsWithDeviceInfo(userID string) ([]models.UserSession, error)
	GetUserDeviceAttestations(userID string) ([]models.DeviceAttestation, error)
	BulkGetUserRoles(userIDs []string) (map[string][]models.Role, error)
	BulkGetRolePermissions(roleIDs []int64) (map[int64][]models.Permission, error)
	GetRecentAuditLogs(offset, limit int) ([]models.AuditLog, int64, error)
	GetLoginAttemptsByUser(userID string, offset, limit int) ([]models.LoginAttempt, int64, error)
	GetSuspiciousLoginAttempts(offset, limit int) ([]models.LoginAttempt, int64, error)
}
