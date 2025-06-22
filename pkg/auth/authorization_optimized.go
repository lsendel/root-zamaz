package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
	
	"gorm.io/gorm"
	
	"mvp.local/pkg/errors"
	"mvp.local/pkg/models"
)

// PaginationConfig defines configuration for paginated queries
type PaginationConfig struct {
	BatchSize    int           // Number of records per batch
	MaxGoroutines int          // Maximum concurrent goroutines for processing
	IdleTimeout  time.Duration // Timeout for idle batches
}

// DefaultPaginationConfig returns sensible defaults for pagination
func DefaultPaginationConfig() PaginationConfig {
	return PaginationConfig{
		BatchSize:     100,
		MaxGoroutines: 4,
		IdleTimeout:   30 * time.Second,
	}
}

// syncDatabaseToPolicyOptimized synchronizes database roles and permissions using pagination
func (a *AuthorizationService) syncDatabaseToPolicyOptimized(config PaginationConfig) error {
	// Load existing policy from database
	if err := a.enforcer.LoadPolicy(); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to load existing policy")
	}
	
	// Process roles with pagination
	if err := a.syncRolesWithPagination(config); err != nil {
		return err
	}
	
	// Process user roles with pagination
	if err := a.syncUserRolesWithPagination(config); err != nil {
		return err
	}
	
	// Log sync completion
	if a.obs != nil {
		a.obs.Logger.Info().
			Int("batch_size", config.BatchSize).
			Msg("Database to policy sync completed")
	}
	
	return nil
}

// syncRolesWithPagination processes roles in batches
func (a *AuthorizationService) syncRolesWithPagination(config PaginationConfig) error {
	var totalCount int64
	if err := a.db.Model(&models.Role{}).Count(&totalCount).Error; err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to count roles")
	}
	
	// Calculate number of batches
	batches := int((totalCount + int64(config.BatchSize) - 1) / int64(config.BatchSize))
	
	// Use a worker pool to process batches concurrently
	errChan := make(chan error, batches)
	sem := make(chan struct{}, config.MaxGoroutines)
	var wg sync.WaitGroup
	
	for i := 0; i < batches; i++ {
		offset := i * config.BatchSize
		
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			
			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()
			
			if err := a.processRoleBatch(offset, config.BatchSize); err != nil {
				errChan <- err
			}
		}(offset)
	}
	
	// Wait for all workers to complete
	wg.Wait()
	close(errChan)
	
	// Check for errors
	for err := range errChan {
		if err != nil {
			return err
		}
	}
	
	return nil
}

// processRoleBatch processes a single batch of roles
func (a *AuthorizationService) processRoleBatch(offset, limit int) error {
	var roles []models.Role
	
	// Use optimized query with selective preloading
	err := a.db.
		Preload("Permissions", "is_active = ?", true). // Only load active permissions
		Limit(limit).
		Offset(offset).
		Find(&roles).Error
		
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, fmt.Sprintf("Failed to load roles batch at offset %d", offset))
	}
	
	// Process roles in batch
	for _, role := range roles {
		for _, permission := range role.Permissions {
			// Skip if permission is not active (redundant check for safety)
			if !permission.IsActive {
				continue
			}
			
			// Check if permission already exists to avoid duplicates
			hasPermission, _ := a.enforcer.HasPermissionForUser(role.Name, permission.Resource, permission.Action)
			if !hasPermission {
				_, err := a.enforcer.AddPermissionForUser(role.Name, permission.Resource, permission.Action)
				if err != nil {
					// Log error but continue processing
					if a.obs != nil {
						a.obs.Logger.Error().
							Err(err).
							Str("role", role.Name).
							Str("permission", permission.Name).
							Msg("Failed to add permission for role")
					}
				}
			}
		}
	}
	
	return nil
}

// syncUserRolesWithPagination processes user roles in batches
func (a *AuthorizationService) syncUserRolesWithPagination(config PaginationConfig) error {
	var totalCount int64
	if err := a.db.Model(&models.User{}).Count(&totalCount).Error; err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to count users")
	}
	
	// Calculate number of batches
	batches := int((totalCount + int64(config.BatchSize) - 1) / int64(config.BatchSize))
	
	// Use a worker pool to process batches concurrently
	errChan := make(chan error, batches)
	sem := make(chan struct{}, config.MaxGoroutines)
	var wg sync.WaitGroup
	
	for i := 0; i < batches; i++ {
		offset := i * config.BatchSize
		
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			
			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()
			
			if err := a.processUserBatch(offset, config.BatchSize); err != nil {
				errChan <- err
			}
		}(offset)
	}
	
	// Wait for all workers to complete
	wg.Wait()
	close(errChan)
	
	// Check for errors
	for err := range errChan {
		if err != nil {
			return err
		}
	}
	
	return nil
}

// processUserBatch processes a single batch of users
func (a *AuthorizationService) processUserBatch(offset, limit int) error {
	var users []models.User
	
	// Use optimized query with selective preloading
	err := a.db.
		Preload("Roles", "is_active = ?", true). // Only load active roles
		Limit(limit).
		Offset(offset).
		Find(&users).Error
		
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, fmt.Sprintf("Failed to load users batch at offset %d", offset))
	}
	
	// Process users in batch
	for _, user := range users {
		for _, role := range user.Roles {
			// Skip if role is not active (redundant check for safety)
			if !role.IsActive {
				continue
			}
			
			// Check if role assignment already exists to avoid duplicates
			hasRole, _ := a.enforcer.HasRoleForUser(user.ID.String(), role.Name)
			if !hasRole {
				_, err := a.enforcer.AddRoleForUser(user.ID.String(), role.Name)
				if err != nil {
					// Log error but continue processing
					if a.obs != nil {
						a.obs.Logger.Error().
							Err(err).
							Str("user_id", user.ID.String()).
							Str("role", role.Name).
							Msg("Failed to add role for user")
					}
				}
			}
		}
	}
	
	return nil
}

// GetPermissionsForRoleOptimized retrieves permissions with caching and pagination
func (a *AuthorizationService) GetPermissionsForRoleOptimized(role string, limit, offset int) ([][]string, int64, error) {
	if err := a.ensureInitialized(); err != nil {
		return nil, 0, err
	}
	
	// Try to get from cache first
	cacheKey := RolePermissionsCachePrefix + role
	if a.cache != nil {
		if cached, err := a.cache.Get(context.Background(), cacheKey); err == nil && cached != nil {
			var permissions [][]string
			if err := json.Unmarshal(cached, &permissions); err == nil {
				// For cached results, apply pagination in memory
				total := int64(len(permissions))
				start := offset
				end := offset + limit
				
				if start > len(permissions) {
					return [][]string{}, total, nil
				}
				if end > len(permissions) {
					end = len(permissions)
				}
				
				return permissions[start:end], total, nil
			}
		}
	}
	
	// Get all permissions for the role (Casbin doesn't support pagination natively)
	allPermissions := a.enforcer.GetPermissionsForUser(role)
	total := int64(len(allPermissions))
	
	// Apply pagination
	start := offset
	end := offset + limit
	
	if start > len(allPermissions) {
		return [][]string{}, total, nil
	}
	if end > len(allPermissions) {
		end = len(allPermissions)
	}
	
	permissions := allPermissions[start:end]
	
	// Cache the full result set
	if a.cache != nil && offset == 0 {
		if data, err := json.Marshal(allPermissions); err == nil {
			_ = a.cache.Set(context.Background(), cacheKey, data, CacheTTL)
		}
	}
	
	return permissions, total, nil
}

// CreateDatabaseIndexes creates indexes for frequently queried fields
func (a *AuthorizationService) CreateDatabaseIndexes() error {
	// Create indexes for better query performance
	indexes := []struct {
		Table   string
		Columns []string
	}{
		{"roles", []string{"name", "is_active"}},
		{"permissions", []string{"resource", "action", "is_active"}},
		{"user_roles", []string{"user_id", "role_id"}},
		{"role_permissions", []string{"role_id", "permission_id"}},
	}
	
	for _, idx := range indexes {
		indexName := fmt.Sprintf("idx_%s_%s", idx.Table, strings.Join(idx.Columns, "_"))
		
		// Create index if it doesn't exist
		if err := a.db.Exec(fmt.Sprintf(
			"CREATE INDEX IF NOT EXISTS %s ON %s (%s)",
			indexName, idx.Table, strings.Join(idx.Columns, ", "),
		)).Error; err != nil {
			// Log warning but don't fail
			if a.obs != nil {
				a.obs.Logger.Warn().
					Err(err).
					Str("index", indexName).
					Msg("Failed to create database index")
			}
		}
	}
	
	return nil
}