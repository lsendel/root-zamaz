// Package database provides database connection and management for the MVP Zero Trust Auth system.
// It includes GORM setup, PostgreSQL connection, automatic migrations,
// and database health checks with comprehensive error handling.
package database

import (
	"context"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"mvp.local/pkg/config"
	"mvp.local/pkg/errors"
	"mvp.local/pkg/models"
)

// Database represents the database connection and configuration
type Database struct {
	DB     *gorm.DB
	config *config.DatabaseConfig
}

// DatabaseInterface defines the contract for database operations
type DatabaseInterface interface {
	Connect() error
	Close() error
	Migrate() error
	Health() error
	GetDB() *gorm.DB
	Transaction(fn func(tx *gorm.DB) error) error
}

// NewDatabase creates a new database instance with the provided configuration
func NewDatabase(cfg *config.DatabaseConfig) *Database {
	return &Database{
		config: cfg,
	}
}

// Connect establishes a connection to the PostgreSQL database using GORM
func (d *Database) Connect() error {
	// Build DSN (Data Source Name) for PostgreSQL
	dsn := d.config.DatabaseDSN()

	// Configure GORM logger based on environment
	var gormLogger logger.Interface
	gormLogger = logger.Default.LogMode(logger.Info)

	// GORM configuration
	gormConfig := &gorm.Config{
		Logger: gormLogger,
		NamingStrategy: nil, // Use default naming strategy
	}

	// Connect to database
	db, err := gorm.Open(postgres.Open(dsn), gormConfig)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to connect to database")
	}

	// Get underlying sql.DB for connection pool configuration
	sqlDB, err := db.DB()
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to get underlying database connection")
	}

	// Configure connection pool
	sqlDB.SetMaxOpenConns(d.config.MaxConnections)
	sqlDB.SetMaxIdleConns(d.config.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(d.config.ConnMaxLifetime)

	// Test the connection
	if err := sqlDB.Ping(); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to ping database")
	}

	d.DB = db
	return nil
}

// Close closes the database connection
func (d *Database) Close() error {
	if d.DB == nil {
		return nil
	}

	sqlDB, err := d.DB.DB()
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to get underlying database connection")
	}

	if err := sqlDB.Close(); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to close database connection")
	}

	return nil
}

// Migrate runs database migrations for all models
func (d *Database) Migrate() error {
	if d.DB == nil {
		return errors.Internal("Database connection not established")
	}

	// Auto-migrate all models
	err := d.DB.AutoMigrate(
		&models.User{},
		&models.UserSession{},
		&models.DeviceAttestation{},
		&models.Role{},
		&models.Permission{},
		&models.AuditLog{},
	)

	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to run database migrations")
	}

	// Create default roles and permissions
	if err := d.seedDefaultData(); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to seed default data")
	}

	return nil
}

// seedDefaultData creates default roles and permissions if they don't exist
func (d *Database) seedDefaultData() error {
	// Create default roles
	defaultRoles := []models.Role{
		{
			Name:        "admin",
			Description: "System administrator with full access",
			IsActive:    true,
		},
		{
			Name:        "user",
			Description: "Regular user with limited access",
			IsActive:    true,
		},
		{
			Name:        "device_manager",
			Description: "User who can manage device attestations",
			IsActive:    true,
		},
	}

	for _, role := range defaultRoles {
		var existingRole models.Role
		result := d.DB.Where("name = ?", role.Name).First(&existingRole)
		if result.Error == gorm.ErrRecordNotFound {
			if err := d.DB.Create(&role).Error; err != nil {
				return fmt.Errorf("failed to create role %s: %w", role.Name, err)
			}
		}
	}

	// Create default permissions
	defaultPermissions := []models.Permission{
		{Name: "user.read", Resource: "user", Action: "read", Description: "Read user information", IsActive: true},
		{Name: "user.write", Resource: "user", Action: "write", Description: "Create and update users", IsActive: true},
		{Name: "user.delete", Resource: "user", Action: "delete", Description: "Delete users", IsActive: true},
		{Name: "user.admin", Resource: "user", Action: "admin", Description: "Full user administration", IsActive: true},
		
		{Name: "device.read", Resource: "device", Action: "read", Description: "Read device attestations", IsActive: true},
		{Name: "device.write", Resource: "device", Action: "write", Description: "Create and update device attestations", IsActive: true},
		{Name: "device.delete", Resource: "device", Action: "delete", Description: "Delete device attestations", IsActive: true},
		{Name: "device.verify", Resource: "device", Action: "verify", Description: "Verify device attestations", IsActive: true},
		
		{Name: "system.read", Resource: "system", Action: "read", Description: "Read system information", IsActive: true},
		{Name: "system.admin", Resource: "system", Action: "admin", Description: "Full system administration", IsActive: true},
		
		{Name: "audit.read", Resource: "audit", Action: "read", Description: "Read audit logs", IsActive: true},
	}

	for _, permission := range defaultPermissions {
		var existingPermission models.Permission
		result := d.DB.Where("name = ?", permission.Name).First(&existingPermission)
		if result.Error == gorm.ErrRecordNotFound {
			if err := d.DB.Create(&permission).Error; err != nil {
				return fmt.Errorf("failed to create permission %s: %w", permission.Name, err)
			}
		}
	}

	// Assign permissions to roles
	if err := d.assignDefaultRolePermissions(); err != nil {
		return fmt.Errorf("failed to assign default role permissions: %w", err)
	}

	return nil
}

// assignDefaultRolePermissions assigns default permissions to roles
func (d *Database) assignDefaultRolePermissions() error {
	// Admin role gets all permissions
	var adminRole models.Role
	if err := d.DB.Where("name = ?", "admin").First(&adminRole).Error; err != nil {
		return err
	}

	var allPermissions []models.Permission
	if err := d.DB.Find(&allPermissions).Error; err != nil {
		return err
	}

	if err := d.DB.Model(&adminRole).Association("Permissions").Replace(allPermissions); err != nil {
		return err
	}

	// User role gets basic permissions
	var userRole models.Role
	if err := d.DB.Where("name = ?", "user").First(&userRole).Error; err != nil {
		return err
	}

	var userPermissions []models.Permission
	userPermissionNames := []string{"user.read", "device.read", "system.read"}
	if err := d.DB.Where("name IN ?", userPermissionNames).Find(&userPermissions).Error; err != nil {
		return err
	}

	if err := d.DB.Model(&userRole).Association("Permissions").Replace(userPermissions); err != nil {
		return err
	}

	// Device manager role gets device permissions
	var deviceManagerRole models.Role
	if err := d.DB.Where("name = ?", "device_manager").First(&deviceManagerRole).Error; err != nil {
		return err
	}

	var devicePermissions []models.Permission
	devicePermissionNames := []string{"user.read", "device.read", "device.write", "device.verify", "system.read"}
	if err := d.DB.Where("name IN ?", devicePermissionNames).Find(&devicePermissions).Error; err != nil {
		return err
	}

	if err := d.DB.Model(&deviceManagerRole).Association("Permissions").Replace(devicePermissions); err != nil {
		return err
	}

	return nil
}

// Health checks the database connection and returns health status
func (d *Database) Health() error {
	if d.DB == nil {
		return errors.Internal("Database connection not established")
	}

	sqlDB, err := d.DB.DB()
	if err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to get underlying database connection")
	}

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Database health check failed")
	}

	return nil
}

// GetDB returns the GORM database instance
func (d *Database) GetDB() *gorm.DB {
	return d.DB
}

// Transaction executes a function within a database transaction
func (d *Database) Transaction(fn func(tx *gorm.DB) error) error {
	if d.DB == nil {
		return errors.Internal("Database connection not established")
	}

	return d.DB.Transaction(fn)
}

// GetStats returns database connection statistics
func (d *Database) GetStats() (map[string]interface{}, error) {
	if d.DB == nil {
		return nil, errors.Internal("Database connection not established")
	}

	sqlDB, err := d.DB.DB()
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to get underlying database connection")
	}

	stats := sqlDB.Stats()
	
	return map[string]interface{}{
		"max_open_connections": stats.MaxOpenConnections,
		"open_connections":     stats.OpenConnections,
		"in_use":              stats.InUse,
		"idle":                stats.Idle,
		"wait_count":          stats.WaitCount,
		"wait_duration":       stats.WaitDuration.String(),
		"max_idle_closed":     stats.MaxIdleClosed,
		"max_idle_time_closed": stats.MaxIdleTimeClosed,
		"max_lifetime_closed": stats.MaxLifetimeClosed,
	}, nil
}