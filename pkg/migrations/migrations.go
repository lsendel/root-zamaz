// Package migrations provides database migration functionality for the MVP Zero Trust Auth system.
package migrations

import (
	"context"
	"fmt"
	"sort"
	"time"

	"gorm.io/gorm"
	"mvp.local/pkg/errors"
)

// Migration represents a database migration
type Migration struct {
	ID          string
	Description string
	Version     int64
	UpSQL       string
	DownSQL     string
	ExecutedAt  *time.Time
}

// MigrationRecord represents the database table for tracking migrations
type MigrationRecord struct {
	ID          string    `gorm:"primaryKey"`
	Description string    `gorm:"not null"`
	Version     int64     `gorm:"not null;uniqueIndex"`
	ExecutedAt  time.Time `gorm:"not null;default:CURRENT_TIMESTAMP"`
	Checksum    string    `gorm:"not null"`
}

// TableName returns the table name for migration records
func (MigrationRecord) TableName() string {
	return "schema_migrations"
}

// Migrator handles database migrations
type Migrator struct {
	db         *gorm.DB
	migrations []Migration
}

// NewMigrator creates a new migration manager
func NewMigrator(db *gorm.DB) *Migrator {
	return &Migrator{
		db:         db,
		migrations: GetAllMigrations(),
	}
}

// Initialize sets up the migration system
func (m *Migrator) Initialize() error {
	// Create migration tracking table
	if err := m.db.AutoMigrate(&MigrationRecord{}); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to create migration table")
	}
	return nil
}

// Migrate runs all pending migrations
func (m *Migrator) Migrate() error {
	if err := m.Initialize(); err != nil {
		return err
	}

	// Get executed migrations
	executed, err := m.getExecutedMigrations()
	if err != nil {
		return err
	}

	// Sort migrations by version
	sort.Slice(m.migrations, func(i, j int) bool {
		return m.migrations[i].Version < m.migrations[j].Version
	})

	// Run pending migrations
	for _, migration := range m.migrations {
		if _, exists := executed[migration.ID]; !exists {
			if err := m.runMigration(migration); err != nil {
				return errors.Wrap(err, errors.CodeInternal, fmt.Sprintf("Failed to run migration %s", migration.ID))
			}
		}
	}

	return nil
}

// Rollback rolls back the last migration
func (m *Migrator) Rollback() error {
	// Get the last executed migration
	var lastMigration MigrationRecord
	err := m.db.Order("version DESC").First(&lastMigration).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.NotFound("No migrations to rollback")
		}
		return errors.Wrap(err, errors.CodeInternal, "Failed to get last migration")
	}

	// Find the migration definition
	var targetMigration *Migration
	for _, migration := range m.migrations {
		if migration.ID == lastMigration.ID {
			targetMigration = &migration
			break
		}
	}

	if targetMigration == nil {
		return errors.NotFound(fmt.Sprintf("Migration definition not found for %s", lastMigration.ID))
	}

	// Run rollback
	return m.runRollback(*targetMigration)
}

// Status returns the current migration status
func (m *Migrator) Status() ([]MigrationStatus, error) {
	executed, err := m.getExecutedMigrations()
	if err != nil {
		return nil, err
	}

	var status []MigrationStatus
	for _, migration := range m.migrations {
		migrationStatus := MigrationStatus{
			ID:          migration.ID,
			Description: migration.Description,
			Version:     migration.Version,
			Applied:     false,
		}

		if record, exists := executed[migration.ID]; exists {
			migrationStatus.Applied = true
			migrationStatus.ExecutedAt = &record.ExecutedAt
		}

		status = append(status, migrationStatus)
	}

	// Sort by version
	sort.Slice(status, func(i, j int) bool {
		return status[i].Version < status[j].Version
	})

	return status, nil
}

// MigrationStatus represents the status of a migration
type MigrationStatus struct {
	ID          string     `json:"id"`
	Description string     `json:"description"`
	Version     int64      `json:"version"`
	Applied     bool       `json:"applied"`
	ExecutedAt  *time.Time `json:"executed_at,omitempty"`
}

// runMigration executes a migration
func (m *Migrator) runMigration(migration Migration) error {
	// Start transaction
	tx := m.db.Begin()
	if tx.Error != nil {
		return errors.Wrap(tx.Error, errors.CodeInternal, "Failed to start transaction")
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Execute migration SQL
	if err := tx.Exec(migration.UpSQL).Error; err != nil {
		tx.Rollback()
		return errors.Wrap(err, errors.CodeInternal, fmt.Sprintf("Failed to execute migration %s", migration.ID))
	}

	// Record migration
	record := MigrationRecord{
		ID:          migration.ID,
		Description: migration.Description,
		Version:     migration.Version,
		ExecutedAt:  time.Now(),
		Checksum:    calculateChecksum(migration.UpSQL),
	}

	if err := tx.Create(&record).Error; err != nil {
		tx.Rollback()
		return errors.Wrap(err, errors.CodeInternal, "Failed to record migration")
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to commit migration")
	}

	fmt.Printf("Applied migration: %s - %s\n", migration.ID, migration.Description)
	return nil
}

// runRollback executes a migration rollback
func (m *Migrator) runRollback(migration Migration) error {
	if migration.DownSQL == "" {
		return errors.Validation("Migration has no rollback SQL")
	}

	// Start transaction
	tx := m.db.Begin()
	if tx.Error != nil {
		return errors.Wrap(tx.Error, errors.CodeInternal, "Failed to start transaction")
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Execute rollback SQL
	if err := tx.Exec(migration.DownSQL).Error; err != nil {
		tx.Rollback()
		return errors.Wrap(err, errors.CodeInternal, fmt.Sprintf("Failed to rollback migration %s", migration.ID))
	}

	// Remove migration record
	if err := tx.Where("id = ?", migration.ID).Delete(&MigrationRecord{}).Error; err != nil {
		tx.Rollback()
		return errors.Wrap(err, errors.CodeInternal, "Failed to remove migration record")
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to commit rollback")
	}

	fmt.Printf("Rolled back migration: %s - %s\n", migration.ID, migration.Description)
	return nil
}

// getExecutedMigrations returns a map of executed migrations
func (m *Migrator) getExecutedMigrations() (map[string]MigrationRecord, error) {
	var records []MigrationRecord
	if err := m.db.Find(&records).Error; err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to get executed migrations")
	}

	executed := make(map[string]MigrationRecord)
	for _, record := range records {
		executed[record.ID] = record
	}

	return executed, nil
}

// calculateChecksum calculates a simple checksum for SQL content
func calculateChecksum(sql string) string {
	// Simple checksum implementation
	// In production, you might want to use a proper hash function
	var sum int
	for _, char := range sql {
		sum += int(char)
	}
	return fmt.Sprintf("%x", sum)
}

// CreateMigration creates a new migration file template
func CreateMigration(id, description string) Migration {
	return Migration{
		ID:          id,
		Description: description,
		Version:     time.Now().Unix(),
		UpSQL:       "-- Add your migration SQL here\n",
		DownSQL:     "-- Add your rollback SQL here\n",
	}
}

// GetAllMigrations returns all available migrations
func GetAllMigrations() []Migration {
	return []Migration{
		{
			ID:          "001_initial_schema",
			Description: "Create initial database schema",
			Version:     1640995200, // 2022-01-01
			UpSQL: `
-- Users table for authentication
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    is_active BOOLEAN DEFAULT true,
    is_admin BOOLEAN DEFAULT false,
    failed_login_attempts INTEGER DEFAULT 0,
    last_failed_login_at TIMESTAMP WITH TIME ZONE,
    account_locked_at TIMESTAMP WITH TIME ZONE,
    account_locked_until TIMESTAMP WITH TIME ZONE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Device attestations table
CREATE TABLE IF NOT EXISTS device_attestations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(255) UNIQUE NOT NULL,
    device_name VARCHAR(100) NOT NULL,
    platform VARCHAR(50) NOT NULL,
    spiffe_id VARCHAR(255),
    workload_selector VARCHAR(255),
    attestation_data JSONB,
    status VARCHAR(20) DEFAULT 'pending',
    verified_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_device_attestations_user_id ON device_attestations(user_id);
CREATE INDEX IF NOT EXISTS idx_device_attestations_device_id ON device_attestations(device_id);
CREATE INDEX IF NOT EXISTS idx_device_attestations_status ON device_attestations(status);
`,
			DownSQL: `
DROP TABLE IF EXISTS device_attestations;
DROP TABLE IF EXISTS users;
`,
		},
		{
			ID:          "002_add_rbac_tables",
			Description: "Add RBAC tables for roles and permissions",
			Version:     1640995300, // 2022-01-01 + 100 seconds
			UpSQL: `
-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- User roles junction table
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_by UUID REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);

-- Role permissions junction table
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
CREATE INDEX IF NOT EXISTS idx_permissions_resource_action ON permissions(resource, action);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);
`,
			DownSQL: `
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
`,
		},
		{
			ID:          "003_add_audit_log",
			Description: "Add audit log table for security monitoring",
			Version:     1640995400, // 2022-01-01 + 200 seconds
			UpSQL: `
-- Audit log table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255),
    details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    status VARCHAR(20) DEFAULT 'success',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for audit log queries
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs(status);
`,
			DownSQL: `
DROP TABLE IF EXISTS audit_logs;
`,
		},
	}
}