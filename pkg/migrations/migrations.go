// Package migrations provides database migration functionality for the MVP Zero Trust Auth system.
package migrations

import (
	"fmt"
	"sort"
	"strings"
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

	// Split SQL into individual statements
	statements := splitSQL(migration.UpSQL)

	// Execute each statement separately
	for i, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" || strings.HasPrefix(stmt, "--") {
			continue // Skip empty lines and comments
		}

		if err := tx.Exec(stmt).Error; err != nil {
			tx.Rollback()
			return errors.Wrap(err, errors.CodeInternal, fmt.Sprintf("Failed to execute migration %s statement %d: %s", migration.ID, i+1, stmt))
		}
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

// splitSQL splits a multi-statement SQL string into individual statements
func splitSQL(sql string) []string {
	// Split on semicolons but be careful about quoted strings
	var statements []string
	var current strings.Builder
	inQuotes := false
	inComment := false

	lines := strings.Split(sql, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines
		if line == "" {
			continue
		}

		// Skip comment lines
		if strings.HasPrefix(line, "--") {
			continue
		}

		// Check for SQL statements that end with semicolon
		if strings.HasSuffix(line, ";") && !inQuotes && !inComment {
			current.WriteString(line[:len(line)-1]) // Remove the semicolon
			stmt := strings.TrimSpace(current.String())
			if stmt != "" {
				statements = append(statements, stmt)
			}
			current.Reset()
		} else {
			if current.Len() > 0 {
				current.WriteString("\n")
			}
			current.WriteString(line)
		}
	}

	// Add any remaining statement
	if current.Len() > 0 {
		stmt := strings.TrimSpace(current.String())
		if stmt != "" {
			statements = append(statements, stmt)
		}
	}

	return statements
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
    trust_level INTEGER DEFAULT 0,
    is_verified BOOLEAN DEFAULT false,
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
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description VARCHAR(200),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description VARCHAR(200),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- User roles junction table
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_by UUID REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);

-- Role permissions junction table
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
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
			ID:          "003_add_security_tables",
			Description: "Add audit logs and login attempts tables for security monitoring",
			Version:     1640995400, // 2022-01-01 + 200 seconds
			UpSQL: `
-- Login attempts table for security tracking and rate limiting
CREATE TABLE IF NOT EXISTS login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) NOT NULL,
    user_id UUID REFERENCES users(id),
    ip_address VARCHAR(45) NOT NULL,
    user_agent VARCHAR(500),
    success BOOLEAN DEFAULT false,
    failure_reason VARCHAR(200),
    is_suspicious BOOLEAN DEFAULT false,
    blocked_by_rate BOOLEAN DEFAULT false,
    request_id VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- User sessions table for session management
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN DEFAULT true,
    device_id VARCHAR(100),
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    location VARCHAR(100),
    trust_level INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100) NOT NULL,
    details JSONB,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    request_id VARCHAR(100),
    success BOOLEAN DEFAULT false,
    error_msg VARCHAR(500),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create basic indexes
CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_address ON login_attempts(ip_address);
CREATE INDEX IF NOT EXISTS idx_login_attempts_created_at ON login_attempts(created_at);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_session_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
`,
			DownSQL: `
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS login_attempts;
`,
		},
		{
			ID:          "004_add_performance_indexes",
			Description: "Add comprehensive performance indexes for critical query patterns",
			Version:     1640995500, // 2022-01-01 + 300 seconds
			UpSQL: `
-- Users table performance indexes
CREATE INDEX IF NOT EXISTS idx_users_email_active ON users(email) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_users_username_active ON users(username) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_users_failed_login_attempts ON users(failed_login_attempts) WHERE failed_login_attempts > 0;
CREATE INDEX IF NOT EXISTS idx_users_account_locked ON users(account_locked_until) WHERE account_locked_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login_at DESC);

-- Login attempts performance indexes - for rate limiting and security analysis
CREATE INDEX IF NOT EXISTS idx_login_attempts_username_created ON login_attempts(username, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_created ON login_attempts(ip_address, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_attempts_success_created ON login_attempts(success, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_attempts_suspicious ON login_attempts(is_suspicious) WHERE is_suspicious = true;
CREATE INDEX IF NOT EXISTS idx_login_attempts_user_success ON login_attempts(user_id, success, created_at DESC);

-- Audit logs performance indexes - for security analysis and reporting
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_created ON audit_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_created ON audit_logs(action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_success_created ON audit_logs(success, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip_created ON audit_logs(ip_address, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_action ON audit_logs(resource, action);

-- User sessions performance indexes - for session management
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_active ON user_sessions(user_id, is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_sessions_device_user ON user_sessions(device_id, user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_ip_created ON user_sessions(ip_address, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token_active ON user_sessions(session_token) WHERE is_active = true;

-- Device attestations performance indexes - for Zero Trust verification
CREATE INDEX IF NOT EXISTS idx_device_attestations_user_status ON device_attestations(user_id, is_verified, trust_level);
CREATE INDEX IF NOT EXISTS idx_device_attestations_device_verified ON device_attestations(device_id, is_verified);
CREATE INDEX IF NOT EXISTS idx_device_attestations_platform_trust ON device_attestations(platform, trust_level);
CREATE INDEX IF NOT EXISTS idx_device_attestations_spiffe_id ON device_attestations(spiffe_id);
CREATE INDEX IF NOT EXISTS idx_device_attestations_verified_at ON device_attestations(verified_at DESC) WHERE verified_at IS NOT NULL;

-- RBAC performance indexes
CREATE INDEX IF NOT EXISTS idx_roles_name_active ON roles(name) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_permissions_resource_action_active ON permissions(resource, action) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_permissions_name_active ON permissions(name) WHERE is_active = true;

-- Junction table performance indexes for many-to-many relationships
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id_opt ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id_opt ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id_opt ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id_opt ON role_permissions(permission_id);

-- Composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_action_time ON audit_logs(user_id, action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_device_active ON user_sessions(user_id, device_id, is_active);
`,
			DownSQL: `
-- Drop performance indexes
DROP INDEX IF EXISTS idx_users_email_active;
DROP INDEX IF EXISTS idx_users_username_active;
DROP INDEX IF EXISTS idx_users_failed_login_attempts;
DROP INDEX IF EXISTS idx_users_account_locked;
DROP INDEX IF EXISTS idx_users_last_login;
DROP INDEX IF EXISTS idx_login_attempts_username_created;
DROP INDEX IF EXISTS idx_login_attempts_ip_created;
DROP INDEX IF EXISTS idx_login_attempts_success_created;
DROP INDEX IF EXISTS idx_login_attempts_suspicious;
DROP INDEX IF EXISTS idx_login_attempts_user_success;
DROP INDEX IF EXISTS idx_audit_logs_user_created;
DROP INDEX IF EXISTS idx_audit_logs_action_created;
DROP INDEX IF EXISTS idx_audit_logs_success_created;
DROP INDEX IF EXISTS idx_audit_logs_ip_created;
DROP INDEX IF EXISTS idx_audit_logs_resource_action;
DROP INDEX IF EXISTS idx_user_sessions_user_active;
DROP INDEX IF EXISTS idx_user_sessions_expires_at;
DROP INDEX IF EXISTS idx_user_sessions_device_user;
DROP INDEX IF EXISTS idx_user_sessions_ip_created;
DROP INDEX IF EXISTS idx_user_sessions_token_active;
DROP INDEX IF EXISTS idx_device_attestations_user_status;
DROP INDEX IF EXISTS idx_device_attestations_device_verified;
DROP INDEX IF EXISTS idx_device_attestations_platform_trust;
DROP INDEX IF EXISTS idx_device_attestations_spiffe_id;
DROP INDEX IF EXISTS idx_device_attestations_verified_at;
DROP INDEX IF EXISTS idx_roles_name_active;
DROP INDEX IF EXISTS idx_permissions_resource_action_active;
DROP INDEX IF EXISTS idx_permissions_name_active;
DROP INDEX IF EXISTS idx_user_roles_user_id_opt;
DROP INDEX IF EXISTS idx_user_roles_role_id_opt;
DROP INDEX IF EXISTS idx_role_permissions_role_id_opt;
DROP INDEX IF EXISTS idx_role_permissions_permission_id_opt;
DROP INDEX IF EXISTS idx_audit_logs_user_action_time;
DROP INDEX IF EXISTS idx_user_sessions_user_device_active;
`,
		},
		{
			ID:          "005_audit_compliance_fields",
			Description: "Add compliance tag and retention fields to audit logs",
			Version:     1640995600, // 2022-01-01 + 400 seconds
			UpSQL: `
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS compliance_tag VARCHAR(50);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS retain_until TIMESTAMP WITH TIME ZONE;
`,
			DownSQL: `
ALTER TABLE audit_logs DROP COLUMN IF EXISTS compliance_tag;
ALTER TABLE audit_logs DROP COLUMN IF EXISTS retain_until;
`,
		},
		{
			ID:          "006_compliance_audit_logs",
			Description: "Create comprehensive compliance audit logs table",
			Version:     1640995700, // 2022-01-01 + 500 seconds
			UpSQL: `
-- Compliance audit logs table with enhanced features
CREATE TABLE IF NOT EXISTS compliance_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,

    -- Basic audit fields
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    details JSONB,
    success BOOLEAN DEFAULT false,
    error_msg VARCHAR(500),

    -- Request context
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    request_id VARCHAR(100),
    session_id VARCHAR(100),
    tenant_id VARCHAR(100),

    -- Compliance-specific fields
    compliance_frameworks VARCHAR(200), -- Comma-separated
    data_classification VARCHAR(50),
    sensitivity_level INTEGER DEFAULT 1 CHECK (sensitivity_level >= 1 AND sensitivity_level <= 5),
    legal_basis VARCHAR(50),
    data_subjects JSONB,
    data_categories JSONB,
    processing_purpose VARCHAR(500),
    geolocation_country VARCHAR(10),

    -- Risk and controls
    risk_score INTEGER DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    controls_applied JSONB,
    approval_required BOOLEAN DEFAULT false,
    approval_status VARCHAR(50),
    review_status VARCHAR(50),

    -- Retention and lifecycle
    retention_category VARCHAR(50),
    business_justification VARCHAR(1000),
    retain_until TIMESTAMP WITH TIME ZONE,
    archive_date TIMESTAMP WITH TIME ZONE,
    purge_date TIMESTAMP WITH TIME ZONE,
    
    -- Lifecycle tracking
    archived BOOLEAN DEFAULT false,
    archived_at TIMESTAMP WITH TIME ZONE,

    -- Context and metadata
    business_context JSONB,
    technical_context JSONB
);

-- Performance indexes for compliance audit logs
CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_user_id ON compliance_audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_action ON compliance_audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_created_at ON compliance_audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_data_classification ON compliance_audit_logs(data_classification);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_sensitivity_level ON compliance_audit_logs(sensitivity_level);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_risk_score ON compliance_audit_logs(risk_score);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_retention_category ON compliance_audit_logs(retention_category);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_archive_date ON compliance_audit_logs(archive_date);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_purge_date ON compliance_audit_logs(purge_date);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_archived ON compliance_audit_logs(archived);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_geolocation ON compliance_audit_logs(geolocation_country);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_request_id ON compliance_audit_logs(request_id);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_session_id ON compliance_audit_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_tenant_id ON compliance_audit_logs(tenant_id);

-- Composite indexes for common compliance queries
CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_user_time ON compliance_audit_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_classification_risk ON compliance_audit_logs(data_classification, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_logs_retention_archive ON compliance_audit_logs(retention_category, archive_date);
`,
			DownSQL: `
DROP TABLE IF EXISTS compliance_audit_logs;
`,
		},
		{
			ID:          "007_compliance_violations",
			Description: "Create compliance violations tracking table",
			Version:     1640995800, // 2022-01-01 + 600 seconds
			UpSQL: `
-- Compliance violations table
CREATE TABLE IF NOT EXISTS compliance_violations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,

    -- Associated audit log
    audit_log_id UUID NOT NULL REFERENCES compliance_audit_logs(id) ON DELETE CASCADE,

    -- Violation details
    violation_type VARCHAR(100) NOT NULL,
    framework VARCHAR(50),
    severity INTEGER NOT NULL CHECK (severity >= 1 AND severity <= 5),
    description VARCHAR(1000),
    remediation VARCHAR(1000),
    risk_score INTEGER DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),

    -- Resolution tracking
    status VARCHAR(50) DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'ACCEPTED')),
    assigned_to VARCHAR(100),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution VARCHAR(1000),
    resolution_by VARCHAR(100)
);

-- Performance indexes for compliance violations
CREATE INDEX IF NOT EXISTS idx_compliance_violations_audit_log_id ON compliance_violations(audit_log_id);
CREATE INDEX IF NOT EXISTS idx_compliance_violations_violation_type ON compliance_violations(violation_type);
CREATE INDEX IF NOT EXISTS idx_compliance_violations_framework ON compliance_violations(framework);
CREATE INDEX IF NOT EXISTS idx_compliance_violations_severity ON compliance_violations(severity);
CREATE INDEX IF NOT EXISTS idx_compliance_violations_status ON compliance_violations(status);
CREATE INDEX IF NOT EXISTS idx_compliance_violations_created_at ON compliance_violations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_violations_assigned_to ON compliance_violations(assigned_to);
CREATE INDEX IF NOT EXISTS idx_compliance_violations_resolved_at ON compliance_violations(resolved_at DESC);

-- Composite indexes for common violation queries
CREATE INDEX IF NOT EXISTS idx_compliance_violations_framework_severity ON compliance_violations(framework, severity DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_violations_status_created ON compliance_violations(status, created_at DESC);
`,
			DownSQL: `
DROP TABLE IF EXISTS compliance_violations;
`,
		},
		{
			ID:          "008_gdpr_data_subject_requests",
			Description: "Create GDPR data subject requests table",
			Version:     1640995900, // 2022-01-01 + 700 seconds
			UpSQL: `
-- Data subject requests table for GDPR compliance
CREATE TABLE IF NOT EXISTS data_subject_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,

    -- Request details
    request_type VARCHAR(50) NOT NULL CHECK (request_type IN ('ACCESS', 'RECTIFICATION', 'ERASURE', 'RESTRICTION', 'PORTABILITY', 'OBJECTION')),
    data_subject VARCHAR(255) NOT NULL,
    requestor_id VARCHAR(100),
    
    -- Contact information
    email VARCHAR(255),
    phone_number VARCHAR(50),
    
    -- Request processing
    status VARCHAR(50) DEFAULT 'RECEIVED' CHECK (status IN ('RECEIVED', 'VERIFIED', 'PROCESSING', 'COMPLETED', 'REJECTED')),
    priority VARCHAR(20) DEFAULT 'NORMAL' CHECK (priority IN ('LOW', 'NORMAL', 'HIGH', 'URGENT')),
    assigned_to VARCHAR(100),
    due_date TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Legal basis and verification
    legal_basis VARCHAR(100),
    identity_verified BOOLEAN DEFAULT false,
    verification_method VARCHAR(100),
    verified_by VARCHAR(100),
    verified_at TIMESTAMP WITH TIME ZONE,
    
    -- Request details
    description VARCHAR(2000),
    data_categories JSONB,
    processing_purposes JSONB,
    
    -- Response and resolution
    response TEXT,
    response_method VARCHAR(50) CHECK (response_method IN ('EMAIL', 'POSTAL', 'SECURE_PORTAL')),
    rejection_reason VARCHAR(1000),
    
    -- Compliance tracking
    compliance_notes TEXT,
    reviewed_by VARCHAR(100),
    reviewed_at TIMESTAMP WITH TIME ZONE
);

-- Performance indexes for data subject requests
CREATE INDEX IF NOT EXISTS idx_data_subject_requests_request_type ON data_subject_requests(request_type);
CREATE INDEX IF NOT EXISTS idx_data_subject_requests_data_subject ON data_subject_requests(data_subject);
CREATE INDEX IF NOT EXISTS idx_data_subject_requests_status ON data_subject_requests(status);
CREATE INDEX IF NOT EXISTS idx_data_subject_requests_priority ON data_subject_requests(priority);
CREATE INDEX IF NOT EXISTS idx_data_subject_requests_due_date ON data_subject_requests(due_date);
CREATE INDEX IF NOT EXISTS idx_data_subject_requests_created_at ON data_subject_requests(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_data_subject_requests_assigned_to ON data_subject_requests(assigned_to);
CREATE INDEX IF NOT EXISTS idx_data_subject_requests_completed_at ON data_subject_requests(completed_at DESC);

-- Composite indexes for common DSR queries
CREATE INDEX IF NOT EXISTS idx_data_subject_requests_type_status ON data_subject_requests(request_type, status);
CREATE INDEX IF NOT EXISTS idx_data_subject_requests_status_due ON data_subject_requests(status, due_date);
`,
			DownSQL: `
DROP TABLE IF EXISTS data_subject_requests;
`,
		},
		{
			ID:          "009_gdpr_consent_records",
			Description: "Create GDPR consent tracking table",
			Version:     1641000000, // 2022-01-01 + 800 seconds
			UpSQL: `
-- Consent records table for GDPR compliance
CREATE TABLE IF NOT EXISTS consent_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,

    -- Data subject
    data_subject VARCHAR(255) NOT NULL,
    user_id UUID REFERENCES users(id),
    
    -- Consent details
    consent_type VARCHAR(100) NOT NULL,
    purpose VARCHAR(500) NOT NULL,
    legal_basis VARCHAR(100),
    data_categories JSONB,
    
    -- Consent status
    status VARCHAR(50) NOT NULL CHECK (status IN ('GIVEN', 'WITHDRAWN', 'EXPIRED')),
    consent_given BOOLEAN NOT NULL,
    consent_date TIMESTAMP WITH TIME ZONE NOT NULL,
    withdrawn_date TIMESTAMP WITH TIME ZONE,
    expiry_date TIMESTAMP WITH TIME ZONE,
    
    -- Consent mechanism
    consent_method VARCHAR(100),
    consent_text TEXT,
    consent_version VARCHAR(20),
    
    -- Technical details
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    consent_proof JSONB,
    
    -- Withdrawal details
    withdrawal_method VARCHAR(100),
    withdrawal_reason VARCHAR(500)
);

-- Performance indexes for consent records
CREATE INDEX IF NOT EXISTS idx_consent_records_data_subject ON consent_records(data_subject);
CREATE INDEX IF NOT EXISTS idx_consent_records_user_id ON consent_records(user_id);
CREATE INDEX IF NOT EXISTS idx_consent_records_consent_type ON consent_records(consent_type);
CREATE INDEX IF NOT EXISTS idx_consent_records_status ON consent_records(status);
CREATE INDEX IF NOT EXISTS idx_consent_records_consent_given ON consent_records(consent_given);
CREATE INDEX IF NOT EXISTS idx_consent_records_consent_date ON consent_records(consent_date DESC);
CREATE INDEX IF NOT EXISTS idx_consent_records_withdrawn_date ON consent_records(withdrawn_date DESC);
CREATE INDEX IF NOT EXISTS idx_consent_records_expiry_date ON consent_records(expiry_date);

-- Composite indexes for common consent queries
CREATE INDEX IF NOT EXISTS idx_consent_records_subject_type ON consent_records(data_subject, consent_type);
CREATE INDEX IF NOT EXISTS idx_consent_records_status_date ON consent_records(status, consent_date DESC);
`,
			DownSQL: `
DROP TABLE IF EXISTS consent_records;
`,
		},
		{
			ID:          "010_retention_policies",
			Description: "Create retention policies configuration table",
			Version:     1641000100, // 2022-01-01 + 900 seconds
			UpSQL: `
-- Retention policies table
CREATE TABLE IF NOT EXISTS retention_policies (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,

    -- Policy identification
    name VARCHAR(100) UNIQUE NOT NULL,
    description VARCHAR(500),
    category VARCHAR(50) NOT NULL,
    
    -- Retention rules
    retention_period INTEGER NOT NULL,
    retention_unit VARCHAR(10) DEFAULT 'DAYS' CHECK (retention_unit IN ('DAYS', 'MONTHS', 'YEARS')),
    archive_period INTEGER,
    
    -- Applicability
    data_classification VARCHAR(50),
    compliance_framework VARCHAR(50),
    legal_basis VARCHAR(100),
    
    -- Policy status
    is_active BOOLEAN DEFAULT true,
    effective_date TIMESTAMP WITH TIME ZONE NOT NULL,
    expiry_date TIMESTAMP WITH TIME ZONE,
    
    -- Approval and governance
    approved_by VARCHAR(100),
    approved_at TIMESTAMP WITH TIME ZONE,
    review_date TIMESTAMP WITH TIME ZONE,
    reviewed_by VARCHAR(100),
    
    -- Policy rules
    rules JSONB,
    exceptions JSONB,
    automation_rules JSONB
);

-- Performance indexes for retention policies
CREATE INDEX IF NOT EXISTS idx_retention_policies_name ON retention_policies(name);
CREATE INDEX IF NOT EXISTS idx_retention_policies_category ON retention_policies(category);
CREATE INDEX IF NOT EXISTS idx_retention_policies_data_classification ON retention_policies(data_classification);
CREATE INDEX IF NOT EXISTS idx_retention_policies_compliance_framework ON retention_policies(compliance_framework);
CREATE INDEX IF NOT EXISTS idx_retention_policies_is_active ON retention_policies(is_active);
CREATE INDEX IF NOT EXISTS idx_retention_policies_effective_date ON retention_policies(effective_date);
CREATE INDEX IF NOT EXISTS idx_retention_policies_review_date ON retention_policies(review_date);
`,
			DownSQL: `
DROP TABLE IF EXISTS retention_policies;
`,
		},
		{
			ID:          "011_compliance_reports",
			Description: "Create compliance reports table",
			Version:     1641000200, // 2022-01-01 + 1000 seconds
			UpSQL: `
-- Compliance reports table
CREATE TABLE IF NOT EXISTS compliance_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,

    -- Report details
    report_type VARCHAR(100) NOT NULL,
    title VARCHAR(200) NOT NULL,
    description VARCHAR(1000),
    framework VARCHAR(50),
    
    -- Reporting period
    period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Report generation
    generated_by VARCHAR(100),
    generated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(50) DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'FINAL', 'PUBLISHED')),
    
    -- Report content
    executive_summary TEXT,
    findings JSONB,
    recommendations JSONB,
    metrics JSONB,
    
    -- Report metadata
    version VARCHAR(20),
    confidentiality VARCHAR(50) DEFAULT 'INTERNAL',
    
    -- Approval and distribution
    approved_by VARCHAR(100),
    approved_at TIMESTAMP WITH TIME ZONE,
    published_at TIMESTAMP WITH TIME ZONE,
    distribution JSONB
);

-- Performance indexes for compliance reports
CREATE INDEX IF NOT EXISTS idx_compliance_reports_report_type ON compliance_reports(report_type);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_framework ON compliance_reports(framework);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_status ON compliance_reports(status);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_period_start ON compliance_reports(period_start DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_generated_at ON compliance_reports(generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_generated_by ON compliance_reports(generated_by);

-- Composite indexes for common report queries
CREATE INDEX IF NOT EXISTS idx_compliance_reports_type_period ON compliance_reports(report_type, period_start DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_framework_period ON compliance_reports(framework, period_start DESC);
`,
			DownSQL: `
DROP TABLE IF EXISTS compliance_reports;
`,
		},
	}
}
