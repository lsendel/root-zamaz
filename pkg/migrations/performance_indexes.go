// Package migrations provides database migration functions for performance optimization
package migrations

import (
	"fmt"

	"gorm.io/gorm"
)

// AddPerformanceIndexes adds critical performance indexes to improve query performance
func AddPerformanceIndexes(db *gorm.DB) error {
	// Users table indexes
	indexes := []string{
		// Active users lookup - very common query pattern
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email_active ON users(email) WHERE is_active = true",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_username_active ON users(username) WHERE is_active = true",
		
		// Login security indexes
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_failed_login_attempts ON users(failed_login_attempts) WHERE failed_login_attempts > 0",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_account_locked ON users(account_locked_until) WHERE account_locked_until IS NOT NULL",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_last_login ON users(last_login_at DESC)",
		
		// Audit logs table indexes - for security analysis and reporting
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_user_created ON audit_logs(user_id, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_action_created ON audit_logs(action, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_success_created ON audit_logs(success, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_ip_created ON audit_logs(ip_address, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_resource_action ON audit_logs(resource, action)",
		
		// Login attempts table indexes - for rate limiting and security analysis
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_login_attempts_username_created ON login_attempts(username, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_login_attempts_ip_created ON login_attempts(ip_address, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_login_attempts_success_created ON login_attempts(success, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_login_attempts_suspicious ON login_attempts(is_suspicious) WHERE is_suspicious = true",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_login_attempts_user_success ON login_attempts(user_id, success, created_at DESC)",
		
		// User sessions table indexes - for session management and cleanup
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_user_active ON user_sessions(user_id, is_active) WHERE is_active = true",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_device_user ON user_sessions(device_id, user_id)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_ip_created ON user_sessions(ip_address, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_token_active ON user_sessions(session_token) WHERE is_active = true",
		
		// Device attestations table indexes - for Zero Trust device verification
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_attestations_user_status ON device_attestations(user_id, is_verified, trust_level)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_attestations_device_verified ON device_attestations(device_id, is_verified)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_attestations_platform_trust ON device_attestations(platform, trust_level)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_attestations_spiffe_id ON device_attestations(spiffe_id)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_device_attestations_verified_at ON device_attestations(verified_at DESC) WHERE verified_at IS NOT NULL",
		
		// Roles and permissions indexes - for RBAC performance
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_roles_name_active ON roles(name) WHERE is_active = true",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_permissions_resource_action ON permissions(resource, action) WHERE is_active = true",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_permissions_name_active ON permissions(name) WHERE is_active = true",
		
		// Junction table indexes for many-to-many relationships
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id)",
		
		// Composite indexes for common query patterns
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_user_action_time ON audit_logs(user_id, action, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_login_attempts_username_ip_time ON login_attempts(username, ip_address, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_user_device_active ON user_sessions(user_id, device_id, is_active)",
	}

	// Execute each index creation
	for i, indexSQL := range indexes {
		fmt.Printf("Creating performance index %d/%d...\n", i+1, len(indexes))
		
		if err := db.Exec(indexSQL).Error; err != nil {
			// Log the error but continue with other indexes
			fmt.Printf("Warning: Failed to create index %d: %v\n", i+1, err)
			fmt.Printf("SQL: %s\n", indexSQL)
			// Don't return error here - some indexes might already exist
		}
	}

	fmt.Printf("Performance indexes creation completed.\n")
	return nil
}

// DropPerformanceIndexes removes the performance indexes (for rollback)
func DropPerformanceIndexes(db *gorm.DB) error {
	indexes := []string{
		"DROP INDEX CONCURRENTLY IF EXISTS idx_users_email_active",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_users_username_active",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_users_failed_login_attempts",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_users_account_locked",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_users_last_login",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_user_created",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_action_created",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_success_created",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_ip_created",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_resource_action",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_login_attempts_username_created",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_login_attempts_ip_created",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_login_attempts_success_created",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_login_attempts_suspicious",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_login_attempts_user_success",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_user_sessions_user_active",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_user_sessions_expires_at",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_user_sessions_device_user",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_user_sessions_ip_created",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_user_sessions_token_active",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_device_attestations_user_status",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_device_attestations_device_verified",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_device_attestations_platform_trust",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_device_attestations_spiffe_id",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_device_attestations_verified_at",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_roles_name_active",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_permissions_resource_action",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_permissions_name_active",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_user_roles_user_id",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_user_roles_role_id",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_role_permissions_role_id",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_role_permissions_permission_id",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_user_action_time",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_login_attempts_username_ip_time",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_user_sessions_user_device_active",
	}

	for i, indexSQL := range indexes {
		fmt.Printf("Dropping performance index %d/%d...\n", i+1, len(indexes))
		
		if err := db.Exec(indexSQL).Error; err != nil {
			fmt.Printf("Warning: Failed to drop index %d: %v\n", i+1, err)
		}
	}

	fmt.Printf("Performance indexes removal completed.\n")
	return nil
}

// AddPartitioning adds table partitioning for large tables (PostgreSQL specific)
func AddPartitioning(db *gorm.DB) error {
	// Partition audit_logs by month for better performance on large datasets
	partitionSQL := []string{
		// Convert audit_logs to partitioned table
		`DO $$
		BEGIN
			-- Check if audit_logs is already partitioned
			IF NOT EXISTS (
				SELECT 1 FROM pg_partitioned_table 
				WHERE schemaname = 'public' AND tablename = 'audit_logs'
			) THEN
				-- Create new partitioned table
				CREATE TABLE audit_logs_new (
					LIKE audit_logs INCLUDING ALL
				) PARTITION BY RANGE (created_at);
				
				-- Copy data if original table exists and has data
				IF EXISTS (SELECT 1 FROM audit_logs LIMIT 1) THEN
					INSERT INTO audit_logs_new SELECT * FROM audit_logs;
				END IF;
				
				-- Rename tables
				DROP TABLE IF EXISTS audit_logs_old;
				ALTER TABLE audit_logs RENAME TO audit_logs_old;
				ALTER TABLE audit_logs_new RENAME TO audit_logs;
				
				-- Create initial partitions (current month and next month)
				EXECUTE format('CREATE TABLE audit_logs_%s PARTITION OF audit_logs 
					FOR VALUES FROM (%L) TO (%L)',
					to_char(date_trunc('month', CURRENT_DATE), 'YYYY_MM'),
					date_trunc('month', CURRENT_DATE),
					date_trunc('month', CURRENT_DATE + interval '1 month'));
					
				EXECUTE format('CREATE TABLE audit_logs_%s PARTITION OF audit_logs 
					FOR VALUES FROM (%L) TO (%L)',
					to_char(date_trunc('month', CURRENT_DATE + interval '1 month'), 'YYYY_MM'),
					date_trunc('month', CURRENT_DATE + interval '1 month'),
					date_trunc('month', CURRENT_DATE + interval '2 months'));
			END IF;
		END
		$$`,
		
		// Similar partitioning for login_attempts
		`DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_partitioned_table 
				WHERE schemaname = 'public' AND tablename = 'login_attempts'
			) THEN
				CREATE TABLE login_attempts_new (
					LIKE login_attempts INCLUDING ALL
				) PARTITION BY RANGE (created_at);
				
				IF EXISTS (SELECT 1 FROM login_attempts LIMIT 1) THEN
					INSERT INTO login_attempts_new SELECT * FROM login_attempts;
				END IF;
				
				DROP TABLE IF EXISTS login_attempts_old;
				ALTER TABLE login_attempts RENAME TO login_attempts_old;
				ALTER TABLE login_attempts_new RENAME TO login_attempts;
				
				EXECUTE format('CREATE TABLE login_attempts_%s PARTITION OF login_attempts 
					FOR VALUES FROM (%L) TO (%L)',
					to_char(date_trunc('month', CURRENT_DATE), 'YYYY_MM'),
					date_trunc('month', CURRENT_DATE),
					date_trunc('month', CURRENT_DATE + interval '1 month'));
					
				EXECUTE format('CREATE TABLE login_attempts_%s PARTITION OF login_attempts 
					FOR VALUES FROM (%L) TO (%L)',
					to_char(date_trunc('month', CURRENT_DATE + interval '1 month'), 'YYYY_MM'),
					date_trunc('month', CURRENT_DATE + interval '1 month'),
					date_trunc('month', CURRENT_DATE + interval '2 months'));
			END IF;
		END
		$$`,
	}

	for i, sql := range partitionSQL {
		fmt.Printf("Setting up table partitioning %d/%d...\n", i+1, len(partitionSQL))
		
		if err := db.Exec(sql).Error; err != nil {
			fmt.Printf("Warning: Failed to setup partitioning %d: %v\n", i+1, err)
			// Continue with other operations
		}
	}

	fmt.Printf("Table partitioning setup completed.\n")
	return nil
}

// OptimizeDatabase runs VACUUM and ANALYZE on all tables for performance
func OptimizeDatabase(db *gorm.DB) error {
	tables := []string{
		"users", "user_sessions", "device_attestations", "roles", "permissions",
		"user_roles", "role_permissions", "login_attempts", "audit_logs",
	}

	for _, table := range tables {
		fmt.Printf("Optimizing table: %s\n", table)
		
		// ANALYZE to update statistics
		if err := db.Exec(fmt.Sprintf("ANALYZE %s", table)).Error; err != nil {
			fmt.Printf("Warning: Failed to analyze table %s: %v\n", table, err)
		}
		
		// VACUUM to reclaim storage and update statistics
		if err := db.Exec(fmt.Sprintf("VACUUM %s", table)).Error; err != nil {
			fmt.Printf("Warning: Failed to vacuum table %s: %v\n", table, err)
		}
	}

	fmt.Printf("Database optimization completed.\n")
	return nil
}