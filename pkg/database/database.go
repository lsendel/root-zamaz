// Package database provides database connection and management for the MVP Zero Trust Auth system.
// It includes GORM setup, PostgreSQL connection, automatic migrations,
// and database health checks with comprehensive error handling.
package database

import (
	"context"
	"database/sql"
	"runtime"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"mvp.local/pkg/config"
	"mvp.local/pkg/errors"
	"mvp.local/pkg/migrations"
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
		Logger:         gormLogger,
		NamingStrategy: nil, // Use default naming strategy
		PrepareStmt:    d.config.PrepareStmt,
		DisableForeignKeyConstraintWhenMigrating: d.config.DisableForeignKey,
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

	// Configure connection pool with workload-optimized settings
	d.configureConnectionPool(sqlDB)

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

// Migrate runs database migrations using the migration system
func (d *Database) Migrate() error {
	if d.DB == nil {
		return errors.Internal("Database connection not established")
	}

	// Use the migration system for proper versioned migrations
	migrator := migrations.NewMigrator(d.DB)
	if err := migrator.Migrate(); err != nil {
		return errors.Wrap(err, errors.CodeInternal, "Failed to run database migrations")
	}

	return nil
}

// GetMigrationStatus returns the current migration status
func (d *Database) GetMigrationStatus() ([]migrations.MigrationStatus, error) {
	if d.DB == nil {
		return nil, errors.Internal("Database connection not established")
	}

	migrator := migrations.NewMigrator(d.DB)
	return migrator.Status()
}

// RollbackMigration rolls back the last migration
func (d *Database) RollbackMigration() error {
	if d.DB == nil {
		return errors.Internal("Database connection not established")
	}

	migrator := migrations.NewMigrator(d.DB)
	return migrator.Rollback()
}

// Note: RBAC roles and permissions are now handled by Casbin
// No seeding needed since we're using SQL migrations for the basic schema

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
		"in_use":               stats.InUse,
		"idle":                 stats.Idle,
		"wait_count":           stats.WaitCount,
		"wait_duration":        stats.WaitDuration.String(),
		"max_idle_closed":      stats.MaxIdleClosed,
		"max_idle_time_closed": stats.MaxIdleTimeClosed,
		"max_lifetime_closed":  stats.MaxLifetimeClosed,
	}, nil
}

// configureConnectionPool optimizes connection pool settings based on workload and system resources
func (d *Database) configureConnectionPool(sqlDB *sql.DB) {
	// Calculate optimal connection pool size based on CPU cores and expected workload
	numCPU := runtime.NumCPU()
	
	// Default values from config
	maxConnections := d.config.MaxConnections
	maxIdleConns := d.config.MaxIdleConns
	connMaxLifetime := d.config.ConnMaxLifetime
	connMaxIdleTime := d.config.ConnMaxIdleTime

	// Workload-based optimization
	// For I/O intensive workloads like authentication services:
	// Rule of thumb: 2-4 connections per CPU core for balanced workload
	optimalMaxConnections := numCPU * 3

	// Adjust based on configured value vs optimal
	if maxConnections <= 0 || maxConnections > optimalMaxConnections*2 {
		maxConnections = optimalMaxConnections
	}

	// Ensure max idle connections is reasonable (typically 20-30% of max connections)
	optimalMaxIdle := maxConnections / 4
	if optimalMaxIdle < 2 {
		optimalMaxIdle = 2
	}
	if optimalMaxIdle > 10 {
		optimalMaxIdle = 10
	}

	if maxIdleConns <= 0 || maxIdleConns > maxConnections {
		maxIdleConns = optimalMaxIdle
	}

	// For Zero Trust auth workload, shorter lifetimes are better for security
	if connMaxLifetime <= 0 || connMaxLifetime > 30*time.Minute {
		connMaxLifetime = 15 * time.Minute
	}

	if connMaxIdleTime <= 0 || connMaxIdleTime > 10*time.Minute {
		connMaxIdleTime = 5 * time.Minute
	}

	// Apply optimized settings
	sqlDB.SetMaxOpenConns(maxConnections)
	sqlDB.SetMaxIdleConns(maxIdleConns)
	sqlDB.SetConnMaxLifetime(connMaxLifetime)
	sqlDB.SetConnMaxIdleTime(connMaxIdleTime)
}
