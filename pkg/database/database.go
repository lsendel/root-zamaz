// Package database provides database connection and management for the MVP Zero Trust Auth system.
// It includes GORM setup, PostgreSQL connection, automatic migrations,
// and database health checks with comprehensive error handling.
package database

import (
	"context"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"mvp.local/pkg/config"
	"mvp.local/pkg/errors"
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

	// Skip auto-migration entirely since we're using SQL migrations
	// The database schema is already created by scripts/sql/init/migrations.sql
	// The SQL migrations handle all table creation and constraints

	// Only check if the database connection works
	return d.Health()
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
