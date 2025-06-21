package performance

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"gorm.io/gorm"

	"mvp.local/pkg/common/errors"
)

// DatabaseOptimizer provides performance optimizations for database operations
type DatabaseOptimizer struct {
	db     *gorm.DB
	cache  *CacheOptimizer
	logger zerolog.Logger
}

// NewDatabaseOptimizer creates a new database optimizer
func NewDatabaseOptimizer(db *gorm.DB, cache *CacheOptimizer, logger zerolog.Logger) *DatabaseOptimizer {
	return &DatabaseOptimizer{
		db:     db,
		cache:  cache,
		logger: logger,
	}
}

// QueryOptions defines optimization options for queries
type QueryOptions struct {
	UseCache   bool
	CacheTTL   time.Duration
	EagerLoad  []string
	IndexHints []string
	Timeout    time.Duration
	BatchSize  int
}

// DefaultQueryOptions returns sensible defaults
func DefaultQueryOptions() QueryOptions {
	return QueryOptions{
		UseCache:  true,
		CacheTTL:  5 * time.Minute,
		Timeout:   30 * time.Second,
		BatchSize: 100,
	}
}

// OptimizedFind performs an optimized database find operation
func (d *DatabaseOptimizer) OptimizedFind(
	ctx context.Context,
	dest interface{},
	query string,
	args []interface{},
	options QueryOptions,
) error {
	// Add timeout to context
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Generate cache key if caching is enabled
	var cacheKey string
	if options.UseCache && d.cache != nil {
		cacheKey = d.generateCacheKey(query, args)

		// Try cache first
		if cached, err := d.getCachedResult(ctx, cacheKey); err == nil {
			d.logger.Debug().Str("cache_key", cacheKey).Msg("Database query cache hit")
			return d.deserializeResult(cached, dest)
		}
	}

	// Build optimized query
	dbQuery := d.db.WithContext(ctx)

	// Add eager loading
	for _, preload := range options.EagerLoad {
		dbQuery = dbQuery.Preload(preload)
	}

	// Add index hints if provided
	for _, hint := range options.IndexHints {
		dbQuery = dbQuery.Set("gorm:query_hint", hint)
	}

	// Execute query
	start := time.Now()
	err := dbQuery.Raw(query, args...).Scan(dest).Error
	duration := time.Since(start)

	// Log slow queries
	if duration > 1*time.Second {
		d.logger.Warn().
			Dur("duration", duration).
			Str("query", query).
			Interface("args", args).
			Msg("Slow database query detected")
	}

	if err != nil {
		return errors.NewDatabaseError("optimized_find", "query", err)
	}

	// Cache result if caching is enabled
	if options.UseCache && d.cache != nil && cacheKey != "" {
		go d.cacheResult(context.Background(), cacheKey, dest, options.CacheTTL)
	}

	return nil
}

// OptimizedBatchInsert performs batch insert with optimizations
func (d *DatabaseOptimizer) OptimizedBatchInsert(
	ctx context.Context,
	tableName string,
	records interface{},
	options QueryOptions,
) error {
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	batchSize := options.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}

	return d.db.WithContext(ctx).CreateInBatches(records, batchSize).Error
}

// OptimizedUpdate performs optimized batch updates
func (d *DatabaseOptimizer) OptimizedUpdate(
	ctx context.Context,
	model interface{},
	updates map[string]interface{},
	where string,
	args []interface{},
	options QueryOptions,
) error {
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Execute update
	result := d.db.WithContext(ctx).Model(model).Where(where, args...).Updates(updates)
	if result.Error != nil {
		return errors.NewDatabaseError("optimized_update", "update", result.Error)
	}

	// Invalidate related cache entries if caching is enabled
	if d.cache != nil {
		go d.invalidateRelatedCache(context.Background(), model, where, args)
	}

	return nil
}

// CreateMissingIndexes analyzes and creates missing database indexes
func (d *DatabaseOptimizer) CreateMissingIndexes(ctx context.Context) error {
	indexes := []struct {
		table   string
		columns []string
		name    string
	}{
		// Users table indexes
		{"users", []string{"email"}, "idx_users_email"},
		{"users", []string{"is_active", "created_at"}, "idx_users_active_created"},
		{"users", []string{"last_login_at"}, "idx_users_last_login"},

		// User sessions indexes
		{"user_sessions", []string{"user_id", "is_active"}, "idx_sessions_user_active"},
		{"user_sessions", []string{"token_hash"}, "idx_sessions_token_hash"},
		{"user_sessions", []string{"expires_at"}, "idx_sessions_expires"},

		// Roles and permissions indexes
		{"roles", []string{"name"}, "idx_roles_name"},
		{"user_roles", []string{"user_id", "role_id"}, "idx_user_roles_composite"},
		{"role_permissions", []string{"role_id", "permission_id"}, "idx_role_perms_composite"},

		// Audit logs indexes
		{"audit_logs", []string{"user_id", "created_at"}, "idx_audit_user_created"},
		{"audit_logs", []string{"action", "created_at"}, "idx_audit_action_created"},
		{"audit_logs", []string{"ip_address", "created_at"}, "idx_audit_ip_created"},

		// Device attestations indexes
		{"device_attestations", []string{"user_id", "is_active"}, "idx_devices_user_active"},
		{"device_attestations", []string{"device_fingerprint"}, "idx_devices_fingerprint"},
	}

	for _, idx := range indexes {
		if err := d.createIndexIfNotExists(ctx, idx.table, idx.columns, idx.name); err != nil {
			d.logger.Error().
				Err(err).
				Str("table", idx.table).
				Interface("columns", idx.columns).
				Str("index", idx.name).
				Msg("Failed to create index")
		} else {
			d.logger.Info().
				Str("table", idx.table).
				Interface("columns", idx.columns).
				Str("index", idx.name).
				Msg("Index created successfully")
		}
	}

	return nil
}

// AnalyzeQueryPerformance analyzes slow queries and provides recommendations
func (d *DatabaseOptimizer) AnalyzeQueryPerformance(ctx context.Context) (map[string]interface{}, error) {
	analysis := make(map[string]interface{})

	// Get slow query log (PostgreSQL example)
	var slowQueries []struct {
		Query    string
		Duration time.Duration
		Count    int
	}

	// This would be database-specific implementation
	query := `
		SELECT query, avg(total_time) as avg_duration, calls as count
		FROM pg_stat_statements 
		WHERE avg_time > 1000 
		ORDER BY avg_time DESC 
		LIMIT 10
	`

	if err := d.db.WithContext(ctx).Raw(query).Scan(&slowQueries).Error; err != nil {
		d.logger.Warn().Err(err).Msg("Could not analyze query performance")
	} else {
		analysis["slow_queries"] = slowQueries
	}

	// Get table statistics
	tableStats, err := d.getTableStatistics(ctx)
	if err != nil {
		d.logger.Warn().Err(err).Msg("Could not get table statistics")
	} else {
		analysis["table_statistics"] = tableStats
	}

	// Get index usage statistics
	indexStats, err := d.getIndexStatistics(ctx)
	if err != nil {
		d.logger.Warn().Err(err).Msg("Could not get index statistics")
	} else {
		analysis["index_statistics"] = indexStats
	}

	return analysis, nil
}

// Helper methods

func (d *DatabaseOptimizer) generateCacheKey(query string, args []interface{}) string {
	// Create a deterministic cache key from query and args
	return fmt.Sprintf("query:%x", fmt.Sprintf("%s:%v", query, args))
}

func (d *DatabaseOptimizer) getCachedResult(ctx context.Context, key string) (interface{}, error) {
	// Implement cache retrieval
	return d.cache.GetWithFallback(ctx, key, DefaultCacheOptions(), func() (interface{}, error) {
		return nil, errors.NewNotFoundError("cache")
	})
}

func (d *DatabaseOptimizer) deserializeResult(cached interface{}, dest interface{}) error {
	// Implement result deserialization
	return nil
}

func (d *DatabaseOptimizer) cacheResult(ctx context.Context, key string, data interface{}, ttl time.Duration) {
	// Implement async caching
	options := DefaultCacheOptions()
	options.TTL = ttl
	d.cache.GetWithFallback(ctx, key, options, func() (interface{}, error) {
		return data, nil
	})
}

func (d *DatabaseOptimizer) invalidateRelatedCache(ctx context.Context, model interface{}, where string, args []interface{}) {
	// Implement cache invalidation based on model type
	pattern := fmt.Sprintf("*%T*", model)
	d.cache.InvalidatePattern(ctx, "zamaz", pattern)
}

func (d *DatabaseOptimizer) createIndexIfNotExists(ctx context.Context, table string, columns []string, name string) error {
	// Check if index exists
	var exists bool
	checkQuery := `
		SELECT EXISTS (
			SELECT 1 FROM pg_indexes 
			WHERE indexname = ? AND tablename = ?
		)
	`

	if err := d.db.WithContext(ctx).Raw(checkQuery, name, table).Scan(&exists).Error; err != nil {
		return err
	}

	if exists {
		return nil // Index already exists
	}

	// Create index
	columnList := strings.Join(columns, ", ")
	createQuery := fmt.Sprintf("CREATE INDEX CONCURRENTLY %s ON %s (%s)", name, table, columnList)

	return d.db.WithContext(ctx).Exec(createQuery).Error
}

func (d *DatabaseOptimizer) getTableStatistics(ctx context.Context) (interface{}, error) {
	var stats []struct {
		TableName string `json:"table_name"`
		RowCount  int64  `json:"row_count"`
		TableSize string `json:"table_size"`
	}

	query := `
		SELECT 
			schemaname||'.'||tablename as table_name,
			n_tup_ins + n_tup_upd + n_tup_del as row_count,
			pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as table_size
		FROM pg_stat_user_tables 
		ORDER BY n_tup_ins + n_tup_upd + n_tup_del DESC
	`

	err := d.db.WithContext(ctx).Raw(query).Scan(&stats).Error
	return stats, err
}

func (d *DatabaseOptimizer) getIndexStatistics(ctx context.Context) (interface{}, error) {
	var stats []struct {
		IndexName  string `json:"index_name"`
		TableName  string `json:"table_name"`
		IndexScans int64  `json:"index_scans"`
		TupleReads int64  `json:"tuple_reads"`
		IndexSize  string `json:"index_size"`
	}

	query := `
		SELECT 
			indexrelname as index_name,
			relname as table_name,
			idx_scan as index_scans,
			idx_tup_read as tuple_reads,
			pg_size_pretty(pg_relation_size(indexrelid)) as index_size
		FROM pg_stat_user_indexes 
		ORDER BY idx_scan DESC
	`

	err := d.db.WithContext(ctx).Raw(query).Scan(&stats).Error
	return stats, err
}
