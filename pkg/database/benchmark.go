// Package database provides performance benchmarking tools for database connection pools
package database

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"mvp.local/pkg/config"
	"mvp.local/pkg/errors"
	"mvp.local/pkg/observability"
)

// BenchmarkConfig defines parameters for database performance benchmarking
type BenchmarkConfig struct {
	// Test parameters
	ConcurrentConnections int           `yaml:"concurrent_connections" default:"10"`
	TestDuration          time.Duration `yaml:"test_duration" default:"60s"`
	QueryTypes            []QueryType   `yaml:"query_types"`
	WarmupDuration        time.Duration `yaml:"warmup_duration" default:"10s"`

	// Result parameters
	SampleInterval    time.Duration `yaml:"sample_interval" default:"1s"`
	ReportInterval    time.Duration `yaml:"report_interval" default:"10s"`
	DetailedReporting bool          `yaml:"detailed_reporting" default:"true"`
	ExportResults     bool          `yaml:"export_results" default:"true"`
	ExportPath        string        `yaml:"export_path" default:"./benchmark_results"`
}

// QueryType represents different types of database queries to benchmark
type QueryType string

const (
	QueryTypeSelect QueryType = "select"
	QueryTypeInsert QueryType = "insert"
	QueryTypeUpdate QueryType = "update"
	QueryTypeDelete QueryType = "delete"
	QueryTypeJoin   QueryType = "join"
	QueryTypeIndex  QueryType = "index"
)

// BenchmarkRunner executes database performance benchmarks
type BenchmarkRunner struct {
	config   *BenchmarkConfig
	db       *gorm.DB
	database *Database
	obs      *observability.Observability

	// Runtime state
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Results collection
	results   *BenchmarkResults
	resultsMu sync.RWMutex
}

// BenchmarkResults contains comprehensive benchmark results
type BenchmarkResults struct {
	StartTime     time.Time              `json:"start_time"`
	EndTime       time.Time              `json:"end_time"`
	Duration      time.Duration          `json:"duration"`
	Configuration *BenchmarkConfig       `json:"configuration"`
	PoolConfig    *config.DatabaseConfig `json:"pool_config"`

	// Overall statistics
	TotalQueries     int64         `json:"total_queries"`
	QueriesPerSecond float64       `json:"queries_per_second"`
	AverageLatency   time.Duration `json:"average_latency"`
	MedianLatency    time.Duration `json:"median_latency"`
	P95Latency       time.Duration `json:"p95_latency"`
	P99Latency       time.Duration `json:"p99_latency"`
	MinLatency       time.Duration `json:"min_latency"`
	MaxLatency       time.Duration `json:"max_latency"`

	// Error statistics
	TotalErrors      int64   `json:"total_errors"`
	ErrorRate        float64 `json:"error_rate"`
	TimeoutErrors    int64   `json:"timeout_errors"`
	ConnectionErrors int64   `json:"connection_errors"`

	// Connection pool statistics
	PoolStats             []PoolSnapshot `json:"pool_stats"`
	MaxConnections        int            `json:"max_connections"`
	PeakConnections       int            `json:"peak_connections"`
	AverageConnections    float64        `json:"average_connections"`
	ConnectionUtilization float64        `json:"connection_utilization"`

	// Query type breakdown
	QueryTypeResults map[QueryType]*QueryTypeResults `json:"query_type_results"`

	// Time series data
	TimeSeriesData []TimeSeriesPoint `json:"time_series_data"`

	// Performance insights
	Insights        []PerformanceInsight `json:"insights"`
	Recommendations []Recommendation     `json:"recommendations"`
}

// QueryTypeResults contains results for a specific query type
type QueryTypeResults struct {
	QueryCount       int64         `json:"query_count"`
	AverageLatency   time.Duration `json:"average_latency"`
	MinLatency       time.Duration `json:"min_latency"`
	MaxLatency       time.Duration `json:"max_latency"`
	ErrorCount       int64         `json:"error_count"`
	ErrorRate        float64       `json:"error_rate"`
	QueriesPerSecond float64       `json:"queries_per_second"`
}

// PoolSnapshot captures connection pool state at a point in time
type PoolSnapshot struct {
	Timestamp       time.Time `json:"timestamp"`
	OpenConnections int       `json:"open_connections"`
	InUse           int       `json:"in_use"`
	Idle            int       `json:"idle"`
	WaitCount       int64     `json:"wait_count"`
	WaitDuration    int64     `json:"wait_duration_ms"`
}

// TimeSeriesPoint represents a data point in the benchmark time series
type TimeSeriesPoint struct {
	Timestamp        time.Time `json:"timestamp"`
	QueriesPerSecond float64   `json:"queries_per_second"`
	AverageLatency   int64     `json:"average_latency_ms"`
	ErrorRate        float64   `json:"error_rate"`
	ConnectionsInUse int       `json:"connections_in_use"`
}

// PerformanceInsight provides analysis of benchmark results
type PerformanceInsight struct {
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
}

// Recommendation suggests optimizations based on benchmark results
type Recommendation struct {
	Type           string `json:"type"`
	Priority       string `json:"priority"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Implementation string `json:"implementation"`
	ExpectedImpact string `json:"expected_impact"`
}

// WorkerResult tracks results from a single benchmark worker
type WorkerResult struct {
	WorkerID     int
	QueryCount   int64
	ErrorCount   int64
	TotalLatency time.Duration
	MinLatency   time.Duration
	MaxLatency   time.Duration
	Latencies    []time.Duration
}

// NewBenchmarkRunner creates a new database benchmark runner
func NewBenchmarkRunner(
	config *BenchmarkConfig,
	database *Database,
	obs *observability.Observability,
) (*BenchmarkRunner, error) {
	if database == nil || database.DB == nil {
		return nil, errors.Internal("Database connection required for benchmarking")
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &BenchmarkRunner{
		config:   config,
		db:       database.DB,
		database: database,
		obs:      obs,
		ctx:      ctx,
		cancel:   cancel,
		results: &BenchmarkResults{
			Configuration:    config,
			PoolConfig:       database.config,
			QueryTypeResults: make(map[QueryType]*QueryTypeResults),
			TimeSeriesData:   make([]TimeSeriesPoint, 0),
			Insights:         make([]PerformanceInsight, 0),
			Recommendations:  make([]Recommendation, 0),
		},
	}, nil
}

// RunBenchmark executes the complete benchmark suite
func (br *BenchmarkRunner) RunBenchmark() (*BenchmarkResults, error) {
	br.obs.Logger.Info().
		Int("concurrent_connections", br.config.ConcurrentConnections).
		Dur("test_duration", br.config.TestDuration).
		Msg("Starting database benchmark")

	br.results.StartTime = time.Now()

	// Initialize query type results
	for _, queryType := range br.config.QueryTypes {
		br.results.QueryTypeResults[queryType] = &QueryTypeResults{}
	}

	// Start pool monitoring
	go br.monitorPool()

	// Start time series collection
	go br.collectTimeSeries()

	// Warmup phase
	if br.config.WarmupDuration > 0 {
		br.obs.Logger.Info().Dur("duration", br.config.WarmupDuration).Msg("Starting benchmark warmup")
		br.runWarmup()
	}

	// Main benchmark phase
	br.obs.Logger.Info().Dur("duration", br.config.TestDuration).Msg("Starting main benchmark")
	workerResults := br.runMainBenchmark()

	br.results.EndTime = time.Now()
	br.results.Duration = br.results.EndTime.Sub(br.results.StartTime)

	// Process results
	br.processResults(workerResults)

	// Generate insights and recommendations
	br.generateInsights()
	br.generateRecommendations()

	// Export results if configured
	if br.config.ExportResults {
		if err := br.exportResults(); err != nil {
			br.obs.Logger.Warn().Err(err).Msg("Failed to export benchmark results")
		}
	}

	br.obs.Logger.Info().
		Int64("total_queries", br.results.TotalQueries).
		Float64("qps", br.results.QueriesPerSecond).
		Dur("avg_latency", br.results.AverageLatency).
		Float64("error_rate", br.results.ErrorRate).
		Msg("Benchmark completed")

	return br.results, nil
}

// runWarmup performs a warmup phase to stabilize the system
func (br *BenchmarkRunner) runWarmup() {
	ctx, cancel := context.WithTimeout(br.ctx, br.config.WarmupDuration)
	defer cancel()

	var wg sync.WaitGroup

	// Start fewer workers for warmup
	warmupWorkers := br.config.ConcurrentConnections / 2
	if warmupWorkers < 1 {
		warmupWorkers = 1
	}

	for i := 0; i < warmupWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			br.runBenchmarkWorker(ctx, workerID, true)
		}(i)
	}

	wg.Wait()
}

// runMainBenchmark executes the main benchmark with full concurrency
func (br *BenchmarkRunner) runMainBenchmark() []*WorkerResult {
	ctx, cancel := context.WithTimeout(br.ctx, br.config.TestDuration)
	defer cancel()

	results := make([]*WorkerResult, br.config.ConcurrentConnections)
	resultsCh := make(chan *WorkerResult, br.config.ConcurrentConnections)

	var wg sync.WaitGroup

	// Start all benchmark workers
	for i := 0; i < br.config.ConcurrentConnections; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			result := br.runBenchmarkWorker(ctx, workerID, false)
			resultsCh <- result
		}(i)
	}

	// Wait for all workers to complete
	wg.Wait()
	close(resultsCh)

	// Collect results
	i := 0
	for result := range resultsCh {
		results[i] = result
		i++
	}

	return results
}

// runBenchmarkWorker executes benchmark queries in a single worker
func (br *BenchmarkRunner) runBenchmarkWorker(ctx context.Context, workerID int, isWarmup bool) *WorkerResult {
	result := &WorkerResult{
		WorkerID:   workerID,
		MinLatency: time.Hour, // Initialize to high value
		Latencies:  make([]time.Duration, 0, 1000),
	}

	queryIndex := 0

	for {
		select {
		case <-ctx.Done():
			return result
		default:
			// Select query type (round-robin for simplicity)
			queryType := br.config.QueryTypes[queryIndex%len(br.config.QueryTypes)]
			queryIndex++

			// Execute query and measure latency
			start := time.Now()
			err := br.executeQuery(queryType)
			latency := time.Since(start)

			// Update worker results (skip during warmup)
			if !isWarmup {
				result.QueryCount++
				result.TotalLatency += latency
				result.Latencies = append(result.Latencies, latency)

				if latency < result.MinLatency {
					result.MinLatency = latency
				}
				if latency > result.MaxLatency {
					result.MaxLatency = latency
				}

				if err != nil {
					result.ErrorCount++
				}

				// Update global counters
				atomic.AddInt64(&br.results.TotalQueries, 1)
				if err != nil {
					atomic.AddInt64(&br.results.TotalErrors, 1)
				}
			}
		}
	}
}

// executeQuery executes a specific type of database query
func (br *BenchmarkRunner) executeQuery(queryType QueryType) error {
	switch queryType {
	case QueryTypeSelect:
		return br.executeSelectQuery()
	case QueryTypeInsert:
		return br.executeInsertQuery()
	case QueryTypeUpdate:
		return br.executeUpdateQuery()
	case QueryTypeDelete:
		return br.executeDeleteQuery()
	case QueryTypeJoin:
		return br.executeJoinQuery()
	case QueryTypeIndex:
		return br.executeIndexQuery()
	default:
		return errors.Validation(fmt.Sprintf("Unknown query type: %s", queryType))
	}
}

// executeSelectQuery performs a simple SELECT operation
func (br *BenchmarkRunner) executeSelectQuery() error {
	var count int64
	return br.db.Raw("SELECT COUNT(*) FROM users").Scan(&count).Error
}

// executeInsertQuery performs a simple INSERT operation
func (br *BenchmarkRunner) executeInsertQuery() error {
	return br.db.Exec(`
		INSERT INTO benchmark_data (data, created_at) 
		VALUES (?, ?) 
		ON CONFLICT DO NOTHING
	`, fmt.Sprintf("benchmark_%d", time.Now().UnixNano()), time.Now()).Error
}

// executeUpdateQuery performs a simple UPDATE operation
func (br *BenchmarkRunner) executeUpdateQuery() error {
	return br.db.Exec(`
		UPDATE benchmark_data 
		SET updated_at = ? 
		WHERE id = (SELECT id FROM benchmark_data ORDER BY RANDOM() LIMIT 1)
	`, time.Now()).Error
}

// executeDeleteQuery performs a simple DELETE operation
func (br *BenchmarkRunner) executeDeleteQuery() error {
	return br.db.Exec(`
		DELETE FROM benchmark_data 
		WHERE id IN (
			SELECT id FROM benchmark_data 
			WHERE created_at < ? 
			ORDER BY created_at 
			LIMIT 1
		)
	`, time.Now().Add(-time.Hour)).Error
}

// executeJoinQuery performs a JOIN operation
func (br *BenchmarkRunner) executeJoinQuery() error {
	var results []map[string]interface{}
	return br.db.Raw(`
		SELECT u.id, u.email, COUNT(r.id) as role_count
		FROM users u
		LEFT JOIN user_roles ur ON u.id = ur.user_id
		LEFT JOIN roles r ON ur.role_id = r.id
		GROUP BY u.id, u.email
		LIMIT 10
	`).Find(&results).Error
}

// executeIndexQuery performs an indexed lookup
func (br *BenchmarkRunner) executeIndexQuery() error {
	var user map[string]interface{}
	return br.db.Raw(`
		SELECT * FROM users 
		WHERE email = ? 
		LIMIT 1
	`, fmt.Sprintf("user_%d@example.com", time.Now().UnixNano()%1000)).Find(&user).Error
}

// monitorPool continuously monitors connection pool statistics
func (br *BenchmarkRunner) monitorPool() {
	ticker := time.NewTicker(br.config.SampleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-br.ctx.Done():
			return
		case <-ticker.C:
			if stats, err := br.database.GetStats(); err == nil {
				br.resultsMu.Lock()
				snapshot := PoolSnapshot{
					Timestamp:       time.Now(),
					OpenConnections: int(stats["open_connections"].(int32)),
					InUse:           int(stats["in_use"].(int32)),
					Idle:            int(stats["idle"].(int32)),
					WaitCount:       stats["wait_count"].(int64),
				}
				if wd, ok := stats["wait_duration_ms"].(int64); ok {
					snapshot.WaitDuration = wd
				}
				br.results.PoolStats = append(br.results.PoolStats, snapshot)
				br.resultsMu.Unlock()
			}
		}
	}
}

// collectTimeSeries collects time series performance data
func (br *BenchmarkRunner) collectTimeSeries() {
	ticker := time.NewTicker(br.config.SampleInterval)
	defer ticker.Stop()

	lastQueryCount := int64(0)
	lastTimestamp := time.Now()

	for {
		select {
		case <-br.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			currentQueryCount := atomic.LoadInt64(&br.results.TotalQueries)
			currentErrorCount := atomic.LoadInt64(&br.results.TotalErrors)

			interval := now.Sub(lastTimestamp).Seconds()
			qps := float64(currentQueryCount-lastQueryCount) / interval
			errorRate := 0.0
			if currentQueryCount > 0 {
				errorRate = float64(currentErrorCount) / float64(currentQueryCount)
			}

			// Get current connection usage
			connectionsInUse := 0
			if stats, err := br.database.GetStats(); err == nil {
				if inUse, ok := stats["in_use"].(int32); ok {
					connectionsInUse = int(inUse)
				}
			}

			br.resultsMu.Lock()
			br.results.TimeSeriesData = append(br.results.TimeSeriesData, TimeSeriesPoint{
				Timestamp:        now,
				QueriesPerSecond: qps,
				ErrorRate:        errorRate,
				ConnectionsInUse: connectionsInUse,
			})
			br.resultsMu.Unlock()

			lastQueryCount = currentQueryCount
			lastTimestamp = now
		}
	}
}

// processResults analyzes and aggregates benchmark results
func (br *BenchmarkRunner) processResults(workerResults []*WorkerResult) {
	allLatencies := make([]time.Duration, 0)

	for _, result := range workerResults {
		allLatencies = append(allLatencies, result.Latencies...)
	}

	if len(allLatencies) == 0 {
		return
	}

	// Sort latencies for percentile calculations
	sort.Slice(allLatencies, func(i, j int) bool {
		return allLatencies[i] < allLatencies[j]
	})

	// Calculate basic statistics
	br.results.QueriesPerSecond = float64(br.results.TotalQueries) / br.results.Duration.Seconds()

	totalLatency := time.Duration(0)
	for _, latency := range allLatencies {
		totalLatency += latency
	}
	br.results.AverageLatency = totalLatency / time.Duration(len(allLatencies))

	// Calculate percentiles
	br.results.MinLatency = allLatencies[0]
	br.results.MaxLatency = allLatencies[len(allLatencies)-1]
	br.results.MedianLatency = allLatencies[len(allLatencies)/2]
	br.results.P95Latency = allLatencies[int(float64(len(allLatencies))*0.95)]
	br.results.P99Latency = allLatencies[int(float64(len(allLatencies))*0.99)]

	// Calculate error rate
	if br.results.TotalQueries > 0 {
		br.results.ErrorRate = float64(br.results.TotalErrors) / float64(br.results.TotalQueries)
	}

	// Calculate connection pool statistics
	if len(br.results.PoolStats) > 0 {
		maxConns := 0
		totalConns := 0
		for _, snapshot := range br.results.PoolStats {
			if snapshot.OpenConnections > maxConns {
				maxConns = snapshot.OpenConnections
			}
			totalConns += snapshot.OpenConnections
		}
		br.results.PeakConnections = maxConns
		br.results.AverageConnections = float64(totalConns) / float64(len(br.results.PoolStats))

		if stats, err := br.database.GetStats(); err == nil {
			if maxOpen, ok := stats["max_open_connections"].(int32); ok {
				br.results.MaxConnections = int(maxOpen)
				br.results.ConnectionUtilization = float64(br.results.PeakConnections) / float64(maxOpen)
			}
		}
	}
}

// generateInsights analyzes results and generates performance insights
func (br *BenchmarkRunner) generateInsights() {
	// High latency insight
	if br.results.AverageLatency > 100*time.Millisecond {
		severity := "warning"
		if br.results.AverageLatency > 500*time.Millisecond {
			severity = "critical"
		}

		br.results.Insights = append(br.results.Insights, PerformanceInsight{
			Category:    "latency",
			Severity:    severity,
			Title:       "High Average Latency",
			Description: fmt.Sprintf("Average query latency is %v, which may impact user experience", br.results.AverageLatency),
			Impact:      "Users may experience slow response times",
		})
	}

	// High error rate insight
	if br.results.ErrorRate > 0.01 { // 1%
		severity := "warning"
		if br.results.ErrorRate > 0.05 { // 5%
			severity = "critical"
		}

		br.results.Insights = append(br.results.Insights, PerformanceInsight{
			Category:    "reliability",
			Severity:    severity,
			Title:       "High Error Rate",
			Description: fmt.Sprintf("Error rate is %.2f%%, indicating potential reliability issues", br.results.ErrorRate*100),
			Impact:      "Application functionality may be degraded",
		})
	}

	// Connection pool utilization insight
	if br.results.ConnectionUtilization > 0.8 {
		br.results.Insights = append(br.results.Insights, PerformanceInsight{
			Category:    "connection_pool",
			Severity:    "warning",
			Title:       "High Connection Pool Utilization",
			Description: fmt.Sprintf("Connection pool utilization is %.1f%%, approaching maximum capacity", br.results.ConnectionUtilization*100),
			Impact:      "May cause connection waits and increased latency under higher load",
		})
	}

	// Low throughput insight
	expectedQPS := float64(br.config.ConcurrentConnections) * 10 // Rough estimate
	if br.results.QueriesPerSecond < expectedQPS*0.5 {
		br.results.Insights = append(br.results.Insights, PerformanceInsight{
			Category:    "throughput",
			Severity:    "warning",
			Title:       "Low Throughput",
			Description: fmt.Sprintf("Achieving %.1f QPS with %d concurrent connections, which is below expected performance", br.results.QueriesPerSecond, br.config.ConcurrentConnections),
			Impact:      "System may not handle expected production load",
		})
	}
}

// generateRecommendations provides optimization suggestions based on results
func (br *BenchmarkRunner) generateRecommendations() {
	// Connection pool size recommendation
	if br.results.ConnectionUtilization > 0.8 {
		br.results.Recommendations = append(br.results.Recommendations, Recommendation{
			Type:           "connection_pool",
			Priority:       "high",
			Title:          "Increase Connection Pool Size",
			Description:    "Connection pool utilization is high, consider increasing max connections",
			Implementation: "Increase DB_MAX_CONNECTIONS environment variable or use high_throughput optimization profile",
			ExpectedImpact: "Reduced connection wait times and improved throughput under load",
		})
	}

	// Query optimization recommendation
	if br.results.AverageLatency > 50*time.Millisecond {
		br.results.Recommendations = append(br.results.Recommendations, Recommendation{
			Type:           "query_optimization",
			Priority:       "medium",
			Title:          "Optimize Query Performance",
			Description:    "Average query latency is elevated, consider query optimization",
			Implementation: "Review slow queries, add indexes, optimize query plans",
			ExpectedImpact: "Significantly reduced query latency and improved user experience",
		})
	}

	// Prepared statements recommendation
	if !br.results.PoolConfig.PrepareStmt {
		br.results.Recommendations = append(br.results.Recommendations, Recommendation{
			Type:           "configuration",
			Priority:       "low",
			Title:          "Enable Prepared Statements",
			Description:    "Prepared statements are disabled, enabling them can improve performance",
			Implementation: "Set DB_PREPARE_STMT=true in environment configuration",
			ExpectedImpact: "Reduced query parsing overhead and slight performance improvement",
		})
	}

	// Optimization profile recommendation
	if br.results.QueriesPerSecond > 100 && br.results.PoolConfig.OptimizationProfile != "high_throughput" {
		br.results.Recommendations = append(br.results.Recommendations, Recommendation{
			Type:           "optimization_profile",
			Priority:       "medium",
			Title:          "Use High Throughput Profile",
			Description:    "System is handling high query volume, consider switching to high_throughput profile",
			Implementation: "Set DB_OPTIMIZATION_PROFILE=high_throughput in environment configuration",
			ExpectedImpact: "Optimized connection pool settings for high-throughput workloads",
		})
	}
}

// exportResults saves benchmark results to files
func (br *BenchmarkRunner) exportResults() error {
	// Implementation would export results to JSON, CSV, and generate HTML reports
	br.obs.Logger.Info().
		Str("export_path", br.config.ExportPath).
		Msg("Benchmark results exported (implementation pending)")
	return nil
}

// Stop gracefully stops the benchmark runner
func (br *BenchmarkRunner) Stop() {
	br.cancel()
	br.wg.Wait()
}
