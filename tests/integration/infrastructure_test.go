// Package integration provides integration tests for the MVP Zero Trust Auth system.
// These tests verify connectivity and basic functionality of external dependencies
// including PostgreSQL, Redis, NATS, and the observability stack.
package integration

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go/modules/compose"
)

func TestInfrastructureIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	// Start Docker Compose environment
	composeStack, err := compose.NewDockerComposeWith(
		compose.WithStackFiles("../../docker-compose.test.yml"),
		compose.StackIdentifier("integration-test"),
	)
	if err != nil {
		t.Skipf("Failed to initialize Docker Compose environment, skipping integration tests: %v", err)
	}

	t.Cleanup(func() {
		_ = composeStack.Down(ctx, compose.RemoveOrphans(true), compose.RemoveVolumes(true))
	})

	err = composeStack.Up(ctx, compose.Wait(true))
	if err != nil {
		t.Skipf("Failed to start Docker Compose environment, skipping integration tests: %v", err)
	}

	// Test database connectivity
	t.Run("PostgreSQL", func(t *testing.T) {
		// Test database connection and basic operations
		db := setupTestDB(t)
		defer db.Close()

		err := db.Ping()
		assert.NoError(t, err)
	})

	// Test Redis connectivity
	t.Run("Redis", func(t *testing.T) {
		client := setupTestRedis(t)
		defer client.Close()

		err := client.Ping(ctx).Err()
		assert.NoError(t, err)
	})

	// Test NATS connectivity
	t.Run("NATS", func(t *testing.T) {
		nc := setupTestNATS(t)
		defer nc.Close()

		assert.True(t, nc.IsConnected())
	})

	// Test observability stack
	t.Run("Observability", func(t *testing.T) {
		// Test Prometheus
		resp, err := httpGet("http://localhost:9090/-/healthy")
		assert.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)

		// Test Grafana
		resp, err = httpGet("http://localhost:3000/api/health")
		assert.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)

		// Test Jaeger
		resp, err = httpGet("http://localhost:16686/")
		assert.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})

	// Test SPIRE infrastructure
	t.Run("SPIRE", func(t *testing.T) {
		// Wait for SPIRE server to be ready
		time.Sleep(30 * time.Second)

		// Test SPIRE server health
		resp, err := httpGet("http://localhost:8081/live")
		if err != nil {
			t.Skipf("SPIRE server not available, skipping test: %v", err)
		}
		assert.Equal(t, 200, resp.StatusCode)
	})
}

// Helper functions

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()

	// Connection string for the PostgreSQL container
	connStr := "host=localhost port=5432 user=mvp_user password=mvp_password dbname=mvp_db sslmode=disable"

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	return db
}

func setupTestRedis(t *testing.T) *redis.Client {
	t.Helper()

	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password
		DB:       0,  // default DB
	})

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("Failed to connect to Redis: %v", err)
	}

	return client
}

func setupTestNATS(t *testing.T) *nats.Conn {
	t.Helper()

	nc, err := nats.Connect("nats://localhost:4222")
	if err != nil {
		t.Fatalf("Failed to connect to NATS: %v", err)
	}

	return nc
}

func httpGet(url string) (*http.Response, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	return client.Get(url)
}
