package integration

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/testcontainers/testcontainers-go"
    "github.com/testcontainers/testcontainers-go/modules/compose"
)

func TestInfrastructureIntegration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test in short mode")
    }

    ctx := context.Background()

    // Start Docker Compose environment
    composeStack, err := compose.NewDockerComposeWith(
        compose.WithStackFiles("../../docker-compose.yml"),
        compose.StackIdentifier("integration-test"),
    )
    require.NoError(t, err)

    t.Cleanup(func() {
        _ = composeStack.Down(ctx, compose.RemoveOrphans(true), compose.RemoveVolumes(true))
    })

    err = composeStack.Up(ctx, compose.Wait(true))
    require.NoError(t, err)

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
        assert.NoError(t, err)
        assert.Equal(t, 200, resp.StatusCode)
    })
}
