package observability

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewSLAMetrics(t *testing.T) {
	obs, err := New(Config{ServiceName: "test", PrometheusPort: 0})
	require.NoError(t, err)
	defer obs.Shutdown(context.Background())

	metrics, err := NewSLAMetrics(obs.Meter)
	require.NoError(t, err)
	require.NotNil(t, metrics)
}

func TestSLAMetrics_Record(t *testing.T) {
	obs, err := New(Config{ServiceName: "test", PrometheusPort: 0})
	require.NoError(t, err)
	defer obs.Shutdown(context.Background())

	metrics, err := NewSLAMetrics(obs.Meter)
	require.NoError(t, err)

	ctx := context.Background()
	metrics.RecordHTTPRequest(ctx, "GET", "/", 200)
	metrics.RecordHTTPRequest(ctx, "GET", "/", 500)

	metrics.StartUptimeCollection(ctx, 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
}
