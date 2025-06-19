package audit

import (
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	"mvp.local/pkg/models"
	"mvp.local/pkg/testutil"
)

func TestLogEventCompliance(t *testing.T) {
	db := testutil.SetupTestDB(t)
	obs := testutil.NewMockObservability()
	svc := NewService(db, obs)

	app := fiber.New()
	ctx := app.AcquireCtx(new(fasthttp.RequestCtx))
	defer app.ReleaseCtx(ctx)

	svc.LogEvent(LogEntry{
		Action:        "test",
		Resource:      "system",
		Details:       map[string]interface{}{"foo": "bar"},
		Success:       true,
		Context:       ctx,
		ComplianceTag: "GDPR",
		Retention:     24 * time.Hour,
	})

	time.Sleep(100 * time.Millisecond)

	var count int64
	require.NoError(t, db.Model(&models.AuditLog{}).Count(&count).Error)
	require.Equal(t, int64(1), count)

	var logEntry models.AuditLog
	require.NoError(t, db.First(&logEntry).Error)
	require.Equal(t, "GDPR", logEntry.ComplianceTag)
	require.WithinDuration(t, time.Now().Add(24*time.Hour), *logEntry.RetainUntil, time.Second)
}
