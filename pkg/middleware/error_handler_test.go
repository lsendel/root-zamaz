package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"mvp.local/pkg/errors"
	"mvp.local/pkg/observability"
	"mvp.local/pkg/testutil"
)

// helper to create fiber app with error handler
func newErrorApp(obs *observability.Observability) *fiber.App {
	return fiber.New(fiber.Config{ErrorHandler: ErrorHandlerMiddleware(obs)})
}

func TestErrorHandlerMiddleware_AppError(t *testing.T) {
	obs := testutil.SetupTestObservability(t)
	app := newErrorApp(obs)

	app.Get("/fail", func(c *fiber.Ctx) error {
		return errors.Validation("bad input")
	})

	req := httptest.NewRequest("GET", "/fail", nil)
	req.Header.Set("X-Request-ID", "req-1")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	errObj := body["error"].(map[string]interface{})
	assert.Equal(t, string(errors.CodeValidation), errObj["code"])
	assert.Equal(t, "bad input", errObj["message"])
	assert.Equal(t, "req-1", body["request_id"])
}

func TestErrorHandlerMiddleware_GenericError(t *testing.T) {
	obs := testutil.SetupTestObservability(t)
	app := newErrorApp(obs)

	app.Get("/boom", func(c *fiber.Ctx) error {
		return fiber.ErrInternalServerError
	})

	req := httptest.NewRequest("GET", "/boom", nil)
	req.Header.Set("X-Request-ID", "req-2")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	errObj := body["error"].(map[string]interface{})
	assert.Equal(t, string(errors.CodeInternal), errObj["code"])
	assert.Equal(t, "An internal error occurred", errObj["message"])
}

func TestRecoveryMiddleware(t *testing.T) {
	obs := testutil.SetupTestObservability(t)
	app := fiber.New()
	app.Use(RecoveryMiddleware(obs))

	app.Get("/panic", func(c *fiber.Ctx) error {
		panic("boom")
	})

	req := httptest.NewRequest("GET", "/panic", nil)
	req.Header.Set("X-Request-ID", "req-3")

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	errObj := body["error"].(map[string]interface{})
	assert.Equal(t, string(errors.CodeInternal), errObj["code"])
	assert.Equal(t, "An unexpected error occurred", errObj["message"])
}
