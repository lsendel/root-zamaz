package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"mvp.local/pkg/session"
)

func TestDefaultSessionMiddlewareConfig(t *testing.T) {
	t.Run("DefaultSessionMiddlewareConfig_Values", func(t *testing.T) {
		config := DefaultSessionMiddlewareConfig()

		assert.Equal(t, "session_id", config.CookieName)
		assert.Equal(t, "/", config.CookiePath)
		assert.Equal(t, "", config.CookieDomain)
		assert.True(t, config.CookieSecure)
		assert.True(t, config.CookieHTTPOnly)
		assert.Equal(t, "Strict", config.CookieSameSite)
		assert.Equal(t, 24*time.Hour, config.CookieExpiration)
		assert.False(t, config.RequireSession)
		assert.True(t, config.AutoRefresh)
	})
}

func TestSessionMiddleware_NoSession(t *testing.T) {
	t.Run("SessionMiddleware_NoSessionCookie_NotRequired", func(t *testing.T) {
		// Create a mock session manager (can be nil for this test)
		sessionManager := &session.SessionManager{}

		app := fiber.New()
		app.Use(SessionMiddleware(sessionManager))
		app.Get("/test", func(c *fiber.Ctx) error {
			// Verify no session data in context
			sessionData, exists := GetSessionFromContext(c)
			assert.Nil(t, sessionData)
			assert.False(t, exists)

			userID := GetUserIDFromContext(c)
			assert.Empty(t, userID)

			return c.JSON(fiber.Map{"message": "no session required"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("SessionMiddleware_NoSessionCookie_Required", func(t *testing.T) {
		sessionManager := &session.SessionManager{}

		config := DefaultSessionMiddlewareConfig()
		config.RequireSession = true

		app := fiber.New()
		app.Use(SessionMiddleware(sessionManager, config))
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "should not reach here"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should return unauthorized error
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestSessionMiddleware_WithRedis(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Redis integration test in short mode")
	}

	// Create Redis client for testing
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1, // Use different DB for testing
	})

	ctx := context.Background()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis not available: %v", err)
	}

	// Clean up before and after tests
	redisClient.FlushDB(ctx)
	defer redisClient.FlushDB(ctx)

	sessionManager := session.NewSessionManager(redisClient, nil)

	t.Run("SessionMiddleware_ValidSession", func(t *testing.T) {
		app := fiber.New()
		app.Use(SessionMiddleware(sessionManager))
		app.Get("/test", func(c *fiber.Ctx) error {
			sessionData, exists := GetSessionFromContext(c)
			if !exists {
				return c.JSON(fiber.Map{"message": "no session"})
			}

			userID := GetUserIDFromContext(c)
			tenantID := GetTenantIDFromContext(c)

			return c.JSON(fiber.Map{
				"message":   "session found",
				"user_id":   userID,
				"tenant_id": tenantID,
				"session":   sessionData,
			})
		})

		// Create a session manually
		testUserID := "test-user-123"
		sessionData := session.SessionData{
			UserID:       testUserID,
			TenantID:     "test-tenant",
			IPAddress:    "192.168.1.1",
			UserAgent:    "test-agent",
			CreatedAt:    time.Now(),
			LastActivity: time.Now(),
			ExpiresAt:    time.Now().Add(24 * time.Hour),
		}

		createdSession, err := sessionManager.CreateSession(ctx, testUserID, sessionData)
		require.NoError(t, err)

		// Test with valid session cookie
		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  "session_id",
			Value: createdSession.SessionID,
		})

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("SessionMiddleware_InvalidSession", func(t *testing.T) {
		app := fiber.New()
		app.Use(SessionMiddleware(sessionManager))
		app.Get("/test", func(c *fiber.Ctx) error {
			sessionData, exists := GetSessionFromContext(c)
			if !exists {
				return c.JSON(fiber.Map{"message": "no session"})
			}

			return c.JSON(fiber.Map{
				"message": "session found",
				"session": sessionData,
			})
		})

		// Test with invalid session ID
		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  "session_id",
			Value: "invalid-session-id",
		})

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Should have cleared the invalid cookie
		cookies := resp.Cookies()
		var sessionCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "session_id" {
				sessionCookie = cookie
				break
			}
		}

		if sessionCookie != nil {
			// Cookie should be cleared (empty value and expired)
			assert.Empty(t, sessionCookie.Value)
			assert.True(t, sessionCookie.Expires.Before(time.Now()))
		}
	})

	t.Run("SessionMiddleware_RequiredSession_Invalid", func(t *testing.T) {
		config := DefaultSessionMiddlewareConfig()
		config.RequireSession = true

		app := fiber.New()
		app.Use(SessionMiddleware(sessionManager, config))
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "should not reach here"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  "session_id",
			Value: "invalid-session-id",
		})

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestRequireSessionMiddleware(t *testing.T) {
	t.Run("RequireSessionMiddleware_NoSession", func(t *testing.T) {
		sessionManager := &session.SessionManager{}

		app := fiber.New()
		app.Use(RequireSessionMiddleware(sessionManager))
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "protected"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestCreateSessionHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Redis integration test in short mode")
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1,
	})

	ctx := context.Background()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis not available: %v", err)
	}

	redisClient.FlushDB(ctx)
	defer redisClient.FlushDB(ctx)

	sessionManager := session.NewSessionManager(redisClient, nil)

	t.Run("CreateSessionHandler_Success", func(t *testing.T) {
		createSession := CreateSessionHandler(sessionManager)

		app := fiber.New()
		app.Post("/login", func(c *fiber.Ctx) error {
			// Simulate successful login
			userID := "test-user-456"
			sessionData := session.SessionData{
				TenantID:  "test-tenant",
				ExpiresAt: time.Now().Add(24 * time.Hour),
			}

			err := createSession(c, userID, sessionData)
			if err != nil {
				return err
			}

			// Verify session was created in context
			storedUserID := GetUserIDFromContext(c)
			storedTenantID := GetTenantIDFromContext(c)

			return c.JSON(fiber.Map{
				"message":   "login successful",
				"user_id":   storedUserID,
				"tenant_id": storedTenantID,
			})
		})

		req := httptest.NewRequest("POST", "/login", nil)
		req.Header.Set("User-Agent", "test-login-agent")

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Should have set session cookie
		cookies := resp.Cookies()
		var sessionCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "session_id" {
				sessionCookie = cookie
				break
			}
		}

		require.NotNil(t, sessionCookie)
		assert.NotEmpty(t, sessionCookie.Value)
		assert.True(t, sessionCookie.HttpOnly)
		assert.True(t, sessionCookie.Secure)
		assert.Equal(t, http.SameSiteStrictMode, sessionCookie.SameSite)
	})
}

func TestDestroySessionHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Redis integration test in short mode")
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1,
	})

	ctx := context.Background()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis not available: %v", err)
	}

	redisClient.FlushDB(ctx)
	defer redisClient.FlushDB(ctx)

	sessionManager := session.NewSessionManager(redisClient, nil)

	t.Run("DestroySessionHandler_Success", func(t *testing.T) {
		// Create a session first
		testUserID := "test-user-789"
		sessionData := session.SessionData{
			UserID:    testUserID,
			TenantID:  "test-tenant",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}

		createdSession, err := sessionManager.CreateSession(ctx, testUserID, sessionData)
		require.NoError(t, err)

		destroySession := DestroySessionHandler(sessionManager)

		app := fiber.New()
		app.Post("/logout", func(c *fiber.Ctx) error {
			err := destroySession(c)
			if err != nil {
				return err
			}

			// Verify session was cleared from context
			userID := GetUserIDFromContext(c)
			tenantID := GetTenantIDFromContext(c)

			return c.JSON(fiber.Map{
				"message":   "logout successful",
				"user_id":   userID,   // Should be empty
				"tenant_id": tenantID, // Should be empty
			})
		})

		req := httptest.NewRequest("POST", "/logout", nil)
		req.AddCookie(&http.Cookie{
			Name:  "session_id",
			Value: createdSession.SessionID,
		})

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Should have cleared session cookie
		cookies := resp.Cookies()
		var sessionCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "session_id" {
				sessionCookie = cookie
				break
			}
		}

		if sessionCookie != nil {
			assert.Empty(t, sessionCookie.Value)
			assert.True(t, sessionCookie.Expires.Before(time.Now()))
		}

		// Verify session was deleted from Redis
		_, err = sessionManager.GetSession(ctx, createdSession.SessionID)
		assert.Error(t, err) // Should error because session no longer exists
	})

	t.Run("DestroySessionHandler_NoSession", func(t *testing.T) {
		destroySession := DestroySessionHandler(sessionManager)

		app := fiber.New()
		app.Post("/logout", func(c *fiber.Ctx) error {
			err := destroySession(c)
			if err != nil {
				return err
			}

			return c.JSON(fiber.Map{"message": "no session to destroy"})
		})

		req := httptest.NewRequest("POST", "/logout", nil)
		// No session cookie

		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestSessionMiddleware_CustomConfig(t *testing.T) {
	t.Run("SessionMiddleware_CustomCookieConfig", func(t *testing.T) {
		sessionManager := &session.SessionManager{}

		config := SessionMiddlewareConfig{
			CookieName:       "custom_session",
			CookiePath:       "/api",
			CookieDomain:     "example.com",
			CookieSecure:     false,
			CookieHTTPOnly:   false,
			CookieSameSite:   "Lax",
			CookieExpiration: 12 * time.Hour,
			RequireSession:   false,
			AutoRefresh:      false,
		}

		app := fiber.New()
		app.Use(SessionMiddleware(sessionManager, config))
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "custom config"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("SessionMiddleware_CustomErrorHandler", func(t *testing.T) {
		sessionManager := &session.SessionManager{}

		config := DefaultSessionMiddlewareConfig()
		config.RequireSession = true
		config.ErrorResponse = func(c *fiber.Ctx, err error) error {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   "custom session error",
				"message": err.Error(),
			})
		}

		app := fiber.New()
		app.Use(SessionMiddleware(sessionManager, config))
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "protected"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("SessionMiddleware_RedirectOnError", func(t *testing.T) {
		sessionManager := &session.SessionManager{}

		config := DefaultSessionMiddlewareConfig()
		config.RequireSession = true
		config.RedirectOnError = "/login"

		app := fiber.New()
		app.Use(SessionMiddleware(sessionManager, config))
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "protected"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should redirect
		assert.True(t, resp.StatusCode >= 300 && resp.StatusCode < 400)
		assert.Equal(t, "/login", resp.Header.Get("Location"))
	})
}

func TestContextHelpers(t *testing.T) {
	t.Run("GetSessionFromContext_NoSession", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			sessionData, exists := GetSessionFromContext(c)
			assert.Nil(t, sessionData)
			assert.False(t, exists)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("GetUserIDFromContext_NoUserID", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			userID := GetUserIDFromContext(c)
			assert.Empty(t, userID)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("GetTenantIDFromContext_NoTenantID", func(t *testing.T) {
		app := fiber.New()
		app.Get("/test", func(c *fiber.Ctx) error {
			tenantID := GetTenantIDFromContext(c)
			assert.Empty(t, tenantID)
			return c.SendStatus(200)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// Benchmark tests
func BenchmarkSessionMiddleware_NoSession(b *testing.B) {
	sessionManager := &session.SessionManager{}

	app := fiber.New()
	app.Use(SessionMiddleware(sessionManager))
	app.Get("/bench", func(c *fiber.Ctx) error {
		return c.SendStatus(200)
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/bench", nil)
			_, _ = app.Test(req)
		}
	})
}

func BenchmarkGetUserIDFromContext(b *testing.B) {
	app := fiber.New()
	app.Get("/bench", func(c *fiber.Ctx) error {
		c.Locals("user_id", "test-user-123")

		for i := 0; i < 100; i++ {
			_ = GetUserIDFromContext(c)
		}

		return c.SendStatus(200)
	})

	req := httptest.NewRequest("GET", "/bench", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = app.Test(req)
	}
}
