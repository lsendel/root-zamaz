package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"mvp.local/pkg/observability"
	"mvp.local/pkg/testutil"
)

func TestRateLimiter_NewRateLimiter(t *testing.T) {
	t.Run("CreateRateLimiter_Success", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)
		client := redis.NewClient(&redis.Options{
			Addr: "localhost:6379",
			DB:   0,
		})

		rateLimiter := NewRateLimiter(client, obs)

		assert.NotNil(t, rateLimiter)
		assert.Equal(t, client, rateLimiter.redis)
		assert.Equal(t, obs, rateLimiter.obs)
		assert.Equal(t, DefaultRateLimit, rateLimiter.limit)
		assert.Equal(t, DefaultWindow, rateLimiter.window)
	})

	t.Run("CreateRateLimiter_WithNilRedis", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)

		rateLimiter := NewRateLimiter(nil, obs)

		assert.NotNil(t, rateLimiter)
		assert.Nil(t, rateLimiter.redis)
		assert.Equal(t, obs, rateLimiter.obs)
	})
}

func TestRateLimiter_SetConfig(t *testing.T) {
	t.Run("SetConfig_ValidValues", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)
		client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
		rateLimiter := NewRateLimiter(client, obs)

		rateLimiter.SetConfig(50, 30*time.Second)

		assert.Equal(t, 50, rateLimiter.limit)
		assert.Equal(t, 30*time.Second, rateLimiter.window)
	})

	t.Run("SetConfig_InvalidValues", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)
		client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
		rateLimiter := NewRateLimiter(client, obs)

		// Set negative values - should use defaults
		rateLimiter.SetConfig(-1, -5*time.Second)

		assert.Equal(t, DefaultRateLimit, rateLimiter.limit)
		assert.Equal(t, DefaultWindow, rateLimiter.window)

		// Set zero values - should use defaults
		rateLimiter.SetConfig(0, 0)

		assert.Equal(t, DefaultRateLimit, rateLimiter.limit)
		assert.Equal(t, DefaultWindow, rateLimiter.window)
	})
}

func TestRateLimiter_getClientIP(t *testing.T) {
	obs := testutil.SetupTestObservability(t)
	rateLimiter := NewRateLimiter(nil, obs)

	testCases := []struct {
		name           string
		headers        map[string]string
		remoteAddr     string
		expectedIP     string
	}{
		{
			name: "X-Forwarded-For_SingleIP",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.1",
			},
			remoteAddr: "10.0.0.1:8080",
			expectedIP: "192.168.1.1",
		},
		{
			name: "X-Forwarded-For_MultipleIPs",
			headers: map[string]string{
				"X-Forwarded-For": "192.168.1.1, 10.0.0.1, 172.16.0.1",
			},
			remoteAddr: "10.0.0.1:8080",
			expectedIP: "192.168.1.1",
		},
		{
			name: "X-Real-IP_Header",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.1",
			},
			remoteAddr: "10.0.0.1:8080",
			expectedIP: "203.0.113.1",
		},
		{
			name: "CF-Connecting-IP_Header",
			headers: map[string]string{
				"CF-Connecting-IP": "198.51.100.1",
			},
			remoteAddr: "10.0.0.1:8080",
			expectedIP: "198.51.100.1",
		},
		{
			name:       "RemoteAddr_NoHeaders",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.1:8080",
			expectedIP: "192.168.1.1",
		},
		{
			name:       "RemoteAddr_IPv6",
			headers:    map[string]string{},
			remoteAddr: "[2001:db8::1]:8080",
			expectedIP: "2001:db8::1",
		},
		{
			name:       "RemoteAddr_InvalidFormat",
			headers:    map[string]string{},
			remoteAddr: "invalid-addr",
			expectedIP: "invalid-addr",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New()
			
			app.Get("/test", func(c *fiber.Ctx) error {
				// Set headers
				for key, value := range tc.headers {
					c.Request().Header.Set(key, value)
				}
				
				ip := rateLimiter.getClientIP(c)
				assert.Equal(t, tc.expectedIP, ip)
				return c.SendStatus(200)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tc.remoteAddr

			_, err := app.Test(req)
			require.NoError(t, err)
		})
	}
}

func TestRateLimiter_RateLimitMiddleware_NoRedis(t *testing.T) {
	t.Run("NoRedis_PassThrough", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)
		rateLimiter := NewRateLimiter(nil, obs)

		app := fiber.New()
		app.Use(rateLimiter.RateLimitMiddleware())
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "success"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestRateLimiter_WithMockRedis(t *testing.T) {
	// Create a test Redis client for integration testing
	// Note: This requires a running Redis instance for full testing
	testRedisAddr := "localhost:6379"
	
	t.Run("RateLimit_AllowedRequests", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping Redis integration test in short mode")
		}

		obs := testutil.SetupTestObservability(t)
		client := redis.NewClient(&redis.Options{
			Addr: testRedisAddr,
			DB:   1, // Use different DB for testing
		})

		// Test Redis connection
		ctx := context.Background()
		if err := client.Ping(ctx).Err(); err != nil {
			t.Skipf("Redis not available at %s: %v", testRedisAddr, err)
		}

		// Clean up before test
		client.FlushDB(ctx)
		defer client.FlushDB(ctx)

		rateLimiter := NewRateLimiter(client, obs)
		rateLimiter.SetConfig(5, 60*time.Second) // 5 requests per minute

		app := fiber.New()
		app.Use(rateLimiter.RateLimitMiddleware())
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "success"})
		})

		// Make 5 requests - all should succeed
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.1:8080"

			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode, "Request %d should succeed", i+1)
		}
	})

	t.Run("RateLimit_ExceededRequests", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping Redis integration test in short mode")
		}

		obs := testutil.SetupTestObservability(t)
		client := redis.NewClient(&redis.Options{
			Addr: testRedisAddr,
			DB:   1,
		})

		ctx := context.Background()
		if err := client.Ping(ctx).Err(); err != nil {
			t.Skipf("Redis not available at %s: %v", testRedisAddr, err)
		}

		client.FlushDB(ctx)
		defer client.FlushDB(ctx)

		rateLimiter := NewRateLimiter(client, obs)
		rateLimiter.SetConfig(3, 60*time.Second) // 3 requests per minute

		app := fiber.New()
		app.Use(rateLimiter.RateLimitMiddleware())
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "success"})
		})

		clientIP := "192.168.1.2"

		// Make 3 requests - should succeed
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = fmt.Sprintf("%s:8080", clientIP)

			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode, "Request %d should succeed", i+1)
		}

		// 4th request should be rate limited
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = fmt.Sprintf("%s:8080", clientIP)

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "Request 4 should be rate limited")
	})

	t.Run("RateLimit_DifferentIPs", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping Redis integration test in short mode")
		}

		obs := testutil.SetupTestObservability(t)
		client := redis.NewClient(&redis.Options{
			Addr: testRedisAddr,
			DB:   1,
		})

		ctx := context.Background()
		if err := client.Ping(ctx).Err(); err != nil {
			t.Skipf("Redis not available at %s: %v", testRedisAddr, err)
		}

		client.FlushDB(ctx)
		defer client.FlushDB(ctx)

		rateLimiter := NewRateLimiter(client, obs)
		rateLimiter.SetConfig(2, 60*time.Second) // 2 requests per minute

		app := fiber.New()
		app.Use(rateLimiter.RateLimitMiddleware())
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "success"})
		})

		// Test that different IPs have separate rate limits
		ips := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}

		for _, ip := range ips {
			// Each IP should be able to make 2 requests
			for i := 0; i < 2; i++ {
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = fmt.Sprintf("%s:8080", ip)

				resp, err := app.Test(req)
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode, "IP %s request %d should succeed", ip, i+1)
			}

			// 3rd request should be rate limited for this IP
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = fmt.Sprintf("%s:8080", ip)

			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "IP %s request 3 should be rate limited", ip)
		}
	})

	t.Run("RateLimit_WindowExpiry", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping Redis integration test in short mode")
		}

		obs := testutil.SetupTestObservability(t)
		client := redis.NewClient(&redis.Options{
			Addr: testRedisAddr,
			DB:   1,
		})

		ctx := context.Background()
		if err := client.Ping(ctx).Err(); err != nil {
			t.Skipf("Redis not available at %s: %v", testRedisAddr, err)
		}

		client.FlushDB(ctx)
		defer client.FlushDB(ctx)

		rateLimiter := NewRateLimiter(client, obs)
		rateLimiter.SetConfig(1, 2*time.Second) // 1 request per 2 seconds

		app := fiber.New()
		app.Use(rateLimiter.RateLimitMiddleware())
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "success"})
		})

		clientIP := "192.168.1.100"

		// First request should succeed
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = fmt.Sprintf("%s:8080", clientIP)

		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Second request immediately should be rate limited
		req = httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = fmt.Sprintf("%s:8080", clientIP)

		resp, err = app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)

		// Wait for window to expire
		time.Sleep(3 * time.Second)

		// Request should succeed again after window expiry
		req = httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = fmt.Sprintf("%s:8080", clientIP)

		resp, err = app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestRateLimiter_RedisErrors(t *testing.T) {
	t.Run("Redis_ConnectionError", func(t *testing.T) {
		obs := testutil.SetupTestObservability(t)
		// Create client with invalid address to simulate connection error
		client := redis.NewClient(&redis.Options{
			Addr: "invalid:6379",
			DB:   0,
		})

		rateLimiter := NewRateLimiter(client, obs)

		app := fiber.New()
		app.Use(rateLimiter.RateLimitMiddleware())
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "success"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)

		// Should pass through on Redis errors (fail open)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestRateLimiter_Headers(t *testing.T) {
	t.Run("RateLimit_Headers", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping Redis integration test in short mode")
		}

		obs := testutil.SetupTestObservability(t)
		client := redis.NewClient(&redis.Options{
			Addr: "localhost:6379",
			DB:   1,
		})

		ctx := context.Background()
		if err := client.Ping(ctx).Err(); err != nil {
			t.Skipf("Redis not available: %v", err)
		}

		client.FlushDB(ctx)
		defer client.FlushDB(ctx)

		rateLimiter := NewRateLimiter(client, obs)
		rateLimiter.SetConfig(5, 60*time.Second)

		app := fiber.New()
		app.Use(rateLimiter.RateLimitMiddleware())
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"message": "success"})
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:8080"

		resp, err := app.Test(req)
		require.NoError(t, err)

		// Check that rate limit headers are set
		assert.NotEmpty(t, resp.Header.Get("X-RateLimit-Limit"))
		assert.NotEmpty(t, resp.Header.Get("X-RateLimit-Remaining"))
		assert.NotEmpty(t, resp.Header.Get("X-RateLimit-Reset"))
	})
}

// Benchmark tests
func BenchmarkRateLimiter_Middleware(b *testing.B) {
	obs := testutil.SetupTestObservability(b)
	rateLimiter := NewRateLimiter(nil, obs) // No Redis for benchmark

	app := fiber.New()
	app.Use(rateLimiter.RateLimitMiddleware())
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendStatus(200)
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/test", nil)
			_, _ = app.Test(req)
		}
	})
}