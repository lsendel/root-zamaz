package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	// Clear environment
	clearTestEnv()

	t.Run("load with defaults", func(t *testing.T) {
		config, err := Load()
		require.NoError(t, err)
		require.NotNil(t, config)

		// Verify defaults
		assert.Equal(t, "mvp-zero-trust-auth", config.App.Name)
		assert.Equal(t, "dev", config.App.Version)
		assert.Equal(t, "development", config.App.Environment)
		assert.False(t, config.App.Debug)

		assert.Equal(t, 8080, config.HTTP.Port)
		assert.Equal(t, "0.0.0.0", config.HTTP.Host)
		assert.Equal(t, 30*time.Second, config.HTTP.ReadTimeout)

		assert.Equal(t, "localhost", config.Database.Host)
		assert.Equal(t, 5432, config.Database.Port)
		assert.Equal(t, "mvp_db", config.Database.Database)

		assert.Equal(t, "info", config.Observability.LogLevel)
		assert.Equal(t, "json", config.Observability.LogFormat)
		assert.Equal(t, 1.0, config.Observability.SamplingRatio)
	})

	t.Run("load with environment variables", func(t *testing.T) {
		// Set environment variables
		os.Setenv("APP_NAME", "test-app")
		os.Setenv("HTTP_PORT", "9000")
		os.Setenv("DEBUG", "true")
		os.Setenv("LOG_LEVEL", "debug")
		os.Setenv("DB_MAX_CONNECTIONS", "50")
		os.Setenv("TRACING_SAMPLING_RATIO", "0.5")

		defer clearTestEnv()

		config, err := Load()
		require.NoError(t, err)

		assert.Equal(t, "test-app", config.App.Name)
		assert.Equal(t, 9000, config.HTTP.Port)
		assert.True(t, config.App.Debug)
		assert.Equal(t, "debug", config.Observability.LogLevel)
		assert.Equal(t, 50, config.Database.MaxConnections)
		assert.Equal(t, 0.5, config.Observability.SamplingRatio)
	})
}

func TestValidateConfig(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		config := &Config{
			App: AppConfig{
				Name:        "test-app",
				Version:     "1.0.0",
				Environment: "test",
			},
			HTTP: HTTPConfig{
				Port:         8080,
				Host:         "localhost",
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
				IdleTimeout:  120 * time.Second,
			},
			Database: DatabaseConfig{
				Host:                "localhost",
				Port:                5432,
				Database:            "testdb",
				Username:            "testuser",
				MaxConnections:      25,
				MaxIdleConns:        5,
				MinIdleConns:        2,
				OptimizationProfile: "balanced",
				FailureThreshold:    3,
				MonitoringInterval:  5 * time.Minute,
			},
			Observability: ObservabilityConfig{
				ServiceName:    "test-service",
				ServiceVersion: "1.0.0",
				Environment:    "test",
				LogLevel:       "info",
				LogFormat:      "json",
				PrometheusPort: 9090,
				JaegerEndpoint: "http://localhost:14268/api/traces",
				SamplingRatio:  0.5,
				MetricsPath:    "/metrics",
				HealthPath:     "/health",
				BatchTimeout:   1 * time.Second,
				ExportTimeout:  30 * time.Second,
			},
			Security: SecurityConfig{
				JWT: JWTConfig{
					Secret:         "test-secret",
					ExpiryDuration: 24 * time.Hour,
					Algorithm:      "HS256",
				},
				Lockout: LockoutConfig{
					MaxFailedAttempts: 5,
					LockoutDuration:   15 * time.Minute,
					ResetWindow:       1 * time.Hour,
				},
			},
		}

		err := validateConfig(config)
		assert.NoError(t, err)
	})

	t.Run("missing required fields", func(t *testing.T) {
		tests := []struct {
			name   string
			config *Config
			errMsg string
		}{
			{
				name: "missing app name",
				config: &Config{
					App: AppConfig{Name: ""},
				},
				errMsg: "app.name is required",
			},
			{
				name: "invalid port",
				config: &Config{
					App:  AppConfig{Name: "test"},
					HTTP: HTTPConfig{Port: -1},
				},
				errMsg: "http.port must be between 1 and 65535",
			},
			{
				name: "missing database host",
				config: &Config{
					App:      AppConfig{Name: "test"},
					HTTP:     HTTPConfig{Port: 8080},
					Database: DatabaseConfig{Host: ""},
				},
				errMsg: "database.host is required",
			},
			{
				name: "invalid log level",
				config: &Config{
					App:      AppConfig{Name: "test"},
					HTTP:     HTTPConfig{Port: 8080},
					Database: DatabaseConfig{Host: "localhost", Database: "test", Username: "test"},
					Observability: ObservabilityConfig{
						LogLevel:      "invalid",
						LogFormat:     "json",
						SamplingRatio: 1.0,
					},
				},
				errMsg: "observability.log_level must be one of: debug, info, warn, error",
			},
			{
				name: "invalid sampling ratio",
				config: &Config{
					App:      AppConfig{Name: "test"},
					HTTP:     HTTPConfig{Port: 8080},
					Database: DatabaseConfig{Host: "localhost", Database: "test", Username: "test"},
					Observability: ObservabilityConfig{
						LogLevel:      "info",
						LogFormat:     "json",
						SamplingRatio: 1.5,
					},
				},
				errMsg: "observability.sampling_ratio must be between 0 and 1",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := validateConfig(tt.config)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			})
		}
	})

	t.Run("production validation", func(t *testing.T) {
		config := &Config{
			App: AppConfig{
				Name:        "test-app",
				Environment: "production",
			},
			HTTP: HTTPConfig{Port: 8080},
			Database: DatabaseConfig{
				Host:     "localhost",
				Database: "testdb",
				Username: "testuser",
			},
			Observability: ObservabilityConfig{
				LogLevel:      "info",
				LogFormat:     "json",
				SamplingRatio: 1.0,
			},
			Security: SecurityConfig{
				JWT: JWTConfig{Secret: ""}, // Missing JWT secret in production
			},
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "jwt.secret is required in production")
	})

	t.Run("TLS validation", func(t *testing.T) {
		config := &Config{
			App: AppConfig{Name: "test-app"},
			HTTP: HTTPConfig{
				Port: 8080,
				TLS: TLSConfig{
					Enabled:  true,
					CertFile: "", // Missing cert file
					KeyFile:  "key.pem",
				},
			},
			Database: DatabaseConfig{
				Host:     "localhost",
				Database: "testdb",
				Username: "testuser",
			},
			Observability: ObservabilityConfig{
				LogLevel:      "info",
				LogFormat:     "json",
				SamplingRatio: 1.0,
			},
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "tls.cert_file is required when TLS is enabled")
	})
}

func TestConfigMethods(t *testing.T) {
	t.Run("DatabaseDSN", func(t *testing.T) {
		db := DatabaseConfig{
			Host:     "localhost",
			Port:     5432,
			Username: "user",
			Password: "pass",
			Database: "testdb",
			SSLMode:  "disable",
		}

		expected := "host=localhost port=5432 user=user password=pass dbname=testdb sslmode=disable"
		assert.Equal(t, expected, db.DatabaseDSN())
	})

	t.Run("RedisAddr", func(t *testing.T) {
		redis := RedisConfig{
			Host: "localhost",
			Port: 6379,
		}

		assert.Equal(t, "localhost:6379", redis.RedisAddr())
	})

	t.Run("HTTPAddr", func(t *testing.T) {
		http := HTTPConfig{
			Host: "0.0.0.0",
			Port: 8080,
		}

		assert.Equal(t, "0.0.0.0:8080", http.HTTPAddr())
	})
}

func TestAppConfigEnvironmentMethods(t *testing.T) {
	tests := []struct {
		environment string
		isProd      bool
		isDev       bool
		isTest      bool
	}{
		{"production", true, false, false},
		{"PRODUCTION", true, false, false},
		{"development", false, true, false},
		{"DEVELOPMENT", false, true, false},
		{"test", false, false, true},
		{"TEST", false, false, true},
		{"staging", false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.environment, func(t *testing.T) {
			app := AppConfig{Environment: tt.environment}

			assert.Equal(t, tt.isProd, app.IsProduction())
			assert.Equal(t, tt.isDev, app.IsDevelopment())
			assert.Equal(t, tt.isTest, app.IsTest())
		})
	}
}

func TestEnvHelpers(t *testing.T) {
	t.Run("getEnvWithDefault", func(t *testing.T) {
		os.Setenv("TEST_STRING", "test_value")
		defer os.Unsetenv("TEST_STRING")

		assert.Equal(t, "test_value", getEnvWithDefault("TEST_STRING", "default"))
		assert.Equal(t, "default", getEnvWithDefault("NON_EXISTENT", "default"))
	})

	t.Run("getEnvIntWithDefault", func(t *testing.T) {
		os.Setenv("TEST_INT", "42")
		os.Setenv("TEST_INT_INVALID", "not_a_number")
		defer func() {
			os.Unsetenv("TEST_INT")
			os.Unsetenv("TEST_INT_INVALID")
		}()

		assert.Equal(t, 42, getEnvIntWithDefault("TEST_INT", 10))
		assert.Equal(t, 10, getEnvIntWithDefault("TEST_INT_INVALID", 10))
		assert.Equal(t, 10, getEnvIntWithDefault("NON_EXISTENT", 10))
	})

	t.Run("getEnvBoolWithDefault", func(t *testing.T) {
		os.Setenv("TEST_BOOL_TRUE", "true")
		os.Setenv("TEST_BOOL_FALSE", "false")
		os.Setenv("TEST_BOOL_INVALID", "not_a_bool")
		defer func() {
			os.Unsetenv("TEST_BOOL_TRUE")
			os.Unsetenv("TEST_BOOL_FALSE")
			os.Unsetenv("TEST_BOOL_INVALID")
		}()

		assert.True(t, getEnvBoolWithDefault("TEST_BOOL_TRUE", false))
		assert.False(t, getEnvBoolWithDefault("TEST_BOOL_FALSE", true))
		assert.True(t, getEnvBoolWithDefault("TEST_BOOL_INVALID", true))
		assert.False(t, getEnvBoolWithDefault("NON_EXISTENT", false))
	})

	t.Run("getEnvDurationWithDefault", func(t *testing.T) {
		os.Setenv("TEST_DURATION", "5s")
		os.Setenv("TEST_DURATION_INVALID", "not_a_duration")
		defer func() {
			os.Unsetenv("TEST_DURATION")
			os.Unsetenv("TEST_DURATION_INVALID")
		}()

		assert.Equal(t, 5*time.Second, getEnvDurationWithDefault("TEST_DURATION", time.Minute))
		assert.Equal(t, time.Minute, getEnvDurationWithDefault("TEST_DURATION_INVALID", time.Minute))
		assert.Equal(t, time.Minute, getEnvDurationWithDefault("NON_EXISTENT", time.Minute))
	})

	t.Run("getEnvSliceWithDefault", func(t *testing.T) {
		os.Setenv("TEST_SLICE", "a,b,c")
		defer os.Unsetenv("TEST_SLICE")

		expected := []string{"a", "b", "c"}
		defaultSlice := []string{"default"}

		assert.Equal(t, expected, getEnvSliceWithDefault("TEST_SLICE", defaultSlice))
		assert.Equal(t, defaultSlice, getEnvSliceWithDefault("NON_EXISTENT", defaultSlice))
	})
}

func clearTestEnv() {
	envVars := []string{
		"APP_NAME", "APP_VERSION", "ENVIRONMENT", "DEBUG",
		"HTTP_PORT", "HTTP_HOST", "TLS_ENABLED",
		"DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD",
		"LOG_LEVEL", "LOG_FORMAT", "TRACING_SAMPLING_RATIO",
		"JWT_SECRET",
	}

	for _, env := range envVars {
		os.Unsetenv(env)
	}
}
