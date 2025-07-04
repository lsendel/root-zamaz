// Package config provides structured configuration management for the MVP Zero Trust Auth system.
// It supports environment variables, YAML files, and validation with sensible defaults.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"mvp.local/pkg/errors"
)

// Config represents the complete application configuration
type Config struct {
	App           AppConfig           `yaml:"app"`
	Database      DatabaseConfig      `yaml:"database"`
	Redis         RedisConfig         `yaml:"redis"`
	NATS          NATSConfig          `yaml:"nats"`
	Observability ObservabilityConfig `yaml:"observability"`
	Security      SecurityConfig      `yaml:"security"`
	HTTP          HTTPConfig          `yaml:"http"`
}

// AppConfig contains general application settings
type AppConfig struct {
	Name          string `yaml:"name" env:"APP_NAME" default:"mvp-zero-trust-auth"`
	Version       string `yaml:"version" env:"APP_VERSION" default:"dev"`
	Environment   string `yaml:"environment" env:"ENVIRONMENT" default:"development"`
	Debug         bool   `yaml:"debug" env:"DEBUG" default:"false"`
	RBACModelPath string `yaml:"rbac_model_path" env:"RBAC_MODEL_PATH" default:"configs/rbac_model.conf"`
}

// HTTPConfig contains HTTP server configuration
type HTTPConfig struct {
	Port         int           `yaml:"port" env:"HTTP_PORT" default:"8080"`
	Host         string        `yaml:"host" env:"HTTP_HOST" default:"0.0.0.0"`
	ReadTimeout  time.Duration `yaml:"read_timeout" env:"HTTP_READ_TIMEOUT" default:"30s"`
	WriteTimeout time.Duration `yaml:"write_timeout" env:"HTTP_WRITE_TIMEOUT" default:"30s"`
	IdleTimeout  time.Duration `yaml:"idle_timeout" env:"HTTP_IDLE_TIMEOUT" default:"120s"`
	TLS          TLSConfig     `yaml:"tls"`
}

// TLSConfig contains TLS configuration
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled" env:"TLS_ENABLED" default:"false"`
	CertFile string `yaml:"cert_file" env:"TLS_CERT_FILE"`
	KeyFile  string `yaml:"key_file" env:"TLS_KEY_FILE"`
}

// DatabaseConfig contains database connection settings
type DatabaseConfig struct {
	Host     string `yaml:"host" env:"DB_HOST" default:"localhost"`
	Port     int    `yaml:"port" env:"DB_PORT" default:"5432"`
	Database string `yaml:"database" env:"DB_NAME" default:"mvp_db"`
	Username string `yaml:"username" env:"DB_USER" default:"mvp_user"`
	Password string `yaml:"password" env:"DB_PASSWORD" default:"please_change_this_password_in_production"`
	SSLMode  string `yaml:"ssl_mode" env:"DB_SSL_MODE" default:"disable"`

	// Connection pool settings
	MaxConnections  int           `yaml:"max_connections" env:"DB_MAX_CONNECTIONS" default:"25"`
	MaxIdleConns    int           `yaml:"max_idle_conns" env:"DB_MAX_IDLE_CONNS" default:"5"`
	MinIdleConns    int           `yaml:"min_idle_conns" env:"DB_MIN_IDLE_CONNS" default:"2"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime" env:"DB_CONN_MAX_LIFETIME" default:"300s"`
	ConnMaxIdleTime time.Duration `yaml:"conn_max_idle_time" env:"DB_CONN_MAX_IDLE_TIME" default:"60s"`

	// Advanced pool optimization
	OptimizationProfile string        `yaml:"optimization_profile" env:"DB_OPTIMIZATION_PROFILE" default:"balanced"`
	AutoTuning          bool          `yaml:"auto_tuning" env:"DB_AUTO_TUNING" default:"true"`
	MonitoringInterval  time.Duration `yaml:"monitoring_interval" env:"DB_MONITORING_INTERVAL" default:"30s"`
	LeakDetection       bool          `yaml:"leak_detection" env:"DB_LEAK_DETECTION" default:"true"`
	LeakThreshold       time.Duration `yaml:"leak_threshold" env:"DB_LEAK_THRESHOLD" default:"60s"`

	// Performance tuning
	MaxQueueWait     time.Duration `yaml:"max_queue_wait" env:"DB_MAX_QUEUE_WAIT" default:"30s"`
	RetryAttempts    int           `yaml:"retry_attempts" env:"DB_RETRY_ATTEMPTS" default:"3"`
	RetryDelay       time.Duration `yaml:"retry_delay" env:"DB_RETRY_DELAY" default:"1s"`
	CircuitBreaker   bool          `yaml:"circuit_breaker" env:"DB_CIRCUIT_BREAKER" default:"true"`
	FailureThreshold int           `yaml:"failure_threshold" env:"DB_FAILURE_THRESHOLD" default:"5"`

	// Query timeouts
	QueryTimeout   time.Duration `yaml:"query_timeout" env:"DB_QUERY_TIMEOUT" default:"30s"`
	ConnectTimeout time.Duration `yaml:"connect_timeout" env:"DB_CONNECT_TIMEOUT" default:"10s"`

	// Performance tuning
	PrepareStmt       bool `yaml:"prepare_stmt" env:"DB_PREPARE_STMT" default:"true"`
	DisableForeignKey bool `yaml:"disable_foreign_key" env:"DB_DISABLE_FOREIGN_KEY" default:"false"`

	// Monitoring and observability
	EnableMetrics       bool          `yaml:"enable_metrics" env:"DB_ENABLE_METRICS" default:"true"`
	SlowQueryThreshold  time.Duration `yaml:"slow_query_threshold" env:"DB_SLOW_QUERY_THRESHOLD" default:"1s"`
	DetailedMetrics     bool          `yaml:"detailed_metrics" env:"DB_DETAILED_METRICS" default:"false"`
	QueryLogging        bool          `yaml:"query_logging" env:"DB_QUERY_LOGGING" default:"false"`
	ConnectionTracing   bool          `yaml:"connection_tracing" env:"DB_CONNECTION_TRACING" default:"false"`
	StatsExportInterval time.Duration `yaml:"stats_export_interval" env:"DB_STATS_EXPORT_INTERVAL" default:"60s"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval" env:"DB_HEALTH_CHECK_INTERVAL" default:"30s"`
}

// RedisConfig contains Redis connection settings
type RedisConfig struct {
	Host         string        `yaml:"host" env:"REDIS_HOST" default:"localhost"`
	Port         int           `yaml:"port" env:"REDIS_PORT" default:"6379"`
	Password     string        `yaml:"password" env:"REDIS_PASSWORD"`
	Database     int           `yaml:"database" env:"REDIS_DB" default:"0"`
	PoolSize     int           `yaml:"pool_size" env:"REDIS_POOL_SIZE" default:"10"`
	DialTimeout  time.Duration `yaml:"dial_timeout" env:"REDIS_DIAL_TIMEOUT" default:"5s"`
	ReadTimeout  time.Duration `yaml:"read_timeout" env:"REDIS_READ_TIMEOUT" default:"3s"`
	WriteTimeout time.Duration `yaml:"write_timeout" env:"REDIS_WRITE_TIMEOUT" default:"3s"`
}

// NATSConfig contains NATS messaging configuration
type NATSConfig struct {
	URL            string        `yaml:"url" env:"NATS_URL" default:"nats://localhost:4222"`
	ClientID       string        `yaml:"client_id" env:"NATS_CLIENT_ID"`
	ClusterID      string        `yaml:"cluster_id" env:"NATS_CLUSTER_ID" default:"mvp-cluster"`
	MaxReconnects  int           `yaml:"max_reconnects" env:"NATS_MAX_RECONNECTS" default:"5"`
	ReconnectWait  time.Duration `yaml:"reconnect_wait" env:"NATS_RECONNECT_WAIT" default:"2s"`
	ConnectionName string        `yaml:"connection_name" env:"NATS_CONNECTION_NAME" default:"mvp-service"`
	PingInterval   time.Duration `yaml:"ping_interval" env:"NATS_PING_INTERVAL" default:"120s"`
	MaxPingsOut    int           `yaml:"max_pings_out" env:"NATS_MAX_PINGS_OUT" default:"2"`
}

// ObservabilityConfig contains observability and monitoring settings
type ObservabilityConfig struct {
	ServiceName    string        `yaml:"service_name" env:"SERVICE_NAME" default:"mvp-zero-trust-auth"`
	ServiceVersion string        `yaml:"service_version" env:"SERVICE_VERSION" default:"dev"`
	Environment    string        `yaml:"environment" env:"OBSERVABILITY_ENVIRONMENT" default:"development"`
	LogLevel       string        `yaml:"log_level" env:"LOG_LEVEL" default:"info"`
	LogFormat      string        `yaml:"log_format" env:"LOG_FORMAT" default:"json"`
	PrometheusPort int           `yaml:"prometheus_port" env:"PROMETHEUS_PORT" default:"9090"`
	JaegerEndpoint string        `yaml:"jaeger_endpoint" env:"JAEGER_ENDPOINT" default:"http://localhost:14268/api/traces"`
	SamplingRatio  float64       `yaml:"sampling_ratio" env:"TRACING_SAMPLING_RATIO" default:"1.0"`
	MetricsPath    string        `yaml:"metrics_path" env:"METRICS_PATH" default:"/metrics"`
	HealthPath     string        `yaml:"health_path" env:"HEALTH_PATH" default:"/health"`
	BatchTimeout   time.Duration `yaml:"batch_timeout" env:"TRACING_BATCH_TIMEOUT" default:"1s"`
	ExportTimeout  time.Duration `yaml:"export_timeout" env:"TRACING_EXPORT_TIMEOUT" default:"30s"`
}

// SecurityConfig contains security-related settings
type SecurityConfig struct {
	SPIRE              SPIREConfig          `yaml:"spire"`
	JWT                JWTConfig            `yaml:"jwt"`
	CORS               CORSConfig           `yaml:"cors"`
	RateLimit          RateLimitConfig      `yaml:"rate_limit"`
	Lockout            LockoutConfig        `yaml:"lockout"`
	RequestSigning     RequestSigningConfig `yaml:"request_signing"`
	TrustedProxies     []string             `yaml:"trusted_proxies" env:"TRUSTED_PROXIES"`
	AllowedOrigins     []string             `yaml:"allowed_origins" env:"ALLOWED_ORIGINS"`
	SecureHeaders      bool                 `yaml:"secure_headers" env:"SECURE_HEADERS" default:"true"`
	ContentTypeNosniff bool                 `yaml:"content_type_nosniff" env:"CONTENT_TYPE_NOSNIFF" default:"true"`
	DisableAuth        bool                 `yaml:"disable_auth" env:"DISABLE_AUTH" default:"false"`
}

// SPIREConfig contains SPIRE workload identity settings
type SPIREConfig struct {
	SocketPath    string        `yaml:"socket_path" env:"SPIRE_SOCKET_PATH" default:"/tmp/spire-agent/public/api.sock"`
	ServerAddress string        `yaml:"server_address" env:"SPIRE_SERVER_ADDRESS" default:"unix:///tmp/spire-server/private/api.sock"`
	TrustDomain   string        `yaml:"trust_domain" env:"SPIRE_TRUST_DOMAIN" default:"example.org"`
	DefaultSVID   string        `yaml:"default_svid" env:"SPIRE_DEFAULT_SVID"`
	FetchTimeout  time.Duration `yaml:"fetch_timeout" env:"SPIRE_FETCH_TIMEOUT" default:"30s"`
	RefreshHint   time.Duration `yaml:"refresh_hint" env:"SPIRE_REFRESH_HINT" default:"30s"`
}

// JWTConfig contains JWT token settings
type JWTConfig struct {
	Secret         string        `yaml:"secret" env:"JWT_SECRET"`
	Issuer         string        `yaml:"issuer" env:"JWT_ISSUER" default:"mvp-zero-trust-auth"`
	Audience       string        `yaml:"audience" env:"JWT_AUDIENCE" default:"mvp-services"`
	ExpiryDuration time.Duration `yaml:"expiry_duration" env:"JWT_EXPIRY_DURATION" default:"24h"`
	Algorithm      string        `yaml:"algorithm" env:"JWT_ALGORITHM" default:"HS256"`
}

// CORSConfig contains CORS settings
type CORSConfig struct {
	Enabled          bool     `yaml:"enabled" env:"CORS_ENABLED" default:"true"`
	AllowedOrigins   []string `yaml:"allowed_origins" env:"CORS_ALLOWED_ORIGINS"`
	AllowedMethods   []string `yaml:"allowed_methods" env:"CORS_ALLOWED_METHODS"`
	AllowedHeaders   []string `yaml:"allowed_headers" env:"CORS_ALLOWED_HEADERS"`
	ExposedHeaders   []string `yaml:"exposed_headers" env:"CORS_EXPOSED_HEADERS"`
	AllowCredentials bool     `yaml:"allow_credentials" env:"CORS_ALLOW_CREDENTIALS" default:"false"`
	MaxAge           int      `yaml:"max_age" env:"CORS_MAX_AGE" default:"86400"`
}

// RateLimitConfig contains rate limiting settings
type RateLimitConfig struct {
	Enabled    bool          `yaml:"enabled" env:"RATE_LIMIT_ENABLED" default:"true"`
	Requests   int           `yaml:"requests" env:"RATE_LIMIT_REQUESTS" default:"100"`
	Window     time.Duration `yaml:"window" env:"RATE_LIMIT_WINDOW" default:"60s"`
	SkipPaths  []string      `yaml:"skip_paths" env:"RATE_LIMIT_SKIP_PATHS"`
	SkipIPs    []string      `yaml:"skip_ips" env:"RATE_LIMIT_SKIP_IPS"`
	StatusCode int           `yaml:"status_code" env:"RATE_LIMIT_STATUS_CODE" default:"429"`
}

// LockoutConfig contains account lockout and brute force protection settings
type LockoutConfig struct {
	MaxFailedAttempts   int           `yaml:"max_failed_attempts" env:"LOCKOUT_MAX_FAILED_ATTEMPTS" default:"5"`
	LockoutDuration     time.Duration `yaml:"lockout_duration" env:"LOCKOUT_DURATION" default:"15m"`
	ResetWindow         time.Duration `yaml:"reset_window" env:"LOCKOUT_RESET_WINDOW" default:"1h"`
	ProgressiveDelay    bool          `yaml:"progressive_delay" env:"LOCKOUT_PROGRESSIVE_DELAY" default:"true"`
	BaseDelay           time.Duration `yaml:"base_delay" env:"LOCKOUT_BASE_DELAY" default:"1s"`
	MaxDelay            time.Duration `yaml:"max_delay" env:"LOCKOUT_MAX_DELAY" default:"30s"`
	EnableNotifications bool          `yaml:"enable_notifications" env:"LOCKOUT_ENABLE_NOTIFICATIONS" default:"true"`
	IPLockoutEnabled    bool          `yaml:"ip_lockout_enabled" env:"IP_LOCKOUT_ENABLED" default:"true"`
	IPLockoutThreshold  int           `yaml:"ip_lockout_threshold" env:"IP_LOCKOUT_THRESHOLD" default:"10"`
	IPLockoutDuration   time.Duration `yaml:"ip_lockout_duration" env:"IP_LOCKOUT_DURATION" default:"1h"`
}

// RequestSigningConfig contains settings for API request signing
type RequestSigningConfig struct {
	Enabled      bool          `yaml:"enabled" env:"REQUEST_SIGNING_ENABLED" default:"false"`
	Algorithm    string        `yaml:"algorithm" env:"REQUEST_SIGNING_ALGORITHM" default:"HMAC-SHA256"`
	KeyID        string        `yaml:"key_id" env:"REQUEST_SIGNING_KEY_ID"`
	Secret       string        `yaml:"secret" env:"REQUEST_SIGNING_SECRET"`
	Headers      []string      `yaml:"headers" env:"REQUEST_SIGNING_HEADERS"`
	MaxClockSkew time.Duration `yaml:"max_clock_skew" env:"REQUEST_SIGNING_MAX_CLOCK_SKEW" default:"5s"`
	ReplayWindow time.Duration `yaml:"replay_window" env:"REQUEST_SIGNING_REPLAY_WINDOW" default:"1m"`
}

// Load loads configuration from environment variables with defaults
func Load() (*Config, error) {
	config := &Config{}

	if err := loadFromEnv(config); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "Failed to load configuration")
	}

	if err := validateConfig(config); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "Configuration validation failed")
	}

	return config, nil
}

// DatabaseDSN returns a formatted database connection string
func (d *DatabaseConfig) DatabaseDSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.Username, d.Password, d.Database, d.SSLMode)
}

// RedisAddr returns a formatted Redis address
func (r *RedisConfig) RedisAddr() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

// HTTPAddr returns a formatted HTTP address
func (h *HTTPConfig) HTTPAddr() string {
	return fmt.Sprintf("%s:%d", h.Host, h.Port)
}

// IsProduction returns true if running in production environment
func (a *AppConfig) IsProduction() bool {
	return strings.ToLower(a.Environment) == "production"
}

// IsDevelopment returns true if running in development environment
func (a *AppConfig) IsDevelopment() bool {
	return strings.ToLower(a.Environment) == "development"
}

// IsTest returns true if running in test environment
func (a *AppConfig) IsTest() bool {
	return strings.ToLower(a.Environment) == "test"
}

// loadFromEnv loads configuration from environment variables using reflection and struct tags
func loadFromEnv(config *Config) error {
	// Set App config
	config.App.Name = getEnvWithDefault("APP_NAME", "mvp-zero-trust-auth")
	config.App.Version = getEnvWithDefault("APP_VERSION", "dev")
	config.App.Environment = getEnvWithDefault("ENVIRONMENT", "development")
	config.App.Debug = getEnvBoolWithDefault("DEBUG", false)
	config.App.RBACModelPath = getEnvWithDefault("RBAC_MODEL_PATH", "configs/rbac_model.conf")

	// Set HTTP config
	config.HTTP.Port = getEnvIntWithDefault("HTTP_PORT", 8080)
	config.HTTP.Host = getEnvWithDefault("HTTP_HOST", "0.0.0.0")
	config.HTTP.ReadTimeout = getEnvDurationWithDefault("HTTP_READ_TIMEOUT", 30*time.Second)
	config.HTTP.WriteTimeout = getEnvDurationWithDefault("HTTP_WRITE_TIMEOUT", 30*time.Second)
	config.HTTP.IdleTimeout = getEnvDurationWithDefault("HTTP_IDLE_TIMEOUT", 120*time.Second)

	// Set TLS config
	config.HTTP.TLS.Enabled = getEnvBoolWithDefault("TLS_ENABLED", false)
	config.HTTP.TLS.CertFile = getEnvWithDefault("TLS_CERT_FILE", "")
	config.HTTP.TLS.KeyFile = getEnvWithDefault("TLS_KEY_FILE", "")

	// Set Database config
	config.Database.Host = getEnvWithDefault("DB_HOST", "localhost")
	config.Database.Port = getEnvIntWithDefault("DB_PORT", 5432)
	config.Database.Database = getEnvWithDefault("DB_NAME", "mvp_db")
	config.Database.Username = getEnvWithDefault("DB_USER", "mvp_user")
	config.Database.Password = getEnvWithDefault("DB_PASSWORD", "please_change_this_password_in_production")
	config.Database.SSLMode = getEnvWithDefault("DB_SSL_MODE", "disable")
	config.Database.MaxConnections = getEnvIntWithDefault("DB_MAX_CONNECTIONS", 25)
	config.Database.MaxIdleConns = getEnvIntWithDefault("DB_MAX_IDLE_CONNS", 5)
	config.Database.MinIdleConns = getEnvIntWithDefault("DB_MIN_IDLE_CONNS", 2)
	config.Database.ConnMaxLifetime = getEnvDurationWithDefault("DB_CONN_MAX_LIFETIME", 300*time.Second)
	config.Database.ConnMaxIdleTime = getEnvDurationWithDefault("DB_CONN_MAX_IDLE_TIME", 60*time.Second)
	config.Database.QueryTimeout = getEnvDurationWithDefault("DB_QUERY_TIMEOUT", 30*time.Second)
	config.Database.ConnectTimeout = getEnvDurationWithDefault("DB_CONNECT_TIMEOUT", 10*time.Second)
	config.Database.PrepareStmt = getEnvBoolWithDefault("DB_PREPARE_STMT", true)
	config.Database.DisableForeignKey = getEnvBoolWithDefault("DB_DISABLE_FOREIGN_KEY", false)
	config.Database.EnableMetrics = getEnvBoolWithDefault("DB_ENABLE_METRICS", true)
	config.Database.SlowQueryThreshold = getEnvDurationWithDefault("DB_SLOW_QUERY_THRESHOLD", 1*time.Second)
	config.Database.OptimizationProfile = getEnvWithDefault("DB_OPTIMIZATION_PROFILE", "balanced")
	config.Database.AutoTuning = getEnvBoolWithDefault("DB_AUTO_TUNING", true)
	config.Database.MonitoringInterval = getEnvDurationWithDefault("DB_MONITORING_INTERVAL", 30*time.Second)
	config.Database.LeakDetection = getEnvBoolWithDefault("DB_LEAK_DETECTION", true)
	config.Database.LeakThreshold = getEnvDurationWithDefault("DB_LEAK_THRESHOLD", 60*time.Second)
	config.Database.MaxQueueWait = getEnvDurationWithDefault("DB_MAX_QUEUE_WAIT", 30*time.Second)
	config.Database.RetryAttempts = getEnvIntWithDefault("DB_RETRY_ATTEMPTS", 3)
	config.Database.RetryDelay = getEnvDurationWithDefault("DB_RETRY_DELAY", 1*time.Second)
	config.Database.CircuitBreaker = getEnvBoolWithDefault("DB_CIRCUIT_BREAKER", true)
	config.Database.FailureThreshold = getEnvIntWithDefault("DB_FAILURE_THRESHOLD", 5)
	config.Database.DetailedMetrics = getEnvBoolWithDefault("DB_DETAILED_METRICS", false)
	config.Database.QueryLogging = getEnvBoolWithDefault("DB_QUERY_LOGGING", false)
	config.Database.ConnectionTracing = getEnvBoolWithDefault("DB_CONNECTION_TRACING", false)
	config.Database.StatsExportInterval = getEnvDurationWithDefault("DB_STATS_EXPORT_INTERVAL", 60*time.Second)
	config.Database.HealthCheckInterval = getEnvDurationWithDefault("DB_HEALTH_CHECK_INTERVAL", 30*time.Second)

	// Set Redis config
	config.Redis.Host = getEnvWithDefault("REDIS_HOST", "localhost")
	config.Redis.Port = getEnvIntWithDefault("REDIS_PORT", 6379)
	config.Redis.Password = getEnvWithDefault("REDIS_PASSWORD", "")
	config.Redis.Database = getEnvIntWithDefault("REDIS_DB", 0)
	config.Redis.PoolSize = getEnvIntWithDefault("REDIS_POOL_SIZE", 10)
	config.Redis.DialTimeout = getEnvDurationWithDefault("REDIS_DIAL_TIMEOUT", 5*time.Second)
	config.Redis.ReadTimeout = getEnvDurationWithDefault("REDIS_READ_TIMEOUT", 3*time.Second)
	config.Redis.WriteTimeout = getEnvDurationWithDefault("REDIS_WRITE_TIMEOUT", 3*time.Second)

	// Set NATS config
	config.NATS.URL = getEnvWithDefault("NATS_URL", "nats://localhost:4222")
	config.NATS.ClientID = getEnvWithDefault("NATS_CLIENT_ID", "")
	config.NATS.ClusterID = getEnvWithDefault("NATS_CLUSTER_ID", "mvp-cluster")
	config.NATS.MaxReconnects = getEnvIntWithDefault("NATS_MAX_RECONNECTS", 5)
	config.NATS.ReconnectWait = getEnvDurationWithDefault("NATS_RECONNECT_WAIT", 2*time.Second)
	config.NATS.ConnectionName = getEnvWithDefault("NATS_CONNECTION_NAME", "mvp-service")
	config.NATS.PingInterval = getEnvDurationWithDefault("NATS_PING_INTERVAL", 120*time.Second)
	config.NATS.MaxPingsOut = getEnvIntWithDefault("NATS_MAX_PINGS_OUT", 2)

	// Set Observability config
	config.Observability.ServiceName = getEnvWithDefault("SERVICE_NAME", "mvp-zero-trust-auth")
	config.Observability.ServiceVersion = getEnvWithDefault("SERVICE_VERSION", "dev")
	config.Observability.Environment = getEnvWithDefault("OBSERVABILITY_ENVIRONMENT", "development")
	config.Observability.LogLevel = getEnvWithDefault("LOG_LEVEL", "info")
	config.Observability.LogFormat = getEnvWithDefault("LOG_FORMAT", "json")
	config.Observability.PrometheusPort = getEnvIntWithDefault("PROMETHEUS_PORT", 9090)
	config.Observability.JaegerEndpoint = getEnvWithDefault("JAEGER_ENDPOINT", "http://localhost:14268/api/traces")
	config.Observability.SamplingRatio = getEnvFloatWithDefault("TRACING_SAMPLING_RATIO", 1.0)
	config.Observability.MetricsPath = getEnvWithDefault("METRICS_PATH", "/metrics")
	config.Observability.HealthPath = getEnvWithDefault("HEALTH_PATH", "/health")
	config.Observability.BatchTimeout = getEnvDurationWithDefault("TRACING_BATCH_TIMEOUT", 1*time.Second)
	config.Observability.ExportTimeout = getEnvDurationWithDefault("TRACING_EXPORT_TIMEOUT", 30*time.Second)

	// Set Security config
	config.Security.SecureHeaders = getEnvBoolWithDefault("SECURE_HEADERS", true)
	config.Security.ContentTypeNosniff = getEnvBoolWithDefault("CONTENT_TYPE_NOSNIFF", true)
	config.Security.DisableAuth = getEnvBoolWithDefault("DISABLE_AUTH", false)
	config.Security.TrustedProxies = getEnvSliceWithDefault("TRUSTED_PROXIES", []string{})
	config.Security.AllowedOrigins = getEnvSliceWithDefault("ALLOWED_ORIGINS", []string{})

	// Set SPIRE config
	config.Security.SPIRE.SocketPath = getEnvWithDefault("SPIRE_SOCKET_PATH", "/tmp/spire-agent/public/api.sock")
	config.Security.SPIRE.ServerAddress = getEnvWithDefault("SPIRE_SERVER_ADDRESS", "unix:///tmp/spire-server/private/api.sock")
	config.Security.SPIRE.TrustDomain = getEnvWithDefault("SPIRE_TRUST_DOMAIN", "example.org")
	config.Security.SPIRE.DefaultSVID = getEnvWithDefault("SPIRE_DEFAULT_SVID", "")
	config.Security.SPIRE.FetchTimeout = getEnvDurationWithDefault("SPIRE_FETCH_TIMEOUT", 30*time.Second)
	config.Security.SPIRE.RefreshHint = getEnvDurationWithDefault("SPIRE_REFRESH_HINT", 30*time.Second)

	// Set JWT config
	config.Security.JWT.Secret = getEnvWithDefault("JWT_SECRET", "")
	config.Security.JWT.Issuer = getEnvWithDefault("JWT_ISSUER", "mvp-zero-trust-auth")
	config.Security.JWT.Audience = getEnvWithDefault("JWT_AUDIENCE", "mvp-services")
	config.Security.JWT.ExpiryDuration = getEnvDurationWithDefault("JWT_EXPIRY_DURATION", 24*time.Hour)
	config.Security.JWT.Algorithm = getEnvWithDefault("JWT_ALGORITHM", "HS256")

	// Set CORS config
	config.Security.CORS.Enabled = getEnvBoolWithDefault("CORS_ENABLED", true)
	config.Security.CORS.AllowedOrigins = getEnvSliceWithDefault("CORS_ALLOWED_ORIGINS", []string{"http://localhost:3000", "http://localhost:5173", "https://localhost:3000", "https://localhost:5173"})
	config.Security.CORS.AllowedMethods = getEnvSliceWithDefault("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	config.Security.CORS.AllowedHeaders = getEnvSliceWithDefault("CORS_ALLOWED_HEADERS", []string{"*"})
	config.Security.CORS.ExposedHeaders = getEnvSliceWithDefault("CORS_EXPOSED_HEADERS", []string{})
	config.Security.CORS.AllowCredentials = getEnvBoolWithDefault("CORS_ALLOW_CREDENTIALS", false)
	config.Security.CORS.MaxAge = getEnvIntWithDefault("CORS_MAX_AGE", 86400)

	// Set Rate Limit config
	config.Security.RateLimit.Enabled = getEnvBoolWithDefault("RATE_LIMIT_ENABLED", true)
	config.Security.RateLimit.Requests = getEnvIntWithDefault("RATE_LIMIT_REQUESTS", 100)
	config.Security.RateLimit.Window = getEnvDurationWithDefault("RATE_LIMIT_WINDOW", 60*time.Second)
	config.Security.RateLimit.SkipPaths = getEnvSliceWithDefault("RATE_LIMIT_SKIP_PATHS", []string{"/health", "/metrics"})
	config.Security.RateLimit.SkipIPs = getEnvSliceWithDefault("RATE_LIMIT_SKIP_IPS", []string{})
	config.Security.RateLimit.StatusCode = getEnvIntWithDefault("RATE_LIMIT_STATUS_CODE", 429)

	// Set Lockout config
	config.Security.Lockout.MaxFailedAttempts = getEnvIntWithDefault("LOCKOUT_MAX_FAILED_ATTEMPTS", 5)
	config.Security.Lockout.LockoutDuration = getEnvDurationWithDefault("LOCKOUT_DURATION", 15*time.Minute)
	config.Security.Lockout.ResetWindow = getEnvDurationWithDefault("LOCKOUT_RESET_WINDOW", 1*time.Hour)
	config.Security.Lockout.ProgressiveDelay = getEnvBoolWithDefault("LOCKOUT_PROGRESSIVE_DELAY", true)
	config.Security.Lockout.BaseDelay = getEnvDurationWithDefault("LOCKOUT_BASE_DELAY", 1*time.Second)
	config.Security.Lockout.MaxDelay = getEnvDurationWithDefault("LOCKOUT_MAX_DELAY", 30*time.Second)
	config.Security.Lockout.EnableNotifications = getEnvBoolWithDefault("LOCKOUT_ENABLE_NOTIFICATIONS", true)
	config.Security.Lockout.IPLockoutEnabled = getEnvBoolWithDefault("IP_LOCKOUT_ENABLED", true)
	config.Security.Lockout.IPLockoutThreshold = getEnvIntWithDefault("IP_LOCKOUT_THRESHOLD", 10)
	config.Security.Lockout.IPLockoutDuration = getEnvDurationWithDefault("IP_LOCKOUT_DURATION", 1*time.Hour)

	// Set Request Signing config
	config.Security.RequestSigning.Enabled = getEnvBoolWithDefault("REQUEST_SIGNING_ENABLED", false)
	config.Security.RequestSigning.Algorithm = getEnvWithDefault("REQUEST_SIGNING_ALGORITHM", "HMAC-SHA256")
	config.Security.RequestSigning.KeyID = getEnvWithDefault("REQUEST_SIGNING_KEY_ID", "")
	config.Security.RequestSigning.Secret = getEnvWithDefault("REQUEST_SIGNING_SECRET", "")
	config.Security.RequestSigning.Headers = getEnvSliceWithDefault("REQUEST_SIGNING_HEADERS", []string{})
	config.Security.RequestSigning.MaxClockSkew = getEnvDurationWithDefault("REQUEST_SIGNING_MAX_CLOCK_SKEW", 5*time.Second)
	config.Security.RequestSigning.ReplayWindow = getEnvDurationWithDefault("REQUEST_SIGNING_REPLAY_WINDOW", time.Minute)

	return nil
}

// validateConfig validates the loaded configuration
func validateConfig(config *Config) error {
	// Validate required fields
	if config.App.Name == "" {
		return errors.Validation("app.name is required")
	}

	if config.HTTP.Port <= 0 || config.HTTP.Port > 65535 {
		return errors.Validation("http.port must be between 1 and 65535")
	}

	if config.Database.Host == "" {
		return errors.Validation("database.host is required")
	}

	if config.Database.Database == "" {
		return errors.Validation("database.database is required")
	}

	if config.Database.Username == "" {
		return errors.Validation("database.username is required")
	}

	if config.Security.JWT.Secret == "" && config.App.IsProduction() {
		return errors.Validation("jwt.secret is required in production")
	}

	// Validate observability settings
	validLogLevels := []string{"debug", "info", "warn", "error"}
	if !contains(validLogLevels, config.Observability.LogLevel) {
		return errors.Validation("observability.log_level must be one of: debug, info, warn, error")
	}

	validLogFormats := []string{"json", "console"}
	if !contains(validLogFormats, config.Observability.LogFormat) {
		return errors.Validation("observability.log_format must be one of: json, console")
	}

	if config.Observability.SamplingRatio < 0 || config.Observability.SamplingRatio > 1 {
		return errors.Validation("observability.sampling_ratio must be between 0 and 1")
	}

	// Validate TLS configuration
	if config.HTTP.TLS.Enabled {
		if config.HTTP.TLS.CertFile == "" {
			return errors.Validation("tls.cert_file is required when TLS is enabled")
		}
		if config.HTTP.TLS.KeyFile == "" {
			return errors.Validation("tls.key_file is required when TLS is enabled")
		}
	}

	// Validate database configuration
	if config.Database.Port <= 0 || config.Database.Port > 65535 {
		return errors.Validation("database.port must be between 1 and 65535")
	}

	if config.Database.MaxConnections <= 0 {
		return errors.Validation("database.max_connections must be greater than 0")
	}

	if config.Database.MaxIdleConns < 0 || config.Database.MaxIdleConns > config.Database.MaxConnections {
		return errors.Validation("database.max_idle_conns must be between 0 and max_connections")
	}

	if config.Database.ConnMaxLifetime < 0 {
		return errors.Validation("database.conn_max_lifetime must be non-negative")
	}

	// Validate new connection pool settings
	validProfiles := []string{"development", "testing", "balanced", "high_throughput", "low_latency", "resource_constrained"}
	if !contains(validProfiles, config.Database.OptimizationProfile) {
		return errors.Validation("database.optimization_profile must be one of: development, testing, balanced, high_throughput, low_latency, resource_constrained")
	}

	if config.Database.RetryAttempts < 0 || config.Database.RetryAttempts > 10 {
		return errors.Validation("database.retry_attempts must be between 0 and 10")
	}

	if config.Database.FailureThreshold <= 0 {
		return errors.Validation("database.failure_threshold must be greater than 0")
	}

	if config.Database.MonitoringInterval <= 0 {
		return errors.Validation("database.monitoring_interval must be positive")
	}

	// Validate Redis configuration
	if config.Redis.Host != "" {
		if config.Redis.Port <= 0 || config.Redis.Port > 65535 {
			return errors.Validation("redis.port must be between 1 and 65535")
		}
		if config.Redis.Database < 0 || config.Redis.Database > 15 {
			return errors.Validation("redis.database must be between 0 and 15")
		}
		if config.Redis.PoolSize <= 0 {
			return errors.Validation("redis.pool_size must be greater than 0")
		}
	}

	// Validate security configuration
	if config.Security.JWT.ExpiryDuration <= 0 {
		return errors.Validation("jwt.expiry_duration must be positive")
	}

	if config.Security.JWT.ExpiryDuration > 168*time.Hour { // 7 days
		return errors.Validation("jwt.expiry_duration should not exceed 7 days for security")
	}

	validJWTAlgorithms := []string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512"}
	if !contains(validJWTAlgorithms, config.Security.JWT.Algorithm) {
		return errors.Validation("jwt.algorithm must be one of: HS256, HS384, HS512, RS256, RS384, RS512")
	}

	// Validate rate limiting configuration
	if config.Security.RateLimit.Enabled {
		if config.Security.RateLimit.Requests <= 0 {
			return errors.Validation("rate_limit.requests must be greater than 0")
		}
		if config.Security.RateLimit.Window <= 0 {
			return errors.Validation("rate_limit.window must be positive")
		}
	}

	// Validate lockout configuration
	if config.Security.Lockout.MaxFailedAttempts <= 0 {
		return errors.Validation("lockout.max_failed_attempts must be greater than 0")
	}

	if config.Security.Lockout.LockoutDuration <= 0 {
		return errors.Validation("lockout.lockout_duration must be positive")
	}

	if config.Security.Lockout.ResetWindow <= 0 {
		return errors.Validation("lockout.reset_window must be positive")
	}

	// Validate request signing configuration
	if config.Security.RequestSigning.Enabled {
		if config.Security.RequestSigning.Secret == "" {
			return errors.Validation("request_signing.secret is required when request signing is enabled")
		}
	}

	// Validate HTTP timeouts
	if config.HTTP.ReadTimeout <= 0 {
		return errors.Validation("http.read_timeout must be positive")
	}

	if config.HTTP.WriteTimeout <= 0 {
		return errors.Validation("http.write_timeout must be positive")
	}

	if config.HTTP.IdleTimeout <= 0 {
		return errors.Validation("http.idle_timeout must be positive")
	}

	// Validate CORS configuration
	if config.Security.CORS.Enabled && config.App.IsProduction() {
		if len(config.Security.CORS.AllowedOrigins) == 0 {
			return errors.Validation("cors.allowed_origins must be specified in production")
		}
		for _, origin := range config.Security.CORS.AllowedOrigins {
			if origin == "*" {
				return errors.Validation("cors.allowed_origins should not use '*' in production")
			}
		}
	}

	// Validate observability configuration
	if config.Observability.PrometheusPort <= 0 || config.Observability.PrometheusPort > 65535 {
		return errors.Validation("observability.prometheus_port must be between 1 and 65535")
	}

	if config.Observability.BatchTimeout <= 0 {
		return errors.Validation("observability.batch_timeout must be positive")
	}

	if config.Observability.ExportTimeout <= 0 {
		return errors.Validation("observability.export_timeout must be positive")
	}

	// Production-specific validations
	if config.App.IsProduction() {
		if len(config.Security.JWT.Secret) < 32 {
			return errors.Validation("jwt.secret must be at least 32 characters in production")
		}

		if !config.HTTP.TLS.Enabled {
			return errors.Validation("TLS must be enabled in production")
		}

		if config.Security.DisableAuth {
			return errors.Validation("authentication cannot be disabled in production")
		}

		if config.Observability.LogLevel == "debug" {
			return errors.Validation("log level should not be 'debug' in production")
		}
	}

	return nil
}

// Helper functions for environment variable parsing

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntWithDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBoolWithDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvFloatWithDefault(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
			return floatValue
		}
	}
	return defaultValue
}

func getEnvDurationWithDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getEnvSliceWithDefault(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
