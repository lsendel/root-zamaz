# Configuration Guide

This directory contains configuration files and examples for the Keycloak Zero Trust library.

## Configuration Files

### Main Configuration

- **`zerotrust-config.yaml`** - Complete configuration template with all available options
- **`docker-compose.yml`** - Docker Compose setup for development environment
- **`.env.example`** - Environment variables template

### Environment-Specific Configs

- **`config-dev.yaml`** - Development environment settings
- **`config-staging.yaml`** - Staging environment settings  
- **`config-prod.yaml`** - Production environment settings

## Quick Start

1. **Copy the configuration template:**
   ```bash
   cp zerotrust-config.yaml config.yaml
   ```

2. **Set environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your actual values
   ```

3. **Load configuration in your application:**
   ```go
   import "github.com/yourorg/go-keycloak-zerotrust/pkg/config"
   
   cfg, err := config.LoadFromFile("config.yaml")
   if err != nil {
       log.Fatal(err)
   }
   ```

## Configuration Sections

### Keycloak Settings

```yaml
keycloak:
  base_url: "https://keycloak.company.com"
  realm: "company"
  client_id: "api-service"
  client_secret: "${KEYCLOAK_CLIENT_SECRET}"
```

**Required Environment Variables:**
- `KEYCLOAK_CLIENT_SECRET` - Keycloak client secret
- `KEYCLOAK_ADMIN_USERNAME` - Admin username (optional)
- `KEYCLOAK_ADMIN_PASSWORD` - Admin password (optional)

### Zero Trust Features

```yaml
zero_trust:
  enable_device_attestation: true
  enable_risk_assessment: true
  enable_continuous_auth: true
  
  trust_level_thresholds:
    read: 25
    write: 50
    admin: 75
    delete: 90
```

**Key Settings:**
- **Trust Thresholds**: Minimum trust levels for different operations
- **Risk Thresholds**: Risk score boundaries for decision making
- **TTL Settings**: How long verifications remain valid

### Device Attestation

```yaml
zero_trust:
  device_attestation:
    supported_platforms:
      - "android"
      - "ios" 
      - "windows"
      - "macos"
      - "linux"
      - "web"
    
    android:
      require_safetynet: true
      allow_unlocked_bootloader: false
```

**Platform-Specific Settings:**
- **Android**: SafetyNet, Play Protect, bootloader status
- **iOS**: DeviceCheck, Secure Enclave, jailbreak detection
- **Web**: WebAuthn, fingerprinting, secure context

### Risk Assessment

```yaml
zero_trust:
  risk_assessment:
    geolocation:
      high_risk_countries:
        - "CN"
        - "RU"
        - "IR"
    
    threat_intelligence:
      enable_ip_reputation: true
      providers:
        - name: "virustotal"
          api_key: "${VIRUSTOTAL_API_KEY}"
```

**Risk Factors:**
- **Geolocation**: Country risk, unusual locations
- **Threat Intelligence**: IP reputation, known threats
- **Behavior Analysis**: Usage patterns, anomalies
- **Network Analysis**: VPN/Tor detection

### Caching & Storage

```yaml
cache:
  type: "redis"
  redis:
    host: "localhost"
    port: 6379
    password: "${REDIS_PASSWORD}"

database:
  type: "postgres" 
  connection:
    host: "localhost"
    port: 5432
    database: "zerotrust"
    password: "${DATABASE_PASSWORD}"
```

**Storage Options:**
- **Cache**: Memory, Redis, or external cache
- **Database**: PostgreSQL, MySQL, or SQLite
- **TTL Settings**: Cache expiration times

### Security & Compliance

```yaml
security:
  tls:
    min_version: "1.2"
  
  rate_limiting:
    enabled: true
    requests_per_minute: 100
  
  cors:
    allowed_origins:
      - "https://app.company.com"
```

**Security Features:**
- **TLS Configuration**: Minimum versions, cipher suites
- **Rate Limiting**: Per-endpoint request limits
- **CORS**: Cross-origin resource sharing
- **Audit Logging**: Comprehensive audit trails

### Observability

```yaml
observability:
  metrics:
    enabled: true
    endpoint: "/metrics"
  
  logging:
    level: "info"
    format: "json"
  
  tracing:
    enabled: true
    jaeger_endpoint: "http://localhost:14268/api/traces"
```

**Monitoring Features:**
- **Metrics**: Prometheus-compatible metrics
- **Logging**: Structured JSON logging
- **Tracing**: Distributed tracing with Jaeger
- **Audit**: Security event logging

## Environment Variables

Create a `.env` file with these variables:

```bash
# Keycloak Configuration
KEYCLOAK_CLIENT_SECRET=your-client-secret
KEYCLOAK_ADMIN_USERNAME=admin
KEYCLOAK_ADMIN_PASSWORD=admin-password

# Database
DATABASE_PASSWORD=db-password

# Cache
REDIS_PASSWORD=redis-password

# External Services
GEOLOCATION_API_KEY=geo-api-key
VIRUSTOTAL_API_KEY=vt-api-key
ABUSE_CH_API_KEY=abuse-ch-key

# Notifications
NOTIFICATION_WEBHOOK_URL=https://hooks.slack.com/your-webhook

# Directory Services
LDAP_BIND_PASSWORD=ldap-password
```

## Environment-Specific Configuration

### Development

```yaml
# config-dev.yaml
zero_trust:
  trust_level_thresholds:
    read: 10      # Lower thresholds for dev
    write: 25
    admin: 50
    delete: 75

development:
  debug:
    enabled: true
    
observability:
  logging:
    level: "debug"
  tracing:
    sample_rate: 1.0    # Full tracing in dev
```

### Production

```yaml
# config-prod.yaml
zero_trust:
  trust_level_thresholds:
    read: 25
    write: 50
    admin: 85      # Higher threshold for prod
    delete: 95

security:
  rate_limiting:
    requests_per_minute: 500    # Higher limits

observability:
  logging:
    level: "warn"    # Less verbose logging
  tracing:
    sample_rate: 0.05    # Minimal tracing overhead
```

## Configuration Loading

### From File

```go
import "github.com/yourorg/go-keycloak-zerotrust/pkg/config"

// Load from YAML file
cfg, err := config.LoadFromFile("config.yaml")
if err != nil {
    log.Fatal(err)
}

// Load with environment override
cfg, err := config.LoadWithEnv("config.yaml", "prod")
if err != nil {
    log.Fatal(err)
}
```

### From Environment

```go
// Load entirely from environment variables
cfg, err := config.LoadFromEnv()
if err != nil {
    log.Fatal(err)
}
```

### Environment Variable Mapping

Configuration keys map to environment variables using this pattern:

```yaml
# config.yaml
keycloak:
  base_url: "http://localhost:8080"
  client_secret: "${KEYCLOAK_CLIENT_SECRET}"

# Environment variable
KEYCLOAK_BASE_URL=https://prod-keycloak.com
KEYCLOAK_CLIENT_SECRET=secret-value
```

## Best Practices

### Security

1. **Never commit secrets** to version control
2. **Use environment variables** for sensitive data
3. **Enable audit logging** in production
4. **Set appropriate trust thresholds** for your risk tolerance
5. **Configure rate limiting** to prevent abuse

### Performance

1. **Use Redis caching** for better performance
2. **Tune TTL values** based on your requirements
3. **Configure connection pools** appropriately
4. **Enable metrics** for monitoring
5. **Use structured logging** for better observability

### Deployment

1. **Use environment-specific configs** (dev/staging/prod)
2. **Validate configuration** on startup
3. **Monitor configuration changes** through audit logs
4. **Test configuration** in staging before production
5. **Document custom settings** for your organization

## Troubleshooting

### Common Issues

**Configuration not loading:**
```bash
# Check file permissions
ls -la config.yaml

# Validate YAML syntax
yamllint config.yaml
```

**Environment variables not expanding:**
```bash
# Check if variables are set
env | grep KEYCLOAK

# Test variable expansion
envsubst < config.yaml
```

**Trust thresholds too restrictive:**
```yaml
# Temporarily lower thresholds for testing
zero_trust:
  trust_level_thresholds:
    read: 10
    write: 25
```

**High resource usage:**
```yaml
# Reduce tracing and logging
observability:
  tracing:
    sample_rate: 0.01
  logging:
    level: "error"
```

### Validation

The library provides configuration validation:

```go
cfg, err := config.LoadFromFile("config.yaml")
if err != nil {
    log.Fatal(err)
}

if err := cfg.Validate(); err != nil {
    log.Fatalf("Invalid configuration: %v", err)
}
```

### Health Checks

Monitor configuration health:

```go
// Check if external services are reachable
healthStatus := cfg.HealthCheck(ctx)
for service, status := range healthStatus {
    log.Printf("%s: %s", service, status)
}
```

## Examples

See the `examples/` directory for complete configuration examples:

- **Basic Setup**: Minimal configuration for getting started
- **Enterprise Setup**: Full-featured enterprise configuration
- **High Security**: Maximum security configuration
- **Development**: Developer-friendly settings
- **Kubernetes**: Configuration for Kubernetes deployment