# Configuration Guide

Comprehensive configuration guide for the Zamaz Zero Trust Platform covering all environments and deployment scenarios.

## :gear: Configuration Overview

Zamaz uses a layered configuration approach:

1. **Default values** - Built-in sensible defaults
2. **Environment variables** - Override via `.env` file or system environment
3. **Configuration files** - YAML/JSON configuration files
4. **Command-line flags** - Runtime parameter overrides
5. **Kubernetes secrets** - Secure credential management

## :file_folder: Configuration Files

### Environment Configuration (`.env`)

The primary configuration file for local development:

```bash
# Copy the example configuration
cp .env.example .env

# Edit with your specific values
nano .env
```

### Application Configuration (`config/app.yaml`)

```yaml
# Application Configuration
app:
  name: "zamaz-auth"
  version: "1.0.0"
  environment: "development"  # development, staging, production
  debug: false
  
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: false
    cert_file: "/etc/certs/tls.crt"
    key_file: "/etc/certs/tls.key"
  
  timeouts:
    read: "30s"
    write: "30s"
    idle: "120s"
    shutdown: "30s"

database:
  driver: "postgres"
  host: "localhost"
  port: 5432
  name: "zamaz_db"
  user: "zamaz"
  password: "${DB_PASSWORD}"
  ssl_mode: "disable"
  
  pool:
    max_open: 25
    max_idle: 5
    max_lifetime: "5m"
    max_idle_time: "5m"

cache:
  driver: "redis"
  host: "localhost"
  port: 6379
  database: 0
  password: "${REDIS_PASSWORD}"
  
  pool:
    max_active: 100
    max_idle: 50
    idle_timeout: "240s"

auth:
  jwt:
    secret: "${JWT_SECRET}"
    expiry: "24h"
    refresh_expiry: "168h"  # 7 days
    issuer: "zamaz-auth"
    audience: ["zamaz-api", "zamaz-frontend"]
  
  password:
    min_length: 8
    require_uppercase: true
    require_lowercase: true
    require_numbers: true
    require_symbols: true
    bcrypt_cost: 12

security:
  cors:
    allowed_origins: ["http://localhost:3000"]
    allowed_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allowed_headers: ["Content-Type", "Authorization"]
    exposed_headers: ["X-Total-Count"]
    allow_credentials: true
    max_age: "12h"
  
  rate_limiting:
    enabled: true
    requests_per_minute: 60
    burst: 10
    
  encryption:
    key: "${ENCRYPTION_KEY}"
    algorithm: "AES-256-GCM"

observability:
  logging:
    level: "info"  # debug, info, warn, error
    format: "json"  # json, text
    output: "stdout"  # stdout, file
    file_path: "/var/log/zamaz.log"
  
  metrics:
    enabled: true
    endpoint: "/metrics"
    prometheus:
      enabled: true
      endpoint: "http://localhost:9090"
  
  tracing:
    enabled: true
    jaeger:
      endpoint: "http://localhost:14268/api/traces"
      service_name: "zamaz-auth"
      sampler_ratio: 0.1

service_discovery:
  enabled: true
  provider: "consul"  # consul, kubernetes, memory
  
  consul:
    endpoint: "http://localhost:8500"
    service_name: "zamaz-auth"
    service_port: 8080
    health_check:
      interval: "10s"
      timeout: "3s"
      deregister_after: "30s"

features:
  audit_logging: true
  device_attestation: true
  multi_factor_auth: true
  session_management: true
  api_versioning: true
```

## :cloud: Environment-Specific Configuration

### Development Environment

```yaml
# config/development.yaml
app:
  environment: "development"
  debug: true

server:
  tls:
    enabled: false

database:
  ssl_mode: "disable"
  
observability:
  logging:
    level: "debug"
    format: "text"
  
  tracing:
    sampler_ratio: 1.0  # Trace everything in development

security:
  cors:
    allowed_origins: ["*"]  # Permissive CORS for development
```

### Staging Environment

```yaml
# config/staging.yaml
app:
  environment: "staging"
  debug: false

server:
  tls:
    enabled: true

database:
  ssl_mode: "require"
  
observability:
  logging:
    level: "info"
  
  tracing:
    sampler_ratio: 0.5

security:
  cors:
    allowed_origins: ["https://staging.zamaz.io"]
```

### Production Environment

```yaml
# config/production.yaml
app:
  environment: "production"
  debug: false

server:
  tls:
    enabled: true

database:
  ssl_mode: "require"
  pool:
    max_open: 100
    max_idle: 20

cache:
  pool:
    max_active: 500
    max_idle: 100

observability:
  logging:
    level: "warn"
    format: "json"
  
  tracing:
    sampler_ratio: 0.01  # Sample 1% in production

security:
  cors:
    allowed_origins: ["https://app.zamaz.io"]
  
  rate_limiting:
    requests_per_minute: 1000
    burst: 100
```

## :kubernetes: Kubernetes Configuration

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: zamaz-config
  namespace: zamaz-system
data:
  app.yaml: |
    app:
      environment: "production"
      debug: false
    
    server:
      host: "0.0.0.0"
      port: 8080
      tls:
        enabled: true
        cert_file: "/etc/certs/tls.crt"
        key_file: "/etc/certs/tls.key"
    
    observability:
      metrics:
        enabled: true
      tracing:
        enabled: true
        jaeger:
          endpoint: "http://jaeger-collector.istio-system:14268/api/traces"
```

### Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: zamaz-secrets
  namespace: zamaz-system
type: Opaque
stringData:
  DB_PASSWORD: "secure_database_password"
  REDIS_PASSWORD: "secure_redis_password"
  JWT_SECRET: "your-super-secure-jwt-secret-key"
  ENCRYPTION_KEY: "32-character-encryption-key-here"
```

### Deployment Configuration

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zamaz-auth
  namespace: zamaz-system
spec:
  replicas: 3
  selector:
    matchLabels:
      app: zamaz-auth
  template:
    metadata:
      labels:
        app: zamaz-auth
    spec:
      containers:
      - name: zamaz-auth
        image: zamaz/root-zamaz:v1.0.0
        ports:
        - containerPort: 8080
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: zamaz-secrets
              key: DB_PASSWORD
        - name: CONFIG_FILE
          value: "/etc/config/app.yaml"
        volumeMounts:
        - name: config
          mountPath: /etc/config
        - name: certs
          mountPath: /etc/certs
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: zamaz-config
      - name: certs
        secret:
          secretName: zamaz-tls
```

## :shield: Security Configuration

### Authentication Configuration

```yaml
auth:
  providers:
    # Local authentication
    local:
      enabled: true
      
    # OAuth2 providers
    oauth2:
      google:
        enabled: true
        client_id: "${GOOGLE_CLIENT_ID}"
        client_secret: "${GOOGLE_CLIENT_SECRET}"
        scopes: ["openid", "email", "profile"]
        
      github:
        enabled: true
        client_id: "${GITHUB_CLIENT_ID}"
        client_secret: "${GITHUB_CLIENT_SECRET}"
        scopes: ["user:email"]
        
    # SAML providers
    saml:
      enabled: false
      entity_id: "zamaz-auth"
      acs_url: "https://api.zamaz.io/auth/saml/acs"
      
  # Multi-factor authentication
  mfa:
    enabled: true
    required_for_admin: true
    totp:
      enabled: true
      issuer: "Zamaz"
    sms:
      enabled: false
      provider: "twilio"
```

### Authorization Configuration

```yaml
authorization:
  # Role-based access control
  rbac:
    enabled: true
    
  # Policy as code
  opa:
    enabled: true
    endpoint: "http://opa-server:8181"
    
  # Casbin integration
  casbin:
    enabled: true
    model_file: "/etc/casbin/rbac_model.conf"
    policy_file: "/etc/casbin/rbac_policy.csv"
```

## :telescope: Observability Configuration

### Prometheus Configuration

```yaml
observability:
  metrics:
    prometheus:
      enabled: true
      namespace: "zamaz"
      subsystem: "auth"
      
      # Custom metrics
      custom_metrics:
        - name: "auth_requests_total"
          type: "counter"
          help: "Total authentication requests"
          
        - name: "auth_success_rate"
          type: "histogram"
          help: "Authentication success rate"
          buckets: [0.1, 0.5, 1.0, 2.0, 5.0]
```

### Jaeger Tracing

```yaml
tracing:
  jaeger:
    service_name: "zamaz-auth"
    sampler:
      type: "probabilistic"
      param: 0.1
    reporter:
      endpoint: "http://jaeger-collector:14268/api/traces"
      batch_size: 100
      flush_interval: "5s"
```

### Logging Configuration

```yaml
logging:
  level: "info"
  format: "json"
  
  # Structured logging fields
  fields:
    service: "zamaz-auth"
    version: "1.0.0"
    
  # Log rotation
  rotation:
    max_size: "100MB"
    max_age: "30d"
    max_backups: 10
    compress: true
```

## :gear: Feature Flags

```yaml
features:
  # Authentication features
  password_complexity: true
  session_timeout: true
  device_trust: true
  
  # API features
  rate_limiting: true
  request_signing: true
  api_versioning: true
  
  # Security features
  audit_logging: true
  threat_detection: true
  compliance_reporting: true
  
  # Experimental features
  experimental:
    webauthn: false
    zero_knowledge_proofs: false
    quantum_resistant_crypto: false
```

## :wrench: Runtime Configuration

### Command Line Flags

```bash
# Start with custom configuration
./zamaz-server \
  --config /etc/zamaz/config.yaml \
  --log-level debug \
  --port 8080 \
  --db-url "postgres://user:pass@localhost/db" \
  --enable-metrics \
  --metrics-port 9090
```

### Environment Variable Override

```bash
# Override any configuration value
export ZAMAZ_SERVER_PORT=8081
export ZAMAZ_DATABASE_HOST=db.example.com
export ZAMAZ_AUTH_JWT_EXPIRY=1h
export ZAMAZ_OBSERVABILITY_LOGGING_LEVEL=debug

# Start server
./zamaz-server
```

## :test_tube: Configuration Validation

### Validation Script

```bash
#!/bin/bash
# validate-config.sh

echo "Validating Zamaz configuration..."

# Check required environment variables
required_vars=(
  "JWT_SECRET"
  "DATABASE_URL"
  "REDIS_URL"
)

for var in "${required_vars[@]}"; do
  if [[ -z "${!var}" ]]; then
    echo "❌ Missing required environment variable: $var"
    exit 1
  fi
done

# Validate configuration file
if [[ -f "config/app.yaml" ]]; then
  echo "✅ Configuration file found"
  
  # Validate YAML syntax
  python3 -c "import yaml; yaml.safe_load(open('config/app.yaml'))" 2>/dev/null
  if [[ $? -eq 0 ]]; then
    echo "✅ Configuration file is valid YAML"
  else
    echo "❌ Configuration file has invalid YAML syntax"
    exit 1
  fi
else
  echo "❌ Configuration file not found: config/app.yaml"
  exit 1
fi

echo "✅ Configuration validation passed"
```

### Testing Configuration

```bash
# Validate configuration
make config-validate

# Test with dry-run
./zamaz-server --config config/app.yaml --dry-run

# Load test configuration
curl http://localhost:8080/api/v1/config/status
```

## :arrows_clockwise: Configuration Reload

Enable hot-reloading of configuration:

```yaml
config:
  reload:
    enabled: true
    interval: "30s"
    signal: "SIGHUP"
    
  watch:
    enabled: true
    paths:
      - "/etc/zamaz/config.yaml"
      - "/etc/zamaz/secrets"
```

## :page_facing_up: Best Practices

1. **Secrets Management**
   - Never commit secrets to version control
   - Use environment variables or secret management systems
   - Rotate secrets regularly

2. **Environment Separation**
   - Use different configurations for each environment
   - Validate configuration before deployment
   - Use infrastructure as code

3. **Security Hardening**
   - Enable TLS in production
   - Use strong encryption keys
   - Implement proper CORS policies
   - Enable audit logging

4. **Performance Tuning**
   - Adjust connection pool sizes based on load
   - Configure appropriate timeouts
   - Enable caching where appropriate
   - Monitor and tune observability sampling rates

## :sos: Troubleshooting

Common configuration issues and solutions:

!!! bug "Configuration Not Loading"
    
    **Issue**: Application using default values instead of configuration file
    
    **Solution**:
    ```bash
    # Check file path and permissions
    ls -la config/app.yaml
    
    # Validate YAML syntax
    python3 -c "import yaml; print(yaml.safe_load(open('config/app.yaml')))"
    
    # Check environment variables
    env | grep ZAMAZ_
    ```

!!! bug "Database Connection Failed"
    
    **Issue**: Cannot connect to database
    
    **Solution**:
    ```bash
    # Test database connectivity
    pg_isready -h localhost -p 5432
    
    # Check database URL format
    echo $DATABASE_URL
    
    # Validate credentials
    psql $DATABASE_URL -c "SELECT 1;"
    ```

For more configuration help, see the [Troubleshooting Guide](../troubleshooting.md).