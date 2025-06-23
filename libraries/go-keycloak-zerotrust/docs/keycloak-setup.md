# Keycloak Setup Guide

This comprehensive guide walks you through setting up Keycloak for use with the go-keycloak-zerotrust library, including Zero Trust features and production-ready configurations.

## Table of Contents

1. [Quick Start with Docker](#quick-start-with-docker)
2. [Production Installation](#production-installation)
3. [Realm Configuration](#realm-configuration)
4. [Client Configuration](#client-configuration)
5. [User Management](#user-management)
6. [Zero Trust Configuration](#zero-trust-configuration)
7. [Security Hardening](#security-hardening)
8. [Monitoring and Logging](#monitoring-and-logging)
9. [Troubleshooting](#troubleshooting)

## Quick Start with Docker

### 1. Basic Keycloak Setup

For development and testing purposes:

```bash
# Create a directory for Keycloak data
mkdir -p ./keycloak-data

# Run Keycloak with PostgreSQL
docker-compose up -d
```

**docker-compose.yml:**

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: keycloak_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keycloak"]
      interval: 10s
      timeout: 5s
      retries: 5

  keycloak:
    image: quay.io/keycloak/keycloak:22.0
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: keycloak_password
      KC_HOSTNAME: localhost
      KC_HOSTNAME_PORT: 8080
      KC_HOSTNAME_STRICT: false
      KC_HOSTNAME_STRICT_HTTPS: false
      KC_LOG_LEVEL: info
      KC_METRICS_ENABLED: true
      KC_HEALTH_ENABLED: true
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
    ports:
      - "8080:8080"
    depends_on:
      postgres:
        condition: service_healthy
    command: start-dev
    volumes:
      - ./themes:/opt/keycloak/themes
      - ./imports:/opt/keycloak/data/import

volumes:
  postgres_data:
```

### 2. Initial Setup

1. **Start the services:**
   ```bash
   docker-compose up -d
   ```

2. **Wait for Keycloak to start:**
   ```bash
   # Check logs
   docker-compose logs -f keycloak
   
   # Wait for "Keycloak started" message
   ```

3. **Access Keycloak Admin Console:**
   - URL: http://localhost:8080/admin
   - Username: `admin`
   - Password: `admin`

## Production Installation

### 1. Prerequisites

**System Requirements:**
- CPU: 4+ cores
- RAM: 8GB+ (16GB recommended)
- Storage: 100GB+ SSD
- Network: HTTPS-capable load balancer
- Database: PostgreSQL 12+ (clustered for HA)

**Dependencies:**
- Java 17+
- PostgreSQL 12+
- Reverse proxy (Nginx/Apache)
- SSL certificates
- Monitoring tools

### 2. Installation Options

#### Option A: Package Installation

```bash
# Download Keycloak
wget https://github.com/keycloak/keycloak/releases/download/22.0.5/keycloak-22.0.5.tar.gz
tar -xzf keycloak-22.0.5.tar.gz
cd keycloak-22.0.5

# Configure environment
export KEYCLOAK_ADMIN=admin
export KEYCLOAK_ADMIN_PASSWORD=secure_admin_password

# Build for production
./bin/kc.sh build
```

#### Option B: Kubernetes Deployment

**keycloak-deployment.yaml:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
  namespace: keycloak
spec:
  replicas: 2
  selector:
    matchLabels:
      app: keycloak
  template:
    metadata:
      labels:
        app: keycloak
    spec:
      containers:
      - name: keycloak
        image: quay.io/keycloak/keycloak:22.0
        args: ["start"]
        env:
        - name: KEYCLOAK_ADMIN
          value: "admin"
        - name: KEYCLOAK_ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: keycloak-admin-secret
              key: password
        - name: KC_DB
          value: postgres
        - name: KC_DB_URL
          value: jdbc:postgresql://postgres-service:5432/keycloak
        - name: KC_DB_USERNAME
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: username
        - name: KC_DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password
        - name: KC_HOSTNAME
          value: keycloak.company.com
        - name: KC_PROXY
          value: edge
        ports:
        - name: http
          containerPort: 8080
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 60
          periodSeconds: 30
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
```

### 3. Database Configuration

**PostgreSQL Setup:**

```sql
-- Create database and user
CREATE DATABASE keycloak;
CREATE USER keycloak WITH ENCRYPTED PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;

-- Performance tuning
ALTER DATABASE keycloak SET log_statement = 'none';
ALTER DATABASE keycloak SET log_min_duration_statement = 1000;
```

**Connection Pool Configuration:**

```properties
# conf/keycloak.conf
db=postgres
db-url=jdbc:postgresql://postgres-host:5432/keycloak
db-username=keycloak
db-password=secure_password
db-pool-initial-size=20
db-pool-min-size=10
db-pool-max-size=100
```

## Realm Configuration

### 1. Create Production Realm

1. **Access Admin Console**
2. **Create New Realm:**
   - Name: `production` (or your company name)
   - Display Name: `Production Environment`
   - Enabled: `true`

### 2. Realm Settings

**General Settings:**
```json
{
  "realm": "production",
  "displayName": "Production Environment",
  "enabled": true,
  "userManagedAccessAllowed": false,
  "registrationAllowed": false,
  "registrationEmailAsUsername": true,
  "rememberMe": true,
  "verifyEmail": true,
  "loginWithEmailAllowed": true,
  "duplicateEmailsAllowed": false,
  "resetPasswordAllowed": true,
  "editUsernameAllowed": false,
  "bruteForceProtected": true,
  "permanentLockout": false,
  "maxFailureWaitSeconds": 900,
  "minimumQuickLoginWaitSeconds": 60,
  "waitIncrementSeconds": 60,
  "quickLoginCheckMilliSeconds": 1000,
  "maxDeltaTimeSeconds": 43200,
  "failureFactor": 30
}
```

**Security Settings:**
- **Brute Force Protection**: Enabled
- **Max Login Failures**: 5
- **Wait Increment**: 60 seconds
- **Max Wait**: 900 seconds
- **Quick Login Check**: 1000ms

**Login Settings:**
- **User Registration**: Disabled (for production)
- **Forgot Password**: Enabled
- **Remember Me**: Enabled
- **Verify Email**: Enabled
- **Login with Email**: Enabled

### 3. Authentication Flows

#### Custom Zero Trust Flow

1. **Navigate to Authentication → Flows**
2. **Copy Browser Flow** → Name: "Zero Trust Browser"
3. **Modify Flow:**

```
Zero Trust Browser Flow:
├── Cookie (ALTERNATIVE)
├── Kerberos (DISABLED)
├── Identity Provider Redirector (ALTERNATIVE)
└── Zero Trust Forms (ALTERNATIVE)
    ├── Username Password Form (REQUIRED)
    ├── Zero Trust Conditional OTP (CONDITIONAL)
    │   ├── Condition - User Configured (REQUIRED)
    │   └── OTP Form (REQUIRED)
    ├── Device Verification (CONDITIONAL)
    │   ├── Condition - Device Trust Level (REQUIRED)
    │   └── Device Attestation (REQUIRED)
    └── Risk Assessment (REQUIRED)
```

#### Custom Authentication Scripts

**Device Trust Level Condition:**

```javascript
// Device Trust Level Authenticator
function authenticate(context) {
    var user = context.getUser();
    var session = context.getAuthenticationSession();
    var trustLevel = getUserTrustLevel(user);
    var requiredLevel = session.getClientNote("required_trust_level") || "50";
    
    if (trustLevel >= parseInt(requiredLevel)) {
        context.success();
    } else {
        context.attempted();
    }
}

function getUserTrustLevel(user) {
    var trustLevelAttr = user.getFirstAttribute("trust_level");
    return trustLevelAttr ? parseInt(trustLevelAttr) : 0;
}
```

## Client Configuration

### 1. Create Zero Trust Client

**Client Settings:**
```json
{
  "clientId": "zerotrust-api",
  "name": "Zero Trust API Client",
  "protocol": "openid-connect",
  "clientAuthenticatorType": "client-secret",
  "secret": "generate-secure-secret",
  "redirectUris": [
    "https://api.company.com/*",
    "https://app.company.com/*"
  ],
  "webOrigins": [
    "https://app.company.com"
  ],
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": true,
  "serviceAccountsEnabled": true,
  "publicClient": false,
  "frontchannelLogout": true,
  "fullScopeAllowed": false,
  "nodeReRegistrationTimeout": 0,
  "defaultClientScopes": [
    "web-origins",
    "role_list",
    "profile",
    "roles",
    "email"
  ],
  "optionalClientScopes": [
    "address",
    "phone",
    "offline_access",
    "microprofile-jwt"
  ]
}
```

### 2. Client Mappers

#### Trust Level Mapper

```json
{
  "name": "trust-level-mapper",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-attribute-mapper",
  "config": {
    "userinfo.token.claim": "true",
    "user.attribute": "trust_level",
    "id.token.claim": "true",
    "access.token.claim": "true",
    "claim.name": "trust_level",
    "jsonType.label": "int"
  }
}
```

#### Device ID Mapper

```json
{
  "name": "device-id-mapper",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-attribute-mapper",
  "config": {
    "userinfo.token.claim": "true",
    "user.attribute": "device_id",
    "id.token.claim": "true",
    "access.token.claim": "true",
    "claim.name": "device_id",
    "jsonType.label": "String"
  }
}
```

#### Risk Score Mapper

```json
{
  "name": "risk-score-mapper",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-attribute-mapper",
  "config": {
    "userinfo.token.claim": "true",
    "user.attribute": "risk_score",
    "id.token.claim": "true",
    "access.token.claim": "true",
    "claim.name": "risk_score",
    "jsonType.label": "double"
  }
}
```

### 3. Client Scopes

#### Zero Trust Scope

```json
{
  "name": "zerotrust",
  "description": "Zero Trust specific claims",
  "protocol": "openid-connect",
  "attributes": {
    "consent.screen.text": "${zeroTrustScopeConsentText}",
    "display.on.consent.screen": "true"
  },
  "protocolMappers": [
    {
      "name": "trust-level",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-usermodel-attribute-mapper",
      "config": {
        "user.attribute": "trust_level",
        "claim.name": "trust_level",
        "jsonType.label": "int",
        "id.token.claim": "true",
        "access.token.claim": "true"
      }
    },
    {
      "name": "device-verified",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-usermodel-attribute-mapper",
      "config": {
        "user.attribute": "device_verified",
        "claim.name": "device_verified",
        "jsonType.label": "boolean",
        "id.token.claim": "true",
        "access.token.claim": "true"
      }
    }
  ]
}
```

## User Management

### 1. User Attributes for Zero Trust

**Required Attributes:**
```json
{
  "trust_level": "75",
  "device_id": "device-12345",
  "device_verified": "true",
  "risk_score": "25.5",
  "last_device_attestation": "2024-01-15T10:30:00Z",
  "preferred_mfa_method": "totp",
  "security_clearance": "confidential",
  "department": "engineering",
  "location_restrictions": "US,CA,UK"
}
```

### 2. Bulk User Import

**users-import.json:**
```json
{
  "realm": "production",
  "users": [
    {
      "username": "john.doe",
      "email": "john.doe@company.com",
      "firstName": "John",
      "lastName": "Doe",
      "enabled": true,
      "emailVerified": true,
      "attributes": {
        "trust_level": ["50"],
        "department": ["engineering"],
        "security_clearance": ["secret"]
      },
      "credentials": [
        {
          "type": "password",
          "value": "temp-password",
          "temporary": true
        }
      ],
      "realmRoles": ["user"],
      "clientRoles": {
        "zerotrust-api": ["api-user"]
      }
    }
  ]
}
```

**Import Command:**
```bash
# Import via Admin CLI
/opt/keycloak/bin/kc.sh import --file users-import.json
```

### 3. User Federation (LDAP/Active Directory)

**LDAP Configuration:**
```json
{
  "name": "company-ldap",
  "providerId": "ldap",
  "providerType": "org.keycloak.storage.UserStorageProvider",
  "config": {
    "connectionUrl": ["ldap://ldap.company.com:389"],
    "usersDn": ["ou=users,dc=company,dc=com"],
    "bindDn": ["cn=keycloak,ou=service,dc=company,dc=com"],
    "bindCredential": ["ldap-bind-password"],
    "searchScope": ["2"],
    "usernameAttribute": ["uid"],
    "uuidAttribute": ["entryUUID"],
    "userObjectClasses": ["inetOrgPerson, organizationalPerson"],
    "connectionPooling": ["true"],
    "pagination": ["true"],
    "batchSizeForSync": ["1000"],
    "fullSyncPeriod": ["604800"],
    "changedSyncPeriod": ["86400"],
    "importEnabled": ["true"],
    "syncRegistrations": ["false"],
    "vendor": ["other"],
    "allowKerberosAuthentication": ["false"],
    "useKerberosForPasswordAuthentication": ["false"]
  }
}
```

**Attribute Mappers:**
```json
[
  {
    "name": "username",
    "providerId": "user-attribute-ldap-mapper",
    "config": {
      "ldap.attribute": "uid",
      "user.model.attribute": "username",
      "read.only": "true",
      "always.read.value.from.ldap": "false"
    }
  },
  {
    "name": "email",
    "providerId": "user-attribute-ldap-mapper",
    "config": {
      "ldap.attribute": "mail",
      "user.model.attribute": "email",
      "read.only": "true",
      "always.read.value.from.ldap": "false"
    }
  },
  {
    "name": "department",
    "providerId": "user-attribute-ldap-mapper",
    "config": {
      "ldap.attribute": "ou",
      "user.model.attribute": "department",
      "read.only": "true",
      "always.read.value.from.ldap": "true"
    }
  }
]
```

## Zero Trust Configuration

### 1. Custom Event Listeners

**Zero Trust Event Listener:**
```java
@Provider
public class ZeroTrustEventListener implements EventListenerProvider {
    
    @Override
    public void onEvent(Event event) {
        switch (event.getType()) {
            case LOGIN:
                handleLogin(event);
                break;
            case LOGIN_ERROR:
                handleLoginError(event);
                break;
            case LOGOUT:
                handleLogout(event);
                break;
        }
    }
    
    private void handleLogin(Event event) {
        // Update user trust level based on successful login
        updateTrustLevel(event.getUserId(), event.getIpAddress());
        
        // Perform risk assessment
        assessLoginRisk(event);
        
        // Update device verification status
        updateDeviceVerification(event);
    }
}
```

### 2. Custom SPI Implementations

**Trust Level Provider:**
```java
@Provider
public class DatabaseTrustLevelProvider implements TrustLevelProvider {
    
    @Override
    public int getTrustLevel(String userId, KeycloakSession session) {
        // Fetch from external database or service
        return trustLevelService.getUserTrustLevel(userId);
    }
    
    @Override
    public void updateTrustLevel(String userId, int newLevel, KeycloakSession session) {
        // Update in external database
        trustLevelService.updateTrustLevel(userId, newLevel);
        
        // Update Keycloak user attributes
        UserModel user = session.users().getUserById(session.getContext().getRealm(), userId);
        user.setSingleAttribute("trust_level", String.valueOf(newLevel));
    }
}
```

### 3. Theme Customization

**Zero Trust Theme Structure:**
```
themes/
└── zerotrust/
    ├── login/
    │   ├── login.ftl
    │   ├── login-device-verification.ftl
    │   ├── login-risk-assessment.ftl
    │   └── resources/
    │       ├── css/
    │       ├── js/
    │       └── img/
    └── account/
        ├── account.ftl
        ├── device-management.ftl
        └── resources/
```

**Device Verification Template (login-device-verification.ftl):**
```html
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('device') displayInfo=realm.password; section>
    <#if section = "header">
        ${msg("deviceVerificationTitle")}
    <#elseif section = "form">
        <form id="device-verification-form" action="${url.loginAction}" method="post">
            <div class="form-group">
                <label for="device-code">${msg("deviceVerificationCode")}</label>
                <input type="text" id="device-code" name="device-code" class="form-control" required />
            </div>
            
            <div class="form-group">
                <button class="btn btn-primary btn-block" type="submit">
                    ${msg("verifyDevice")}
                </button>
            </div>
            
            <div class="form-group">
                <a href="${url.loginUrl}">${msg("backToLogin")}</a>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
```

## Security Hardening

### 1. SSL/TLS Configuration

**HTTPS Configuration:**
```properties
# conf/keycloak.conf
hostname=keycloak.company.com
https-certificate-file=/opt/keycloak/certs/keycloak.crt
https-certificate-key-file=/opt/keycloak/certs/keycloak.key
https-protocols=TLSv1.3,TLSv1.2
https-cipher-suites=TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384
```

**Certificate Management:**
```bash
# Generate CSR
openssl req -new -newkey rsa:4096 -nodes -keyout keycloak.key -out keycloak.csr

# Install certificate
cp keycloak.crt /opt/keycloak/certs/
cp keycloak.key /opt/keycloak/certs/
chmod 600 /opt/keycloak/certs/keycloak.key
```

### 2. Security Headers

**Reverse Proxy Configuration (Nginx):**
```nginx
server {
    listen 443 ssl http2;
    server_name keycloak.company.com;
    
    ssl_certificate /etc/ssl/certs/keycloak.crt;
    ssl_certificate_key /etc/ssl/private/keycloak.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
    
    location / {
        proxy_pass http://keycloak-backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }
}
```

### 3. Rate Limiting

**Application Level Rate Limiting:**
```properties
# conf/keycloak.conf
spi-rate-limiting-enabled=true
spi-rate-limiting-login-attempts=5
spi-rate-limiting-login-window=300
spi-rate-limiting-admin-attempts=10
spi-rate-limiting-admin-window=60
```

**Nginx Rate Limiting:**
```nginx
http {
    # Rate limiting zones
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=admin:10m rate=10r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;
    
    server {
        # Login endpoints
        location ~ ^/realms/.*/protocol/openid-connect/(auth|token) {
            limit_req zone=login burst=10 nodelay;
            proxy_pass http://keycloak-backend;
        }
        
        # Admin endpoints
        location /admin/ {
            limit_req zone=admin burst=20 nodelay;
            proxy_pass http://keycloak-backend;
        }
        
        # API endpoints
        location ~ ^/realms/.*/protocol/openid-connect/userinfo {
            limit_req zone=api burst=200 nodelay;
            proxy_pass http://keycloak-backend;
        }
    }
}
```

### 4. Database Security

**PostgreSQL Security:**
```sql
-- Create dedicated user with minimal privileges
CREATE ROLE keycloak_app WITH LOGIN ENCRYPTED PASSWORD 'secure_password';
GRANT CONNECT ON DATABASE keycloak TO keycloak_app;
GRANT USAGE ON SCHEMA public TO keycloak_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO keycloak_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO keycloak_app;

-- Enable SSL
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_cert_file = '/etc/ssl/certs/server.crt';
ALTER SYSTEM SET ssl_key_file = '/etc/ssl/private/server.key';

-- Connection security
ALTER SYSTEM SET ssl_min_protocol_version = 'TLSv1.2';
ALTER SYSTEM SET password_encryption = 'scram-sha-256';
```

## Monitoring and Logging

### 1. Metrics Configuration

**Prometheus Metrics:**
```properties
# conf/keycloak.conf
metrics-enabled=true
```

**Prometheus Configuration:**
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'keycloak'
    static_configs:
      - targets: ['keycloak:8080']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### 2. Logging Configuration

**Structured Logging:**
```xml
<!-- log4j2.xml -->
<Configuration>
    <Appenders>
        <RollingFile name="FILE" fileName="logs/keycloak.log"
                     filePattern="logs/keycloak-%d{yyyy-MM-dd}-%i.log.gz">
            <JsonLayout compact="true" eventEol="true">
                <KeyValuePair key="service" value="keycloak"/>
                <KeyValuePair key="environment" value="production"/>
            </JsonLayout>
            <Policies>
                <TimeBasedTriggeringPolicy/>
                <SizeBasedTriggeringPolicy size="100MB"/>
            </Policies>
            <DefaultRolloverStrategy max="30"/>
        </RollingFile>
    </Appenders>
    
    <Loggers>
        <Logger name="org.keycloak.events" level="INFO" additivity="false">
            <AppenderRef ref="FILE"/>
        </Logger>
        <Root level="WARN">
            <AppenderRef ref="FILE"/>
        </Root>
    </Loggers>
</Configuration>
```

### 3. Health Checks

**Health Check Endpoints:**
```bash
# Readiness probe
curl -f http://localhost:8080/health/ready

# Liveness probe
curl -f http://localhost:8080/health/live

# Metrics endpoint
curl http://localhost:8080/metrics
```

**Kubernetes Health Checks:**
```yaml
readinessProbe:
  httpGet:
    path: /health/ready
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  successThreshold: 1
  failureThreshold: 3

livenessProbe:
  httpGet:
    path: /health/live
    port: 8080
  initialDelaySeconds: 60
  periodSeconds: 30
  timeoutSeconds: 10
  failureThreshold: 3
```

## Troubleshooting

### 1. Common Issues

#### Database Connection Issues

**Problem:** Connection pool exhaustion
**Solution:**
```properties
# Increase connection pool size
db-pool-max-size=200
db-pool-min-size=20

# Add connection validation
db-pool-validate-on-match=true
db-pool-background-validation=true
```

#### Memory Issues

**Problem:** OutOfMemoryError
**Solution:**
```bash
# Increase JVM memory
export JAVA_OPTS="-Xms2g -Xmx8g -XX:MetaspaceSize=96M -XX:MaxMetaspaceSize=256m"

# Enable GC logging
export JAVA_OPTS="$JAVA_OPTS -XX:+UseG1GC -XX:+PrintGC -XX:+PrintGCDetails"
```

#### SSL Certificate Issues

**Problem:** Certificate validation errors
**Solution:**
```bash
# Verify certificate chain
openssl s_client -connect keycloak.company.com:443 -showcerts

# Check certificate expiration
openssl x509 -in keycloak.crt -text -noout | grep "Not After"

# Validate certificate with CA
openssl verify -CAfile ca-bundle.crt keycloak.crt
```

### 2. Debug Configuration

**Enable Debug Logging:**
```xml
<Logger name="org.keycloak" level="DEBUG"/>
<Logger name="org.keycloak.authentication" level="TRACE"/>
<Logger name="org.keycloak.events" level="DEBUG"/>
<Logger name="org.keycloak.services" level="DEBUG"/>
```

**Debug Authentication Flows:**
```properties
# Enable authentication debugging
log-level=DEBUG
```

### 3. Performance Tuning

**JVM Tuning:**
```bash
# Production JVM settings
export JAVA_OPTS="-server \
  -Xms4g -Xmx8g \
  -XX:+UseG1GC \
  -XX:MaxGCPauseMillis=100 \
  -XX:+UseStringDeduplication \
  -XX:+OptimizeStringConcat \
  -XX:+UseCompressedOops \
  -XX:+UseCompressedClassPointers"
```

**Database Tuning:**
```sql
-- PostgreSQL performance tuning
ALTER SYSTEM SET shared_buffers = '2GB';
ALTER SYSTEM SET effective_cache_size = '6GB';
ALTER SYSTEM SET maintenance_work_mem = '512MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.7;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;
```

### 4. Backup and Recovery

**Database Backup:**
```bash
#!/bin/bash
# backup-keycloak.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/keycloak"
DB_NAME="keycloak"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup database
pg_dump -h localhost -U keycloak -d $DB_NAME -f "$BACKUP_DIR/keycloak_$DATE.sql"

# Compress backup
gzip "$BACKUP_DIR/keycloak_$DATE.sql"

# Cleanup old backups (keep 30 days)
find "$BACKUP_DIR" -name "keycloak_*.sql.gz" -mtime +30 -delete
```

**Configuration Backup:**
```bash
#!/bin/bash
# Export realm configuration
/opt/keycloak/bin/kc.sh export --dir /backups/keycloak/realms --realm production

# Backup themes and custom extensions
tar -czf /backups/keycloak/themes_$DATE.tar.gz /opt/keycloak/themes/
tar -czf /backups/keycloak/providers_$DATE.tar.gz /opt/keycloak/providers/
```

This comprehensive Keycloak setup guide provides everything needed to deploy and configure Keycloak for production use with the go-keycloak-zerotrust library, including advanced security features and Zero Trust implementations.