# Docker Deployment Guide

This guide covers deploying the Zero Trust Auth MVP using Docker and Docker Compose for both development and production environments.

## 🐳 Overview

The application supports multiple Docker deployment strategies:

1. **Development**: Docker Compose with hot reload
2. **Production**: Optimized multi-stage Docker images
3. **Hybrid**: Local development with containerized services

## 🚀 Quick Start

### Development Deployment

```bash
# Clone repository
git clone <repository-url>
cd root-zamaz

# Start all services
make dev-up

# Check service status
docker ps

# View logs
make logs

# Stop services
make dev-down
```

### Production Deployment

```bash
# Build production image
docker build -t mvp-auth:latest .

# Run with production configuration
docker run -d \
  --name mvp-auth-prod \
  --restart=unless-stopped \
  -p 8080:8080 \
  -e DATABASE_URL=postgres://user:pass@host:5432/db \
  -e REDIS_URL=redis://redis:6379 \
  -e JWT_SECRET=your-production-secret \
  mvp-auth:latest
```

## 📁 Docker Configuration Files

### Main Docker Compose (`docker-compose.yml`)

```yaml
services:
  # Core Infrastructure
  envoy:
    image: envoyproxy/envoy:v1.28-latest
    platform: linux/amd64
    ports:
      - "8080:8080"
      - "8443:8443"
      - "9901:9901"
    volumes:
      - ./envoy/configs:/etc/envoy
      - ./envoy/certs:/etc/ssl/certs
    depends_on:
      - jaeger
      - prometheus
    networks:
      - mvp-network

  # SPIRE Infrastructure
  spire-server:
    image: ghcr.io/spiffe/spire-server:1.8.5
    hostname: spire-server
    ports:
      - "8081:8081"
    volumes:
      - ./deployments/spire/server:/opt/spire/conf/server
      - spire-server-data:/opt/spire/data
    command: ["-config", "/opt/spire/conf/server/server.conf"]
    networks:
      - mvp-network

  spire-agent:
    image: ghcr.io/spiffe/spire-agent:1.8.5
    hostname: spire-agent
    depends_on:
      - spire-server
    volumes:
      - ./deployments/spire/agent:/opt/spire/conf/agent
      - spire-agent-socket:/tmp/spire-agent/public
    command: ["-config", "/opt/spire/conf/agent/agent.conf"]
    networks:
      - mvp-network

  # Database
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: mvp_db
      POSTGRES_USER: mvp_user
      POSTGRES_PASSWORD: mvp_password
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./scripts/sql/init:/docker-entrypoint-initdb.d
    ports:
      - "5432:5432"
    networks:
      - mvp-network

  # Cache
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis-data:/data
    ports:
      - "6379:6379"
    networks:
      - mvp-network

  # Message Queue
  nats:
    image: nats:2.10-alpine
    command: ["-js", "-m", "8222"]
    volumes:
      - nats-data:/data
    ports:
      - "4222:4222"
      - "8222:8222"
    networks:
      - mvp-network

  # Observability Stack
  prometheus:
    image: prom/prometheus:v2.47.0
    ports:
      - "9090:9090"
    volumes:
      - ./observability/prometheus:/etc/prometheus
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'
    networks:
      - mvp-network

  grafana:
    image: grafana/grafana:10.1.0
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-simple-json-datasource
    volumes:
      - grafana-data:/var/lib/grafana
      - ./observability/grafana/provisioning:/etc/grafana/provisioning
      - ./observability/dashboards:/var/lib/grafana/dashboards
    networks:
      - mvp-network

  jaeger:
    image: jaegertracing/all-in-one:1.49
    ports:
      - "5775:5775/udp"
      - "6831:6831/udp"
      - "6832:6832/udp"
      - "5778:5778"
      - "16686:16686"
      - "14268:14268"
      - "14250:14250"
      - "9411:9411"
    environment:
      - COLLECTOR_ZIPKIN_HOST_PORT=:9411
    networks:
      - mvp-network

  loki:
    image: grafana/loki:2.9.0
    ports:
      - "3100:3100"
    volumes:
      - ./observability/loki/config.yml:/etc/loki/local-config.yaml
      - loki-data:/loki
    command: -config.file=/etc/loki/local-config.yaml
    networks:
      - mvp-network

  promtail:
    image: grafana/promtail:2.9.0
    volumes:
      - /var/log:/var/log:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - ./observability/promtail/config.yml:/etc/promtail/config.yml
    command: -config.file=/etc/promtail/config.yml
    networks:
      - mvp-network

volumes:
  postgres-data:
  redis-data:
  nats-data:
  prometheus-data:
  grafana-data:
  loki-data:
  spire-server-data:
  spire-agent-socket:

networks:
  mvp-network:
    driver: bridge
```

### Application Dockerfile

```dockerfile
# Multi-stage Dockerfile for MVP Zero Trust Auth System
# Stage 1: Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build arguments
ARG VERSION=dev
ARG COMMIT_SHA=unknown
ARG BUILD_TIME=unknown

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT_SHA} -X main.buildTime=${BUILD_TIME} -w -s" \
    -a -installsuffix cgo \
    -o mvp-auth ./cmd/server

# Stage 2: Runtime stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata curl && \
    adduser -D -s /bin/sh -u 1001 appuser

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/mvp-auth .
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy configuration files if they exist
COPY --from=builder /app/configs/ ./configs/ 2>/dev/null || true

# Create necessary directories
RUN mkdir -p /app/logs /app/data && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose ports
EXPOSE 8080 9000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Set entrypoint
ENTRYPOINT ["./mvp-auth"]
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file for local development:

```bash
# Database Configuration
DATABASE_HOST=postgres
DATABASE_PORT=5432
DATABASE_NAME=mvp_db
DATABASE_USER=mvp_user
DATABASE_PASSWORD=mvp_password
DATABASE_SSL_MODE=disable

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DATABASE=0

# NATS Configuration
NATS_URL=nats://nats:4222

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_ACCESS_TOKEN_EXPIRATION=24h
JWT_REFRESH_TOKEN_EXPIRATION=7d

# Server Configuration
HTTP_HOST=0.0.0.0
HTTP_PORT=8080
HTTP_READ_TIMEOUT=30s
HTTP_WRITE_TIMEOUT=30s

# Observability
JAEGER_ENDPOINT=http://jaeger:14268/api/traces
PROMETHEUS_PORT=9000
LOG_LEVEL=info
LOG_FORMAT=json

# Security
CORS_ALLOWED_ORIGINS=http://localhost:5175,http://localhost:3000
DISABLE_AUTH=false

# Environment
ENVIRONMENT=development
SERVICE_NAME=mvp-zero-trust-auth
SERVICE_VERSION=1.0.0
```

### Production Environment Variables

```bash
# Database Configuration (use managed database in production)
DATABASE_URL=postgres://user:password@prod-db-host:5432/mvp_db?sslmode=require

# Redis Configuration (use managed Redis in production)
REDIS_URL=redis://prod-redis-host:6379

# JWT Configuration (use strong secrets)
JWT_SECRET=${STRONG_RANDOM_SECRET}
JWT_ACCESS_TOKEN_EXPIRATION=1h
JWT_REFRESH_TOKEN_EXPIRATION=24h

# Server Configuration
HTTP_HOST=0.0.0.0
HTTP_PORT=8080
HTTP_READ_TIMEOUT=15s
HTTP_WRITE_TIMEOUT=15s

# TLS Configuration
TLS_ENABLED=true
TLS_CERT_FILE=/etc/ssl/certs/server.crt
TLS_KEY_FILE=/etc/ssl/private/server.key

# Observability
JAEGER_ENDPOINT=https://jaeger.monitoring.svc.cluster.local:14268/api/traces
PROMETHEUS_PORT=9000
LOG_LEVEL=warn
LOG_FORMAT=json

# Security
CORS_ALLOWED_ORIGINS=https://yourdomain.com
DISABLE_AUTH=false

# Environment
ENVIRONMENT=production
SERVICE_NAME=mvp-zero-trust-auth
SERVICE_VERSION=${BUILD_VERSION}
```

## 🚀 Deployment Strategies

### 1. Development Environment

```bash
# Start development environment
make dev-up

# Check all services are running
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Access services
open http://localhost:3000  # Grafana
open http://localhost:9090  # Prometheus
open http://localhost:16686 # Jaeger
```

### 2. Production Single-Host

```bash
# Create production directory
mkdir -p /opt/mvp-auth
cd /opt/mvp-auth

# Create production docker-compose
cat > docker-compose.prod.yml << 'EOF'
version: '3.8'
services:
  mvp-auth:
    image: mvp-auth:latest
    restart: unless-stopped
    ports:
      - "80:8080"
      - "443:8080"  # Configure TLS termination
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
      - JWT_SECRET=${JWT_SECRET}
      - ENVIRONMENT=production
    volumes:
      - ./logs:/app/logs
      - ./certs:/etc/ssl/certs:ro
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:15-alpine
    restart: unless-stopped
    environment:
      - POSTGRES_DB=mvp_db
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis-data:/data

volumes:
  postgres-data:
  redis-data:
EOF

# Start production services
docker-compose -f docker-compose.prod.yml up -d
```

### 3. Production with Reverse Proxy

```nginx
# /etc/nginx/sites-available/mvp-auth
server {
    listen 80;
    server_name auth.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name auth.yourdomain.com;

    ssl_certificate /etc/ssl/certs/auth.yourdomain.com.crt;
    ssl_certificate_key /etc/ssl/private/auth.yourdomain.com.key;

    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Health check endpoint
        location /health {
            access_log off;
            proxy_pass http://127.0.0.1:8080/health;
        }
    }
}
```

### 4. Multi-Host with Docker Swarm

```yaml
# docker-stack.yml
version: '3.8'

services:
  mvp-auth:
    image: mvp-auth:latest
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      placement:
        constraints:
          - node.role == worker
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
      - JWT_SECRET=${JWT_SECRET}
    networks:
      - mvp-network

  postgres:
    image: postgres:15-alpine
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.role == manager
    environment:
      - POSTGRES_DB=mvp_db
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    networks:
      - mvp-network

  redis:
    image: redis:7-alpine
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.role == manager
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis-data:/data
    networks:
      - mvp-network

volumes:
  postgres-data:
  redis-data:

networks:
  mvp-network:
    driver: overlay
    attachable: true
```

Deploy with Docker Swarm:

```bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-stack.yml mvp-auth

# Check services
docker service ls
docker stack ps mvp-auth
```

## 🔍 Monitoring & Health Checks

### Health Check Configuration

```yaml
# In docker-compose.yml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```

### Monitoring with Docker

```bash
# Check container health
docker ps --filter "health=healthy"
docker ps --filter "health=unhealthy"

# View container logs
docker logs mvp-zero-trust-auth-envoy-1 --tail 100 --follow

# Monitor resource usage
docker stats

# Check container details
docker inspect mvp-zero-trust-auth-envoy-1
```

### Log Management

```yaml
# Configure log rotation
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

## 🔒 Security Considerations

### 1. Secrets Management

```bash
# Use Docker secrets in production
echo "your-jwt-secret" | docker secret create jwt_secret -
echo "your-db-password" | docker secret create db_password -

# Reference in docker-compose
services:
  mvp-auth:
    secrets:
      - jwt_secret
      - db_password
    environment:
      - JWT_SECRET_FILE=/run/secrets/jwt_secret
      - DB_PASSWORD_FILE=/run/secrets/db_password

secrets:
  jwt_secret:
    external: true
  db_password:
    external: true
```

### 2. Network Security

```yaml
# Isolate networks
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # No external access

services:
  mvp-auth:
    networks:
      - frontend
      - backend
  
  postgres:
    networks:
      - backend  # Only internal access
```

### 3. Container Security

```dockerfile
# Security best practices
FROM alpine:3.18

# Create non-root user
RUN adduser -D -s /bin/sh -u 1001 appuser

# Remove unnecessary packages
RUN apk del --purge build-dependencies

# Use read-only filesystem
docker run --read-only --tmpfs /tmp mvp-auth:latest

# Limit resources
docker run --memory=512m --cpus=1.0 mvp-auth:latest

# Drop capabilities
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE mvp-auth:latest
```

## 🧪 Testing Docker Deployment

### Development Testing

```bash
# Start development environment
make dev-up

# Wait for services to be ready
./scripts/wait-for-services.sh

# Run integration tests
make test-integration

# Test API endpoints
curl http://localhost:8080/health
curl http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'
```

### Production Testing

```bash
# Test production image
docker build -t mvp-auth:test .

# Run production tests
docker run --rm \
  -e DATABASE_URL=postgres://test:test@host:5432/test \
  -e REDIS_URL=redis://redis:6379 \
  -e JWT_SECRET=test-secret \
  mvp-auth:test \
  /app/mvp-auth --test

# Load testing
docker run --rm \
  --network=host \
  loadimpact/k6 run \
  -e BASE_URL=http://localhost:8080 \
  tests/load/basic-load-test.js
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Container Won't Start
```bash
# Check logs
docker logs container-name

# Check health status
docker inspect --format='{{.State.Health.Status}}' container-name

# Check resource constraints
docker stats container-name
```

#### 2. Service Discovery Issues
```bash
# Check network connectivity
docker exec container-name ping other-container

# Check DNS resolution
docker exec container-name nslookup postgres

# List networks
docker network ls
docker network inspect mvp-zero-trust-auth_mvp-network
```

#### 3. Volume Mount Issues
```bash
# Check volume mounts
docker inspect container-name | grep -A 10 "Mounts"

# Check permissions
docker exec container-name ls -la /app/data

# Fix permissions
docker exec --user root container-name chown -R appuser:appuser /app/data
```

#### 4. Database Connection Issues
```bash
# Test database connectivity
docker exec postgres-container psql -U mvp_user -d mvp_db -c "SELECT 1;"

# Check database logs
docker logs postgres-container

# Verify environment variables
docker exec mvp-auth-container env | grep DATABASE
```

### Performance Tuning

```yaml
# Resource limits in docker-compose
services:
  mvp-auth:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
```

### Backup and Recovery

```bash
# Database backup
docker exec postgres-container pg_dump -U mvp_user mvp_db > backup.sql

# Volume backup
docker run --rm \
  -v mvp_postgres_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/postgres-backup.tar.gz /data

# Restore database
docker exec -i postgres-container psql -U mvp_user mvp_db < backup.sql
```

## 📚 Additional Resources

- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Container Security](https://docs.docker.com/engine/security/)
- [Production Deployment](docs/deployment/production.md)