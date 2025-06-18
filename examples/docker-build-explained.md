# Docker Multi-stage Build Explained

## Dockerfile Analysis

### Stage 1: Builder (golang:1.23-alpine)
```dockerfile
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

# Build arguments for version injection
ARG VERSION=dev
ARG COMMIT_SHA=unknown
ARG BUILD_TIME=unknown

# Optimized build with static linking
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT_SHA} -X main.buildTime=${BUILD_TIME} -w -s" \
    -a -installsuffix cgo \
    -o mvp-auth ./
```

**Key Optimizations:**
- `CGO_ENABLED=0` - Static binary, no C dependencies
- `-w -s` - Strip debug info and symbol table (smaller binary)
- `-a -installsuffix cgo` - Rebuild packages for static linking
- Layer caching with go.mod first

### Stage 2: Runtime (alpine:3.18)
```dockerfile
FROM alpine:3.18

# Minimal runtime dependencies
RUN apk --no-cache add ca-certificates tzdata curl && \
    adduser -D -s /bin/sh -u 1001 appuser

WORKDIR /app

# Copy only the binary (multi-MB -> few MB)
COPY --from=builder /app/mvp-auth .
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Security: non-root user
USER appuser

# Health check integration
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1
```

## Docker Build Examples

### Development Build
```bash
# Basic build
docker build -t mvp-auth:dev .

# With version information
docker build \
  --build-arg VERSION=v1.0.0 \
  --build-arg COMMIT_SHA=$(git rev-parse HEAD) \
  --build-arg BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ") \
  -t mvp-auth:v1.0.0 \
  .
```

### Production Build
```bash
# Multi-platform build for production
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=$(git describe --tags --always) \
  --build-arg COMMIT_SHA=$(git rev-parse HEAD) \
  --build-arg BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ") \
  --push \
  -t registry.example.com/mvp-auth:latest \
  -t registry.example.com/mvp-auth:$(git describe --tags --always) \
  .
```

### Build Size Comparison
```bash
# Without multi-stage (full Go environment)
FROM golang:1.23-alpine
# ... copy source and build in place
# Result: ~300MB+ image

# With multi-stage (runtime only)
FROM golang:1.23-alpine AS builder  # Build stage
FROM alpine:3.18                    # Runtime stage  
# Result: ~20MB image
```

## Container Runtime Examples

### Basic Container Run
```bash
# Run container with health checks
docker run -d \
  --name mvp-auth \
  --health-cmd="curl -f http://localhost:8080/health || exit 1" \
  --health-interval=30s \
  --health-retries=3 \
  --health-start-period=10s \
  -p 8080:8080 \
  mvp-auth:latest
```

### Production Container Run
```bash
# Production run with observability
docker run -d \
  --name mvp-auth-prod \
  --restart=unless-stopped \
  --memory=512m \
  --cpus=1.0 \
  --user=1001:1001 \
  --read-only \
  --tmpfs /tmp \
  --tmpfs /app/logs \
  -p 8080:8080 \
  -p 9000:9000 \
  -e DATABASE_URL=postgres://user:pass@db:5432/mvp \
  -e REDIS_URL=redis://redis:6379 \
  -e ENVIRONMENT=production \
  mvp-auth:v1.0.0
```

### With Docker Compose Integration
```yaml
# docker-compose.yml integration
services:
  mvp-auth:
    build:
      context: .
      dockerfile: Dockerfile
      args:
        VERSION: ${VERSION:-dev}
        COMMIT_SHA: ${COMMIT_SHA:-unknown}
        BUILD_TIME: ${BUILD_TIME:-unknown}
    image: mvp-auth:${VERSION:-dev}
    container_name: mvp-auth
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 10s
```

## Build Performance Tips

### Optimize Build Speed
```bash
# Use BuildKit for faster builds
export DOCKER_BUILDKIT=1
docker build .

# Build with cache mount (experimental)
docker build --mount=type=cache,target=/root/.cache/go-build .

# Multi-stage cache
docker build --target builder -t mvp-auth:builder .
docker build --cache-from mvp-auth:builder .
```

### Layer Caching Strategy
```dockerfile
# ✅ Good: Dependencies first (changes less frequently)
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build

# ❌ Bad: Source code first (invalidates cache often)
COPY . .
RUN go mod download
RUN go build
```