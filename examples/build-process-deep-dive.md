# Build Process Deep Dive

## Build Script Flow (`scripts/build.sh`)

### Phase 1: Environment Setup
```bash
# Version detection from Git
VERSION=${VERSION:-$(git describe --tags --always --dirty)}
COMMIT_SHA=${COMMIT_SHA:-$(git rev-parse HEAD)}
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Example output:
# Version: v1.0.0-dirty
# Commit: 4363a0e1234567890abcdef
# Build Time: 2024-01-15T10:30:45Z
```

### Phase 2: Go Service Compilation
```bash
# LDFLAGS injection for runtime version info
LDFLAGS="-X main.version=${VERSION} -X main.commit=${COMMIT_SHA} -X main.buildTime=${BUILD_TIME}"

# Build process with fallback discovery
if [ -f "cmd/server/main.go" ]; then
    go build -ldflags "${LDFLAGS}" -o bin/mvp-auth ./cmd/server
elif [ -f "cmd/auth-service/main.go" ]; then
    go build -ldflags "${LDFLAGS}" -o bin/auth-service ./cmd/auth-service
else
    # Fallback to build all
    go build -ldflags "${LDFLAGS}" -o bin/mvp-auth ./...
fi
```

### Phase 3: Service Discovery & Multi-service Build
```bash
# Automatic service discovery
for service_dir in cmd/*/; do
    if [ -d "$service_dir" ] && [ -f "${service_dir}main.go" ]; then
        service_name=$(basename "$service_dir")
        echo "Building ${service_name}..."
        go build -ldflags "${LDFLAGS}" -o bin/${service_name} ./${service_dir}
    fi
done
```

### Phase 4: Quality Assurance
```bash
# Run tests before considering build successful
go test -short ./...

# Frontend testing (if available)
if [ -f "frontend/package.json" ]; then
    cd frontend
    npm run test:ci 2>/dev/null || npm test 2>/dev/null || echo "No frontend tests found"
    cd ..
fi
```

### Phase 5: Asset Building
```bash
# Frontend asset compilation
if [ -f "frontend/package.json" ]; then
    cd frontend
    
    # Install deps if needed
    if [ ! -d "node_modules" ]; then
        npm ci
    fi
    
    # Build production assets
    npm run build
    cd ..
fi
```

### Phase 6: Container Image Building
```bash
# Docker image building (if Docker available)
if command -v docker &> /dev/null; then
    # Single Dockerfile build
    if [ -f "Dockerfile" ]; then
        docker build -t mvp-auth:${VERSION} -t mvp-auth:latest \
            --build-arg VERSION=${VERSION} \
            --build-arg COMMIT_SHA=${COMMIT_SHA} \
            --build-arg BUILD_TIME=${BUILD_TIME} \
            .
    fi
    
    # Docker Compose build
    if [ -f "docker-compose.yml" ]; then
        docker-compose build
    fi
fi
```

### Phase 7: Build Metadata
```bash
# Create build information file
cat > bin/build-info.json << EOF
{
  "version": "${VERSION}",
  "commit": "${COMMIT_SHA}",
  "buildTime": "${BUILD_TIME}",
  "goVersion": "$(go version | cut -d' ' -f3)",
  "builtBy": "${USER:-unknown}",
  "buildHost": "$(hostname)"
}
EOF
```

## Build Outputs

### Binary Artifacts
```
bin/
├── mvp-auth              # Main server binary
├── build-info.json       # Build metadata
└── [service-name]        # Additional services (if any)
```

### Frontend Artifacts (if built)
```
frontend/dist/
├── index.html            # Main SPA entry point
├── assets/
│   ├── index-[hash].js   # Main JS bundle
│   ├── index-[hash].css  # Main CSS bundle
│   └── [asset-files]     # Static assets
└── [other-files]         # PWA manifests, etc.
```

### Docker Images
```
mvp-auth:latest          # Latest tag
mvp-auth:v1.0.0         # Version tag
mvp-auth:[commit-sha]   # Commit-specific tag
```

## Runtime Version Information

The build process injects version information accessible at runtime:

```go
// In main.go, these variables are set by LDFLAGS
var (
    version   = "dev"
    commit    = "unknown" 
    buildTime = "unknown"
)

// Usage in application
func main() {
    log.Printf("Starting MVP Auth System v%s (commit: %s, built: %s)", 
        version, commit, buildTime)
}

// Available via API endpoint
func versionHandler(c *fiber.Ctx) error {
    return c.JSON(fiber.Map{
        "version":   version,
        "commit":    commit,
        "buildTime": buildTime,
    })
}
```