# Build System Examples

## Simple Build (build-server)

The `make build-server` target provides the fastest way to build just the Go server:

```bash
# Basic server build
make build-server

# Equivalent direct command
go build -o bin/server ./cmd/server
```

**What it does:**
1. Compiles `cmd/server/main.go` 
2. Creates `bin/server` executable
3. No tests, no dependencies check
4. Fast iteration for development

**Output:**
```
🔨 Building authentication server...
✅ Server build completed
```

## Comprehensive Build (build)

The `make build` target runs the full build script:

```bash
# Full build process
make build

# Direct script execution
./scripts/build.sh
```

**What it does:**
1. **Version Detection** - Git tags, commit SHA, build time
2. **Go Service Build** - With version injection
3. **Testing** - Runs all unit tests
4. **Frontend Build** - npm ci + npm run build
5. **Docker Images** - Multi-stage builds
6. **Build Artifacts** - Creates build-info.json

## Build with Run

```bash
# Build and immediately start server
make run-server

# Equivalent to:
make build-server && ./bin/server
```

## Manual Build Examples

### Direct Go Build
```bash
# Basic build
go build -o bin/mvp-auth ./cmd/server

# With version info
VERSION=$(git describe --tags --always --dirty)
COMMIT=$(git rev-parse HEAD)
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

go build -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILD_TIME}" -o bin/mvp-auth ./cmd/server
```

### Cross-platform builds
```bash
# Linux build
GOOS=linux GOARCH=amd64 go build -o bin/mvp-auth-linux ./cmd/server

# Windows build  
GOOS=windows GOARCH=amd64 go build -o bin/mvp-auth-windows.exe ./cmd/server

# macOS ARM build
GOOS=darwin GOARCH=arm64 go build -o bin/mvp-auth-darwin-arm64 ./cmd/server
```