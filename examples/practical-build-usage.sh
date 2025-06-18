#!/bin/bash
# Practical Build Usage Examples

echo "=== MVP Zero Trust Auth Build Examples ==="

# 1. Quick Development Build
echo "1. Quick development build:"
echo "make build-server"
echo "# Creates: bin/server"
echo ""

# 2. Full Build Pipeline  
echo "2. Full build pipeline:"
echo "make build"
echo "# - Runs tests"
echo "# - Builds Go services"  
echo "# - Builds frontend"
echo "# - Creates Docker images"
echo "# - Generates build-info.json"
echo ""

# 3. Build and Test
echo "3. Build with immediate testing:"
echo "make build && make test"
echo ""

# 4. Clean Build
echo "4. Clean build (remove old artifacts):"
echo "rm -rf bin/ frontend/dist/ && make build"
echo ""

# 5. Version-specific Build
echo "5. Version-specific build:"
echo "VERSION=v1.2.3 make build"
echo "# Overrides git-detected version"
echo ""

# 6. Production Build
echo "6. Production build process:"
echo "git tag v1.0.0"
echo "make clean"
echo "make build"
echo "# Results in version v1.0.0 binary"
echo ""

# 7. Cross-platform Build
echo "7. Cross-platform builds:"
echo "# Linux"
echo "GOOS=linux GOARCH=amd64 go build -o bin/mvp-auth-linux ./cmd/server"
echo ""
echo "# Windows"  
echo "GOOS=windows GOARCH=amd64 go build -o bin/mvp-auth-windows.exe ./cmd/server"
echo ""
echo "# macOS ARM"
echo "GOOS=darwin GOARCH=arm64 go build -o bin/mvp-auth-darwin-arm64 ./cmd/server"
echo ""

# 8. Docker Builds
echo "8. Docker build variations:"
echo "# Development"
echo "docker build -t mvp-auth:dev ."
echo ""
echo "# Production with version"
echo "docker build --build-arg VERSION=v1.0.0 --build-arg COMMIT_SHA=\$(git rev-parse HEAD) -t mvp-auth:v1.0.0 ."
echo ""
echo "# Multi-platform"
echo "docker buildx build --platform linux/amd64,linux/arm64 -t mvp-auth:latest ."
echo ""

# 9. CI/CD Build
echo "9. CI/CD pipeline build:"
echo "make ci-build"
echo "# - Formats code"
echo "# - Runs quality checks"  
echo "# - Runs security scans"
echo "# - Builds all artifacts"
echo ""

# 10. Debugging Build Issues
echo "10. Debug build issues:"
echo "# Verbose Go build"
echo "go build -v -x -o bin/server ./cmd/server"
echo ""
echo "# Check dependencies"
echo "go mod tidy && go mod verify"
echo ""
echo "# Build without cache"
echo "go clean -cache && make build-server"
echo ""

# 11. Performance Optimized Build
echo "11. Performance optimized builds:"
echo "# Smaller binary"
echo "go build -ldflags='-s -w' -o bin/server-small ./cmd/server"
echo ""
echo "# Static binary"
echo "CGO_ENABLED=0 go build -a -ldflags='-extldflags \"-static\"' -o bin/server-static ./cmd/server"
echo ""

# 12. Build Information
echo "12. View build information:"
echo "# Check binary info"
echo "go version -m bin/server"
echo ""
echo "# Runtime version"
echo "./bin/server --version"
echo ""
echo "# Build metadata"
echo "cat bin/build-info.json | jq ."
echo ""

echo "=== Build Examples Complete ==="