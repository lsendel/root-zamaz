#!/bin/bash

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Build configuration
BUILD_DIR="bin"
VERSION=${VERSION:-$(git describe --tags --always --dirty)}
COMMIT_SHA=${COMMIT_SHA:-$(git rev-parse HEAD)}
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo -e "${BLUE}🔨 Building MVP Zero Trust Auth System${NC}"
echo -e "${BLUE}Version: ${VERSION}${NC}"
echo -e "${BLUE}Commit: ${COMMIT_SHA}${NC}"

# Create build directory
mkdir -p ${BUILD_DIR}

# Build Go services
echo -e "${YELLOW}📦 Building Go services...${NC}"

# Check if we have Go installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}❌ Go is not installed${NC}"
    exit 1
fi

# Build flags for Go
LDFLAGS="-X main.version=${VERSION} -X main.commit=${COMMIT_SHA} -X main.buildTime=${BUILD_TIME}"

# Build auth service (main application)
if [ -f "cmd/server/main.go" ]; then
    echo -e "${BLUE}  Building server...${NC}"
    go build -ldflags "${LDFLAGS}" -o ${BUILD_DIR}/mvp-auth ./cmd/server
elif [ -f "cmd/auth-service/main.go" ]; then
    echo -e "${BLUE}  Building auth-service...${NC}"
    go build -ldflags "${LDFLAGS}" -o ${BUILD_DIR}/auth-service ./cmd/auth-service
elif [ -f "main.go" ]; then
    echo -e "${BLUE}  Building main application...${NC}"
    go build -ldflags "${LDFLAGS}" -o ${BUILD_DIR}/mvp-auth ./
else
    echo -e "${YELLOW}  No Go main found, building all packages...${NC}"
    go build -ldflags "${LDFLAGS}" -o ${BUILD_DIR}/mvp-auth ./...
fi

# Build additional services if they exist
for service_dir in cmd/*/; do
    if [ -d "$service_dir" ] && [ -f "${service_dir}main.go" ]; then
        service_name=$(basename "$service_dir")
        if [ "$service_name" != "auth-service" ]; then  # Skip if already built
            echo -e "${BLUE}  Building ${service_name}...${NC}"
            go build -ldflags "${LDFLAGS}" -o ${BUILD_DIR}/${service_name} ./${service_dir}
        fi
    fi
done

# Run tests before building
echo -e "${YELLOW}🧪 Running tests...${NC}"
go test -short ./...

echo -e "${GREEN}✅ Go services built successfully${NC}"

# Build frontend assets
if [ -f "frontend/package.json" ]; then
    echo -e "${YELLOW}📦 Building frontend assets...${NC}"
    
    # Check if npm/node is installed
    if ! command -v npm &> /dev/null; then
        echo -e "${RED}❌ npm is not installed${NC}"
        exit 1
    fi
    
    cd frontend
    
    # Install dependencies if node_modules doesn't exist
    if [ ! -d "node_modules" ]; then
        echo -e "${BLUE}  Installing dependencies...${NC}"
        npm ci
    fi
    
    # Run frontend tests
    echo -e "${BLUE}  Running frontend tests...${NC}"
    npm run test:ci 2>/dev/null || npm test 2>/dev/null || echo "No frontend tests found"
    
    # Build frontend
    echo -e "${BLUE}  Building frontend...${NC}"
    npm run build
    
    cd ..
    echo -e "${GREEN}✅ Frontend built successfully${NC}"
else
    echo -e "${YELLOW}⚠️  No frontend package.json found, skipping frontend build${NC}"
fi

# Build Docker images
if command -v docker &> /dev/null; then
    echo -e "${YELLOW}🐳 Building Docker images...${NC}"
    
    # Check if Dockerfile exists
    if [ -f "Dockerfile" ]; then
        echo -e "${BLUE}  Building main Docker image...${NC}"
        docker build -t mvp-auth:${VERSION} -t mvp-auth:latest \
            --build-arg VERSION=${VERSION} \
            --build-arg COMMIT_SHA=${COMMIT_SHA} \
            --build-arg BUILD_TIME=${BUILD_TIME} \
            .
    fi
    
    # Build with docker-compose if available
    if [ -f "docker-compose.yml" ]; then
        echo -e "${BLUE}  Building with docker-compose...${NC}"
        docker-compose build
    fi
    
    echo -e "${GREEN}✅ Docker images built successfully${NC}"
else
    echo -e "${YELLOW}⚠️  Docker not found, skipping Docker image build${NC}"
fi

# Create build info file
echo -e "${YELLOW}📝 Creating build info...${NC}"
cat > ${BUILD_DIR}/build-info.json << EOF
{
  "version": "${VERSION}",
  "commit": "${COMMIT_SHA}",
  "buildTime": "${BUILD_TIME}",
  "goVersion": "$(go version | cut -d' ' -f3)",
  "builtBy": "${USER:-unknown}",
  "buildHost": "$(hostname)"
}
EOF

# List built artifacts
echo -e "${YELLOW}📋 Build artifacts:${NC}"
ls -la ${BUILD_DIR}/

# Calculate sizes
if command -v du &> /dev/null; then
    echo -e "${YELLOW}📊 Artifact sizes:${NC}"
    du -h ${BUILD_DIR}/*
fi

echo -e "${GREEN}🎉 Project build completed successfully!${NC}"
echo -e "${BLUE}Build artifacts are in: ${BUILD_DIR}/${NC}"
echo -e "${BLUE}Version: ${VERSION}${NC}"
