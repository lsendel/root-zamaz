# Development Setup Guide

This guide will help you set up a complete development environment for the Zero Trust Auth MVP.

## 🛠️ Prerequisites

### Required Software

| Tool | Version | Purpose |
|------|---------|---------|
| **Go** | 1.23+ | Backend development |
| **Node.js** | 18+ | Frontend development |
| **Docker** | 20+ | Container orchestration |
| **Docker Compose** | 2.0+ | Development services |
| **Make** | Latest | Build automation |
| **Git** | Latest | Version control |

### Optional but Recommended

| Tool | Purpose |
|------|---------|
| **VS Code** | IDE with Go/TypeScript support |
| **Postman** | API testing |
| **k6** | Load testing |
| **kubectl** | Kubernetes management |
| **helm** | Kubernetes package management |

## 🚀 Quick Setup

### 1. Clone Repository

```bash
# Clone the repository
git clone <repository-url>
cd root-zamaz

# Verify you're in the right directory
ls -la
# Should see: Makefile, docker-compose.yml, go.mod, frontend/, etc.
```

### 2. Verify Prerequisites

```bash
# Check Go version
go version
# Expected: go version go1.23.x

# Check Node.js version
node --version
# Expected: v18.x.x or higher

# Check Docker
docker --version
# Expected: Docker version 20.x.x

# Check Docker Compose
docker-compose --version
# Expected: Docker Compose version 2.x.x

# Check Make
make --version
# Expected: GNU Make 3.81 or higher
```

### 3. Initial Setup

```bash
# Run initial setup
make dev-setup

# This will:
# - Create .env file if it doesn't exist
# - Install frontend dependencies
# - Generate development certificates
# - Set up Git hooks (if configured)
```

### 4. Start Development Environment

```bash
# Start all infrastructure services
make dev-up

# Wait for services to be ready (about 2-3 minutes)
# You should see output indicating services are starting

# In another terminal, start the frontend
make dev-frontend

# Or start everything at once
make dev-all
```

### 5. Verify Installation

```bash
# Check all services are running
docker ps

# Test backend API
curl http://localhost:8080/health

# Open frontend in browser
open http://localhost:5175

# Test login with default credentials
# Username: admin
# Password: password
```

## 📁 Project Structure

```
root-zamaz/
├── 📁 cmd/                    # Application entry points
│   └── server/               # Main server application
│       └── main.go          # Server entry point
├── 📁 pkg/                   # Core packages (reusable)
│   ├── auth/                # Authentication & authorization
│   ├── config/              # Configuration management
│   ├── database/            # Database layer
│   ├── handlers/            # HTTP handlers
│   ├── middleware/          # HTTP middleware
│   ├── models/              # Data models
│   ├── observability/       # Metrics, tracing, logging
│   └── testutil/            # Testing utilities
├── 📁 frontend/              # React TypeScript SPA
│   ├── src/                 # Source code
│   ├── tests/               # Frontend tests
│   ├── public/              # Static assets
│   └── dist/                # Built assets (generated)
├── 📁 deployments/           # Deployment configurations
│   ├── kubernetes/          # K8s manifests
│   ├── helm/                # Helm charts
│   └── spire/               # SPIRE configurations
├── 📁 envoy/                 # Envoy proxy configuration
│   ├── configs/             # Envoy YAML configs
│   └── certs/               # TLS certificates
├── 📁 observability/         # Monitoring configurations
│   ├── prometheus/          # Prometheus config
│   ├── grafana/             # Grafana dashboards
│   └── jaeger/              # Jaeger config
├── 📁 scripts/               # Build and utility scripts
├── 📁 tests/                 # Integration and E2E tests
├── 📁 docs/                  # Documentation
├── 📁 examples/              # Example configurations
├── Makefile                  # Build automation
├── docker-compose.yml       # Development services
├── go.mod                   # Go module definition
└── README.md                # Project overview
```

## 🔧 Development Tools Setup

### VS Code Configuration

Install recommended extensions:

```bash
# Install VS Code extensions
code --install-extension golang.go
code --install-extension bradlc.vscode-tailwindcss
code --install-extension esbenp.prettier-vscode
code --install-extension ms-vscode.vscode-typescript-next
code --install-extension ms-vscode.vscode-eslint
```

Create `.vscode/settings.json`:

```json
{
  "go.toolsManagement.checkForUpdates": "local",
  "go.useLanguageServer": true,
  "go.formatTool": "goimports",
  "go.lintTool": "golangci-lint",
  "go.testFlags": ["-v", "-race"],
  "go.coverOnSave": true,
  "go.coverageDecorator": {
    "type": "gutter",
    "coveredHighlightColor": "rgba(64,128,64,0.5)",
    "uncoveredHighlightColor": "rgba(128,64,64,0.25)"
  },
  "typescript.preferences.importModuleSpecifier": "relative",
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true,
    "source.organizeImports": true
  }
}
```

Create `.vscode/launch.json` for debugging:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Launch Server",
      "type": "go",
      "request": "launch",
      "mode": "auto",
      "program": "./cmd/server",
      "env": {
        "DATABASE_URL": "postgres://mvp_user:mvp_password@localhost:5432/mvp_db?sslmode=disable",
        "REDIS_URL": "redis://localhost:6379",
        "JWT_SECRET": "development-secret-key",
        "LOG_LEVEL": "debug"
      },
      "args": []
    },
    {
      "name": "Run Tests",
      "type": "go",
      "request": "launch",
      "mode": "test",
      "program": "${workspaceFolder}",
      "args": ["-v"]
    }
  ]
}
```

### Git Configuration

```bash
# Configure Git hooks (optional)
git config core.hooksPath .githooks

# Set up pre-commit hooks
cat > .githooks/pre-commit << 'EOF'
#!/bin/bash
set -e

echo "Running pre-commit checks..."

# Format Go code
echo "🎨 Formatting Go code..."
make fmt

# Lint Go code
echo "🔍 Linting Go code..."
make lint

# Run tests
echo "🧪 Running tests..."
make test

# Format frontend code
echo "🎨 Formatting frontend code..."
cd frontend && npm run format && cd ..

# Lint frontend code
echo "🔍 Linting frontend code..."
cd frontend && npm run lint && cd ..

echo "✅ Pre-commit checks passed!"
EOF

chmod +x .githooks/pre-commit
```

## 🗄️ Database Setup

### Local Database (Docker)

The development environment uses PostgreSQL in Docker:

```bash
# Database is automatically started with make dev-up
# Connection details:
# Host: localhost
# Port: 5432
# Database: mvp_db
# Username: mvp_user
# Password: mvp_password
```

### Manual Database Setup (Optional)

If you prefer a local PostgreSQL installation:

```bash
# Install PostgreSQL (macOS)
brew install postgresql@15
brew services start postgresql@15

# Create database and user
createuser -s mvp_user
createdb -O mvp_user mvp_db

# Set password
psql -d mvp_db -c "ALTER USER mvp_user WITH PASSWORD 'mvp_password';"

# Run migrations
make db-migrate
```

### Database Management

```bash
# Connect to database
docker exec -it mvp-zero-trust-auth-postgres-1 psql -U mvp_user -d mvp_db

# Reset database
make db-reset

# Run migrations
make db-migrate

# View database logs
docker logs mvp-zero-trust-auth-postgres-1
```

## 🎯 Environment Configuration

### Environment Variables

Create `.env` file (automatically created by `make dev-setup`):

```bash
# Database
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=mvp_db
DATABASE_USER=mvp_user
DATABASE_PASSWORD=mvp_password
DATABASE_SSL_MODE=disable

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DATABASE=0

# JWT
JWT_SECRET=development-secret-key-change-in-production
JWT_ACCESS_TOKEN_EXPIRATION=24h
JWT_REFRESH_TOKEN_EXPIRATION=7d

# Server
HTTP_HOST=localhost
HTTP_PORT=8080
HTTP_READ_TIMEOUT=30s
HTTP_WRITE_TIMEOUT=30s

# Observability
JAEGER_ENDPOINT=http://localhost:14268/api/traces
PROMETHEUS_PORT=9000
LOG_LEVEL=debug
LOG_FORMAT=json

# Development
ENVIRONMENT=development
DISABLE_AUTH=false
CORS_ALLOWED_ORIGINS=http://localhost:5175
```

### Configuration Files

#### Go Configuration (`pkg/config/config.go`)

The application uses a hierarchical configuration system:

1. Default values
2. Environment variables
3. Configuration files
4. Command-line flags

#### Frontend Configuration (`frontend/vite.config.ts`)

```typescript
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5175,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
  },
});
```

## 🧪 Testing Setup

### Backend Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run integration tests (requires services)
make test-integration

# Run specific test
go test -v ./pkg/auth/...

# Run tests with race detection
go test -race ./...

# Run benchmarks
go test -bench=. ./pkg/...
```

### Frontend Testing

```bash
cd frontend

# Install dependencies
npm install

# Run unit tests
npm test

# Run tests in watch mode
npm run test:watch

# Run E2E tests
npm run test:e2e

# Generate coverage report
npm run test:coverage
```

### Integration Testing

```bash
# Start test environment
make test-integration

# This will:
# - Start Docker Compose test services
# - Run integration tests
# - Clean up test environment
```

## 🔄 Development Workflow

### Daily Development

```bash
# 1. Start development environment
make dev-up

# 2. Start frontend (in separate terminal)
make dev-frontend

# 3. Make changes to code

# 4. Run tests frequently
make test

# 5. Check code quality
make lint
make fmt

# 6. Commit changes
git add .
git commit -m "feat: add new feature"

# 7. Push changes
git push origin feature-branch
```

### Adding New Features

```bash
# 1. Create feature branch
git checkout -b feature/new-feature

# 2. Add your code changes

# 3. Add tests
# - Unit tests in *_test.go files
# - Integration tests in tests/integration/
# - E2E tests in frontend/tests/e2e/

# 4. Update documentation

# 5. Run quality checks
make quality-check

# 6. Commit and push
git add .
git commit -m "feat: implement new feature"
git push origin feature/new-feature
```

### Debugging

#### Backend Debugging

```bash
# Enable debug logging
export LOG_LEVEL=debug
make run-server

# Or with VS Code debugger
# Set breakpoints and press F5

# View detailed logs
docker logs mvp-zero-trust-auth-envoy-1 --follow
```

#### Frontend Debugging

```bash
# Start development server
cd frontend
npm run dev

# Browser debugging:
# 1. Open browser dev tools
# 2. Use React DevTools extension
# 3. Check console for errors
# 4. Use debugger; statements
```

#### Database Debugging

```bash
# Connect to database
docker exec -it mvp-zero-trust-auth-postgres-1 psql -U mvp_user -d mvp_db

# View queries
export DB_LOG_LEVEL=debug

# Check database logs
docker logs mvp-zero-trust-auth-postgres-1
```

## 🛠️ Common Tasks

### Building

```bash
# Build backend only
make build-server

# Build everything (backend + frontend + Docker)
make build

# Build frontend only
make build-frontend

# Clean build artifacts
make clean
```

### Code Quality

```bash
# Format code
make fmt

# Lint code
make lint

# Security scan
make security-scan

# All quality checks
make quality-check
```

### Dependencies

```bash
# Update Go dependencies
go mod tidy
go mod download

# Update frontend dependencies
cd frontend
npm update
npm audit fix

# Check for vulnerabilities
make check-deps
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Port Already in Use
```bash
# Find process using port
lsof -i :8080

# Kill process
kill -9 <PID>

# Or use different port
export HTTP_PORT=8081
```

#### 2. Docker Issues
```bash
# Restart Docker
make dev-down
make dev-up

# Clean Docker cache
docker system prune -f

# Reset everything
make clean
```

#### 3. Database Connection Issues
```bash
# Check database is running
docker ps | grep postgres

# Check connectivity
pg_isready -h localhost -p 5432

# Reset database
make db-reset
```

#### 4. Frontend Build Issues
```bash
cd frontend

# Clear cache
rm -rf node_modules package-lock.json
npm install

# Reset build
rm -rf dist
npm run build
```

### Getting Help

#### Check System Status
```bash
# Check all services
make dev-up
docker ps

# Check logs
make logs

# Check resource usage
docker stats
```

#### Reset Environment
```bash
# Complete reset
make clean
make dev-setup
make dev-up
```

## 📚 Next Steps

After completing the setup:

1. **Explore the API**: Visit http://localhost:8080/swagger/index.html
2. **Check the Frontend**: Open http://localhost:5175
3. **View Monitoring**: Check Grafana at http://localhost:3000
4. **Read the Code**: Start with `cmd/server/main.go`
5. **Run Tests**: Execute `make test` to ensure everything works
6. **Make Changes**: Try modifying a handler or adding a new endpoint

## 🤝 Contributing

Ready to contribute? Check out:

- [Contributing Guidelines](contributing.md)
- [Code Style Guide](code-style.md)
- [Testing Guide](testing.md)
- [API Documentation](../api/README.md)