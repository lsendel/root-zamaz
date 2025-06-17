# MVP Zero Trust Auth System Makefile
# Environment variables with defaults
DB_HOST ?= localhost
DB_PORT ?= 5432
DB_NAME ?= mvp_db
DB_USER ?= mvp_user
DB_PASSWORD ?= mvp_password
NATS_URL ?= nats://localhost:4222
REDIS_URL ?= redis://localhost:6379
COMPOSE_FILE ?= docker-compose.yml
ENV_FILE ?= .env

.PHONY: help dev-up dev-down build test clean logs deploy-local \
        build-frontend test-coverage check-coverage test-integration test-load \
        db-migrate certs-generate monitoring-setup dev-setup \
        lint fmt check-deps security-scan quality-check ci-build pre-commit \
        db-reset

# Default target
help: ## Show this help message
	@echo "MVP Zero Trust Auth System - Available targets:"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "Environment variables:"
	@echo "  DB_HOST=$(DB_HOST)"
	@echo "  DB_PORT=$(DB_PORT)"
	@echo "  DB_NAME=$(DB_NAME)"
	@echo "  DB_USER=$(DB_USER)"
	@echo "  NATS_URL=$(NATS_URL)"
	@echo "  REDIS_URL=$(REDIS_URL)"

# Development environment
dev-setup: ## Set up development environment dependencies
	@echo "🔧 Setting up development environment..."
	@if [ ! -f $(ENV_FILE) ]; then \
		echo "📝 Creating .env file from example..."; \
		cp .env.example $(ENV_FILE) || echo "⚠️  No .env.example found"; \
	fi
	@./scripts/setup-dev.sh || (echo "❌ Development setup failed" && exit 1)
	@echo "✅ Development environment setup complete"

dev-up: ## Start development environment with Docker Compose
	@echo "🚀 Starting development environment..."
	@docker-compose -f $(COMPOSE_FILE) --env-file $(ENV_FILE) up -d || (echo "❌ Failed to start services" && exit 1)
	@echo "✅ Development environment started"
	@echo "🔍 Services available at:"
	@echo "  - Grafana: http://localhost:3000 (admin/admin)"
	@echo "  - Prometheus: http://localhost:9090"
	@echo "  - Jaeger: http://localhost:16686"
	@echo "  - Envoy Admin: http://localhost:9901"

dev-down: ## Stop development environment
	@echo "🛑 Stopping development environment..."
	@docker-compose -f $(COMPOSE_FILE) down -v
	@echo "✅ Development environment stopped"

logs: ## Show logs from all services
	@docker-compose -f $(COMPOSE_FILE) logs -f

# Build targets
build: ## Build all services using build script
	@echo "🔨 Building all services..."
	@./scripts/build.sh || (echo "❌ Build failed" && exit 1)
	@echo "✅ Build completed successfully"

build-frontend: ## Build frontend application
	@echo "🔨 Building frontend..."
	@cd frontend && npm ci && npm run build || (echo "❌ Frontend build failed" && exit 1)
	@echo "✅ Frontend build completed"

# Test targets
test: ## Run all unit tests with race detection
	@echo "🧪 Running tests..."
	@go test -race -v ./... || (echo "❌ Tests failed" && exit 1)
	@echo "✅ All tests passed"

test-coverage: ## Run tests with coverage report
	@echo "🧪 Running tests with coverage..."
	@go test -race -coverprofile=coverage.out -covermode=atomic ./... || (echo "❌ Coverage tests failed" && exit 1)
	@go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report generated: coverage.html"

check-coverage: ## Check if coverage meets threshold
	@echo "📊 Checking coverage threshold..."
	@if [ ! -f coverage.out ]; then echo "❌ No coverage file found. Run 'make test-coverage' first" && exit 1; fi
	@coverage=$$(go tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	echo "Coverage: $$coverage%"; \
	if [ $$(echo "$$coverage < 80" | bc -l 2>/dev/null || echo "1") -eq 1 ]; then \
		echo "❌ Coverage $$coverage% is below 80% threshold"; \
		exit 1; \
	fi; \
	echo "✅ Coverage $$coverage% meets threshold"

test-integration: ## Run integration tests (requires services)
	@echo "🧪 Running integration tests..."
	@echo "📝 Starting test infrastructure..."
	@docker-compose -f docker-compose.test.yml up -d || (echo "❌ Failed to start test services" && exit 1)
	@sleep 5
	@go test -v ./tests/integration/... --timeout=60s || (echo "❌ Integration tests failed" && docker-compose -f docker-compose.test.yml down && exit 1)
	@docker-compose -f docker-compose.test.yml down
	@echo "✅ Integration tests completed"

test-load: ## Run load tests using k6
	@echo "🧪 Running load tests..."
	@command -v k6 >/dev/null 2>&1 || (echo "❌ k6 not installed. Install from https://k6.io/docs/getting-started/installation/" && exit 1)
	@k6 run tests/load/basic-load-test.js || (echo "❌ Load tests failed" && exit 1)
	@echo "✅ Load tests completed"

# Code quality targets
lint: ## Run linter on Go code
	@echo "🔍 Running linter..."
	@command -v golangci-lint >/dev/null 2>&1 || (echo "❌ golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest" && exit 1)
	@golangci-lint run || (echo "❌ Linting failed" && exit 1)
	@echo "✅ Linting completed"

fmt: ## Format Go code
	@echo "🎨 Formatting code..."
	@go fmt ./...
	@go mod tidy
	@echo "✅ Code formatting completed"

check-deps: ## Check for dependency vulnerabilities
	@echo "🔍 Checking dependencies for vulnerabilities..."
	@echo "Running govulncheck..."
	@command -v govulncheck >/dev/null 2>&1 || (echo "Installing govulncheck..." && go install golang.org/x/vuln/cmd/govulncheck@latest)
	@govulncheck ./... || (echo "❌ Vulnerability check failed" && exit 1)
	@echo "Running nancy for dependency scanning..."
	@go list -json -deps ./... | docker run --rm -i sonatypecorp/nancy:latest sleuth || (echo "❌ Nancy vulnerability check failed" && exit 1)
	@echo "✅ Dependency check completed"

security-scan: ## Run security scan on codebase
	@echo "🔒 Running security scan..."
	@command -v gosec >/dev/null 2>&1 || (echo "❌ gosec not installed. Run: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest" && exit 1)
	@gosec ./... || (echo "❌ Security scan failed" && exit 1)
	@echo "✅ Security scan completed"

# Clean up
clean: ## Clean up containers, volumes, and build artifacts
	@echo "🧹 Cleaning up..."
	@docker-compose -f $(COMPOSE_FILE) down -v --remove-orphans
	@docker-compose -f docker-compose.test.yml down -v --remove-orphans 2>/dev/null || true
	@docker system prune -f
	@docker volume prune -f
	@rm -f coverage.out coverage.html
	@echo "✅ Cleanup completed"

# Deployment
deploy-local: ## Deploy to local Kubernetes cluster
	@echo "🚀 Deploying to local Kubernetes..."
	@./scripts/deploy.sh || (echo "❌ Local deployment failed" && exit 1)
	@echo "✅ Local deployment completed"

# Database operations
db-migrate: ## Run database migrations
	@echo "📊 Running database migrations..."
	@docker-compose -f $(COMPOSE_FILE) exec postgres psql -U $(DB_USER) -d $(DB_NAME) -f /docker-entrypoint-initdb.d/migrations.sql || (echo "❌ Migration failed" && exit 1)
	@echo "✅ Database migrations completed"

db-reset: ## Reset database to clean state
	@echo "🔄 Resetting database..."
	@docker-compose -f $(COMPOSE_FILE) down postgres
	@docker volume rm $$(docker volume ls -q | grep postgres) 2>/dev/null || true
	@docker-compose -f $(COMPOSE_FILE) up -d postgres
	@echo "✅ Database reset completed"

# Certificate operations
certs-generate: ## Generate development certificates
	@echo "🔐 Generating development certificates..."
	@./scripts/generate-certs.sh || (echo "❌ Certificate generation failed" && exit 1)
	@echo "✅ Certificates generated"

# Monitoring
monitoring-setup: ## Set up monitoring dashboards
	@echo "📊 Setting up monitoring dashboards..."
	@./scripts/setup-monitoring.sh || (echo "❌ Monitoring setup failed" && exit 1)
	@echo "✅ Monitoring setup completed"

# Quality gates
quality-check: ## Run all quality checks (coverage, lint, security)
	@echo "🔍 Running comprehensive quality checks..."
	@$(MAKE) test-coverage
	@$(MAKE) check-coverage
	@$(MAKE) lint
	@$(MAKE) check-deps
	@$(MAKE) security-scan
	@echo "✅ All quality checks passed"

ci-build: ## Complete CI build pipeline
	@echo "🏗️ Running CI build pipeline..."
	@$(MAKE) fmt
	@$(MAKE) quality-check
	@$(MAKE) build
	@echo "✅ CI build pipeline completed"

pre-commit: ## Run pre-commit checks
	@echo "🔄 Running pre-commit checks..."
	@$(MAKE) fmt
	@$(MAKE) lint
	@$(MAKE) test
	@echo "✅ Pre-commit checks completed"
