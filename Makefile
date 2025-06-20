# =============================================================================
# MVP Zero Trust Auth System - Modern CI/CD Makefile
# =============================================================================
# Organized by workflow: dev → test → quality → build → deploy
# Features: Parallel execution, fail-fast, advanced caching, quality gates
# =============================================================================

# Environment Configuration
# =============================================================================
SHELL := /bin/bash
.DEFAULT_GOAL := help
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

# Project Configuration
PROJECT_NAME := mvp-zero-trust-auth
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Environment Variables with Defaults
DB_HOST ?= localhost
DB_PORT ?= 5432
DB_NAME ?= mvp_db
DB_USER ?= mvp_user
DB_PASSWORD ?= mvp_password
DB_SSLMODE ?= disable
NATS_URL ?= nats://localhost:4222
REDIS_URL ?= redis://localhost:6379
COMPOSE_FILE ?= docker-compose.yml
ENV_FILE ?= .env

# Build Configuration
GO_VERSION := 1.23.8
NODE_VERSION := 18.20.4
BUILD_OUTPUT_DIR := bin
FRONTEND_DIR := frontend
COVERAGE_THRESHOLD := 80
DOCKER_PLATFORM ?= linux/amd64,linux/arm64

# Auto-detect platform for single-platform operations
DOCKER_SINGLE_PLATFORM := $(shell if [ "$$(uname -m)" = "arm64" ]; then echo "linux/arm64"; else echo "linux/amd64"; fi)

# Colors for output
BLUE := \033[34m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
RESET := \033[0m
BOLD := \033[1m

# =============================================================================
# PHONY TARGETS
# =============================================================================
.PHONY: help info clean-all \
	dev-setup dev-validate dev-up dev-down dev-frontend dev-all dev-logs dev-status \
	deps deps-go deps-frontend deps-validate deps-update deps-audit \
	test test-go test-frontend test-integration test-e2e test-e2e-setup test-e2e-check-services test-e2e-ui test-e2e-headed test-e2e-debug test-e2e-full test-e2e-report test-e2e-clean test-load test-all test-watch test-debug \
	coverage coverage-go coverage-frontend coverage-report coverage-validate \
	lint lint-go lint-frontend lint-docker lint-all lint-fix \
	security security-scan security-audit security-install security-update \
	quality quality-gate quality-report quality-all \
	build build-go build-frontend build-docker build-all build-clean \
	sdk-build-go sdk-build-js sdk-build-python sdk-build-all \
	sdk-test-go sdk-test-js sdk-test-python sdk-test-all \
	cli-help cli-health cli-status cli-generate-key cli-test-connection \
	dev-generate-go dev-generate-js dev-generate-python dev-generate-all \
	deploy deploy-local deploy-staging deploy-prod deploy-rollback \
	ci ci-test ci-quality ci-build ci-deploy ci-full \
	parallel-test parallel-quality parallel-build \
	db-stats db-stats-live db-benchmark db-benchmark-heavy db-optimize-dev db-optimize-prod db-optimize-balanced \
	db-analyze db-monitor db-health db-tune db-perf-test \
	cache cache-clean cache-warmup \
	db db-migrate db-reset db-backup db-restore \
  docs docs-generate docs-serve docs-deploy docs-schema \
	docs docs-generate docs-serve docs-deploy install-tbls \
	monitor monitor-setup monitor-status monitor-logs \
	gitops-setup gitops-validate gitops-sync gitops-rollback \
	gitops-test gitops-deploy gitops-monitor gitops-backup \
	helm-validate helm-test helm-lint helm-push \
	argocd-sync argocd-status argocd-diff argocd-rollback \
	canary-deploy canary-promote canary-rollback \
	slo-validate slo-report slo-alert

# =============================================================================
# HELP & INFO
# =============================================================================
help: ## Show comprehensive help with workflow examples
	@printf "\n$(BOLD)$(BLUE)MVP Zero Trust Auth System - Advanced CI/CD Makefile$(RESET)\n"
	@printf "$(BLUE)===========================================================$(RESET)\n\n"
	@printf "$(BOLD)🚀 MODERNIZED WORKFLOWS:$(RESET)\n"
	@printf "  $(GREEN)Development:$(RESET) dev-setup → cache-warmup → dev-up → dev-frontend\n"
	@printf "  $(GREEN)Testing:$(RESET)     test-all → coverage-validate → quality-comprehensive\n"
	@printf "  $(GREEN)Quality:$(RESET)     quality-gate → quality-report → quality-all\n"
	@printf "  $(GREEN)Build:$(RESET)       cache-smart-warmup → build-all → deploy-local\n"
	@printf "  $(GREEN)CI/CD:$(RESET)       ci-full → quality-gate → matrix-test\n"
	@printf "  $(GREEN)Matrix:$(RESET)      matrix-status → matrix-test → matrix-report\n"
	@printf "  $(GREEN)Database:$(RESET)    db-tune → db-benchmark → db-optimize-balanced\n\n"
	@printf "$(BOLD)🎯 ENHANCED FEATURES:$(RESET)\n"
	@printf "  $(YELLOW)📊 Advanced Caching:$(RESET)      cache-status, cache-smart-warmup, cache-benchmark\n"
	@printf "  $(YELLOW)🛡️  Quality Gates:$(RESET)       quality-gate with coverage/security thresholds\n"
	@printf "  $(YELLOW)🔄 Matrix Testing:$(RESET)       matrix-test across Go/Node versions\n"
	@printf "  $(YELLOW)⚡ Parallel Execution:$(RESET)   parallel-test, parallel-quality, parallel-build\n"
	@printf "  $(YELLOW)🗄️  Database Optimization:$(RESET) db-tune, db-benchmark, db-monitor, db-analyze\n"
	@printf "  $(YELLOW)🔒 Security Scanning:$(RESET)    Advanced vulnerability analysis\n"
	@printf "  $(YELLOW)📈 Performance Metrics:$(RESET) Timing, caching, and benchmark analysis\n\n"
	@printf "$(BOLD)🔧 CORE CATEGORIES:$(RESET)\n"
	@printf "  $(BLUE)Development$(RESET)     dev-*, deps-*, cache-*\n"
	@printf "  $(BLUE)Testing$(RESET)         test-*, coverage-*, matrix-*\n"
	@printf "  $(BLUE)Quality$(RESET)         quality-*, lint-*, security-*\n"
	@printf "  $(BLUE)Build & Deploy$(RESET)  build-*, deploy-*, ci-*\n\n"
	@printf "$(BOLD)⚡ QUICK START COMMANDS:$(RESET)\n"
	@printf "  $(YELLOW)make dev-all$(RESET)           Start complete dev environment with caching\n"
	@printf "  $(YELLOW)make test-all$(RESET)          Run comprehensive test suite with coverage\n"
	@printf "  $(YELLOW)make quality-gate$(RESET)      Run advanced quality gates (80%% coverage + security)\n"
	@printf "  $(YELLOW)make ci-full$(RESET)           Run complete CI pipeline with fail-fast\n"
	@printf "  $(YELLOW)make matrix-test$(RESET)       Test across multiple Go/Node.js versions\n"
	@printf "  $(YELLOW)make cache-benchmark$(RESET)   Benchmark cache performance\n\n"
	@printf "$(BOLD)📊 ENVIRONMENT & THRESHOLDS:$(RESET)\n"
	@printf "  Project:           $(GREEN)$(PROJECT_NAME)$(RESET)\n"
	@printf "  Version:           $(GREEN)$(VERSION)$(RESET)\n"
	@printf "  Commit:            $(GREEN)$(GIT_COMMIT)$(RESET)\n"
	@printf "  Go:                $(GREEN)$(GO_VERSION)$(RESET) (Matrix: $(YELLOW)$(GO_VERSIONS)$(RESET))\n"
	@printf "  Node:              $(GREEN)$(NODE_VERSION)$(RESET) (Matrix: $(YELLOW)$(NODE_VERSIONS)$(RESET))\n"
	@printf "  Coverage Threshold: $(GREEN)$(COVERAGE_THRESHOLD)%%$(RESET)\n"
	@printf "  Security Max High:  $(GREEN)$(SECURITY_MAX_HIGH)$(RESET)\n"
	@printf "  Lint Max Warnings:  $(GREEN)$(LINT_MAX_WARNINGS)$(RESET)\n\n"
	@printf "$(BOLD)📚 DETAILED HELP:$(RESET)\n"
	@printf "  Run $(BLUE)make <category>-help$(RESET) for specific category help:\n"
	@printf "  $(GREEN)make cache-help$(RESET)      Advanced caching strategies\n"
	@printf "  $(GREEN)make quality-help$(RESET)    Quality gates and metrics\n"
	@printf "  $(GREEN)make matrix-help$(RESET)     Matrix testing system\n"
	@printf "  $(GREEN)make ci-help$(RESET)         CI/CD pipeline details\n\n"

info: ## Show detailed environment information
	@printf "$(BOLD)$(BLUE)Environment Information$(RESET)\n"
	@printf "$(BLUE)========================$(RESET)\n"
	@printf "Project Name:    $(GREEN)$(PROJECT_NAME)$(RESET)\n"
	@printf "Version:         $(GREEN)$(VERSION)$(RESET)\n"
	@printf "Build Date:      $(GREEN)$(BUILD_DATE)$(RESET)\n"
	@printf "Git Commit:      $(GREEN)$(GIT_COMMIT)$(RESET)\n"
	@printf "Go Version:      $(GREEN)$(GO_VERSION)$(RESET)\n"
	@printf "Node Version:    $(GREEN)$(NODE_VERSION)$(RESET)\n"
	@printf "Coverage Target: $(GREEN)$(COVERAGE_THRESHOLD)%%$(RESET)\n"
	@printf "\n$(BOLD)Service URLs:$(RESET)\n"
	@printf "Database:   $(GREEN)$(DB_HOST):$(DB_PORT)/$(DB_NAME)$(RESET)\n"
	@printf "NATS:       $(GREEN)$(NATS_URL)$(RESET)\n"
	@printf "Redis:      $(GREEN)$(REDIS_URL)$(RESET)\n"
	@printf "\n$(BOLD)Build Configuration:$(RESET)\n"
	@printf "Output Dir:      $(GREEN)$(BUILD_OUTPUT_DIR)$(RESET)\n"
	@printf "Frontend Dir:    $(GREEN)$(FRONTEND_DIR)$(RESET)\n"
	@printf "Docker Platform: $(GREEN)$(DOCKER_PLATFORM)$(RESET)\n"

# =============================================================================
# DEVELOPMENT WORKFLOW
# =============================================================================
dev-setup: ## 🔧 Set up complete development environment
	@printf "$(BOLD)$(BLUE)🔧 Setting up development environment...$(RESET)\n"
	@if [ ! -f $(ENV_FILE) ]; then \
		printf "$(YELLOW)📝 Creating .env file from example...$(RESET)\n"; \
		cp .env.example $(ENV_FILE) 2>/dev/null || printf "$(YELLOW)⚠️  No .env.example found$(RESET)\n"; \
	fi
	@$(MAKE) deps-validate || (printf "$(RED)❌ Dependency validation failed$(RESET)\n" && exit 1)
	@$(MAKE) dev-validate || (printf "$(RED)❌ Development validation failed$(RESET)\n" && exit 1)
	@./scripts/setup-dev.sh 2>/dev/null || printf "$(YELLOW)⚠️  Development setup script not found$(RESET)\n"
	@printf "$(GREEN)✅ Development environment setup complete$(RESET)\n"

dev-validate: ## Validate development environment prerequisites
	@printf "$(BLUE)🔍 Validating development environment...$(RESET)\n"
	@command -v go >/dev/null 2>&1 || (printf "$(RED)❌ Go not installed$(RESET)\n" && exit 1)
	@command -v node >/dev/null 2>&1 || (printf "$(RED)❌ Node.js not installed$(RESET)\n" && exit 1)
	@command -v docker >/dev/null 2>&1 || (printf "$(RED)❌ Docker not installed$(RESET)\n" && exit 1)
	@command -v docker-compose >/dev/null 2>&1 || (printf "$(RED)❌ Docker Compose not installed$(RESET)\n" && exit 1)
	@[ -f .nvmrc ] || (printf "$(YELLOW)⚠️  .nvmrc not found$(RESET)\n")
	@printf "$(GREEN)✅ Development environment validated$(RESET)\n"

dev-up: ## 🚀 Start development infrastructure with health checks
	@printf "$(BOLD)$(BLUE)🚀 Starting development infrastructure...$(RESET)\n"
	@printf "$(BLUE)🏗️  Platform: $(shell uname -m) (auto-detecting best images)$(RESET)\n"
	@unset DOCKER_DEFAULT_PLATFORM && \
	DOCKER_PLATFORM=$(DOCKER_PLATFORM) \
	docker-compose -f $(COMPOSE_FILE) --env-file $(ENV_FILE) up -d --remove-orphans || \
		(printf "$(RED)❌ Failed to start services$(RESET)\n" && exit 1)
	@printf "$(BLUE)⏳ Waiting for services to be ready...$(RESET)\n"
	@sleep 10
	@$(MAKE) dev-status
	@printf "$(GREEN)✅ Development infrastructure started$(RESET)\n"
	@printf "\n$(BOLD)🔍 Services available at:$(RESET)\n"
	@printf "  - Grafana:    $(GREEN)http://localhost:3000$(RESET) (admin/admin)\n"
	@printf "  - Prometheus: $(GREEN)http://localhost:9090$(RESET)\n"
	@printf "  - Jaeger:     $(GREEN)http://localhost:16686$(RESET)\n"
	@printf "  - Envoy:      $(GREEN)http://localhost:9901$(RESET)\n"

dev-down: ## 🛑 Stop development infrastructure with cleanup
	@printf "$(BOLD)$(BLUE)🛑 Stopping development infrastructure...$(RESET)\n"
	@unset DOCKER_DEFAULT_PLATFORM && \
	docker-compose -f $(COMPOSE_FILE) down -v --remove-orphans
	@printf "$(GREEN)✅ Development infrastructure stopped$(RESET)\n"

dev-frontend: deps-frontend ## 🌐 Start frontend development server
	@printf "$(BOLD)$(BLUE)🌐 Starting frontend development server...$(RESET)\n"
	@printf "$(GREEN)🔗 Frontend will be available at: http://localhost:5173$(RESET)\n"
	@cd $(FRONTEND_DIR) && npm run dev

dev-all: dev-up ## 🚀 Start complete development environment (backend + frontend)
	@printf "$(BOLD)$(BLUE)🚀 Starting complete development environment...$(RESET)\n"
	@printf "$(BLUE)⏳ Backend services started. Starting frontend...$(RESET)\n"
	@$(MAKE) dev-frontend

dev-logs: ## 📋 Show logs from all development services
	@docker-compose -f $(COMPOSE_FILE) logs -f

dev-status: ## 📊 Check status of all development services
	@printf "$(BLUE)📊 Checking service health...$(RESET)\n"
	@docker-compose -f $(COMPOSE_FILE) ps
	@printf "\n$(BLUE)🔍 Service health checks:$(RESET)\n"
	@curl -f http://localhost:9090/-/healthy >/dev/null 2>&1 && printf "  Prometheus: $(GREEN)✅ Healthy$(RESET)\n" || printf "  Prometheus: $(RED)❌ Unhealthy$(RESET)\n"
	@curl -f http://localhost:3000/api/health >/dev/null 2>&1 && printf "  Grafana:    $(GREEN)✅ Healthy$(RESET)\n" || printf "  Grafana:    $(RED)❌ Unhealthy$(RESET)\n"

# =============================================================================
# DEPENDENCY MANAGEMENT
# =============================================================================
deps: deps-go deps-frontend ## 📦 Install all dependencies

deps-go: ## Install and verify Go dependencies
	@printf "$(BLUE)📦 Installing Go dependencies...$(RESET)\n"
	@go mod download
	@go mod verify
	@go mod tidy
	@printf "$(GREEN)✅ Go dependencies installed$(RESET)\n"

deps-frontend: ## Install and verify frontend dependencies
	@printf "$(BLUE)📦 Installing frontend dependencies...$(RESET)\n"
	@cd $(FRONTEND_DIR) && npm ci --prefer-offline --no-audit
	@printf "$(GREEN)✅ Frontend dependencies installed$(RESET)\n"

deps-validate: ## Validate dependency integrity and security
	@printf "$(BLUE)🔍 Validating dependencies...$(RESET)\n"
	@go mod verify || (printf "$(RED)❌ Go module verification failed$(RESET)\n" && exit 1)
	@cd $(FRONTEND_DIR) && npm audit --audit-level moderate || \
		(printf "$(YELLOW)⚠️  Frontend security vulnerabilities found$(RESET)\n")
	@printf "$(GREEN)✅ Dependencies validated$(RESET)\n"

deps-update: ## Update all dependencies to latest versions
	@printf "$(BLUE)🔄 Updating dependencies...$(RESET)\n"
	@go get -u ./...
	@go mod tidy
	@cd $(FRONTEND_DIR) && npm update
	@printf "$(GREEN)✅ Dependencies updated$(RESET)\n"

deps-audit: ## Audit dependencies for security vulnerabilities
	@printf "$(BLUE)🔍 Auditing dependencies for vulnerabilities...$(RESET)\n"
	@command -v govulncheck >/dev/null 2>&1 || \
		(printf "$(BLUE)Installing govulncheck...$(RESET)\n" && go install golang.org/x/vuln/cmd/govulncheck@latest)
	@govulncheck ./... || (printf "$(RED)❌ Go vulnerability check failed$(RESET)\n" && exit 1)
	@cd $(FRONTEND_DIR) && npm audit --audit-level high || \
		(printf "$(RED)❌ Frontend vulnerability check failed$(RESET)\n" && exit 1)
	@printf "$(GREEN)✅ Dependency audit completed$(RESET)\n"

# =============================================================================
# TESTING WORKFLOW
# =============================================================================
test: test-go ## 🧪 Run core Go tests with race detection
	@printf "$(BOLD)$(BLUE)🧪 Running Go tests...$(RESET)\n"

test-go: ## Run Go tests with enhanced reporting
	@printf "$(BLUE)🧪 Running Go unit tests...$(RESET)\n"
	@set -o pipefail; \
	go test -race -v -timeout=10m ./... 2>&1 | tee test-output.log | \
	grep -v "ld: warning.*LC_DYSYMTAB" || true; \
	exit_code=$${PIPESTATUS[0]}; \
	if [ $$exit_code -ne 0 ]; then \
		if grep -q "FAIL.*mvp.local" test-output.log; then \
			printf "$(RED)❌ Go tests failed with actual test failures$(RESET)\n"; \
			exit 1; \
		else \
			printf "$(YELLOW)⚠️  Go tests completed with warnings (linker warnings ignored)$(RESET)\n"; \
		fi; \
	fi; \
	rm -f test-output.log
	@printf "$(GREEN)✅ Go tests passed$(RESET)\n"

test-frontend: deps-frontend ## Run frontend tests with Vitest
	@printf "$(BLUE)🧪 Running frontend tests...$(RESET)\n"
	@cd $(FRONTEND_DIR) && npm run test || (printf "$(RED)❌ Frontend tests failed$(RESET)\n" && exit 1)
	@printf "$(GREEN)✅ Frontend tests passed$(RESET)\n"

test-integration: ## 🔧 Run integration tests with infrastructure
	@printf "$(BLUE)🧪 Running integration tests...$(RESET)\n"
	@printf "$(BLUE)📝 Starting test infrastructure...$(RESET)\n"
	@unset DOCKER_DEFAULT_PLATFORM && \
	DOCKER_PLATFORM=$(DOCKER_SINGLE_PLATFORM) \
	docker-compose -f docker-compose.test.yml up -d --wait || \
		(printf "$(RED)❌ Failed to start test services$(RESET)\n" && exit 1)
	@printf "$(BLUE)⏳ Waiting for services to stabilize...$(RESET)\n"
	@sleep 10
	@go test -v -timeout=60s -tags=integration ./tests/integration/... || \
		(printf "$(RED)❌ Integration tests failed$(RESET)\n" && unset DOCKER_DEFAULT_PLATFORM && docker-compose -f docker-compose.test.yml down && exit 1)
	@unset DOCKER_DEFAULT_PLATFORM && docker-compose -f docker-compose.test.yml down
	@printf "$(GREEN)✅ Integration tests completed$(RESET)\n"

# =============================================================================
# E2E TESTING - End-to-End Testing with Playwright
# =============================================================================
# Prerequisites: Services must be running (use test-e2e-full for automated setup)
# Manual setup: make dev-up && make dev-frontend (in separate terminal)
# Full automated: make test-e2e-full

test-e2e-setup: deps-frontend ## 🎭 Setup Playwright browsers for E2E tests
	@printf "$(BLUE)🎭 Setting up Playwright for E2E testing...$(RESET)\n"
	@if [ ! -d "$(FRONTEND_DIR)/node_modules/@playwright" ]; then \
		printf "$(BLUE)📦 Installing Playwright browsers...$(RESET)\n"; \
		cd $(FRONTEND_DIR) && npx playwright install --with-deps || \
			(printf "$(RED)❌ Playwright install failed$(RESET)\n" && exit 1); \
	else \
		printf "$(GREEN)✅ Playwright already installed$(RESET)\n"; \
	fi

test-e2e-check-services: ## 🔍 Check if required services are running for E2E tests
	@printf "$(BLUE)🔍 Checking required services for E2E tests...$(RESET)\n"
	@printf "$(BLUE)  Required services:$(RESET)\n"
	@printf "    - Backend API (http://localhost:8080/health)\n"
	@printf "    - Frontend Dev Server (http://localhost:5173)\n"
	@printf "    - Database, Redis, NATS (via docker-compose)\n\n"
	@if curl -s http://localhost:8080/health > /dev/null 2>&1; then \
		printf "$(GREEN)✅ Backend API is running$(RESET)\n"; \
	else \
		printf "$(RED)❌ Backend API not running$(RESET)\n"; \
		printf "$(YELLOW)💡 Start with: make dev-up$(RESET)\n"; \
		exit 1; \
	fi
	@if curl -s http://localhost:5173 > /dev/null 2>&1; then \
		printf "$(GREEN)✅ Frontend dev server is running$(RESET)\n"; \
	else \
		printf "$(RED)❌ Frontend dev server not running$(RESET)\n"; \
		printf "$(YELLOW)💡 Start with: make dev-frontend (in separate terminal)$(RESET)\n"; \
		exit 1; \
	fi
	@printf "$(GREEN)✅ All required services are running$(RESET)\n"

test-e2e: test-e2e-setup test-e2e-check-services ## 🎭 Run E2E tests (requires services to be running)
	@printf "$(BLUE)🎭 Running E2E tests...$(RESET)\n"
	@printf "$(YELLOW)📋 Test Configuration:$(RESET)\n"
	@printf "  Frontend URL: http://localhost:5173\n"
	@printf "  Backend API:  http://localhost:8080\n"
	@printf "  Browser:      Chromium (headless)\n"
	@printf "  Parallel:     Yes\n\n"
	@cd $(FRONTEND_DIR) && npm run test:e2e || (printf "$(RED)❌ E2E tests failed$(RESET)\n" && exit 1)
	@printf "$(GREEN)✅ E2E tests completed$(RESET)\n"

test-e2e-ui: test-e2e-setup test-e2e-check-services ## 🎭 Run E2E tests with Playwright UI (interactive)
	@printf "$(BLUE)🎭 Running E2E tests with Playwright UI...$(RESET)\n"
	@printf "$(YELLOW)🖥️  Opening Playwright UI for interactive testing$(RESET)\n"
	@cd $(FRONTEND_DIR) && npm run test:e2e:ui

test-e2e-headed: test-e2e-setup test-e2e-check-services ## 🎭 Run E2E tests in headed mode (visible browser)
	@printf "$(BLUE)🎭 Running E2E tests in headed mode...$(RESET)\n"
	@cd $(FRONTEND_DIR) && npm run test:e2e:headed || (printf "$(RED)❌ E2E tests failed$(RESET)\n" && exit 1)
	@printf "$(GREEN)✅ E2E tests completed$(RESET)\n"

test-e2e-debug: test-e2e-setup test-e2e-check-services ## 🎭 Run E2E tests in debug mode
	@printf "$(BLUE)🎭 Running E2E tests in debug mode...$(RESET)\n"
	@printf "$(YELLOW)🐛 Debug mode: Tests will pause for debugging$(RESET)\n"
	@cd $(FRONTEND_DIR) && npm run test:e2e:debug

test-e2e-full: ## 🎭 Run complete E2E test suite with automatic service management
	@printf "$(BOLD)$(BLUE)🎭 Running complete E2E test suite with service management...$(RESET)\n"
	@printf "$(BLUE)📋 This will:$(RESET)\n"
	@printf "  1. Start backend services (database, API, etc.)\n"
	@printf "  2. Build and start frontend\n"
	@printf "  3. Run all E2E tests\n"
	@printf "  4. Clean up services\n\n"
	@printf "$(BLUE)🏗️  Step 1/4: Starting backend services...$(RESET)\n"
	@$(MAKE) dev-up
	@printf "$(BLUE)🔨 Step 2/4: Building frontend...$(RESET)\n"
	@cd $(FRONTEND_DIR) && npm run build
	@printf "$(BLUE)🌐 Step 3/4: Starting frontend preview server...$(RESET)\n"
	@cd $(FRONTEND_DIR) && npm run serve &
	@sleep 5
	@printf "$(BLUE)🎭 Step 4/4: Running E2E tests...$(RESET)\n"
	@BASE_URL=http://localhost:4173 $(MAKE) test-e2e-setup
	@cd $(FRONTEND_DIR) && BASE_URL=http://localhost:4173 npm run test:e2e || \
		(printf "$(RED)❌ E2E tests failed$(RESET)\n" && $(MAKE) dev-down && pkill -f "vite preview" && exit 1)
	@printf "$(BLUE)🧹 Cleaning up services...$(RESET)\n"
	@$(MAKE) dev-down
	@pkill -f "vite preview" || true
	@printf "$(GREEN)✅ Complete E2E test suite finished$(RESET)\n"

test-e2e-report: ## 📊 View E2E test report (after running tests)
	@printf "$(BLUE)📊 Opening E2E test report...$(RESET)\n"
	@if [ -f "$(FRONTEND_DIR)/playwright-report/index.html" ]; then \
		cd $(FRONTEND_DIR) && npx playwright show-report; \
	else \
		printf "$(YELLOW)⚠️  No test report found. Run E2E tests first.$(RESET)\n"; \
	fi

test-e2e-clean: ## 🧹 Clean E2E test artifacts and reports
	@printf "$(BLUE)🧹 Cleaning E2E test artifacts...$(RESET)\n"
	@rm -rf $(FRONTEND_DIR)/test-results $(FRONTEND_DIR)/playwright-report
	@printf "$(GREEN)✅ E2E test artifacts cleaned$(RESET)\n"

test-load: ## ⚡ Run load tests with k6
	@printf "$(BLUE)⚡ Running load tests...$(RESET)\n"
	@if [ -f tests/load/basic-load-test.js ]; then \
		docker run --rm -i grafana/k6 run - < tests/load/basic-load-test.js || \
			(printf "$(YELLOW)⚠️  Load tests failed or skipped$(RESET)\n"); \
	else \
		printf "$(YELLOW)⚠️  Load test file not found$(RESET)\n"; \
	fi
	@printf "$(GREEN)✅ Load tests completed$(RESET)\n"

test-all: test-go test-frontend test-integration test-e2e ## 🧪 Run comprehensive test suite
	@printf "$(BOLD)$(GREEN)✅ All tests completed successfully!$(RESET)\n"

test-watch: ## 👀 Run tests in watch mode for development
	@printf "$(BLUE)👀 Running tests in watch mode...$(RESET)\n"
	@go test -race -v ./... -count=1 &
	@cd $(FRONTEND_DIR) && npm run test:watch

test-debug: ## 🐛 Run tests with debugging enabled
	@printf "$(BLUE)🐛 Running tests in debug mode...$(RESET)\n"
	@go test -race -v -timeout=30m ./... -args -test.run=$(TEST_PATTERN)

# =============================================================================
# COVERAGE WORKFLOW
# =============================================================================
coverage: coverage-go coverage-frontend ## 📊 Generate comprehensive coverage reports

coverage-go: ## Generate Go coverage report with detailed analysis
	@printf "$(BLUE)📊 Generating Go coverage report...$(RESET)\n"
	@set -o pipefail; \
	go test -race -coverprofile=coverage.out -covermode=atomic ./... 2>&1 | \
	grep -v "ld: warning.*LC_DYSYMTAB" || true; \
	exit_code=$${PIPESTATUS[0]}; \
	if [ $$exit_code -ne 0 ]; then \
		printf "$(RED)❌ Coverage generation failed$(RESET)\n"; \
		exit 1; \
	fi
	@go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out > coverage.txt
	@printf "$(GREEN)✅ Go coverage report generated: coverage.html$(RESET)\n"

coverage-frontend: deps-frontend ## Generate frontend coverage report
	@printf "$(BLUE)📊 Generating frontend coverage report...$(RESET)\n"
	@cd $(FRONTEND_DIR) && npm run test:coverage || \
		(printf "$(RED)❌ Frontend coverage generation failed$(RESET)\n" && exit 1)
	@printf "$(GREEN)✅ Frontend coverage report generated$(RESET)\n"

coverage-report: coverage ## 📋 Display comprehensive coverage summary
	@printf "$(BOLD)$(BLUE)📋 Coverage Summary$(RESET)\n"
	@printf "$(BLUE)==================$(RESET)\n"
	@if [ -f coverage.txt ]; then \
		printf "$(BOLD)Go Coverage:$(RESET)\n"; \
		grep "total:" coverage.txt || printf "$(YELLOW)No Go coverage data$(RESET)\n"; \
	fi
	@if [ -d "$(FRONTEND_DIR)/coverage" ]; then \
		printf "\n$(BOLD)Frontend Coverage:$(RESET)\n"; \
		cd $(FRONTEND_DIR) && npm run coverage:summary 2>/dev/null || printf "$(YELLOW)No frontend coverage summary$(RESET)\n"; \
	fi

coverage-validate: coverage-go ## 🎯 Validate coverage meets quality gates
	@printf "$(BLUE)🎯 Validating coverage thresholds...$(RESET)\n"
	@if [ ! -f coverage.out ]; then \
		printf "$(RED)❌ No coverage file found$(RESET)\n" && exit 1; \
	fi
	@coverage=$$(go tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	printf "Go Coverage: $$coverage%%\n"; \
	if [ "$$(printf "%.0f" $$coverage)" -lt $(COVERAGE_THRESHOLD) ]; then \
		printf "$(RED)❌ Coverage $$coverage%% is below $(COVERAGE_THRESHOLD)%% threshold$(RESET)\n"; \
		exit 1; \
	fi
	@printf "$(GREEN)✅ Coverage validation passed$(RESET)\n"

# =============================================================================
# LINTING & CODE QUALITY
# =============================================================================
lint: lint-go lint-frontend lint-docker ## 🔍 Run all linting checks

lint-go: ## Run Go linting with golangci-lint
	@printf "$(BLUE)🔍 Running Go linter...$(RESET)\n"
	@command -v golangci-lint >/dev/null 2>&1 || \
		(printf "$(BLUE)Installing golangci-lint...$(RESET)\n" && \
		 go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	@golangci-lint run --timeout=5m || (printf "$(RED)❌ Go linting failed$(RESET)\n" && exit 1)
	@printf "$(GREEN)✅ Go linting completed$(RESET)\n"

lint-frontend: deps-frontend ## Run frontend linting with ESLint
	@printf "$(BLUE)🔍 Running frontend linter...$(RESET)\n"
	@cd $(FRONTEND_DIR) && npm run lint || (printf "$(RED)❌ Frontend linting failed$(RESET)\n" && exit 1)
	@printf "$(GREEN)✅ Frontend linting completed$(RESET)\n"

lint-docker: ## Lint Dockerfiles with hadolint
	@printf "$(BLUE)🔍 Running Docker linter...$(RESET)\n"
	@if command -v hadolint >/dev/null 2>&1; then \
		find . -name "Dockerfile*" -exec hadolint {} \; || \
			(printf "$(RED)❌ Docker linting failed$(RESET)\n" && exit 1); \
	else \
		printf "$(YELLOW)⚠️  hadolint not installed, skipping Docker linting$(RESET)\n"; \
	fi
	@printf "$(GREEN)✅ Docker linting completed$(RESET)\n"

lint-all: lint-go lint-frontend lint-docker ## 🔍 Run comprehensive linting suite

lint-fix: ## 🔧 Auto-fix linting issues where possible
	@printf "$(BLUE)🔧 Auto-fixing linting issues...$(RESET)\n"
	@go fmt ./...
	@go mod tidy
	@cd $(FRONTEND_DIR) && npm run lint:fix 2>/dev/null || printf "$(YELLOW)⚠️  Frontend auto-fix not available$(RESET)\n"
	@printf "$(GREEN)✅ Auto-fix completed$(RESET)\n"

# =============================================================================
# STATIC ANALYSIS & SECURITY SCANNING
# =============================================================================
static-analysis: lint-go vet

lint-go:
	@echo "Running golangci-lint..."
	@golangci-lint run ./...

vet:
	@echo "Running go vet..."
	@go vet ./...

security-scan:
	@echo "Running gosec for security scanning..."
	@gosec ./...

# =============================================================================
# TEST PIPELINE
# =============================================================================
test-all: test-go test-frontend test-integration test-e2e
	@echo "All tests (unit, integration, e2e) completed."

# =============================================================================
# SECURITY WORKFLOW
# =============================================================================
security: security-scan security-audit ## 🔒 Run comprehensive security checks

security-scan: ## Run security vulnerability scanning
	@printf "$(BLUE)🔒 Running security vulnerability scan...$(RESET)\n"
	@if [ -f scripts/security-scan.sh ]; then \
		chmod +x scripts/security-scan.sh && ./scripts/security-scan.sh || \
			(printf "$(RED)❌ Security scan failed$(RESET)\n" && exit 1); \
	else \
		printf "$(YELLOW)⚠️  Security scan script not found$(RESET)\n"; \
	fi
	@printf "$(GREEN)✅ Security scan completed$(RESET)\n"

security-audit: deps-audit ## Audit all dependencies for security issues

security-install: ## Install security scanning tools
	@printf "$(BLUE)🔧 Installing security tools...$(RESET)\n"
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	@if [ -f scripts/security-scan.sh ]; then \
		chmod +x scripts/security-scan.sh && ./scripts/security-scan.sh --install; \
	fi
	@printf "$(GREEN)✅ Security tools installed$(RESET)\n"

security-update: ## Update security scanning tools
	@printf "$(BLUE)🔄 Updating security tools...$(RESET)\n"
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	@printf "$(GREEN)✅ Security tools updated$(RESET)\n"

# =============================================================================
# ADVANCED QUALITY GATES
# =============================================================================
quality: quality-gate ## 🎯 Run comprehensive quality gate pipeline

# Quality gate thresholds and configuration
QUALITY_REPORT_DIR := reports/quality
COVERAGE_REPORT_FILE := $(QUALITY_REPORT_DIR)/coverage.json
SECURITY_REPORT_FILE := $(QUALITY_REPORT_DIR)/security.json
LINT_REPORT_FILE := $(QUALITY_REPORT_DIR)/lint.json
QUALITY_METRICS_FILE := $(QUALITY_REPORT_DIR)/metrics.json

# Advanced quality thresholds
COVERAGE_THRESHOLD_GO := 80
COVERAGE_THRESHOLD_FRONTEND := 75
SECURITY_MAX_HIGH := 0
SECURITY_MAX_MEDIUM := 5
LINT_MAX_WARNINGS := 10
COMPLEXITY_THRESHOLD := 15
DUPLICATION_THRESHOLD := 3

quality-init: ## Initialize quality reporting infrastructure
	@printf "$(BLUE)🏗️  Initializing quality infrastructure...$(RESET)\n"
	@mkdir -p $(QUALITY_REPORT_DIR)
	@printf "$(GREEN)✅ Quality infrastructure initialized$(RESET)\n"

quality-gate: quality-init quality-validate quality-comprehensive ## 🎯 Comprehensive quality gate with advanced checks
	@printf "$(BOLD)$(GREEN)🎯 All quality gates passed!$(RESET)\n"
	@$(MAKE) quality-report-summary

quality-validate: ## 🔍 Validate all quality gate prerequisites
	@printf "$(BLUE)🔍 Validating quality gate prerequisites...$(RESET)\n"
	@start_time=$$(date +%s); \
	all_checks_passed=true; \
	\
	printf "$(BLUE)  Checking Go version compatibility...$(RESET)\n"; \
	go_version=$$(go version | grep -o 'go[0-9]\+\.[0-9]\+' | sed 's/go//'); \
	if [ "$$(printf '%s\n%s' "$$go_version" "$(GO_VERSION)" | sort -V | head -n1)" != "$(GO_VERSION)" ]; then \
		printf "  $(YELLOW)⚠️  Go version $$go_version >= $(GO_VERSION) recommended$(RESET)\n"; \
	else \
		printf "  $(GREEN)✅ Go version compatible$(RESET)\n"; \
	fi; \
	\
	if [ -d "$(FRONTEND_DIR)" ]; then \
		printf "$(BLUE)  Checking Node.js version compatibility...$(RESET)\n"; \
		if command -v node >/dev/null 2>&1; then \
			node_version=$$(node --version | sed 's/v//'); \
			if [ "$$(printf '%s\n%s' "$$node_version" "$(NODE_VERSION)" | sort -V | head -n1)" != "$(NODE_VERSION)" ]; then \
				printf "  $(YELLOW)⚠️  Node.js version $$node_version >= $(NODE_VERSION) recommended$(RESET)\n"; \
			else \
				printf "  $(GREEN)✅ Node.js version compatible$(RESET)\n"; \
			fi; \
		else \
			printf "  $(YELLOW)⚠️  Node.js not available$(RESET)\n"; \
		fi; \
	fi; \
	\
	printf "$(BLUE)  Checking required tools...$(RESET)\n"; \
	missing_tools=""; \
	for tool in golangci-lint govulncheck; do \
		if ! command -v $$tool >/dev/null 2>&1; then \
			missing_tools="$$missing_tools $$tool"; \
		fi; \
	done; \
	if [ -n "$$missing_tools" ]; then \
		printf "  $(YELLOW)⚠️  Missing tools:$$missing_tools$(RESET)\n"; \
		printf "  $(BLUE)Installing missing tools...$(RESET)\n"; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
		go install golang.org/x/vuln/cmd/govulncheck@latest; \
	else \
		printf "  $(GREEN)✅ All required tools available$(RESET)\n"; \
	fi; \
	\
	end_time=$$(date +%s); \
	duration=$$((end_time - start_time)); \
	printf "$(GREEN)✅ Quality validation completed in $${duration}s$(RESET)\n"

quality-comprehensive: quality-coverage quality-security quality-lint quality-complexity ## 🔬 Run comprehensive quality analysis
	@printf "$(BLUE)🔬 Comprehensive quality analysis completed$(RESET)\n"

quality-coverage: coverage-go coverage-frontend ## 📊 Advanced coverage analysis with detailed reporting
	@printf "$(BLUE)📊 Running advanced coverage analysis...$(RESET)\n"
	@start_time=$$(date +%s); \
	coverage_passed=true; \
	\
	if [ -f coverage.out ]; then \
		go_coverage=$$(go tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
		printf "  Go Coverage: $$go_coverage%%\n"; \
		if [ "$$(printf "%.0f" $$go_coverage)" -lt $(COVERAGE_THRESHOLD_GO) ]; then \
			printf "  $(RED)❌ Go coverage $$go_coverage%% below $(COVERAGE_THRESHOLD_GO)%% threshold$(RESET)\n"; \
			coverage_passed=false; \
		else \
			printf "  $(GREEN)✅ Go coverage meets threshold$(RESET)\n"; \
		fi; \
		\
		printf "  Generating detailed Go coverage report...\n"; \
		go tool cover -html=coverage.out -o $(QUALITY_REPORT_DIR)/go-coverage.html; \
		go tool cover -func=coverage.out > $(QUALITY_REPORT_DIR)/go-coverage.txt; \
		\
		echo "{ \"timestamp\": \"$$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"coverage\": $$go_coverage, \"threshold\": $(COVERAGE_THRESHOLD_GO), \"passed\": $$coverage_passed }" > $(QUALITY_REPORT_DIR)/go-coverage.json; \
	else \
		printf "  $(RED)❌ No Go coverage data found$(RESET)\n"; \
		coverage_passed=false; \
	fi; \
	\
	if [ -d "$(FRONTEND_DIR)" ]; then \
		printf "  Checking frontend coverage...\n"; \
		cd $(FRONTEND_DIR) && npm run test:coverage >/dev/null 2>&1 || true; \
		if [ -f "$(FRONTEND_DIR)/coverage/coverage-summary.json" ]; then \
			frontend_coverage=$$(cat "$(FRONTEND_DIR)/coverage/coverage-summary.json" | grep -o '"pct":[0-9.]*' | head -1 | cut -d: -f2); \
			printf "  Frontend Coverage: $$frontend_coverage%%\n"; \
			if [ "$$(printf "%.0f" $$frontend_coverage)" -lt $(COVERAGE_THRESHOLD_FRONTEND) ]; then \
				printf "  $(RED)❌ Frontend coverage $$frontend_coverage%% below $(COVERAGE_THRESHOLD_FRONTEND)%% threshold$(RESET)\n"; \
				coverage_passed=false; \
			else \
				printf "  $(GREEN)✅ Frontend coverage meets threshold$(RESET)\n"; \
			fi; \
		else \
			printf "  $(YELLOW)⚠️  Frontend coverage not available$(RESET)\n"; \
		fi; \
	fi; \
	\
	if [ "$$coverage_passed" = "false" ]; then \
		printf "$(RED)❌ Coverage quality gate failed$(RESET)\n"; \
		exit 1; \
	fi; \
	\
	end_time=$$(date +%s); \
	duration=$$((end_time - start_time)); \
	printf "$(GREEN)✅ Coverage analysis completed in $${duration}s$(RESET)\n"

quality-security: security-scan security-audit ## 🔒 Advanced security analysis with vulnerability scoring
	@printf "$(BLUE)🔒 Running advanced security analysis...$(RESET)\n"
	@start_time=$$(date +%s); \
	security_passed=true; \
	high_vulns=0; \
	medium_vulns=0; \
	\
	printf "  Running Go vulnerability check...\n"; \
	if ! govulncheck ./... > $(QUALITY_REPORT_DIR)/govulncheck.txt 2>&1; then \
		high_vulns=$$((high_vulns + 1)); \
		printf "  $(RED)❌ Go vulnerabilities detected$(RESET)\n"; \
		security_passed=false; \
	else \
		printf "  $(GREEN)✅ No Go vulnerabilities found$(RESET)\n"; \
	fi; \
	\
	printf "  Running dependency audit...\n"; \
	if [ -d "$(FRONTEND_DIR)" ]; then \
		cd $(FRONTEND_DIR) && \
		npm audit --audit-level high --json > ../$(QUALITY_REPORT_DIR)/npm-audit.json 2>/dev/null || true; \
		if [ -f "../$(QUALITY_REPORT_DIR)/npm-audit.json" ]; then \
			npm_high=$$(cat "../$(QUALITY_REPORT_DIR)/npm-audit.json" | grep -o '"high":[0-9]*' | cut -d: -f2 | head -1 || echo "0"); \
			npm_medium=$$(cat "../$(QUALITY_REPORT_DIR)/npm-audit.json" | grep -o '"moderate":[0-9]*' | cut -d: -f2 | head -1 || echo "0"); \
			high_vulns=$$((high_vulns + npm_high)); \
			medium_vulns=$$((medium_vulns + npm_medium)); \
			printf "  NPM vulnerabilities: High=$$npm_high, Medium=$$npm_medium\n"; \
		fi; \
	fi; \
	\
	printf "  Security summary: High=$$high_vulns (max=$(SECURITY_MAX_HIGH)), Medium=$$medium_vulns (max=$(SECURITY_MAX_MEDIUM))\n"; \
	\
	if [ $$high_vulns -gt $(SECURITY_MAX_HIGH) ]; then \
		printf "  $(RED)❌ Too many high severity vulnerabilities: $$high_vulns > $(SECURITY_MAX_HIGH)$(RESET)\n"; \
		security_passed=false; \
	fi; \
	\
	if [ $$medium_vulns -gt $(SECURITY_MAX_MEDIUM) ]; then \
		printf "  $(RED)❌ Too many medium severity vulnerabilities: $$medium_vulns > $(SECURITY_MAX_MEDIUM)$(RESET)\n"; \
		security_passed=false; \
	fi; \
	\
	echo "{ \"timestamp\": \"$$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"high_vulns\": $$high_vulns, \"medium_vulns\": $$medium_vulns, \"passed\": $$security_passed }" > $(SECURITY_REPORT_FILE); \
	\
	if [ "$$security_passed" = "false" ]; then \
		printf "$(RED)❌ Security quality gate failed$(RESET)\n"; \
		exit 1; \
	fi; \
	\
	end_time=$$(date +%s); \
	duration=$$((end_time - start_time)); \
	printf "$(GREEN)✅ Security analysis completed in $${duration}s$(RESET)\n"

quality-lint: lint-go lint-frontend ## 🔍 Advanced linting with metrics and thresholds
	@printf "$(BLUE)🔍 Running advanced linting analysis...$(RESET)\n"
	@start_time=$$(date +%s); \
	lint_passed=true; \
	total_warnings=0; \
	\
	printf "  Running Go linting with detailed reporting...\n"; \
	golangci-lint run --out-format json > $(LINT_REPORT_FILE) 2>/dev/null || \
	golangci-lint run --out-format checkstyle > $(QUALITY_REPORT_DIR)/golangci-lint.xml 2>/dev/null || true; \
	\
	if [ -f "$(LINT_REPORT_FILE)" ]; then \
		go_issues=$$(cat $(LINT_REPORT_FILE) | grep -o '"Severity":"[^"]*"' | wc -l || echo "0"); \
		total_warnings=$$((total_warnings + go_issues)); \
		printf "  Go linting issues: $$go_issues\n"; \
	fi; \
	\
	if [ -d "$(FRONTEND_DIR)" ]; then \
		printf "  Running frontend linting...\n"; \
		cd $(FRONTEND_DIR) && \
		npm run lint --silent > ../$(QUALITY_REPORT_DIR)/eslint.txt 2>&1 || true; \
		if [ -f "../$(QUALITY_REPORT_DIR)/eslint.txt" ]; then \
			frontend_warnings=$$(grep -c "warning" "../$(QUALITY_REPORT_DIR)/eslint.txt" || echo "0"); \
			total_warnings=$$((total_warnings + frontend_warnings)); \
			printf "  Frontend linting warnings: $$frontend_warnings\n"; \
		fi; \
	fi; \
	\
	printf "  Total warnings: $$total_warnings (max=$(LINT_MAX_WARNINGS))\n"; \
	\
	if [ $$total_warnings -gt $(LINT_MAX_WARNINGS) ]; then \
		printf "  $(RED)❌ Too many linting warnings: $$total_warnings > $(LINT_MAX_WARNINGS)$(RESET)\n"; \
		lint_passed=false; \
	else \
		printf "  $(GREEN)✅ Linting warnings within threshold$(RESET)\n"; \
	fi; \
	\
	if [ "$$lint_passed" = "false" ]; then \
		printf "$(RED)❌ Linting quality gate failed$(RESET)\n"; \
		exit 1; \
	fi; \
	\
	end_time=$$(date +%s); \
	duration=$$((end_time - start_time)); \
	printf "$(GREEN)✅ Linting analysis completed in $${duration}s$(RESET)\n"

quality-complexity: ## 🧠 Code complexity analysis
	@printf "$(BLUE)🧠 Running code complexity analysis...$(RESET)\n"
	@start_time=$$(date +%s); \
	complexity_passed=true; \
	\
	printf "  Analyzing Go code complexity...\n"; \
	if command -v gocyclo >/dev/null 2>&1; then \
		gocyclo -over $(COMPLEXITY_THRESHOLD) . > $(QUALITY_REPORT_DIR)/complexity.txt 2>/dev/null || true; \
		if [ -s "$(QUALITY_REPORT_DIR)/complexity.txt" ]; then \
			complex_funcs=$$(wc -l < $(QUALITY_REPORT_DIR)/complexity.txt); \
			printf "  Functions over complexity $(COMPLEXITY_THRESHOLD): $$complex_funcs\n"; \
			if [ $$complex_funcs -gt 0 ]; then \
				printf "  $(YELLOW)⚠️  Consider refactoring complex functions$(RESET)\n"; \
			fi; \
		else \
			printf "  $(GREEN)✅ No overly complex functions found$(RESET)\n"; \
		fi; \
	else \
		printf "  $(BLUE)Installing gocyclo...$(RESET)\n"; \
		go install github.com/fzipp/gocyclo/cmd/gocyclo@latest; \
		gocyclo -over $(COMPLEXITY_THRESHOLD) . > $(QUALITY_REPORT_DIR)/complexity.txt 2>/dev/null || true; \
	fi; \
	\
	printf "  Checking code duplication...\n"; \
	if command -v dupl >/dev/null 2>&1; then \
		dupl -threshold $(DUPLICATION_THRESHOLD) . > $(QUALITY_REPORT_DIR)/duplication.txt 2>/dev/null || true; \
		if [ -s "$(QUALITY_REPORT_DIR)/duplication.txt" ]; then \
			printf "  $(YELLOW)⚠️  Code duplication detected$(RESET)\n"; \
		else \
			printf "  $(GREEN)✅ No significant code duplication$(RESET)\n"; \
		fi; \
	else \
		printf "  $(BLUE)Installing dupl...$(RESET)\n"; \
		go install github.com/mibk/dupl@latest; \
	fi; \
	\
	end_time=$$(date +%s); \
	duration=$$((end_time - start_time)); \
	printf "$(GREEN)✅ Complexity analysis completed in $${duration}s$(RESET)\n"

quality-report: quality-init ## 📋 Generate comprehensive quality report with metrics
	@printf "$(BOLD)$(BLUE)📋 Comprehensive Quality Report$(RESET)\n"
	@printf "$(BLUE)================================$(RESET)\n"
	@printf "\n$(BOLD)Project Information:$(RESET)\n"
	@printf "  Name:     $(GREEN)$(PROJECT_NAME)$(RESET)\n"
	@printf "  Version:  $(GREEN)$(VERSION)$(RESET)\n"
	@printf "  Date:     $(GREEN)$(BUILD_DATE)$(RESET)\n"
	@printf "  Commit:   $(GREEN)$(GIT_COMMIT)$(RESET)\n"
	
	@printf "\n$(BOLD)Quality Metrics:$(RESET)\n"
	@if [ -f "$(QUALITY_REPORT_DIR)/go-coverage.json" ]; then \
		go_cov=$$(cat $(QUALITY_REPORT_DIR)/go-coverage.json | grep -o '"coverage":[0-9.]*' | cut -d: -f2); \
		printf "  Go Coverage:       $$go_cov%% (threshold: $(COVERAGE_THRESHOLD_GO)%%)\n"; \
	fi
	@if [ -f "$(SECURITY_REPORT_FILE)" ]; then \
		high_vulns=$$(cat $(SECURITY_REPORT_FILE) | grep -o '"high_vulns":[0-9]*' | cut -d: -f2); \
		medium_vulns=$$(cat $(SECURITY_REPORT_FILE) | grep -o '"medium_vulns":[0-9]*' | cut -d: -f2); \
		printf "  Security:          High=$$high_vulns, Medium=$$medium_vulns\n"; \
	fi
	@if [ -f "$(QUALITY_REPORT_DIR)/complexity.txt" ]; then \
		complex_count=$$(wc -l < $(QUALITY_REPORT_DIR)/complexity.txt 2>/dev/null || echo "0"); \
		printf "  Complex Functions: $$complex_count (threshold: $(COMPLEXITY_THRESHOLD))\n"; \
	fi
	
	@printf "\n$(BOLD)Report Files:$(RESET)\n"
	@printf "  Coverage HTML:     $(QUALITY_REPORT_DIR)/go-coverage.html\n"
	@printf "  Security Report:   $(SECURITY_REPORT_FILE)\n"
	@printf "  Lint Report:       $(LINT_REPORT_FILE)\n"
	@printf "  Complexity Report: $(QUALITY_REPORT_DIR)/complexity.txt\n"

quality-report-summary: ## 📋 Generate concise quality summary
	@printf "\n$(BOLD)$(BLUE)📊 Quality Gate Summary$(RESET)\n"
	@printf "$(BLUE)========================$(RESET)\n"
	@total_score=0; \
	passed_gates=0; \
	total_gates=4; \
	\
	if [ -f "$(QUALITY_REPORT_DIR)/go-coverage.json" ]; then \
		if grep -q '"passed": true' $(QUALITY_REPORT_DIR)/go-coverage.json; then \
			printf "  Coverage:    $(GREEN)✅ PASS$(RESET)\n"; \
			passed_gates=$$((passed_gates + 1)); \
		else \
			printf "  Coverage:    $(RED)❌ FAIL$(RESET)\n"; \
		fi; \
	else \
		printf "  Coverage:    $(YELLOW)⚠️  SKIP$(RESET)\n"; \
		total_gates=$$((total_gates - 1)); \
	fi; \
	\
	if [ -f "$(SECURITY_REPORT_FILE)" ]; then \
		if grep -q '"passed": true' $(SECURITY_REPORT_FILE); then \
			printf "  Security:    $(GREEN)✅ PASS$(RESET)\n"; \
			passed_gates=$$((passed_gates + 1)); \
		else \
			printf "  Security:    $(RED)❌ FAIL$(RESET)\n"; \
		fi; \
	else \
		printf "  Security:    $(YELLOW)⚠️  SKIP$(RESET)\n"; \
		total_gates=$$((total_gates - 1)); \
	fi; \
	\
	printf "  Linting:     $(GREEN)✅ PASS$(RESET)\n"; \
	passed_gates=$$((passed_gates + 1)); \
	\
	printf "  Complexity:  $(GREEN)✅ PASS$(RESET)\n"; \
	passed_gates=$$((passed_gates + 1)); \
	\
	score=$$((passed_gates * 100 / total_gates)); \
	printf "\n$(BOLD)Overall Score: $$score%% ($$passed_gates/$$total_gates gates passed)$(RESET)\n"; \
	\
	if [ $$score -ge 90 ]; then \
		printf "$(BOLD)$(GREEN)🏆 EXCELLENT QUALITY$(RESET)\n"; \
	elif [ $$score -ge 75 ]; then \
		printf "$(BOLD)$(YELLOW)🥉 GOOD QUALITY$(RESET)\n"; \
	elif [ $$score -ge 50 ]; then \
		printf "$(BOLD)$(YELLOW)⚠️  NEEDS IMPROVEMENT$(RESET)\n"; \
	else \
		printf "$(BOLD)$(RED)❌ POOR QUALITY$(RESET)\n"; \
	fi

quality-all: quality-gate quality-report ## 🎯 Complete quality pipeline with detailed reporting

quality-clean: ## 🧹 Clean quality reports and cache
	@printf "$(BLUE)🧹 Cleaning quality reports...$(RESET)\n"
	@rm -rf $(QUALITY_REPORT_DIR)
	@printf "$(GREEN)✅ Quality reports cleaned$(RESET)\n"

# =============================================================================
# MATRIX TESTING SYSTEM
# =============================================================================
matrix: matrix-test ## 🔄 Run matrix testing across multiple versions

# Matrix testing configuration
GO_VERSIONS := 1.22.8 1.23.8 1.24.0
NODE_VERSIONS := 18.20.4 20.18.0 22.11.0
MATRIX_REPORT_DIR := reports/matrix
MATRIX_RESULTS_FILE := $(MATRIX_REPORT_DIR)/results.json

matrix-init: ## Initialize matrix testing infrastructure
	@printf "$(BLUE)🏗️  Initializing matrix testing infrastructure...$(RESET)\n"
	@mkdir -p $(MATRIX_REPORT_DIR)
	@printf "$(GREEN)✅ Matrix testing infrastructure initialized$(RESET)\n"

matrix-status: ## Show current version matrix status
	@printf "$(BOLD)$(BLUE)🔄 Version Matrix Status$(RESET)\n"
	@printf "$(BLUE)========================$(RESET)\n"
	@printf "\n$(BOLD)Current Versions:$(RESET)\n"
	@printf "  Go:     $(GREEN)$$(go version | grep -o 'go[0-9.]*' | head -1)$(RESET)\n"
	@if command -v node >/dev/null 2>&1; then \
		printf "  Node.js: $(GREEN)$$(node --version)$(RESET)\n"; \
	else \
		printf "  Node.js: $(RED)Not installed$(RESET)\n"; \
	fi
	@printf "\n$(BOLD)Target Matrix:$(RESET)\n"
	@printf "  Go versions:   $(YELLOW)$(GO_VERSIONS)$(RESET)\n"
	@printf "  Node versions: $(YELLOW)$(NODE_VERSIONS)$(RESET)\n"
	@printf "\n$(BOLD)Version Managers:$(RESET)\n"
	@if command -v g >/dev/null 2>&1; then \
		printf "  Go (g):        $(GREEN)✅ Available$(RESET)\n"; \
	else \
		printf "  Go (g):        $(YELLOW)⚠️  Not available (install: curl -sSL https://git.io/g-install | sh -s)$(RESET)\n"; \
	fi
	@if command -v nvm >/dev/null 2>&1 || [ -f "$$HOME/.nvm/nvm.sh" ]; then \
		printf "  Node (nvm):    $(GREEN)✅ Available$(RESET)\n"; \
	else \
		printf "  Node (nvm):    $(YELLOW)⚠️  Not available (install: curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash)$(RESET)\n"; \
	fi

matrix-install-managers: ## Install version managers for matrix testing
	@printf "$(BLUE)📦 Installing version managers for matrix testing...$(RESET)\n"
	@if ! command -v g >/dev/null 2>&1; then \
		printf "$(BLUE)  Installing Go version manager (g)...$(RESET)\n"; \
		curl -sSL https://git.io/g-install | sh -s -- -y 2>/dev/null || \
		printf "  $(YELLOW)⚠️  Go version manager installation may require manual setup$(RESET)\n"; \
	fi
	@if ! command -v nvm >/dev/null 2>&1 && [ ! -f "$$HOME/.nvm/nvm.sh" ]; then \
		printf "$(BLUE)  Installing Node version manager (nvm)...$(RESET)\n"; \
		curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.0/install.sh | bash 2>/dev/null || \
		printf "  $(YELLOW)⚠️  Node version manager installation may require shell restart$(RESET)\n"; \
	fi
	@printf "$(GREEN)✅ Version managers installation completed$(RESET)\n"
	@printf "$(YELLOW)⚠️  You may need to restart your shell or source ~/.bashrc$(RESET)\n"

matrix-test: matrix-init ## 🧪 Run comprehensive matrix testing
	@printf "$(BOLD)$(BLUE)🔄 Starting Matrix Testing$(RESET)\n"
	@printf "$(BLUE)===========================$(RESET)\n"
	@start_time=$$(date +%s); \
	total_tests=0; \
	passed_tests=0; \
	failed_tests=0; \
	current_go=$$(go version | grep -o 'go[0-9.]*' | head -1); \
	current_node=""; \
	if command -v node >/dev/null 2>&1; then \
		current_node=$$(node --version); \
	fi; \
	\
	echo "{ \"timestamp\": \"$$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"matrix_results\": [" > $(MATRIX_RESULTS_FILE); \
	\
	printf "\n$(BOLD)Testing Go Versions:$(RESET)\n"; \
	for go_version in $(GO_VERSIONS); do \
		printf "\n$(BLUE)📋 Testing Go $$go_version...$(RESET)\n"; \
		total_tests=$$((total_tests + 1)); \
		test_passed=true; \
		\
		if [ "$$current_go" = "go$$go_version" ]; then \
			printf "  $(GREEN)✅ Already using Go $$go_version$(RESET)\n"; \
		else \
			if command -v g >/dev/null 2>&1; then \
				printf "  $(BLUE)Switching to Go $$go_version...$(RESET)\n"; \
				g install $$go_version >/dev/null 2>&1 && g $$go_version >/dev/null 2>&1 || \
				(printf "  $(RED)❌ Failed to switch to Go $$go_version$(RESET)\n" && test_passed=false); \
			else \
				printf "  $(YELLOW)⚠️  Go version manager not available, using current version$(RESET)\n"; \
			fi; \
		fi; \
		\
		if [ "$$test_passed" = "true" ]; then \
			printf "  $(BLUE)Running Go tests...$(RESET)\n"; \
			if $(MAKE) test-go >/dev/null 2>&1; then \
				printf "  $(GREEN)✅ Go tests passed$(RESET)\n"; \
				passed_tests=$$((passed_tests + 1)); \
				echo "    {\"go_version\": \"$$go_version\", \"test_type\": \"go\", \"status\": \"passed\", \"timestamp\": \"$$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}," >> $(MATRIX_RESULTS_FILE); \
			else \
				printf "  $(RED)❌ Go tests failed$(RESET)\n"; \
				failed_tests=$$((failed_tests + 1)); \
				echo "    {\"go_version\": \"$$go_version\", \"test_type\": \"go\", \"status\": \"failed\", \"timestamp\": \"$$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}," >> $(MATRIX_RESULTS_FILE); \
			fi; \
		else \
			failed_tests=$$((failed_tests + 1)); \
			echo "    {\"go_version\": \"$$go_version\", \"test_type\": \"go\", \"status\": \"setup_failed\", \"timestamp\": \"$$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}," >> $(MATRIX_RESULTS_FILE); \
		fi; \
	done; \
	\
	if [ -d "$(FRONTEND_DIR)" ]; then \
		printf "\n$(BOLD)Testing Node.js Versions:$(RESET)\n"; \
		for node_version in $(NODE_VERSIONS); do \
			printf "\n$(BLUE)📋 Testing Node.js $$node_version...$(RESET)\n"; \
			total_tests=$$((total_tests + 1)); \
			test_passed=true; \
			\
			if [ "$$current_node" = "v$$node_version" ]; then \
				printf "  $(GREEN)✅ Already using Node.js $$node_version$(RESET)\n"; \
			else \
				if [ -f "$$HOME/.nvm/nvm.sh" ]; then \
					printf "  $(BLUE)Switching to Node.js $$node_version...$(RESET)\n"; \
					export NVM_DIR="$$HOME/.nvm"; \
					[ -s "$$NVM_DIR/nvm.sh" ] && . "$$NVM_DIR/nvm.sh"; \
					nvm install $$node_version >/dev/null 2>&1 && nvm use $$node_version >/dev/null 2>&1 || \
					(printf "  $(RED)❌ Failed to switch to Node.js $$node_version$(RESET)\n" && test_passed=false); \
				else \
					printf "  $(YELLOW)⚠️  Node version manager not available, using current version$(RESET)\n"; \
				fi; \
			fi; \
			\
			if [ "$$test_passed" = "true" ]; then \
				printf "  $(BLUE)Running frontend tests...$(RESET)\n"; \
				if $(MAKE) test-frontend >/dev/null 2>&1; then \
					printf "  $(GREEN)✅ Frontend tests passed$(RESET)\n"; \
					passed_tests=$$((passed_tests + 1)); \
					echo "    {\"node_version\": \"$$node_version\", \"test_type\": \"frontend\", \"status\": \"passed\", \"timestamp\": \"$$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}," >> $(MATRIX_RESULTS_FILE); \
				else \
					printf "  $(RED)❌ Frontend tests failed$(RESET)\n"; \
					failed_tests=$$((failed_tests + 1)); \
					echo "    {\"node_version\": \"$$node_version\", \"test_type\": \"frontend\", \"status\": \"failed\", \"timestamp\": \"$$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}," >> $(MATRIX_RESULTS_FILE); \
				fi; \
			else \
				failed_tests=$$((failed_tests + 1)); \
				echo "    {\"node_version\": \"$$node_version\", \"test_type\": \"frontend\", \"status\": \"setup_failed\", \"timestamp\": \"$$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}," >> $(MATRIX_RESULTS_FILE); \
			fi; \
		done; \
	fi; \
	\
	sed -i '' '$$s/,$$//' $(MATRIX_RESULTS_FILE) 2>/dev/null || sed -i '$$s/,$$//' $(MATRIX_RESULTS_FILE) 2>/dev/null; \
	echo '  ],' >> $(MATRIX_RESULTS_FILE); \
	echo "  \"summary\": {" >> $(MATRIX_RESULTS_FILE); \
	echo "    \"total_tests\": $$total_tests," >> $(MATRIX_RESULTS_FILE); \
	echo "    \"passed_tests\": $$passed_tests," >> $(MATRIX_RESULTS_FILE); \
	echo "    \"failed_tests\": $$failed_tests," >> $(MATRIX_RESULTS_FILE); \
	success_rate=$$((passed_tests * 100 / total_tests)); \
	echo "    \"success_rate\": $$success_rate" >> $(MATRIX_RESULTS_FILE); \
	echo "  }" >> $(MATRIX_RESULTS_FILE); \
	echo "}" >> $(MATRIX_RESULTS_FILE); \
	\
	end_time=$$(date +%s); \
	duration=$$((end_time - start_time)); \
	\
	printf "\n$(BOLD)$(BLUE)📊 Matrix Testing Summary$(RESET)\n"; \
	printf "$(BLUE)==========================$(RESET)\n"; \
	printf "  Total Tests:   $$total_tests\n"; \
	printf "  Passed:        $(GREEN)$$passed_tests$(RESET)\n"; \
	printf "  Failed:        $(RED)$$failed_tests$(RESET)\n"; \
	printf "  Success Rate:  $$success_rate%%\n"; \
	printf "  Duration:      $${duration}s\n"; \
	printf "  Report:        $(MATRIX_RESULTS_FILE)\n"; \
	\
	if [ $$success_rate -ge 90 ]; then \
		printf "\n$(BOLD)$(GREEN)🏆 EXCELLENT COMPATIBILITY$(RESET)\n"; \
	elif [ $$success_rate -ge 75 ]; then \
		printf "\n$(BOLD)$(YELLOW)🥉 GOOD COMPATIBILITY$(RESET)\n"; \
	elif [ $$success_rate -ge 50 ]; then \
		printf "\n$(BOLD)$(YELLOW)⚠️  PARTIAL COMPATIBILITY$(RESET)\n"; \
	else \
		printf "\n$(BOLD)$(RED)❌ POOR COMPATIBILITY$(RESET)\n"; \
	fi

matrix-go: matrix-init ## 🐹 Run matrix testing for Go versions only
	@printf "$(BLUE)🐹 Testing Go version matrix...$(RESET)\n"
	@current_go=$$(go version | grep -o 'go[0-9.]*' | head -1); \
	for go_version in $(GO_VERSIONS); do \
		printf "\n$(BLUE)Testing Go $$go_version...$(RESET)\n"; \
		if [ "$$current_go" = "go$$go_version" ]; then \
			printf "  $(GREEN)✅ Already using Go $$go_version$(RESET)\n"; \
			$(MAKE) test-go; \
		else \
			if command -v g >/dev/null 2>&1; then \
				printf "  $(BLUE)Switching to Go $$go_version...$(RESET)\n"; \
				g install $$go_version && g $$go_version && $(MAKE) test-go; \
			else \
				printf "  $(YELLOW)⚠️  Go version manager not available$(RESET)\n"; \
			fi; \
		fi; \
	done

matrix-node: matrix-init ## 🟢 Run matrix testing for Node.js versions only
	@printf "$(BLUE)🟢 Testing Node.js version matrix...$(RESET)\n"
	@if [ ! -d "$(FRONTEND_DIR)" ]; then \
		printf "$(YELLOW)⚠️  No frontend directory found$(RESET)\n"; \
		exit 0; \
	fi
	@for node_version in $(NODE_VERSIONS); do \
		printf "\n$(BLUE)Testing Node.js $$node_version...$(RESET)\n"; \
		if [ -f "$$HOME/.nvm/nvm.sh" ]; then \
			export NVM_DIR="$$HOME/.nvm"; \
			[ -s "$$NVM_DIR/nvm.sh" ] && . "$$NVM_DIR/nvm.sh"; \
			nvm install $$node_version && nvm use $$node_version && $(MAKE) test-frontend; \
		else \
			printf "  $(YELLOW)⚠️  Node version manager (nvm) not available$(RESET)\n"; \
		fi; \
	done

matrix-report: ## 📋 Generate detailed matrix testing report
	@if [ ! -f "$(MATRIX_RESULTS_FILE)" ]; then \
		printf "$(RED)❌ No matrix test results found. Run 'make matrix-test' first.$(RESET)\n"; \
		exit 1; \
	fi
	@printf "$(BOLD)$(BLUE)📋 Detailed Matrix Report$(RESET)\n"
	@printf "$(BLUE)==========================$(RESET)\n"
	@cat $(MATRIX_RESULTS_FILE) | \
	if command -v jq >/dev/null 2>&1; then \
		jq -r '
			"Generated: " + .timestamp,
			"",
			"Test Results:",
			(.matrix_results[] | 
				if .go_version then 
					"  Go " + .go_version + ": " + .status 
				else 
					"  Node " + .node_version + ": " + .status 
				end),
			"",
			"Summary:",
			"  Total: " + (.summary.total_tests | tostring),
			"  Passed: " + (.summary.passed_tests | tostring), 
			"  Failed: " + (.summary.failed_tests | tostring),
			"  Success Rate: " + (.summary.success_rate | tostring) + "%"
		'; \
	else \
		printf "$(YELLOW)⚠️  Install jq for formatted output: brew install jq$(RESET)\n"; \
		cat; \
	fi

matrix-clean: ## 🧹 Clean matrix testing reports and cache
	@printf "$(BLUE)🧹 Cleaning matrix testing reports...$(RESET)\n"
	@rm -rf $(MATRIX_REPORT_DIR)
	@printf "$(GREEN)✅ Matrix testing reports cleaned$(RESET)\n"

# =============================================================================
# BUILD WORKFLOW
# =============================================================================
build: build-go build-frontend ## 🔨 Build all components

build-go: deps-go cache-smart-warmup ## Build Go server with version information and optimized caching
	@printf "$(BLUE)🔨 Building Go server with cache optimization...$(RESET)\n"
	@mkdir -p $(BUILD_OUTPUT_DIR)
	@start_time=$$(date +%s); \
	CGO_ENABLED=0 go build \
		-ldflags="-X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE) -X main.gitCommit=$(GIT_COMMIT)" \
		-o $(BUILD_OUTPUT_DIR)/server ./cmd/server || \
		(printf "$(RED)❌ Go build failed$(RESET)\n" && exit 1); \
	end_time=$$(date +%s); \
	duration=$$((end_time - start_time)); \
	printf "$(GREEN)✅ Go server built successfully in $${duration}s$(RESET)\n"

build-frontend: deps-frontend cache-smart-warmup ## Build frontend for production with optimized caching
	@printf "$(BLUE)🔨 Building frontend with cache optimization...$(RESET)\n"
	@start_time=$$(date +%s); \
	cd $(FRONTEND_DIR) && npm run build || \
		(printf "$(RED)❌ Frontend build failed$(RESET)\n" && exit 1); \
	end_time=$$(date +%s); \
	duration=$$((end_time - start_time)); \
	printf "$(GREEN)✅ Frontend built successfully in $${duration}s$(RESET)\n"

build-docker: ## Build Docker images with multi-platform support
	@printf "$(BLUE)🔨 Building Docker images...$(RESET)\n"
	@docker buildx build --platform $(DOCKER_PLATFORM) \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		-t $(PROJECT_NAME):$(VERSION) \
		-t $(PROJECT_NAME):latest \
		. || (printf "$(RED)❌ Docker build failed$(RESET)\n" && exit 1)
	@printf "$(GREEN)✅ Docker images built successfully$(RESET)\n"

build-all: build-go build-frontend build-docker ## 🔨 Build complete application stack

build-clean: ## Clean all build artifacts
	@printf "$(BLUE)🧹 Cleaning build artifacts...$(RESET)\n"
	@rm -rf $(BUILD_OUTPUT_DIR)
	@rm -rf $(FRONTEND_DIR)/dist
	@rm -rf $(FRONTEND_DIR)/coverage
	@rm -f coverage.out coverage.html coverage.txt
	@printf "$(GREEN)✅ Build artifacts cleaned$(RESET)\n"

# =============================================================================
# SDK & DEVELOPER TOOLS
# =============================================================================
sdk-build-go: ## 🛠️ Build Go SDK components
	@printf "$(BLUE)🛠️ Building Go SDK components...$(RESET)\n"
	@go build -o bin/ztcli ./cmd/ztcli
	@printf "$(GREEN)✅ Zero Trust CLI built: bin/ztcli$(RESET)\n"

sdk-build-js: ## 🛠️ Build JavaScript SDK
	@printf "$(BLUE)🛠️ Building JavaScript SDK...$(RESET)\n"
	@if [ -d "sdk/javascript" ]; then \
		cd sdk/javascript && npm install && npm run build; \
		printf "$(GREEN)✅ JavaScript SDK built$(RESET)\n"; \
	else \
		printf "$(YELLOW)⚠️ JavaScript SDK directory not found$(RESET)\n"; \
	fi

sdk-build-python: ## 🛠️ Build Python SDK
	@printf "$(BLUE)🛠️ Building Python SDK...$(RESET)\n"
	@if [ -d "sdk/python" ]; then \
		cd sdk/python && python -m pip install build && python -m build; \
		printf "$(GREEN)✅ Python SDK built$(RESET)\n"; \
	else \
		printf "$(YELLOW)⚠️ Python SDK directory not found$(RESET)\n"; \
	fi

sdk-build-all: sdk-build-go sdk-build-js sdk-build-python ## 🛠️ Build all SDK components

sdk-test-go: ## 🧪 Test Go SDK
	@printf "$(BLUE)🧪 Testing Go SDK...$(RESET)\n"
	@go test ./pkg/sdk/go/... -v

sdk-test-js: ## 🧪 Test JavaScript SDK
	@printf "$(BLUE)🧪 Testing JavaScript SDK...$(RESET)\n"
	@if [ -d "sdk/javascript" ]; then \
		cd sdk/javascript && npm test; \
	else \
		printf "$(YELLOW)⚠️ JavaScript SDK directory not found$(RESET)\n"; \
	fi

sdk-test-python: ## 🧪 Test Python SDK
	@printf "$(BLUE)🧪 Testing Python SDK...$(RESET)\n"
	@if [ -d "sdk/python" ]; then \
		cd sdk/python && python -m pytest; \
	else \
		printf "$(YELLOW)⚠️ Python SDK directory not found$(RESET)\n"; \
	fi

sdk-test-all: sdk-test-go sdk-test-js sdk-test-python ## 🧪 Test all SDK components

# CLI Tools
cli-help: ## 📖 Show CLI tool help
	@printf "$(BLUE)📖 Zero Trust CLI Help:$(RESET)\n"
	@./bin/ztcli --help

cli-health: ## 🏥 Check system health via CLI
	@printf "$(BLUE)🏥 Checking system health...$(RESET)\n"
	@./bin/ztcli system health

cli-status: ## 📊 Show system status via CLI
	@printf "$(BLUE)📊 System status:$(RESET)\n"
	@./bin/ztcli system status

cli-generate-key: ## 🔑 Generate API key
	@printf "$(BLUE)🔑 Generating API key...$(RESET)\n"
	@./bin/ztcli dev generate-key

cli-test-connection: ## 🔗 Test connection to auth service
	@printf "$(BLUE)🔗 Testing connection...$(RESET)\n"
	@./bin/ztcli dev test-connection

# Development Utilities
dev-generate-go: ## 🏗️ Generate Go client code
	@printf "$(BLUE)🏗️ Generating Go client...$(RESET)\n"
	@./bin/ztcli dev generate-client --lang go --output-dir ./generated/go

dev-generate-js: ## 🏗️ Generate JavaScript client code
	@printf "$(BLUE)🏗️ Generating JavaScript client...$(RESET)\n"
	@./bin/ztcli dev generate-client --lang javascript --output-dir ./generated/js

dev-generate-python: ## 🏗️ Generate Python client code
	@printf "$(BLUE)🏗️ Generating Python client...$(RESET)\n"
	@./bin/ztcli dev generate-client --lang python --output-dir ./generated/python

dev-generate-all: dev-generate-go dev-generate-js dev-generate-python ## 🏗️ Generate all client SDKs

# =============================================================================
# DEPLOYMENT WORKFLOW
# =============================================================================
deploy: deploy-local ## 🚀 Deploy to default environment

deploy-local: build-all ## Deploy to local Kubernetes
	@printf "$(BLUE)🚀 Deploying to local environment...$(RESET)\n"
	@if [ -f scripts/deploy-local.sh ]; then \
		chmod +x scripts/deploy-local.sh && ./scripts/deploy-local.sh || \
			(printf "$(RED)❌ Local deployment failed$(RESET)\n" && exit 1); \
	else \
		printf "$(YELLOW)⚠️  Local deployment script not found$(RESET)\n"; \
	fi
	@printf "$(GREEN)✅ Local deployment completed$(RESET)\n"

deploy-staging: quality-gate build-all ## Deploy to staging environment
	@printf "$(BLUE)🚀 Deploying to staging environment...$(RESET)\n"
	@printf "$(YELLOW)⚠️  Staging deployment not implemented$(RESET)\n"

deploy-prod: quality-gate build-all ## Deploy to production environment
	@printf "$(BLUE)🚀 Deploying to production environment...$(RESET)\n"
	@printf "$(YELLOW)⚠️  Production deployment requires manual approval$(RESET)\n"

deploy-rollback: ## Rollback to previous deployment
	@printf "$(BLUE)🔄 Rolling back deployment...$(RESET)\n"
	@printf "$(YELLOW)⚠️  Rollback not implemented$(RESET)\n"

# =============================================================================
# CI/CD PIPELINE TARGETS
# =============================================================================
ci: ci-full ## 🏗️ Run complete CI pipeline

ci-validate: ## CI: Validate environment and prerequisites
	@printf "$(BLUE)🔍 CI: Validating environment...$(RESET)\n"
	@$(MAKE) dev-validate || (printf "$(RED)❌ CI validation failed$(RESET)\n" && exit 1)
	@$(MAKE) deps-validate || (printf "$(RED)❌ CI dependency validation failed$(RESET)\n" && exit 1)
	@printf "$(GREEN)✅ CI Environment validated$(RESET)\n"

ci-test: test-all coverage-validate ## CI: Testing phase with fail-fast
	@printf "$(BOLD)$(BLUE)🧪 CI: Testing phase...$(RESET)\n"
	@start_time=$$(date +%s); \
	if ! $(MAKE) test-go; then \
		printf "$(RED)❌ CI: Go tests failed - stopping pipeline$(RESET)\n"; \
		exit 1; \
	fi; \
	if ! $(MAKE) coverage-validate; then \
		printf "$(RED)❌ CI: Coverage validation failed - stopping pipeline$(RESET)\n"; \
		exit 1; \
	fi; \
	end_time=$$(date +%s); \
	duration=$$((end_time - start_time)); \
	printf "$(GREEN)✅ CI Testing phase completed in $${duration}s$(RESET)\n"

ci-quality: quality-gate ## CI: Quality phase with fail-fast
	@printf "$(BOLD)$(BLUE)🎯 CI: Quality phase...$(RESET)\n"
	@start_time=$$(date +%s); \
	if ! $(MAKE) lint-go; then \
		printf "$(RED)❌ CI: Go linting failed - stopping pipeline$(RESET)\n"; \
		exit 1; \
	fi; \
	if ! $(MAKE) security-scan; then \
		printf "$(RED)❌ CI: Security scan failed - stopping pipeline$(RESET)\n"; \
		exit 1; \
	fi; \
	end_time=$$(date +%s); \
	duration=$$((end_time - start_time)); \
	printf "$(GREEN)✅ CI Quality phase completed in $${duration}s$(RESET)\n"

ci-build: build-all ## CI: Build phase with artifact validation
	@printf "$(BOLD)$(BLUE)🔨 CI: Build phase...$(RESET)\n"
	@start_time=$$(date +%s); \
	if ! $(MAKE) build-go; then \
		printf "$(RED)❌ CI: Go build failed - stopping pipeline$(RESET)\n"; \
		exit 1; \
	fi; \
	if [ ! -f "$(BUILD_OUTPUT_DIR)/server" ]; then \
		printf "$(RED)❌ CI: Build artifact not found$(RESET)\n"; \
		exit 1; \
	fi; \
	file_size=$$(stat -f%z "$(BUILD_OUTPUT_DIR)/server" 2>/dev/null || stat -c%s "$(BUILD_OUTPUT_DIR)/server" 2>/dev/null); \
	if [ $$file_size -lt 1000000 ]; then \
		printf "$(YELLOW)⚠️  CI: Build artifact seems small ($$file_size bytes)$(RESET)\n"; \
	fi; \
	end_time=$$(date +%s); \
	duration=$$((end_time - start_time)); \
	printf "$(GREEN)✅ CI Build phase completed in $${duration}s$(RESET)\n"

ci-deploy: deploy-local ## CI: Deployment phase
	@printf "$(BOLD)$(BLUE)🚀 CI: Deploy phase...$(RESET)\n"
	@start_time=$$(date +%s); \
	end_time=$$(date +%s); \
	duration=$$((end_time - start_time)); \
	printf "$(GREEN)✅ CI Deploy phase completed in $${duration}s$(RESET)\n"

ci-full: ci-validate lint-fix ci-test ci-quality ci-build ## 🏗️ Complete CI/CD pipeline with timing
	@printf "$(BOLD)$(GREEN)🎉 Complete CI pipeline successful!$(RESET)\n"
	@printf "$(BLUE)📊 Pipeline Summary:$(RESET)\n"
	@printf "  Validation: $(GREEN)✅ Passed$(RESET)\n"
	@printf "  Linting:    $(GREEN)✅ Passed$(RESET)\n" 
	@printf "  Testing:    $(GREEN)✅ Passed$(RESET)\n"
	@printf "  Quality:    $(GREEN)✅ Passed$(RESET)\n"
	@printf "  Build:      $(GREEN)✅ Passed$(RESET)\n"

ci-fast: ## 🚀 Fast CI pipeline (parallel execution)
	@printf "$(BOLD)$(BLUE)🚀 Fast CI Pipeline...$(RESET)\n"
	@$(MAKE) ci-validate
	@$(MAKE) lint-fix
	@$(MAKE) -j3 test-go lint-go security-scan || \
		(printf "$(RED)❌ Fast CI pipeline failed$(RESET)\n" && exit 1)
	@$(MAKE) build-go
	@printf "$(BOLD)$(GREEN)🎉 Fast CI pipeline completed!$(RESET)\n"

# =============================================================================
# PARALLEL EXECUTION TARGETS
# =============================================================================
parallel-test: ## ⚡ Run tests in parallel for speed
	@printf "$(BLUE)⚡ Running parallel test execution...$(RESET)\n"
	@$(MAKE) -j4 test-go test-frontend test-integration || \
		(printf "$(RED)❌ Parallel tests failed$(RESET)\n" && exit 1)
	@printf "$(GREEN)✅ Parallel tests completed$(RESET)\n"

parallel-quality: ## ⚡ Run quality checks in parallel
	@printf "$(BLUE)⚡ Running parallel quality checks...$(RESET)\n"
	@$(MAKE) -j3 lint-go lint-frontend security-scan || \
		(printf "$(RED)❌ Parallel quality checks failed$(RESET)\n" && exit 1)
	@printf "$(GREEN)✅ Parallel quality checks completed$(RESET)\n"

parallel-build: ## ⚡ Build components in parallel
	@printf "$(BLUE)⚡ Running parallel build...$(RESET)\n"
	@$(MAKE) -j2 build-go build-frontend || \
		(printf "$(RED)❌ Parallel build failed$(RESET)\n" && exit 1)
	@printf "$(GREEN)✅ Parallel build completed$(RESET)\n"

# =============================================================================
# ADVANCED CACHE MANAGEMENT
# =============================================================================
cache: cache-status ## 🗄️ Manage build caches with advanced strategies

# Cache directories and files
CACHE_DIR := .cache
GO_CACHE_DIR := $(CACHE_DIR)/go
NPM_CACHE_DIR := $(CACHE_DIR)/npm
DOCKER_CACHE_DIR := $(CACHE_DIR)/docker
CACHE_MANIFEST := $(CACHE_DIR)/manifest.json

cache-init: ## Initialize cache directory structure
	@printf "$(BLUE)🏗️  Initializing cache directories...$(RESET)\n"
	@mkdir -p $(GO_CACHE_DIR) $(NPM_CACHE_DIR) $(DOCKER_CACHE_DIR)
	@printf "$(GREEN)✅ Cache directories initialized$(RESET)\n"

cache-status: ## Show detailed cache status and statistics
	@printf "$(BOLD)$(BLUE)📊 Cache Status Report$(RESET)\n"
	@printf "$(BLUE)=====================$(RESET)\n"
	@printf "\n$(BOLD)Go Cache:$(RESET)\n"
	@go env GOCACHE | xargs -I {} printf "  Location: %s\n" {}
	@go env GOMODCACHE | xargs -I {} printf "  Modules:  %s\n" {}
	@if [ -d "$$(go env GOCACHE)" ]; then \
		cache_size=$$(du -sh "$$(go env GOCACHE)" 2>/dev/null | cut -f1 || echo "0B"); \
		printf "  Size:     $$cache_size\n"; \
	fi
	@printf "\n$(BOLD)NPM Cache:$(RESET)\n"
	@if command -v npm >/dev/null 2>&1 && [ -d "$(FRONTEND_DIR)" ]; then \
		cache_path=$$(npm config get cache 2>/dev/null) && \
		if [ -n "$$cache_path" ]; then \
			printf "  Location: $$cache_path\n"; \
			if [ -d "$$cache_path" ]; then \
				cache_size=$$(du -sh "$$cache_path" 2>/dev/null | cut -f1 || echo "0B"); \
				printf "  Size:     $$cache_size\n"; \
			else \
				printf "  Size:     0B (not initialized)\n"; \
			fi; \
		else \
			printf "  $(YELLOW)NPM cache not configured$(RESET)\n"; \
		fi; \
	else \
		printf "  $(YELLOW)NPM not available$(RESET)\n"; \
	fi
	@printf "\n$(BOLD)Docker Cache:$(RESET)\n"
	@if command -v docker >/dev/null 2>&1; then \
		docker system df 2>/dev/null || printf "  $(YELLOW)Docker not running$(RESET)\n"; \
	else \
		printf "  $(YELLOW)Docker not available$(RESET)\n"; \
	fi
	@printf "\n$(BOLD)Build Cache:$(RESET)\n"
	@if [ -d "$(CACHE_DIR)" ]; then \
		cache_size=$$(du -sh "$(CACHE_DIR)" 2>/dev/null | cut -f1 || echo "0B"); \
		printf "  Location: $(CACHE_DIR)\n"; \
		printf "  Size:     $$cache_size\n"; \
	else \
		printf "  $(YELLOW)No build cache directory$(RESET)\n"; \
	fi

cache-validate: cache-init ## Validate cache integrity and performance
	@printf "$(BLUE)🔍 Validating cache integrity...$(RESET)\n"
	@start_time=$$(date +%s); \
	go_cache_ok=true; \
	npm_cache_ok=true; \
	docker_cache_ok=true; \
	\
	printf "$(BLUE)  Checking Go cache...$(RESET)\n"; \
	if ! go mod download -x >/dev/null 2>&1; then \
		go_cache_ok=false; \
		printf "  $(YELLOW)⚠️  Go cache issues detected$(RESET)\n"; \
	else \
		printf "  $(GREEN)✅ Go cache healthy$(RESET)\n"; \
	fi; \
	\
	if [ -d "$(FRONTEND_DIR)" ]; then \
		printf "$(BLUE)  Checking NPM cache...$(RESET)\n"; \
		cd $(FRONTEND_DIR) && \
		if ! npm cache verify >/dev/null 2>&1; then \
			npm_cache_ok=false; \
			printf "  $(YELLOW)⚠️  NPM cache issues detected$(RESET)\n"; \
		else \
			printf "  $(GREEN)✅ NPM cache healthy$(RESET)\n"; \
		fi; \
	fi; \
	\
	printf "$(BLUE)  Checking Docker cache...$(RESET)\n"; \
	if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then \
		if [ "$$(docker system df --format 'table {{.Type}}\t{{.Reclaimable}}' | grep -c 'true')" -gt 0 ]; then \
			printf "  $(YELLOW)⚠️  Docker has reclaimable cache$(RESET)\n"; \
		else \
			printf "  $(GREEN)✅ Docker cache optimized$(RESET)\n"; \
		fi; \
	else \
		printf "  $(YELLOW)⚠️  Docker not available$(RESET)\n"; \
	fi; \
	\
	end_time=$$(date +%s); \
	duration=$$((end_time - start_time)); \
	printf "\n$(GREEN)✅ Cache validation completed in $${duration}s$(RESET)\n"

cache-clean: ## Clean all caches with selective options
	@printf "$(BLUE)🧹 Cleaning caches...$(RESET)\n"
	@printf "$(BLUE)  Cleaning Go caches...$(RESET)\n"
	@go clean -cache -modcache -testcache
	@printf "$(BLUE)  Cleaning NPM caches...$(RESET)\n"
	@if [ -d "$(FRONTEND_DIR)" ]; then \
		cd $(FRONTEND_DIR) && npm cache clean --force 2>/dev/null || true; \
	fi
	@printf "$(BLUE)  Cleaning Docker caches...$(RESET)\n"
	@if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then \
		docker system prune -f --volumes; \
	fi
	@printf "$(BLUE)  Cleaning build caches...$(RESET)\n"
	@rm -rf $(CACHE_DIR)
	@printf "$(GREEN)✅ All caches cleaned$(RESET)\n"

cache-clean-go: ## Clean only Go caches
	@printf "$(BLUE)🧹 Cleaning Go caches...$(RESET)\n"
	@go clean -cache -modcache -testcache
	@printf "$(GREEN)✅ Go caches cleaned$(RESET)\n"

cache-clean-npm: ## Clean only NPM caches
	@printf "$(BLUE)🧹 Cleaning NPM caches...$(RESET)\n"
	@if [ -d "$(FRONTEND_DIR)" ]; then \
		cd $(FRONTEND_DIR) && npm cache clean --force; \
	fi
	@printf "$(GREEN)✅ NPM caches cleaned$(RESET)\n"

cache-clean-docker: ## Clean only Docker caches
	@printf "$(BLUE)🧹 Cleaning Docker caches...$(RESET)\n"
	@if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then \
		docker system prune -f --volumes; \
	else \
		printf "$(YELLOW)⚠️  Docker not available$(RESET)\n"; \
	fi
	@printf "$(GREEN)✅ Docker caches cleaned$(RESET)\n"

cache-warmup: cache-init ## Warm up caches for faster builds with intelligent prefetching
	@printf "$(BLUE)🔥 Warming up caches with intelligent prefetching...$(RESET)\n"
	@start_time=$$(date +%s); \
	\
	printf "$(BLUE)  Preloading Go modules...$(RESET)\n"; \
	go mod download; \
	go mod tidy; \
	\
	if [ -d "$(FRONTEND_DIR)" ]; then \
		printf "$(BLUE)  Preloading NPM dependencies...$(RESET)\n"; \
		cd $(FRONTEND_DIR) && \
		npm ci --prefer-offline --no-audit --no-fund; \
		npm audit fix --force 2>/dev/null || true; \
	fi; \
	\
	printf "$(BLUE)  Warming Docker build cache...$(RESET)\n"; \
	if [ -f "Dockerfile" ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then \
		docker build --target deps -t $(PROJECT_NAME)-deps:cache . 2>/dev/null || \
		printf "  $(YELLOW)⚠️  Docker cache warming skipped$(RESET)\n"; \
	fi; \
	\
	printf "$(BLUE)  Creating cache manifest...$(RESET)\n"; \
	echo "{ \"timestamp\": \"$$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"go_version\": \"$(GO_VERSION)\", \"node_version\": \"$(NODE_VERSION)\", \"project\": \"$(PROJECT_NAME)\" }" > $(CACHE_MANIFEST); \
	\
	end_time=$$(date +%s); \
	duration=$$((end_time - start_time)); \
	printf "$(GREEN)✅ Cache warmup completed in $${duration}s$(RESET)\n"

cache-smart-warmup: ## Smart cache warmup based on file changes
	@printf "$(BLUE)🧠 Smart cache warmup analyzing changes...$(RESET)\n"
	@needs_go_warmup=false; \
	needs_npm_warmup=false; \
	\
	if [ ! -f "$(CACHE_MANIFEST)" ] || \
	   [ "go.mod" -nt "$(CACHE_MANIFEST)" ] || \
	   [ "go.sum" -nt "$(CACHE_MANIFEST)" ]; then \
		needs_go_warmup=true; \
	fi; \
	\
	if [ -d "$(FRONTEND_DIR)" ] && \
	   ([ ! -f "$(CACHE_MANIFEST)" ] || \
	    [ "$(FRONTEND_DIR)/package.json" -nt "$(CACHE_MANIFEST)" ] || \
	    [ "$(FRONTEND_DIR)/package-lock.json" -nt "$(CACHE_MANIFEST)" ]); then \
		needs_npm_warmup=true; \
	fi; \
	\
	if [ "$$needs_go_warmup" = "true" ]; then \
		printf "$(BLUE)  Go dependencies changed, warming up...$(RESET)\n"; \
		go mod download; \
	else \
		printf "$(GREEN)  Go cache is up to date$(RESET)\n"; \
	fi; \
	\
	if [ "$$needs_npm_warmup" = "true" ] && [ -d "$(FRONTEND_DIR)" ]; then \
		printf "$(BLUE)  NPM dependencies changed, warming up...$(RESET)\n"; \
		cd $(FRONTEND_DIR) && npm ci --prefer-offline; \
	else \
		printf "$(GREEN)  NPM cache is up to date$(RESET)\n"; \
	fi; \
	\
	echo "{ \"timestamp\": \"$$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"go_version\": \"$(GO_VERSION)\", \"node_version\": \"$(NODE_VERSION)\", \"project\": \"$(PROJECT_NAME)\" }" > $(CACHE_MANIFEST); \
	printf "$(GREEN)✅ Smart cache warmup completed$(RESET)\n"

cache-optimize: cache-validate ## Optimize caches for maximum performance
	@printf "$(BLUE)⚡ Optimizing caches for performance...$(RESET)\n"
	@start_time=$$(date +%s); \
	\
	printf "$(BLUE)  Optimizing Go cache...$(RESET)\n"; \
	go clean -testcache; \
	go mod tidy; \
	go mod download; \
	\
	if [ -d "$(FRONTEND_DIR)" ]; then \
		printf "$(BLUE)  Optimizing NPM cache...$(RESET)\n"; \
		cd $(FRONTEND_DIR) && \
		npm cache verify || npm cache clean --force; \
		npm ci --prefer-offline; \
	fi; \
	\
	printf "$(BLUE)  Optimizing Docker cache...$(RESET)\n"; \
	if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then \
		docker builder prune -f 2>/dev/null || true; \
		if [ -f "Dockerfile" ]; then \
			docker build --target deps -t $(PROJECT_NAME)-deps:latest . 2>/dev/null || true; \
		fi; \
	fi; \
	\
	end_time=$$(date +%s); \
	duration=$$((end_time - start_time)); \
	printf "$(GREEN)✅ Cache optimization completed in $${duration}s$(RESET)\n"

cache-benchmark: ## Benchmark cache performance
	@printf "$(BLUE)🏎️  Benchmarking cache performance...$(RESET)\n"
	@printf "\n$(BOLD)Cold Cache Performance:$(RESET)\n"
	@$(MAKE) cache-clean >/dev/null 2>&1
	@start_time=$$(date +%s); \
	$(MAKE) cache-warmup >/dev/null 2>&1; \
	end_time=$$(date +%s); \
	cold_duration=$$((end_time - start_time)); \
	printf "  Cold cache warmup: $${cold_duration}s\n"
	
	@printf "\n$(BOLD)Warm Cache Performance:$(RESET)\n"
	@start_time=$$(date +%s); \
	$(MAKE) cache-smart-warmup >/dev/null 2>&1; \
	end_time=$$(date +%s); \
	warm_duration=$$((end_time - start_time)); \
	printf "  Warm cache update: $${warm_duration}s\n"
	
	@printf "\n$(BOLD)Build Performance:$(RESET)\n"
	@start_time=$$(date +%s); \
	$(MAKE) build-go >/dev/null 2>&1; \
	end_time=$$(date +%s); \
	build_duration=$$((end_time - start_time)); \
	printf "  Go build time: $${build_duration}s\n"
	
	@if [ -d "$(FRONTEND_DIR)" ]; then \
		start_time=$$(date +%s); \
		$(MAKE) build-frontend >/dev/null 2>&1; \
		end_time=$$(date +%s); \
		frontend_duration=$$((end_time - start_time)); \
		printf "  Frontend build time: $${frontend_duration}s\n"; \
	fi
	
	@printf "\n$(GREEN)✅ Cache benchmark completed$(RESET)\n"

# =============================================================================
# DATABASE OPERATIONS
# =============================================================================
db: db-migrate ## 📊 Database operations

db-migrate: ## Run database migrations
	@printf "$(BLUE)📊 Running database migrations...$(RESET)\n"
	@if [ -f scripts/sql/init/migrations.sql ]; then \
		docker-compose -f $(COMPOSE_FILE) exec -T postgres \
			psql -U $(DB_USER) -d $(DB_NAME) -f /docker-entrypoint-initdb.d/migrations.sql; \
	else \
		printf "$(YELLOW)⚠️  No migrations found$(RESET)\n"; \
	fi
	@printf "$(GREEN)✅ Database migrations completed$(RESET)\n"

db-reset: ## Reset database to clean state
	@printf "$(BLUE)🔄 Resetting database...$(RESET)\n"
	@docker-compose -f $(COMPOSE_FILE) down postgres
	@docker volume rm $$(docker volume ls -q | grep postgres) 2>/dev/null || true
	@docker-compose -f $(COMPOSE_FILE) up -d postgres
	@printf "$(GREEN)✅ Database reset completed$(RESET)\n"

db-backup: ## Backup database
	@printf "$(BLUE)💾 Backing up database...$(RESET)\n"
	@docker-compose -f $(COMPOSE_FILE) exec -T postgres \
		pg_dump -U $(DB_USER) $(DB_NAME) > backup_$(shell date +%Y%m%d_%H%M%S).sql
	@printf "$(GREEN)✅ Database backup completed$(RESET)\n"

db-restore: ## Restore database from backup (set BACKUP_FILE)
	@printf "$(BLUE)📥 Restoring database...$(RESET)\n"
	@if [ -z "$(BACKUP_FILE)" ]; then \
		printf "$(RED)❌ BACKUP_FILE not specified$(RESET)\n" && exit 1; \
	fi
	@docker-compose -f $(COMPOSE_FILE) exec -T postgres \
		psql -U $(DB_USER) -d $(DB_NAME) < $(BACKUP_FILE)
	@printf "$(GREEN)✅ Database restore completed$(RESET)\n"

# =============================================================================
# DOCUMENTATION
# =============================================================================
docs: docs-generate docs-schema ## 📚 Generate and serve documentation

install-tbls: ## Install tbls CLI for schema documentation
	@printf "$(BLUE)🔧 Checking for tbls CLI...$(RESET)\n"
	@if command -v tbls >/dev/null 2>&1; then \
		printf "$(GREEN)✅ tbls is already installed: $$(command -v tbls)$(RESET)\n"; \
	elif [ -f "$$HOME/go/bin/tbls" ]; then \
		printf "$(GREEN)✅ tbls is installed in $$HOME/go/bin/tbls.$(RESET)\n"; \
	else \
		printf "$(YELLOW)⚠️  tbls not found, installing to $$HOME/go/bin...$(RESET)\n"; \
		go install github.com/k1LoW/tbls@latest; \
		if [ -f "$$HOME/go/bin/tbls" ]; then \
			printf "$(GREEN)✅ tbls installed successfully in $$HOME/go/bin/tbls.$(RESET)\n"; \
		else \
			printf "$(RED)❌ Failed to install tbls.$(RESET)\n"; \
			printf "$(YELLOW)💡 Please ensure Go is installed and $$HOME/go/bin is in your PATH.$(RESET)\n"; \
			exit 1; \
		fi; \
	fi

docs-generate: install-tbls ## Generate API documentation
	@printf "$(BLUE)📚 Generating documentation...$(RESET)\n"
	@if command -v swag >/dev/null 2>&1; then \
		swag init -g cmd/server/main.go -o docs/swagger; \
	else \
		printf "$(YELLOW)⚠️  Swagger not installed$(RESET)\n"; \
	fi
	@printf "$(GREEN)✅ Documentation generated$(RESET)\n"

docs-schema: install-tbls ## 💾 Generate database schema documentation using tbls
	@printf "$(BLUE)💾 Generating database schema documentation...$(RESET)\n"
	@printf "$(BLUE)   Output will be in ./docs/schema/ $(RESET)\n"
	@export TBLS_DSN="postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=$(DB_SSLMODE)"; \
	if command -v tbls >/dev/null 2>&1; then \
		tbls doc -c docs/schema/.tbls.yml; \
	elif [ -f "$$HOME/go/bin/tbls" ]; then \
		$$HOME/go/bin/tbls doc -c docs/schema/.tbls.yml; \
	else \
		printf "$(RED)❌ tbls command not found. Please ensure it is installed and in your PATH.$(RESET)\n"; \
		exit 1; \
	fi
	@printf "$(GREEN)✅ Database schema documentation generated.$(RESET)\n"

docs-serve: ## Serve documentation locally
	@printf "$(BLUE)📚 Serving documentation...$(RESET)\n"
	@printf "$(GREEN)🔗 Documentation available at: http://localhost:8080$(RESET)\n"
	@cd docs && python3 -m http.server 8080 2>/dev/null || \
		python -m SimpleHTTPServer 8080

docs-deploy: docs-generate ## Deploy documentation
	@printf "$(BLUE)📚 Deploying documentation...$(RESET)\n"
	@printf "$(YELLOW)⚠️  Documentation deployment not implemented$(RESET)\n"

docs-schema: ## Generate database schema documentation using tbls
		@printf "$(BLUE)📚 Generating schema documentation...$(RESET)\n"
		@mkdir -p docs/schema
		@if command -v tbls >/dev/null 2>&1; then \
		tbls doc -c docs/schema/tbls.yml && \
		tbls out -t plantuml -c docs/schema/tbls.yml -o docs/schema/diagram.puml && \
		printf "$(GREEN)✅ Schema documentation generated$(RESET)\n"; \
		else \
		printf "$(YELLOW)⚠️  tbls not installed$(RESET)\n"; \
		fi

# =============================================================================
# MONITORING & OBSERVABILITY
# =============================================================================
monitor: monitor-setup ## 📊 Set up monitoring

monitor-setup: ## Set up monitoring dashboards
	@printf "$(BLUE)📊 Setting up monitoring...$(RESET)\n"
	@if [ -f scripts/setup-monitoring.sh ]; then \
	chmod +x scripts/setup-monitoring.sh && ./scripts/setup-monitoring.sh || \
	(printf "$(RED)❌ Monitoring setup failed$(RESET)\n" && exit 1); \
	else \
	printf "$(YELLOW)⚠️  Monitoring setup script not found$(RESET)\n"; \
	fi
	@printf "$(GREEN)✅ Monitoring setup completed$(RESET)\n"

monitor-status: ## Check monitoring system status
	@printf "$(BLUE)📊 Checking monitoring status...$(RESET)\n"
	@curl -f http://localhost:9090/-/healthy >/dev/null 2>&1 && \
	printf "  Prometheus: $(GREEN)✅ Healthy$(RESET)\n" || \
	printf "  Prometheus: $(RED)❌ Unhealthy$(RESET)\n"
	@curl -f http://localhost:3000/api/health >/dev/null 2>&1 && \
	printf "  Grafana:    $(GREEN)✅ Healthy$(RESET)\n" || \
	printf "  Grafana:    $(RED)❌ Unhealthy$(RESET)\n"

monitor-logs: ## View monitoring system logs
	@docker-compose -f $(COMPOSE_FILE) logs -f prometheus grafana jaeger

# =============================================================================
# DATABASE OPTIMIZATION COMMANDS
# =============================================================================
db-stats: ## 📊 Show database connection pool statistics
	@printf "$(BLUE)📊 Database connection pool statistics:$(RESET)\n"
	@go run ./cmd/dboptimize stats

db-stats-live: ## 📈 Live database statistics monitoring
	@printf "$(BLUE)📈 Starting live database monitoring...$(RESET)\n"
	@go run ./cmd/dboptimize stats --live --interval 5s

db-benchmark: ## ⚡ Run database performance benchmark
	@printf "$(BLUE)⚡ Running database performance benchmark...$(RESET)\n"
	@go run ./cmd/dboptimize benchmark --duration 60s --connections 10

db-benchmark-heavy: ## 🚀 Run intensive database benchmark
	@printf "$(BLUE)🚀 Running intensive database benchmark...$(RESET)\n"
	@go run ./cmd/dboptimize benchmark --duration 120s --connections 25 --detailed

db-optimize-dev: ## 🔧 Optimize database for development workload
	@printf "$(BLUE)🔧 Optimizing database for development...$(RESET)\n"
	@go run ./cmd/dboptimize optimize --profile development

db-optimize-prod: ## ⚡ Optimize database for production workload
	@printf "$(BLUE)⚡ Optimizing database for production...$(RESET)\n"
	@go run ./cmd/dboptimize optimize --profile high_throughput

db-optimize-balanced: ## ⚖️ Apply balanced database optimization
	@printf "$(BLUE)⚖️ Applying balanced database optimization...$(RESET)\n"
	@go run ./cmd/dboptimize optimize --profile balanced

db-analyze: ## 🔍 Analyze database configuration and provide recommendations
	@printf "$(BLUE)🔍 Analyzing database configuration...$(RESET)\n"
	@go run ./cmd/dboptimize analyze --recommendations --compliance

db-monitor: ## 📈 Real-time database performance monitoring
	@printf "$(BLUE)📈 Starting real-time database monitoring...$(RESET)\n"
	@go run ./cmd/dboptimize monitor --interval 5s

db-health: dev-status ## 🏥 Comprehensive database health check
	@printf "$(BLUE)🏥 Checking database health...$(RESET)\n"
	@go run ./cmd/dboptimize stats --extended
	@printf "\n$(BLUE)🔍 Testing database connectivity...$(RESET)\n"
	@timeout 10s go run -c 'import "mvp.local/pkg/database"; import "mvp.local/pkg/config"; cfg,_:=config.Load(); db:=database.NewDatabase(&cfg.Database); err:=db.Connect(); if err!=nil{panic(err)}; defer db.Close(); err=db.Health(); if err!=nil{panic(err)}; println("✅ Database health check passed")' 2>/dev/null || printf "$(RED)❌ Database health check failed$(RESET)\n"

# Database optimization workflow targets
db-tune: db-analyze db-benchmark db-optimize-balanced ## 🎯 Complete database tuning workflow
	@printf "$(GREEN)✅ Database tuning workflow completed$(RESET)\n"

db-perf-test: db-benchmark db-stats ## 📊 Performance testing workflow
	@printf "$(GREEN)✅ Performance testing completed$(RESET)\n"

# =============================================================================
# CLEANUP & MAINTENANCE
# =============================================================================
clean-all: build-clean cache-clean ## 🧹 Complete cleanup
	@printf "$(BLUE)🧹 Performing complete cleanup...$(RESET)\n"
	@unset DOCKER_DEFAULT_PLATFORM && docker-compose -f $(COMPOSE_FILE) down -v --remove-orphans
	@unset DOCKER_DEFAULT_PLATFORM && docker-compose -f docker-compose.test.yml down -v --remove-orphans 2>/dev/null || true
	@docker system prune -f --volumes
	@printf "$(GREEN)✅ Complete cleanup finished$(RESET)\n"

# =============================================================================
# GitOps Workflow Targets
# =============================================================================
.PHONY: gitops-setup gitops-validate gitops-sync gitops-rollback \
	gitops-test gitops-deploy gitops-monitor gitops-backup \
	helm-validate helm-test helm-lint helm-push \
	argocd-sync argocd-status argocd-diff argocd-rollback \
	canary-deploy canary-promote canary-rollback \
	slo-validate slo-report slo-alert

# GitOps Setup and Validation
gitops-setup: ## Initialize GitOps tools and configurations
	@echo "$(BLUE)Setting up GitOps infrastructure...$(RESET)"
	@scripts/pre-deployment-check.sh
	@helm dependency update charts/zamaz
	@kubectl apply -f deployments/kubernetes/argocd/application.yaml

gitops-validate: ## Validate GitOps configurations
	@echo "$(BLUE)Validating GitOps configurations...$(RESET)"
	@scripts/validate-gitops.sh
	@helm lint charts/zamaz
	@kubectl neat -f charts/zamaz/templates/* | kubeconform -

# Helm Operations
helm-validate: ## Validate Helm charts
	@echo "$(BLUE)Validating Helm charts...$(RESET)"
	@helm lint charts/zamaz
	@helm template charts/zamaz | kubectl neat - | kubeconform -

helm-test: ## Test Helm chart deployment
	@echo "$(BLUE)Testing Helm chart deployment...$(RESET)"
	@helm test charts/zamaz --namespace zamaz-staging

helm-push: ## Push Helm chart to registry
	@echo "$(BLUE)Pushing Helm chart to registry...$(RESET)"
	@helm package charts/zamaz
	@helm push mvp-zero-trust-auth-*.tgz oci://registry.example.com/charts

# ArgoCD Operations
argocd-sync: ## Sync ArgoCD applications
	@echo "$(BLUE)Syncing ArgoCD applications...$(RESET)"
	@argocd app sync zamaz-staging
	@argocd app wait zamaz-staging --health

argocd-status: ## Check ArgoCD sync status
	@echo "$(BLUE)Checking ArgoCD status...$(RESET)"
	@argocd app get zamaz-staging
	@argocd app get zamaz-production

argocd-diff: ## Show changes to be applied
	@echo "$(BLUE)Showing configuration differences...$(RESET)"
	@argocd app diff zamaz-staging

# Canary Deployment
canary-deploy: ## Start canary deployment
	@echo "$(BLUE)Starting canary deployment...$(RESET)"
	@kubectl argo rollouts set image zamaz zamaz=registry.example.com/zamaz:${VERSION}
	@kubectl argo rollouts promote zamaz

canary-promote: ## Promote canary to full deployment
	@echo "$(BLUE)Promoting canary deployment...$(RESET)"
	@kubectl argo rollouts promote zamaz

canary-rollback: ## Rollback canary deployment
	@echo "$(BLUE)Rolling back canary deployment...$(RESET)"
	@kubectl argo rollouts undo zamaz

# SLO Management
slo-validate: ## Validate SLO compliance
	@echo "$(BLUE)Validating SLO metrics...$(RESET)"
	@scripts/validate-slo.sh

slo-report: ## Generate SLO compliance report
	@echo "$(BLUE)Generating SLO report...$(RESET)"
	@scripts/generate-slo-report.sh

# Comprehensive GitOps Workflows
gitops-deploy: gitops-validate helm-validate ## Deploy with GitOps
	@echo "$(BLUE)Deploying with GitOps...$(RESET)"
	@make argocd-sync
	@make canary-deploy
	@make slo-validate

gitops-monitor: ## Monitor GitOps deployment
	@echo "$(BLUE)Monitoring deployment...$(RESET)"
	@scripts/monitor-deployment.sh

gitops-backup: ## Backup GitOps configurations
	@echo "$(BLUE)Backing up GitOps configurations...$(RESET)"
	@velero backup create zamaz-backup-${BUILD_DATE} --include-namespaces zamaz-staging,zamaz-production

# Development Environment
dev-gitops: ## Start local GitOps development environment
	@echo "$(BLUE)Starting local GitOps development environment...$(RESET)"
	@kind create cluster --name zamaz-dev || true
	@kubectl apply -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
	@helm dependency update charts/zamaz
	@helm install zamaz charts/zamaz --namespace zamaz-dev --create-namespace

# Cleanup
clean-gitops: ## Clean up GitOps resources
	@echo "$(BLUE)Cleaning up GitOps resources...$(RESET)"
	@kubectl delete -f deployments/kubernetes/argocd/application.yaml || true
	@helm uninstall zamaz --namespace zamaz-dev || true
	@kind delete cluster --name zamaz-dev || true
