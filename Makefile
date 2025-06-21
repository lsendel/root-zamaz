# =============================================================================
# MVP Zero Trust Auth System - User-Friendly Makefile
# =============================================================================
# Organized by common usage patterns and user workflows
# =============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

# Load environment variables from .env file if it exists
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

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
NATS_URL ?= nats://localhost:4222
REDIS_URL ?= redis://localhost:6379
FRONTEND_DIR := frontend
BUILD_OUTPUT_DIR := bin
COVERAGE_THRESHOLD := 80

# GitHub Configuration (from .env)
GITHUB_TOKEN ?= 
GITHUB_OWNER ?= lsendel
GITHUB_REPO ?= root-zamaz
GITHUB_WIKI_URL := https://github.com/$(GITHUB_OWNER)/$(GITHUB_REPO)/wiki

# Documentation Configuration
DOCS_PORT ?= 8001
DOCS_HOST ?= 127.0.0.1
WIKI_SYNC_ENABLED ?= true
WIKI_BRANCH ?= main
WIKI_SUBDIRECTORY ?= Documentation

# Colors
BLUE := \033[34m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
RESET := \033[0m
BOLD := \033[1m

# =============================================================================
# 🚀 QUICK START COMMANDS (Most Common)
# =============================================================================

.PHONY: help start stop status dev test build clean

help: ## 📖 Show this help (most common commands at top)
	@printf "\n$(BOLD)$(BLUE)MVP Zero Trust Auth System$(RESET)\n"
	@printf "$(BLUE)================================$(RESET)\n\n"
	@printf "$(BOLD)🔧 FIRST TIME SETUP:$(RESET)\n"
	@printf "  $(GREEN)make env-setup$(RESET)   🔧 Setup environment configuration (.env)\n"
	@printf "  $(GREEN)make env-check$(RESET)   🔍 Check environment configuration\n\n"
	@printf "$(BOLD)🚀 QUICK START:$(RESET)\n"
	@printf "  $(GREEN)make start$(RESET)       🚀 Start the full development environment\n"
	@printf "  $(GREEN)make dev$(RESET)         💻 Start development server with hot reload\n"
	@printf "  $(GREEN)make test$(RESET)        🧪 Run all tests\n"
	@printf "  $(GREEN)make build$(RESET)       🔨 Build the application\n"
	@printf "  $(GREEN)make stop$(RESET)        🛑 Stop all services\n"
	@printf "  $(GREEN)make clean$(RESET)       🧹 Clean all artifacts\n"
	@printf "  $(GREEN)make status$(RESET)      📊 Show system status\n\n"
	@printf "$(BOLD)📚 DETAILED HELP:$(RESET)\n"
	@printf "  $(BLUE)make dev-help$(RESET)        Development workflow commands\n"
	@printf "  $(BLUE)make test-help$(RESET)       Testing and quality commands\n"
	@printf "  $(BLUE)make docs-help$(RESET)       Documentation commands\n"
	@printf "  $(BLUE)make docker-help$(RESET)     Docker and deployment commands\n"
	@printf "  $(BLUE)make db-help$(RESET)         Database management commands\n"
	@printf "  $(BLUE)make matrix-help$(RESET)     Matrix testing across versions\n"
	@printf "  $(BLUE)make show-env$(RESET)        Show current environment config\n"
	@printf "  $(BLUE)make all-targets$(RESET)     Show ALL available targets\n\n"

start: dev-up ## 🚀 Start the full development environment
	@printf "$(GREEN)🚀 Development environment started!$(RESET)\n"
	@printf "$(BLUE)📍 Frontend: http://localhost:5173$(RESET)\n"
	@printf "$(BLUE)📍 Backend API: http://localhost:8080$(RESET)\n"

stop: dev-down ## 🛑 Stop all services

status: dev-status ## 📊 Show system status

dev: dev-frontend ## 💻 Start development with hot reload

test: test-all ## 🧪 Run all tests

build: build-all ## 🔨 Build the application

clean: clean-all ## 🧹 Clean all artifacts

# =============================================================================
# 💻 DEVELOPMENT WORKFLOW
# =============================================================================

.PHONY: dev-help dev-setup dev-up dev-down dev-frontend dev-status dev-logs

dev-help: ## 💻 Show development workflow help
	@printf "\n$(BOLD)$(BLUE)Development Workflow$(RESET)\n"
	@printf "$(BLUE)=====================$(RESET)\n\n"
	@printf "$(BOLD)Setup & Environment:$(RESET)\n"
	@printf "  $(GREEN)make dev-setup$(RESET)    📦 Install all dependencies\n"
	@printf "  $(GREEN)make dev-up$(RESET)       🚀 Start all services (Docker)\n"
	@printf "  $(GREEN)make dev-down$(RESET)     🛑 Stop all services\n"
	@printf "  $(GREEN)make dev-status$(RESET)   📊 Check service status\n"
	@printf "  $(GREEN)make dev-logs$(RESET)     📜 View service logs\n\n"
	@printf "$(BOLD)Development Server:$(RESET)\n"
	@printf "  $(GREEN)make dev-frontend$(RESET) 💻 Start frontend dev server\n"
	@printf "  $(GREEN)make dev-backend$(RESET)  🔧 Start backend dev server\n\n"

dev-setup: ## 📦 Install all dependencies
	@printf "$(BLUE)📦 Setting up development environment...$(RESET)\n"
	@npm install
	@cd $(FRONTEND_DIR) && npm install
	@printf "$(GREEN)✅ Development environment ready$(RESET)\n"

dev-up: ## 🚀 Start all services with Docker Compose
	@printf "$(BLUE)🚀 Starting development services...$(RESET)\n"
	@docker-compose up -d
	@printf "$(GREEN)✅ Services started$(RESET)\n"

dev-down: ## 🛑 Stop all services
	@printf "$(BLUE)🛑 Stopping services...$(RESET)\n"
	@docker-compose down
	@printf "$(GREEN)✅ Services stopped$(RESET)\n"

dev-frontend: ## 💻 Start frontend development server
	@printf "$(BLUE)💻 Starting frontend development server...$(RESET)\n"
	@cd $(FRONTEND_DIR) && npm run dev

dev-backend: ## 🔧 Start backend development server
	@printf "$(BLUE)🔧 Starting backend development server...$(RESET)\n"
	@go run cmd/server/main.go

dev-status: ## 📊 Show development environment status
	@printf "$(BLUE)📊 Development Environment Status$(RESET)\n"
	@printf "$(BLUE)===================================$(RESET)\n"
	@printf "Docker Services:\n"
	@docker-compose ps
	@printf "\nSystem Info:\n"
	@printf "Node Version: $$(node --version 2>/dev/null || echo 'Not installed')\n"
	@printf "Go Version: $$(go version 2>/dev/null | cut -d' ' -f3 || echo 'Not installed')\n"

dev-logs: ## 📜 View service logs
	@docker-compose logs -f

# =============================================================================
# 🧪 TESTING & QUALITY
# =============================================================================

.PHONY: test-help test-all test-unit test-integration test-e2e test-coverage lint lint-fix

test-help: ## 🧪 Show testing and quality help
	@printf "\n$(BOLD)$(BLUE)Testing & Quality$(RESET)\n"
	@printf "$(BLUE)==================$(RESET)\n\n"
	@printf "$(BOLD)Testing:$(RESET)\n"
	@printf "  $(GREEN)make test-all$(RESET)         🧪 Run all tests\n"
	@printf "  $(GREEN)make test-unit$(RESET)        🔬 Run unit tests only\n"
	@printf "  $(GREEN)make test-integration$(RESET) 🔗 Run integration tests\n"
	@printf "  $(GREEN)make test-e2e$(RESET)         🎭 Run end-to-end tests\n"
	@printf "  $(GREEN)make test-coverage$(RESET)    📊 Generate coverage report\n"
	@printf "  $(GREEN)make test-watch$(RESET)       👀 Run tests in watch mode\n\n"
	@printf "$(BOLD)Quality:$(RESET)\n"
	@printf "  $(GREEN)make lint$(RESET)             🔍 Run linting\n"
	@printf "  $(GREEN)make lint-fix$(RESET)         🔧 Fix linting issues\n"
	@printf "  $(GREEN)make type-check$(RESET)       🏷️  Run type checking\n"
	@printf "  $(GREEN)make security-audit$(RESET)   🔒 Security audit\n\n"

test-all: ## 🧪 Run all tests
	@printf "$(BLUE)🧪 Running all tests...$(RESET)\n"
	@npm run test:all

test-unit: ## 🔬 Run unit tests only
	@printf "$(BLUE)🔬 Running unit tests...$(RESET)\n"
	@npm run test

test-integration: ## 🔗 Run integration tests
	@printf "$(BLUE)🔗 Running integration tests...$(RESET)\n"
	@npm run test:integration

test-e2e: ## 🎭 Run end-to-end tests
	@printf "$(BLUE)🎭 Running E2E tests...$(RESET)\n"
	@npm run test:e2e

test-coverage: ## 📊 Generate test coverage report
	@printf "$(BLUE)📊 Generating coverage report...$(RESET)\n"
	@npm run test:coverage

test-watch: ## 👀 Run tests in watch mode
	@printf "$(BLUE)👀 Running tests in watch mode...$(RESET)\n"
	@cd $(FRONTEND_DIR) && npm run test:watch

test-wiki: ## 📚 Test wiki integration
	@printf "$(BLUE)📚 Testing wiki integration...$(RESET)\n"
	@./scripts/test-wiki-integration.sh

# =============================================================================
# 🔍 CODE QUALITY & LINTING (2025 Best Practices)
# =============================================================================

.PHONY: lint lint-fix lint-go lint-frontend lint-python lint-go-fix lint-frontend-fix lint-python-fix
.PHONY: format format-check format-go format-frontend format-python security-scan type-check
.PHONY: quality-check quality-fix pre-commit-install pre-commit-run quality-ci install-tools

lint: ## 🔍 Run all linting (Go, JS/TS, Python)
	@printf "$(GREEN)🔍 Running comprehensive linting...$(RESET)\n"
	@$(MAKE) lint-go
	@$(MAKE) lint-frontend
	@$(MAKE) lint-python
	@printf "$(GREEN)✅ All linting completed$(RESET)\n"

lint-fix: ## 🔧 Fix all linting issues (Go, JS/TS, Python)
	@printf "$(GREEN)🔧 Auto-fixing linting issues...$(RESET)\n"
	@$(MAKE) lint-go-fix
	@$(MAKE) lint-frontend-fix
	@$(MAKE) lint-python-fix
	@printf "$(GREEN)✅ All auto-fixes completed$(RESET)\n"

# Go linting with golangci-lint
lint-go: ## 🔍 Run Go linting
	@printf "$(BLUE)🔍 Running Go linting...$(RESET)\n"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --config .golangci.yml; \
	else \
		printf "$(YELLOW)⚠️  golangci-lint not installed. Installing...$(RESET)\n"; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0; \
		golangci-lint run --config .golangci.yml; \
	fi

lint-go-fix: ## 🔧 Fix Go linting issues
	@printf "$(BLUE)🔧 Fixing Go linting issues...$(RESET)\n"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --config .golangci.yml --fix; \
	else \
		printf "$(YELLOW)⚠️  golangci-lint not installed. Installing...$(RESET)\n"; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0; \
		golangci-lint run --config .golangci.yml --fix; \
	fi

# Frontend linting with Biome
lint-frontend: ## 🔍 Run frontend linting (JS/TS)
	@printf "$(BLUE)🔍 Running frontend linting...$(RESET)\n"
	@if command -v biome >/dev/null 2>&1; then \
		biome check frontend/src; \
	else \
		printf "$(YELLOW)⚠️  Biome not installed. Using npm fallback...$(RESET)\n"; \
		npm run lint --prefix frontend; \
	fi

lint-frontend-fix: ## 🔧 Fix frontend linting issues
	@printf "$(BLUE)🔧 Fixing frontend linting issues...$(RESET)\n"
	@if command -v biome >/dev/null 2>&1; then \
		biome check --apply frontend/src; \
	else \
		printf "$(YELLOW)⚠️  Biome not installed. Using npm fallback...$(RESET)\n"; \
		npm run lint:fix --prefix frontend; \
	fi

# Python linting with Ruff
lint-python: ## 🔍 Run Python linting
	@printf "$(BLUE)🔍 Running Python linting...$(RESET)\n"
	@if [ -d "sdk/python" ]; then \
		if command -v ruff >/dev/null 2>&1; then \
			ruff check sdk/python; \
		else \
			printf "$(YELLOW)⚠️  Ruff not installed. Installing...$(RESET)\n"; \
			pip install ruff; \
			ruff check sdk/python; \
		fi; \
	else \
		printf "$(YELLOW)⚠️  No Python SDK found, skipping Python linting$(RESET)\n"; \
	fi

lint-python-fix: ## 🔧 Fix Python linting issues
	@printf "$(BLUE)🔧 Fixing Python linting issues...$(RESET)\n"
	@if [ -d "sdk/python" ]; then \
		if command -v ruff >/dev/null 2>&1; then \
			ruff check --fix sdk/python; \
			ruff format sdk/python; \
		else \
			printf "$(YELLOW)⚠️  Ruff not installed. Installing...$(RESET)\n"; \
			pip install ruff; \
			ruff check --fix sdk/python; \
			ruff format sdk/python; \
		fi; \
	else \
		printf "$(YELLOW)⚠️  No Python SDK found, skipping Python linting$(RESET)\n"; \
	fi

# =============================================================================
# 🎨 CODE FORMATTING
# =============================================================================

format: ## 🎨 Format all code (Go, JS/TS, Python)
	@printf "$(GREEN)🎨 Formatting all code...$(RESET)\n"
	@$(MAKE) format-go
	@$(MAKE) format-frontend
	@$(MAKE) format-python
	@printf "$(GREEN)✅ All formatting completed$(RESET)\n"

format-check: ## 🔍 Check code formatting
	@printf "$(BLUE)🔍 Checking code formatting...$(RESET)\n"
	@gofmt -l . | grep -v vendor | grep -v node_modules | head -10
	@if command -v biome >/dev/null 2>&1; then biome check --formatter-enabled=true frontend/src; fi
	@if [ -d "sdk/python" ] && command -v ruff >/dev/null 2>&1; then ruff format --check sdk/python; fi

format-go: ## 🎨 Format Go code
	@printf "$(BLUE)🎨 Formatting Go code...$(RESET)\n"
	@if command -v gofumpt >/dev/null 2>&1; then \
		gofumpt -w .; \
	else \
		gofmt -w .; \
	fi
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	fi

format-frontend: ## 🎨 Format frontend code
	@printf "$(BLUE)🎨 Formatting frontend code...$(RESET)\n"
	@if command -v biome >/dev/null 2>&1; then \
		biome format --write frontend/src; \
	else \
		printf "$(YELLOW)⚠️  Biome not installed. Using prettier fallback...$(RESET)\n"; \
		cd frontend && npx prettier --write "src/**/*.{ts,tsx,js,jsx}"; \
	fi

format-python: ## 🎨 Format Python code
	@printf "$(BLUE)🎨 Formatting Python code...$(RESET)\n"
	@if [ -d "sdk/python" ]; then \
		if command -v ruff >/dev/null 2>&1; then \
			ruff format sdk/python; \
		else \
			printf "$(YELLOW)⚠️  Ruff not installed. Installing...$(RESET)\n"; \
			pip install ruff; \
			ruff format sdk/python; \
		fi; \
	else \
		printf "$(YELLOW)⚠️  No Python SDK found, skipping Python formatting$(RESET)\n"; \
	fi

# =============================================================================
# 🛡️ SECURITY & TYPE CHECKING
# =============================================================================

security-scan: ## 🛡️ Run comprehensive security scans
	@printf "$(GREEN)🛡️ Running security scans...$(RESET)\n"
	@$(MAKE) security-go
	@$(MAKE) security-frontend
	@$(MAKE) security-python
	@$(MAKE) security-containers
	@printf "$(GREEN)✅ Security scans completed$(RESET)\n"

security-go: ## 🛡️ Run Go security scan
	@printf "$(BLUE)🛡️ Scanning Go code for vulnerabilities...$(RESET)\n"
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		printf "$(YELLOW)⚠️  gosec not installed. Installing...$(RESET)\n"; \
		go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; \
		gosec ./...; \
	fi
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		printf "$(YELLOW)⚠️  govulncheck not installed. Installing...$(RESET)\n"; \
		go install golang.org/x/vuln/cmd/govulncheck@latest; \
		govulncheck ./...; \
	fi

security-frontend: ## 🛡️ Run frontend security audit
	@printf "$(BLUE)🛡️ Auditing frontend dependencies...$(RESET)\n"
	@cd frontend && npm audit --audit-level=moderate

security-python: ## 🛡️ Run Python security scan
	@printf "$(BLUE)🛡️ Scanning Python code for vulnerabilities...$(RESET)\n"
	@if [ -d "sdk/python" ]; then \
		if command -v bandit >/dev/null 2>&1; then \
			bandit -r sdk/python -f json -o bandit-report.json; \
		else \
			printf "$(YELLOW)⚠️  bandit not installed. Installing...$(RESET)\n"; \
			pip install bandit; \
			bandit -r sdk/python -f json -o bandit-report.json; \
		fi; \
	else \
		printf "$(YELLOW)⚠️  No Python SDK found, skipping Python security scan$(RESET)\n"; \
	fi

security-containers: ## 🛡️ Scan container images for vulnerabilities
	@printf "$(BLUE)🛡️ Scanning container images...$(RESET)\n"
	@if command -v trivy >/dev/null 2>&1; then \
		trivy fs .; \
	else \
		printf "$(YELLOW)⚠️  Trivy not installed. Skipping container scan$(RESET)\n"; \
	fi

type-check: ## 🏷️ Run type checking for all languages
	@printf "$(GREEN)🏷️ Running type checking...$(RESET)\n"
	@$(MAKE) type-check-go
	@$(MAKE) type-check-frontend
	@$(MAKE) type-check-python
	@printf "$(GREEN)✅ Type checking completed$(RESET)\n"

type-check-go: ## 🏷️ Run Go type checking
	@printf "$(BLUE)🏷️ Type checking Go code...$(RESET)\n"
	@go vet ./...

type-check-frontend: ## 🏷️ Run frontend type checking
	@printf "$(BLUE)🏷️ Type checking frontend code...$(RESET)\n"
	@cd $(FRONTEND_DIR) && npm run type-check

type-check-python: ## 🏷️ Run Python type checking
	@printf "$(BLUE)🏷️ Type checking Python code...$(RESET)\n"
	@if [ -d "sdk/python" ]; then \
		if command -v mypy >/dev/null 2>&1; then \
			mypy sdk/python --strict --ignore-missing-imports; \
		else \
			printf "$(YELLOW)⚠️  mypy not installed. Installing...$(RESET)\n"; \
			pip install mypy; \
			mypy sdk/python --strict --ignore-missing-imports; \
		fi; \
	else \
		printf "$(YELLOW)⚠️  No Python SDK found, skipping Python type checking$(RESET)\n"; \
	fi

# =============================================================================
# 🔄 PRE-COMMIT & UNIFIED QUALITY
# =============================================================================

pre-commit-install: ## 🔄 Install pre-commit hooks
	@printf "$(GREEN)🔄 Installing pre-commit hooks...$(RESET)\n"
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit install; \
		pre-commit install --hook-type commit-msg; \
	else \
		printf "$(YELLOW)⚠️  pre-commit not installed. Installing...$(RESET)\n"; \
		pip install pre-commit; \
		pre-commit install; \
		pre-commit install --hook-type commit-msg; \
	fi

pre-commit-run: ## 🔄 Run pre-commit hooks on all files
	@printf "$(BLUE)🔄 Running pre-commit hooks...$(RESET)\n"
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit run --all-files; \
	else \
		printf "$(YELLOW)⚠️  pre-commit not installed. Run 'make pre-commit-install' first$(RESET)\n"; \
	fi

quality-check: ## 🏆 Run comprehensive quality checks
	@printf "$(GREEN)🏆 Running comprehensive quality checks...$(RESET)\n"
	@$(MAKE) lint
	@$(MAKE) type-check
	@$(MAKE) security-scan
	@$(MAKE) format-check
	@printf "$(GREEN)✅ All quality checks completed$(RESET)\n"

quality-fix: ## 🔧 Auto-fix all quality issues
	@printf "$(GREEN)🔧 Auto-fixing all quality issues...$(RESET)\n"
	@$(MAKE) format
	@$(MAKE) lint-fix
	@printf "$(GREEN)✅ All auto-fixes completed$(RESET)\n"

quality-ci: ## 🤖 Quality checks for CI (fail-fast)
	@printf "$(GREEN)🤖 Running CI quality checks...$(RESET)\n"
	@set -e; \
	$(MAKE) format-check; \
	$(MAKE) lint; \
	$(MAKE) type-check; \
	$(MAKE) security-scan
	@printf "$(GREEN)✅ CI quality checks passed$(RESET)\n"

# =============================================================================
# 🛠️ TOOL INSTALLATION
# =============================================================================

install-tools: ## 🛠️ Install all development tools
	@printf "$(GREEN)🛠️ Installing all development tools...$(RESET)\n"
	@$(MAKE) install-go-tools
	@$(MAKE) install-js-tools
	@$(MAKE) install-python-tools
	@printf "$(GREEN)✅ All tools installed$(RESET)\n"

install-go-tools: ## 🛠️ Install Go development tools
	@printf "$(BLUE)🛠️ Installing Go tools...$(RESET)\n"
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0
	@go install mvdan.cc/gofumpt@latest
	@go install golang.org/x/tools/cmd/goimports@latest
	@go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	@go install golang.org/x/vuln/cmd/govulncheck@latest

install-js-tools: ## 🛠️ Install JavaScript/TypeScript tools
	@printf "$(BLUE)🛠️ Installing JS/TS tools...$(RESET)\n"
	@if command -v npm >/dev/null 2>&1; then \
		npm install -g @biomejs/biome@latest; \
	else \
		printf "$(YELLOW)⚠️  npm not found$(RESET)\n"; \
	fi

install-python-tools: ## 🛠️ Install Python development tools
	@printf "$(BLUE)🛠️ Installing Python tools...$(RESET)\n"
	@pip install -U ruff mypy bandit pre-commit

# =============================================================================
# 🔨 BUILD & DEPLOYMENT
# =============================================================================

.PHONY: build-all build-frontend build-backend build-docker build-clean

build-all: build-frontend build-backend ## 🔨 Build all components
	@printf "$(GREEN)✅ All components built successfully$(RESET)\n"

build-frontend: ## 🎨 Build frontend for production
	@printf "$(BLUE)🎨 Building frontend...$(RESET)\n"
	@cd $(FRONTEND_DIR) && npm run build
	@printf "$(GREEN)✅ Frontend built$(RESET)\n"

build-backend: ## ⚙️ Build backend server
	@printf "$(BLUE)⚙️ Building backend...$(RESET)\n"
	@mkdir -p $(BUILD_OUTPUT_DIR)
	@CGO_ENABLED=0 go build \
		-ldflags="-X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE) -X main.gitCommit=$(GIT_COMMIT)" \
		-o $(BUILD_OUTPUT_DIR)/server ./cmd/server
	@printf "$(GREEN)✅ Backend built$(RESET)\n"

build-docker: ## 🐳 Build Docker images
	@printf "$(BLUE)🐳 Building Docker images...$(RESET)\n"
	@docker build -t $(PROJECT_NAME):$(VERSION) .
	@printf "$(GREEN)✅ Docker images built$(RESET)\n"

build-clean: ## 🧹 Clean build artifacts
	@printf "$(BLUE)🧹 Cleaning build artifacts...$(RESET)\n"
	@rm -rf $(BUILD_OUTPUT_DIR)
	@rm -rf $(FRONTEND_DIR)/dist
	@printf "$(GREEN)✅ Build artifacts cleaned$(RESET)\n"

# =============================================================================
# 📚 DOCUMENTATION
# =============================================================================

.PHONY: docs-help docs-serve docs-build docs-schema docs-wiki-sync

docs-help: ## 📚 Show documentation help
	@printf "\n$(BOLD)$(BLUE)Documentation$(RESET)\n"
	@printf "$(BLUE)==============$(RESET)\n\n"
	@printf "$(BOLD)Local Documentation:$(RESET)\n"
	@printf "  $(GREEN)make docs-serve$(RESET)      📖 Serve docs locally\n"
	@printf "  $(GREEN)make docs-build$(RESET)      🏗️  Build static docs\n"
	@printf "  $(GREEN)make docs-schema$(RESET)     💾 Generate database schema docs\n\n"
	@printf "$(BOLD)GitHub Integration:$(RESET)\n"
	@printf "  $(GREEN)make docs-wiki-sync$(RESET)  🔄 Sync docs to GitHub Wiki (requires GITHUB_TOKEN)\n"
	@printf "  $(GREEN)make docs-wiki-test$(RESET)  🧪 Test Wiki Mermaid diagrams (requires GITHUB_TOKEN)\n"
	@printf "  $(GREEN)make docs-test$(RESET)       🧪 Test documentation\n\n"
	@printf "$(BOLD)Environment Setup:$(RESET)\n"
	@printf "  $(GREEN)make env-setup$(RESET)       🔧 Create .env file with GITHUB_TOKEN template\n"
	@printf "  $(GREEN)make check-github-token$(RESET) 🔑 Verify GitHub token configuration\n\n"
	@printf "$(BOLD)Documentation URLs:$(RESET)\n"
	@printf "  Local Server: http://$(DOCS_HOST):$(DOCS_PORT)\n"
	@printf "  Static Files: site/index.html\n"
	@printf "  GitHub Wiki: $(GITHUB_WIKI_URL)\n"
	@printf "  Wiki Sync Status: $(if $(filter true,$(WIKI_SYNC_ENABLED)),$(GREEN)Enabled$(RESET),$(YELLOW)Disabled$(RESET))\n\n"

docs-serve: docs-mkdocs-serve ## 📖 Serve documentation locally

docs-build: docs-mkdocs-build ## 🏗️ Build static documentation

docs-schema: ## 💾 Generate database schema documentation
	@printf "$(BLUE)💾 Generating schema documentation...$(RESET)\n"
	@make docs-schema-optional

docs-wiki-sync: check-github-token ## 🔄 Sync documentation to GitHub Wiki
	@printf "$(BLUE)🔄 Syncing to GitHub Wiki...$(RESET)\n"
	@if [ "$(WIKI_SYNC_ENABLED)" = "true" ]; then \
		printf "$(YELLOW)📤 Syncing to $(GITHUB_WIKI_URL)$(RESET)\n"; \
		if [ -f "scripts/sync-wiki-safe.sh" ]; then \
			GITHUB_TOKEN=$(GITHUB_TOKEN) bash scripts/sync-wiki-safe.sh; \
		else \
			printf "$(RED)❌ Wiki sync script not found$(RESET)\n"; \
		fi; \
	else \
		printf "$(YELLOW)⚠️  Wiki sync disabled (WIKI_SYNC_ENABLED=false)$(RESET)\n"; \
	fi

docs-wiki-test: check-github-token ## 🧪 Test GitHub Wiki integration with Mermaid
	@printf "$(BLUE)🧪 Testing GitHub Wiki integration...$(RESET)\n"
	@if [ -f "scripts/sync-mermaid-test.sh" ]; then \
		GITHUB_TOKEN=$(GITHUB_TOKEN) bash scripts/sync-mermaid-test.sh; \
	else \
		printf "$(RED)❌ Mermaid test script not found$(RESET)\n"; \
	fi

docs-test: test-wiki ## 🧪 Test documentation integration

# =============================================================================
# 🐳 DOCKER & DEPLOYMENT
# =============================================================================

.PHONY: docker-help docker-up docker-down docker-logs docker-build

docker-help: ## 🐳 Show Docker and deployment help
	@printf "\n$(BOLD)$(BLUE)Docker & Deployment$(RESET)\n"
	@printf "$(BLUE)=====================$(RESET)\n\n"
	@printf "$(BOLD)Local Development:$(RESET)\n"
	@printf "  $(GREEN)make docker-up$(RESET)       🚀 Start services with Docker\n"
	@printf "  $(GREEN)make docker-down$(RESET)     🛑 Stop Docker services\n"
	@printf "  $(GREEN)make docker-logs$(RESET)     📜 View Docker logs\n"
	@printf "  $(GREEN)make docker-build$(RESET)    🔨 Build Docker images\n\n"
	@printf "$(BOLD)Service URLs:$(RESET)\n"
	@printf "  Database: $(DB_HOST):$(DB_PORT)\n"
	@printf "  NATS: $(NATS_URL)\n"
	@printf "  Redis: $(REDIS_URL)\n\n"

docker-up: dev-up ## 🚀 Start services with Docker Compose
docker-down: dev-down ## 🛑 Stop Docker services  
docker-logs: dev-logs ## 📜 View Docker service logs
docker-build: build-docker ## 🔨 Build Docker images

# =============================================================================
# 🗄️ DATABASE MANAGEMENT
# =============================================================================

.PHONY: db-help db-migrate db-reset db-backup db-restore

db-help: ## 🗄️ Show database management help
	@printf "\n$(BOLD)$(BLUE)Database Management$(RESET)\n"
	@printf "$(BLUE)====================$(RESET)\n\n"
	@printf "$(BOLD)Schema Management:$(RESET)\n"
	@printf "  $(GREEN)make db-migrate$(RESET)      🔄 Run database migrations\n"
	@printf "  $(GREEN)make db-reset$(RESET)        🔄 Reset database (migrate + seed)\n"
	@printf "  $(GREEN)make db-seed$(RESET)         🌱 Seed with sample data\n\n"
	@printf "$(BOLD)Backup & Restore:$(RESET)\n"
	@printf "  $(GREEN)make db-backup$(RESET)       💾 Backup database\n"
	@printf "  $(GREEN)make db-restore$(RESET)      📥 Restore database\n\n"
	@printf "$(BOLD)Documentation:$(RESET)\n"
	@printf "  $(GREEN)make db-docs$(RESET)         📚 Generate schema docs\n\n"
	@printf "$(BOLD)Connection Info:$(RESET)\n"
	@printf "  Host: $(DB_HOST):$(DB_PORT)\n"
	@printf "  Database: $(DB_NAME)\n"
	@printf "  User: $(DB_USER)\n\n"

db-migrate: ## 🔄 Run database migrations
	@printf "$(BLUE)🔄 Running database migrations...$(RESET)\n"
	@echo "Migration placeholder - implement based on your migration tool"

db-reset: ## 🔄 Reset database (migrate + seed)
	@printf "$(BLUE)🔄 Resetting database...$(RESET)\n"
	@make db-migrate
	@make db-seed

db-seed: ## 🌱 Seed database with sample data
	@printf "$(BLUE)🌱 Seeding database...$(RESET)\n"
	@echo "Seed placeholder - implement based on your seeding tool"

db-backup: ## 💾 Backup database
	@printf "$(BLUE)💾 Backing up database...$(RESET)\n"
	@echo "Backup placeholder - implement with pg_dump or your backup tool"

db-restore: ## 📥 Restore database from backup
	@printf "$(BLUE)📥 Restoring database...$(RESET)\n"
	@echo "Restore placeholder - implement with psql or your restore tool"

db-docs: docs-schema ## 📚 Generate database documentation

# =============================================================================
# 🔄 MATRIX TESTING
# =============================================================================

.PHONY: matrix-help matrix-test matrix-status matrix-report matrix-clean

matrix-help: ## 🔄 Show matrix testing help
	@printf "\n$(BOLD)$(BLUE)Matrix Testing$(RESET)\n"
	@printf "$(BLUE)===============$(RESET)\n\n"
	@printf "$(BOLD)Cross-Version Testing:$(RESET)\n"
	@printf "  $(GREEN)make matrix-test$(RESET)     🧪 Test across multiple versions\n"
	@printf "  $(GREEN)make matrix-status$(RESET)   📊 Show version matrix status\n"
	@printf "  $(GREEN)make matrix-report$(RESET)   📋 Generate detailed report\n"
	@printf "  $(GREEN)make matrix-clean$(RESET)    🧹 Clean matrix test data\n\n"
	@printf "$(BOLD)Supported Versions:$(RESET)\n"
	@printf "  Node.js: 16.x, 18.x, 20.x\n"
	@printf "  Go: 1.21.x, 1.22.x, 1.23.x\n\n"
	@printf "$(BOLD)Test Matrix:$(RESET)\n"
	@printf "  - Unit tests across all version combinations\n"
	@printf "  - Integration tests with different runtimes\n"
	@printf "  - Performance benchmarks\n"
	@printf "  - Compatibility validation\n\n"

matrix-test: ## 🧪 Run matrix testing across multiple versions
	@printf "$(BLUE)🧪 Running matrix tests...$(RESET)\n"
	@echo "Matrix testing placeholder - implement version switching and testing"

matrix-status: ## 📊 Show version matrix status
	@printf "$(BLUE)📊 Matrix Testing Status$(RESET)\n"
	@printf "$(BLUE)========================$(RESET)\n"
	@printf "Current Node.js: $$(node --version 2>/dev/null || echo 'Not installed')\n"
	@printf "Current Go: $$(go version 2>/dev/null | cut -d' ' -f3 || echo 'Not installed')\n"
	@printf "Matrix tests: Not yet implemented\n"

matrix-report: ## 📋 Generate matrix testing report
	@printf "$(BLUE)📋 Matrix testing report placeholder$(RESET)\n"

matrix-clean: ## 🧹 Clean matrix testing data
	@printf "$(BLUE)🧹 Cleaning matrix test data...$(RESET)\n"
	@rm -rf reports/matrix

# =============================================================================
# 🧹 CLEANUP & MAINTENANCE
# =============================================================================

.PHONY: clean-all clean-deps clean-cache clean-logs

clean-all: build-clean clean-deps clean-cache clean-logs ## 🧹 Clean everything
	@printf "$(GREEN)✅ Complete cleanup finished$(RESET)\n"

clean-deps: ## 🧹 Clean dependency caches
	@printf "$(BLUE)🧹 Cleaning dependency caches...$(RESET)\n"
	@rm -rf node_modules
	@rm -rf $(FRONTEND_DIR)/node_modules
	@go clean -modcache
	@printf "$(GREEN)✅ Dependencies cleaned$(RESET)\n"

clean-cache: ## 🧹 Clean build caches
	@printf "$(BLUE)🧹 Cleaning build caches...$(RESET)\n"
	@rm -rf .cache
	@rm -rf $(FRONTEND_DIR)/.cache
	@printf "$(GREEN)✅ Caches cleaned$(RESET)\n"

clean-logs: ## 🧹 Clean log files
	@printf "$(BLUE)🧹 Cleaning log files...$(RESET)\n"
	@rm -rf logs/
	@printf "$(GREEN)✅ Logs cleaned$(RESET)\n"

# =============================================================================
# 📋 ALL TARGETS (Complete List)
# =============================================================================

all-targets: ## 📋 Show ALL available targets
	@printf "\n$(BOLD)$(BLUE)All Available Targets$(RESET)\n"
	@printf "$(BLUE)======================$(RESET)\n\n"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_0-9-]+:.*##/ { printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# =============================================================================
# ENVIRONMENT & SETUP TARGETS
# =============================================================================

.PHONY: env-setup env-check check-github-token setup-env show-env

env-setup: ## 🔧 Setup environment configuration
	@printf "$(BLUE)🔧 Setting up environment configuration...$(RESET)\n"
	@if [ ! -f ".env" ]; then \
		printf "$(YELLOW)📋 Creating .env from template...$(RESET)\n"; \
		cp .env.template .env; \
		printf "$(GREEN)✅ Created .env file$(RESET)\n"; \
		printf "$(YELLOW)⚠️  Please edit .env with your actual values$(RESET)\n"; \
		printf "$(BLUE)💡 Key variables to configure:$(RESET)\n"; \
		printf "  - GITHUB_TOKEN (for wiki sync)\n"; \
		printf "  - DB_PASSWORD (database password)\n"; \
		printf "  - JWT_SECRET (JWT signing key)\n"; \
		printf "  - SESSION_SECRET (session encryption)\n"; \
	else \
		printf "$(GREEN)✅ .env file already exists$(RESET)\n"; \
	fi

env-check: ## 🔍 Check environment configuration
	@printf "$(BLUE)🔍 Environment Configuration Status$(RESET)\n"
	@printf "$(BLUE)====================================$(RESET)\n"
	@printf "Environment file: $(if $(wildcard ./.env),$(GREEN)✅ Found$(RESET),$(RED)❌ Missing$(RESET))\n"
	@if [ -f ".env" ]; then \
		printf "GitHub Token: $(if $(GITHUB_TOKEN),$(GREEN)✅ Set$(RESET),$(YELLOW)⚠️  Missing$(RESET))\n"; \
		printf "Database Config: $(if $(DB_PASSWORD),$(GREEN)✅ Set$(RESET),$(YELLOW)⚠️  Using defaults$(RESET))\n"; \
		printf "Wiki Sync: $(if $(filter true,$(WIKI_SYNC_ENABLED)),$(GREEN)✅ Enabled$(RESET),$(YELLOW)⚠️  Disabled$(RESET))\n"; \
	else \
		printf "$(YELLOW)💡 Run 'make env-setup' to create .env file$(RESET)\n"; \
	fi

check-github-token: ## 🔑 Verify GitHub token is configured
	@if [ -z "$(GITHUB_TOKEN)" ]; then \
		printf "$(RED)❌ GITHUB_TOKEN not set$(RESET)\n"; \
		printf "$(BLUE)💡 Setup instructions:$(RESET)\n"; \
		printf "  1. Copy template: make env-setup\n"; \
		printf "  2. Get token: https://github.com/settings/tokens\n"; \
		printf "  3. Add to .env: GITHUB_TOKEN=your_token_here\n"; \
		printf "  4. Required scopes: repo, wiki, workflow\n"; \
		exit 1; \
	else \
		printf "$(GREEN)✅ GitHub token configured$(RESET)\n"; \
	fi

setup-env: env-setup ## 🚀 Complete environment setup (alias for env-setup)

env-generate-template: ## 🔧 Generate/update .env.template with all configurations
	@printf "$(BLUE)🔧 Generating comprehensive .env.template...$(RESET)\n"
	@cat > .env.template << 'EOF' ;\
# Environment Configuration Template\
# Copy this file to .env and configure with your actual values\
# DO NOT commit .env file to version control\
\
# =============================================================================\
# GitHub Integration\
# =============================================================================\
\
# GitHub Personal Access Token for API operations\
# Required for: wiki sync, releases, workflow triggers\
# Scopes needed: repo, wiki, workflow\
# Generate at: https://github.com/settings/tokens\
GITHUB_TOKEN=your_github_token_here\
\
# GitHub Repository Information\
GITHUB_OWNER=$(GITHUB_OWNER)\
GITHUB_REPO=$(GITHUB_REPO)\
\
# =============================================================================\
# Database Configuration\
# =============================================================================\
\
# PostgreSQL Database Settings\
DB_HOST=$(DB_HOST)\
DB_PORT=$(DB_PORT)\
DB_NAME=$(DB_NAME)\
DB_USER=$(DB_USER)\
DB_PASSWORD=your_secure_password_here\
DB_SSLMODE=disable\
\
# Database URL (alternative to individual settings)\
DATABASE_URL=postgresql://$${DB_USER}:$${DB_PASSWORD}@$${DB_HOST}:$${DB_PORT}/$${DB_NAME}?sslmode=$${DB_SSLMODE}\
\
# =============================================================================\
# Service Configuration\
# =============================================================================\
\
# NATS Messaging\
NATS_URL=$(NATS_URL)\
\
# Redis Cache\
REDIS_URL=$(REDIS_URL)\
\
# Application Settings\
APP_ENV=development\
APP_PORT=8080\
APP_HOST=localhost\
\
# =============================================================================\
# Authentication & Security\
# =============================================================================\
\
# JWT Configuration (CRITICAL - Generate secure secrets)\
JWT_SECRET=your_jwt_secret_here_minimum_32_characters\
JWT_EXPIRY=1h\
REFRESH_TOKEN_EXPIRY=7d\
\
# Session Configuration (CRITICAL - Generate secure secrets)\
SESSION_SECRET=your_session_secret_here_minimum_32_characters\
SESSION_TIMEOUT=24h\
\
# CORS Settings\
CORS_ORIGINS=http://localhost:3000,http://localhost:5173,http://$(DOCS_HOST):$(DOCS_PORT)\
\
# =============================================================================\
# External Services\
# =============================================================================\
\
# Bytebase Configuration\
BYTEBASE_URL=http://localhost:5678\
BYTEBASE_TOKEN=your_bytebase_token_here\
\
# SPIRE Configuration (Zero Trust Identity)\
SPIRE_SOCKET_PATH=/run/spire/sockets/agent.sock\
SPIRE_TRUST_DOMAIN=zamaz.dev\
\
# =============================================================================\
# Development Tools\
# =============================================================================\
\
# Log Level (debug, info, warn, error)\
LOG_LEVEL=debug\
\
# Enable Development Features\
ENABLE_PPROF=true\
ENABLE_DEBUG_ENDPOINTS=true\
\
# API Documentation\
SWAGGER_ENABLED=true\
SWAGGER_HOST=localhost:8080\
\
# =============================================================================\
# Documentation & Wiki\
# =============================================================================\
\
# MkDocs Configuration\
DOCS_PORT=$(DOCS_PORT)\
DOCS_HOST=$(DOCS_HOST)\
\
# Wiki Sync Configuration\
WIKI_SYNC_ENABLED=$(WIKI_SYNC_ENABLED)\
WIKI_BRANCH=$(WIKI_BRANCH)\
WIKI_SUBDIRECTORY=$(WIKI_SUBDIRECTORY)\
\
# =============================================================================\
# Testing Configuration\
# =============================================================================\
\
# Test Database (separate from main DB)\
TEST_DB_HOST=localhost\
TEST_DB_PORT=5432\
TEST_DB_NAME=mvp_test_db\
TEST_DB_USER=mvp_test_user\
TEST_DB_PASSWORD=test_password\
\
# E2E Testing\
E2E_BASE_URL=http://localhost:8080\
E2E_TIMEOUT=30000\
\
# Load Testing\
LOAD_TEST_USERS=10\
LOAD_TEST_DURATION=5m\
\
# =============================================================================\
# Monitoring & Observability\
# =============================================================================\
\
# Metrics Configuration\
METRICS_ENABLED=true\
METRICS_PORT=9090\
\
# Prometheus\
PROMETHEUS_URL=http://localhost:9090\
\
# Grafana\
GRAFANA_URL=http://localhost:3000\
GRAFANA_API_KEY=your_grafana_api_key_here\
\
# =============================================================================\
# CI/CD Configuration\
# =============================================================================\
\
# Docker Configuration\
DOCKER_REGISTRY=ghcr.io\
DOCKER_IMAGE_NAME=$(GITHUB_OWNER)/$(GITHUB_REPO)\
DOCKER_TAG=latest\
\
# Deployment Configuration\
DEPLOY_ENV=development\
KUBE_NAMESPACE=zamaz-auth-dev\
ARGOCD_SERVER=your-argocd-server.com\
\
# =============================================================================\
# Security Secrets Generation\
# =============================================================================\
# Generate secure secrets with:\
# JWT_SECRET=$$(openssl rand -base64 32)\
# SESSION_SECRET=$$(openssl rand -base64 32)\
EOF
	@printf "$(GREEN)✅ .env.template updated with current configuration$(RESET)\n"
	@printf "$(BLUE)💡 Use 'make env-setup' to create .env from this template$(RESET)\n"

env-secrets: ## 🔐 Generate secure secrets for JWT and SESSION
	@printf "$(BLUE)🔐 Generating secure secrets...$(RESET)\n"
	@printf "$(YELLOW)Add these to your .env file:$(RESET)\n"
	@printf "JWT_SECRET=$$(openssl rand -base64 32)\n"
	@printf "SESSION_SECRET=$$(openssl rand -base64 32)\n"
	@printf "$(BLUE)💡 These secrets are cryptographically secure$(RESET)\n"

show-env: ## 📋 Show current environment variables (safe)
	@printf "$(BLUE)📋 Current Environment Configuration$(RESET)\n"
	@printf "$(BLUE)====================================$(RESET)\n"
	@printf "Project: $(GREEN)$(PROJECT_NAME)$(RESET)\n"
	@printf "Version: $(GREEN)$(VERSION)$(RESET)\n"
	@printf "GitHub Owner: $(GREEN)$(GITHUB_OWNER)$(RESET)\n"
	@printf "GitHub Repo: $(GREEN)$(GITHUB_REPO)$(RESET)\n"
	@printf "GitHub Token: $(if $(GITHUB_TOKEN),$(GREEN)✅ Set (****)$(RESET),$(RED)❌ Not set$(RESET))\n"
	@printf "Database Host: $(GREEN)$(DB_HOST):$(DB_PORT)$(RESET)\n"
	@printf "Database Name: $(GREEN)$(DB_NAME)$(RESET)\n"
	@printf "Frontend Dir: $(GREEN)$(FRONTEND_DIR)$(RESET)\n"
	@printf "Docs Port: $(GREEN)$(DOCS_HOST):$(DOCS_PORT)$(RESET)\n"
	@printf "Wiki Sync: $(if $(filter true,$(WIKI_SYNC_ENABLED)),$(GREEN)Enabled$(RESET),$(YELLOW)Disabled$(RESET))\n"

# =============================================================================
# MISSING DOCUMENTATION TARGETS (Referenced but not implemented)
# =============================================================================

.PHONY: docs-mkdocs-serve docs-mkdocs-build docs-mkdocs-install docs-schema-optional docs-wiki-preview

docs-mkdocs-install: ## 📚 Install MkDocs and dependencies
	@printf "$(BLUE)📚 Installing MkDocs...$(RESET)\n"
	@if [ ! -d ".venv-docs" ]; then \
		printf "$(YELLOW)📦 Creating virtual environment...$(RESET)\n"; \
		python3 -m venv .venv-docs; \
	fi
	@./.venv-docs/bin/pip install -q mkdocs mkdocs-material pymdown-extensions
	@printf "$(GREEN)✅ MkDocs environment ready$(RESET)\n"

docs-mkdocs-serve: docs-mkdocs-install ## 📖 Start MkDocs development server
	@printf "$(BLUE)📖 Starting MkDocs server...$(RESET)\n"
	@printf "$(GREEN)📍 Documentation available at: http://127.0.0.1:8001$(RESET)\n"
	@./.venv-docs/bin/mkdocs serve --dev-addr 127.0.0.1:8001

docs-mkdocs-build: docs-mkdocs-install ## 🏗️ Build MkDocs static site
	@printf "$(BLUE)🏗️ Building MkDocs static site...$(RESET)\n"
	@./.venv-docs/bin/mkdocs build
	@printf "$(GREEN)✅ Static documentation built$(RESET)\n"

docs-schema-optional: ## 💾 Generate schema documentation if database available
	@printf "$(BLUE)💾 Generating schema documentation...$(RESET)\n"
	@mkdir -p docs/combined/schema
	@if command -v tbls >/dev/null 2>&1; then \
		if tbls doc --force docs/schema 2>/dev/null; then \
			printf "$(GREEN)✅ Schema documentation generated$(RESET)\n"; \
			cp -r docs/schema/* docs/combined/schema/ 2>/dev/null || true; \
		else \
			printf "$(YELLOW)⚠️  Database not available - skipping schema docs$(RESET)\n"; \
			echo "Database connection required for schema generation" > docs/combined/schema/README.md; \
		fi; \
	else \
		printf "$(YELLOW)⚠️  tbls not installed - skipping schema docs$(RESET)\n"; \
		echo "Install tbls to generate schema documentation" > docs/combined/schema/README.md; \
	fi

docs-wiki-preview: ## 🔍 Preview wiki sync (safe mode)
	@printf "$(BLUE)🔍 Previewing wiki sync...$(RESET)\n"
	@if [ -f "scripts/sync-wiki-safe.sh" ]; then \
		bash scripts/sync-wiki-safe.sh; \
	else \
		printf "$(YELLOW)⚠️  Wiki sync script not found$(RESET)\n"; \
		printf "$(BLUE)💡 Create scripts/sync-wiki-safe.sh for wiki integration$(RESET)\n"; \
	fi

# =============================================================================
# INCLUDE EXISTING ADVANCED TARGETS
# =============================================================================
# Keep all existing advanced targets from the original Makefile below this line
# This preserves existing functionality while providing better organization

