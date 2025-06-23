# Go Keycloak Zero Trust - Development Makefile
# This Makefile provides easy commands for development, testing, and deployment

# ================================
# Configuration
# ================================

# Go configuration
GO_VERSION := 1.21
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GOGENERATE := $(GOCMD) generate

# Project configuration
PROJECT_NAME := go-keycloak-zerotrust
MAIN_PATH := ./cmd/server
BUILD_DIR := ./build
DIST_DIR := ./dist

# Docker configuration
DOCKER_COMPOSE := docker-compose
KEYCLOAK_CONTAINER := keycloak-zerotrust-kc
POSTGRES_CONTAINER := keycloak-zerotrust-db
REDIS_CONTAINER := keycloak-zerotrust-redis

# Test configuration
TEST_TIMEOUT := 30m
COVERAGE_OUT := coverage.out
COVERAGE_HTML := coverage.html

# Environment files
ENV_FILE := .env
ENV_TEMPLATE := .env.template
ENV_LOCAL := .env.local

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
PURPLE := \033[0;35m
CYAN := \033[0;36m
WHITE := \033[0;37m
NC := \033[0m # No Color

# ================================
# Help Documentation
# ================================

.PHONY: help
help: ## 📖 Show this help message
	@echo "$(CYAN)Go Keycloak Zero Trust - Development Commands$(NC)"
	@echo "================================================="
	@echo ""
	@echo "$(GREEN)🚀 Quick Start:$(NC)"
	@echo "  make setup     - Complete development setup"
	@echo "  make start     - Start all services"
	@echo "  make test-e2e  - Run end-to-end tests"
	@echo "  make stop      - Stop all services"
	@echo ""
	@echo "$(GREEN)📋 Available Commands:$(NC)"
	@awk 'BEGIN {FS = ":.*##"; printf ""} /^[a-zA-Z_-]+:.*?##/ { printf "  $(CYAN)%-15s$(NC) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)🎯 Common Workflows:$(NC)"
	@echo "  Development: make setup → make start → make test"
	@echo "  Testing:     make test-unit → make test-integration → make test-e2e"
	@echo "  Production:  make build-all → make docker-build"

# ================================
# Environment Setup
# ================================

.PHONY: setup
setup: check-deps env-setup deps-install services-pull ## 🛠️ Complete development environment setup
	@echo "$(GREEN)✅ Development environment setup complete!$(NC)"
	@echo ""
	@echo "$(CYAN)Next steps:$(NC)"
	@echo "  1. make start     # Start all services"
	@echo "  2. make test-e2e  # Run end-to-end tests"
	@echo "  3. make keycloak-info # Get Keycloak access info"

.PHONY: check-deps
check-deps: ## 🔍 Check required dependencies
	@echo "$(BLUE)Checking dependencies...$(NC)"
	@command -v go >/dev/null 2>&1 || { echo "$(RED)❌ Go is required but not installed$(NC)"; exit 1; }
	@command -v docker >/dev/null 2>&1 || { echo "$(RED)❌ Docker is required but not installed$(NC)"; exit 1; }
	@command -v docker-compose >/dev/null 2>&1 || { echo "$(RED)❌ Docker Compose is required but not installed$(NC)"; exit 1; }
	@go version | grep -q "go1\.[2-9][1-9]\|go1\.2[1-9]" || { echo "$(RED)❌ Go 1.21+ is required$(NC)"; exit 1; }
	@echo "$(GREEN)✅ All dependencies are available$(NC)"

.PHONY: env-setup
env-setup: ## 📝 Setup environment configuration
	@echo "$(BLUE)Setting up environment configuration...$(NC)"
	@if [ ! -f $(ENV_FILE) ]; then \
		cp $(ENV_TEMPLATE) $(ENV_FILE); \
		echo "$(GREEN)✅ Created $(ENV_FILE) from template$(NC)"; \
		echo "$(YELLOW)⚠️  Please review and update $(ENV_FILE) with your specific values$(NC)"; \
	else \
		echo "$(YELLOW)⚠️  $(ENV_FILE) already exists, skipping creation$(NC)"; \
	fi

.PHONY: deps-install
deps-install: ## 📦 Install Go dependencies
	@echo "$(BLUE)Installing Go dependencies...$(NC)"
	@$(GOMOD) download
	@$(GOMOD) tidy
	@echo "$(GREEN)✅ Go dependencies installed$(NC)"

.PHONY: services-pull
services-pull: ## 🐳 Pull Docker images for services
	@echo "$(BLUE)Pulling Docker images...$(NC)"
	@$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.dev.yml pull
	@echo "$(GREEN)✅ Docker images pulled$(NC)"

# ================================
# Service Management
# ================================

.PHONY: start
start: ## 🚀 Start all development services
	@echo "$(BLUE)Starting development services...$(NC)"
	@$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.dev.yml up -d
	@echo "$(GREEN)✅ Services started$(NC)"
	@echo ""
	@$(MAKE) --no-print-directory wait-for-services
	@$(MAKE) --no-print-directory services-status

.PHONY: stop
stop: ## 🛑 Stop all services
	@echo "$(BLUE)Stopping services...$(NC)"
	@$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.dev.yml down
	@echo "$(GREEN)✅ Services stopped$(NC)"

.PHONY: restart
restart: stop start ## 🔄 Restart all services

.PHONY: services-status
services-status: ## 📊 Show status of all services
	@echo "$(CYAN)Service Status:$(NC)"
	@echo "================"
	@$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.dev.yml ps
	@echo ""
	@echo "$(CYAN)Service URLs:$(NC)"
	@echo "=============="
	@echo "🔐 Keycloak Admin: $(GREEN)http://localhost:8080/admin$(NC)"
	@echo "📊 Keycloak Metrics: $(GREEN)http://localhost:8080/metrics$(NC)"
	@echo "🗄️  PostgreSQL: $(GREEN)localhost:5432$(NC)"
	@echo "🔴 Redis: $(GREEN)localhost:6379$(NC)"
	@echo ""
	@echo "$(CYAN)Default Credentials:$(NC)"
	@echo "===================="
	@echo "👤 Keycloak Admin: $(YELLOW)admin / admin$(NC)"
	@echo "🗄️  PostgreSQL: $(YELLOW)keycloak / keycloak_password$(NC)"

.PHONY: wait-for-services
wait-for-services: ## ⏳ Wait for services to be ready
	@echo "$(BLUE)Waiting for services to be ready...$(NC)"
	@echo -n "⏳ PostgreSQL: "
	@for i in {1..30}; do \
		if docker exec $(POSTGRES_CONTAINER) pg_isready -U keycloak >/dev/null 2>&1; then \
			echo "$(GREEN)✅ Ready$(NC)"; break; \
		fi; \
		echo -n "."; sleep 2; \
		if [ $$i -eq 30 ]; then echo "$(RED)❌ Timeout$(NC)"; exit 1; fi; \
	done
	@echo -n "⏳ Redis: "
	@for i in {1..30}; do \
		if docker exec $(REDIS_CONTAINER) redis-cli ping >/dev/null 2>&1; then \
			echo "$(GREEN)✅ Ready$(NC)"; break; \
		fi; \
		echo -n "."; sleep 2; \
		if [ $$i -eq 30 ]; then echo "$(RED)❌ Timeout$(NC)"; exit 1; fi; \
	done
	@echo -n "⏳ Keycloak: "
	@for i in {1..60}; do \
		if curl -s http://localhost:8080/health/ready >/dev/null 2>&1; then \
			echo "$(GREEN)✅ Ready$(NC)"; break; \
		fi; \
		echo -n "."; sleep 3; \
		if [ $$i -eq 60 ]; then echo "$(RED)❌ Timeout$(NC)"; exit 1; fi; \
	done

.PHONY: logs
logs: ## 📋 Show logs from all services
	@$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.dev.yml logs -f

.PHONY: logs-keycloak
logs-keycloak: ## 📋 Show Keycloak logs
	@$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.dev.yml logs -f keycloak

.PHONY: logs-postgres
logs-postgres: ## 📋 Show PostgreSQL logs
	@$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.dev.yml logs -f postgres

.PHONY: logs-redis
logs-redis: ## 📋 Show Redis logs
	@$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.dev.yml logs -f redis

# ================================
# Keycloak Management
# ================================

.PHONY: keycloak-info
keycloak-info: ## 🔐 Show Keycloak access information
	@echo "$(CYAN)Keycloak Access Information$(NC)"
	@echo "==========================="
	@echo ""
	@echo "$(GREEN)🌐 Admin Console:$(NC)"
	@echo "   URL: http://localhost:8080/admin"
	@echo "   Username: admin"
	@echo "   Password: admin"
	@echo ""
	@echo "$(GREEN)🔗 API Endpoints:$(NC)"
	@echo "   Base URL: http://localhost:8080"
	@echo "   Health: http://localhost:8080/health"
	@echo "   Metrics: http://localhost:8080/metrics"
	@echo ""
	@echo "$(GREEN)🎯 Quick Setup Steps:$(NC)"
	@echo "   1. Open http://localhost:8080/admin in your browser"
	@echo "   2. Login with admin/admin"
	@echo "   3. Create a new realm or use 'master'"
	@echo "   4. Create a client for your application"
	@echo "   5. Update your .env file with the client details"

.PHONY: keycloak-setup
keycloak-setup: ## 🔧 Auto-setup Keycloak with test realm and client
	@echo "$(BLUE)Setting up Keycloak with test configuration...$(NC)"
	@./scripts/keycloak-setup.sh
	@echo "$(GREEN)✅ Keycloak setup complete$(NC)"

.PHONY: keycloak-import
keycloak-import: ## 📥 Import test realm configuration
	@echo "$(BLUE)Importing test realm configuration...$(NC)"
	@docker exec $(KEYCLOAK_CONTAINER) /opt/keycloak/bin/kc.sh import --file /opt/keycloak/data/import/realm-test.json
	@echo "$(GREEN)✅ Test realm imported$(NC)"

.PHONY: keycloak-reset
keycloak-reset: ## 🔄 Reset Keycloak to clean state
	@echo "$(BLUE)Resetting Keycloak to clean state...$(NC)"
	@$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.dev.yml down keycloak
	@docker volume rm keycloak-zerotrust_keycloak_data 2>/dev/null || true
	@$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.dev.yml up -d keycloak
	@$(MAKE) --no-print-directory wait-for-services
	@echo "$(GREEN)✅ Keycloak reset complete$(NC)"

# ================================
# Testing
# ================================

.PHONY: test
test: test-unit ## 🧪 Run basic unit tests

.PHONY: test-unit
test-unit: ## 🧪 Run unit tests
	@echo "$(BLUE)Running unit tests...$(NC)"
	@$(GOTEST) -v -race -timeout $(TEST_TIMEOUT) ./pkg/... ./internal/...
	@echo "$(GREEN)✅ Unit tests completed$(NC)"

.PHONY: test-integration
test-integration: ## 🔗 Run integration tests (requires services)
	@echo "$(BLUE)Running integration tests...$(NC)"
	@$(GOTEST) -v -race -timeout $(TEST_TIMEOUT) -tags=integration ./test/integration/...
	@echo "$(GREEN)✅ Integration tests completed$(NC)"

.PHONY: test-e2e
test-e2e: ## 🎯 Run end-to-end tests (requires services)
	@echo "$(BLUE)Running end-to-end tests...$(NC)"
	@echo "$(YELLOW)⚠️  Make sure services are running (make start)$(NC)"
	@$(GOTEST) -v -timeout $(TEST_TIMEOUT) -tags=e2e ./test/e2e/...
	@echo "$(GREEN)✅ End-to-end tests completed$(NC)"

.PHONY: test-benchmark
test-benchmark: ## ⚡ Run performance benchmarks
	@echo "$(BLUE)Running benchmarks...$(NC)"
	@$(GOTEST) -bench=. -benchmem -run=^$$ ./test/benchmark/...
	@echo "$(GREEN)✅ Benchmarks completed$(NC)"

.PHONY: test-all
test-all: test-unit test-integration test-e2e ## 🚀 Run all tests
	@echo "$(GREEN)✅ All tests completed successfully!$(NC)"

.PHONY: test-coverage
test-coverage: ## 📊 Generate test coverage report
	@echo "$(BLUE)Generating test coverage report...$(NC)"
	@$(GOTEST) -v -race -coverprofile=$(COVERAGE_OUT) -covermode=atomic ./pkg/... ./internal/...
	@$(GOCMD) tool cover -html=$(COVERAGE_OUT) -o $(COVERAGE_HTML)
	@$(GOCMD) tool cover -func=$(COVERAGE_OUT)
	@echo "$(GREEN)✅ Coverage report generated: $(COVERAGE_HTML)$(NC)"

.PHONY: test-security
test-security: ## 🔒 Run security tests and vulnerability scanning
	@echo "$(BLUE)Running security tests...$(NC)"
	@command -v gosec >/dev/null 2>&1 || $(GOGET) github.com/securego/gosec/v2/cmd/gosec@latest
	@gosec ./...
	@echo "$(GREEN)✅ Security tests completed$(NC)"

# ================================
# Code Quality
# ================================

.PHONY: lint
lint: ## 🔍 Run code linting
	@echo "$(BLUE)Running code linting...$(NC)"
	@command -v golangci-lint >/dev/null 2>&1 || { echo "$(RED)❌ golangci-lint not installed. Run: make install-tools$(NC)"; exit 1; }
	@golangci-lint run --timeout=5m
	@echo "$(GREEN)✅ Linting completed$(NC)"

.PHONY: format
format: ## 💄 Format code
	@echo "$(BLUE)Formatting code...$(NC)"
	@$(GOCMD) fmt ./...
	@command -v goimports >/dev/null 2>&1 && goimports -w . || echo "$(YELLOW)⚠️  goimports not available$(NC)"
	@echo "$(GREEN)✅ Code formatted$(NC)"

.PHONY: vet
vet: ## 🔍 Run go vet
	@echo "$(BLUE)Running go vet...$(NC)"
	@$(GOCMD) vet ./...
	@echo "$(GREEN)✅ Vet completed$(NC)"

.PHONY: mod-tidy
mod-tidy: ## 📦 Tidy Go modules
	@echo "$(BLUE)Tidying Go modules...$(NC)"
	@$(GOMOD) tidy
	@echo "$(GREEN)✅ Modules tidied$(NC)"

.PHONY: quality
quality: format vet lint mod-tidy ## ✨ Run all code quality checks

# ================================
# Build & Release
# ================================

.PHONY: build
build: ## 🔨 Build the main application
	@echo "$(BLUE)Building application...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@$(GOBUILD) -o $(BUILD_DIR)/server $(MAIN_PATH)
	@echo "$(GREEN)✅ Build completed: $(BUILD_DIR)/server$(NC)"

.PHONY: build-all
build-all: ## 🔨 Build for multiple platforms
	@echo "$(BLUE)Building for multiple platforms...$(NC)"
	@mkdir -p $(DIST_DIR)
	@GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(DIST_DIR)/server-linux-amd64 $(MAIN_PATH)
	@GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(DIST_DIR)/server-linux-arm64 $(MAIN_PATH)
	@GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(DIST_DIR)/server-darwin-amd64 $(MAIN_PATH)
	@GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(DIST_DIR)/server-darwin-arm64 $(MAIN_PATH)
	@GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(DIST_DIR)/server-windows-amd64.exe $(MAIN_PATH)
	@echo "$(GREEN)✅ Multi-platform build completed$(NC)"

.PHONY: docker-build
docker-build: ## 🐳 Build Docker image
	@echo "$(BLUE)Building Docker image...$(NC)"
	@docker build -t go-keycloak-zerotrust:latest .
	@echo "$(GREEN)✅ Docker image built$(NC)"

.PHONY: docker-run
docker-run: docker-build ## 🐳 Run Docker container
	@echo "$(BLUE)Running Docker container...$(NC)"
	@docker run --rm -p 8081:8080 --env-file $(ENV_FILE) go-keycloak-zerotrust:latest

# ================================
# Documentation
# ================================

.PHONY: docs
docs: ## 📚 Generate documentation
	@echo "$(BLUE)Generating documentation...$(NC)"
	@$(GOCMD) doc -all ./... > docs/api-generated.md
	@echo "$(GREEN)✅ Documentation generated$(NC)"

.PHONY: docs-serve
docs-serve: ## 📚 Serve documentation locally
	@echo "$(BLUE)Starting documentation server...$(NC)"
	@command -v mkdocs >/dev/null 2>&1 || { echo "$(RED)❌ mkdocs not installed. Run: pip install mkdocs$(NC)"; exit 1; }
	@mkdocs serve -a 127.0.0.1:8001

# ================================
# Development Tools
# ================================

.PHONY: install-tools
install-tools: ## 🛠️ Install development tools
	@echo "$(BLUE)Installing development tools...$(NC)"
	@$(GOGET) github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@$(GOGET) github.com/securego/gosec/v2/cmd/gosec@latest
	@$(GOGET) golang.org/x/tools/cmd/goimports@latest
	@$(GOGET) golang.org/x/vuln/cmd/govulncheck@latest
	@echo "$(GREEN)✅ Development tools installed$(NC)"

.PHONY: check-tools
check-tools: ## 🔍 Check if development tools are installed
	@echo "$(BLUE)Checking development tools...$(NC)"
	@command -v golangci-lint >/dev/null 2>&1 && echo "$(GREEN)✅ golangci-lint$(NC)" || echo "$(RED)❌ golangci-lint$(NC)"
	@command -v gosec >/dev/null 2>&1 && echo "$(GREEN)✅ gosec$(NC)" || echo "$(RED)❌ gosec$(NC)"
	@command -v goimports >/dev/null 2>&1 && echo "$(GREEN)✅ goimports$(NC)" || echo "$(RED)❌ goimports$(NC)"

.PHONY: dev-shell
dev-shell: ## 💻 Start development shell with environment loaded
	@echo "$(BLUE)Starting development shell...$(NC)"
	@echo "$(GREEN)Environment loaded. Type 'exit' to return.$(NC)"
	@bash --rcfile <(echo "source ~/.bashrc 2>/dev/null || source ~/.bash_profile 2>/dev/null || true; source $(ENV_FILE) 2>/dev/null || true; PS1='[dev] \$$ '")

# ================================
# Database Management
# ================================

.PHONY: db-connect
db-connect: ## 🗄️ Connect to PostgreSQL database
	@echo "$(BLUE)Connecting to PostgreSQL...$(NC)"
	@docker exec -it $(POSTGRES_CONTAINER) psql -U keycloak -d keycloak

.PHONY: db-backup
db-backup: ## 💾 Backup database
	@echo "$(BLUE)Creating database backup...$(NC)"
	@mkdir -p ./backups
	@docker exec $(POSTGRES_CONTAINER) pg_dump -U keycloak keycloak > ./backups/keycloak_$(shell date +%Y%m%d_%H%M%S).sql
	@echo "$(GREEN)✅ Database backup created$(NC)"

.PHONY: redis-cli
redis-cli: ## 🔴 Connect to Redis CLI
	@echo "$(BLUE)Connecting to Redis...$(NC)"
	@docker exec -it $(REDIS_CONTAINER) redis-cli

# ================================
# Cleanup
# ================================

.PHONY: clean
clean: ## 🧹 Clean build artifacts
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@rm -f $(COVERAGE_OUT) $(COVERAGE_HTML)
	@$(GOCMD) clean -cache -testcache -modcache
	@echo "$(GREEN)✅ Cleanup completed$(NC)"

.PHONY: clean-docker
clean-docker: stop ## 🧹 Clean Docker resources
	@echo "$(BLUE)Cleaning Docker resources...$(NC)"
	@$(DOCKER_COMPOSE) -f deployments/docker/docker-compose.dev.yml down -v --remove-orphans
	@docker system prune -f
	@echo "$(GREEN)✅ Docker cleanup completed$(NC)"

.PHONY: reset
reset: clean-docker clean setup ## 🔄 Complete reset and setup
	@echo "$(GREEN)✅ Complete reset finished$(NC)"

# ================================
# CI/CD Support
# ================================

.PHONY: ci-setup
ci-setup: check-deps deps-install ## 🤖 Setup for CI environment
	@echo "$(GREEN)✅ CI setup completed$(NC)"

.PHONY: ci-test
ci-test: test-unit test-security ## 🤖 Run CI tests
	@echo "$(GREEN)✅ CI tests completed$(NC)"

# ================================
# Examples & Demos
# ================================

.PHONY: run-basic-example
run-basic-example: ## 🎯 Run basic example
	@echo "$(BLUE)Running basic example...$(NC)"
	@cd examples/basic && go run main.go

.PHONY: run-gin-example
run-gin-example: ## 🎯 Run Gin framework example
	@echo "$(BLUE)Running Gin example...$(NC)"
	@cd examples/gin-basic && go run main.go

.PHONY: run-echo-example
run-echo-example: ## 🎯 Run Echo framework example
	@echo "$(BLUE)Running Echo example...$(NC)"
	@cd examples/echo-basic && go run main.go

.PHONY: demo
demo: ## 🎬 Run interactive demo
	@echo "$(BLUE)Starting interactive demo...$(NC)"
	@./scripts/demo.sh

# ================================
# Component Registry
# ================================

.PHONY: component-list
component-list: ## 📦 List all available components
	@./scripts/component-cli.sh list

.PHONY: component-info
component-info: ## 📦 Show component information (make component-info COMPONENT=core)
	@./scripts/component-cli.sh info $(COMPONENT)

.PHONY: component-validate
component-validate: ## 📦 Validate all components
	@./scripts/component-cli.sh validate

.PHONY: component-bump
component-bump: ## 📦 Bump component version (make component-bump COMPONENT=core TYPE=minor)
	@./scripts/component-cli.sh bump $(COMPONENT) $(TYPE)

.PHONY: component-publish
component-publish: ## 📦 Publish component (make component-publish COMPONENT=core)
	@./scripts/component-cli.sh publish $(COMPONENT) $(TYPE)

.PHONY: component-registry
component-registry: ## 📦 Build component registry index
	@./scripts/component-cli.sh build-registry

.PHONY: component-install
component-install: ## 📦 Install component locally (make component-install COMPONENT=core VERSION=latest)
	@./scripts/component-cli.sh install $(COMPONENT) $(VERSION)

.PHONY: component-help
component-help: ## 📦 Show component registry help
	@echo "$(CYAN)$(BOLD)Component Registry Commands:$(NC)"
	@echo "  make component-list           - List all components and versions"
	@echo "  make component-info COMPONENT=<name>  - Show detailed component info"
	@echo "  make component-validate       - Validate all component manifests"
	@echo "  make component-bump COMPONENT=<name> TYPE=<patch|minor|major>  - Bump version"
	@echo "  make component-publish COMPONENT=<name>  - Trigger component release"
	@echo "  make component-registry       - Build and update registry index"
	@echo "  make component-install COMPONENT=<name> VERSION=<version>  - Install locally"
	@echo ""
	@echo "$(YELLOW)Examples:$(NC)"
	@echo "  make component-info COMPONENT=core"
	@echo "  make component-bump COMPONENT=middleware TYPE=minor"
	@echo "  make component-publish COMPONENT=core"
	@echo ""
	@echo "$(YELLOW)Available Components:$(NC)"
	@echo "  • core - Core Zero Trust authentication library"
	@echo "  • middleware - Framework middleware (Gin, Echo, Fiber, gRPC)"
	@echo "  • clients - Multi-language client SDKs (Java, Python)"
	@echo "  • examples - Complete examples and templates"

# ================================
# Help System Updates
# ================================

# Additional convenience targets for development
.PHONY: help-categories
help-categories: ## 📚 Show help for specific categories
	@echo "$(CYAN)$(BOLD)Available Help Categories:$(NC)"
	@echo "  make setup-help      - Setup and environment commands"
	@echo "  make dev-help        - Development workflow commands" 
	@echo "  make test-help       - Testing and validation commands"
	@echo "  make services-help   - Service management commands"
	@echo "  make keycloak-help   - Keycloak specific commands"
	@echo "  make docker-help     - Docker and cleanup commands"
	@echo "  make component-help  - Component registry commands"

# ================================
# Default target
# ================================

.DEFAULT_GOAL := help