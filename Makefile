.PHONY: help dev-up dev-down build test clean logs deploy-local

# Default target
help:
	@echo "Available targets:"
	@echo "  dev-up          - Start development environment"
	@echo "  dev-down        - Stop development environment"
	@echo "  build           - Build all services"
	@echo "  test            - Run all tests"
	@echo "  test-coverage   - Run tests with coverage"
	@echo "  test-integration- Run integration tests"
	@echo "  clean           - Clean up containers and volumes"
	@echo "  logs            - Show logs from all services"
	@echo "  deploy-local    - Deploy to local Kubernetes"

# Development environment
dev-up:
	@echo "🚀 Starting development environment..."
	docker-compose up -d
	@echo "✅ Development environment started"
	@echo "🔍 Services available at:"
	@echo "  - Grafana: http://localhost:3000 (admin/admin)"
	@echo "  - Prometheus: http://localhost:9090"
	@echo "  - Jaeger: http://localhost:16686"
	@echo "  - Envoy Admin: http://localhost:9901"

dev-down:
	@echo "🛑 Stopping development environment..."
	docker-compose down -v
	@echo "✅ Development environment stopped"

logs:
	docker-compose logs -f

# Build targets
build:
	@echo "🔨 Building all services..."
	./scripts/build.sh

build-frontend:
	@echo "🔨 Building frontend..."
	cd frontend && npm run build

# Test targets
test:
	@echo "🧪 Running tests..."
	go test -race -v ./...

test-coverage:
	@echo "🧪 Running tests with coverage..."
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html

test-integration:
	@echo "🧪 Running integration tests..."
	go test -tags=integration -v ./tests/integration/...

test-load:
	@echo "🧪 Running load tests..."
	k6 run tests/load/basic-load-test.js

# Clean up
clean:
	@echo "🧹 Cleaning up..."
	docker-compose down -v --remove-orphans
	docker system prune -f
	docker volume prune -f

# Deployment
deploy-local:
	@echo "🚀 Deploying to local Kubernetes..."
	./scripts/deploy-local.sh

# Database operations
db-migrate:
	@echo "📊 Running database migrations..."
	docker-compose exec postgres psql -U mvp_user -d mvp_db -f /docker-entrypoint-initdb.d/migrations.sql

# Certificate operations
certs-generate:
	@echo "🔐 Generating development certificates..."
	./scripts/generate-certs.sh

# Monitoring
monitoring-setup:
	@echo "📊 Setting up monitoring dashboards..."
	./scripts/setup-monitoring.sh
