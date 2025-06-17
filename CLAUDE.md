# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Zero Trust Authentication MVP built with Go, using the Fiber web framework. The project implements a microservices architecture with comprehensive observability including structured logging, distributed tracing, and metrics.

## Build and Development Commands

### Core Development Commands
- `make dev-up` - Start the development environment with Docker Compose (includes Grafana, Prometheus, Jaeger, Envoy)
- `make dev-down` - Stop the development environment and clean up volumes
- `make build` - Build all services using `./scripts/build.sh`
- `make build-frontend` - Build the frontend specifically

### Testing Commands
- `make test` - Run all tests with race detection (`go test -race -v ./...`)
- `make test-coverage` - Run tests with coverage report generation
- `make test-integration` - Run integration tests (`go test -tags=integration -v ./tests/integration/...`)
  - Requires Docker Compose environment to be running (`make dev-up`)
  - Tests PostgreSQL, Redis, NATS, Prometheus, Grafana, Jaeger, and SPIRE connectivity
- `make test-load` - Run load tests using k6

### Other Commands
- `make logs` - Follow logs from all Docker Compose services
- `make clean` - Clean up containers, volumes, and prune Docker system
- `make deploy-local` - Deploy to local Kubernetes using `./scripts/deploy-local.sh`
- `make db-migrate` - Run database migrations
- `make certs-generate` - Generate development certificates
- `make monitoring-setup` - Set up monitoring dashboards

## Architecture Overview

### Core Packages
- **pkg/observability/** - Centralized observability implementation with OpenTelemetry integration
  - Structured logging with zerolog
  - Distributed tracing with Jaeger
  - Metrics with Prometheus
  - Security metrics tracking

- **pkg/messaging/** - NATS messaging system integration for inter-service communication

- **pkg/middleware/** - HTTP middleware components
  - Observability middleware for automatic request tracing and metrics

- **pkg/testutil/** - Testing utilities, particularly for observability mocking

### Infrastructure
- **deployments/kubernetes/** - Kubernetes manifests including SPIRE configurations
- **deployments/spire/** - SPIRE agent and server configurations for workload identity
- **docker-compose.yml** - Main development environment setup
- **docker-compose.observability.yml** - Observability stack configuration

### Testing
- **tests/integration/** - Integration tests for infrastructure and observability
- **tests/load/** - k6 load testing scripts

### Frontend
- Built with Vite (`npm run dev`, `npm run build`)
- Located in the `frontend/` directory

## Key Dependencies
- Web Framework: Fiber v2
- Messaging: NATS
- Observability: OpenTelemetry, Prometheus, Jaeger, zerolog
- Testing: testify, testcontainers
- Frontend: Vite

## Development Tips
- The project uses Go 1.23.8 with toolchain 1.23.10
- Services are accessible at:
  - Grafana: http://localhost:3000 (admin/admin)
  - Prometheus: http://localhost:9090
  - Jaeger: http://localhost:16686
  - Envoy Admin: http://localhost:9901