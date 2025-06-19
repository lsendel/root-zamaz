# Development Guide

## Prerequisites

- Go 1.22+
- Node.js 20+
- Docker
- Kubernetes (local development with kind/minikube)
- Helm 3.14+

## Quick Start

```bash
# Clone and set up development environment
make dev-setup

# Start local development environment with observability
make dev-up

# Start frontend development server
make dev-frontend

# Run tests
make test-all

# Run GitOps local environment
make dev-gitops
```

## Development Workflow

1. **Local Development**
   ```bash
   make dev-setup    # First time setup
   make dev-up       # Start local services
   make dev-frontend # Start frontend
   ```

2. **Testing**
   ```bash
   make test        # Run unit tests
   make test-e2e    # Run end-to-end tests
   make test-load   # Run load tests
   ```

3. **Quality Checks**
   ```bash
   make quality-all  # Run all quality checks
   make lint-fix     # Fix linting issues
   ```

4. **GitOps Development**
   ```bash
   make dev-gitops   # Start local GitOps environment
   make gitops-validate # Validate configurations
   ```

## Project Structure

```
├── cmd/            # Application entrypoints
├── pkg/            # Internal packages
├── api/            # API definitions
├── internal/       # Private application code
├── frontend/       # Frontend application
├── charts/         # Helm charts
├── deployments/    # Deployment configurations
├── docs/          # Documentation
└── scripts/       # Development and CI scripts
```

## Development Best Practices

1. **Code Style**
   - Follow [Go style guide](https://golang.org/doc/effective_go)
   - Use TypeScript for frontend development
   - Document all public APIs

2. **Testing**
   - Write unit tests for new code
   - Include integration tests for API changes
   - E2E tests for critical paths

3. **GitOps**
   - All configuration changes through Git
   - Use ArgoCD for deployments
   - Follow progressive delivery pattern

4. **Security**
   - Run SAST in CI pipeline
   - Regular dependency updates
   - Follow zero-trust principles

5. **Observability**
   - Include metrics for new features
   - Add tracing for API endpoints
   - Update dashboards for new services

## Environment Setup

### Configuration

Environment variables are managed through:
- `.env` for local development
- Helm values for Kubernetes
- Vault for secrets

### Dependencies

Dependencies are managed using:
- Go modules
- npm/pnpm for frontend
- Helm for Kubernetes resources

## Debugging

1. **Local Development**
   ```bash
   make dev-logs     # View service logs
   make dev-status   # Check service status
   ```

2. **Kubernetes**
   ```bash
   make k8s-debug    # Start debug session
   make k8s-logs     # View pod logs
   ```

## CI/CD Pipeline

Our CI/CD pipeline includes:
1. Automated tests
2. Quality gates
3. Security scanning
4. GitOps deployment

## Additional Resources

- [Architecture Documentation](docs/architecture/README.md)
- [API Documentation](docs/api/README.md)
- [Security Guidelines](docs/security/README.md)
- [Operations Manual](docs/operations/README.md)
