# Zero Trust Authentication MVP

Modern authentication system implementing Zero Trust principles with GitOps deployment model.

## Features

- Zero Trust Authentication
- GitOps-based deployment
- Comprehensive observability
- Progressive delivery
- High availability design
- Security-first approach

## Quick Start

```bash
# Development setup
make dev-setup
make dev-up

# GitOps local environment
make dev-gitops

# Run tests
make test-all
```

## Documentation

📚 **[Complete Documentation](https://zamaz.github.io/root-zamaz)** | **[GitHub Wiki](https://github.com/zamaz/root-zamaz/wiki)** | **[Local Docs](http://127.0.0.1:8001)**

### Quick Links
- 🔐 [Database Schema](https://zamaz.github.io/root-zamaz/schema/) - Domain-driven schema documentation
- 🛡️ [Security Architecture](https://zamaz.github.io/root-zamaz/architecture/security/) - Zero Trust implementation
- 🚀 [Getting Started](https://zamaz.github.io/root-zamaz/getting-started/quick-start/) - Quick setup guide
- 📊 [API Documentation](https://zamaz.github.io/root-zamaz/api/) - REST API reference
- 🏗️ [Development Guide](https://zamaz.github.io/root-zamaz/development/) - Contributing guidelines

### Documentation Commands
```bash
# Generate all documentation
make docs-ci

# Serve documentation locally  
make docs-mkdocs-serve

# Generate schema documentation only
make docs-schema

# Sync documentation to GitHub Wiki
make docs-wiki-sync-api
```

### Local Documentation
- [Database Change Management](docs/database/bytebase.md)

- [Development Guide](docs/development/README.md)
- [Architecture](docs/architecture/README.md)
- [API Reference](docs/api/README.md)
- [Deployment Guide](docs/deployment/README.md)
- [Security](docs/security/README.md)

## Requirements

- Go 1.22+
- Node.js 20+
- Docker
- Kubernetes 1.28+
- Helm 3.14+

## Architecture

```mermaid
graph TB
    Client --> Ingress
    Ingress --> AuthService
    AuthService --> TokenService
    AuthService --> UserService
    TokenService --> Vault
    UserService --> Database
```

## Security

[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=your-org_zamaz&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=your-org_zamaz)
[![Vulnerabilities](https://snyk.io/test/github/your-org/zamaz/badge.svg)](https://snyk.io/test/github/your-org/zamaz)

## License

MIT License - see [LICENSE](LICENSE) for details
