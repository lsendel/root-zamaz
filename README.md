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

📖 **[Project Wiki](https://github.com/lsendel/root-zamaz/wiki)** - Complete documentation with interactive diagrams

### Quick Links
- 🔐 [Database Schema](https://github.com/lsendel/root-zamaz/wiki/Database-Schema) - Domain-driven schema with Mermaid diagrams
- 🛡️ [Security Architecture](https://github.com/lsendel/root-zamaz/wiki/Architecture-Security) - Zero Trust implementation  
- 🚀 [Getting Started](https://github.com/lsendel/root-zamaz/wiki/Development-Setup) - Quick setup guide
- 📊 [API Documentation](https://github.com/lsendel/root-zamaz/wiki/API-Documentation) - REST API reference
- 🏗️ [Development Guide](https://github.com/lsendel/root-zamaz/wiki/Development-Guide) - Contributing guidelines

### Documentation Commands
```bash
# Generate and sync to wiki
make docs-wiki-sync-api

# Local development
make docs-mkdocs-serve      # Serve locally with live reload  
make docs-schema            # Generate schema docs only
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
