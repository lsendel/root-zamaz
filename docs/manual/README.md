# Manual Documentation Index

This directory contains manually maintained documentation that is always available, regardless of database connectivity.

## 📚 Available Documentation

### 🏗️ Architecture
- [Security Architecture](../architecture/security.md)
- [Zero Trust Implementation](../architecture/zero-trust.md)
- [Service Discovery](../SERVICE_DISCOVERY.md)

### 💻 Development
- [Development Guide](../development/README.md)
- [Setup Instructions](../development/setup.md)
- [API Documentation](../development/api-documentation.md)
- [Testing Guidelines](../development/testing.md)
- [Code Style](../development/code-style.md)

### 🔐 Security
- [Security Policies](../security/policies.md)
- [Threat Model](../security/threat-model.md)
- [Incident Response](../security/incident-response.md)
- [Security Scanning](../security/security-scanning-setup.md)

### ⚙️ Operations
- [GitOps Implementation](../GITOPS_IMPLEMENTATION_PLAN.md)
- [GitOps Quickstart](../GITOPS_QUICKSTART.md)
- [Troubleshooting](../troubleshooting.md)

## 🔄 Schema Documentation

Schema documentation is generated separately and requires database connectivity:
- To generate: `make docs-schema`
- To view: Check `docs/schema/` directory after generation

## 📖 Combined Documentation

To generate complete documentation including schema (when available):
```bash
make docs-combined
```

This creates a unified documentation set in `docs/combined/` that includes both manual and schema documentation.