# 📦 Component Registry

Welcome to the Go Keycloak Zero Trust Component Registry! This registry provides versioned, reusable components for building Zero Trust authentication systems.

## 🚀 Quick Start

### Install GitHub CLI Component Extension
```bash
# Install GitHub CLI if not already installed
# https://cli.github.com/

# Install component extension
gh extension install github/gh-component
```

### Install Components

#### Method 1: GitHub Component CLI
```bash
# Install core component
gh component install yourorg/zerotrust-core@latest

# Install specific version
gh component install yourorg/zerotrust-middleware@1.0.0

# Install all components
gh component install yourorg/zerotrust-complete@latest
```

#### Method 2: Go Modules
```bash
# Core library
go get github.com/yourorg/go-keycloak-zerotrust/components/core@v1.0.0

# Middleware
go get github.com/yourorg/go-keycloak-zerotrust/components/middleware@v1.0.0

# All components
go get github.com/yourorg/go-keycloak-zerotrust@v1.0.0
```

#### Method 3: Container Registry
```bash
# Pull component containers
docker pull ghcr.io/yourorg/zerotrust-core:1.0.0
docker pull ghcr.io/yourorg/zerotrust-middleware:1.0.0

# Extract component files
docker create --name temp ghcr.io/yourorg/zerotrust-core:1.0.0
docker cp temp:/component/ ./vendor/zerotrust-core/
docker rm temp
```

#### Method 4: Component CLI Script
```bash
# Use our component CLI
./scripts/component-cli.sh install core latest
./scripts/component-cli.sh install middleware 1.0.0
```

## 📋 Available Components

### 🔐 Core Component
**Version**: 1.0.0  
**Description**: Core Zero Trust authentication library with Keycloak integration

**Features**:
- JWT token validation and introspection
- Device attestation (Android SafetyNet, iOS DeviceCheck, WebAuthn)
- Risk assessment and behavioral analysis
- Trust score calculation with decay algorithms
- Redis and in-memory caching
- PostgreSQL integration for audit logging

**Installation**:
```bash
go get github.com/yourorg/go-keycloak-zerotrust/components/core@v1.0.0
```

**Usage**:
```go
import "github.com/yourorg/go-keycloak-zerotrust/components/core/zerotrust"

config, _ := zerotrust.LoadConfigFromEnv()
client, _ := zerotrust.NewKeycloakClient(config)
defer client.Close()

// Validate token
claims, err := client.ValidateToken(context.Background(), token)
```

### 🔧 Middleware Component
**Version**: 1.0.0  
**Description**: Framework middleware for Go web frameworks

**Supported Frameworks**:
- **Gin** - High-performance HTTP framework
- **Echo** - Minimalist web framework  
- **Fiber** - Express-inspired framework
- **gRPC** - High-performance RPC framework

**Installation**:
```bash
go get github.com/yourorg/go-keycloak-zerotrust/components/middleware@v1.0.0
```

**Usage**:
```go
// Gin example
import "github.com/yourorg/go-keycloak-zerotrust/components/middleware"

middleware := zerotrust.NewGinMiddleware(client)
router.Use(middleware.Authenticate())
router.GET("/api/data", middleware.RequireTrustLevel(50), handler)
```

### 🌐 Clients Component
**Version**: 1.0.0  
**Description**: Multi-language client SDKs

**Languages**:
- **Java** - Spring Boot integration with comprehensive examples
- **Python** - FastAPI integration with async support
- **Go** - Native Go client (same as core)

**Installation**:
```bash
# Java (Maven)
<dependency>
    <groupId>com.yourorg</groupId>
    <artifactId>zerotrust-client</artifactId>
    <version>1.0.0</version>
</dependency>

# Python (pip)
pip install zerotrust-client==1.0.0
```

### 📚 Examples Component
**Version**: 1.0.0  
**Description**: Complete examples and templates

**Included Examples**:
- Basic authentication patterns
- Trust level-based authorization
- Device attestation workflows
- Risk-based access control
- Multi-framework integration
- Production deployment templates

**Installation**:
```bash
gh component install yourorg/zerotrust-examples@1.0.0
```

## 🔄 Component Lifecycle

### Versioning Strategy
We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

### Release Process
1. **Development**: Feature development in component directories
2. **Testing**: Automated testing via GitHub Actions
3. **Versioning**: Automatic version bumping based on changes
4. **Publishing**: Multi-format publishing (Go modules, containers, archives)
5. **Registry Update**: Automatic registry index updates

### Quality Gates
- ✅ Unit tests (>90% coverage)
- ✅ Integration tests
- ✅ Security scanning
- ✅ Performance benchmarks
- ✅ Documentation validation
- ✅ Multi-platform compatibility

## 🛠️ Development Workflow

### Component Structure
```
components/
├── core/
│   ├── VERSION              # Semantic version
│   ├── component.yaml       # Component manifest
│   ├── README.md           # Component documentation
│   └── src/                # Source code
├── middleware/
│   ├── VERSION
│   ├── component.yaml
│   └── ...
└── registry/
    ├── index.yaml          # Registry index
    ├── components.json     # JSON API
    └── README.md          # This file
```

### Adding New Components
1. Create component directory: `components/new-component/`
2. Add VERSION file: `echo "0.1.0" > components/new-component/VERSION`
3. Create component.yaml manifest
4. Add source code and documentation
5. Update CI/CD workflows
6. Commit and push - automatic release triggers

### Local Development
```bash
# List components
./scripts/component-cli.sh list

# Get component info
./scripts/component-cli.sh info core

# Validate components
./scripts/component-cli.sh validate

# Bump version
./scripts/component-cli.sh bump core minor

# Build registry
./scripts/component-cli.sh build-registry
```

## 🔍 Registry API

### REST API Endpoints
- **Registry Index**: `GET /registry/components.json`
- **Component Info**: `GET /components/{name}/component.yaml`
- **Version History**: `GET /components/{name}/versions.json`

### Example API Usage
```bash
# Get all components
curl -s https://raw.githubusercontent.com/yourorg/go-keycloak-zerotrust/main/registry/components.json | jq .

# Get specific component
curl -s https://raw.githubusercontent.com/yourorg/go-keycloak-zerotrust/main/components/core/component.yaml
```

### Registry Schema
```json
{
  "registry": "github.com/yourorg/go-keycloak-zerotrust",
  "namespace": "yourorg",
  "components": [
    {
      "name": "core",
      "version": "1.0.0",
      "description": "Core Zero Trust authentication library",
      "tags": ["zero-trust", "authentication", "core"],
      "install": {
        "go": "go get github.com/yourorg/go-keycloak-zerotrust/components/core@v1.0.0",
        "container": "docker pull ghcr.io/yourorg/zerotrust-core:1.0.0",
        "script": "./scripts/component-cli.sh install core 1.0.0"
      },
      "updated": "2024-01-15T10:30:00Z"
    }
  ]
}
```

## 🔐 Security & Compliance

### Component Security
- **Signed Releases**: All components are cryptographically signed
- **Vulnerability Scanning**: Automated security scanning on every release
- **SBOM Generation**: Software Bill of Materials for all components
- **License Compliance**: Automated license checking

### Access Control
- **Registry Access**: Public read, authenticated write
- **Component Publishing**: Requires maintainer permissions
- **Version Immutability**: Published versions cannot be modified

## 📊 Metrics & Monitoring

### Component Usage Analytics
- Download counts per component/version
- Installation method preferences
- Geographic distribution
- Framework adoption rates

### Quality Metrics
- Test coverage per component
- Performance benchmarks
- Security scan results
- Documentation completeness

## 🤝 Contributing

### Contributing to Components
1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-component`
3. Add/modify components following our standards
4. Ensure tests pass: `make test-all`
5. Submit pull request

### Component Standards
- **Documentation**: Complete README and API docs
- **Testing**: >90% test coverage
- **Security**: Security scan passing
- **Performance**: Benchmark validation
- **Compatibility**: Multi-platform support

### Review Process
1. **Automated Checks**: CI/CD pipeline validation
2. **Security Review**: Security team approval for new components
3. **API Review**: Breaking change review for major versions
4. **Documentation Review**: Technical writing team review

## 📞 Support

### Community Support
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Community Q&A
- **Stack Overflow**: Tag `go-keycloak-zerotrust`
- **Discord**: Real-time community chat

### Enterprise Support
- **Professional Support**: $500/month
- **Enterprise Support**: $2000/month  
- **Custom Components**: Professional services available

### Resources
- **Documentation**: [docs/](../docs/)
- **Examples**: [examples/](../examples/)
- **API Reference**: [API Docs](../docs/api-reference.md)
- **Migration Guides**: [Migration](../docs/migration/)

---

## 🎯 Roadmap

### Version 1.x
- ✅ Core authentication library
- ✅ Framework middleware
- ✅ Multi-language clients
- ✅ Component registry

### Version 2.x (Q2 2024)
- 🔄 Enhanced device attestation
- 🔄 Machine learning risk models
- 🔄 Advanced compliance features
- 🔄 Cloud provider integrations

### Version 3.x (Q4 2024)
- 📋 Zero Trust network components
- 📋 Mesh integration components
- 📋 Policy engine components
- 📋 Analytics dashboard components

---

**🏆 The Go Keycloak Zero Trust Component Registry - Building secure, scalable authentication systems one component at a time.**