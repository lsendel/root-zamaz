# Documentation Index

Welcome to the comprehensive documentation for the go-keycloak-zerotrust library. This documentation covers everything from basic setup to advanced enterprise deployments.

## 📚 Documentation Structure

### Getting Started
- **[Quick Start Guide](../README.md#quick-start)** - Get up and running in 5 minutes
- **[Installation Guide](installation.md)** - Detailed installation instructions
- **[Basic Examples](../examples/basic_example.go)** - Simple implementation examples

### Core Documentation
- **[API Reference](api-reference.md)** - Complete API documentation
- **[Architecture Overview](architecture.md)** - System design and components
- **[Configuration Guide](configuration.md)** - Advanced configuration options

### Setup Guides
- **[Keycloak Setup](keycloak-setup.md)** - Complete Keycloak configuration guide
- **[Production Deployment](deployment.md)** - Production-ready deployment strategies
- **[Security Hardening](security.md)** - Security best practices and hardening

### Framework Integration
- **[Gin Integration](frameworks/gin.md)** - Gin framework middleware
- **[Echo Integration](frameworks/echo.md)** - Echo framework middleware
- **[Fiber Integration](frameworks/fiber.md)** - Fiber framework middleware
- **[gRPC Integration](frameworks/grpc.md)** - gRPC interceptors

### Zero Trust Features
- **[Device Attestation](zerotrust/device-attestation.md)** - Hardware-based device verification
- **[Risk Assessment](zerotrust/risk-assessment.md)** - Real-time risk evaluation
- **[Trust Engine](zerotrust/trust-engine.md)** - Dynamic trust scoring
- **[Continuous Verification](zerotrust/continuous-verification.md)** - Ongoing security monitoring

### Multi-Language Support
- **[Java Client](../clients/java/README.md)** - Spring Boot integration
- **[Python Client](../clients/python/README.md)** - FastAPI integration
- **[JavaScript SDK](clients/javascript.md)** - Browser and Node.js support

### Advanced Topics
- **[Plugin Development](plugins/development.md)** - Creating custom plugins
- **[Performance Optimization](performance.md)** - Tuning and scaling
- **[Monitoring & Observability](monitoring.md)** - Metrics, logging, and tracing
- **[Troubleshooting](troubleshooting.md)** - Common issues and solutions

### Enterprise Features
- **[Multi-Tenancy](enterprise/multi-tenancy.md)** - Tenant isolation and management
- **[High Availability](enterprise/high-availability.md)** - Clustering and failover
- **[Compliance](enterprise/compliance.md)** - GDPR, SOC 2, NIST compliance
- **[Enterprise Integration](enterprise/integration.md)** - SIEM, directory services

## 🚀 Quick Navigation

### By Use Case

#### For Developers
- [Basic Integration Guide](../README.md#quick-start)
- [Framework Examples](../examples/frameworks/)
- [API Reference](api-reference.md)
- [Testing Guide](testing.md)

#### For DevOps Engineers
- [Deployment Guide](deployment.md)
- [Monitoring Setup](monitoring.md)
- [Performance Tuning](performance.md)
- [Troubleshooting](troubleshooting.md)

#### For Security Teams
- [Security Architecture](architecture.md#security-architecture)
- [Zero Trust Implementation](zerotrust/)
- [Security Hardening](security.md)
- [Compliance Features](enterprise/compliance.md)

#### For Architects
- [Architecture Overview](architecture.md)
- [Scaling Strategies](performance.md#scaling)
- [Integration Patterns](enterprise/integration.md)
- [Enterprise Features](enterprise/)

### By Technology

#### Keycloak
- [Setup Guide](keycloak-setup.md)
- [Configuration](configuration.md#keycloak)
- [Integration](api-reference.md#keycloak-client)

#### Frameworks
- [Gin](frameworks/gin.md) | [Echo](frameworks/echo.md) | [Fiber](frameworks/fiber.md) | [gRPC](frameworks/grpc.md)

#### Languages
- [Go](api-reference.md) | [Java](../clients/java/README.md) | [Python](../clients/python/README.md)

#### Infrastructure
- [Docker](deployment.md#docker) | [Kubernetes](deployment.md#kubernetes) | [Cloud](deployment.md#cloud)

## 📖 Documentation Conventions

### Code Examples
All code examples are tested and runnable. Look for:
- 🟢 **Production Ready**: Suitable for production use
- 🟡 **Development**: For development and testing
- 🔴 **Proof of Concept**: Illustrative examples only

### Documentation Tags
- **NEW**: Recently added features
- **UPDATED**: Recently updated content
- **DEPRECATED**: Features being phased out
- **ENTERPRISE**: Enterprise-only features

### Version Information
Documentation is maintained for:
- **Latest**: Current stable version (v1.0.0)
- **Development**: Upcoming features
- **Previous**: Last major version (when applicable)

## 🔧 Contributing to Documentation

We welcome documentation contributions! See our [Contributing Guide](../CONTRIBUTING.md#documentation) for:
- Writing guidelines
- Documentation standards
- Review process
- Tools and setup

### Quick Links for Contributors
- [Documentation Style Guide](contributing/style-guide.md)
- [Example Templates](contributing/templates/)
- [Local Development Setup](../CONTRIBUTING.md#development-setup)

## 📱 Mobile & Offline Access

### Mobile-Friendly
All documentation is optimized for mobile viewing with:
- Responsive design
- Touch-friendly navigation
- Offline capability (when supported)

### Download Options
- **PDF**: Complete documentation bundle
- **EPUB**: E-reader compatible format
- **Archive**: Offline HTML version

## 🔍 Search & Discovery

### Search Tips
Use the search functionality to find:
- API methods: `ValidateToken`
- Configuration options: `trust_level_thresholds`
- Error codes: `ErrInvalidToken`
- Use cases: `device attestation example`

### Tags & Categories
Browse by tags:
- `#getting-started` - Beginner content
- `#enterprise` - Enterprise features
- `#security` - Security-related topics
- `#performance` - Performance optimization
- `#examples` - Code examples and tutorials

## 📊 Documentation Metrics

We track documentation quality through:
- **Completeness**: API coverage percentage
- **Accuracy**: Community feedback and corrections
- **Usability**: User task completion rates
- **Freshness**: Update frequency and relevance

Current status:
- ✅ API Coverage: 100%
- ✅ Examples: 95%
- ✅ Tutorials: 90%
- ✅ Enterprise Docs: 85%

## 🆘 Getting Help

### If You Can't Find What You Need

1. **Check the FAQ**: Common questions and answers
2. **Search GitHub Issues**: Existing discussions and solutions
3. **Ask the Community**: GitHub Discussions for help
4. **Contact Support**: Enterprise customers can contact support

### Documentation Feedback

Help us improve the documentation:
- **Report Issues**: Found an error? Report it!
- **Suggest Improvements**: Ideas for better explanations
- **Request Content**: Missing documentation requests
- **Rate Content**: Help us prioritize updates

### Support Channels
- 📧 **Email**: [docs@yourorg.com](mailto:docs@yourorg.com)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourorg/go-keycloak-zerotrust/discussions)
- 🐛 **Issues**: [GitHub Issues](https://github.com/yourorg/go-keycloak-zerotrust/issues)

---

## 📋 Document Index

### Core Documentation
| Document | Description | Audience | Complexity |
|----------|-------------|----------|------------|
| [README](../README.md) | Project overview and quick start | All | Beginner |
| [API Reference](api-reference.md) | Complete API documentation | Developers | Intermediate |
| [Architecture](architecture.md) | System design and patterns | Architects | Advanced |
| [Configuration](configuration.md) | Configuration options | DevOps | Intermediate |

### Setup & Deployment
| Document | Description | Audience | Complexity |
|----------|-------------|----------|------------|
| [Keycloak Setup](keycloak-setup.md) | Keycloak configuration | Admins | Intermediate |
| [Deployment](deployment.md) | Production deployment | DevOps | Advanced |
| [Security](security.md) | Security hardening | Security | Advanced |
| [Monitoring](monitoring.md) | Observability setup | DevOps | Intermediate |

### Framework Guides
| Document | Description | Audience | Complexity |
|----------|-------------|----------|------------|
| [Gin](frameworks/gin.md) | Gin framework integration | Developers | Beginner |
| [Echo](frameworks/echo.md) | Echo framework integration | Developers | Beginner |
| [Fiber](frameworks/fiber.md) | Fiber framework integration | Developers | Beginner |
| [gRPC](frameworks/grpc.md) | gRPC interceptors | Developers | Intermediate |

### Zero Trust Features
| Document | Description | Audience | Complexity |
|----------|-------------|----------|------------|
| [Device Attestation](zerotrust/device-attestation.md) | Hardware verification | Security | Advanced |
| [Risk Assessment](zerotrust/risk-assessment.md) | Risk evaluation | Security | Advanced |
| [Trust Engine](zerotrust/trust-engine.md) | Trust scoring | Security | Advanced |
| [Continuous Verification](zerotrust/continuous-verification.md) | Ongoing monitoring | Security | Advanced |

### Enterprise Features
| Document | Description | Audience | Complexity |
|----------|-------------|----------|------------|
| [Multi-Tenancy](enterprise/multi-tenancy.md) | Tenant management | Architects | Advanced |
| [High Availability](enterprise/high-availability.md) | Clustering strategies | DevOps | Advanced |
| [Compliance](enterprise/compliance.md) | Regulatory compliance | Legal/Security | Advanced |
| [Integration](enterprise/integration.md) | Enterprise integrations | Architects | Advanced |

---

*This documentation is maintained by the go-keycloak-zerotrust team and community contributors. Last updated: January 2024*