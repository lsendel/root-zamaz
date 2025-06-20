# CI/CD Pipeline Overview

## Introduction

The Zamaz project implements a comprehensive, modern CI/CD pipeline with security-first principles, multi-architecture support, and full integration with the service discovery and Istio service mesh infrastructure.

> **Enterprise-Grade**: Our CI/CD pipeline follows industry best practices with automated security scanning, multi-stage deployment, and comprehensive testing across multiple environments.

## Pipeline Architecture

### 🔄 Modern CI Pipeline

Our CI pipeline is built around four main phases:

#### Phase 1: Preparation
- **Environment Detection**: Auto-detects deployment environment and version
- **Build Matrix Generation**: Dynamic service discovery for build targets  
- **Safety Checks**: Validation for production deployments
- **Skip Conditions**: Emergency deployment capabilities

#### Phase 2: Quality Gates
- **Code Quality**: Go linting, frontend linting, formatting checks
- **Security Scans**: Multi-tool security validation
- **Test Coverage**: Backend and frontend comprehensive testing
- **Service Mesh Testing**: Istio and service discovery validation

#### Phase 3: Build & Package
- **Multi-Architecture Builds**: Linux (amd64/arm64), Darwin, Windows
- **Container Images**: Multi-platform Docker builds with security scanning
- **Artifact Generation**: Binaries, packages, and deployment manifests

#### Phase 4: Deployment
- **Infrastructure Validation**: Kubernetes manifests, Helm charts, docker-compose
- **Service Discovery Testing**: End-to-end service mesh validation
- **Environment-Specific Deployment**: Staging and production pipelines

### 🛡️ Enhanced Security Pipeline

Our security-first approach includes multi-stage scanning:

#### 1. Dependency Vulnerabilities
- **GoVulnCheck**: Go-specific vulnerability scanning
- **Nancy**: Sonatype dependency analysis
- **NPM Audit**: Frontend dependency security
- **Trivy FS**: Filesystem vulnerability scanning

#### 2. Secret Detection
- **GitLeaks**: Git repository secret scanning with custom rules
- **TruffleHog**: Advanced pattern-based secret detection

#### 3. Static Application Security Testing (SAST)
- **CodeQL**: GitHub's semantic code analysis
- **GoSec**: Go security-focused static analysis
- **Semgrep**: Multi-language pattern-based scanning

#### 4. Container Security
- **Trivy Container**: Container image vulnerability scanning
- **Hadolint**: Dockerfile best practices linting
- **Dockle**: Container image security assessment

#### 5. Infrastructure Security
- **Checkov**: Infrastructure as Code security scanning
- **KICS**: Kubernetes and infrastructure security analysis

### 🚀 Release Pipeline

Automated release management includes:

- **Semantic Versioning**: Automatic version validation and tagging
- **Multi-Platform Builds**: GoReleaser-powered cross-compilation
- **Package Distribution**: Multiple package managers (Homebrew, AUR, Snap, Winget, Nix)
- **Container Registry**: Multi-architecture container images
- **Kubernetes Artifacts**: Ready-to-deploy manifests and Helm charts

### ⚓ Kubernetes Deployment

Advanced deployment features:

- **Multi-Environment Support**: Staging and production pipelines
- **Safety Validations**: Production deployment guards and rollback capabilities
- **Service Discovery Integration**: Consul and Kubernetes DNS validation
- **Istio Service Mesh**: Traffic management and security policy deployment
- **Health Monitoring**: Comprehensive post-deployment validation

## Key Features

### 🔍 Security-First Approach

1. **Multi-Tool Scanning**: Combines multiple security tools for comprehensive coverage
2. **Container Security**: Base image vulnerability scanning and runtime analysis
3. **Supply Chain Security**: Dependency vulnerability tracking and SBOM generation

### ⚡ Performance Optimizations

1. **Parallel Execution**: Matrix builds for multiple platforms
2. **Intelligent Caching**: Go modules, Docker layers, and NPM dependencies
3. **Conditional Execution**: Path-based triggers and environment-specific workflows

### 🏗️ Infrastructure Integration

1. **Service Discovery Testing**: Consul and Kubernetes DNS validation
2. **Istio Service Mesh**: Traffic management and security policy validation
3. **Multi-Environment Support**: Environment-specific configurations and deployment strategies

## Pipeline Workflows

### Workflow Files

| Workflow | File | Purpose |
|----------|------|---------|
| **Modern CI** | `ci-modern.yml` | Main CI/CD pipeline with testing and deployment |
| **Security Scanning** | `security-enhanced.yml` | Comprehensive security validation |
| **Release Management** | `release-modern.yml` | Automated releases with GoReleaser |
| **Kubernetes Deployment** | `deploy-k8s.yml` | Production Kubernetes deployment |

### Trigger Conditions

#### Automatic Triggers
- **Push to main/develop**: Full CI pipeline with deployment to staging
- **Pull Requests**: CI pipeline with security scanning
- **Tag Creation** (`v*.*.*`): Release pipeline with multi-platform builds
- **Schedule**: Daily security scans at 2 AM UTC

#### Manual Triggers
- **Workflow Dispatch**: Manual deployment with environment selection
- **Emergency Deploy**: Skip tests for critical deployments
- **Security Scan**: On-demand security validation

## Environment Configuration

### Staging Environment
- **Namespace**: `zamaz-staging`
- **Replicas**: 2 per service
- **Resources**: Standard allocations
- **Auto-Deploy**: On main branch pushes

### Production Environment
- **Namespace**: `zamaz-production`
- **Replicas**: 3 per service with HA
- **Resources**: Production-grade allocations
- **Deploy**: Manual approval required
- **Safety**: Tagged versions only

## Make Integration

The pipeline integrates with our Make-based build system:

```bash
# CI/CD Management Commands
make cicd-validate         # Validate all CI/CD configurations
make cicd-test-workflows   # Test workflows locally
make cicd-security-test    # Test security scanning pipeline
make cicd-release-test     # Test release build process
make cicd-status          # Show pipeline status
make cicd-monitor         # Monitor pipeline metrics
```

## Security Baseline

### Required Security Controls
1. **Code Scanning**: SAST tools for all languages
2. **Dependency Scanning**: Vulnerability assessment for all dependencies
3. **Container Scanning**: Base image and runtime security
4. **Secret Detection**: Comprehensive secret scanning
5. **Infrastructure Scanning**: IaC security validation

### Compliance Validation
- **Security Files**: Required security configuration files
- **Docker Security**: Non-root users, health checks, minimal base images
- **Kubernetes Security**: Security contexts, RBAC, network policies
- **Service Mesh**: mTLS, authorization policies, traffic encryption

## Monitoring & Observability

### Pipeline Metrics
- **Build Times**: Track build performance across environments
- **Test Coverage**: Maintain 80%+ code coverage
- **Security Scores**: Track vulnerability trends
- **Deployment Success**: Monitor deployment reliability

### Alerting
- **Failed Builds**: Immediate notification for pipeline failures
- **Security Issues**: Alert on new vulnerabilities
- **Deployment Issues**: Monitor post-deployment health
- **Compliance Drift**: Track security baseline changes

## Rollback Procedures

### Automated Rollback
- **Health Check Failures**: Automatic rollback on service health issues
- **Circuit Breaker**: Service mesh-level failure detection
- **Resource Constraints**: Rollback on resource exhaustion

### Manual Rollback
```bash
# Kubernetes rollback
kubectl rollout undo deployment/zamaz-auth-service -n zamaz

# Version-specific rollback
kubectl set image deployment/zamaz-auth-service auth-service=ghcr.io/repo/auth-service:v1.2.3 -n zamaz

# Emergency procedures
make cicd-rollback
```

## Related Documentation

- **[CI Pipeline Details](ci-pipeline.md)** - Detailed CI workflow documentation
- **[Security Pipeline](security-pipeline.md)** - Security scanning and validation
- **[Release Pipeline](release-pipeline.md)** - Automated release management
- **[Deployment Pipeline](deployment-pipeline.md)** - Kubernetes deployment automation
- **[GitHub Actions](github-actions.md)** - Workflow configuration and setup

## Next Steps

1. **[Set up CI/CD locally](../development/setup.md)** - Configure local development environment
2. **[Understand the build process](build.md)** - Learn about our build automation
3. **[Deploy to staging](../deployment/kubernetes.md)** - Practice deployment procedures
4. **[Monitor pipelines](../operations/monitoring.md)** - Set up observability

This modern CI/CD pipeline provides a robust, secure, and scalable foundation for the Zamaz platform, integrating seamlessly with our service discovery and Istio service mesh infrastructure.