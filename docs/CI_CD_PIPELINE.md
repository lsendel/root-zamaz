# Modern CI/CD Pipeline Documentation

## Overview

The Zamaz project implements a comprehensive, modern CI/CD pipeline with security-first principles, multi-architecture support, and full integration with the service discovery and Istio service mesh infrastructure.

## Pipeline Architecture

### 🔄 **Modern CI Pipeline** (`.github/workflows/ci-modern.yml`)

#### **Phase 1: Preparation**
- **Environment Detection**: Auto-detects deployment environment and version
- **Build Matrix Generation**: Dynamic service discovery for build targets
- **Safety Checks**: Validation for production deployments
- **Skip Conditions**: Emergency deployment capabilities

#### **Phase 2: Quality Gates**
- **Code Quality**: Go linting, frontend linting, formatting checks
- **Security Scans**: Multi-tool security validation
- **Test Coverage**: Backend and frontend comprehensive testing
- **Service Mesh Testing**: Istio and service discovery validation

#### **Phase 3: Build & Package**
- **Multi-Architecture Builds**: Linux (amd64/arm64), Darwin, Windows
- **Container Images**: Multi-platform Docker builds with security scanning
- **Artifact Generation**: Binaries, packages, and deployment manifests

#### **Phase 4: Deployment**
- **Infrastructure Validation**: Kubernetes manifests, Helm charts, docker-compose
- **Service Discovery Testing**: End-to-end service mesh validation
- **Environment-Specific Deployment**: Staging and production pipelines

### 🛡️ **Enhanced Security Pipeline** (`.github/workflows/security-enhanced.yml`)

#### **Multi-Stage Security Scanning**

1. **Dependency Vulnerabilities**
   - **GoVulnCheck**: Go-specific vulnerability scanning
   - **Nancy**: Sonatype dependency analysis
   - **NPM Audit**: Frontend dependency security
   - **Trivy FS**: Filesystem vulnerability scanning

2. **Secret Detection**
   - **GitLeaks**: Git repository secret scanning with custom rules
   - **TruffleHog**: Advanced pattern-based secret detection

3. **Static Application Security Testing (SAST)**
   - **CodeQL**: GitHub's semantic code analysis
   - **GoSec**: Go security-focused static analysis
   - **Semgrep**: Multi-language pattern-based scanning

4. **Container Security**
   - **Trivy Container**: Container image vulnerability scanning
   - **Hadolint**: Dockerfile best practices linting
   - **Dockle**: Container image security assessment

5. **Infrastructure Security**
   - **Checkov**: Infrastructure as Code security scanning
   - **KICS**: Kubernetes and infrastructure security analysis

### 🚀 **Release Pipeline** (`.github/workflows/release-modern.yml`)

#### **Automated Release Management**
- **Semantic Versioning**: Automatic version validation and tagging
- **Multi-Platform Builds**: GoReleaser-powered cross-compilation
- **Package Distribution**: Multiple package managers (Homebrew, AUR, Snap, Winget, Nix)
- **Container Registry**: Multi-architecture container images
- **Kubernetes Artifacts**: Ready-to-deploy manifests and Helm charts

#### **Security & Compliance**
- **SBOM Generation**: Software Bill of Materials for all artifacts
- **Vulnerability Scanning**: Container and dependency security validation
- **Signature Verification**: Checksums and artifact integrity
- **Compliance Reporting**: Automated security baseline validation

### ⚓ **Kubernetes Deployment** (`.github/workflows/deploy-k8s.yml`)

#### **Advanced Deployment Features**
- **Multi-Environment Support**: Staging and production pipelines
- **Safety Validations**: Production deployment guards and rollback capabilities
- **Service Discovery Integration**: Consul and Kubernetes DNS validation
- **Istio Service Mesh**: Traffic management and security policy deployment
- **Health Monitoring**: Comprehensive post-deployment validation

## Configuration Files

### **GoReleaser Configuration** (`.goreleaser.yml`)

```yaml
# Modern release automation with:
builds:
  - Multi-platform binaries (Linux, macOS, Windows)
  - ARM64 and AMD64 support
  - Optimized build flags and linking

dockers:
  - Multi-architecture container images
  - Comprehensive image labeling
  - Security-optimized base images

release:
  - Automated changelog generation
  - GitHub release integration
  - Package manager distribution
```

### **Make Commands Integration**

The Makefile includes comprehensive CI/CD management commands:

```bash
# Validation & Testing
make cicd-validate         # Validate all CI/CD configurations
make cicd-test-workflows   # Test workflows locally with act
make cicd-security-test    # Test security scanning pipeline
make cicd-release-test     # Test release build process
make cicd-lint            # Lint CI/CD configuration files

# Pipeline Management
make cicd-status          # Show current pipeline status
make cicd-monitor         # Monitor pipeline metrics
make cicd-rollback        # Rollback deployment

# Deployment
make cicd-deploy-staging     # Deploy to staging environment
make cicd-deploy-production  # Deploy to production environment
```

## Key Features

### 🔍 **Security-First Approach**

1. **Multi-Tool Scanning**
   - Combines multiple security tools for comprehensive coverage
   - SARIF format for unified reporting in GitHub Security tab
   - Fail-fast on critical vulnerabilities

2. **Container Security**
   - Base image vulnerability scanning
   - Dockerfile linting for best practices
   - Runtime security analysis

3. **Supply Chain Security**
   - Dependency vulnerability tracking
   - SBOM generation for transparency
   - License compliance checking

### ⚡ **Performance Optimizations**

1. **Parallel Execution**
   - Matrix builds for multiple platforms
   - Concurrent security scans
   - Parallel test execution

2. **Intelligent Caching**
   - Go module caching
   - Docker layer caching
   - NPM dependency caching

3. **Conditional Execution**
   - Path-based triggers
   - Environment-specific workflows
   - Emergency deployment options

### 🏗️ **Infrastructure Integration**

1. **Service Discovery Testing**
   - Consul service registration validation
   - Kubernetes DNS resolution testing
   - Load balancing verification

2. **Istio Service Mesh**
   - Traffic management configuration
   - Security policy validation
   - Observability integration

3. **Multi-Environment Support**
   - Environment-specific configurations
   - Progressive deployment strategies
   - Automated rollback capabilities

## Pipeline Triggers

### **Automatic Triggers**
- **Push to main/develop**: Full CI pipeline with deployment to staging
- **Pull Requests**: CI pipeline with security scanning
- **Tag Creation** (`v*.*.*`): Release pipeline with multi-platform builds
- **Schedule**: Daily security scans at 2 AM UTC

### **Manual Triggers**
- **Workflow Dispatch**: Manual deployment with environment selection
- **Emergency Deploy**: Skip tests for critical deployments
- **Security Scan**: On-demand security validation

## Environment Configuration

### **Staging Environment**
- **Namespace**: `zamaz-staging`
- **Replicas**: 2 per service
- **Resources**: Standard allocations
- **Monitoring**: Full observability stack
- **Auto-Deploy**: On main branch pushes

### **Production Environment**
- **Namespace**: `zamaz-production`
- **Replicas**: 3 per service with HA
- **Resources**: Production-grade allocations
- **Monitoring**: Enhanced alerting and monitoring
- **Deploy**: Manual approval required
- **Safety**: Tagged versions only

## Security Baseline

### **Required Security Controls**
1. **Code Scanning**: SAST tools for all languages
2. **Dependency Scanning**: Vulnerability assessment for all dependencies
3. **Container Scanning**: Base image and runtime security
4. **Secret Detection**: Comprehensive secret scanning
5. **Infrastructure Scanning**: IaC security validation

### **Compliance Validation**
- **Security Files**: Required security configuration files
- **Docker Security**: Non-root users, health checks, minimal base images
- **Kubernetes Security**: Security contexts, RBAC, network policies
- **Service Mesh**: mTLS, authorization policies, traffic encryption

## Monitoring & Observability

### **Pipeline Metrics**
- **Build Times**: Track build performance across environments
- **Test Coverage**: Maintain 80%+ code coverage
- **Security Scores**: Track vulnerability trends
- **Deployment Success**: Monitor deployment reliability

### **Alerting**
- **Failed Builds**: Immediate notification for pipeline failures
- **Security Issues**: Alert on new vulnerabilities
- **Deployment Issues**: Monitor post-deployment health
- **Compliance Drift**: Track security baseline changes

## Rollback Procedures

### **Automated Rollback**
- **Health Check Failures**: Automatic rollback on service health issues
- **Circuit Breaker**: Service mesh-level failure detection
- **Resource Constraints**: Rollback on resource exhaustion

### **Manual Rollback**
```bash
# Kubernetes rollback
kubectl rollout undo deployment/zamaz-auth-service -n zamaz

# Version-specific rollback
kubectl set image deployment/zamaz-auth-service auth-service=ghcr.io/repo/auth-service:v1.2.3 -n zamaz

# Emergency procedures
make cicd-rollback
```

## Package Distribution

### **Supported Package Managers**
- **Homebrew** (macOS/Linux): `brew install zamaz`
- **AUR** (Arch Linux): `yay -S zamaz-bin`
- **Snap** (Universal Linux): `snap install zamaz`
- **Winget** (Windows): `winget install zamaz`
- **Nix** (NixOS): `nix-env -iA nixpkgs.zamaz`

### **Container Registries**
- **GitHub Container Registry**: `ghcr.io/zamaz/root-zamaz/auth-service`
- **Multi-Architecture**: AMD64 and ARM64 support
- **Version Tags**: Latest, semantic versions, and branch-specific tags

## Development Workflow

### **Local Development**
1. **Pre-commit Hooks**: Automated linting and testing
2. **Local Testing**: `make cicd-test-workflows` for local validation
3. **Security Testing**: `make cicd-security-test` for local security scanning

### **Contributing**
1. **Feature Branches**: Create from develop branch
2. **Pull Requests**: Trigger full CI pipeline
3. **Code Review**: Required before merge
4. **Automated Testing**: All tests must pass

### **Release Process**
1. **Version Tagging**: Create semantic version tags
2. **Automated Build**: GoReleaser builds all artifacts
3. **Security Validation**: Comprehensive security scanning
4. **Distribution**: Automatic package manager updates

## Troubleshooting

### **Common Issues**

1. **Build Failures**
   - Check Go module compatibility
   - Verify dependency availability
   - Review build logs for specific errors

2. **Security Scan Failures**
   - Review vulnerability reports
   - Update dependencies with known vulnerabilities
   - Add exceptions for false positives

3. **Deployment Issues**
   - Verify Kubernetes cluster connectivity
   - Check namespace permissions
   - Review service discovery configuration

### **Debug Commands**
```bash
# Check pipeline status
make cicd-status

# Validate configurations
make cicd-validate

# Test locally
make cicd-test-workflows

# Monitor metrics
make cicd-monitor
```

## Future Enhancements

### **Planned Features**
- **GitOps Integration**: ArgoCD deployment automation
- **Chaos Engineering**: Automated resilience testing
- **Performance Testing**: Load testing integration
- **Multi-Cloud Deployment**: Support for multiple cloud providers

### **Advanced Security**
- **Runtime Security**: Falco integration for runtime protection
- **Policy as Code**: OPA/Gatekeeper policy enforcement
- **Zero Trust**: Enhanced service mesh security policies
- **Compliance Automation**: Automated compliance reporting

This modern CI/CD pipeline provides a robust, secure, and scalable foundation for the Zamaz platform, integrating seamlessly with the service discovery and Istio service mesh infrastructure while maintaining high security and operational standards.