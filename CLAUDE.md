# Claude Notes: MVP Zero Trust Auth System

> **Context**: Root-level project overview and essential workflows  
> **Last Updated**: 2025-06-20  
> **Project**: Zero Trust Authentication MVP with Service Mesh Integration

## 🎯 **Project Mission**

**Zero Trust Authentication MVP** - A comprehensive authentication platform implementing Zero Trust principles with modern DevOps practices, service mesh integration, and enterprise-grade observability.

### **Core Principles**
- **Zero Trust Security**: Never trust, always verify
- **Modern CI/CD**: GitOps workflows with ArgoCD
- **Service Mesh**: Istio-based microservices architecture
- **Observability**: Comprehensive monitoring and alerting
- **Compliance**: GDPR-ready with audit logging

## 🏗️ **Architecture Overview**

### **Technology Stack**
- **Backend**: Go 1.24+ with JWT authentication, Casbin RBAC
- **Frontend**: React + TypeScript + Vite development
- **Database**: PostgreSQL with Bytebase migrations
- **Identity**: SPIRE/SPIFFE workload identity
- **Service Mesh**: Istio with traffic management
- **Observability**: Prometheus, Grafana, Jaeger, Loki
- **Deployment**: Kubernetes + Helm + ArgoCD GitOps

### **Security Architecture**
- **Authentication**: JWT with blacklisting and refresh tokens
- **Authorization**: Casbin RBAC with policy enforcement
- **Device Attestation**: Hardware-based trust verification
- **Audit Logging**: Complete GDPR-compliant audit trail
- **Zero Trust Network**: Service mesh with mutual TLS

## 🚀 **Quick Start Workflows**

### **First Time Setup**
```bash
# 1. Environment Setup
make env-setup       # Create .env file from template
# 2. Edit .env file with your GITHUB_TOKEN (see ENV_SETUP_GUIDE.md)
# 3. Verify configuration
make env-check       # Check environment status
```

### **Development Workflow**
```bash
# Start development environment
make start           # Start all services
make dev             # Frontend dev server
make status          # Check service health

# Testing workflow
make test-all        # Complete test suite
make test-e2e        # Playwright E2E tests
make test-wiki       # Documentation testing

# Documentation workflow
make docs-serve      # Local docs (127.0.0.1:8001)
make docs-schema     # Generate DB schema docs
make docs-wiki-sync  # Sync to GitHub Wiki (requires GITHUB_TOKEN)
```

### **Quality Assurance Workflow**
```bash
make lint            # Code linting
make security-audit  # Security scanning
make type-check      # TypeScript checking
make test-coverage   # Coverage reporting
```

### **Deployment Workflow**
```bash
make build-all       # Build all components
make docker-build    # Container images
# GitOps handles deployment via ArgoCD
```

## 📁 **Project Structure & Context**

### **Core Directories**
| Directory | Purpose | CLAUDE.md | Priority |
|-----------|---------|-----------|----------|
| `/pkg/` | Go backend packages | ✅ `pkg/CLAUDE.md` | **HIGH** |
| `/frontend/` | React TypeScript frontend | ✅ `frontend/CLAUDE.md` | **HIGH** |
| `/deployments/` | Kubernetes manifests | ✅ `deployments/CLAUDE.md` | **HIGH** |
| `/charts/` | Helm charts | ✅ `charts/CLAUDE.md` | **MEDIUM** |
| `/docs/` | Documentation system | ✅ `docs/CLAUDE.md` | **EXISTS** |
| `/scripts/` | Automation scripts | ✅ `scripts/CLAUDE.md` | **EXISTS** |
| `/tests/` | Testing infrastructure | ✅ `tests/CLAUDE.md` | **MEDIUM** |

### **Context Navigation**
- **Backend Development**: See `pkg/CLAUDE.md` for Go architecture
- **Frontend Development**: See `frontend/CLAUDE.md` for React patterns
- **Infrastructure**: See `deployments/CLAUDE.md` for K8s/Helm
- **Documentation**: See `docs/CLAUDE.md` for doc generation
- **Testing**: See `tests/CLAUDE.md` for testing strategies
- **Automation**: See `scripts/CLAUDE.md` for safety protocols

## 🔒 **Critical Security Protocols**

### **Authentication Flow**
1. **User Login** → JWT token generation
2. **Device Attestation** → Hardware trust verification
3. **Session Management** → Redis-backed sessions
4. **Continuous Verification** → Zero Trust validation

### **Authorization Model**
- **Casbin RBAC**: Policy-based access control
- **Role Hierarchy**: Admin → Manager → User permissions
- **Resource Protection**: API endpoint protection
- **Audit Trail**: Complete action logging

### **Development Security**
- **Token Management**: Secure JWT handling patterns
- **Secret Management**: External secrets integration
- **Code Security**: Security scanning in CI/CD
- **Data Protection**: GDPR compliance features

## 🛠️ **Development Guidelines**

### **Code Organization**
- **Domain-Driven Design**: Clear domain boundaries
- **Clean Architecture**: Separation of concerns
- **Security-First**: Security considerations in every component
- **Testing**: Comprehensive test coverage requirements

### **Git Workflow**
- **Main Branch**: `main` - production ready
- **Feature Branches**: Short-lived feature development
- **GitOps**: ArgoCD monitors repository for deployments
- **CI/CD**: GitHub Actions with comprehensive quality gates

### **Documentation Standards**
- **CLAUDE.md Files**: Context for each major component
- **README Files**: Component-specific documentation
- **MkDocs**: Comprehensive documentation site
- **GitHub Wiki**: Public documentation integration

## 📊 **Service Health & Monitoring**

### **Development Services**
- **PostgreSQL**: `localhost:5432` (authentication data)
- **Bytebase**: `localhost:5678` (database management)
- **Frontend Dev**: `localhost:5173` (React development)
- **Backend API**: `localhost:8080` (Go API server)
- **Documentation**: `localhost:8001` (MkDocs server)

### **Monitoring Stack**
- **Metrics**: Prometheus + Grafana dashboards
- **Logging**: Loki + Promtail aggregation
- **Tracing**: Jaeger distributed tracing
- **Alerting**: AlertManager with Slack integration

### **Health Checks**
```bash
make status          # Overall system status
make dev-logs        # Service logs
curl localhost:8080/health  # API health check
```

## 🚨 **Critical Rules & Safety**

### **URL Verification Protocol**
- **NEVER** suggest URLs without testing them first
- **ALWAYS** verify services are running before providing links
- **PROVIDE** alternative access methods if URLs fail
- **DOCUMENT** verification steps in relevant CLAUDE.md files

### **Environment File Security**
- **NEVER** commit `.env` files with real secrets to version control
- **USE** `.env.template` files for configuration structure
- **STORE** production secrets in secure vaults (AWS Secrets Manager, HashiCorp Vault)
- **GENERATE** secure secrets using `make env-secrets`
- **VERIFY** `.gitignore` excludes all `.env*` files except templates
- **REMOVE** any accidentally committed secrets immediately

### **Wiki Integration Safety**
- **PREVIEW** all sync operations before execution
- **LIMIT** sync to Documentation subdirectory only
- **VERIFY** no existing wiki content is overwritten
- **TEST** with small content changes first

### **Database Safety**
- **BACKUP** before schema changes
- **TEST** migrations in development first
- **VERIFY** data integrity after changes
- **DOCUMENT** schema changes in audit logs

### **Deployment Safety**
- **STAGING** deployments before production
- **CANARY** releases for gradual rollouts
- **ROLLBACK** plans for every deployment
- **MONITORING** for deployment impact

## 🔄 **Integration Points**

### **External Services**
- **GitHub**: Repository, Wiki, Actions CI/CD
- **SPIRE Server**: Workload identity and attestation
- **ArgoCD**: GitOps deployment automation
- **Istio**: Service mesh traffic management

### **Internal Services**
- **Authentication**: JWT + Casbin RBAC
- **Audit System**: GDPR compliance logging
- **Observability**: Metrics, logs, traces
- **Documentation**: Automated generation and sync

## 🎯 **Current Focus Areas**

### **Active Development**
- ✅ **Makefile Organization**: User-friendly command structure
- ✅ **Documentation System**: MkDocs + GitHub Wiki integration
- ✅ **Mermaid Diagrams**: GitHub Wiki compatibility fixes
- 🔄 **Testing Framework**: Playwright E2E + comprehensive coverage

### **Upcoming Priorities**
- 🔄 **SPIRE Integration**: Complete workload identity setup
- 📋 **Security Hardening**: Additional zero trust controls
- 📊 **Observability**: Enhanced monitoring and alerting
- 🚀 **Production Readiness**: Complete deployment pipeline

## 📚 **Resources & References**

### **Key Documentation**
- **Local Docs**: http://127.0.0.1:8001 (when docs-serve running)
- **GitHub Wiki**: https://github.com/lsendel/root-zamaz/wiki
- **API Docs**: Generated from OpenAPI specifications
- **Schema Docs**: Database documentation with Mermaid diagrams

### **Development Resources**
- **Makefile Help**: `make help` for quick start commands
- **Category Help**: `make <category>-help` for specific guidance
- **Status Monitoring**: `make status` for system health
- **Testing**: `make test-all` for comprehensive testing

**Remember**: This is a security-first, zero-trust system. Always consider security implications in every development decision and maintain the principle of "never trust, always verify" throughout the codebase.