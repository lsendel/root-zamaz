# Zero Trust Authentication Testing Suite

> **Comprehensive testing for the Zero Trust Architecture framework integration**  
> **Components**: Keycloak + SPIRE + OPA + Custom Middleware  
> **Framework Integration Plan**: Week 4 Complete

## 🧪 **Testing Overview**

This testing suite validates the complete Zero Trust Authentication system with framework integration replacing custom security implementations. The test suite covers:

- **End-to-End Integration**: Complete authentication and authorization flows
- **Workload Communication**: Service-to-service authorization with SPIRE
- **Compliance Policies**: GDPR, SOX, HIPAA, PCI compliance validation  
- **Performance Testing**: Load testing and latency validation
- **Unit Testing**: Individual component testing

## 📁 **Test Structure**

```
tests/
├── unit/                           # Unit tests for individual components
│   ├── auth/                      # Authentication component tests
│   └── middleware/                # Middleware component tests
├── integration/                   # Integration tests for OPA policies
│   └── opa_policies_test.go      # OPA policy integration tests
├── e2e/                          # End-to-end integration tests
│   ├── zero_trust_integration_test.go      # Complete auth flow
│   ├── workload_communication_test.go      # Service-to-service
│   └── compliance_policies_test.go         # Compliance frameworks
├── performance/                   # Performance and load tests
│   └── zero_trust_performance_test.go      # Latency and throughput
└── README.md                     # This file
```

## 🚀 **Quick Start**

### **1. Start Required Services**

```bash
# Start all services
make start

# Or start individually
make keycloak-up    # Identity provider
make opa-up         # Policy engine
make spire-up       # Workload identity (optional)
```

### **2. Verify Service Health**

```bash
# Check all services
make status

# Individual health checks
curl http://localhost:8080/realms/zero-trust    # Keycloak
curl http://localhost:8181/health               # OPA
curl http://localhost:8081/health               # SPIRE (if running)
```

### **3. Run Tests**

```bash
# Run complete test suite
make test-all

# Run specific test categories
make test-unit          # Unit tests only
make test-integration   # OPA integration tests
make test-e2e          # End-to-end tests
make test-compliance   # Compliance policy tests
make test-performance  # Performance tests (takes longer)

# Skip tests if services are down
SKIP_IF_SERVICES_DOWN=true make test-all
```

## 🧪 **Test Categories**

### **1. Unit Tests** (`tests/unit/`)

Fast, isolated tests for individual components:

```bash
# Run all unit tests
go test -v ./tests/unit/...

# Run with coverage
go test -cover -v ./tests/unit/...

# Run in short mode (fast tests only)
go test -short -v ./tests/unit/...
```

**Coverage**:
- Authentication component validation
- Middleware functionality
- Utility functions
- Error handling

### **2. Integration Tests** (`tests/integration/`)

Tests OPA policy integration with realistic scenarios:

```bash
# Run OPA integration tests
go test -v ./tests/integration

# Run specific policy tests
go test -v ./tests/integration -run TestOPAPolicyIntegration
go test -v ./tests/integration -run TestTrustLevelEnforcement
```

**Coverage**:
- Basic authorization policies
- Trust level enforcement (NONE=0, LOW=25, MEDIUM=50, HIGH=75, FULL=100)
- Time-based access control
- Device verification requirements
- Workload authorization
- Data classification policies
- Security incident detection
- Compliance and audit features

### **3. End-to-End Tests** (`tests/e2e/`)

Complete system integration tests:

```bash
# Run all E2E tests
go test -v ./tests/e2e

# Run specific E2E scenarios
go test -v ./tests/e2e -run TestZeroTrustE2E
go test -v ./tests/e2e -run TestWorkloadCommunication
go test -v ./tests/e2e -run TestCompliancePolicies
```

**Coverage**:
- **Authentication Flow**: JWT validation with Keycloak
- **Authorization Flow**: Policy decisions with OPA
- **Trust Level Testing**: 25, 50, 75, 100 trust levels
- **Role-Based Access**: user, admin, finance roles
- **Workload Identity**: Service-to-service communication
- **Compliance Validation**: GDPR, SOX, HIPAA, PCI

### **4. Performance Tests** (`tests/performance/`)

Load testing and performance validation:

```bash
# Run performance tests (requires longer timeout)
go test -v ./tests/performance -timeout 10m

# Run sustained load tests
go test -v ./tests/performance -run TestSustainedLoadTesting -timeout 20m

# Run specific performance scenarios
go test -v ./tests/performance -run TestOPAPolicyEvaluationPerformance
```

**Performance Targets**:
- **OPA Authorization**: < 100ms avg, < 200ms P95, > 100 RPS
- **Workload Authorization**: < 50ms avg, < 100ms P95
- **Data Access Authorization**: < 75ms avg, < 150ms P95

## 🔧 **Configuration**

### **Environment Variables**

```bash
# Service Configuration
export KEYCLOAK_URL="http://localhost:8080"
export KEYCLOAK_REALM="zero-trust"
export KEYCLOAK_CLIENT_ID="zero-trust-app"
export KEYCLOAK_CLIENT_SECRET="test-secret"
export KEYCLOAK_ADMIN_USER="admin"
export KEYCLOAK_ADMIN_PASSWORD="admin123"

export OPA_URL="http://localhost:8181"
export OPA_DB_URL="postgres://opa:opa123@localhost:5435/opa_decisions?sslmode=disable"

export SPIRE_SOCKET_PATH="/tmp/spire-agent/public/api.sock"
export SPIRE_SERVER_URL="localhost:8081"
export SPIRE_TRUST_DOMAIN="zero-trust.dev"

# Test Configuration
export SKIP_IF_SERVICES_DOWN="true"
export TEST_TIMEOUT="30s"
export CONCURRENT_USERS="100"
export TEST_DURATION="5m"
```

### **Test Data**

Tests use predefined scenarios and test users:

```go
// Trust levels used in testing
const (
    TrustLevelNone   = 0   // No trust
    TrustLevelLow    = 25  // Basic authentication
    TrustLevelMedium = 50  // Device verification
    TrustLevelHigh   = 75  // Strong authentication
    TrustLevelFull   = 100 // Maximum trust
)

// Test users with different roles and trust levels
testUsers := []TestUser{
    {Username: "low-user", TrustLevel: 25, Roles: []string{"user"}},
    {Username: "medium-user", TrustLevel: 50, Roles: []string{"user"}},
    {Username: "admin-user", TrustLevel: 75, Roles: []string{"admin", "user"}},
    {Username: "finance-user", TrustLevel: 100, Roles: []string{"finance", "user"}},
}

// SPIFFE IDs for workload testing
spiffeIDs := []string{
    "spiffe://zero-trust.dev/api/auth-service",
    "spiffe://zero-trust.dev/worker/job-processor",
    "spiffe://zero-trust.dev/admin/controller",
}
```

## 📊 **Test Scenarios**

### **Authentication Scenarios**

| Scenario | Trust Level | Roles | Expected Endpoints | Result |
|----------|-------------|-------|-------------------|--------|
| Public access | N/A | N/A | `/health`, `/public/*` | ✅ Allow |
| Low trust user | 25 | user | `/api/profile`, `/api/dashboard` | ✅ Allow |
| Medium trust user | 50 | user | Above + `/api/secure/*` | ✅ Allow |
| High trust admin | 75 | admin | Above + `/api/admin/*` | ✅ Allow |
| Full trust finance | 100 | finance | Above + `/api/financial/*` | ✅ Allow |

### **Workload Communication Matrix**

| Source → Target | API Service | Worker Service | Admin Service | Client Access |
|----------------|-------------|----------------|---------------|---------------|
| **API Service** | ✅ Self | ✅ Allow | ✅ Allow | ✅ Allow |
| **Worker Service** | ✅ Allow | ✅ Self | ❌ Deny | ❌ Deny |
| **Admin Service** | ✅ Allow | ✅ Allow | ✅ Self | ❌ Deny |
| **Client Service** | ✅ Allow | ❌ Deny | ❌ Deny | ✅ Self |

### **Compliance Framework Coverage**

| Framework | Data Types | Requirements Tested | Test File |
|-----------|------------|-------------------|-----------|
| **GDPR** | Personal Data | Purpose limitation, Data minimization, Consent | `compliance_policies_test.go` |
| **SOX** | Financial Data | Access controls, Audit trails, Segregation | `compliance_policies_test.go` |
| **HIPAA** | Health Information | Minimum necessary, Audit logs, Access controls | `compliance_policies_test.go` |
| **PCI DSS** | Payment Data | Access restrictions, Audit requirements | `compliance_policies_test.go` |

## 🔍 **Debugging Tests**

### **Common Issues**

1. **Services Not Running**:
```bash
# Check service status
make status

# Start missing services
make keycloak-up
make opa-up

# Check logs
make dev-logs
```

2. **Database Connection Issues**:
```bash
# Check OPA database
docker exec -it opa-postgres psql -U opa -d opa_decisions -c "\dt"

# Reset database
make opa-db-reset
```

3. **Authentication Failures**:
```bash
# Verify Keycloak configuration
curl http://localhost:8080/realms/zero-trust/.well-known/openid_configuration

# Check realm setup
make keycloak-setup
```

### **Debugging Commands**

```bash
# Run tests with verbose output
go test -v ./tests/e2e -run TestSpecificTest

# Run with race detection
go test -race -v ./tests/e2e

# Run with detailed logging
DETAILED_LOGGING=true go test -v ./tests/e2e

# Skip external service tests
SKIP_IF_SERVICES_DOWN=true go test -v ./tests/e2e
```

## 📈 **Performance Benchmarks**

### **Baseline Performance**

```bash
# Example OPA authorization performance
OPA Authorization Performance Results:
  Total Requests: 1000
  Successful: 998 (99.8%)
  Duration: 8.2s
  Throughput: 121.95 RPS
  Latency - P50: 78ms, P95: 145ms, P99: 167ms

# Example sustained load performance  
Sustained Load Test Results:
  Duration: 5m0s
  Target RPS: 100, Actual RPS: 98.5
  Total Requests: 29550
  Error Rate: 0.12%
  Latency - P50: 82ms, P95: 178ms, P99: 245ms
```

### **Performance Monitoring**

```bash
# Run performance tests with profiling
go test -cpuprofile=cpu.prof -memprofile=mem.prof ./tests/performance

# Analyze profiles
go tool pprof cpu.prof
go tool pprof mem.prof

# Monitor during tests
make opa-metrics  # View OPA metrics
make status       # Check overall system health
```

## 🎯 **Test Categories by Use Case**

### **Development Testing**
```bash
# Quick development testing
make test-unit              # Fast feedback
go test -short ./tests/...  # Skip slow tests
```

### **Integration Testing**
```bash
# Before committing changes
make test-integration       # Validate OPA policies
make test-e2e-quick        # Basic E2E validation
```

### **Release Testing**
```bash
# Complete validation before release
make test-all              # Full test suite
make test-performance      # Performance validation
make test-compliance       # Compliance validation
```

### **Production Readiness**
```bash
# Validate production readiness
make test-sustained-load   # Extended load testing
make test-security-scan    # Security validation
make test-compliance-full  # Complete compliance audit
```

## 📋 **Test Checklist**

Before deploying to production:

- [ ] All unit tests pass (`make test-unit`)
- [ ] Integration tests pass (`make test-integration`) 
- [ ] E2E tests pass (`make test-e2e`)
- [ ] Performance targets met (`make test-performance`)
- [ ] Compliance requirements validated (`make test-compliance`)
- [ ] Security scans clean (`make security-audit`)
- [ ] Load testing successful (`make test-sustained-load`)

## 📚 **Additional Documentation**

- **[Week 4 Testing Guide](../docs/testing/WEEK_4_TESTING_GUIDE.md)** - Detailed testing documentation
- **[Framework Integration Plan](../agent_planning/FRAMEWORK_INTEGRATION_PLAN.md)** - Overall integration strategy
- **[OPA Policies](../deployments/opa/policies/)** - Policy definitions
- **[Docker Compose](../docker-compose.*.yml)** - Service configuration

## 🤝 **Contributing**

When adding new tests:

1. **Follow the existing patterns** in each test category
2. **Add appropriate test data** for new scenarios
3. **Update this README** with new test descriptions
4. **Ensure tests are deterministic** and can run in any order
5. **Add performance benchmarks** for new authorization paths

For questions about the testing suite, refer to the individual test files or the comprehensive [Week 4 Testing Guide](../docs/testing/WEEK_4_TESTING_GUIDE.md).