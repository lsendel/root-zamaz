# Week 4: End-to-End Integration Testing Guide

> **Framework Integration Plan - Week 4 Complete**  
> **Status**: ✅ All Week 4 testing completed  
> **Components**: Keycloak + SPIRE + OPA Integration Testing

## 🎯 **Week 4 Overview**

Week 4 completes the framework integration with comprehensive end-to-end testing of the complete Zero Trust architecture. All components (Keycloak, SPIRE, OPA) are tested together to ensure seamless integration.

### **Testing Categories Completed**

1. **✅ End-to-End Integration Testing** - Complete authentication flow
2. **✅ Workload Communication Testing** - Service-to-service authorization
3. **✅ Compliance Policy Testing** - GDPR, SOX, HIPAA, PCI compliance
4. **✅ Performance Testing** - Load testing and optimization
5. **✅ Documentation** - Comprehensive testing guides

## 🧪 **Test Suites Overview**

### **1. End-to-End Integration Tests**
**File**: `tests/e2e/zero_trust_integration_test.go`

```bash
# Run complete E2E test suite
go test -v ./tests/e2e -run TestZeroTrustE2E

# Run specific test categories
go test -v ./tests/e2e -run TestE2EPublicEndpoints
go test -v ./tests/e2e -run TestE2EProtectedEndpoints
go test -v ./tests/e2e -run TestE2EAuthenticationFlow
```

**Test Coverage**:
- ✅ Public endpoint access (no authentication required)
- ✅ Protected endpoint access control
- ✅ JWT token validation with Keycloak
- ✅ Trust level enforcement (25, 50, 75, 100)
- ✅ Role-based access control (user, admin, finance)
- ✅ Invalid token handling
- ✅ OPA policy decision logging
- ✅ Unified middleware integration

### **2. Workload Communication Tests** 
**File**: `tests/e2e/workload_communication_test.go`

```bash
# Run workload communication tests
go test -v ./tests/e2e -run TestWorkloadCommunication

# Run specific workload scenarios
go test -v ./tests/e2e -run TestWorkloadAPIToWorker
go test -v ./tests/e2e -run TestWorkloadClientRestrictions
```

**Test Coverage**:
- ✅ API ↔ Worker service communication (allowed)
- ✅ Worker → Admin service communication (denied)
- ✅ Client service restrictions (API only)
- ✅ Protocol-specific rules (gRPC, HTTPS allowed; HTTP, TCP denied)
- ✅ Invalid SPIFFE ID handling
- ✅ Time-based workload access controls
- ✅ Load testing for workload authorization
- ✅ mTLS certificate validation (if SPIRE available)

### **3. Compliance Policy Tests**
**File**: `tests/e2e/compliance_policies_test.go`

```bash
# Run compliance policy tests  
go test -v ./tests/e2e -run TestCompliancePolicies

# Run specific compliance frameworks
go test -v ./tests/e2e -run TestGDPRPersonalDataAccess
go test -v ./tests/e2e -run TestSOXFinancialDataAccess
go test -v ./tests/e2e -run TestHIPAAHealthDataAccess
```

**Test Coverage**:
- ✅ **GDPR Compliance**: Purpose limitation, data minimization, audit trails
- ✅ **SOX Compliance**: Financial data access controls, audit requirements
- ✅ **HIPAA Compliance**: PHI protection, minimum necessary principle
- ✅ **PCI DSS Compliance**: Payment card data protection
- ✅ **Data Classification**: Public, Internal, Confidential, Restricted
- ✅ **Time-based Access**: Business hours restrictions
- ✅ **Emergency Access**: Override procedures with audit
- ✅ **Data Retention**: Deletion and anonymization policies
- ✅ **Cross-border Transfer**: Geographic restrictions

### **4. Performance Testing**
**File**: `tests/performance/zero_trust_performance_test.go`

```bash
# Run performance tests (requires longer timeout)
go test -v ./tests/performance -timeout 10m

# Run sustained load tests
go test -v ./tests/performance -run TestSustainedLoadTesting -timeout 20m

# Run specific performance scenarios
go test -v ./tests/performance -run TestOPAPolicyEvaluationPerformance
go test -v ./tests/performance -run TestConcurrentUserSimulation
```

**Performance Benchmarks**:
- ✅ **OPA Authorization**: < 100ms avg, < 200ms P95, > 100 RPS
- ✅ **Workload Authorization**: < 50ms avg, < 100ms P95
- ✅ **Data Access Authorization**: < 75ms avg, < 150ms P95
- ✅ **Sustained Load**: 5-minute load test at target RPS
- ✅ **Memory Usage**: Resource consumption under load
- ✅ **Concurrent Users**: 100 users simulation

## 🚀 **Quick Start Testing**

### **Prerequisites**

1. **Start Required Services**:
```bash
# Start Keycloak
make keycloak-up

# Start OPA  
make opa-up

# Optional: Start SPIRE (for workload identity)
# make spire-up
```

2. **Verify Services**:
```bash
# Check service health
curl http://localhost:8080/realms/zero-trust  # Keycloak
curl http://localhost:8181/health             # OPA

# Verify with Make commands
make status
make keycloak-status
make opa-status
```

### **Run Complete Test Suite**

```bash
# Run all tests with services running
make test-all

# Run specific test categories
make test-e2e           # End-to-end integration
make test-compliance    # Compliance policies  
make test-performance   # Performance testing
make test-integration   # OPA integration tests
```

### **Run Tests Without Services**

```bash
# Skip tests if services are not available
SKIP_IF_SERVICES_DOWN=true go test -v ./tests/e2e

# Run only unit tests (no external dependencies)
go test -short -v ./tests/...
```

## 📊 **Test Scenarios Covered**

### **Authentication Scenarios**

| Scenario | Trust Level | Roles | Expected Result | Test File |
|----------|-------------|-------|-----------------|-----------|
| Public access | N/A | N/A | ✅ Allow | `zero_trust_integration_test.go` |
| No token | N/A | N/A | ❌ 401 Unauthorized | `zero_trust_integration_test.go` |
| Invalid token | N/A | N/A | ❌ 401 Unauthorized | `zero_trust_integration_test.go` |
| Low trust user | 25 | user | ✅ Basic access only | `zero_trust_integration_test.go` |
| Medium trust user | 50 | user | ✅ Secure data access | `zero_trust_integration_test.go` |
| High trust admin | 75 | admin, user | ✅ Admin access | `zero_trust_integration_test.go` |
| Full trust finance | 100 | finance, user | ✅ Financial access | `zero_trust_integration_test.go` |

### **Workload Communication Scenarios**

| Source Service | Target Service | Protocol | Expected Result | Test File |
|----------------|----------------|----------|-----------------|-----------|
| API Service | Worker Service | gRPC | ✅ Allow | `workload_communication_test.go` |
| Worker Service | API Service | gRPC | ✅ Allow | `workload_communication_test.go` |
| Worker Service | Admin Service | gRPC | ❌ Deny | `workload_communication_test.go` |
| Client Service | API Service | HTTPS | ✅ Allow | `workload_communication_test.go` |
| Client Service | Worker Service | gRPC | ❌ Deny | `workload_communication_test.go` |
| Any Service | Any Service | HTTP | ❌ Deny (insecure) | `workload_communication_test.go` |

### **Compliance Scenarios**

| Framework | Data Type | User Role | Purpose | Expected Result | Test File |
|-----------|-----------|-----------|---------|-----------------|-----------|
| GDPR | Personal Data | Medical | medical_treatment | ✅ Allow + Audit | `compliance_policies_test.go` |
| GDPR | Personal Data | Marketing | (no purpose) | ❌ Deny | `compliance_policies_test.go` |
| SOX | Financial Data | Finance Manager | financial_reporting | ✅ Allow + Audit | `compliance_policies_test.go` |
| SOX | Financial Data | Regular User | curiosity | ❌ Deny | `compliance_policies_test.go` |
| HIPAA | PHI | Doctor | medical_treatment | ✅ Allow + Audit | `compliance_policies_test.go` |
| HIPAA | PHI | Admin Staff | administrative | ❌ Deny | `compliance_policies_test.go` |
| PCI | Payment Data | Payment Processor | payment_processing | ✅ Allow + Audit | `compliance_policies_test.go` |

## 🔧 **Test Configuration**

### **Environment Variables**

```bash
# Service URLs
export KEYCLOAK_URL="http://localhost:8080"
export KEYCLOAK_REALM="zero-trust"
export KEYCLOAK_CLIENT_ID="zero-trust-app"
export KEYCLOAK_CLIENT_SECRET="test-secret"

export OPA_URL="http://localhost:8181" 
export OPA_DB_URL="postgres://opa:opa123@localhost:5435/opa_decisions?sslmode=disable"

export SPIRE_SOCKET_PATH="/tmp/spire-agent/public/api.sock"
export SPIRE_SERVER_URL="localhost:8081"
export SPIRE_TRUST_DOMAIN="zero-trust.dev"

# Test behavior
export SKIP_IF_SERVICES_DOWN="true"    # Skip tests if services unavailable
export TEST_TIMEOUT="30s"              # Test timeout
export CONCURRENT_USERS="100"          # Performance test users
export TEST_DURATION="5m"              # Sustained load test duration
```

### **Test Data Setup**

The tests use predefined test users and scenarios:

```go
// Test users with different trust levels
testUsers := []TestUser{
    {Username: "test-user", TrustLevel: 50, Roles: []string{"user"}},
    {Username: "admin-user", TrustLevel: 75, Roles: []string{"admin", "user"}},
    {Username: "finance-user", TrustLevel: 100, Roles: []string{"finance", "user"}},
}

// Test SPIFFE IDs for workload testing
spiffeIDs := []string{
    "spiffe://zero-trust.dev/api/auth-service",
    "spiffe://zero-trust.dev/worker/job-processor", 
    "spiffe://zero-trust.dev/admin/controller",
    "spiffe://zero-trust.dev/client/web-app",
}
```

## 📈 **Performance Expectations**

### **Latency Targets**

| Component | Average | P95 | P99 | Target RPS |
|-----------|---------|-----|-----|------------|
| OPA Authorization | < 100ms | < 200ms | < 300ms | > 100 |
| Workload Authorization | < 50ms | < 100ms | < 150ms | > 200 |
| Data Access Authorization | < 75ms | < 150ms | < 200ms | > 150 |
| Complete Auth Flow | < 200ms | < 400ms | < 500ms | > 50 |

### **Load Testing Results**

```bash
# Example performance test output
OPA Authorization Performance Results:
  Total Requests: 1000
  Successful: 998
  Failed: 2
  Duration: 8.2s
  Throughput: 121.95 RPS
  Latency - Min: 12ms, Max: 186ms, Avg: 82ms
  Latency - P50: 78ms, P95: 145ms, P99: 167ms
```

## 🔍 **Debugging Failed Tests**

### **Common Issues and Solutions**

1. **Services Not Available**:
```bash
# Check service status
make status
curl http://localhost:8080/health  # Keycloak
curl http://localhost:8181/health  # OPA

# Restart services
make keycloak-restart
make opa-restart
```

2. **Test Timeouts**:
```bash
# Increase test timeout
go test -v ./tests/e2e -timeout 60s

# Or set environment variable
export TEST_TIMEOUT="60s"
```

3. **Database Connection Issues**:
```bash
# Check OPA database connectivity
docker exec -it opa-postgres psql -U opa -d opa_decisions -c "\dt"

# Reset database if needed
make opa-db-reset
```

4. **Authentication Failures**:
```bash
# Verify Keycloak realm configuration
curl http://localhost:8080/realms/zero-trust/.well-known/openid_configuration

# Check admin credentials
export KEYCLOAK_ADMIN_USER="admin"
export KEYCLOAK_ADMIN_PASSWORD="admin123"
```

### **Test Debugging Commands**

```bash
# Run tests with verbose output
go test -v ./tests/e2e -run TestSpecificTest

# Run tests with race detection
go test -race -v ./tests/e2e

# Run tests with coverage
go test -cover -v ./tests/e2e

# Run performance tests with profiling
go test -cpuprofile=cpu.prof -memprofile=mem.prof ./tests/performance
```

## 📋 **Test Checklist**

Before deploying to production, ensure all tests pass:

- [ ] **End-to-End Integration**
  - [ ] Public endpoints accessible
  - [ ] Protected endpoints secured
  - [ ] JWT token validation working
  - [ ] Trust level enforcement correct
  - [ ] Role-based access control functional
  - [ ] Invalid token handling proper

- [ ] **Workload Communication**
  - [ ] Service-to-service policies correct
  - [ ] SPIFFE ID validation working
  - [ ] Protocol restrictions enforced
  - [ ] Invalid workload handling proper

- [ ] **Compliance Policies**
  - [ ] GDPR purpose limitation enforced
  - [ ] SOX financial controls working
  - [ ] HIPAA PHI protection active
  - [ ] PCI payment data secured
  - [ ] Data classification enforced

- [ ] **Performance**
  - [ ] Latency targets met
  - [ ] Throughput requirements satisfied
  - [ ] Memory usage acceptable
  - [ ] Sustained load handled

## 🎯 **Next Steps**

Week 4 testing is complete! The framework integration testing validates:

✅ **Complete Zero Trust Architecture** - All components working together  
✅ **Production-Ready Performance** - Meets latency and throughput targets  
✅ **Compliance-Ready Policies** - GDPR, SOX, HIPAA, PCI validated  
✅ **Comprehensive Test Coverage** - E2E, performance, and compliance

**Ready for Week 5**: Production preparation and deployment pipeline setup.

For questions or issues with the testing suite, check the `troubleshooting` section or refer to individual test files for detailed scenarios.