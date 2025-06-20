# Claude Notes: Testing Strategy & Quality Assurance

> **Context**: Comprehensive testing strategy and quality assurance  
> **Last Updated**: 2025-06-20  
> **Focus**: Multi-layer testing with security and performance validation

## 🧪 **Testing Architecture Overview**

### **Testing Pyramid Implementation**
```
        ┌─────────────────────────┐
        │     E2E Tests (20%)     │ ← Playwright, Integration scenarios
        │   User workflow testing │
        ├─────────────────────────┤
        │ Integration Tests (30%) │ ← API contracts, Service interactions
        │  Component integration  │
        ├─────────────────────────┤
        │   Unit Tests (50%)      │ ← Go functions, React components
        │  Fast feedback loops    │
        └─────────────────────────┘
```

### **Quality Gates & Coverage**
- **Unit Test Coverage**: >80% for all packages
- **Integration Coverage**: All API endpoints tested
- **E2E Coverage**: Critical user journeys validated
- **Security Testing**: Automated vulnerability scanning
- **Performance Testing**: Load and stress testing

### **Technology Stack**
- **Go Testing**: Built-in testing + Testify + GoMock
- **Frontend Testing**: Vitest + Testing Library + Playwright
- **API Testing**: Postman/Newman + Go integration tests
- **Security Testing**: OWASP ZAP + Semgrep + Trivy
- **Performance Testing**: K6 + Artillery + Go benchmarks

## 📁 **Test Directory Structure**

### **Organized Testing Architecture**
```
tests/
├── unit/                    # Unit test utilities
│   ├── mocks/              # Generated mocks
│   ├── fixtures/           # Test data fixtures
│   └── helpers/            # Test helper functions
├── integration/            # Integration tests
│   ├── api/               # API endpoint tests
│   ├── database/          # Database integration
│   └── services/          # Service interaction tests
├── e2e/                   # End-to-end tests
│   ├── auth/              # Authentication flows
│   ├── user-workflows/    # User journey tests
│   ├── admin/             # Admin functionality
│   └── wiki-verification.spec.js # Documentation tests
├── performance/           # Performance testing
│   ├── load/              # Load testing scripts
│   ├── stress/            # Stress testing
│   └── benchmarks/        # Performance benchmarks
├── security/              # Security testing
│   ├── penetration/       # Pen testing scripts
│   ├── vulnerability/     # Vuln assessment
│   └── compliance/        # Compliance validation
└── data/                  # Test data management
    ├── fixtures/          # Static test data
    ├── factories/         # Data generation
    └── scenarios/         # Test scenarios
```

## 🔬 **Unit Testing Strategy**

### **Go Unit Testing Patterns**
```go
// Table-Driven Tests with Testify
func TestUserService_CreateUser(t *testing.T) {
    tests := []struct {
        name      string
        input     CreateUserRequest
        setupMock func(*mocks.MockUserRepo, *mocks.MockAuditService)
        want      *User
        wantErr   bool
        errMsg    string
    }{
        {
            name: "valid user creation",
            input: CreateUserRequest{
                Email:    "test@example.com",
                Password: "SecurePass123!",
                Name:     "Test User",
            },
            setupMock: func(repo *mocks.MockUserRepo, audit *mocks.MockAuditService) {
                user := &User{
                    ID:    "user123",
                    Email: "test@example.com",
                    Name:  "Test User",
                }
                repo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(user, nil)
                audit.EXPECT().LogUserCreation(gomock.Any(), user).Return(nil)
            },
            want:    &User{ID: "user123", Email: "test@example.com"},
            wantErr: false,
        },
        {
            name: "duplicate email error",
            input: CreateUserRequest{
                Email:    "existing@example.com",
                Password: "SecurePass123!",
            },
            setupMock: func(repo *mocks.MockUserRepo, audit *mocks.MockAuditService) {
                repo.EXPECT().Create(gomock.Any(), gomock.Any()).
                    Return(nil, domain.ErrUserExists)
            },
            want:    nil,
            wantErr: true,
            errMsg:  "user already exists",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Setup
            ctrl := gomock.NewController(t)
            defer ctrl.Finish()
            
            mockRepo := mocks.NewMockUserRepo(ctrl)
            mockAudit := mocks.NewMockAuditService(ctrl)
            
            if tt.setupMock != nil {
                tt.setupMock(mockRepo, mockAudit)
            }
            
            service := NewUserService(mockRepo, mockAudit)
            
            // Execute
            got, err := service.CreateUser(context.Background(), tt.input)
            
            // Assert
            if tt.wantErr {
                assert.Error(t, err)
                if tt.errMsg != "" {
                    assert.Contains(t, err.Error(), tt.errMsg)
                }
                assert.Nil(t, got)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.want.ID, got.ID)
                assert.Equal(t, tt.want.Email, got.Email)
            }
        })
    }
}

// Security-focused Testing
func TestPasswordValidation(t *testing.T) {
    testCases := []struct {
        name     string
        password string
        valid    bool
        reason   string
    }{
        {"valid strong password", "SecurePass123!", true, ""},
        {"too short", "Pass1!", false, "minimum 8 characters"},
        {"no uppercase", "password123!", false, "requires uppercase"},
        {"no numbers", "SecurePassword!", false, "requires numbers"},
        {"no special chars", "SecurePass123", false, "requires special characters"},
        {"common password", "Password123!", false, "too common"},
    }
    
    validator := security.NewPasswordValidator(security.DefaultPolicy())
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            result := validator.Validate(tc.password)
            
            assert.Equal(t, tc.valid, result.Valid, 
                "Password validation result mismatch")
            
            if !tc.valid {
                assert.Contains(t, result.Reason, tc.reason,
                    "Validation reason should contain expected text")
            }
        })
    }
}
```

### **React Component Testing**
```typescript
// Component Testing with Testing Library
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { LoginForm } from './LoginForm'

describe('LoginForm', () => {
    let queryClient: QueryClient
    
    beforeEach(() => {
        queryClient = new QueryClient({
            defaultOptions: {
                queries: { retry: false },
                mutations: { retry: false },
            },
        })
    })
    
    const renderWithProviders = (component: React.ReactElement) => {
        return render(
            <QueryClientProvider client={queryClient}>
                {component}
            </QueryClientProvider>
        )
    }
    
    it('should validate required fields', async () => {
        const onSubmit = vi.fn()
        renderWithProviders(<LoginForm onSubmit={onSubmit} />)
        
        const submitButton = screen.getByRole('button', { name: /login/i })
        fireEvent.click(submitButton)
        
        await waitFor(() => {
            expect(screen.getByText(/email is required/i)).toBeInTheDocument()
            expect(screen.getByText(/password is required/i)).toBeInTheDocument()
        })
        
        expect(onSubmit).not.toHaveBeenCalled()
    })
    
    it('should handle successful login', async () => {
        const onSubmit = vi.fn().mockResolvedValue({ success: true })
        renderWithProviders(<LoginForm onSubmit={onSubmit} />)
        
        const emailInput = screen.getByLabelText(/email/i)
        const passwordInput = screen.getByLabelText(/password/i)
        const submitButton = screen.getByRole('button', { name: /login/i })
        
        fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
        fireEvent.change(passwordInput, { target: { value: 'password123' } })
        fireEvent.click(submitButton)
        
        await waitFor(() => {
            expect(onSubmit).toHaveBeenCalledWith({
                email: 'test@example.com',
                password: 'password123'
            })
        })
    })
    
    it('should show loading state during submission', async () => {
        const onSubmit = vi.fn().mockImplementation(() => 
            new Promise(resolve => setTimeout(resolve, 100))
        )
        
        renderWithProviders(<LoginForm onSubmit={onSubmit} />)
        
        // Fill form and submit
        fireEvent.change(screen.getByLabelText(/email/i), 
            { target: { value: 'test@example.com' } })
        fireEvent.change(screen.getByLabelText(/password/i), 
            { target: { value: 'password123' } })
        fireEvent.click(screen.getByRole('button', { name: /login/i }))
        
        // Check loading state
        expect(screen.getByRole('button')).toBeDisabled()
        expect(screen.getByText(/logging in/i)).toBeInTheDocument()
        
        await waitFor(() => {
            expect(screen.getByRole('button')).not.toBeDisabled()
        })
    })
})

// Security Testing for XSS Prevention
describe('XSS Prevention', () => {
    it('should sanitize user input in profile display', () => {
        const maliciousInput = '<script>alert("xss")</script>Hello'
        const sanitizedInput = 'Hello'
        
        render(<UserProfile name={maliciousInput} />)
        
        // Should not contain script tag
        expect(screen.queryByText(/<script>/)).not.toBeInTheDocument()
        // Should contain sanitized content
        expect(screen.getByText(sanitizedInput)).toBeInTheDocument()
    })
})
```

## 🎭 **End-to-End Testing Strategy**

### **Playwright E2E Tests**
```typescript
// E2E Authentication Flow Testing
import { test, expect } from '@playwright/test'

test.describe('Authentication Flow', () => {
    test.beforeEach(async ({ page }) => {
        // Setup test data
        await setupTestUser('test@example.com', 'SecurePass123!')
    })
    
    test.afterEach(async ({ page }) => {
        // Cleanup test data
        await cleanupTestUser('test@example.com')
    })
    
    test('complete user authentication journey', async ({ page }) => {
        // Navigate to login page
        await page.goto('/login')
        await expect(page).toHaveTitle(/Login/)
        
        // Fill login form
        await page.fill('[data-testid="email-input"]', 'test@example.com')
        await page.fill('[data-testid="password-input"]', 'SecurePass123!')
        
        // Submit form
        await page.click('[data-testid="login-button"]')
        
        // Verify successful login
        await expect(page).toHaveURL('/dashboard')
        await expect(page.locator('[data-testid="user-welcome"]')).toContainText('Welcome')
        
        // Verify authentication token is set
        const token = await page.evaluate(() => localStorage.getItem('auth_token'))
        expect(token).toBeTruthy()
        
        // Test protected route access
        await page.goto('/profile')
        await expect(page).toHaveURL('/profile')
        await expect(page.locator('[data-testid="profile-form"]')).toBeVisible()
        
        // Test logout
        await page.click('[data-testid="user-menu"]')
        await page.click('[data-testid="logout-button"]')
        
        // Verify logout
        await expect(page).toHaveURL('/login')
        const tokenAfterLogout = await page.evaluate(() => localStorage.getItem('auth_token'))
        expect(tokenAfterLogout).toBeNull()
    })
    
    test('should handle authentication errors gracefully', async ({ page }) => {
        await page.goto('/login')
        
        // Test invalid credentials
        await page.fill('[data-testid="email-input"]', 'invalid@example.com')
        await page.fill('[data-testid="password-input"]', 'wrongpassword')
        await page.click('[data-testid="login-button"]')
        
        // Verify error message
        await expect(page.locator('[data-testid="error-message"]'))
            .toContainText('Invalid credentials')
        
        // Verify user stays on login page
        await expect(page).toHaveURL('/login')
    })
    
    test('should enforce session timeout', async ({ page }) => {
        // Login first
        await loginUser(page, 'test@example.com', 'SecurePass123!')
        
        // Mock session expiration
        await page.evaluate(() => {
            localStorage.setItem('auth_token', 'expired_token')
        })
        
        // Try to access protected route
        await page.goto('/dashboard')
        
        // Should redirect to login due to expired token
        await expect(page).toHaveURL('/login')
        await expect(page.locator('[data-testid="session-expired-message"]'))
            .toBeVisible()
    })
})

// E2E Security Testing
test.describe('Security Validations', () => {
    test('should prevent XSS attacks', async ({ page }) => {
        await loginUser(page, 'test@example.com', 'SecurePass123!')
        await page.goto('/profile')
        
        // Try to inject malicious script
        const maliciousInput = '<script>window.xssExecuted = true</script>Alert'
        await page.fill('[data-testid="name-input"]', maliciousInput)
        await page.click('[data-testid="save-button"]')
        
        // Verify script was not executed
        const xssExecuted = await page.evaluate(() => window.xssExecuted)
        expect(xssExecuted).toBeFalsy()
        
        // Verify content is safely displayed
        await page.reload()
        const displayedName = await page.textContent('[data-testid="user-name"]')
        expect(displayedName).not.toContain('<script>')
        expect(displayedName).toContain('Alert')
    })
    
    test('should enforce CSRF protection', async ({ page }) => {
        await loginUser(page, 'test@example.com', 'SecurePass123!')
        
        // Try to make request without CSRF token
        const response = await page.request.post('/api/v1/user/profile', {
            data: { name: 'Updated Name' },
            headers: {
                'Authorization': `Bearer ${await getAuthToken(page)}`
            }
        })
        
        expect(response.status()).toBe(403) // Forbidden due to missing CSRF token
    })
})
```

## 📊 **Test Reporting & Metrics**

### **Test Coverage Analysis**
```bash
# Go Test Coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# Coverage threshold enforcement
COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print substr($3, 1, length($3)-1)}')
THRESHOLD=80

if (( $(echo "$COVERAGE < $THRESHOLD" | bc -l) )); then
    echo "❌ Coverage $COVERAGE% is below threshold $THRESHOLD%"
    exit 1
fi

# Frontend Test Coverage
npm run test:coverage -- --reporter=json > coverage-report.json
```

### **Quality Metrics Dashboard**
```yaml
# Grafana Dashboard Configuration
dashboard:
  title: "Testing & Quality Metrics"
  panels:
  - title: "Test Execution Trends"
    metrics:
    - test_runs_total
    - test_failures_total
    - test_duration_seconds
    
  - title: "Code Coverage"
    metrics:
    - code_coverage_percentage{type="unit"}
    - code_coverage_percentage{type="integration"}
    - code_coverage_percentage{type="e2e"}
    
  - title: "Security Test Results"
    metrics:
    - security_vulnerabilities_found
    - security_tests_passed
    - security_scan_duration
    
  - title: "Performance Benchmarks"
    metrics:
    - benchmark_duration_ns
    - benchmark_allocations_per_op
    - load_test_requests_per_second
```

## 🔒 **Wiki Testing & Documentation Verification**

### **Current Wiki Testing Status**
- ✅ **Local Documentation**: Working (http://127.0.0.1:8001)
- ✅ **GitHub Wiki Access**: Repository wiki accessible
- ⚠️  **Wiki Content**: Limited content, needs initialization
- ❌ **Schema Sync**: Mermaid diagrams need proper sync to wiki
- ✅ **Test Framework**: Playwright tests functional

### **Wiki Integration Testing**
```typescript
// Wiki verification tests in tests/e2e/wiki-verification.spec.js
test.describe('GitHub Wiki Integration', () => {
  test('Wiki homepage should be accessible', async ({ page }) => {
    await page.goto('https://github.com/lsendel/root-zamaz/wiki')
    
    // Check if wiki exists and loads
    await expect(page).toHaveTitle(/Wiki/)
    
    // Look for wiki content or setup message
    const hasContent = await page.locator('.wiki-wrapper').isVisible()
    const hasSetupMessage = await page.locator('[data-testid="wiki-setup-message"]').isVisible()
    
    expect(hasContent || hasSetupMessage).toBeTruthy()
  })

  test('Documentation section should exist', async ({ page }) => {
    await page.goto('https://github.com/lsendel/root-zamaz/wiki/Documentation')
    
    // Verify documentation content loads
    await expect(page.locator('.markdown-body')).toBeVisible()
    
    // Check for key sections
    const sections = ['Database Schema', 'API Documentation', 'Security']
    for (const section of sections) {
      await expect(page.locator(`text=${section}`)).toBeVisible()
    }
  })
})
```

### **URL Verification Protocol**
```bash
# Always verify URLs before suggesting them
check_url() {
    local url="$1"
    local description="$2"
    
    if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q "200\|302"; then
        echo "✅ $description - Accessible"
        return 0
    else
        echo "❌ $description - Not accessible"
        return 1
    fi
}

# Example usage in scripts
if check_url "http://127.0.0.1:8001" "Local MkDocs Server"; then
    echo "Documentation available at: http://127.0.0.1:8001"
else
    echo "Start server with: make docs-serve"
fi
```

## 🚨 **Critical Testing Rules**

### **URL Verification Protocol**
1. **NEVER** suggest URLs without testing them first
2. **ALWAYS** use curl or browser to verify accessibility
3. **PROVIDE** alternative access methods if URLs fail
4. **UPDATE** this documentation when adding new verification steps

### **Wiki Safety Protocol**
1. **PREVIEW** all sync operations before execution
2. **LIMIT** sync to Documentation subdirectory only
3. **VERIFY** no existing wiki content is overwritten
4. **TEST** with small content changes first

### **Security Testing Requirements**
- **Input Validation**: Test all input boundaries and formats
- **Authentication Testing**: Verify all auth flows and edge cases
- **Authorization Testing**: Test role-based access controls
- **Session Management**: Validate session lifecycle and security
- **XSS Prevention**: Test script injection prevention
- **CSRF Protection**: Verify cross-site request forgery protection

## 📚 **Testing Best Practices**

### **Test Development Guidelines**
1. **Write Tests First**: TDD approach for new features
2. **Test Behavior, Not Implementation**: Focus on what, not how
3. **Use Descriptive Names**: Tests should be self-documenting
4. **Isolate Tests**: Each test should be independent
5. **Mock External Dependencies**: Control test environment
6. **Test Edge Cases**: Include boundary conditions and error paths
7. **Keep Tests Fast**: Unit tests should run in milliseconds
8. **Maintain Test Data**: Use factories and fixtures consistently

### **Quality Gates**
- **Unit Test Coverage**: >80% for all packages
- **Integration Coverage**: All API endpoints tested
- **E2E Coverage**: Critical user journeys validated
- **Security Tests**: No high/critical vulnerabilities
- **Performance Tests**: Response times within SLA
- **Documentation Tests**: Wiki sync and accessibility verified

### **Continuous Testing Integration**
```yaml
# CI/CD Testing Pipeline
stages:
  - lint
  - unit-test
  - integration-test
  - security-test
  - e2e-test
  - wiki-verification

wiki-verification:
  stage: e2e-test
  script:
    - make test-wiki
    - npx playwright test tests/e2e/wiki-verification.spec.js
  artifacts:
    reports:
      junit: wiki-test-results.xml
```

## 🔧 **Troubleshooting Guide**

### **Common Issues & Solutions**
1. **Wiki Not Accessible**: Check if repository wiki is enabled in GitHub settings
2. **No Content in Wiki**: Manual page creation may be required before API sync
3. **Mermaid Not Rendering**: GitHub wiki has limitations with Mermaid diagrams
4. **Sync Failures**: Verify GitHub token permissions for wiki access
5. **Test Failures**: Check service dependencies and test data setup
6. **Performance Issues**: Verify resource allocation and concurrent test execution

### **Test Debugging**
```bash
# Debug test failures
make test-unit ARGS="-v -race"
make test-integration ARGS="-v -count=1"
npx playwright test --debug --headed

# Check test coverage
make test-coverage
open coverage.html

# Run specific test suites
make test-auth     # Authentication tests only
make test-api      # API endpoint tests
make test-security # Security validation tests
```

**Remember**: Testing is not just about finding bugs—it's about building confidence in the system's reliability, security, and performance. In a Zero Trust environment, comprehensive testing is essential for verifying that security controls work as intended and that the system maintains its security posture under all conditions.