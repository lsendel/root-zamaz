# 🐹 Go Code Standards & Best Practices (2025)

> **Go-specific standards for Zero Trust Authentication project**  
> **Last Updated**: 2025-06-21  
> **Enforced by**: golangci-lint, gosec, govulncheck

## 🎯 **Go Quality Tools Stack**

| Tool | Purpose | Version | Config |
|------|---------|---------|--------|
| **golangci-lint** | Comprehensive linting | v1.61+ | `.golangci.yml` |
| **gosec** | Security analysis | latest | built-in |
| **govulncheck** | Vulnerability scanning | latest | built-in |
| **gofumpt** | Stricter formatting | latest | built-in |
| **goimports** | Import organization | latest | built-in |

## 📋 **Mandatory Rules**

### **1. Error Handling (Zero Tolerance)**
```go
// ✅ REQUIRED: All errors must be handled
func GetUser(ctx context.Context, id string) (*User, error) {
    user, err := repo.FindByID(ctx, id)
    if err != nil {
        return nil, fmt.Errorf("failed to get user %s: %w", id, err)
    }
    return user, nil
}

// ❌ FORBIDDEN: Ignored errors
func GetUser(ctx context.Context, id string) *User {
    user, _ := repo.FindByID(ctx, id)  // CI WILL FAIL
    return user
}
```

### **2. Context Propagation (Required)**
```go
// ✅ REQUIRED: Context in all functions
func (s *UserService) CreateUser(ctx context.Context, req CreateUserRequest) error {
    // Pass context to all downstream calls
    if err := s.validator.Validate(ctx, req); err != nil {
        return fmt.Errorf("validation failed: %w", err)
    }
    
    user := &User{
        Email: req.Email,
        Name:  req.Name,
    }
    
    return s.repo.Save(ctx, user)
}

// ❌ FORBIDDEN: Missing context
func (s *UserService) CreateUser(req CreateUserRequest) error {
    // Missing context - CI WILL FAIL
}
```

### **3. Package Structure & Naming**
```go
// ✅ REQUIRED: Proper package organization
package auth

import (
    // Standard library first
    "context"
    "fmt"
    "time"
    
    // Third-party packages
    "github.com/gofiber/fiber/v2"
    "github.com/rs/zerolog"
    
    // Internal packages (always last)
    "mvp.local/pkg/models"
    "mvp.local/pkg/repository"
)

// ✅ REQUIRED: Exported types start with capital
type UserService struct {
    repo   UserRepository
    logger zerolog.Logger
}

// ✅ REQUIRED: Unexported fields start with lowercase
type user struct {
    id    string
    email string
}
```

## 🔒 **Security Standards**

### **1. Input Validation (MANDATORY)**
```go
// ✅ REQUIRED: Validate all inputs
func ValidateEmail(email string) error {
    if len(email) == 0 {
        return errors.New("email is required")
    }
    if len(email) > 254 {
        return errors.New("email too long")
    }
    
    // Use regex for email validation
    emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    if !emailRegex.MatchString(email) {
        return errors.New("invalid email format")
    }
    return nil
}

// ❌ FORBIDDEN: No input validation
func ProcessUser(email string) {
    // Direct use without validation - SECURITY RISK
    db.Exec("SELECT * FROM users WHERE email = " + email)
}
```

### **2. SQL Injection Prevention**
```go
// ✅ REQUIRED: Always use prepared statements
func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
    query := `SELECT id, email, name FROM users WHERE email = $1`
    row := r.db.QueryRowContext(ctx, query, email)
    
    var user User
    err := row.Scan(&user.ID, &user.Email, &user.Name)
    if err == sql.ErrNoRows {
        return nil, ErrUserNotFound
    }
    return &user, err
}

// ❌ FORBIDDEN: String concatenation in queries
func (r *UserRepository) GetUserByEmail(email string) (*User, error) {
    query := "SELECT * FROM users WHERE email = '" + email + "'"  // SQL INJECTION RISK
    // CI WILL FAIL - gosec will catch this
}
```

### **3. Secret Management**
```go
// ✅ REQUIRED: Environment-based configuration
type Config struct {
    DatabaseURL string `env:"DATABASE_URL,required"`
    JWTSecret   string `env:"JWT_SECRET,required"`
    RedisURL    string `env:"REDIS_URL,required"`
}

// ❌ FORBIDDEN: Hardcoded secrets
const (
    DatabaseURL = "postgres://user:password@localhost/db"  // CI WILL FAIL
    JWTSecret   = "super-secret-key"                       // CI WILL FAIL
)
```

## 🏗️ **Code Organization Standards**

### **1. Function Complexity Limits**
```go
// ✅ ACCEPTABLE: Cyclomatic complexity ≤ 15
func ProcessUserRegistration(ctx context.Context, req RegisterRequest) error {
    // Validate input
    if err := ValidateRegistrationRequest(req); err != nil {
        return fmt.Errorf("validation failed: %w", err)
    }
    
    // Check if user exists
    exists, err := r.userRepo.ExistsByEmail(ctx, req.Email)
    if err != nil {
        return fmt.Errorf("failed to check user existence: %w", err)
    }
    if exists {
        return ErrUserAlreadyExists
    }
    
    // Hash password
    hashedPassword, err := r.hasher.Hash(req.Password)
    if err != nil {
        return fmt.Errorf("failed to hash password: %w", err)
    }
    
    // Create user
    user := &User{
        Email:    req.Email,
        Password: hashedPassword,
        Name:     req.Name,
    }
    
    return r.userRepo.Create(ctx, user)
}

// ❌ VIOLATION: Function too complex (>15 cyclomatic complexity)
// Break into smaller functions when golangci-lint complains
```

### **2. Function Length Limits**
```go
// ✅ ACCEPTABLE: ≤ 80 lines, ≤ 50 statements
func AuthenticateUser(ctx context.Context, credentials AuthCredentials) (*AuthResult, error) {
    // Implementation should be concise and focused
    // If function grows beyond limits, extract helper functions
    return &AuthResult{}, nil
}

// Helper functions for complex operations
func validateCredentials(creds AuthCredentials) error { /* ... */ }
func checkAccountLockout(ctx context.Context, email string) error { /* ... */ }
func generateTokens(user *User) (*TokenPair, error) { /* ... */ }
```

## 📊 **Performance Standards**

### **1. Database Operations**
```go
// ✅ REQUIRED: Use GORM efficiently
func (r *UserRepository) GetUsersWithRoles(ctx context.Context, userIDs []string) ([]User, error) {
    var users []User
    
    // Use Preload to avoid N+1 queries
    err := r.db.WithContext(ctx).
        Preload("Roles").
        Where("id IN ?", userIDs).
        Find(&users).Error
    
    return users, err
}

// ❌ PERFORMANCE ISSUE: N+1 query problem
func (r *UserRepository) GetUsersWithRoles(ctx context.Context, userIDs []string) ([]User, error) {
    var users []User
    r.db.Where("id IN ?", userIDs).Find(&users)
    
    // This creates N+1 queries
    for i := range users {
        r.db.Model(&users[i]).Association("Roles").Find(&users[i].Roles)
    }
    return users, nil
}
```

### **2. Memory Management**
```go
// ✅ REQUIRED: Proper slice allocation
func ProcessLargeDataset(items []DataItem) []ProcessedItem {
    // Pre-allocate slice with known capacity
    processed := make([]ProcessedItem, 0, len(items))
    
    for _, item := range items {
        if result := processItem(item); result != nil {
            processed = append(processed, *result)
        }
    }
    return processed
}

// ✅ REQUIRED: Buffer reuse for high-frequency operations
var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 0, 1024)
    },
}

func SerializeData(data interface{}) ([]byte, error) {
    buf := bufferPool.Get().([]byte)
    defer bufferPool.Put(buf[:0])
    
    // Use buffer for serialization
    return json.Marshal(data)
}
```

## 🧪 **Testing Standards**

### **1. Test File Organization**
```go
// File: user_service_test.go
package auth_test

import (
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    
    "mvp.local/pkg/auth"
    "mvp.local/pkg/testutils"
)

// ✅ REQUIRED: Table-driven tests
func TestUserService_CreateUser(t *testing.T) {
    tests := []struct {
        name        string
        request     auth.CreateUserRequest
        setupMocks  func(*testutils.MockUserRepo)
        wantErr     bool
        wantErrType error
    }{
        {
            name: "valid user creation",
            request: auth.CreateUserRequest{
                Email:    "test@example.com",
                Password: "SecurePass123!",
                Name:     "Test User",
            },
            setupMocks: func(repo *testutils.MockUserRepo) {
                repo.EXPECT().
                    ExistsByEmail(gomock.Any(), "test@example.com").
                    Return(false, nil)
                repo.EXPECT().
                    Create(gomock.Any(), gomock.Any()).
                    Return(nil)
            },
            wantErr: false,
        },
        {
            name: "duplicate email",
            request: auth.CreateUserRequest{
                Email: "existing@example.com",
            },
            setupMocks: func(repo *testutils.MockUserRepo) {
                repo.EXPECT().
                    ExistsByEmail(gomock.Any(), "existing@example.com").
                    Return(true, nil)
            },
            wantErr:     true,
            wantErrType: auth.ErrUserAlreadyExists,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Arrange
            ctrl := gomock.NewController(t)
            defer ctrl.Finish()
            
            mockRepo := testutils.NewMockUserRepo(ctrl)
            tt.setupMocks(mockRepo)
            
            service := auth.NewUserService(mockRepo)
            ctx := context.Background()
            
            // Act
            err := service.CreateUser(ctx, tt.request)
            
            // Assert
            if tt.wantErr {
                require.Error(t, err)
                if tt.wantErrType != nil {
                    assert.ErrorIs(t, err, tt.wantErrType)
                }
            } else {
                require.NoError(t, err)
            }
        })
    }
}
```

### **2. Mock Standards**
```go
// ✅ REQUIRED: Interface-based mocking
//go:generate mockgen -source=user_repository.go -destination=mocks/user_repository.go

type UserRepository interface {
    Create(ctx context.Context, user *User) error
    GetByID(ctx context.Context, id string) (*User, error)
    ExistsByEmail(ctx context.Context, email string) (bool, error)
}

// ✅ REQUIRED: Test helpers
func CreateTestUser(t *testing.T, email string) *User {
    t.Helper()
    return &User{
        ID:    uuid.New().String(),
        Email: email,
        Name:  "Test User",
    }
}
```

## 🔧 **Static Analysis Configuration**

### **golangci-lint Rules (Enforced)**
```yaml
# High-priority rules (blocking)
linters:
  enable:
    - errcheck          # Unchecked errors
    - gosimple         # Code simplification
    - govet            # Standard Go analyzer
    - ineffassign      # Ineffectual assignments
    - staticcheck      # Advanced static analysis
    - typecheck        # Type checking
    - unused           # Unused code detection
    - gosec            # Security issues
    - goconst          # Repeated strings
    - gocyclo          # Cyclomatic complexity
    - funlen           # Function length
    - lll              # Line length
    - misspell         # Spelling errors
    - unparam          # Unused parameters
```

### **Security Analysis (gosec)**
```go
// Rules automatically checked:
// G101: Hardcoded credentials
// G102: Network binding to all interfaces
// G103: Unsafe block usage
// G104: Errors not checked
// G105: Type assertion not checked
// G106: SSH host key verification
// G107: URL provided to HTTP request
// G108: Profiling endpoint
// G109: Integer overflow
// G110: DoS vulnerability
```

## ⚡ **Performance Benchmarking**

### **Required Benchmarks**
```go
// File: user_service_benchmark_test.go
func BenchmarkUserService_CreateUser(b *testing.B) {
    service := setupBenchmarkService(b)
    request := auth.CreateUserRequest{
        Email:    "bench@example.com",
        Password: "password",
        Name:     "Benchmark User",
    }
    
    b.ResetTimer()
    b.ReportAllocs()
    
    for i := 0; i < b.N; i++ {
        ctx := context.Background()
        _ = service.CreateUser(ctx, request)
    }
}

// Performance targets:
// - User creation: < 10ms
// - Authentication: < 5ms
// - Token validation: < 1ms
```

## 🚀 **CI/CD Integration**

### **Make Targets**
```bash
# Run all Go quality checks
make lint-go          # golangci-lint
make security-go       # gosec + govulncheck
make type-check-go     # go vet
make format-go         # gofumpt + goimports

# Combined quality check
make quality-ci        # All checks (CI mode)
```

### **Pre-commit Hooks**
```yaml
# Automatically runs on every commit
- repo: https://github.com/dnephin/pre-commit-golang
  hooks:
    - id: go-fmt
    - id: go-vet-mod
    - id: go-mod-tidy
    - id: golangci-lint
```

## 📈 **Quality Metrics**

### **Required Coverage**
- **Unit tests**: ≥ 80% line coverage
- **Integration tests**: ≥ 70% feature coverage
- **Critical paths**: ≥ 95% coverage (auth, security)

### **Performance Benchmarks**
- **API response time**: 95th percentile < 200ms
- **Database queries**: < 100ms average
- **Memory allocations**: Minimize in hot paths

## 🎯 **Quick Reference**

### **Daily Commands**
```bash
# Before committing
make quality-fix        # Auto-fix issues
make lint-go           # Check linting
make test              # Run tests

# Install tools (one-time)
make install-go-tools
```

### **Common Violations & Fixes**
| Violation | Fix Command | Prevention |
|-----------|-------------|------------|
| Unused variable | Remove or use `_` | IDE integration |
| Unchecked error | Add error handling | errcheck linter |
| Long function | Extract methods | gocyclo limit |
| Missing comments | Add godoc | revive linter |
| Security issue | Fix vulnerability | gosec scanner |

---

**Remember**: Go code must pass ALL static analysis checks before merge. No exceptions. Quality is enforced automatically through CI/CD pipelines.