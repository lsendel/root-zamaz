# 📋 Code Standards & Best Practices (2025)

> **Enforced by automated tools and CI/CD pipelines**  
> **Last Updated**: 2025-06-21  
> **Version**: 1.0

## 🎯 **Overview**

This document defines the **mandatory code standards** for the Zero Trust Authentication project. All code MUST pass these standards before merging. Standards are automatically enforced through:

- **Pre-commit hooks** (instant feedback)
- **CI/CD pipelines** (merge blocking)
- **IDE integrations** (real-time checking)

## 🛠️ **Tool Stack (2025 Best Practices)**

### **Universal Standards**
- **No trailing whitespace** ✅
- **Unix line endings (LF)** ✅
- **UTF-8 encoding** ✅
- **Max line length: 120 characters** ✅
- **Consistent indentation** ✅
- **No secrets/API keys in code** 🔒

### **Language-Specific Tools**

| Language | Linter | Formatter | Security | Type Checker |
|----------|--------|-----------|----------|--------------|
| **Go** | golangci-lint v1.61+ | gofumpt | gosec + govulncheck | built-in |
| **TypeScript/JS** | Biome v1.9+ | Biome | npm audit | TypeScript 5.5+ |
| **Python** | Ruff v0.7+ | Ruff | bandit | mypy |

## 🔧 **Go Standards**

### **Mandatory Rules**
```go
// ✅ GOOD: Proper error handling
func processUser(id string) (*User, error) {
    user, err := userRepo.GetByID(ctx, id)
    if err != nil {
        return nil, fmt.Errorf("failed to get user %s: %w", id, err)
    }
    return user, nil
}

// ❌ BAD: Ignored errors
func processUser(id string) *User {
    user, _ := userRepo.GetByID(ctx, id)  // Error ignored!
    return user
}
```

### **Enforced by golangci-lint**
- **Error handling**: All errors MUST be handled
- **Gofmt compliance**: Code MUST be properly formatted
- **Naming conventions**: CamelCase for exported, camelCase for unexported
- **Cyclomatic complexity**: Max 15 per function
- **Function length**: Max 80 lines, 50 statements
- **Magic numbers**: Use named constants
- **Security**: No hardcoded secrets, proper input validation

### **Import Organization**
```go
import (
    // Standard library
    "context"
    "fmt"
    "time"
    
    // External dependencies
    "github.com/gofiber/fiber/v2"
    "github.com/rs/zerolog"
    
    // Internal packages
    "mvp.local/pkg/auth"
    "mvp.local/pkg/models"
)
```

## 🎨 **TypeScript/JavaScript Standards**

### **Mandatory Rules**
```typescript
// ✅ GOOD: Proper type annotations
interface UserProfile {
  id: string
  email: string
  roles: Role[]
  lastLoginAt: Date | null
}

const updateUser = async (id: string, profile: Partial<UserProfile>): Promise<User> => {
  const response = await apiClient.patch<User>(`/users/${id}`, profile)
  return response.data
}

// ❌ BAD: Missing types and error handling
const updateUser = async (id, profile) => {
  const response = await apiClient.patch(`/users/${id}`, profile)
  return response.data  // No error handling!
}
```

### **Enforced by Biome**
- **TypeScript strict mode**: All types MUST be explicit
- **No any types**: Use specific types or unknown
- **Consistent naming**: camelCase for variables, PascalCase for types
- **Arrow functions**: Prefer arrow functions for callbacks
- **Destructuring**: Use object/array destructuring
- **Template literals**: Use template literals over string concatenation

### **React-Specific Rules**
```typescript
// ✅ GOOD: Proper React component
interface UserCardProps {
  user: User
  onEdit: (user: User) => void
  className?: string
}

const UserCard: React.FC<UserCardProps> = ({ user, onEdit, className }) => {
  const handleEdit = useCallback(() => {
    onEdit(user)
  }, [user, onEdit])

  return (
    <div className={className} data-testid="user-card">
      <h3>{user.name}</h3>
      <button onClick={handleEdit} type="button">
        Edit User
      </button>
    </div>
  )
}

// ❌ BAD: Missing types, accessibility, performance
const UserCard = ({ user, onEdit }) => {
  return (
    <div>
      <h3>{user.name}</h3>
      <button onClick={() => onEdit(user)}>Edit</button>  {/* New function every render */}
    </div>
  )
}
```

## 🐍 **Python Standards**

### **Mandatory Rules**
```python
# ✅ GOOD: Proper Python style
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

class UserService:
    """Service for managing user operations."""
    
    def __init__(self, user_repository: UserRepository) -> None:
        self._user_repository = user_repository
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Retrieve a user by their email address.
        
        Args:
            email: The user's email address.
            
        Returns:
            The user if found, None otherwise.
            
        Raises:
            ValidationError: If email format is invalid.
        """
        if not self._is_valid_email(email):
            raise ValidationError(f"Invalid email format: {email}")
            
        try:
            return await self._user_repository.find_by_email(email)
        except RepositoryError as e:
            logger.error("Failed to retrieve user by email %s: %s", email, e)
            raise ServiceError("User retrieval failed") from e

# ❌ BAD: Missing types, docs, error handling
def get_user_by_email(email):
    user = repository.find_by_email(email)  # No error handling!
    return user
```

### **Enforced by Ruff**
- **Type hints**: All function parameters and returns MUST have types
- **Docstrings**: All public functions MUST have Google-style docstrings
- **Error handling**: Proper exception handling and logging
- **Import organization**: Standard -> Third-party -> Local
- **Line length**: 100 characters maximum
- **Security**: No hardcoded passwords, proper input validation

## 🔒 **Security Standards**

### **Universal Security Rules**
```yaml
# ✅ GOOD: Environment-based configuration
database:
  host: ${DB_HOST}
  password: ${DB_PASSWORD}  # From environment
  
# ❌ BAD: Hardcoded secrets
database:
  host: "prod-db.example.com"
  password: "super-secret-123"  # NEVER DO THIS!
```

### **Input Validation (All Languages)**
```go
// ✅ GOOD: Input validation
func validateEmail(email string) error {
    if len(email) == 0 {
        return errors.New("email is required")
    }
    if len(email) > 254 {
        return errors.New("email too long")
    }
    emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    if !emailRegex.MatchString(email) {
        return errors.New("invalid email format")
    }
    return nil
}

// ❌ BAD: No validation
func processEmail(email string) {
    // Direct use without validation - DANGEROUS!
    db.Query("SELECT * FROM users WHERE email = " + email)
}
```

### **Authentication Patterns**
```typescript
// ✅ GOOD: Proper token handling
class AuthService {
  private static readonly TOKEN_STORAGE_KEY = 'auth_token'
  
  setToken(token: string): void {
    // Use secure storage in production
    localStorage.setItem(AuthService.TOKEN_STORAGE_KEY, token)
  }
  
  getToken(): string | null {
    return localStorage.getItem(AuthService.TOKEN_STORAGE_KEY)
  }
  
  isTokenExpired(token: string): boolean {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]))
      return payload.exp * 1000 < Date.now()
    } catch {
      return true  // Assume expired if can't parse
    }
  }
}

// ❌ BAD: Insecure token handling
const token = localStorage.getItem('token')
// No expiration check, no error handling
```

## 🧪 **Testing Standards**

### **Test Coverage Requirements**
- **Minimum coverage**: 80% for all languages
- **Critical paths**: 95% coverage for authentication/authorization
- **New code**: 90% coverage required

### **Test Naming Conventions**
```go
// ✅ GOOD: Descriptive test names
func TestUserService_GetByEmail_ValidEmail_ReturnsUser(t *testing.T) {
    // Test implementation
}

func TestUserService_GetByEmail_InvalidEmail_ReturnsValidationError(t *testing.T) {
    // Test implementation
}

// ❌ BAD: Vague test names
func TestGetUser(t *testing.T) {
    // Which scenario? What's expected?
}
```

### **Test Structure (AAA Pattern)**
```typescript
describe('UserService', () => {
  describe('getUserByEmail', () => {
    it('should return user when email exists', async () => {
      // Arrange
      const email = 'test@example.com'
      const expectedUser = createMockUser({ email })
      mockRepository.findByEmail.mockResolvedValue(expectedUser)
      
      // Act
      const result = await userService.getUserByEmail(email)
      
      // Assert
      expect(result).toEqual(expectedUser)
      expect(mockRepository.findByEmail).toHaveBeenCalledWith(email)
    })
  })
})
```

## 📊 **Performance Standards**

### **Mandatory Performance Rules**
- **Database queries**: Use prepared statements, avoid N+1 queries
- **API responses**: < 200ms for 95th percentile
- **Frontend bundles**: < 250KB initial load
- **Memory usage**: Monitor and prevent leaks

### **Code Performance Patterns**
```go
// ✅ GOOD: Efficient database query
func GetUsersWithRoles(ctx context.Context, userIDs []string) ([]User, error) {
    // Single query with JOIN instead of N+1 queries
    query := `
        SELECT u.id, u.email, u.name, r.id, r.name
        FROM users u
        LEFT JOIN user_roles ur ON u.id = ur.user_id
        LEFT JOIN roles r ON ur.role_id = r.id
        WHERE u.id = ANY($1)
    `
    return db.QueryContext(ctx, query, pq.Array(userIDs))
}

// ❌ BAD: N+1 query problem
func GetUsersWithRoles(ctx context.Context, userIDs []string) ([]User, error) {
    users := make([]User, len(userIDs))
    for i, id := range userIDs {
        user, _ := GetUser(ctx, id)           // Query 1
        user.Roles, _ = GetUserRoles(ctx, id) // Query 2 (N+1 problem!)
        users[i] = user
    }
    return users, nil
}
```

## 🔄 **CI/CD Integration**

### **Pipeline Stages**
1. **Pre-commit hooks**: Instant feedback (< 10 seconds)
2. **Lint stage**: All linting rules (< 2 minutes)
3. **Test stage**: Unit + integration tests (< 10 minutes)
4. **Security stage**: Vulnerability scanning (< 5 minutes)
5. **Build stage**: Production builds (< 5 minutes)

### **Quality Gates**
- ✅ **All linting rules pass** (blocking)
- ✅ **Test coverage ≥ 80%** (blocking)
- ✅ **No high/critical security vulnerabilities** (blocking)
- ✅ **Type checking passes** (blocking)
- ⚠️ **Performance benchmarks within limits** (warning)

## 🚀 **Quick Start Commands**

### **Setup Development Environment**
```bash
# Install all quality tools
make install-tools

# Setup pre-commit hooks
make pre-commit-install

# Run all quality checks
make quality-check
```

### **Daily Development Workflow**
```bash
# Before committing (auto-fix issues)
make quality-fix

# Check everything is OK
make quality-check

# Run tests
make test-all

# Commit (pre-commit hooks will run automatically)
git commit -m "feat: add user authentication"
```

### **CI/CD Commands**
```bash
# Full CI quality pipeline
make quality-ci

# Security scanning
make security-scan

# Performance benchmarks
make benchmark
```

## 📚 **IDE Integration**

### **VS Code Settings** (`.vscode/settings.json`)
```json
{
  "go.lintTool": "golangci-lint",
  "go.lintFlags": ["--config", ".golangci.yml"],
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll": true,
    "source.organizeImports": true
  },
  "typescript.preferences.includePackageJsonAutoImports": "on",
  "eslint.validate": ["typescript", "typescriptreact"],
  "python.linting.enabled": true,
  "python.linting.ruffEnabled": true,
  "python.formatting.provider": "ruff"
}
```

### **Required Extensions**
- **Go**: `golang.go`
- **TypeScript**: `ms-vscode.vscode-typescript-next`
- **Python**: `ms-python.python`
- **Biome**: `biomejs.biome`
- **GitLens**: `eamodio.gitlens`

## 🎯 **Enforcement Strategy**

### **Automated Enforcement**
1. **Pre-commit hooks**: Block commits that don't meet standards
2. **CI/CD pipelines**: Block merges that fail quality checks
3. **GitHub branch protection**: Require status checks to pass
4. **SonarQube**: Track technical debt and code smells

### **Review Process**
1. **Automated review**: Tools provide immediate feedback
2. **Peer review**: Focus on logic, architecture, security
3. **Architecture review**: For significant changes
4. **Security review**: For authentication/authorization changes

## 📈 **Metrics & Monitoring**

### **Quality Metrics**
- **Code coverage**: Track per component and overall
- **Technical debt**: Monitor and reduce systematically
- **Security vulnerabilities**: Zero tolerance for high/critical
- **Performance regressions**: Automatic detection and alerts

### **Team Metrics**
- **Pull request quality**: Measure automated vs manual feedback
- **Time to merge**: Track development velocity
- **Bug escape rate**: Post-deployment defects
- **Developer satisfaction**: Regular surveys on tooling

## ❗ **Common Violations & Fixes**

### **Go Common Issues**
```bash
# Fix: Unused variable
# Before: var user User
# After: Remove unused variables or use _ if needed

# Fix: Error not checked
# Before: result, _ := someFunction()
# After: result, err := someFunction()
#        if err != nil { return err }

# Fix: Function too complex
# Solution: Break into smaller functions
```

### **TypeScript Common Issues**
```bash
# Fix: Any type usage
# Before: const user: any = getData()
# After: const user: User = getData()

# Fix: Missing error boundaries
# Solution: Wrap components in ErrorBoundary

# Fix: Unnecessary re-renders
# Solution: Use React.memo, useMemo, useCallback
```

### **Python Common Issues**
```bash
# Fix: Missing type hints
# Before: def get_user(id):
# After: def get_user(id: str) -> Optional[User]:

# Fix: Bare except clauses
# Before: except:
# After: except SpecificException as e:

# Fix: Long functions
# Solution: Extract methods, use composition
```

## 🔧 **Tool Configuration Files**

All tools are configured via files in the project root:
- `.golangci.yml` - Go linting configuration
- `biome.json` - JS/TS linting and formatting
- `.ruff.toml` - Python linting and formatting
- `.pre-commit-config.yaml` - Pre-commit hooks
- `CODE_STANDARDS.md` - This document

## 🎯 **Success Criteria**

A successful implementation means:
- ✅ **100% of commits** pass pre-commit hooks
- ✅ **100% of PRs** pass CI quality checks
- ✅ **Zero manual lint fixes** needed in code review
- ✅ **Consistent code style** across all contributors
- ✅ **Reduced security vulnerabilities** over time
- ✅ **Improved code maintainability** metrics

---

**Remember**: Quality is not optional. These standards ensure our codebase remains maintainable, secure, and performant as we scale. When in doubt, prioritize security and maintainability over convenience.