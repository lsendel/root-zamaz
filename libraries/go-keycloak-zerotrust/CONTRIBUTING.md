# Contributing to go-keycloak-zerotrust

🎉 Thank you for considering contributing to the go-keycloak-zerotrust library! Your contributions help make Zero Trust authentication more accessible and secure for the Go community.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [How to Contribute](#how-to-contribute)
5. [Development Guidelines](#development-guidelines)
6. [Testing Requirements](#testing-requirements)
7. [Documentation](#documentation)
8. [Security](#security)
9. [Community](#community)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [conduct@yourorg.com](mailto:conduct@yourorg.com).

## Getting Started

### Prerequisites

Before you begin, ensure you have the following installed:

- **Go 1.21+**: [Download Go](https://golang.org/dl/)
- **Git**: [Install Git](https://git-scm.com/downloads)
- **Docker**: [Install Docker](https://docs.docker.com/get-docker/) (for integration tests)
- **Make**: Build automation tool

### Quick Start

1. **Fork the repository** on GitHub
2. **Clone your fork**:
   ```bash
   git clone https://github.com/yourusername/go-keycloak-zerotrust.git
   cd go-keycloak-zerotrust
   ```
3. **Add the upstream remote**:
   ```bash
   git remote add upstream https://github.com/yourorg/go-keycloak-zerotrust.git
   ```
4. **Install dependencies**:
   ```bash
   go mod download
   ```
5. **Run tests** to ensure everything is working:
   ```bash
   make test
   ```

## Development Setup

### Local Environment

```bash
# Install development tools
make dev-setup

# Install pre-commit hooks
make install-hooks

# Run all checks
make check-all
```

### IDE Configuration

#### VS Code
Recommended extensions:
- Go (golang.go)
- Go Test Explorer (golang.test-explorer)
- GitLens (eamodio.gitlens)
- Todo Tree (gruntfuggly.todo-tree)

#### GoLand/IntelliJ
Import the project and enable:
- Go modules support
- Code formatting on save
- Import optimization

### Environment Variables

Create a `.env.local` file for development:

```bash
# Keycloak settings (for integration tests)
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=test
KEYCLOAK_CLIENT_ID=test-client
KEYCLOAK_CLIENT_SECRET=test-secret

# Redis (optional, for cache tests)
REDIS_URL=redis://localhost:6379

# Database (optional, for integration tests)
DATABASE_URL=postgres://user:pass@localhost:5432/keycloak_test
```

## How to Contribute

### Types of Contributions

We welcome various types of contributions:

- 🐛 **Bug Reports**: Help us identify and fix issues
- ✨ **Feature Requests**: Suggest new functionality
- 🔧 **Code Contributions**: Implement features, fix bugs, improve performance
- 📚 **Documentation**: Improve docs, examples, tutorials
- 🧪 **Testing**: Add test cases, improve test coverage
- 🔍 **Code Review**: Review pull requests and provide feedback
- 🌐 **Translations**: Localize error messages and documentation

### Contribution Workflow

1. **Check existing issues** to avoid duplicate work
2. **Create an issue** for discussion (for significant changes)
3. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. **Make your changes** following our guidelines
5. **Add/update tests** for your changes
6. **Update documentation** if needed
7. **Run the full test suite**:
   ```bash
   make test-all
   ```
8. **Commit your changes** using conventional commits:
   ```bash
   git commit -m "feat: add device attestation for WebAuthn"
   ```
9. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```
10. **Create a Pull Request** with a clear description

### Pull Request Guidelines

#### PR Title Format
Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>[optional scope]: <description>

Examples:
feat(auth): add biometric authentication support
fix(cache): resolve Redis connection pool leak
docs(api): update configuration examples
test(device): add Android SafetyNet test cases
```

#### PR Description Template

```markdown
## Summary
Brief description of the changes.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Refactoring

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed
- [ ] Performance impact assessed

## Checklist
- [ ] My code follows the style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes

## Related Issues
Fixes #(issue number)
```

## Development Guidelines

### Code Style

#### Go Code Guidelines

1. **Follow Go conventions**:
   - Use `gofmt` for formatting
   - Use `golint` for linting
   - Follow [Effective Go](https://golang.org/doc/effective_go.html)

2. **Naming conventions**:
   ```go
   // Good
   func ValidateToken(ctx context.Context, token string) error
   type UserInfo struct { ... }
   var ErrInvalidToken = errors.New("invalid token")
   
   // Avoid
   func validate_token(ctx context.Context, token string) error
   func validateToken(ctx context.Context, Token string) error
   ```

3. **Error handling**:
   ```go
   // Good - wrap errors with context
   if err != nil {
       return fmt.Errorf("failed to validate token: %w", err)
   }
   
   // Good - define package-level errors
   var (
       ErrInvalidToken = errors.New("invalid token")
       ErrTokenExpired = errors.New("token expired")
   )
   ```

4. **Interface design**:
   ```go
   // Good - small, focused interfaces
   type TokenValidator interface {
       ValidateToken(ctx context.Context, token string) (*Claims, error)
   }
   
   // Good - accept interfaces, return structs
   func NewClient(validator TokenValidator) *Client
   ```

#### Package Organization

```
pkg/
├── client/          # Keycloak client implementation
├── types/           # Common types and interfaces
├── cache/           # Caching implementations
├── zerotrust/       # Zero Trust features
│   ├── device/      # Device attestation
│   ├── risk/        # Risk assessment
│   └── trust/       # Trust engine
├── config/          # Configuration management
├── plugins/         # Plugin system
└── internal/        # Internal utilities
```

#### Security Guidelines

1. **Input validation**:
   ```go
   func ValidateToken(token string) error {
       if token == "" {
           return ErrEmptyToken
       }
       if len(token) > MaxTokenLength {
           return ErrTokenTooLong
       }
       // Additional validation...
   }
   ```

2. **Secure defaults**:
   ```go
   type Config struct {
       Timeout      time.Duration `default:"30s"`
       MaxRetries   int           `default:"3"`
       UseHTTPS     bool          `default:"true"`
   }
   ```

3. **No secrets in logs**:
   ```go
   // Good
   log.Info("token validation failed", "user_id", userID)
   
   // Bad - never log tokens
   log.Info("token validation failed", "token", token)
   ```

### Performance Guidelines

1. **Context usage**:
   ```go
   func (c *Client) ValidateToken(ctx context.Context, token string) error {
       // Always check context cancellation
       select {
       case <-ctx.Done():
           return ctx.Err()
       default:
       }
       
       // Use context for HTTP requests
       req, err := http.NewRequestWithContext(ctx, "POST", url, body)
   }
   ```

2. **Memory management**:
   ```go
   // Good - use sync.Pool for frequent allocations
   var bufferPool = sync.Pool{
       New: func() interface{} {
           return make([]byte, 0, 1024)
       },
   }
   
   // Good - avoid memory leaks in goroutines
   func (c *Client) Start(ctx context.Context) error {
       go func() {
           defer c.cleanup() // Always cleanup
           for {
               select {
               case <-ctx.Done():
                   return
               case work := <-c.workChan:
                   c.process(work)
               }
           }
       }()
   }
   ```

## Testing Requirements

### Test Categories

1. **Unit Tests**: Test individual functions and methods
2. **Integration Tests**: Test component interactions
3. **End-to-End Tests**: Test complete workflows
4. **Performance Tests**: Benchmark critical paths
5. **Security Tests**: Validate security controls

### Writing Tests

#### Unit Tests
```go
func TestTokenValidator_ValidateToken(t *testing.T) {
    tests := []struct {
        name    string
        token   string
        want    *Claims
        wantErr bool
    }{
        {
            name:  "valid token",
            token: "valid.jwt.token",
            want:  &Claims{UserID: "123"},
        },
        {
            name:    "invalid token",
            token:   "invalid",
            wantErr: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            v := NewTokenValidator(testConfig)
            got, err := v.ValidateToken(context.Background(), tt.token)
            
            if tt.wantErr {
                assert.Error(t, err)
                return
            }
            
            assert.NoError(t, err)
            assert.Equal(t, tt.want, got)
        })
    }
}
```

#### Integration Tests
```go
// +build integration

func TestKeycloakIntegration(t *testing.T) {
    // Use testcontainers for real Keycloak
    keycloakContainer := setupKeycloak(t)
    defer keycloakContainer.Terminate(context.Background())
    
    client := setupClient(t, keycloakContainer.URI)
    
    // Test real integration
    token := getTestToken(t, client)
    claims, err := client.ValidateToken(context.Background(), token)
    
    require.NoError(t, err)
    assert.NotEmpty(t, claims.UserID)
}
```

#### Benchmark Tests
```go
func BenchmarkTokenValidation(b *testing.B) {
    client := setupTestClient(b)
    token := getValidToken(b)
    
    b.ResetTimer()
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            _, err := client.ValidateToken(context.Background(), token)
            if err != nil {
                b.Fatal(err)
            }
        }
    })
}
```

### Test Coverage

Maintain high test coverage:
- **Minimum**: 80% overall coverage
- **Critical paths**: 95% coverage
- **Security functions**: 100% coverage

```bash
# Check coverage
make test-coverage

# Generate coverage report
make coverage-html
```

### Running Tests

```bash
# Unit tests
make test

# Integration tests (requires Docker)
make test-integration

# E2E tests
make test-e2e

# Performance tests
make test-performance

# All tests
make test-all

# Specific package
go test ./pkg/client/...

# Verbose output
go test -v ./...

# Run with race detector
go test -race ./...
```

## Documentation

### Documentation Types

1. **API Documentation**: GoDoc comments
2. **User Guide**: Usage examples and tutorials
3. **Architecture Documentation**: Design decisions and patterns
4. **Configuration Reference**: All configuration options

### Writing Documentation

#### GoDoc Comments
```go
// ValidateToken validates a JWT token and returns the claims.
// It performs the following validations:
//   - Token signature verification
//   - Expiration time checking
//   - Issuer validation
//   - Custom claim validation
//
// Example:
//   claims, err := client.ValidateToken(ctx, "eyJhbGci...")
//   if err != nil {
//       return fmt.Errorf("validation failed: %w", err)
//   }
//   fmt.Printf("User ID: %s", claims.UserID)
func (c *Client) ValidateToken(ctx context.Context, token string) (*Claims, error) {
    // Implementation...
}
```

#### Examples
Create runnable examples in `examples/` directory:

```go
// examples/basic_gin/main.go
package main

import (
    "log"
    "github.com/gin-gonic/gin"
    zerotrust "github.com/yourorg/go-keycloak-zerotrust"
)

func main() {
    // Example implementation
}
```

### Documentation Tools

```bash
# Generate documentation
make docs

# Serve documentation locally
make docs-serve

# Update API reference
make docs-api

# Check documentation links
make docs-check
```

## Security

### Security Policy

For security vulnerabilities, please follow our [Security Policy](SECURITY.md):

1. **Do not** open public issues for security vulnerabilities
2. **Email** security@yourorg.com with details
3. **Include** steps to reproduce and potential impact
4. **Wait** for acknowledgment before public disclosure

### Security Checklist

When contributing code that handles:

- [ ] **Authentication**: Follow OWASP guidelines
- [ ] **Authorization**: Implement least privilege
- [ ] **Cryptography**: Use established libraries
- [ ] **Input Validation**: Sanitize all inputs
- [ ] **Error Handling**: Don't leak sensitive information
- [ ] **Logging**: Don't log secrets or PII

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Email**: [dev@yourorg.com](mailto:dev@yourorg.com) for development questions
- **Security**: [security@yourorg.com](mailto:security@yourorg.com) for security issues

### Getting Help

1. **Check existing documentation** and examples
2. **Search existing issues** for similar problems
3. **Ask in GitHub Discussions** for general questions
4. **Create an issue** for bugs or feature requests

### Recognition

Contributors are recognized in:
- **CONTRIBUTORS.md**: All contributors list
- **Release notes**: Significant contributions
- **GitHub**: Contributor badge and statistics

### Development Philosophy

Our development is guided by these principles:

1. **Security First**: Security is not an afterthought
2. **User Experience**: Simple APIs with powerful features
3. **Performance**: Optimize for common use cases
4. **Reliability**: Thorough testing and error handling
5. **Maintainability**: Clean, well-documented code
6. **Community**: Inclusive and welcoming environment

## License

By contributing to go-keycloak-zerotrust, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

Thank you for contributing to go-keycloak-zerotrust! Your efforts help create a more secure and accessible authentication ecosystem for the Go community. 🙏