# Testing Guide

This guide covers the comprehensive testing strategy for the Zero Trust Auth MVP, including unit tests, integration tests, E2E tests, and performance testing.

## 🧪 Testing Philosophy

Our testing approach follows the **testing pyramid**:

```
    /\
   /  \   E2E Tests (Few, High-level, UI)
  /____\
 /      \  Integration Tests (Some, API/Service level)
/_______\
/        \  Unit Tests (Many, Fast, Isolated)
/__________\
```

### Testing Principles

1. **Fast Feedback**: Tests should run quickly for rapid development
2. **Reliable**: Tests should be deterministic and not flaky
3. **Maintainable**: Tests should be easy to understand and modify
4. **Comprehensive**: Tests should cover critical functionality
5. **Realistic**: Tests should simulate real-world scenarios

## 📊 Test Categories

### 1. Unit Tests
- **Scope**: Individual functions, methods, components
- **Location**: `*_test.go` files alongside source code
- **Tools**: Go testing, testify, frontend: Jest + React Testing Library
- **Coverage Target**: 80% minimum

### 2. Integration Tests
- **Scope**: API endpoints, database interactions, service integration
- **Location**: `tests/integration/`
- **Tools**: Go testing with testcontainers, Docker Compose
- **Coverage**: Critical business flows

### 3. E2E Tests
- **Scope**: Complete user workflows through UI
- **Location**: `frontend/tests/e2e/`
- **Tools**: Playwright
- **Coverage**: Happy paths and critical user journeys

### 4. Performance Tests
- **Scope**: Load testing, stress testing, performance benchmarks
- **Location**: `tests/load/`
- **Tools**: k6, Go benchmarks
- **Coverage**: API endpoints under load

## 🔧 Test Setup

### Prerequisites

```bash
# Install testing tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install golang.org/x/vuln/cmd/govulncheck@latest

# Frontend testing tools (included in package.json)
cd frontend
npm install
```

### Test Environment

```bash
# Start test infrastructure
make dev-up

# Run all tests
make test

# Run with coverage
make test-coverage

# Run integration tests
make test-integration

# Run load tests
make test-load
```

## 🧮 Unit Testing

### Backend Unit Tests

#### Test Structure

```go
// pkg/auth/jwt_test.go
package auth

import (
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestJWTService_GenerateToken(t *testing.T) {
    tests := []struct {
        name          string
        config        *JWTConfig
        userID        string
        username      string
        roles         []string
        permissions   []string
        expectedError bool
    }{
        {
            name: "successful_token_generation",
            config: &JWTConfig{
                Secret:             "test-secret",
                AccessTokenTTL:     time.Hour,
                RefreshTokenTTL:    24 * time.Hour,
                Issuer:            "test-issuer",
                Audience:          "test-audience",
            },
            userID:        "user-123",
            username:      "testuser",
            roles:         []string{"user"},
            permissions:   []string{"read:profile"},
            expectedError: false,
        },
        {
            name: "empty_secret_should_fail",
            config: &JWTConfig{
                Secret: "",
            },
            userID:        "user-123",
            username:      "testuser",
            roles:         []string{"user"},
            permissions:   []string{"read:profile"},
            expectedError: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            service := NewJWTService(tt.config, nil)
            
            token, err := service.GenerateToken(
                context.Background(),
                tt.userID,
                tt.username,
                time.Now().Add(tt.config.AccessTokenTTL),
                tt.roles,
                tt.permissions,
            )

            if tt.expectedError {
                assert.Error(t, err)
                assert.Empty(t, token)
            } else {
                assert.NoError(t, err)
                assert.NotEmpty(t, token)
                
                // Validate token structure
                claims, err := service.ValidateToken(token)
                require.NoError(t, err)
                assert.Equal(t, tt.userID, claims.Subject)
                assert.Equal(t, tt.username, claims.Username)
                assert.Equal(t, tt.roles, claims.Roles)
                assert.Equal(t, tt.permissions, claims.Permissions)
            }
        })
    }
}
```

#### Test Helpers

```go
// pkg/testutil/auth.go
package testutil

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/require"
    "mvp.local/pkg/auth"
)

// CreateTestJWTService creates a JWT service for testing
func CreateTestJWTService(t *testing.T) *auth.JWTService {
    config := &auth.JWTConfig{
        Secret:             "test-secret-key",
        AccessTokenTTL:     time.Hour,
        RefreshTokenTTL:    24 * time.Hour,
        Issuer:            "test-issuer",
        Audience:          "test-audience",
    }
    
    return auth.NewJWTService(config, nil)
}

// GenerateTestToken creates a valid JWT token for testing
func GenerateTestToken(t *testing.T, service *auth.JWTService, userID, username string) string {
    token, err := service.GenerateToken(
        context.Background(),
        userID,
        username,
        time.Now().Add(time.Hour),
        []string{"user"},
        []string{"read:profile"},
    )
    require.NoError(t, err)
    return token
}
```

#### Mock Objects

```go
// pkg/testutil/mocks.go
package testutil

import (
    "github.com/stretchr/testify/mock"
    "mvp.local/pkg/auth"
)

// MockAuthorizationService is a mock implementation
type MockAuthorizationService struct {
    mock.Mock
}

func (m *MockAuthorizationService) CheckPermission(userID, resource, action string) error {
    args := m.Called(userID, resource, action)
    return args.Error(0)
}

func (m *MockAuthorizationService) GetUserRoles(userID string) ([]string, error) {
    args := m.Called(userID)
    return args.Get(0).([]string), args.Error(1)
}

func (m *MockAuthorizationService) GetUserPermissions(userID string) ([]string, error) {
    args := m.Called(userID)
    return args.Get(0).([]string), args.Error(1)
}

// NewMockAuthorizationService creates a new mock with common expectations
func NewMockAuthorizationService() *MockAuthorizationService {
    mock := &MockAuthorizationService{}
    
    // Set up common mock responses
    mock.On("GetUserRoles", "admin").Return([]string{"admin", "user"}, nil)
    mock.On("GetUserPermissions", "admin").Return([]string{"system:admin", "device:verify"}, nil)
    mock.On("CheckPermission", "admin", mock.Anything, mock.Anything).Return(nil)
    
    return mock
}
```

### Frontend Unit Tests

#### Component Testing

```typescript
// frontend/src/components/__tests__/LoginForm.test.tsx
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { vi } from 'vitest';
import LoginForm from '../LoginForm';
import { AuthProvider } from '../../hooks/useAuth';

// Mock the auth hook
vi.mock('../../hooks/useAuth', async () => {
  const actual = await vi.importActual('../../hooks/useAuth');
  return {
    ...actual,
    useAuth: vi.fn(),
  };
});

describe('LoginForm', () => {
  const mockLogin = vi.fn();
  
  beforeEach(() => {
    vi.clearAllMocks();
    (useAuth as any).mockReturnValue({
      login: mockLogin,
      loading: false,
      error: null,
    });
  });

  it('renders login form correctly', () => {
    render(<LoginForm />);
    
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /login/i })).toBeInTheDocument();
  });

  it('submits form with correct credentials', async () => {
    render(<LoginForm />);
    
    const usernameInput = screen.getByLabelText(/username/i);
    const passwordInput = screen.getByLabelText(/password/i);
    const submitButton = screen.getByRole('button', { name: /login/i });
    
    fireEvent.change(usernameInput, { target: { value: 'admin' } });
    fireEvent.change(passwordInput, { target: { value: 'password' } });
    fireEvent.click(submitButton);
    
    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith('admin', 'password');
    });
  });

  it('displays validation errors for empty fields', async () => {
    render(<LoginForm />);
    
    const submitButton = screen.getByRole('button', { name: /login/i });
    fireEvent.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText(/username is required/i)).toBeInTheDocument();
      expect(screen.getByText(/password is required/i)).toBeInTheDocument();
    });
  });

  it('displays error message on login failure', () => {
    (useAuth as any).mockReturnValue({
      login: mockLogin,
      loading: false,
      error: 'Invalid credentials',
    });
    
    render(<LoginForm />);
    
    expect(screen.getByText(/invalid credentials/i)).toBeInTheDocument();
  });
});
```

#### Hook Testing

```typescript
// frontend/src/hooks/__tests__/useAuth.test.tsx
import { renderHook, act } from '@testing-library/react';
import { vi } from 'vitest';
import { useAuth, AuthProvider } from '../useAuth';
import * as api from '../../services/api';

vi.mock('../../services/api');

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <AuthProvider>{children}</AuthProvider>
);

describe('useAuth', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
  });

  it('initializes with no user', () => {
    const { result } = renderHook(() => useAuth(), { wrapper });
    
    expect(result.current.user).toBeNull();
    expect(result.current.loading).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it('logs in user successfully', async () => {
    const mockUser = { id: '1', username: 'admin', email: 'admin@test.com' };
    const mockResponse = {
      access_token: 'access-token',
      refresh_token: 'refresh-token',
      user: mockUser,
    };
    
    vi.mocked(api.login).mockResolvedValue(mockResponse);
    
    const { result } = renderHook(() => useAuth(), { wrapper });
    
    await act(async () => {
      await result.current.login('admin', 'password');
    });
    
    expect(result.current.user).toEqual(mockUser);
    expect(result.current.error).toBeNull();
    expect(localStorage.getItem('authToken')).toBe('access-token');
  });

  it('handles login error', async () => {
    const errorMessage = 'Invalid credentials';
    vi.mocked(api.login).mockRejectedValue(new Error(errorMessage));
    
    const { result } = renderHook(() => useAuth(), { wrapper });
    
    await act(async () => {
      await result.current.login('admin', 'wrong-password');
    });
    
    expect(result.current.user).toBeNull();
    expect(result.current.error).toBe(errorMessage);
  });
});
```

## 🔗 Integration Testing

### API Integration Tests

```go
// tests/integration/auth_integration_test.go
package integration

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/testcontainers/testcontainers-go"
    "github.com/testcontainers/testcontainers-go/modules/postgres"
    "mvp.local/pkg/handlers"
)

func TestAuthIntegration(t *testing.T) {
    // Start test containers
    ctx := context.Background()
    
    // PostgreSQL container
    postgresContainer, err := postgres.RunContainer(ctx,
        testcontainers.WithImage("postgres:15-alpine"),
        postgres.WithDatabase("test_db"),
        postgres.WithUsername("test_user"),
        postgres.WithPassword("test_password"),
    )
    require.NoError(t, err)
    defer postgresContainer.Terminate(ctx)
    
    // Get connection string
    connStr, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
    require.NoError(t, err)
    
    // Setup test server
    server := setupTestServer(t, connStr)
    
    t.Run("POST /api/auth/login", func(t *testing.T) {
        // Test successful login
        loginReq := map[string]string{
            "username": "admin",
            "password": "password",
        }
        
        reqBody, _ := json.Marshal(loginReq)
        req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(reqBody))
        req.Header.Set("Content-Type", "application/json")
        
        w := httptest.NewRecorder()
        server.ServeHTTP(w, req)
        
        assert.Equal(t, http.StatusOK, w.Code)
        
        var response map[string]interface{}
        err := json.Unmarshal(w.Body.Bytes(), &response)
        require.NoError(t, err)
        
        assert.Contains(t, response, "access_token")
        assert.Contains(t, response, "refresh_token")
        assert.Contains(t, response, "user")
    })
    
    t.Run("POST /api/auth/login with invalid credentials", func(t *testing.T) {
        loginReq := map[string]string{
            "username": "admin",
            "password": "wrong-password",
        }
        
        reqBody, _ := json.Marshal(loginReq)
        req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(reqBody))
        req.Header.Set("Content-Type", "application/json")
        
        w := httptest.NewRecorder()
        server.ServeHTTP(w, req)
        
        assert.Equal(t, http.StatusUnauthorized, w.Code)
    })
}

func setupTestServer(t *testing.T, dbURL string) http.Handler {
    // Initialize test database
    db, err := database.NewTestDatabase(dbURL)
    require.NoError(t, err)
    
    // Run migrations
    err = db.Migrate()
    require.NoError(t, err)
    
    // Seed test data
    err = seedTestData(db)
    require.NoError(t, err)
    
    // Create test services
    obs := observability.NewTest()
    authService := auth.NewJWTService(&auth.JWTConfig{
        Secret: "test-secret",
        AccessTokenTTL: time.Hour,
    }, nil)
    
    // Create handlers
    authHandler := handlers.NewAuthHandler(db.GetDB(), authService, nil, obs, &config.Config{})
    
    // Setup router
    router := fiber.New()
    api := router.Group("/api")
    auth := api.Group("/auth")
    auth.Post("/login", authHandler.Login)
    
    return router
}
```

### Database Integration Tests

```go
// tests/integration/database_test.go
package integration

import (
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "mvp.local/pkg/models"
)

func TestUserCRUD(t *testing.T) {
    db := setupTestDB(t)
    
    t.Run("Create User", func(t *testing.T) {
        user := &models.User{
            Username:  "testuser",
            Email:     "test@example.com",
            FirstName: "Test",
            LastName:  "User",
            IsActive:  true,
        }
        
        err := db.Create(user).Error
        require.NoError(t, err)
        assert.NotEmpty(t, user.ID)
        assert.NotZero(t, user.CreatedAt)
    })
    
    t.Run("Find User", func(t *testing.T) {
        // Create test user
        user := &models.User{
            Username: "finduser",
            Email:    "find@example.com",
        }
        db.Create(user)
        
        // Find user
        var foundUser models.User
        err := db.Where("username = ?", "finduser").First(&foundUser).Error
        require.NoError(t, err)
        assert.Equal(t, user.Username, foundUser.Username)
        assert.Equal(t, user.Email, foundUser.Email)
    })
    
    t.Run("Update User", func(t *testing.T) {
        // Create test user
        user := &models.User{
            Username: "updateuser",
            Email:    "update@example.com",
        }
        db.Create(user)
        
        // Update user
        user.FirstName = "Updated"
        err := db.Save(user).Error
        require.NoError(t, err)
        
        // Verify update
        var updatedUser models.User
        db.First(&updatedUser, user.ID)
        assert.Equal(t, "Updated", updatedUser.FirstName)
    })
}
```

## 🎭 E2E Testing

### Playwright Configuration

```typescript
// frontend/playwright.config.ts
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [
    ['html'],
    ['json', { outputFile: 'test-results/results.json' }]
  ],
  use: {
    baseURL: process.env.BASE_URL || 'http://localhost:5175',
    extraHTTPHeaders: {
      'X-API-URL': process.env.API_URL || 'http://localhost:8080'
    },
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
  ],
  webServer: [
    {
      command: 'npm run dev',
      url: 'http://localhost:5175',
      reuseExistingServer: !process.env.CI,
      timeout: 120 * 1000,
    },
    {
      command: 'cd .. && make dev-up',
      url: 'http://localhost:8080/health',
      reuseExistingServer: !process.env.CI,
      timeout: 120 * 1000,
    }
  ],
});
```

### E2E Test Examples

```typescript
// frontend/tests/e2e/auth-flow.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Authentication Flow', () => {
  test.beforeEach(async ({ page }) => {
    // Clear storage before each test
    await page.goto('/');
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
  });

  test('complete authentication workflow', async ({ page }) => {
    // Start at login page
    await page.goto('/login');
    
    // Verify login form
    await expect(page.locator('input[name="username"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();
    
    // Fill and submit login form
    await page.fill('input[name="username"]', 'admin');
    await page.fill('input[name="password"]', 'password');
    await page.click('button[type="submit"]');
    
    // Wait for redirect to dashboard
    await page.waitForURL('/dashboard');
    
    // Verify successful login
    await expect(page.locator('[data-testid="user-menu"]')).toBeVisible();
    await expect(page.locator('text=Welcome, admin')).toBeVisible();
    
    // Test protected navigation
    await page.click('nav a[href="/devices"]');
    await page.waitForURL('/devices');
    await expect(page.locator('h1:has-text("Devices")')).toBeVisible();
    
    // Test logout
    await page.click('[data-testid="user-menu"]');
    await page.click('button:has-text("Logout")');
    await page.waitForURL('/login');
    
    // Verify logout
    await expect(page.locator('input[name="username"]')).toBeVisible();
  });

  test('device management workflow', async ({ page }) => {
    // Login first
    await page.goto('/login');
    await page.fill('input[name="username"]', 'admin');
    await page.fill('input[name="password"]', 'password');
    await page.click('button[type="submit"]');
    await page.waitForURL('/dashboard');
    
    // Navigate to devices
    await page.click('nav a[href="/devices"]');
    
    // Add new device
    await page.click('button:has-text("Add Device")');
    await page.fill('input[name="device_name"]', 'Test Device');
    await page.fill('input[name="device_id"]', 'test-device-001');
    await page.selectOption('select[name="platform"]', 'macOS');
    await page.click('button[type="submit"]');
    
    // Verify device appears in list
    await expect(page.locator('text=Test Device')).toBeVisible();
    
    // Verify device details
    await page.click('text=Test Device');
    await expect(page.locator('text=test-device-001')).toBeVisible();
    await expect(page.locator('text=macOS')).toBeVisible();
  });

  test('admin panel workflow', async ({ page }) => {
    // Login as admin
    await page.goto('/login');
    await page.fill('input[name="username"]', 'admin');
    await page.fill('input[name="password"]', 'password');
    await page.click('button[type="submit"]');
    await page.waitForURL('/dashboard');
    
    // Navigate to admin panel
    await page.click('nav a[href="/admin"]');
    
    // Check user management
    await page.click('tab:has-text("Users")');
    await expect(page.locator('table')).toBeVisible();
    await expect(page.locator('td:has-text("admin")')).toBeVisible();
    
    // Check role management
    await page.click('tab:has-text("Roles")');
    await expect(page.locator('text=admin')).toBeVisible();
    await expect(page.locator('text=user')).toBeVisible();
  });
});
```

### Page Object Model

```typescript
// frontend/tests/e2e/pages/LoginPage.ts
export class LoginPage {
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto('/login');
  }

  async login(username: string, password: string) {
    await this.page.fill('input[name="username"]', username);
    await this.page.fill('input[name="password"]', password);
    await this.page.click('button[type="submit"]');
  }

  async expectLoginForm() {
    await expect(this.page.locator('input[name="username"]')).toBeVisible();
    await expect(this.page.locator('input[name="password"]')).toBeVisible();
    await expect(this.page.locator('button[type="submit"]')).toBeVisible();
  }

  async expectError(message: string) {
    await expect(this.page.locator(`text=${message}`)).toBeVisible();
  }
}

// Usage in tests
test('login with invalid credentials', async ({ page }) => {
  const loginPage = new LoginPage(page);
  
  await loginPage.goto();
  await loginPage.expectLoginForm();
  await loginPage.login('admin', 'wrong-password');
  await loginPage.expectError('Invalid credentials');
});
```

## ⚡ Performance Testing

### Load Testing with k6

```javascript
// tests/load/basic-load-test.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const errorRate = new Rate('errors');

export let options = {
  stages: [
    { duration: '2m', target: 100 }, // Ramp up to 100 users
    { duration: '5m', target: 100 }, // Stay at 100 users
    { duration: '2m', target: 200 }, // Ramp up to 200 users
    { duration: '5m', target: 200 }, // Stay at 200 users
    { duration: '2m', target: 0 },   // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests must complete within 500ms
    http_req_failed: ['rate<0.1'],    // Error rate must be below 10%
    errors: ['rate<0.1'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

export function setup() {
  // Authenticate once and return token
  const loginResponse = http.post(`${BASE_URL}/api/auth/login`, JSON.stringify({
    username: 'admin',
    password: 'password',
  }), {
    headers: { 'Content-Type': 'application/json' },
  });
  
  return {
    token: loginResponse.json('access_token'),
  };
}

export default function(data) {
  // Test health endpoint
  let response = http.get(`${BASE_URL}/health`);
  check(response, {
    'health check status is 200': (r) => r.status === 200,
    'health check response time < 100ms': (r) => r.timings.duration < 100,
  }) || errorRate.add(1);

  // Test authenticated endpoint
  response = http.get(`${BASE_URL}/api/auth/me`, {
    headers: {
      'Authorization': `Bearer ${data.token}`,
    },
  });
  check(response, {
    'auth me status is 200': (r) => r.status === 200,
    'auth me response time < 200ms': (r) => r.timings.duration < 200,
  }) || errorRate.add(1);

  // Test device listing
  response = http.get(`${BASE_URL}/api/devices`, {
    headers: {
      'Authorization': `Bearer ${data.token}`,
    },
  });
  check(response, {
    'devices status is 200': (r) => r.status === 200,
    'devices response time < 300ms': (r) => r.timings.duration < 300,
  }) || errorRate.add(1);

  sleep(1);
}
```

### Benchmark Tests

```go
// pkg/auth/jwt_benchmark_test.go
package auth

import (
    "context"
    "testing"
    "time"
)

func BenchmarkJWTService_GenerateToken(b *testing.B) {
    service := NewJWTService(&JWTConfig{
        Secret:          "benchmark-secret",
        AccessTokenTTL:  time.Hour,
        RefreshTokenTTL: 24 * time.Hour,
    }, nil)

    b.ResetTimer()
    b.ReportAllocs()

    for i := 0; i < b.N; i++ {
        _, err := service.GenerateToken(
            context.Background(),
            "user-123",
            "testuser",
            time.Now().Add(time.Hour),
            []string{"user"},
            []string{"read:profile"},
        )
        if err != nil {
            b.Fatal(err)
        }
    }
}

func BenchmarkJWTService_ValidateToken(b *testing.B) {
    service := NewJWTService(&JWTConfig{
        Secret:          "benchmark-secret",
        AccessTokenTTL:  time.Hour,
        RefreshTokenTTL: 24 * time.Hour,
    }, nil)

    // Generate a token to validate
    token, err := service.GenerateToken(
        context.Background(),
        "user-123",
        "testuser",
        time.Now().Add(time.Hour),
        []string{"user"},
        []string{"read:profile"},
    )
    if err != nil {
        b.Fatal(err)
    }

    b.ResetTimer()
    b.ReportAllocs()

    for i := 0; i < b.N; i++ {
        _, err := service.ValidateToken(token)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

## 📊 Test Coverage

### Measuring Coverage

```bash
# Backend coverage
make test-coverage
open coverage.html

# Frontend coverage
cd frontend
npm run test:coverage
open coverage/lcov-report/index.html

# Check coverage meets threshold
make check-coverage
```

### Coverage Configuration

```go
// .github/workflows/test.yml
- name: Test with coverage
  run: |
    go test -race -coverprofile=coverage.out -covermode=atomic ./...
    go tool cover -html=coverage.out -o coverage.html

- name: Check coverage threshold
  run: |
    COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
    echo "Coverage: ${COVERAGE}%"
    if (( $(echo "$COVERAGE < 80" | bc -l) )); then
      echo "Coverage ${COVERAGE}% is below 80% threshold"
      exit 1
    fi
```

## 🚀 Running Tests

### Local Development

```bash
# Run all tests
make test

# Run specific test packages
go test -v ./pkg/auth/...
go test -v ./pkg/handlers/...

# Run with coverage
make test-coverage

# Run integration tests
make test-integration

# Run E2E tests
cd frontend
npm run test:e2e

# Run load tests
make test-load
```

### CI/CD Pipeline

```yaml
# .github/workflows/test.yml
name: Test

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test
          POSTGRES_DB: test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.23'
    
    - name: Install dependencies
      run: go mod download
    
    - name: Run tests
      run: make test
    
    - name: Run integration tests
      run: make test-integration
      env:
        DATABASE_URL: postgres://postgres:test@localhost:5432/test?sslmode=disable
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.out
```

## 🔧 Test Configuration

### Test Environment Variables

```bash
# Test configuration
export TEST_DATABASE_URL=postgres://test:test@localhost:5432/test_db
export TEST_REDIS_URL=redis://localhost:6379/1
export TEST_JWT_SECRET=test-secret-key
export TEST_LOG_LEVEL=error
export CI=true
```

### Test Data Management

```go
// tests/testdata/users.go
package testdata

import "mvp.local/pkg/models"

var TestUsers = []models.User{
    {
        ID:        "admin-user-id",
        Username:  "admin",
        Email:     "admin@test.com",
        FirstName: "Admin",
        LastName:  "User",
        IsActive:  true,
        IsAdmin:   true,
    },
    {
        ID:        "regular-user-id",
        Username:  "user",
        Email:     "user@test.com",
        FirstName: "Regular",
        LastName:  "User",
        IsActive:  true,
        IsAdmin:   false,
    },
}

func SeedTestUsers(db *gorm.DB) error {
    for _, user := range TestUsers {
        if err := db.Create(&user).Error; err != nil {
            return err
        }
    }
    return nil
}
```

## 🚨 Testing Best Practices

### 1. Test Naming Conventions

```go
// Good test names
func TestJWTService_GenerateToken_WithValidInput_ReturnsToken(t *testing.T)
func TestAuthHandler_Login_WithInvalidCredentials_Returns401(t *testing.T)
func TestDeviceService_CreateDevice_WithExistingDeviceID_ReturnsConflict(t *testing.T)

// Table-driven tests
func TestPasswordValidation(t *testing.T) {
    tests := []struct {
        name     string
        password string
        expected bool
    }{
        {"valid_password", "SecurePass123!", true},
        {"too_short", "123", false},
        {"no_uppercase", "securepass123!", false},
    }
    // ...
}
```

### 2. Test Organization

```
tests/
├── integration/         # Integration tests
│   ├── auth_test.go
│   ├── device_test.go
│   └── admin_test.go
├── load/               # Performance tests
│   ├── basic-load-test.js
│   └── stress-test.js
├── testdata/           # Test fixtures
│   ├── users.json
│   └── devices.json
└── fixtures/           # Test setup utilities
    ├── database.go
    └── server.go
```

### 3. Test Isolation

```go
func TestWithCleanDatabase(t *testing.T) {
    db := setupTestDB(t)
    defer cleanupTestDB(t, db)
    
    // Test logic here
}

func setupTestDB(t *testing.T) *gorm.DB {
    db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
    require.NoError(t, err)
    
    err = db.AutoMigrate(&models.User{}, &models.Device{})
    require.NoError(t, err)
    
    return db
}
```

### 4. Async Testing

```typescript
// Frontend async testing
test('loads user data on mount', async () => {
  const mockUser = { id: '1', name: 'Test User' };
  vi.mocked(api.getCurrentUser).mockResolvedValue(mockUser);
  
  render(<UserProfile />);
  
  expect(screen.getByText('Loading...')).toBeInTheDocument();
  
  await waitFor(() => {
    expect(screen.getByText('Test User')).toBeInTheDocument();
  });
  
  expect(api.getCurrentUser).toHaveBeenCalledTimes(1);
});
```

## 📚 Additional Resources

- [Go Testing Package](https://pkg.go.dev/testing)
- [Testify Documentation](https://github.com/stretchr/testify)
- [Playwright Documentation](https://playwright.dev/)
- [k6 Documentation](https://k6.io/docs/)
- [React Testing Library](https://testing-library.com/docs/react-testing-library/intro/)
- [Testing Best Practices](https://github.com/goldbergyoni/javascript-testing-best-practices)