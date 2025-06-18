# E2E Testing Guide with Playwright

This guide covers how to run and manage End-to-End (E2E) tests using Playwright from the project root.

## Quick Start

### One-Time Setup

```bash
# Install frontend dependencies and Playwright
make frontend-install

# Setup E2E test environment (starts backend services if needed)
make test-e2e-setup
```

### Running E2E Tests

```bash
# Run all E2E tests (headless mode)
make test-e2e

# Run tests with UI mode (interactive)
make test-e2e-ui

# Run tests in headed mode (see browser)
make test-e2e-headed

# Debug tests (step through)
make test-e2e-debug

# Run tests on Chrome only
make test-e2e-chrome

# Show test report
make test-e2e-report
```

## Available Makefile Targets

| Target | Description | Use Case |
|--------|-------------|----------|
| `test-e2e-setup` | Setup E2E environment | First-time setup or environment check |
| `test-e2e` | Run all E2E tests | CI/CD or regular test runs |
| `test-e2e-ui` | Interactive UI mode | Debugging and test development |
| `test-e2e-debug` | Debug mode | Step through failing tests |
| `test-e2e-headed` | Headed browser mode | Watch tests execute |
| `test-e2e-chrome` | Chrome only | Quick single-browser testing |
| `test-e2e-report` | Show HTML report | Review test results |
| `test-e2e-codegen` | Record new tests | Generate test code |
| `test-all` | Run unit + E2E tests | Complete test suite |

## Test Recording

Use Playwright's code generator to record new tests:

```bash
# Start the test recorder
make test-e2e-codegen

# This will:
# 1. Open a browser window
# 2. Navigate to http://localhost:5175
# 3. Record your interactions
# 4. Generate test code
```

## Prerequisites

The E2E tests require:

1. **Backend Services**: PostgreSQL, Redis, etc.
   ```bash
   make dev-up  # Starts all backend services
   ```

2. **Frontend Dev Server** (optional for some tests):
   ```bash
   make dev-frontend  # In a separate terminal
   ```

3. **Playwright Browsers**: Automatically installed on first run

## Test Environment

### Default Test Credentials

- **Username**: `admin`
- **Password**: `password`

### Service URLs

- **Frontend**: http://localhost:5175
- **Backend API**: http://localhost:8080
- **Grafana**: http://localhost:3000 (admin/admin)
- **Jaeger**: http://localhost:16686

## Writing E2E Tests

### Test Structure

E2E tests are located in `frontend/tests/e2e/`:

```
frontend/tests/e2e/
├── auth.spec.ts          # Authentication flows
├── dashboard.spec.ts     # Dashboard functionality
├── devices.spec.ts       # Device management
├── admin.spec.ts         # Admin panel tests
└── fixtures/
    ├── users.ts          # Test user data
    └── devices.ts        # Test device data
```

### Example Test

```typescript
// frontend/tests/e2e/auth.spec.ts
import { test, expect } from '@playwright/test';

test('should successfully login as admin user', async ({ page }) => {
  // Navigate to login page
  await page.goto('/login');
  
  // Fill login form
  await page.fill('input[name="username"]', 'admin');
  await page.fill('input[name="password"]', 'password');
  
  // Submit form
  await page.click('button[type="submit"]');
  
  // Verify successful login
  await expect(page).toHaveURL('/dashboard');
  await expect(page.locator('text=Welcome')).toBeVisible();
});
```

## CI/CD Integration

E2E tests run automatically in CI/CD:

```yaml
# Example GitHub Actions usage
- name: Setup E2E environment
  run: make test-e2e-setup

- name: Run E2E tests
  run: make test-e2e
```

## Troubleshooting

### Common Issues

#### 1. Backend Services Not Running

```bash
# Error: Connection refused to localhost:8080

# Solution:
make dev-up        # Start backend services
make test-e2e-setup  # Verify environment
```

#### 2. Playwright Browsers Not Installed

```bash
# Error: Executable doesn't exist at...

# Solution:
cd frontend && npx playwright install
# Or simply run any test command - it auto-installs
```

#### 3. Port Conflicts

```bash
# Error: Port 5175 already in use

# Solution:
# Kill the process using the port
lsof -ti:5175 | xargs kill -9
```

#### 4. Test Timeouts

```bash
# Increase timeout in playwright.config.ts
use: {
  timeout: 60000,  // 60 seconds
}
```

### Debug Mode

For failing tests, use debug mode:

```bash
# Step through test execution
make test-e2e-debug

# Or add breakpoint in test
test('my test', async ({ page }) => {
  await page.pause();  // Debugger will pause here
});
```

### View Test Results

After running tests:

```bash
# Open HTML report
make test-e2e-report

# Report includes:
# - Test results summary
# - Screenshots of failures
# - Test execution timeline
# - Detailed error traces
```

## Best Practices

### 1. Test Independence

Each test should be independent:

```typescript
test.beforeEach(async ({ page }) => {
  // Reset to clean state
  await page.goto('/');
  await page.evaluate(() => localStorage.clear());
});
```

### 2. Use Data Attributes

Add data attributes for reliable selectors:

```tsx
<button data-testid="submit-login">Login</button>
```

```typescript
await page.click('[data-testid="submit-login"]');
```

### 3. Wait for Elements

Use proper wait strategies:

```typescript
// Good - waits for element
await page.waitForSelector('[data-testid="dashboard"]');

// Better - explicit expectation
await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
```

### 4. Parallel Execution

Configure parallel execution in `playwright.config.ts`:

```typescript
export default {
  workers: process.env.CI ? 1 : undefined,  // Serial in CI, parallel locally
  fullyParallel: true,
};
```

## Advanced Usage

### Running Specific Tests

```bash
# Run tests matching pattern
cd frontend && npx playwright test auth

# Run single test file
cd frontend && npx playwright test tests/e2e/auth.spec.ts

# Run tests with specific tag
cd frontend && npx playwright test --grep @smoke
```

### Multiple Browsers

```bash
# Test on all browsers
make test-e2e

# Test specific browser from frontend dir
cd frontend && npx playwright test --project=firefox
```

### Custom Environment Variables

```bash
# Use different API URL
API_URL=http://localhost:3001 make test-e2e

# Use different base URL
BASE_URL=http://staging.example.com make test-e2e
```

## Continuous Improvement

1. **Add Visual Testing**: Use Playwright's screenshot comparison
2. **Performance Testing**: Measure page load times
3. **Accessibility Testing**: Integrate axe-core
4. **Mobile Testing**: Add mobile viewport tests

## Summary

The Playwright E2E testing setup provides:

- ✅ Easy-to-use Makefile commands from project root
- ✅ Automatic environment setup
- ✅ Multiple testing modes (UI, debug, headed)
- ✅ Test recording capabilities
- ✅ Comprehensive test reporting
- ✅ CI/CD ready configuration

Run `make help` to see all available E2E testing commands.