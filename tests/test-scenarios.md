# Test Scenarios Documentation

## Authentication Test Scenarios

### 1. Admin User Login Scenarios

| Scenario | Username | Password | Tenant | Expected Result | Notes |
|----------|----------|----------|--------|-----------------|-------|
| Valid admin login | admin | password | - | Success | Returns JWT token, user info with admin role |
| Admin with wrong password | admin | wrongpassword | - | 401 Unauthorized | Error: "Invalid credentials" |
| Admin with email | admin@localhost | password | - | Success | Should accept email as username |
| Empty username | - | password | - | 400 Bad Request | Error: "Username and password are required" |
| Empty password | admin | - | - | 400 Bad Request | Error: "Username and password are required" |
| SQL injection attempt | admin' OR '1'='1 | password | - | 401 Unauthorized | Should be safely handled |

### 2. Regular User Login Scenarios

| Scenario | Username | Password | Tenant | Expected Result | Notes |
|----------|----------|----------|--------|-----------------|-------|
| New user registration | testuser | testpass123 | - | 201 Created | Creates user with "user" role |
| Login after registration | testuser | testpass123 | - | Success | Returns JWT with user role |
| Duplicate username | testuser | anypass | - | 409 Conflict | Error: "Username already exists" |
| Duplicate email | newuser | pass123 | - | 409 Conflict | Error: "Email already exists" |
| Weak password | user1 | pass | - | 400 Bad Request | Password min length is 8 |

### 3. Token Management Scenarios

| Scenario | Action | Token Type | Expected Result | Notes |
|----------|--------|------------|-----------------|-------|
| Refresh valid token | POST /api/auth/refresh | Valid refresh token | New access token | Both tokens updated |
| Refresh expired token | POST /api/auth/refresh | Expired refresh token | 401 Unauthorized | Error: "Invalid refresh token" |
| Access with expired token | GET /api/auth/me | Expired access token | 401 Unauthorized | Error: "Token expired" |
| Logout invalidates token | POST /api/auth/logout | Valid access token | Success | Token no longer valid |

### 4. Password Change Scenarios

| Scenario | Current Password | New Password | Expected Result | Notes |
|----------|------------------|--------------|-----------------|-------|
| Valid password change | password | newpassword123 | Success | All sessions invalidated |
| Wrong current password | wrongpass | newpassword123 | 401 Unauthorized | Error: "Invalid current password" |
| Weak new password | password | weak | 400 Bad Request | Password validation fails |
| Same as current | password | password | 400 Bad Request | Should not allow same password |

### 5. Multi-Tenant Scenarios (Future)

| Scenario | Username | Password | Tenant | Expected Result | Notes |
|----------|----------|----------|--------|-----------------|-------|
| User in tenant A | user@company | password | tenant-a | Success | Access to tenant-a resources |
| Same user, wrong tenant | user@company | password | tenant-b | 401 Unauthorized | User not in tenant-b |
| Admin cross-tenant | admin | password | any | Success | Admin can access all tenants |

## Integration Test Execution

### Running Integration Tests

```bash
# Start the development environment
make dev-up

# Wait for services to be ready
sleep 10

# Run integration tests
make test-integration

# Or run specific auth tests
go test -tags=integration -v ./tests/integration -run TestAuthentication
```

### Test Environment Requirements

1. **Database**: PostgreSQL with migrations applied
2. **Redis**: For session management (optional)
3. **API Server**: Running on http://localhost:8080
4. **Initial Data**:
   - Admin user: username=admin, password=password
   - Admin role with full permissions
   - User role with basic permissions

### Test Data Cleanup

Each test should:
1. Create its own test users when needed
2. Use unique usernames (e.g., with timestamps)
3. Clean up created data after test completion
4. Not modify the admin user

## React Integration Test Scenarios

### Screenshot Configuration

```javascript
// tests/integration/config.js
export const screenshotConfig = {
  enabled: true,
  onFailureOnly: true, // Set to false to capture all steps
  outputDir: './tests/screenshots',
  naming: '{testName}-{step}-{timestamp}.png'
};
```

### Login Flow Screenshots

1. **Initial Load**: Login page renders correctly
2. **Empty Form Submission**: Error messages display
3. **Invalid Credentials**: Error notification appears
4. **Successful Login**: Redirect to dashboard
5. **Token Expiry**: Redirect to login with message

### Playwright Test Structure

```javascript
// tests/e2e/auth.spec.js
test.describe('Authentication', () => {
  test('admin login flow', async ({ page }) => {
    // Navigate to login
    await page.goto('/login');
    
    // Fill credentials
    await page.fill('[name="username"]', 'admin');
    await page.fill('[name="password"]', 'password');
    
    // Submit and verify
    await page.click('[type="submit"]');
    await expect(page).toHaveURL('/dashboard');
  });
});
```

## Error Scenarios to Test

1. **Network Errors**:
   - API server down
   - Timeout on requests
   - Network interruption during request

2. **Security Tests**:
   - XSS attempts in login fields
   - CSRF token validation
   - Rate limiting on login attempts

3. **State Management**:
   - Multiple tabs with different sessions
   - Browser refresh during authentication
   - Back button after logout

4. **Edge Cases**:
   - Unicode characters in username/password
   - Very long input strings
   - Concurrent login attempts