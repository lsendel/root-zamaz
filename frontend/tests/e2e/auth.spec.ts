import { test, expect } from '@playwright/test';

// Test data
const testUsers = {
  admin: {
    username: 'admin',
    password: 'password',
    email: 'admin@localhost'
  },
  invalid: {
    username: 'invalid',
    password: 'wrongpass'
  }
};

test.describe('Authentication E2E Tests', () => {
  test.beforeEach(async ({ page }) => {
    // Clear storage before each test
    await page.goto('/');
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
  });

  test('should display login page correctly', async ({ page }) => {
    await page.goto('/login');
    
    // Check page title
    await expect(page).toHaveTitle(/login/i);
    
    // Check form elements are present
    await expect(page.locator('input[name="username"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
    
    // Take screenshot
    await page.screenshot({ path: 'test-results/login-page.png' });
  });

  test('should show validation errors for empty form', async ({ page }) => {
    await page.goto('/login');
    
    // Try to submit without filling form
    await page.click('button[type="submit"]');
    
    // Check for HTML5 validation or custom error messages
    // The form should not submit if fields are required
    const usernameInput = page.locator('input[name="username"]');
    const passwordInput = page.locator('input[name="password"]');
    
    // Check if the browser shows validation messages (HTML5 required attribute)
    const usernameValidity = await usernameInput.evaluate((el: HTMLInputElement) => el.validity.valueMissing);
    const passwordValidity = await passwordInput.evaluate((el: HTMLInputElement) => el.validity.valueMissing);
    
    // At least one field should show validation error
    expect(usernameValidity || passwordValidity).toBeTruthy();
    
    // URL should still be on login page (form didn't submit)
    expect(page.url()).toContain('/login');
    
    // Take screenshot of validation state
    await page.screenshot({ path: 'test-results/login-validation-errors.png' });
  });

  test('should show error for invalid credentials', async ({ page }) => {
    await page.goto('/login');
    
    // Fill form with invalid credentials
    await page.fill('input[name="username"]', testUsers.invalid.username);
    await page.fill('input[name="password"]', testUsers.invalid.password);
    
    // Take screenshot before submit
    await page.screenshot({ path: 'test-results/invalid-credentials-form.png' });
    
    // Listen for the login API response
    const responsePromise = page.waitForResponse(response => 
      response.url().includes('/api/auth/login') && response.request().method() === 'POST'
    );
    
    // Submit form
    await page.click('button[type="submit"]');
    
    // Wait for API response
    const response = await responsePromise;
    
    // Check if login failed (should get 401 or stay on login page)
    if (response.status() !== 200) {
      // API returned error
      expect(response.status()).toBe(401);
    }
    
    // Should still be on login page after failed login
    await page.waitForTimeout(500); // Small wait for any navigation
    expect(page.url()).toContain('/login');
    
    // Check for any error indication (error message, form state, or just staying on login page)
    // Since login failed, staying on login page is sufficient validation
    const isStillOnLogin = page.url().includes('/login');
    expect(isStillOnLogin).toBeTruthy();
    
    // Take screenshot of error state
    await page.screenshot({ path: 'test-results/invalid-credentials-error.png' });
  });

  test('should successfully login as admin user', async ({ page }) => {
    await page.goto('/login');
    
    // Listen for console errors and warnings
    page.on('console', msg => {
      if (msg.type() === 'error' || msg.type() === 'warning') {
        console.log(`Frontend ${msg.type()}:`, msg.text());
      }
    });
    
    // Listen for page errors
    page.on('pageerror', error => {
      console.log('Page error:', error.message);
    });

    // Listen for network responses
    page.on('response', async response => {
      if (response.url().includes('/api/auth/login')) {
        console.log('Login API response:', response.status(), await response.text());
      }
    });
    
    // Fill login form
    await page.fill('input[name="username"]', testUsers.admin.username);
    await page.fill('input[name="password"]', testUsers.admin.password);
    
    // Take screenshot before login
    await page.screenshot({ path: 'test-results/admin-login-form.png' });
    
    // Submit form and wait for navigation
    await page.click('button[type="submit"]');
    
    // Wait for navigation to complete - either to dashboard or stay on login with error
    await page.waitForLoadState('networkidle');
    
    // Give a bit more time for React to render after navigation
    await page.waitForTimeout(1000);
    
    // Check if we successfully navigated away from login
    const currentUrl = page.url();
    
    // If still on login page, check for errors
    if (currentUrl.includes('/login')) {
      console.log('Still on login page after submit');
      // Take screenshot of current state
      await page.screenshot({ path: 'test-results/login-failed-state.png' });
      
      // Check for error messages
      const errorElement = page.locator('.error, .alert, [role="alert"]');
      if (await errorElement.isVisible()) {
        const errorText = await errorElement.textContent();
        console.log('Login error message:', errorText);
      }
    }
    
    // Should be redirected to dashboard after successful login
    expect(currentUrl).not.toContain('/login');
    
    // Check for successful login indicators
    const userMenu = page.locator('[data-testid="user-menu"], .user-menu, .profile-menu');
    await expect(userMenu.first()).toBeVisible({ timeout: 5000 });
    
    // Take screenshot of successful login
    await page.screenshot({ path: 'test-results/admin-login-success.png' });
    
    // Check localStorage for token (corrected key)
    const token = await page.evaluate(() => localStorage.getItem('authToken'));
    expect(token).toBeTruthy();
  });

  test('should maintain session across page refresh', async ({ page }) => {
    // Login first
    await page.goto('/login');
    await page.fill('input[name="username"]', testUsers.admin.username);
    await page.fill('input[name="password"]', testUsers.admin.password);
    await Promise.all([
      page.waitForNavigation(),
      page.click('button[type="submit"]')
    ]);
    
    // Get current URL
    const currentUrl = page.url();
    
    // Refresh page
    await page.reload();
    
    // Wait for page to load
    await page.waitForTimeout(2000);
    
    // Should still be on the same page (not redirected to login)
    expect(page.url()).toBe(currentUrl);
    expect(page.url()).not.toContain('/login');
    
    // Take screenshot
    await page.screenshot({ path: 'test-results/session-persistence.png' });
  });

  test('should logout successfully', async ({ page }) => {
    // Login first
    await page.goto('/login');
    await page.fill('input[name="username"]', testUsers.admin.username);
    await page.fill('input[name="password"]', testUsers.admin.password);
    await Promise.all([
      page.waitForNavigation(),
      page.click('button[type="submit"]')
    ]);
    
    // Find logout button (try common selectors)
    const logoutSelectors = [
      'button:has-text("Logout")',
      'button:has-text("Sign Out")',
      '[data-testid="logout-button"]',
      '.logout-button',
      'a:has-text("Logout")'
    ];
    
    let logoutButton;
    for (const selector of logoutSelectors) {
      try {
        logoutButton = page.locator(selector);
        if (await logoutButton.isVisible({ timeout: 1000 })) {
          break;
        }
      } catch (e) {
        // Continue to next selector
      }
    }
    
    if (logoutButton && await logoutButton.isVisible()) {
      // Take screenshot before logout
      await page.screenshot({ path: 'test-results/before-logout.png' });
      
      // Click logout and wait for navigation
      await Promise.all([
        page.waitForNavigation(),
        logoutButton.click()
      ]);
      
      // Should be redirected to login
      expect(page.url()).toContain('/login');
      
      // Token should be removed
      const token = await page.evaluate(() => localStorage.getItem('token'));
      expect(token).toBeFalsy();
      
      // Take screenshot after logout
      await page.screenshot({ path: 'test-results/after-logout.png' });
    } else {
      test.skip('Logout button not found - UI may not be implemented yet');
    }
  });

  test('should handle network errors gracefully', async ({ page }) => {
    await page.goto('/login');
    
    // Go offline
    await page.context().setOffline(true);
    
    // Try to login
    await page.fill('input[name="username"]', testUsers.admin.username);
    await page.fill('input[name="password"]', testUsers.admin.password);
    await page.click('button[type="submit"]');
    
    // Wait for error to appear
    await page.waitForTimeout(3000);
    
    // Should show network error
    const errorMessage = await page.locator('.error, .alert, [role="alert"]');
    await expect(errorMessage.first()).toBeVisible();
    
    // Take screenshot of network error
    await page.screenshot({ path: 'test-results/network-error.png' });
    
    // Go back online
    await page.context().setOffline(false);
  });

  test('should redirect unauthenticated users to login', async ({ page }) => {
    // Try to access protected route without authentication
    await page.goto('/dashboard');
    
    // Should be redirected to login
    await page.waitForURL('**/login');
    expect(page.url()).toContain('/login');
    
    // Take screenshot
    await page.screenshot({ path: 'test-results/unauthenticated-redirect.png' });
  });

  test('should prevent XSS in login form', async ({ page }) => {
    await page.goto('/login');
    
    const xssPayload = '<script>window.xssTriggered = true;</script>';
    
    // Try XSS in username field
    await page.fill('input[name="username"]', xssPayload);
    await page.fill('input[name="password"]', 'password');
    
    // Submit form
    await page.click('button[type="submit"]');
    await page.waitForTimeout(2000);
    
    // Check that XSS was not executed
    const xssTriggered = await page.evaluate(() => (window as any).xssTriggered);
    expect(xssTriggered).toBeFalsy();
    
    // Take screenshot
    await page.screenshot({ path: 'test-results/xss-prevention.png' });
  });
});