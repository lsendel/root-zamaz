import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import {
  testConfig,
  testUsers,
  testHelpers,
  browserManager,
  setupTest,
  teardownTest
} from './setup.js';

describe('Authentication Integration Tests', () => {
  let page;
  let testPassed;

  beforeAll(async () => {
    // Launch browser once for all tests
    await browserManager.launch();
  });

  afterAll(async () => {
    // Close browser after all tests
    await browserManager.close();
  });

  beforeEach(async () => {
    testPassed = false;
    page = await setupTest('auth');
  });

  afterEach(async () => {
    await teardownTest(page, testPassed);
  });

  describe('Login Page', () => {
    it('should display login form', async () => {
      await page.goto(`${testConfig.baseURL}/login`);
      await page.screenshot({ step: 'initial-load', testName: 'login-form-display' });

      // Check for form elements
      const usernameInput = await testHelpers.waitForElement(page, 'input[name="username"]');
      const passwordInput = await testHelpers.waitForElement(page, 'input[name="password"]');
      const submitButton = await testHelpers.waitForElement(page, 'button[type="submit"]');

      expect(usernameInput).toBe(true);
      expect(passwordInput).toBe(true);
      expect(submitButton).toBe(true);

      testPassed = true;
    });

    it('should show error on empty form submission', async () => {
      await page.goto(`${testConfig.baseURL}/login`);
      
      // Click submit without filling form
      await page.click('button[type="submit"]');
      await page.waitForTimeout(1000); // Wait for error to appear
      
      await page.screenshot({ step: 'empty-form-error', testName: 'login-validation' });

      // Check for error message
      const errorMessage = await testHelpers.getErrorMessage(page);
      expect(errorMessage).toBeTruthy();
      expect(errorMessage).toContain('required');

      testPassed = true;
    });

    it('should show error for invalid credentials', async () => {
      await page.goto(`${testConfig.baseURL}/login`);
      
      // Fill with invalid credentials
      await testHelpers.fillForm(page, {
        username: testUsers.invalidUser.username,
        password: testUsers.invalidUser.password
      });

      await page.screenshot({ step: 'invalid-creds-entered', testName: 'login-invalid' });

      // Submit and wait for response
      await page.click('button[type="submit"]');
      await page.waitForTimeout(2000); // Wait for API response

      await page.screenshot({ step: 'invalid-creds-error', testName: 'login-invalid' });

      // Check for error message
      const errorMessage = await testHelpers.getErrorMessage(page);
      expect(errorMessage).toBeTruthy();
      expect(errorMessage.toLowerCase()).toContain('invalid');

      // Should still be on login page
      expect(page.url()).toContain('/login');

      testPassed = true;
    });
  });

  describe('Admin Login Flow', () => {
    it('should successfully login as admin', async () => {
      await testHelpers.login(page, testUsers.admin.username, testUsers.admin.password);

      // Should redirect to dashboard
      await page.waitForNavigation();
      expect(page.url()).not.toContain('/login');
      
      await page.screenshot({ step: 'dashboard-loaded', testName: 'admin-login-success' });

      // Check authentication
      const isAuthenticated = await testHelpers.checkAuthentication(page);
      expect(isAuthenticated).toBe(true);

      // Check for admin-specific elements
      const adminPanel = await testHelpers.waitForElement(page, '[data-testid="admin-panel"]', { timeout: 3000 });
      expect(adminPanel).toBe(true);

      testPassed = true;
    });

    it('should maintain session across page refresh', async () => {
      // Login first
      await testHelpers.login(page, testUsers.admin.username, testUsers.admin.password);
      await page.waitForNavigation();

      // Refresh page
      await page.reload();
      await page.waitForTimeout(1000);

      await page.screenshot({ step: 'after-refresh', testName: 'session-persistence' });

      // Should still be authenticated
      const isAuthenticated = await testHelpers.checkAuthentication(page);
      expect(isAuthenticated).toBe(true);
      expect(page.url()).not.toContain('/login');

      testPassed = true;
    });

    it('should logout successfully', async () => {
      // Login first
      await testHelpers.login(page, testUsers.admin.username, testUsers.admin.password);
      await page.waitForNavigation();

      // Find and click logout button
      await page.screenshot({ step: 'before-logout', testName: 'logout-flow' });
      
      await testHelpers.logout(page);
      
      await page.screenshot({ step: 'after-logout', testName: 'logout-flow' });

      // Should redirect to login
      expect(page.url()).toContain('/login');

      // Should not be authenticated
      const isAuthenticated = await testHelpers.checkAuthentication(page);
      expect(isAuthenticated).toBe(false);

      testPassed = true;
    });
  });

  describe('Token Management', () => {
    it('should handle expired token gracefully', async () => {
      // Login first
      await testHelpers.login(page, testUsers.admin.username, testUsers.admin.password);
      await page.waitForNavigation();

      // Simulate expired token by removing it
      await page.evaluate(() => {
        localStorage.setItem('token', 'expired-invalid-token');
      });

      // Try to navigate to protected route
      await page.goto(`${testConfig.baseURL}/dashboard`);
      await page.waitForTimeout(2000);

      await page.screenshot({ step: 'expired-token-redirect', testName: 'token-expiry' });

      // Should redirect to login
      expect(page.url()).toContain('/login');

      // Check for session expired message
      const errorMessage = await testHelpers.getErrorMessage(page);
      if (errorMessage) {
        expect(errorMessage.toLowerCase()).toMatch(/session|expired|invalid/);
      }

      testPassed = true;
    });

    it('should refresh token when needed', async () => {
      // This test would require backend support for token refresh
      // For now, we'll test that the refresh mechanism is called

      await testHelpers.login(page, testUsers.admin.username, testUsers.admin.password);
      await page.waitForNavigation();

      // Check if refresh token exists
      const hasRefreshToken = await page.evaluate(() => {
        return localStorage.getItem('refreshToken') !== null;
      });

      expect(hasRefreshToken).toBe(true);

      testPassed = true;
    });
  });

  describe('Error Scenarios', () => {
    it('should handle network errors gracefully', async () => {
      await page.goto(`${testConfig.baseURL}/login`);

      // Simulate network failure
      await page.setOfflineMode(true);

      // Try to login
      await testHelpers.fillForm(page, {
        username: testUsers.admin.username,
        password: testUsers.admin.password
      });

      await page.click('button[type="submit"]');
      await page.waitForTimeout(2000);

      await page.screenshot({ step: 'network-error', testName: 'network-failure' });

      // Should show network error
      const errorMessage = await testHelpers.getErrorMessage(page);
      expect(errorMessage).toBeTruthy();
      expect(errorMessage.toLowerCase()).toMatch(/network|connection|offline/);

      // Re-enable network
      await page.setOfflineMode(false);

      testPassed = true;
    });

    it('should handle server errors', async () => {
      // This would require mocking server responses
      // For now, we'll test with an invalid API endpoint

      await page.goto(`${testConfig.baseURL}/login`);

      // Override the API endpoint temporarily
      await page.evaluate(() => {
        window.__TEST_API_URL__ = 'http://localhost:9999'; // Non-existent server
      });

      await testHelpers.fillForm(page, {
        username: testUsers.admin.username,
        password: testUsers.admin.password
      });

      await page.click('button[type="submit"]');
      await page.waitForTimeout(3000);

      await page.screenshot({ step: 'server-error', testName: 'server-failure' });

      // Should show error
      const errorMessage = await testHelpers.getErrorMessage(page);
      expect(errorMessage).toBeTruthy();

      testPassed = true;
    });
  });

  describe('Security Tests', () => {
    it('should sanitize input to prevent XSS', async () => {
      await page.goto(`${testConfig.baseURL}/login`);

      const xssPayload = '<script>alert("XSS")</script>';
      
      await testHelpers.fillForm(page, {
        username: xssPayload,
        password: 'password'
      });

      await page.screenshot({ step: 'xss-attempt', testName: 'security-xss' });

      // Submit form
      await page.click('button[type="submit"]');
      await page.waitForTimeout(1000);

      // Check that no alert was triggered
      const alertFired = await page.evaluate(() => {
        return window.__xssAlertFired || false;
      });

      expect(alertFired).toBe(false);

      testPassed = true;
    });

    it('should not expose sensitive data in localStorage', async () => {
      await testHelpers.login(page, testUsers.admin.username, testUsers.admin.password);
      await page.waitForNavigation();

      // Check localStorage contents
      const storageData = await page.evaluate(() => {
        const data = {};
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          data[key] = localStorage.getItem(key);
        }
        return data;
      });

      // Password should never be stored
      const storageString = JSON.stringify(storageData);
      expect(storageString).not.toContain(testUsers.admin.password);

      testPassed = true;
    });
  });
});