/**
 * Authentication Helper Utilities for E2E Tests
 * 
 * Provides reusable authentication patterns to eliminate code duplication
 * across test files and ensure consistent test behavior.
 */

import { Page, expect } from '@playwright/test';

export interface TestUser {
  email: string;
  password: string;
  role: 'admin' | 'user' | 'guest';
}

export const TEST_USERS: Record<string, TestUser> = {
  admin: {
    email: 'admin@mvp.local',
    password: 'password',
    role: 'admin'
  },
  user: {
    email: 'user@mvp.local',
    password: 'password',
    role: 'user'
  },
  guest: {
    email: 'guest@mvp.local',
    password: 'password',
    role: 'guest'
  }
};

export class AuthHelper {
  /**
   * Login as admin user with proper waiting and error handling
   */
  static async loginAsAdmin(page: Page): Promise<void> {
    await this.login(page, TEST_USERS.admin);
  }

  /**
   * Login as regular user
   */
  static async loginAsUser(page: Page): Promise<void> {
    await this.login(page, TEST_USERS.user);
  }

  /**
   * Generic login method with customizable credentials
   */
  static async login(page: Page, user: TestUser): Promise<void> {
    // Navigate to login page
    await page.goto('/login');
    
    // Wait for login form to be ready
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    
    // Fill credentials using data-testid selectors for reliability
    await page.fill('[data-testid="email-input"]', user.email);
    await page.fill('[data-testid="password-input"]', user.password);
    
    // Submit form
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login navigation
    if (user.role === 'admin') {
      await page.waitForURL('**/dashboard');
    } else {
      await page.waitForURL('**/dashboard');
    }
    
    // Verify authentication state
    await expect(page.locator('[data-testid="user-menu"]')).toBeVisible();
  }

  /**
   * Logout from current session
   */
  static async logout(page: Page): Promise<void> {
    // Open user menu
    await page.click('[data-testid="user-menu"]');
    
    // Click logout
    await page.click('[data-testid="logout-button"]');
    
    // Wait for navigation to login page
    await page.waitForURL('**/login');
    
    // Verify logged out state
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
  }

  /**
   * Check if user is currently authenticated
   */
  static async isAuthenticated(page: Page): Promise<boolean> {
    try {
      await expect(page.locator('[data-testid="user-menu"]')).toBeVisible({ timeout: 2000 });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Ensure user is logged out before starting test
   */
  static async ensureLoggedOut(page: Page): Promise<void> {
    const isAuth = await this.isAuthenticated(page);
    if (isAuth) {
      await this.logout(page);
    }
  }

  /**
   * Clear authentication state (localStorage, sessionStorage, cookies)
   */
  static async clearAuthState(page: Page): Promise<void> {
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
    
    // Clear cookies
    await page.context().clearCookies();
  }

  /**
   * Verify user role in the UI
   */
  static async verifyUserRole(page: Page, expectedRole: string): Promise<void> {
    await page.click('[data-testid="user-menu"]');
    await expect(page.locator('[data-testid="user-role"]')).toContainText(expectedRole);
  }

  /**
   * Handle failed login attempt
   */
  static async expectLoginFailure(page: Page, email: string, password: string): Promise<void> {
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', email);
    await page.fill('[data-testid="password-input"]', password);
    await page.click('[data-testid="login-button"]');
    
    // Should show error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    
    // Should remain on login page
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
  }
}