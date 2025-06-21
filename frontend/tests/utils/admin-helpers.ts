/**
 * Admin Panel Helper Utilities for E2E Tests
 * 
 * Provides reusable admin panel operations to eliminate repetitive code
 * in admin-related tests and ensure consistent interaction patterns.
 */

import { Page, expect } from '@playwright/test';
import { AuthHelper } from './auth-helpers';
import { WaitHelper } from './wait-helpers';

export interface CreateRoleData {
  name: string;
  description: string;
  permissions?: string[];
}

export interface CreateUserData {
  email: string;
  password: string;
  firstName?: string;
  lastName?: string;
  roles?: string[];
}

export class AdminHelper {
  /**
   * Navigate to admin panel and ensure it's loaded
   */
  static async openAdminPanel(page: Page): Promise<void> {
    // Ensure user is authenticated as admin
    const isAuth = await AuthHelper.isAuthenticated(page);
    if (!isAuth) {
      await AuthHelper.loginAsAdmin(page);
    }

    // Navigate to admin panel
    await page.click('[data-testid="admin-panel-button"]');
    
    // Wait for admin panel to load
    await WaitHelper.waitForElement(page, '[data-testid="admin-panel"]');
    
    // Verify admin panel is active
    await expect(page.locator('[data-testid="admin-panel-title"]')).toBeVisible();
  }

  /**
   * Navigate to specific admin tab
   */
  static async navigateToTab(page: Page, tabName: 'users' | 'roles' | 'permissions' | 'audit'): Promise<void> {
    await this.openAdminPanel(page);
    
    // Click the specific tab
    await page.click(`[data-testid="admin-tab-${tabName}"]`);
    
    // Wait for tab content to load
    await WaitHelper.waitForElement(page, `[data-testid="admin-${tabName}-content"]`);
  }

  /**
   * Create a new role with permissions
   */
  static async createRole(page: Page, roleData: CreateRoleData): Promise<void> {
    await this.navigateToTab(page, 'roles');
    
    // Click create role button
    await page.click('[data-testid="create-role-button"]');
    
    // Wait for modal to open
    await WaitHelper.waitForModal(page, '[data-testid="create-role-modal"]');
    
    // Fill role details
    await page.fill('[data-testid="role-name-input"]', roleData.name);
    await page.fill('[data-testid="role-description-input"]', roleData.description);
    
    // Select permissions if provided
    if (roleData.permissions && roleData.permissions.length > 0) {
      for (const permission of roleData.permissions) {
        await page.check(`[data-testid="permission-${permission}"]`);
      }
    }
    
    // Submit form
    await page.click('[data-testid="create-role-submit"]');
    
    // Wait for success notification
    await WaitHelper.waitForElement(page, '[data-testid="success-notification"]');
    
    // Verify role appears in list
    await WaitHelper.waitForText(page, roleData.name);
  }

  /**
   * Create a new user
   */
  static async createUser(page: Page, userData: CreateUserData): Promise<void> {
    await this.navigateToTab(page, 'users');
    
    // Click create user button
    await page.click('[data-testid="create-user-button"]');
    
    // Wait for modal to open
    await WaitHelper.waitForModal(page, '[data-testid="create-user-modal"]');
    
    // Fill user details
    await page.fill('[data-testid="user-email-input"]', userData.email);
    await page.fill('[data-testid="user-password-input"]', userData.password);
    
    if (userData.firstName) {
      await page.fill('[data-testid="user-firstname-input"]', userData.firstName);
    }
    
    if (userData.lastName) {
      await page.fill('[data-testid="user-lastname-input"]', userData.lastName);
    }
    
    // Assign roles if provided
    if (userData.roles && userData.roles.length > 0) {
      for (const role of userData.roles) {
        await page.check(`[data-testid="role-${role}"]`);
      }
    }
    
    // Submit form
    await page.click('[data-testid="create-user-submit"]');
    
    // Wait for success notification
    await WaitHelper.waitForElement(page, '[data-testid="success-notification"]');
    
    // Verify user appears in list
    await WaitHelper.waitForText(page, userData.email);
  }

  /**
   * Edit an existing user
   */
  static async editUser(page: Page, userEmail: string, updates: Partial<CreateUserData>): Promise<void> {
    await this.navigateToTab(page, 'users');
    
    // Find and click edit button for specific user
    const userRow = page.locator(`[data-testid="user-row"][data-email="${userEmail}"]`);
    await userRow.locator('[data-testid="edit-user-button"]').click();
    
    // Wait for edit modal
    await WaitHelper.waitForModal(page, '[data-testid="edit-user-modal"]');
    
    // Update fields if provided
    if (updates.firstName) {
      await page.fill('[data-testid="user-firstname-input"]', updates.firstName);
    }
    
    if (updates.lastName) {
      await page.fill('[data-testid="user-lastname-input"]', updates.lastName);
    }
    
    // Submit changes
    await page.click('[data-testid="edit-user-submit"]');
    
    // Wait for success notification
    await WaitHelper.waitForElement(page, '[data-testid="success-notification"]');
  }

  /**
   * Delete a user
   */
  static async deleteUser(page: Page, userEmail: string): Promise<void> {
    await this.navigateToTab(page, 'users');
    
    // Find and click delete button for specific user
    const userRow = page.locator(`[data-testid="user-row"][data-email="${userEmail}"]`);
    await userRow.locator('[data-testid="delete-user-button"]').click();
    
    // Confirm deletion in modal
    await WaitHelper.waitForModal(page, '[data-testid="confirm-delete-modal"]');
    await page.click('[data-testid="confirm-delete-button"]');
    
    // Wait for success notification
    await WaitHelper.waitForElement(page, '[data-testid="success-notification"]');
    
    // Verify user is removed from list
    await expect(page.locator(`[data-testid="user-row"][data-email="${userEmail}"]`)).not.toBeVisible();
  }

  /**
   * Search for users
   */
  static async searchUsers(page: Page, searchTerm: string): Promise<void> {
    await this.navigateToTab(page, 'users');
    
    // Use search input
    await page.fill('[data-testid="user-search-input"]', searchTerm);
    await page.press('[data-testid="user-search-input"]', 'Enter');
    
    // Wait for search results to load
    await WaitHelper.waitForLoadingToComplete(page);
  }

  /**
   * Verify user has specific role
   */
  static async verifyUserRole(page: Page, userEmail: string, expectedRole: string): Promise<void> {
    await this.navigateToTab(page, 'users');
    
    const userRow = page.locator(`[data-testid="user-row"][data-email="${userEmail}"]`);
    const roleCell = userRow.locator('[data-testid="user-roles"]');
    
    await expect(roleCell).toContainText(expectedRole);
  }

  /**
   * Check audit logs for specific action
   */
  static async checkAuditLogs(page: Page, action: string, userEmail?: string): Promise<void> {
    await this.navigateToTab(page, 'audit');
    
    // Filter by action
    await page.selectOption('[data-testid="audit-action-filter"]', action);
    
    // Filter by user if provided
    if (userEmail) {
      await page.fill('[data-testid="audit-user-filter"]', userEmail);
    }
    
    // Apply filters
    await page.click('[data-testid="apply-audit-filters"]');
    
    // Wait for results
    await WaitHelper.waitForTableData(page, '[data-testid="audit-table"]');
    
    // Verify action appears in logs
    await expect(page.locator('[data-testid="audit-table"]')).toContainText(action);
  }

  /**
   * Bulk select users
   */
  static async bulkSelectUsers(page: Page, userEmails: string[]): Promise<void> {
    await this.navigateToTab(page, 'users');
    
    for (const email of userEmails) {
      const checkbox = page.locator(`[data-testid="user-row"][data-email="${email}"] [data-testid="user-checkbox"]`);
      await checkbox.check();
    }
    
    // Verify bulk actions become available
    await expect(page.locator('[data-testid="bulk-actions"]')).toBeVisible();
  }

  /**
   * Export user data
   */
  static async exportUsers(page: Page, format: 'csv' | 'json' = 'csv'): Promise<void> {
    await this.navigateToTab(page, 'users');
    
    // Click export button
    await page.click('[data-testid="export-users-button"]');
    
    // Select format
    await page.selectOption('[data-testid="export-format-select"]', format);
    
    // Start export
    await page.click('[data-testid="start-export-button"]');
    
    // Wait for export to complete
    await WaitHelper.waitForElement(page, '[data-testid="export-complete"]');
  }

  /**
   * Close admin panel and return to main dashboard
   */
  static async closeAdminPanel(page: Page): Promise<void> {
    await page.click('[data-testid="close-admin-panel"]');
    
    // Wait for navigation back to dashboard
    await WaitHelper.waitForUrlPattern(page, '**/dashboard');
    
    // Verify we're back to main dashboard
    await expect(page.locator('[data-testid="dashboard-content"]')).toBeVisible();
  }
}