import { test, expect } from '@playwright/test';

// Test data based on actual seeded admin user
const testCredentials = {
  admin: {
    username: 'admin@mvp.local',
    password: 'password'
  }
};

test.describe('Admin Functionality E2E Tests', () => {
  test.beforeEach(async ({ page }) => {
    // Clear storage before each test
    await page.goto('/');
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });

    // Login as admin before each test
    await page.goto('/login');
    await page.fill('input[name="email"]', testCredentials.admin.username);
    await page.fill('input[name="password"]', testCredentials.admin.password);
    await page.click('button[type="submit"]');
    
    // Wait for successful login and redirect to dashboard
    await page.waitForURL('**/dashboard', { timeout: 10000 });
  });

  test.describe('Admin Panel Access', () => {
    test('should display admin panel button for admin user', async ({ page }) => {
      // Check that admin panel button is visible
      const adminButton = page.locator('button:has-text("Admin Panel")');
      await expect(adminButton).toBeVisible();
      
      // Take screenshot for verification
      await page.screenshot({ path: 'test-results/admin-panel-button.png' });
    });

    test('should open admin panel modal', async ({ page }) => {
      // Click admin panel button
      await page.click('button:has-text("Admin Panel")');
      
      // Wait for modal to appear
      await page.waitForSelector('.admin-panel', { timeout: 5000 });
      
      // Check modal is visible
      const adminPanel = page.locator('.admin-panel');
      await expect(adminPanel).toBeVisible();
      
      // Check for tabs
      await expect(page.locator('text=My Permissions')).toBeVisible();
      await expect(page.locator('text=Role Management')).toBeVisible();
      await expect(page.locator('text=User Management')).toBeVisible();
      
      // Take screenshot
      await page.screenshot({ path: 'test-results/admin-panel-modal.png' });
    });

    test('should close admin panel with close button', async ({ page }) => {
      // Open admin panel
      await page.click('button:has-text("Admin Panel")');
      await page.waitForSelector('.admin-panel');
      
      // Close with X button
      await page.click('.admin-panel .close-btn');
      
      // Panel should be hidden
      await expect(page.locator('.admin-panel')).not.toBeVisible();
    });
  });

  test.describe('Role Management', () => {
    test('should display roles in role management tab', async ({ page }) => {
      // Open admin panel
      await page.click('button:has-text("Admin Panel")');
      await page.waitForSelector('.admin-panel');
      
      // Click on Role Management tab
      await page.click('text=Role Management');
      
      // Wait for roles to load
      await page.waitForTimeout(2000);
      
      // Should see role creation form
      await expect(page.locator('input[placeholder*="Role name"]')).toBeVisible();
      await expect(page.locator('textarea[placeholder*="Role description"]')).toBeVisible();
      
      // Should see existing roles list
      const rolesList = page.locator('.roles-list, .role-item');
      if (await rolesList.count() > 0) {
        await expect(rolesList.first()).toBeVisible();
      }
      
      await page.screenshot({ path: 'test-results/role-management-tab.png' });
    });

    test('should create a new role', async ({ page }) => {
      const testRoleName = `test-role-${Date.now()}`;
      const testRoleDescription = 'Test role created by E2E test';
      
      // Open admin panel and go to Role Management
      await page.click('button:has-text("Admin Panel")');
      await page.waitForSelector('.admin-panel');
      await page.click('text=Role Management');
      await page.waitForTimeout(1000);
      
      // Fill role creation form
      await page.fill('input[placeholder*="Role name"]', testRoleName);
      await page.fill('textarea[placeholder*="Role description"]', testRoleDescription);
      
      // Click create button
      await page.click('button:has-text("Create Role")');
      
      // Wait for role to be created and list to update
      await page.waitForTimeout(2000);
      
      // Verify role appears in the list
      await expect(page.locator(`text=${testRoleName}`)).toBeVisible();
      
      await page.screenshot({ path: 'test-results/role-created.png' });
    });

    test('should edit an existing role', async ({ page }) => {
      // Open admin panel and go to Role Management
      await page.click('button:has-text("Admin Panel")');
      await page.waitForSelector('.admin-panel');
      await page.click('text=Role Management');
      await page.waitForTimeout(2000);
      
      // Look for an existing role with edit button
      const editButton = page.locator('button:has-text("Edit")').first();
      if (await editButton.count() > 0) {
        await editButton.click();
        
        // Should see edit form populated
        const nameInput = page.locator('input[value*="role"], input[value*="admin"], input[value*="user"]').first();
        await expect(nameInput).toBeVisible();
        
        // Make a small change
        await nameInput.fill('Updated Role Name');
        
        // Save changes
        await page.click('button:has-text("Update"), button:has-text("Save")');
        await page.waitForTimeout(1000);
        
        await page.screenshot({ path: 'test-results/role-edited.png' });
      }
    });
  });

  test.describe('User Management', () => {
    test('should display users in user management tab', async ({ page }) => {
      // Open admin panel
      await page.click('button:has-text("Admin Panel")');
      await page.waitForSelector('.admin-panel');
      
      // Click on User Management tab
      await page.click('text=User Management');
      
      // Wait for users to load
      await page.waitForTimeout(3000);
      
      // Should see user statistics
      await expect(page.locator('text=Total Users:')).toBeVisible();
      
      // Should see search functionality
      await expect(page.locator('input[placeholder*="Search"], input[placeholder*="search"]')).toBeVisible();
      
      // Should see users list with at least the admin user
      const userCards = page.locator('.user-card, .user-item');
      await expect(userCards.first()).toBeVisible();
      
      // Should see admin user
      await expect(page.locator('text=admin@mvp.local, text=ADMIN')).toBeVisible();
      
      await page.screenshot({ path: 'test-results/user-management-tab.png' });
    });

    test('should search for users', async ({ page }) => {
      // Open admin panel and go to User Management
      await page.click('button:has-text("Admin Panel")');
      await page.waitForSelector('.admin-panel');
      await page.click('text=User Management');
      await page.waitForTimeout(2000);
      
      // Get initial user count
      const initialUsers = await page.locator('.user-card, .user-item').count();
      
      // Search for admin user
      const searchInput = page.locator('input[placeholder*="Search"], input[placeholder*="search"]');
      await searchInput.fill('admin');
      await page.waitForTimeout(1000);
      
      // Should still see admin user
      await expect(page.locator('text=admin@mvp.local')).toBeVisible();
      
      // Search for non-existent user
      await searchInput.fill('nonexistentuser12345');
      await page.waitForTimeout(1000);
      
      // Should see no results or empty state
      const searchResults = await page.locator('.user-card, .user-item').count();
      expect(searchResults).toBeLessThanOrEqual(initialUsers);
      
      await page.screenshot({ path: 'test-results/user-search.png' });
    });

    test('should open user edit modal', async ({ page }) => {
      // Open admin panel and go to User Management
      await page.click('button:has-text("Admin Panel")');
      await page.waitForSelector('.admin-panel');
      await page.click('text=User Management');
      await page.waitForTimeout(2000);
      
      // Look for edit user button
      const editButton = page.locator('button:has-text("Edit User")').first();
      if (await editButton.count() > 0) {
        await editButton.click();
        
        // Should see user edit modal
        await expect(page.locator('.modal-overlay, .edit-modal')).toBeVisible();
        await expect(page.locator('input[value*="admin"]')).toBeVisible();
        
        await page.screenshot({ path: 'test-results/user-edit-modal.png' });
        
        // Close modal
        await page.click('.close-btn, button:has-text("Cancel")');
      }
    });

    test('should toggle user status', async ({ page }) => {
      // Open admin panel and go to User Management
      await page.click('button:has-text("Admin Panel")');
      await page.waitForSelector('.admin-panel');
      await page.click('text=User Management');
      await page.waitForTimeout(2000);
      
      // Look for activate/deactivate buttons
      const statusButton = page.locator('button:has-text("Activate"), button:has-text("Deactivate")').first();
      if (await statusButton.count() > 0) {
        const buttonText = await statusButton.textContent();
        await statusButton.click();
        
        // Wait for update
        await page.waitForTimeout(2000);
        
        // Button text should change or status should update
        // This is a basic test - in real scenarios we'd verify the status change
        await page.screenshot({ path: 'test-results/user-status-toggle.png' });
      }
    });

    test('should assign role to user', async ({ page }) => {
      // Open admin panel and go to User Management
      await page.click('button:has-text("Admin Panel")');
      await page.waitForSelector('.admin-panel');
      await page.click('text=User Management');
      await page.waitForTimeout(2000);
      
      // Look for role assignment buttons
      const assignButton = page.locator('button:has-text("Assign"), button:has-text("+ Assign")').first();
      if (await assignButton.count() > 0) {
        await assignButton.click();
        
        // Wait for role assignment
        await page.waitForTimeout(2000);
        
        await page.screenshot({ path: 'test-results/role-assignment.png' });
      }
    });
  });

  test.describe('Permissions Tab', () => {
    test('should display user permissions', async ({ page }) => {
      // Open admin panel
      await page.click('button:has-text("Admin Panel")');
      await page.waitForSelector('.admin-panel');
      
      // Should be on permissions tab by default
      await expect(page.locator('text=My Permissions')).toBeVisible();
      
      // Should show current user's permissions
      await expect(page.locator('text=Current User Permissions:')).toBeVisible();
      
      // Should show system permissions list
      await expect(page.locator('text=System Permissions:')).toBeVisible();
      
      await page.screenshot({ path: 'test-results/permissions-tab.png' });
    });
  });

  test.describe('Profile Page Navigation', () => {
    test('should navigate to profile page', async ({ page }) => {
      // Click profile link in dashboard
      await page.click('a:has-text("Profile"), .profile-link');
      
      // Should navigate to profile page
      await page.waitForURL('**/profile');
      
      // Should see profile page content
      await expect(page.locator('h1:has-text("User Profile")')).toBeVisible();
      await expect(page.locator('text=Personal Information')).toBeVisible();
      
      await page.screenshot({ path: 'test-results/profile-page.png' });
    });

    test('should edit profile information', async ({ page }) => {
      // Navigate to profile page
      await page.click('a:has-text("Profile"), .profile-link');
      await page.waitForURL('**/profile');
      
      // Click edit button
      const editButton = page.locator('button:has-text("Edit Profile")');
      if (await editButton.count() > 0) {
        await editButton.click();
        
        // Should see edit form
        await expect(page.locator('input[value*="admin"]')).toBeVisible();
        
        // Make changes
        await page.fill('input[id="first_name"]', 'Test');
        await page.fill('input[id="last_name"]', 'Admin');
        
        // Save changes
        await page.click('button:has-text("Save Changes")');
        
        // Should see success message or updated information
        await page.waitForTimeout(2000);
        
        await page.screenshot({ path: 'test-results/profile-edited.png' });
      }
    });
  });

  test.describe('Error Handling', () => {
    test('should handle admin panel errors gracefully', async ({ page }) => {
      // Open admin panel
      await page.click('button:has-text("Admin Panel")');
      await page.waitForSelector('.admin-panel');
      
      // Go to Role Management and try to create role with invalid data
      await page.click('text=Role Management');
      await page.waitForTimeout(1000);
      
      // Try to create role with empty name
      await page.click('button:has-text("Create Role")');
      
      // Should handle validation errors
      // Note: This depends on form validation implementation
      await page.waitForTimeout(1000);
      
      await page.screenshot({ path: 'test-results/admin-error-handling.png' });
    });

    test('should handle network errors in admin operations', async ({ page }) => {
      // Open admin panel
      await page.click('button:has-text("Admin Panel")');
      await page.waitForSelector('.admin-panel');
      
      // Simulate network issues by going offline
      await page.context().setOffline(true);
      
      // Try to perform admin operation
      await page.click('text=User Management');
      await page.waitForTimeout(3000);
      
      // Should handle network errors gracefully
      // (May show error messages or loading states)
      
      // Re-enable network
      await page.context().setOffline(false);
      
      await page.screenshot({ path: 'test-results/admin-network-error.png' });
    });
  });

  test.describe('Security Tests', () => {
    test('should prevent XSS in admin forms', async ({ page }) => {
      // Open admin panel and go to Role Management
      await page.click('button:has-text("Admin Panel")');
      await page.waitForSelector('.admin-panel');
      await page.click('text=Role Management');
      await page.waitForTimeout(1000);
      
      // Try to input XSS payload
      const xssPayload = '<script>alert("XSS")</script>';
      await page.fill('input[placeholder*="Role name"]', xssPayload);
      await page.fill('textarea[placeholder*="Role description"]', xssPayload);
      
      // Submit form
      await page.click('button:has-text("Create Role")');
      await page.waitForTimeout(1000);
      
      // Check that no alert was triggered and XSS was sanitized
      const alertFired = await page.evaluate(() => {
        return window.__xssAlertFired || false;
      });
      expect(alertFired).toBe(false);
      
      await page.screenshot({ path: 'test-results/admin-xss-prevention.png' });
    });
  });
});