/**
 * E2E Test Utilities - Main Export
 * 
 * Centralized export for all E2E test utilities to provide a clean
 * import interface for test files.
 */

export { AuthHelper, TEST_USERS, type TestUser } from './auth-helpers';
export { ScreenshotHelper, type ScreenshotOptions } from './screenshot-helper';
export { WaitHelper, type WaitOptions } from './wait-helpers';
export { 
  AdminHelper, 
  type CreateRoleData, 
  type CreateUserData 
} from './admin-helpers';

// Re-export common Playwright types for convenience
export type { Page, Locator, expect } from '@playwright/test';