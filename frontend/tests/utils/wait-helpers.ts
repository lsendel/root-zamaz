/**
 * Wait Helper Utilities for E2E Tests
 * 
 * Provides robust waiting strategies to eliminate flaky tests caused by
 * timing issues and improve test reliability.
 */

import { Page, Locator, expect } from '@playwright/test';

export interface WaitOptions {
  timeout?: number;
  pollInterval?: number;
  retries?: number;
}

export class WaitHelper {
  private static readonly DEFAULT_TIMEOUT = 10000;
  private static readonly DEFAULT_POLL_INTERVAL = 100;

  /**
   * Wait for element to be visible with enhanced error handling
   */
  static async waitForElement(
    page: Page, 
    selector: string, 
    options: WaitOptions = {}
  ): Promise<Locator> {
    const timeout = options.timeout ?? this.DEFAULT_TIMEOUT;
    
    try {
      const element = page.locator(selector);
      await expect(element).toBeVisible({ timeout });
      return element;
    } catch (error) {
      throw new Error(`Element "${selector}" not visible after ${timeout}ms: ${error.message}`);
    }
  }

  /**
   * Wait for element to disappear
   */
  static async waitForElementToDisappear(
    page: Page, 
    selector: string, 
    options: WaitOptions = {}
  ): Promise<void> {
    const timeout = options.timeout ?? this.DEFAULT_TIMEOUT;
    
    try {
      await expect(page.locator(selector)).not.toBeVisible({ timeout });
    } catch (error) {
      throw new Error(`Element "${selector}" still visible after ${timeout}ms`);
    }
  }

  /**
   * Wait for loading states to complete
   */
  static async waitForLoadingToComplete(page: Page): Promise<void> {
    const loadingSelectors = [
      '[data-testid="loading"]',
      '[data-testid="spinner"]',
      '.loading',
      '.spinner',
      '[aria-label="Loading"]'
    ];

    // Wait for any loading indicators to disappear
    for (const selector of loadingSelectors) {
      try {
        await expect(page.locator(selector)).not.toBeVisible({ timeout: 5000 });
      } catch {
        // Ignore if selector doesn't exist
      }
    }

    // Wait for network to be idle
    await page.waitForLoadState('networkidle');
  }

  /**
   * Wait for text content to appear
   */
  static async waitForText(
    page: Page, 
    text: string, 
    options: WaitOptions = {}
  ): Promise<Locator> {
    const timeout = options.timeout ?? this.DEFAULT_TIMEOUT;
    
    try {
      const element = page.locator(`text=${text}`);
      await expect(element).toBeVisible({ timeout });
      return element;
    } catch (error) {
      throw new Error(`Text "${text}" not found after ${timeout}ms`);
    }
  }

  /**
   * Wait for URL to match pattern
   */
  static async waitForUrlPattern(
    page: Page, 
    pattern: string | RegExp, 
    options: WaitOptions = {}
  ): Promise<void> {
    const timeout = options.timeout ?? this.DEFAULT_TIMEOUT;
    
    try {
      await page.waitForURL(pattern, { timeout });
    } catch (error) {
      const currentUrl = page.url();
      throw new Error(`URL did not match pattern "${pattern}" after ${timeout}ms. Current URL: ${currentUrl}`);
    }
  }

  /**
   * Wait for API response with specific status
   */
  static async waitForApiResponse(
    page: Page, 
    urlPattern: string | RegExp, 
    expectedStatus: number = 200,
    options: WaitOptions = {}
  ): Promise<void> {
    const timeout = options.timeout ?? this.DEFAULT_TIMEOUT;
    
    try {
      await page.waitForResponse((response) => {
        const matchesUrl = typeof urlPattern === 'string' 
          ? response.url().includes(urlPattern)
          : urlPattern.test(response.url());
        return matchesUrl && response.status() === expectedStatus;
      }, { timeout });
    } catch (error) {
      throw new Error(`API response matching "${urlPattern}" with status ${expectedStatus} not received after ${timeout}ms`);
    }
  }

  /**
   * Wait for element to be enabled (not disabled)
   */
  static async waitForElementEnabled(
    page: Page, 
    selector: string, 
    options: WaitOptions = {}
  ): Promise<Locator> {
    const timeout = options.timeout ?? this.DEFAULT_TIMEOUT;
    
    try {
      const element = page.locator(selector);
      await expect(element).toBeEnabled({ timeout });
      return element;
    } catch (error) {
      throw new Error(`Element "${selector}" not enabled after ${timeout}ms`);
    }
  }

  /**
   * Wait for table data to load
   */
  static async waitForTableData(
    page: Page, 
    tableSelector: string = 'table',
    minRows: number = 1,
    options: WaitOptions = {}
  ): Promise<void> {
    const timeout = options.timeout ?? this.DEFAULT_TIMEOUT;
    
    try {
      // Wait for table to be visible
      await expect(page.locator(tableSelector)).toBeVisible({ timeout });
      
      // Wait for minimum number of data rows (excluding header)
      await expect(page.locator(`${tableSelector} tbody tr`)).toHaveCount(minRows, { timeout });
    } catch (error) {
      throw new Error(`Table "${tableSelector}" did not load ${minRows} rows after ${timeout}ms`);
    }
  }

  /**
   * Wait for form validation to complete
   */
  static async waitForFormValidation(
    page: Page, 
    formSelector: string = 'form',
    options: WaitOptions = {}
  ): Promise<void> {
    const timeout = options.timeout ?? this.DEFAULT_TIMEOUT;
    
    // Wait for any validation messages to appear
    await page.waitForTimeout(500); // Small delay for validation to trigger
    
    // Wait for validation indicators to disappear
    const validationSelectors = [
      `${formSelector} [data-testid="field-validating"]`,
      `${formSelector} .validating`,
      `${formSelector} [aria-label="Validating"]`
    ];

    for (const selector of validationSelectors) {
      try {
        await expect(page.locator(selector)).not.toBeVisible({ timeout: 2000 });
      } catch {
        // Ignore if selector doesn't exist
      }
    }
  }

  /**
   * Wait with retry mechanism for flaky elements
   */
  static async waitWithRetry<T>(
    operation: () => Promise<T>,
    options: WaitOptions = {}
  ): Promise<T> {
    const retries = options.retries ?? 3;
    const pollInterval = options.pollInterval ?? this.DEFAULT_POLL_INTERVAL;
    
    let lastError: Error;
    
    for (let i = 0; i < retries; i++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error as Error;
        
        if (i < retries - 1) {
          await page.waitForTimeout(pollInterval * (i + 1)); // Exponential backoff
        }
      }
    }
    
    throw new Error(`Operation failed after ${retries} retries. Last error: ${lastError.message}`);
  }

  /**
   * Wait for modal to open and be ready for interaction
   */
  static async waitForModal(
    page: Page, 
    modalSelector: string = '[role="dialog"]',
    options: WaitOptions = {}
  ): Promise<Locator> {
    const timeout = options.timeout ?? this.DEFAULT_TIMEOUT;
    
    try {
      const modal = page.locator(modalSelector);
      
      // Wait for modal to be visible
      await expect(modal).toBeVisible({ timeout });
      
      // Wait for modal animation to complete
      await page.waitForTimeout(300);
      
      // Ensure modal is ready for interaction
      await expect(modal).toBeAttached();
      
      return modal;
    } catch (error) {
      throw new Error(`Modal "${modalSelector}" not ready after ${timeout}ms`);
    }
  }
}