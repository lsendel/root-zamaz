/**
 * Screenshot Helper Utilities for E2E Tests
 * 
 * Provides consistent screenshot capture for debugging and visual regression testing.
 * All screenshots are organized by test name and include timestamps.
 */

import { Page } from '@playwright/test';
import { mkdirSync } from 'fs';
import { dirname } from 'path';

export interface ScreenshotOptions {
  fullPage?: boolean;
  clip?: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
  quality?: number; // 0-100 for JPEG
  type?: 'png' | 'jpeg';
}

export class ScreenshotHelper {
  private static readonly SCREENSHOT_DIR = 'test-results/screenshots';

  /**
   * Capture a screenshot for a specific test step
   */
  static async captureStep(
    page: Page, 
    testName: string, 
    step: string, 
    options: ScreenshotOptions = {}
  ): Promise<string> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `${testName}-${step}-${timestamp}.png`;
    const filepath = `${this.SCREENSHOT_DIR}/${filename}`;
    
    // Ensure directory exists
    mkdirSync(dirname(filepath), { recursive: true });
    
    await page.screenshot({ 
      path: filepath,
      fullPage: options.fullPage ?? true,
      clip: options.clip,
      quality: options.quality,
      type: options.type ?? 'png'
    });
    
    return filepath;
  }

  /**
   * Capture screenshot on test failure
   */
  static async captureFailure(
    page: Page, 
    testName: string, 
    error: Error
  ): Promise<string> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `FAILURE-${testName}-${timestamp}.png`;
    const filepath = `${this.SCREENSHOT_DIR}/failures/${filename}`;
    
    // Ensure directory exists
    mkdirSync(dirname(filepath), { recursive: true });
    
    await page.screenshot({ 
      path: filepath,
      fullPage: true
    });
    
    console.log(`📸 Failure screenshot saved: ${filepath}`);
    console.log(`❌ Test failed with error: ${error.message}`);
    
    return filepath;
  }

  /**
   * Capture element-specific screenshot
   */
  static async captureElement(
    page: Page, 
    selector: string, 
    testName: string, 
    elementName: string
  ): Promise<string> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `${testName}-${elementName}-${timestamp}.png`;
    const filepath = `${this.SCREENSHOT_DIR}/elements/${filename}`;
    
    // Ensure directory exists
    mkdirSync(dirname(filepath), { recursive: true });
    
    const element = page.locator(selector);
    await element.screenshot({ path: filepath });
    
    return filepath;
  }

  /**
   * Capture before/after screenshots for comparison
   */
  static async captureComparison(
    page: Page, 
    testName: string, 
    actionName: string
  ): Promise<{ before: string; after: string }> {
    const before = await this.captureStep(page, testName, `${actionName}-before`);
    
    return {
      before,
      after: async () => await this.captureStep(page, testName, `${actionName}-after`)
    } as any;
  }

  /**
   * Capture screenshot with automatic element highlighting
   */
  static async captureWithHighlight(
    page: Page, 
    selector: string, 
    testName: string, 
    step: string
  ): Promise<string> {
    // Add highlight styling
    await page.locator(selector).evaluate((el) => {
      el.style.border = '3px solid red';
      el.style.backgroundColor = 'rgba(255, 0, 0, 0.1)';
    });
    
    const filepath = await this.captureStep(page, testName, step);
    
    // Remove highlight
    await page.locator(selector).evaluate((el) => {
      el.style.border = '';
      el.style.backgroundColor = '';
    });
    
    return filepath;
  }

  /**
   * Capture mobile viewport screenshot
   */
  static async captureMobile(
    page: Page, 
    testName: string, 
    step: string, 
    device: 'iPhone' | 'Android' = 'iPhone'
  ): Promise<string> {
    const viewport = device === 'iPhone' 
      ? { width: 375, height: 667 } 
      : { width: 360, height: 640 };
    
    await page.setViewportSize(viewport);
    
    const filename = `${testName}-${step}-${device.toLowerCase()}.png`;
    const filepath = `${this.SCREENSHOT_DIR}/mobile/${filename}`;
    
    // Ensure directory exists
    mkdirSync(dirname(filepath), { recursive: true });
    
    await page.screenshot({ 
      path: filepath,
      fullPage: true
    });
    
    return filepath;
  }

  /**
   * Clean up old screenshots (keep last 10 per test)
   */
  static async cleanup(testName?: string): Promise<void> {
    // Implementation would clean up old screenshots
    // This is a placeholder for the cleanup logic
    console.log(`🧹 Cleaning up screenshots${testName ? ` for ${testName}` : ''}`);
  }
}