// Integration test setup with screenshot capabilities
import puppeteer from 'puppeteer';
import { mkdir } from 'fs/promises';
import path from 'path';

// Screenshot configuration
export const screenshotConfig = {
  enabled: true,
  onFailureOnly: true, // Set to false to capture all steps
  outputDir: path.join(process.cwd(), 'tests/screenshots'),
  naming: (testName, step, timestamp) => {
    const sanitized = testName.replace(/[^a-zA-Z0-9]/g, '-');
    return `${sanitized}-${step}-${timestamp}.png`;
  }
};

// Test configuration
export const testConfig = {
  baseURL: process.env.TEST_BASE_URL || 'http://localhost:5173',
  apiURL: process.env.API_URL || 'http://localhost:8080',
  headless: process.env.HEADLESS !== 'false',
  slowMo: process.env.SLOW_MO ? parseInt(process.env.SLOW_MO) : 0,
  defaultTimeout: 30000,
  viewportWidth: 1280,
  viewportHeight: 720
};

// Test users
export const testUsers = {
  admin: {
    username: 'admin',
    password: 'password',
    email: 'admin@localhost',
    roles: ['admin', 'user']
  },
  regularUser: {
    username: 'testuser',
    password: 'testpass123',
    email: 'testuser@example.com',
    roles: ['user']
  },
  invalidUser: {
    username: 'invalid',
    password: 'wrongpass',
    email: 'invalid@example.com',
    roles: []
  }
};

// Browser instance manager
class BrowserManager {
  constructor() {
    this.browser = null;
    this.screenshotCount = 0;
  }

  async launch() {
    this.browser = await puppeteer.launch({
      headless: testConfig.headless,
      slowMo: testConfig.slowMo,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    
    // Ensure screenshot directory exists
    if (screenshotConfig.enabled) {
      await mkdir(screenshotConfig.outputDir, { recursive: true });
    }
    
    return this.browser;
  }

  async close() {
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
    }
  }

  async newPage() {
    if (!this.browser) {
      await this.launch();
    }
    
    const page = await this.browser.newPage();
    await page.setViewport({
      width: testConfig.viewportWidth,
      height: testConfig.viewportHeight
    });
    
    // Add screenshot helper
    page.screenshot = this.createScreenshotHelper(page);
    
    return page;
  }

  createScreenshotHelper(page) {
    return async (options = {}) => {
      if (!screenshotConfig.enabled) return;
      
      const {
        step = 'screenshot',
        testName = 'test',
        force = false
      } = options;
      
      // Skip if only capturing failures and not forced
      if (screenshotConfig.onFailureOnly && !force) return;
      
      const timestamp = Date.now();
      const filename = screenshotConfig.naming(testName, step, timestamp);
      const filepath = path.join(screenshotConfig.outputDir, filename);
      
      await page.screenshot({
        path: filepath,
        fullPage: true
      });
      
      this.screenshotCount++;
      console.log(`📸 Screenshot saved: ${filename}`);
      
      return filepath;
    };
  }
}

// Test helpers
export const testHelpers = {
  async login(page, username, password) {
    await page.goto(`${testConfig.baseURL}/login`);
    await page.screenshot({ step: 'login-page-loaded', testName: 'login' });
    
    // Fill login form
    await page.waitForSelector('input[name="username"]');
    await page.type('input[name="username"]', username);
    await page.type('input[name="password"]', password);
    
    await page.screenshot({ step: 'credentials-entered', testName: 'login' });
    
    // Submit form
    await Promise.all([
      page.waitForNavigation(),
      page.click('button[type="submit"]')
    ]);
    
    await page.screenshot({ step: 'after-submit', testName: 'login' });
  },

  async logout(page) {
    const logoutButton = await page.$('button:contains("Logout")');
    if (logoutButton) {
      await Promise.all([
        page.waitForNavigation(),
        logoutButton.click()
      ]);
    }
  },

  async checkAuthentication(page) {
    // Check if we're on a protected page
    const url = page.url();
    if (url.includes('/login')) {
      return false;
    }
    
    // Check for auth token in localStorage
    const hasToken = await page.evaluate(() => {
      return localStorage.getItem('token') !== null;
    });
    
    return hasToken;
  },

  async waitForElement(page, selector, options = {}) {
    const { timeout = 5000, visible = true } = options;
    
    try {
      await page.waitForSelector(selector, { timeout, visible });
      return true;
    } catch (error) {
      return false;
    }
  },

  async getErrorMessage(page) {
    // Look for common error message selectors
    const errorSelectors = [
      '.error-message',
      '.alert-danger',
      '[role="alert"]',
      '.notification.is-danger'
    ];
    
    for (const selector of errorSelectors) {
      const element = await page.$(selector);
      if (element) {
        const text = await page.evaluate(el => el.textContent, element);
        return text.trim();
      }
    }
    
    return null;
  },

  async fillForm(page, formData) {
    for (const [field, value] of Object.entries(formData)) {
      const selector = `input[name="${field}"], textarea[name="${field}"], select[name="${field}"]`;
      await page.waitForSelector(selector);
      
      const tagName = await page.evaluate(sel => {
        const el = document.querySelector(sel);
        return el ? el.tagName.toLowerCase() : null;
      }, selector);
      
      if (tagName === 'select') {
        await page.select(selector, value);
      } else {
        await page.click(selector, { clickCount: 3 }); // Select all
        await page.type(selector, value);
      }
    }
  }
};

// Test lifecycle helpers
export const browserManager = new BrowserManager();

export async function setupTest(testName) {
  const page = await browserManager.newPage();
  
  // Add console log listener
  page.on('console', msg => {
    if (msg.type() === 'error') {
      console.error(`Browser console error: ${msg.text()}`);
    }
  });
  
  // Add error listener
  page.on('pageerror', error => {
    console.error(`Page error: ${error.message}`);
  });
  
  return page;
}

export async function teardownTest(page, testPassed = true) {
  if (!testPassed && screenshotConfig.enabled) {
    // Take failure screenshot
    await page.screenshot({
      step: 'test-failure',
      testName: 'failure',
      force: true
    });
  }
  
  await page.close();
}

// Export everything as default for convenience
export default {
  screenshotConfig,
  testConfig,
  testUsers,
  testHelpers,
  browserManager,
  setupTest,
  teardownTest
};