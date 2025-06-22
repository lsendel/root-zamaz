/**
 * Test setup configuration for Jest
 */

// Extend Jest matchers
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeValidJWT(): R;
      toHaveTrustLevel(level: number): R;
      toBeBlacklisted(): R;
    }
  }
}

// Custom Jest matchers for authentication testing
expect.extend({
  toBeValidJWT(received: string) {
    const parts = received.split('.');
    const pass = parts.length === 3 && 
                 parts.every(part => part.length > 0) &&
                 received.startsWith('eyJ'); // JWT header starts with eyJ

    if (pass) {
      return {
        message: () => `expected ${received} not to be a valid JWT`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be a valid JWT`,
        pass: false,
      };
    }
  },

  toHaveTrustLevel(received: any, expectedLevel: number) {
    const pass = received && 
                 typeof received.trustLevel === 'number' && 
                 received.trustLevel === expectedLevel;

    if (pass) {
      return {
        message: () => `expected trust level not to be ${expectedLevel}`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected trust level to be ${expectedLevel}, received ${received?.trustLevel}`,
        pass: false,
      };
    }
  },

  async toBeBlacklisted(received: any) {
    let pass = false;
    let errorMessage = '';

    try {
      if (received && typeof received.isBlacklisted === 'function') {
        pass = await received.isBlacklisted();
      } else {
        errorMessage = 'Object does not have isBlacklisted method';
      }
    } catch (error) {
      errorMessage = `Error checking blacklist: ${error}`;
    }

    if (pass) {
      return {
        message: () => `expected token not to be blacklisted`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected token to be blacklisted${errorMessage ? ': ' + errorMessage : ''}`,
        pass: false,
      };
    }
  }
});

// Global test configuration
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret-key-32-characters-long-for-testing';

// Mock console methods in tests to reduce noise
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};