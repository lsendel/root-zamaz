import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
    css: true,
    exclude: [
      '**/tests/e2e/**',
      '**/tests/integration/**',
      '**/tests/api/**',
      '**/node_modules/**'
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      exclude: [
        'node_modules/',
        'dist/',
        'tests/',
        '**/*.d.ts',
        'src/main.tsx',
        'src/vite-env.d.ts',
        'vite.config.ts',
        'vitest.config.ts',
        'playwright.config.ts'
      ],
      thresholds: {
        global: {
          branches: 80,
          functions: 80,
          lines: 80,
          statements: 80
        }
      }
    },
    // Parallel execution for faster tests
    pool: 'threads',
    poolOptions: {
      threads: {
        singleThread: false,
        minThreads: 1,
        maxThreads: 4
      }
    },
    // Test timeout
    testTimeout: 10000,
    hookTimeout: 10000,
    // Mock configuration
    clearMocks: true,
    restoreMocks: true,
    mockReset: true
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, './src')
    }
  }
})