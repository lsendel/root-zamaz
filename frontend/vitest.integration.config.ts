import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./tests/integration/setup.js'],
    include: ['tests/integration/**/*.{test,spec}.{js,ts,tsx}'],
    testTimeout: 30000,
    hookTimeout: 30000,
    // Sequential execution for integration tests
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true
      }
    }
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, './src')
    }
  }
})