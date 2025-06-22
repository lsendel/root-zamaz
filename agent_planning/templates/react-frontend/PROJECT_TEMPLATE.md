# React TypeScript Frontend Template - Zero Trust Security

> **Template**: Production-ready React TypeScript frontend with Zero Trust integration  
> **Based On**: Zero Trust Authentication MVP frontend patterns  
> **Version**: 1.0  
> **Last Updated**: 2025-06-21

## 🎯 **Template Overview**

This template provides a complete React TypeScript frontend foundation implementing Zero Trust security principles, modern development practices, and production-ready performance optimizations.

### **Key Features**
- **Zero Trust Security**: JWT authentication, protected routes, XSS prevention
- **Modern React Patterns**: Hooks, context, compound components
- **Type Safety**: TypeScript strict mode with comprehensive typing
- **State Management**: Zustand for global state, React Query for server state
- **Performance Optimized**: Code splitting, memoization, bundle optimization
- **Testing Ready**: Vitest, Testing Library, Playwright E2E tests

## 📁 **Directory Structure**

```
{frontend-name}/
├── public/
│   ├── index.html                     # HTML template
│   ├── favicon.ico
│   └── manifest.json
├── src/
│   ├── components/                    # Reusable UI components
│   │   ├── ui/                       # Base UI components
│   │   ├── forms/                    # Form components
│   │   ├── navigation/               # Navigation components
│   │   └── layout/                   # Layout components
│   ├── pages/                        # Route-level page components
│   │   ├── auth/                     # Authentication pages
│   │   ├── dashboard/                # Dashboard pages
│   │   └── profile/                  # User profile pages
│   ├── hooks/                        # Custom React hooks
│   │   ├── auth/                     # Authentication hooks
│   │   ├── api/                      # API hooks
│   │   └── ui/                       # UI utility hooks
│   ├── stores/                       # Zustand state stores
│   │   ├── auth.ts                   # Authentication store
│   │   ├── ui.ts                     # UI state store
│   │   └── user.ts                   # User data store
│   ├── services/                     # API service layer
│   │   ├── api/                      # API client configuration
│   │   ├── auth/                     # Authentication services
│   │   └── storage/                  # Storage services
│   ├── types/                        # TypeScript type definitions
│   │   ├── auth.ts                   # Authentication types
│   │   ├── api.ts                    # API response types
│   │   └── common.ts                 # Common types
│   ├── utils/                        # Utility functions
│   │   ├── validation.ts             # Form validation
│   │   ├── formatting.ts             # Data formatting
│   │   └── security.ts               # Security utilities
│   ├── styles/                       # Global styles and themes
│   │   ├── globals.css
│   │   ├── variables.css
│   │   └── components.css
│   ├── App.tsx                       # Main application component
│   ├── main.tsx                      # Application entry point
│   └── router.tsx                    # Routing configuration
├── tests/                            # Test utilities and setup
│   ├── __mocks__/                    # Test mocks
│   ├── fixtures/                     # Test data fixtures
│   ├── setup.ts                      # Test setup configuration
│   └── utils.tsx                     # Test utilities
├── e2e/                              # Playwright E2E tests
│   ├── auth.spec.ts                  # Authentication tests
│   ├── dashboard.spec.ts             # Dashboard tests
│   └── utils.ts                      # E2E test utilities
├── .env.template                     # Environment variables template
├── .gitignore                        # Git ignore patterns
├── .eslintrc.json                    # ESLint configuration
├── biome.json                        # Biome configuration
├── index.html                        # Vite HTML template
├── package.json                      # Dependencies and scripts
├── playwright.config.ts              # Playwright configuration
├── tsconfig.json                     # TypeScript configuration
├── tsconfig.node.json                # Node TypeScript configuration
├── vite.config.ts                    # Vite configuration
├── vitest.config.ts                  # Vitest configuration
└── README.md                         # Project documentation
```

## 🛠️ **Template Files**

### **Main Application (src/App.tsx)**
```typescript
import React from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'
import { BrowserRouter } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'

import { AppRouter } from './router'
import { AuthProvider } from './components/auth/AuthProvider'
import { ErrorBoundary } from './components/ui/ErrorBoundary'
import { LoadingProvider } from './components/ui/LoadingProvider'

import './styles/globals.css'

// React Query client configuration
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
      retry: (failureCount, error: any) => {
        // Don't retry on 401/403 errors
        if (error?.status === 401 || error?.status === 403) {
          return false
        }
        return failureCount < 3
      },
      refetchOnWindowFocus: false,
    },
    mutations: {
      retry: false,
    },
  },
})

function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AuthProvider>
            <LoadingProvider>
              <AppRouter />
              <Toaster
                position="top-right"
                toastOptions={{
                  duration: 4000,
                  style: {
                    background: '#363636',
                    color: '#fff',
                  },
                }}
              />
            </LoadingProvider>
          </AuthProvider>
        </BrowserRouter>
        {import.meta.env.DEV && <ReactQueryDevtools />}
      </QueryClientProvider>
    </ErrorBoundary>
  )
}

export default App
```

### **Authentication Store (src/stores/auth.ts)**
```typescript
import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'

import { User, LoginCredentials, AuthTokens } from '../types/auth'
import { authService } from '../services/auth/authService'
import { tokenService } from '../services/auth/tokenService'

interface AuthState {
  user: User | null
  tokens: AuthTokens | null
  isAuthenticated: boolean
  isLoading: boolean
  error: string | null
}

interface AuthActions {
  login: (credentials: LoginCredentials) => Promise<void>
  logout: () => void
  refreshToken: () => Promise<void>
  updateProfile: (profile: Partial<User>) => void
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void
  clearError: () => void
}

type AuthStore = AuthState & AuthActions

export const useAuthStore = create<AuthStore>()(
  persist(
    (set, get) => ({
      // State
      user: null,
      tokens: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,

      // Actions
      login: async (credentials: LoginCredentials) => {
        set({ isLoading: true, error: null })
        
        try {
          const response = await authService.login(credentials)
          const { user, token, refreshToken } = response

          // Store tokens securely
          tokenService.setTokens(token, refreshToken)

          set({
            user,
            tokens: { accessToken: token, refreshToken },
            isAuthenticated: true,
            isLoading: false,
            error: null,
          })
        } catch (error: any) {
          const errorMessage = error.response?.data?.message || 'Login failed'
          set({
            isLoading: false,
            error: errorMessage,
          })
          throw error
        }
      },

      logout: () => {
        // Clear tokens from storage
        tokenService.clearTokens()
        
        // Reset state
        set({
          user: null,
          tokens: null,
          isAuthenticated: false,
          error: null,
        })
      },

      refreshToken: async () => {
        try {
          const refreshToken = tokenService.getRefreshToken()
          if (!refreshToken) {
            throw new Error('No refresh token available')
          }

          const response = await authService.refreshToken(refreshToken)
          const { token: newToken, refreshToken: newRefreshToken } = response

          // Update tokens
          tokenService.setTokens(newToken, newRefreshToken)

          set({
            tokens: { 
              accessToken: newToken, 
              refreshToken: newRefreshToken 
            },
          })
        } catch (error) {
          // Refresh failed, force logout
          get().logout()
          throw error
        }
      },

      updateProfile: (profile: Partial<User>) => {
        set((state) => ({
          user: state.user ? { ...state.user, ...profile } : null,
        }))
      },

      setLoading: (isLoading: boolean) => set({ isLoading }),
      setError: (error: string | null) => set({ error }),
      clearError: () => set({ error: null }),
    }),
    {
      name: 'auth-storage',
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        user: state.user,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
)
```

### **Protected Route Component (src/components/auth/ProtectedRoute.tsx)**
```typescript
import React from 'react'
import { Navigate, useLocation } from 'react-router-dom'

import { useAuthStore } from '../../stores/auth'
import { LoadingSpinner } from '../ui/LoadingSpinner'

interface ProtectedRouteProps {
  children: React.ReactNode
  requiredRoles?: string[]
  fallback?: React.ReactNode
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  requiredRoles = [],
  fallback,
}) => {
  const { isAuthenticated, user, isLoading } = useAuthStore()
  const location = useLocation()

  // Show loading spinner while authentication is being checked
  if (isLoading) {
    return <LoadingSpinner />
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated || !user) {
    return fallback || (
      <Navigate 
        to="/login" 
        state={{ from: location.pathname }} 
        replace 
      />
    )
  }

  // Check role-based access if required roles are specified
  if (requiredRoles.length > 0) {
    const hasRequiredRole = requiredRoles.some(role =>
      user.roles.includes(role)
    )

    if (!hasRequiredRole) {
      return fallback || <Navigate to="/unauthorized" replace />
    }
  }

  return <>{children}</>
}
```

### **API Client (src/services/api/apiClient.ts)**
```typescript
import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios'

import { tokenService } from '../auth/tokenService'
import { useAuthStore } from '../../stores/auth'

class ApiClient {
  private client: AxiosInstance
  private baseURL: string

  constructor(baseURL: string) {
    this.baseURL = baseURL
    this.client = axios.create({
      baseURL,
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      },
    })

    this.setupInterceptors()
  }

  private setupInterceptors() {
    // Request interceptor to add auth token
    this.client.interceptors.request.use(
      (config) => {
        const token = tokenService.getAccessToken()
        if (token) {
          config.headers.Authorization = `Bearer ${token}`
        }

        // Add request ID for tracing
        config.headers['X-Request-ID'] = crypto.randomUUID()
        
        return config
      },
      (error) => Promise.reject(error)
    )

    // Response interceptor to handle auth errors
    this.client.interceptors.response.use(
      (response) => response,
      async (error) => {
        const originalRequest = error.config

        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true

          try {
            // Attempt token refresh
            await useAuthStore.getState().refreshToken()
            
            // Retry original request with new token
            const newToken = tokenService.getAccessToken()
            if (newToken) {
              originalRequest.headers.Authorization = `Bearer ${newToken}`
            }
            
            return this.client(originalRequest)
          } catch (refreshError) {
            // Refresh failed, force logout
            useAuthStore.getState().logout()
            window.location.href = '/login'
          }
        }

        return Promise.reject(error)
      }
    )
  }

  async get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response: AxiosResponse<T> = await this.client.get(url, config)
    return response.data
  }

  async post<T>(
    url: string,
    data?: any,
    config?: AxiosRequestConfig
  ): Promise<T> {
    const response: AxiosResponse<T> = await this.client.post(url, data, config)
    return response.data
  }

  async put<T>(
    url: string,
    data?: any,
    config?: AxiosRequestConfig
  ): Promise<T> {
    const response: AxiosResponse<T> = await this.client.put(url, data, config)
    return response.data
  }

  async delete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response: AxiosResponse<T> = await this.client.delete(url, config)
    return response.data
  }
}

export const apiClient = new ApiClient(
  import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080/api/v1'
)
```

### **Package.json Template**
```json
{
  "name": "{frontend-name}",
  "version": "1.0.0",
  "type": "module",
  "description": "React TypeScript frontend with Zero Trust security",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "test": "vitest",
    "test:ui": "vitest --ui",
    "test:coverage": "vitest --coverage",
    "test:e2e": "playwright test",
    "test:e2e:ui": "playwright test --ui",
    "lint": "biome check .",
    "lint:fix": "biome check --apply .",
    "format": "biome format --write .",
    "type-check": "tsc --noEmit",
    "analyze": "npx vite-bundle-analyzer"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.8.0",
    "zustand": "^4.4.0",
    "@tanstack/react-query": "^4.29.0",
    "axios": "^1.4.0",
    "react-hook-form": "^7.45.0",
    "zod": "^3.21.0",
    "@hookform/resolvers": "^3.1.0",
    "react-hot-toast": "^2.4.0",
    "clsx": "^1.2.0",
    "date-fns": "^2.30.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.0",
    "@types/react-dom": "^18.2.0",
    "@biomejs/biome": "^1.5.0",
    "@vitejs/plugin-react": "^4.0.0",
    "vite": "^4.4.0",
    "typescript": "^5.0.0",
    "vitest": "^0.34.0",
    "@vitest/ui": "^0.34.0",
    "@testing-library/react": "^14.0.0",
    "@testing-library/jest-dom": "^5.16.0",
    "@testing-library/user-event": "^14.4.0",
    "@playwright/test": "^1.37.0",
    "vite-bundle-analyzer": "^0.7.0",
    "jsdom": "^22.1.0"
  },
  "engines": {
    "node": ">=18.0.0",
    "npm": ">=9.0.0"
  }
}
```

### **Vite Configuration (vite.config.ts)**
```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
      '@components': resolve(__dirname, './src/components'),
      '@pages': resolve(__dirname, './src/pages'),
      '@hooks': resolve(__dirname, './src/hooks'),
      '@services': resolve(__dirname, './src/services'),
      '@stores': resolve(__dirname, './src/stores'),
      '@types': resolve(__dirname, './src/types'),
      '@utils': resolve(__dirname, './src/utils'),
    },
  },
  server: {
    port: 3000,
    host: true,
    cors: true,
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          query: ['@tanstack/react-query'],
          forms: ['react-hook-form', 'zod'],
        },
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./tests/setup.ts'],
  },
})
```

### **Environment Template (.env.template)**
```bash
# {FRONTEND_NAME} Environment Configuration

# Application Configuration
VITE_APP_NAME={frontend-name}
VITE_APP_VERSION=1.0.0
VITE_ENVIRONMENT=development

# API Configuration
VITE_API_BASE_URL=http://localhost:8080/api/v1
VITE_API_TIMEOUT=10000

# Authentication Configuration
VITE_JWT_STORAGE_KEY=auth-token
VITE_REFRESH_TOKEN_KEY=refresh-token
VITE_TOKEN_REFRESH_THRESHOLD=300000

# Security Configuration
VITE_ENABLE_CSP=true
VITE_ENABLE_CSRF_PROTECTION=true
VITE_SECURE_COOKIES=false

# Feature Flags
VITE_ENABLE_ANALYTICS=false
VITE_ENABLE_ERROR_REPORTING=false
VITE_ENABLE_DEBUG_MODE=true

# UI Configuration
VITE_DEFAULT_THEME=light
VITE_ENABLE_DARK_MODE=true
VITE_ANIMATION_DURATION=200

# Development Configuration
VITE_HOT_RELOAD=true
VITE_ENABLE_DEVTOOLS=true
VITE_SOURCE_MAPS=true

# External Services
VITE_SENTRY_DSN=
VITE_ANALYTICS_ID=
VITE_INTERCOM_APP_ID=
```

### **Makefile Template**
```makefile
# React TypeScript Frontend Makefile
.PHONY: help dev build test lint clean install

# Configuration
PROJECT_NAME := {frontend-name}
NODE_VERSION := $(shell node --version)
NPM_VERSION := $(shell npm --version)

help: ## 📖 Show this help message
	@echo "🚀 $(PROJECT_NAME) - React TypeScript Frontend"
	@echo "=============================================="
	@echo "📋 DEVELOPMENT:"
	@echo "  make dev          ⚡ Start development server"
	@echo "  make build        🔨 Build for production"
	@echo "  make preview      👀 Preview production build"
	@echo "  make test         🧪 Run all tests"
	@echo "  make test-e2e     🎭 Run E2E tests"
	@echo ""
	@echo "🔍 QUALITY:"
	@echo "  make lint         🔍 Run linting"
	@echo "  make format       ✨ Format code"
	@echo "  make type-check   📊 Check TypeScript types"
	@echo ""
	@echo "🧹 UTILITIES:"
	@echo "  make clean        🧹 Clean build artifacts"
	@echo "  make install      📥 Install dependencies"

## Development Commands

dev: ## ⚡ Start development server
	@echo "⚡ Starting development server..."
	npm run dev

build: ## 🔨 Build for production
	@echo "🔨 Building for production..."
	npm run build

preview: ## 👀 Preview production build
	@echo "👀 Previewing production build..."
	npm run preview

## Testing Commands

test: ## 🧪 Run all tests
	@echo "🧪 Running unit tests..."
	npm run test

test-ui: ## 🧪 Run tests with UI
	@echo "🧪 Running tests with UI..."
	npm run test:ui

test-coverage: ## 📊 Run tests with coverage
	@echo "📊 Running tests with coverage..."
	npm run test:coverage

test-e2e: ## 🎭 Run E2E tests
	@echo "🎭 Running E2E tests..."
	npm run test:e2e

test-e2e-ui: ## 🎭 Run E2E tests with UI
	@echo "🎭 Running E2E tests with UI..."
	npm run test:e2e:ui

## Quality Commands

lint: ## 🔍 Run linting
	@echo "🔍 Running linting..."
	npm run lint

lint-fix: ## 🔧 Fix linting issues
	@echo "🔧 Fixing linting issues..."
	npm run lint:fix

format: ## ✨ Format code
	@echo "✨ Formatting code..."
	npm run format

type-check: ## 📊 Check TypeScript types
	@echo "📊 Checking TypeScript types..."
	npm run type-check

## Utility Commands

install: ## 📥 Install dependencies
	@echo "📥 Installing dependencies..."
	npm install

clean: ## 🧹 Clean build artifacts
	@echo "🧹 Cleaning build artifacts..."
	rm -rf dist/
	rm -rf node_modules/.vite/
	rm -rf coverage/
	npm cache clean --force

## Analysis Commands

analyze: ## 📊 Analyze bundle size
	@echo "📊 Analyzing bundle size..."
	npm run analyze

## Environment Commands

env-setup: ## 🔧 Setup environment file
	@echo "🔧 Setting up environment..."
	@if [ ! -f .env ]; then \
		cp .env.template .env; \
		echo "✅ Created .env file from template"; \
		echo "📝 Please edit .env with your configuration"; \
	else \
		echo "⚠️  .env file already exists"; \
	fi

env-check: ## ✅ Validate environment configuration
	@echo "✅ Checking environment configuration..."
	@node -e "console.log('Node.js:', process.version)"
	@npm --version | head -1 | awk '{print "npm:", $$1}'
	@echo "Project: $(PROJECT_NAME)"

## Deployment Commands

deploy-preview: ## 🚀 Deploy preview build
	@echo "🚀 Deploying preview..."
	npm run build
	# Add your deployment commands here

status: ## 📊 Check development server status
	@echo "📊 Development Server Status:"
	@curl -s http://localhost:3000 > /dev/null && echo "✅ Server is running" || echo "❌ Server is not running"
```

## 📋 **Setup Instructions**

### **1. Initialize New Frontend**
```bash
# Create new frontend from template
mkdir my-new-frontend
cd my-new-frontend

# Copy template files
npm init vite@latest . -- --template react-ts

# Install dependencies
npm install

# Set up environment
make env-setup
# Edit .env with your configuration
```

### **2. Development Workflow**
```bash
# Start development server
make dev

# Run tests in watch mode
make test

# Run linting and formatting
make lint format

# Type checking
make type-check
```

### **3. Customize for Your Use Case**
1. Replace `{frontend-name}` placeholders
2. Update package.json with your project details
3. Configure API endpoints in environment variables
4. Implement your pages and components
5. Set up authentication flows
6. Configure routing and navigation

## 🔒 **Security Features Included**

- **XSS Prevention** with proper input sanitization
- **CSRF Protection** with token validation
- **Secure Token Storage** with automatic refresh
- **Protected Routes** with role-based access
- **Input Validation** with Zod schemas
- **Error Boundary** for graceful error handling
- **Security Headers** configuration
- **Content Security Policy** setup

## 🚀 **Performance Optimizations**

- **Code Splitting** with dynamic imports
- **Bundle Analysis** tools included
- **Tree Shaking** for optimal bundle size
- **Lazy Loading** for routes and components
- **Memoization** patterns for expensive operations
- **Image Optimization** strategies
- **Caching Strategies** for API calls

This template provides a solid foundation for building secure, performant React TypeScript applications following the patterns established in the Zero Trust Authentication MVP.