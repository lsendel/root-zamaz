# Claude Notes: React Frontend Architecture

> **Context**: React TypeScript frontend with Zero Trust security  
> **Last Updated**: 2025-06-20  
> **Focus**: Modern React patterns with comprehensive security integration

## ⚛️ **Technology Stack Overview**

### **Core Technologies**
- **Framework**: React 18 with TypeScript for type safety
- **Build Tool**: Vite for fast development and optimized builds
- **State Management**: Zustand for lightweight, type-safe state
- **Data Fetching**: React Query (TanStack Query) for server state
- **Routing**: React Router with protected route patterns
- **Testing**: Playwright E2E + Vitest unit tests + Testing Library

### **Development Tools**
- **Linting**: ESLint with strict TypeScript rules
- **Formatting**: Prettier with consistent code style
- **Type Checking**: TypeScript strict mode enabled
- **Dev Server**: Vite dev server with HMR

## 🏗️ **Project Structure**

### **Directory Organization**
```
frontend/
├── src/
│   ├── components/     # Reusable UI components
│   ├── pages/         # Route-level page components  
│   ├── hooks/         # Custom React hooks
│   ├── stores/        # Zustand state stores
│   ├── services/      # API service layer
│   ├── types/         # TypeScript type definitions
│   ├── utils/         # Utility functions
│   └── styles/        # Global styles and themes
├── public/            # Static assets
├── tests/             # Test utilities and setup
└── e2e/              # Playwright E2E tests
```

### **Key Configuration Files**
- `vite.config.ts` - Build configuration and development server
- `tsconfig.json` - TypeScript compiler configuration
- `playwright.config.ts` - E2E testing configuration
- `vitest.config.ts` - Unit testing configuration

## 🔐 **Security Architecture**

### **Authentication Integration**
```typescript
// Auth Store with Zustand
interface AuthStore {
  user: User | null
  token: string | null
  isAuthenticated: boolean
  isLoading: boolean
  
  // Actions
  login: (credentials: LoginCredentials) => Promise<void>
  logout: () => void
  refreshToken: () => Promise<void>
  updateProfile: (profile: UserProfile) => Promise<void>
}

// JWT Token Management
class TokenService {
  private static TOKEN_KEY = 'auth_token'
  private static REFRESH_KEY = 'refresh_token'
  
  static setTokens(accessToken: string, refreshToken: string): void {
    localStorage.setItem(this.TOKEN_KEY, accessToken)
    localStorage.setItem(this.REFRESH_KEY, refreshToken)
  }
  
  static getAccessToken(): string | null {
    return localStorage.getItem(this.TOKEN_KEY)
  }
  
  static clearTokens(): void {
    localStorage.removeItem(this.TOKEN_KEY)
    localStorage.removeItem(this.REFRESH_KEY)
  }
  
  static isTokenExpired(token: string): boolean {
    // JWT expiration check logic
  }
}
```

### **Protected Routes Pattern**
```typescript
// Protected Route Component
interface ProtectedRouteProps {
  children: React.ReactNode
  requiredRole?: string[]
  fallback?: React.ReactNode
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  requiredRole,
  fallback = <Navigate to="/login" />
}) => {
  const { isAuthenticated, user, isLoading } = useAuthStore()
  
  if (isLoading) {
    return <LoadingSpinner />
  }
  
  if (!isAuthenticated) {
    return fallback
  }
  
  if (requiredRole && !hasRequiredRole(user, requiredRole)) {
    return <Navigate to="/unauthorized" />
  }
  
  return <>{children}</>
}

// Route Configuration
const AppRoutes = () => (
  <Routes>
    <Route path="/login" element={<LoginPage />} />
    <Route path="/register" element={<RegisterPage />} />
    
    <Route path="/dashboard" element={
      <ProtectedRoute>
        <DashboardPage />
      </ProtectedRoute>
    } />
    
    <Route path="/admin" element={
      <ProtectedRoute requiredRole={['admin']}>
        <AdminPanel />
      </ProtectedRoute>
    } />
  </Routes>
)
```

### **API Security Integration**
```typescript
// API Client with Authentication
class ApiClient {
  private baseURL: string
  private tokenService: TokenService
  
  constructor(baseURL: string) {
    this.baseURL = baseURL
    this.tokenService = new TokenService()
  }
  
  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const token = this.tokenService.getAccessToken()
    
    const config: RequestInit = {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options.headers,
      },
    }
    
    const response = await fetch(`${this.baseURL}${endpoint}`, config)
    
    if (response.status === 401) {
      // Handle token refresh or logout
      await this.handleUnauthorized()
      throw new Error('Unauthorized')
    }
    
    if (!response.ok) {
      throw new Error(`API Error: ${response.statusText}`)
    }
    
    return response.json()
  }
  
  private async handleUnauthorized(): Promise<void> {
    // Attempt token refresh or force logout
    try {
      await this.refreshToken()
    } catch {
      this.tokenService.clearTokens()
      window.location.href = '/login'
    }
  }
}
```

## 🎨 **Component Architecture**

### **Component Design Patterns**
```typescript
// Compound Component Pattern
interface TabsProps {
  children: React.ReactNode
  defaultValue?: string
  onValueChange?: (value: string) => void
}

interface TabsComposition {
  List: React.FC<TabsListProps>
  Trigger: React.FC<TabsTriggerProps>
  Content: React.FC<TabsContentProps>
}

const Tabs: React.FC<TabsProps> & TabsComposition = ({
  children,
  defaultValue,
  onValueChange
}) => {
  const [activeTab, setActiveTab] = useState(defaultValue)
  
  const contextValue = {
    activeTab,
    setActiveTab: (value: string) => {
      setActiveTab(value)
      onValueChange?.(value)
    }
  }
  
  return (
    <TabsContext.Provider value={contextValue}>
      <div className="tabs">{children}</div>
    </TabsContext.Provider>
  )
}

// Usage
<Tabs defaultValue="profile">
  <Tabs.List>
    <Tabs.Trigger value="profile">Profile</Tabs.Trigger>
    <Tabs.Trigger value="security">Security</Tabs.Trigger>
  </Tabs.List>
  <Tabs.Content value="profile">
    <ProfileForm />
  </Tabs.Content>
  <Tabs.Content value="security">
    <SecuritySettings />
  </Tabs.Content>
</Tabs>
```

### **Custom Hooks Patterns**
```typescript
// Data Fetching Hook with React Query
function useUserProfile(userId: string) {
  return useQuery({
    queryKey: ['user', userId],
    queryFn: () => apiClient.get<User>(`/users/${userId}`),
    staleTime: 5 * 60 * 1000, // 5 minutes
    cacheTime: 10 * 60 * 1000, // 10 minutes
    retry: (failureCount, error) => {
      // Don't retry on 401/403 errors
      if (error.status === 401 || error.status === 403) {
        return false
      }
      return failureCount < 3
    }
  })
}

// Form Management Hook
function useFormValidation<T>(
  initialValues: T,
  validationSchema: ValidationSchema<T>
) {
  const [values, setValues] = useState<T>(initialValues)
  const [errors, setErrors] = useState<Partial<Record<keyof T, string>>>({})
  const [touched, setTouched] = useState<Partial<Record<keyof T, boolean>>>({})
  
  const validate = useCallback((fieldValues: T) => {
    const result = validationSchema.safeParse(fieldValues)
    if (!result.success) {
      const fieldErrors: Partial<Record<keyof T, string>> = {}
      result.error.issues.forEach(issue => {
        const field = issue.path[0] as keyof T
        fieldErrors[field] = issue.message
      })
      setErrors(fieldErrors)
      return false
    }
    setErrors({})
    return true
  }, [validationSchema])
  
  return {
    values,
    errors,
    touched,
    setFieldValue: (field: keyof T, value: any) => {
      setValues(prev => ({ ...prev, [field]: value }))
      setTouched(prev => ({ ...prev, [field]: true }))
    },
    validate,
    isValid: Object.keys(errors).length === 0
  }
}
```

## 📊 **State Management Architecture**

### **Zustand Store Patterns**
```typescript
// Auth Store
interface AuthState {
  user: User | null
  token: string | null
  isAuthenticated: boolean
  isLoading: boolean
}

interface AuthActions {
  login: (credentials: LoginCredentials) => Promise<void>
  logout: () => void
  setUser: (user: User) => void
  setLoading: (loading: boolean) => void
}

type AuthStore = AuthState & AuthActions

const useAuthStore = create<AuthStore>((set, get) => ({
  // State
  user: null,
  token: null,
  isAuthenticated: false,
  isLoading: false,
  
  // Actions
  login: async (credentials) => {
    set({ isLoading: true })
    try {
      const response = await apiClient.post('/auth/login', credentials)
      const { user, token, refreshToken } = response
      
      TokenService.setTokens(token, refreshToken)
      set({ 
        user, 
        token, 
        isAuthenticated: true, 
        isLoading: false 
      })
    } catch (error) {
      set({ isLoading: false })
      throw error
    }
  },
  
  logout: () => {
    TokenService.clearTokens()
    set({ 
      user: null, 
      token: null, 
      isAuthenticated: false 
    })
  },
  
  setUser: (user) => set({ user }),
  setLoading: (isLoading) => set({ isLoading })
}))

// UI Store for global UI state
interface UIStore {
  theme: 'light' | 'dark'
  sidebarOpen: boolean
  notifications: Notification[]
  
  toggleTheme: () => void
  toggleSidebar: () => void
  addNotification: (notification: Omit<Notification, 'id'>) => void
  removeNotification: (id: string) => void
}

const useUIStore = create<UIStore>((set) => ({
  theme: 'light',
  sidebarOpen: true,
  notifications: [],
  
  toggleTheme: () => set((state) => ({ 
    theme: state.theme === 'light' ? 'dark' : 'light' 
  })),
  toggleSidebar: () => set((state) => ({ 
    sidebarOpen: !state.sidebarOpen 
  })),
  addNotification: (notification) => set((state) => ({
    notifications: [...state.notifications, {
      ...notification,
      id: crypto.randomUUID()
    }]
  })),
  removeNotification: (id) => set((state) => ({
    notifications: state.notifications.filter(n => n.id !== id)
  }))
}))
```

## 🧪 **Testing Strategy**

### **Unit Testing with Vitest**
```typescript
// Component Testing
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { LoginForm } from './LoginForm'

describe('LoginForm', () => {
  it('should call onSubmit with form data when submitted', async () => {
    const mockOnSubmit = vi.fn()
    
    render(<LoginForm onSubmit={mockOnSubmit} />)
    
    const emailInput = screen.getByLabelText(/email/i)
    const passwordInput = screen.getByLabelText(/password/i)
    const submitButton = screen.getByRole('button', { name: /login/i })
    
    fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
    fireEvent.change(passwordInput, { target: { value: 'password123' } })
    fireEvent.click(submitButton)
    
    expect(mockOnSubmit).toHaveBeenCalledWith({
      email: 'test@example.com',
      password: 'password123'
    })
  })
  
  it('should display validation errors for invalid input', async () => {
    render(<LoginForm onSubmit={vi.fn()} />)
    
    const submitButton = screen.getByRole('button', { name: /login/i })
    fireEvent.click(submitButton)
    
    expect(screen.getByText(/email is required/i)).toBeInTheDocument()
    expect(screen.getByText(/password is required/i)).toBeInTheDocument()
  })
})

// Custom Hook Testing
import { renderHook, act } from '@testing-library/react'
import { useFormValidation } from './useFormValidation'

describe('useFormValidation', () => {
  it('should validate form values correctly', () => {
    const schema = z.object({
      email: z.string().email('Invalid email'),
      password: z.string().min(8, 'Password too short')
    })
    
    const { result } = renderHook(() => 
      useFormValidation({ email: '', password: '' }, schema)
    )
    
    act(() => {
      result.current.setFieldValue('email', 'invalid-email')
    })
    
    act(() => {
      const isValid = result.current.validate(result.current.values)
      expect(isValid).toBe(false)
    })
    
    expect(result.current.errors.email).toBe('Invalid email')
  })
})
```

### **E2E Testing with Playwright**
```typescript
// E2E Test Example
import { test, expect } from '@playwright/test'

test.describe('Authentication Flow', () => {
  test('should allow user to login with valid credentials', async ({ page }) => {
    await page.goto('/login')
    
    // Fill login form
    await page.fill('[data-testid="email-input"]', 'test@example.com')
    await page.fill('[data-testid="password-input"]', 'password123')
    
    // Submit form
    await page.click('[data-testid="login-button"]')
    
    // Verify redirect to dashboard
    await expect(page).toHaveURL('/dashboard')
    await expect(page.locator('[data-testid="user-menu"]')).toBeVisible()
  })
  
  test('should protect routes requiring authentication', async ({ page }) => {
    await page.goto('/dashboard')
    
    // Should redirect to login
    await expect(page).toHaveURL('/login')
    await expect(page.locator('h1')).toContainText('Login')
  })
  
  test('should handle logout correctly', async ({ page, context }) => {
    // Login first
    await loginUser(page, 'test@example.com', 'password123')
    
    // Logout
    await page.click('[data-testid="user-menu"]')
    await page.click('[data-testid="logout-button"]')
    
    // Verify logout
    await expect(page).toHaveURL('/login')
    
    // Verify tokens are cleared
    const localStorage = await page.evaluate(() => window.localStorage)
    expect(localStorage.auth_token).toBeUndefined()
  })
})
```

## 🎯 **Performance Optimization**

### **Code Splitting & Lazy Loading**
```typescript
// Route-based Code Splitting
import { lazy, Suspense } from 'react'

const Dashboard = lazy(() => import('./pages/Dashboard'))
const AdminPanel = lazy(() => import('./pages/AdminPanel'))
const UserProfile = lazy(() => import('./pages/UserProfile'))

const AppRoutes = () => (
  <Routes>
    <Route path="/dashboard" element={
      <Suspense fallback={<PageLoader />}>
        <ProtectedRoute>
          <Dashboard />
        </ProtectedRoute>
      </Suspense>
    } />
    <Route path="/admin" element={
      <Suspense fallback={<PageLoader />}>
        <ProtectedRoute requiredRole={['admin']}>
          <AdminPanel />
        </ProtectedRoute>
      </Suspense>
    } />
  </Routes>
)

// Component-level Lazy Loading
const HeavyChart = lazy(() => import('./components/HeavyChart'))

const DashboardPage = () => {
  const [showChart, setShowChart] = useState(false)
  
  return (
    <div>
      <h1>Dashboard</h1>
      {showChart && (
        <Suspense fallback={<ChartLoader />}>
          <HeavyChart />
        </Suspense>
      )}
      <button onClick={() => setShowChart(true)}>
        Load Chart
      </button>
    </div>
  )
}
```

### **Memoization Patterns**
```typescript
// React.memo for component optimization
const ExpensiveComponent = React.memo<ExpensiveComponentProps>(
  ({ data, onUpdate }) => {
    // Expensive rendering logic
    return <div>{/* Complex UI */}</div>
  },
  (prevProps, nextProps) => {
    // Custom comparison function
    return (
      prevProps.data.id === nextProps.data.id &&
      prevProps.data.lastModified === nextProps.data.lastModified
    )
  }
)

// useMemo for expensive calculations
const ProcessedData = ({ rawData }: { rawData: DataItem[] }) => {
  const processedData = useMemo(() => {
    return rawData
      .filter(item => item.active)
      .map(item => ({
        ...item,
        computedValue: expensiveCalculation(item)
      }))
      .sort((a, b) => a.priority - b.priority)
  }, [rawData])
  
  return <DataGrid data={processedData} />
}
```

## 🚨 **Security Best Practices**

### **Input Validation & Sanitization**
```typescript
// Form Validation with Zod
import { z } from 'zod'

const LoginSchema = z.object({
  email: z.string()
    .email('Invalid email address')
    .min(1, 'Email is required'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(100, 'Password too long'),
  rememberMe: z.boolean().default(false)
})

type LoginFormData = z.infer<typeof LoginSchema>

// XSS Prevention
const sanitizeHTML = (html: string): string => {
  const div = document.createElement('div')
  div.textContent = html
  return div.innerHTML
}

// Safe HTML Rendering
const SafeHTML: React.FC<{ content: string }> = ({ content }) => {
  const sanitizedContent = useMemo(() => sanitizeHTML(content), [content])
  
  return (
    <div dangerouslySetInnerHTML={{ __html: sanitizedContent }} />
  )
}
```

### **Error Handling & User Feedback**
```typescript
// Error Boundary
class ErrorBoundary extends React.Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  constructor(props: ErrorBoundaryProps) {
    super(props)
    this.state = { hasError: false, error: null }
  }
  
  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error }
  }
  
  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Log error to monitoring service
    console.error('Error caught by boundary:', error, errorInfo)
    
    // Send to error tracking service
    errorTrackingService.captureException(error, {
      extra: errorInfo,
      tags: { component: 'ErrorBoundary' }
    })
  }
  
  render() {
    if (this.state.hasError) {
      return this.props.fallback || <DefaultErrorFallback />
    }
    
    return this.props.children
  }
}

// Global Error Handler Hook
function useGlobalErrorHandler() {
  return useCallback((error: Error, context?: string) => {
    // Log error
    console.error(`Error in ${context}:`, error)
    
    // Show user-friendly notification
    toast.error('Something went wrong. Please try again.')
    
    // Send to error tracking
    errorTrackingService.captureException(error, {
      tags: { context }
    })
  }, [])
}
```

## 📚 **Development Guidelines**

### **Code Style & Conventions**
- Use TypeScript strict mode for type safety
- Follow React Hooks rules and best practices
- Use functional components with hooks over class components
- Implement proper error boundaries for component trees
- Use meaningful variable and function names

### **Component Guidelines**
- Keep components small and focused (single responsibility)
- Use composition over inheritance
- Implement proper prop types and default values
- Handle loading and error states consistently
- Use semantic HTML for accessibility

### **State Management Guidelines**
- Use local state (useState) for component-specific state
- Use Zustand for global application state
- Use React Query for server state management
- Minimize state duplication across stores
- Implement proper error handling in state updates

**Remember**: This frontend implements Zero Trust security principles. Always validate user input, handle authentication/authorization properly, and maintain security-first development practices throughout the application.