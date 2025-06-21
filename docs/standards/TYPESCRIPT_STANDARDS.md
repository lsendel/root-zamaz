# ⚛️ TypeScript/React Code Standards & Best Practices (2025)

> **TypeScript & React-specific standards for Zero Trust Frontend**  
> **Last Updated**: 2025-06-21  
> **Enforced by**: Biome, TypeScript 5.5+, ESLint

## 🎯 **TypeScript Quality Tools Stack**

| Tool | Purpose | Version | Config |
|------|---------|---------|--------|
| **Biome** | Ultra-fast linting & formatting | v1.9+ | `biome.json` |
| **TypeScript** | Type checking | 5.5+ | `tsconfig.json` |
| **Vitest** | Unit testing | latest | `vitest.config.ts` |
| **Playwright** | E2E testing | latest | `playwright.config.ts` |
| **ESLint** | Fallback linting | v9+ | `.eslintrc.cjs` |

## 📋 **Mandatory TypeScript Rules**

### **1. Strict Type Safety (Zero Tolerance)**
```typescript
// ✅ REQUIRED: Explicit types for all function parameters and returns
interface UserProfile {
  id: string
  email: string
  roles: Role[]
  lastLoginAt: Date | null
  preferences: UserPreferences
}

const updateUserProfile = async (
  id: string, 
  updates: Partial<UserProfile>
): Promise<ApiResponse<UserProfile>> => {
  const response = await apiClient.patch<UserProfile>(`/users/${id}`, updates)
  
  if (!response.success) {
    throw new ApiError(response.error.message, response.error.code)
  }
  
  return response
}

// ❌ FORBIDDEN: Any types or missing type annotations
const updateUserProfile = async (id, updates): Promise<any> => {
  const response = await apiClient.patch(`/users/${id}`, updates)
  return response  // CI WILL FAIL
}
```

### **2. Null Safety & Error Handling**
```typescript
// ✅ REQUIRED: Proper null handling
interface User {
  id: string
  email: string
  profile: UserProfile | null  // Explicit nullable
}

const getDisplayName = (user: User): string => {
  // Handle null case explicitly
  return user.profile?.displayName ?? user.email
}

// ✅ REQUIRED: Result pattern for error handling
type Result<T, E = Error> = 
  | { success: true; data: T }
  | { success: false; error: E }

const fetchUser = async (id: string): Promise<Result<User, ApiError>> => {
  try {
    const user = await userService.getById(id)
    return { success: true, data: user }
  } catch (error) {
    return { 
      success: false, 
      error: error instanceof ApiError ? error : new ApiError('Unknown error')
    }
  }
}

// ❌ FORBIDDEN: Unchecked null access
const getDisplayName = (user: User): string => {
  return user.profile.displayName  // CI WILL FAIL - possible null reference
}
```

### **3. Generic Type Constraints**
```typescript
// ✅ REQUIRED: Proper generic constraints
interface Repository<T extends { id: string }> {
  findById(id: string): Promise<T | null>
  save(entity: T): Promise<T>
  delete(id: string): Promise<void>
}

interface ApiResponse<TData> {
  success: boolean
  data?: TData
  error?: ApiError
  metadata?: ResponseMetadata
}

// ✅ REQUIRED: Utility types for transformation
type CreateUserRequest = Omit<User, 'id' | 'createdAt' | 'updatedAt'>
type UpdateUserRequest = Partial<Pick<User, 'name' | 'email' | 'preferences'>>

// ❌ FORBIDDEN: Unconstrained generics
interface Repository<T> {  // Too broad - CI WILL FAIL
  save(entity: T): Promise<T>
}
```

## ⚛️ **React Component Standards**

### **1. Component Definition & Props**
```typescript
// ✅ REQUIRED: Proper component interfaces
interface UserCardProps {
  user: User
  onEdit: (user: User) => void
  onDelete: (userId: string) => void
  className?: string
  isLoading?: boolean
  'data-testid'?: string  // Testing support
}

const UserCard: React.FC<UserCardProps> = ({ 
  user, 
  onEdit, 
  onDelete, 
  className,
  isLoading = false,
  'data-testid': testId = 'user-card'
}) => {
  // ✅ REQUIRED: Memoized callbacks
  const handleEdit = useCallback(() => {
    onEdit(user)
  }, [user, onEdit])
  
  const handleDelete = useCallback(() => {
    onDelete(user.id)
  }, [user.id, onDelete])
  
  // ✅ REQUIRED: Conditional rendering with loading states
  if (isLoading) {
    return <UserCardSkeleton data-testid={`${testId}-loading`} />
  }
  
  return (
    <Card className={className} data-testid={testId}>
      <CardHeader>
        <CardTitle>{user.name}</CardTitle>
        <CardSubtitle>{user.email}</CardSubtitle>
      </CardHeader>
      <CardActions>
        <Button onClick={handleEdit} variant="outline">
          Edit
        </Button>
        <Button 
          onClick={handleDelete} 
          variant="destructive"
          disabled={isLoading}
        >
          Delete
        </Button>
      </CardActions>
    </Card>
  )
}

// ❌ FORBIDDEN: Inline functions and missing types
const UserCard = ({ user, onEdit }) => {  // Missing types - CI WILL FAIL
  return (
    <div>
      <h3>{user.name}</h3>
      <button onClick={() => onEdit(user)}>Edit</button>  {/* New function every render */}
    </div>
  )
}
```

### **2. Hooks & State Management**
```typescript
// ✅ REQUIRED: Custom hooks with proper typing
interface UseUserDataReturn {
  users: User[]
  loading: boolean
  error: string | null
  refetch: () => void
  updateUser: (id: string, updates: UpdateUserRequest) => Promise<void>
}

const useUserData = (): UseUserDataReturn => {
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  
  const fetchUsers = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const result = await userService.getAll()
      
      if (result.success) {
        setUsers(result.data)
      } else {
        setError(result.error.message)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
      setLoading(false)
    }
  }, [])
  
  const updateUser = useCallback(async (id: string, updates: UpdateUserRequest) => {
    const result = await userService.update(id, updates)
    if (result.success) {
      setUsers(prev => prev.map(user => 
        user.id === id ? { ...user, ...updates } : user
      ))
    } else {
      throw new Error(result.error.message)
    }
  }, [])
  
  useEffect(() => {
    fetchUsers()
  }, [fetchUsers])
  
  return {
    users,
    loading,
    error,
    refetch: fetchUsers,
    updateUser
  }
}

// ❌ FORBIDDEN: Untyped state and missing dependencies
const useUserData = () => {
  const [users, setUsers] = useState([])  // Missing type - CI WILL FAIL
  const [loading, setLoading] = useState(true)
  
  useEffect(() => {
    fetchUsers()  // Missing dependency - CI WILL FAIL
  }, [])
  
  return { users, loading }
}
```

### **3. Event Handling & Forms**
```typescript
// ✅ REQUIRED: Typed form handling
interface LoginFormData {
  email: string
  password: string
  rememberMe: boolean
}

const LoginForm: React.FC<{ onSubmit: (data: LoginFormData) => Promise<void> }> = ({ 
  onSubmit 
}) => {
  const [formData, setFormData] = useState<LoginFormData>({
    email: '',
    password: '',
    rememberMe: false
  })
  
  const [errors, setErrors] = useState<Partial<Record<keyof LoginFormData, string>>>({})
  const [isSubmitting, setIsSubmitting] = useState(false)
  
  const handleInputChange = useCallback((
    field: keyof LoginFormData
  ) => (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const value = event.target.type === 'checkbox' 
      ? event.target.checked 
      : event.target.value
      
    setFormData(prev => ({ ...prev, [field]: value }))
    
    // Clear error when user starts typing
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: undefined }))
    }
  }, [errors])
  
  const validateForm = useCallback((): boolean => {
    const newErrors: Partial<Record<keyof LoginFormData, string>> = {}
    
    if (!formData.email) {
      newErrors.email = 'Email is required'
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = 'Email is invalid'
    }
    
    if (!formData.password) {
      newErrors.password = 'Password is required'
    } else if (formData.password.length < 8) {
      newErrors.password = 'Password must be at least 8 characters'
    }
    
    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }, [formData])
  
  const handleSubmit = useCallback(async (
    event: React.FormEvent<HTMLFormElement>
  ) => {
    event.preventDefault()
    
    if (!validateForm()) {
      return
    }
    
    try {
      setIsSubmitting(true)
      await onSubmit(formData)
    } catch (error) {
      setErrors({ 
        email: error instanceof Error ? error.message : 'Login failed' 
      })
    } finally {
      setIsSubmitting(false)
    }
  }, [formData, validateForm, onSubmit])
  
  return (
    <form onSubmit={handleSubmit} data-testid="login-form">
      <FormField>
        <Label htmlFor="email">Email</Label>
        <Input
          id="email"
          type="email"
          value={formData.email}
          onChange={handleInputChange('email')}
          disabled={isSubmitting}
          aria-invalid={!!errors.email}
          aria-describedby={errors.email ? 'email-error' : undefined}
        />
        {errors.email && (
          <ErrorMessage id="email-error">{errors.email}</ErrorMessage>
        )}
      </FormField>
      
      <FormField>
        <Label htmlFor="password">Password</Label>
        <Input
          id="password"
          type="password"
          value={formData.password}
          onChange={handleInputChange('password')}
          disabled={isSubmitting}
          aria-invalid={!!errors.password}
          aria-describedby={errors.password ? 'password-error' : undefined}
        />
        {errors.password && (
          <ErrorMessage id="password-error">{errors.password}</ErrorMessage>
        )}
      </FormField>
      
      <FormField>
        <Checkbox
          id="rememberMe"
          checked={formData.rememberMe}
          onChange={handleInputChange('rememberMe')}
          disabled={isSubmitting}
        />
        <Label htmlFor="rememberMe">Remember me</Label>
      </FormField>
      
      <Button 
        type="submit" 
        disabled={isSubmitting}
        data-testid="login-submit"
      >
        {isSubmitting ? 'Signing in...' : 'Sign in'}
      </Button>
    </form>
  )
}
```

## 🔒 **Security Standards**

### **1. XSS Prevention**
```typescript
// ✅ REQUIRED: Sanitize user input
import DOMPurify from 'dompurify'

interface SafeHTMLProps {
  content: string
  allowedTags?: string[]
}

const SafeHTML: React.FC<SafeHTMLProps> = ({ content, allowedTags = [] }) => {
  const sanitizedContent = useMemo(() => {
    return DOMPurify.sanitize(content, {
      ALLOWED_TAGS: allowedTags,
      ALLOWED_ATTR: ['href', 'title', 'alt']
    })
  }, [content, allowedTags])
  
  return (
    <div 
      dangerouslySetInnerHTML={{ __html: sanitizedContent }}
      data-testid="safe-html-content"
    />
  )
}

// ❌ FORBIDDEN: Unsafe HTML rendering
const UnsafeHTML: React.FC<{ content: string }> = ({ content }) => {
  return (
    <div dangerouslySetInnerHTML={{ __html: content }} />  // CI WILL FAIL
  )
}
```

### **2. Authentication & Authorization**
```typescript
// ✅ REQUIRED: Type-safe auth state
interface AuthState {
  user: User | null
  token: string | null
  isAuthenticated: boolean
  isLoading: boolean
  permissions: Permission[]
}

interface AuthContextValue extends AuthState {
  login: (credentials: LoginCredentials) => Promise<void>
  logout: () => void
  hasPermission: (permission: Permission) => boolean
  hasRole: (role: Role) => boolean
}

const AuthContext = createContext<AuthContextValue | null>(null)

export const useAuth = (): AuthContextValue => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

// ✅ REQUIRED: Protected route component
interface ProtectedRouteProps {
  children: React.ReactNode
  requiredPermissions?: Permission[]
  requiredRoles?: Role[]
  fallback?: React.ReactNode
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  requiredPermissions = [],
  requiredRoles = [],
  fallback = <Navigate to="/login" replace />
}) => {
  const { isAuthenticated, isLoading, hasPermission, hasRole } = useAuth()
  
  if (isLoading) {
    return <LoadingSpinner data-testid="auth-loading" />
  }
  
  if (!isAuthenticated) {
    return fallback
  }
  
  const hasRequiredPermissions = requiredPermissions.every(hasPermission)
  const hasRequiredRoles = requiredRoles.every(hasRole)
  
  if (!hasRequiredPermissions || !hasRequiredRoles) {
    return <Navigate to="/unauthorized" replace />
  }
  
  return <>{children}</>
}
```

## 🧪 **Testing Standards**

### **1. Unit Testing with Vitest**
```typescript
// File: UserCard.test.tsx
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { UserCard } from './UserCard'
import { createMockUser } from '@/test-utils/factories'

describe('UserCard', () => {
  const mockOnEdit = vi.fn()
  const mockOnDelete = vi.fn()
  
  beforeEach(() => {
    vi.clearAllMocks()
  })
  
  it('should render user information correctly', () => {
    const user = createMockUser({
      name: 'John Doe',
      email: 'john@example.com'
    })
    
    render(
      <UserCard 
        user={user} 
        onEdit={mockOnEdit} 
        onDelete={mockOnDelete} 
      />
    )
    
    expect(screen.getByText('John Doe')).toBeInTheDocument()
    expect(screen.getByText('john@example.com')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /edit/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /delete/i })).toBeInTheDocument()
  })
  
  it('should call onEdit when edit button is clicked', async () => {
    const user = createMockUser()
    
    render(
      <UserCard 
        user={user} 
        onEdit={mockOnEdit} 
        onDelete={mockOnDelete} 
      />
    )
    
    const editButton = screen.getByRole('button', { name: /edit/i })
    await fireEvent.click(editButton)
    
    expect(mockOnEdit).toHaveBeenCalledTimes(1)
    expect(mockOnEdit).toHaveBeenCalledWith(user)
  })
  
  it('should show loading skeleton when isLoading is true', () => {
    const user = createMockUser()
    
    render(
      <UserCard 
        user={user} 
        onEdit={mockOnEdit} 
        onDelete={mockOnDelete} 
        isLoading={true}
      />
    )
    
    expect(screen.getByTestId('user-card-loading')).toBeInTheDocument()
    expect(screen.queryByText(user.name)).not.toBeInTheDocument()
  })
})
```

### **2. E2E Testing with Playwright**
```typescript
// File: auth.spec.ts
import { test, expect } from '@playwright/test'

test.describe('Authentication Flow', () => {
  test('should allow user to login with valid credentials', async ({ page }) => {
    await page.goto('/login')
    
    // Fill login form
    await page.fill('[data-testid="email-input"]', 'test@example.com')
    await page.fill('[data-testid="password-input"]', 'password123')
    
    // Submit form
    await page.click('[data-testid="login-submit"]')
    
    // Verify successful login
    await expect(page).toHaveURL('/dashboard')
    await expect(page.locator('[data-testid="user-menu"]')).toBeVisible()
    
    // Verify user information is displayed
    await expect(page.locator('[data-testid="user-email"]')).toContainText('test@example.com')
  })
  
  test('should show error for invalid credentials', async ({ page }) => {
    await page.goto('/login')
    
    await page.fill('[data-testid="email-input"]', 'invalid@example.com')
    await page.fill('[data-testid="password-input"]', 'wrongpassword')
    await page.click('[data-testid="login-submit"]')
    
    // Verify error message is shown
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible()
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Invalid credentials')
    
    // Verify user stays on login page
    await expect(page).toHaveURL('/login')
  })
  
  test('should protect authenticated routes', async ({ page }) => {
    // Try to access protected route without authentication
    await page.goto('/dashboard')
    
    // Should redirect to login
    await expect(page).toHaveURL('/login')
    await expect(page.locator('h1')).toContainText('Sign in')
  })
})
```

## ⚡ **Performance Standards**

### **1. Bundle Optimization**
```typescript
// ✅ REQUIRED: Code splitting with React.lazy
const Dashboard = lazy(() => import('./pages/Dashboard'))
const AdminPanel = lazy(() => import('./pages/AdminPanel'))
const UserProfile = lazy(() => import('./pages/UserProfile'))

const AppRoutes: React.FC = () => (
  <Routes>
    <Route 
      path="/dashboard" 
      element={
        <Suspense fallback={<PageSkeleton />}>
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        </Suspense>
      } 
    />
    <Route 
      path="/admin" 
      element={
        <Suspense fallback={<PageSkeleton />}>
          <ProtectedRoute requiredRoles={['admin']}>
            <AdminPanel />
          </ProtectedRoute>
        </Suspense>
      } 
    />
  </Routes>
)

// ✅ REQUIRED: Memoization for expensive calculations
const UserList: React.FC<{ users: User[]; filters: UserFilters }> = ({ 
  users, 
  filters 
}) => {
  const filteredUsers = useMemo(() => {
    return users
      .filter(user => {
        if (filters.role && !user.roles.includes(filters.role)) return false
        if (filters.status && user.status !== filters.status) return false
        if (filters.search) {
          const searchLower = filters.search.toLowerCase()
          return user.name.toLowerCase().includes(searchLower) ||
                 user.email.toLowerCase().includes(searchLower)
        }
        return true
      })
      .sort((a, b) => {
        switch (filters.sortBy) {
          case 'name': return a.name.localeCompare(b.name)
          case 'email': return a.email.localeCompare(b.email)
          case 'lastLogin': return (b.lastLoginAt?.getTime() ?? 0) - (a.lastLoginAt?.getTime() ?? 0)
          default: return 0
        }
      })
  }, [users, filters])
  
  return (
    <div data-testid="user-list">
      {filteredUsers.map(user => (
        <UserCard key={user.id} user={user} />
      ))}
    </div>
  )
}
```

### **2. Memory Management**
```typescript
// ✅ REQUIRED: Cleanup in useEffect
const useWebSocket = (url: string) => {
  const [socket, setSocket] = useState<WebSocket | null>(null)
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'disconnected'>('disconnected')
  
  useEffect(() => {
    const ws = new WebSocket(url)
    setSocket(ws)
    setConnectionStatus('connecting')
    
    ws.onopen = () => setConnectionStatus('connected')
    ws.onclose = () => setConnectionStatus('disconnected')
    ws.onerror = () => setConnectionStatus('disconnected')
    
    // ✅ REQUIRED: Cleanup function
    return () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.close()
      }
    }
  }, [url])
  
  return { socket, connectionStatus }
}

// ✅ REQUIRED: Abort controllers for async operations
const useAsyncOperation = () => {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  
  const execute = useCallback(async <T>(
    operation: (signal: AbortSignal) => Promise<T>
  ): Promise<T | null> => {
    const controller = new AbortController()
    
    try {
      setLoading(true)
      setError(null)
      
      const result = await operation(controller.signal)
      return result
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        return null // Operation was cancelled
      }
      setError(err instanceof Error ? err.message : 'Unknown error')
      throw err
    } finally {
      setLoading(false)
    }
  }, [])
  
  return { execute, loading, error }
}
```

## 🔧 **Static Analysis Configuration**

### **Biome Rules (Enforced)**
```json
{
  "linter": {
    "rules": {
      "correctness": {
        "noUndeclaredVariables": "error",
        "noUnusedVariables": "error",
        "useExhaustiveDependencies": "warn"
      },
      "suspicious": {
        "noExplicitAny": "error",
        "noDebugger": "error",
        "noConsoleLog": "warn"
      },
      "style": {
        "noVar": "error",
        "useConst": "error",
        "useTemplate": "error"
      },
      "security": {
        "noDangerouslySetInnerHtml": "warn"
      }
    }
  }
}
```

### **TypeScript Strict Mode**
```json
{
  "compilerOptions": {
    "strict": true,
    "noImplicitAny": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true
  }
}
```

## 🚀 **CI/CD Integration**

### **Make Targets**
```bash
# TypeScript quality checks
make lint-frontend      # Biome linting
make type-check-frontend # TypeScript checking
make format-frontend    # Code formatting
make test-frontend      # Unit + E2E tests

# Combined quality check
make quality-ci         # All checks (CI mode)
```

### **Performance Budgets**
```json
{
  "bundleSize": {
    "initial": "250KB",
    "chunks": "100KB"
  },
  "performance": {
    "firstContentfulPaint": "2000ms",
    "largestContentfulPaint": "2500ms",
    "cumulativeLayoutShift": "0.1"
  }
}
```

---

**Remember**: TypeScript code must maintain 100% type safety and pass all performance budgets. No `any` types allowed in production code.