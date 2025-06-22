import { describe, it, expect, vi } from 'vitest'
import { render } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Mock all the router components to avoid nesting issues
vi.mock('react-router-dom', () => ({
  BrowserRouter: ({ children }: { children: React.ReactNode }) => <div data-testid="router">{children}</div>,
  Routes: ({ children }: { children: React.ReactNode }) => <div data-testid="routes">{children}</div>,
  Route: ({ children }: { children: React.ReactNode }) => <div data-testid="route">{children}</div>,
}))

// Mock the AuthProvider to avoid context issues
vi.mock('../../hooks/useAuth', () => ({
  AuthProvider: ({ children }: { children: React.ReactNode }) => <div data-testid="auth-provider">{children}</div>,
}))

// Mock ErrorBoundary
vi.mock('../../components/error-boundary', () => ({
  ErrorBoundary: ({ children }: { children: React.ReactNode }) => <div data-testid="error-boundary">{children}</div>,
}))

// Mock Notifications
vi.mock('../../components/notifications', () => ({
  Notifications: () => <div data-testid="notifications">Notifications</div>,
}))

// Mock ProtectedRoute
vi.mock('../../components/ProtectedRoute', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div data-testid="protected-route">{children}</div>,
}))

// Test wrapper with providers
const TestWrapper = ({ children }: { children: React.ReactNode }) => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })

  return (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  )
}

describe('App Component', () => {
  it('should render without crashing', async () => {
    const App = (await import('../../App')).default
    
    const { container } = render(
      <TestWrapper>
        <App />
      </TestWrapper>
    )
    
    // Should render the app without throwing
    expect(container).toBeInTheDocument()
  })

  it('should contain expected components', async () => {
    const App = (await import('../../App')).default
    
    const { getByTestId } = render(
      <TestWrapper>
        <App />
      </TestWrapper>
    )
    
    // Check if core components are rendered
    expect(getByTestId('router')).toBeInTheDocument()
    expect(getByTestId('auth-provider')).toBeInTheDocument()
    expect(getByTestId('error-boundary')).toBeInTheDocument()
  })
})