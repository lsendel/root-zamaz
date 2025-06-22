import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import ProtectedRoute from '../ProtectedRoute'

// Mock the auth store
vi.mock('../../stores/auth-store.ts', () => ({
  useAuthStore: vi.fn(),
}))

const TestWrapper = ({ children }: { children: React.ReactNode }) => (
  <MemoryRouter>
    {children}
  </MemoryRouter>
)

describe('ProtectedRoute', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should render children when authenticated', async () => {
    const { useAuthStore } = await import('../../stores/auth-store.ts')
    
    // Mock authenticated state - return true for both calls
    ;(useAuthStore as any)
      .mockReturnValueOnce(true)   // isAuthenticated
      .mockReturnValueOnce(false)  // isLoading

    render(
      <TestWrapper>
        <ProtectedRoute>
          <div>Protected Content</div>
        </ProtectedRoute>
      </TestWrapper>
    )

    expect(screen.getByText('Protected Content')).toBeInTheDocument()
  })

  it('should show loading when authentication is loading', async () => {
    const { useAuthStore } = await import('../../stores/auth-store.ts')
    
    // Mock loading state - return true for isLoading
    ;(useAuthStore as any)
      .mockReturnValueOnce(false)  // isAuthenticated 
      .mockReturnValueOnce(true)   // isLoading

    render(
      <TestWrapper>
        <ProtectedRoute>
          <div>Protected Content</div>
        </ProtectedRoute>
      </TestWrapper>
    )

    // Should show loading spinner
    expect(screen.getByText('Loading...')).toBeInTheDocument()
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
  })

  it('should redirect when not authenticated', async () => {
    const { useAuthStore } = await import('../../stores/auth-store.ts')
    
    // Mock unauthenticated state - return false for both
    ;(useAuthStore as any)
      .mockReturnValueOnce(false)  // isAuthenticated
      .mockReturnValueOnce(false)  // isLoading

    render(
      <TestWrapper>
        <ProtectedRoute>
          <div>Protected Content</div>
        </ProtectedRoute>
      </TestWrapper>
    )

    // Should not show protected content
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
  })
})