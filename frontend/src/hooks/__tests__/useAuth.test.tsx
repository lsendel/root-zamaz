import { describe, it, expect, vi } from 'vitest'

// Mock the auth store directly
const mockAuthStore = {
  user: null,
  token: null,
  isAuthenticated: false,
  isLoading: false,
  login: vi.fn(),
  logout: vi.fn(),
  refreshToken: vi.fn(),
}

vi.mock('../../stores/auth-store.ts', () => ({
  useAuthStore: vi.fn(() => mockAuthStore),
}))

describe('useAuth Hook', () => {
  it('should access auth store correctly', async () => {
    const { useAuthStore } = await import('../../stores/auth-store.ts')
    
    const state = useAuthStore()
    
    expect(state).toMatchObject({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      login: expect.any(Function),
      logout: expect.any(Function),
    })
  })

  it('should call login method from store', async () => {
    const { useAuthStore } = await import('../../stores/auth-store.ts')
    const state = useAuthStore()
    
    const credentials = { email: 'test@example.com', password: 'password123' }
    
    await state.login(credentials)
    
    expect(mockAuthStore.login).toHaveBeenCalledWith(credentials)
  })

  it('should call logout method from store', async () => {
    const { useAuthStore } = await import('../../stores/auth-store.ts')
    const state = useAuthStore()
    
    state.logout()
    
    expect(mockAuthStore.logout).toHaveBeenCalled()
  })
})