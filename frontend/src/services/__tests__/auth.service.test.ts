import { describe, it, expect, vi, beforeEach } from 'vitest'
import { AuthService } from '../auth.service'

// Mock the api-client module
vi.mock('../api-client', () => ({
  apiClient: {
    post: vi.fn(),
    get: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}))

describe('AuthService', () => {
  let authService: AuthService

  beforeEach(() => {
    vi.clearAllMocks()
    authService = new AuthService()
  })

  describe('login', () => {
    it('should make correct API call for login', async () => {
      const { apiClient } = await import('../api-client')
      const mockResponse = {
        success: true,
        data: {
          user: { id: '1', email: 'test@example.com' },
          token: 'fake-jwt-token',
          refreshToken: 'fake-refresh-token'
        }
      }

      ;(apiClient.post as any).mockResolvedValueOnce(mockResponse)

      const credentials = {
        email: 'test@example.com',
        password: 'password123'
      }

      const result = await authService.login(credentials)

      expect(apiClient.post).toHaveBeenCalledWith('/auth/login', credentials)
      expect(result).toEqual(mockResponse)
    })

    it('should throw error on failed login', async () => {
      const { apiClient } = await import('../api-client')
      const error = new Error('Unauthorized')
      ;(apiClient.post as any).mockRejectedValueOnce(error)

      const credentials = {
        email: 'test@example.com',
        password: 'wrongpassword'
      }

      await expect(authService.login(credentials)).rejects.toThrow('Unauthorized')
    })
  })

  describe('logout', () => {
    it('should handle logout correctly', async () => {
      const { apiClient } = await import('../api-client')
      const mockResponse = { success: true, data: null }
      ;(apiClient.post as any).mockResolvedValueOnce(mockResponse)

      const result = await authService.logout()

      expect(apiClient.post).toHaveBeenCalledWith('/auth/logout')
      expect(result).toEqual(mockResponse)
    })
  })

  describe('refreshToken', () => {
    it('should refresh token successfully', async () => {
      const { apiClient } = await import('../api-client')
      const mockResponse = {
        success: true,
        data: {
          token: 'new-jwt-token',
          refreshToken: 'new-refresh-token'
        }
      }

      ;(apiClient.post as any).mockResolvedValueOnce(mockResponse)

      const result = await authService.refreshToken()

      expect(apiClient.post).toHaveBeenCalledWith('/auth/refresh')
      expect(result).toEqual(mockResponse)
    })
  })
})