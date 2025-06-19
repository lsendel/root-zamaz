import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { authApi } from '../../services/api'
import { useAuthStore } from '../../stores/auth-store'
import { useUIStore } from '../../stores/ui-store'

// Query keys
export const authKeys = {
  all: ['auth'] as const,
  user: () => [...authKeys.all, 'user'] as const,
  profile: () => [...authKeys.all, 'profile'] as const,
}

// Login mutation
export const useLogin = () => {
  const setUser = useAuthStore(state => state.setUser)
  const setToken = useAuthStore(state => state.setToken)
  const addNotification = useUIStore(state => state.addNotification)
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: authApi.login,
    onSuccess: (response) => {
      const { user, token } = response.data
      setUser(user)
      setToken(token)
      
      // Cache user data
      queryClient.setQueryData(authKeys.user(), user)
      
      addNotification({
        type: 'success',
        title: 'Login Successful',
        message: `Welcome back, ${user.first_name}!`
      })
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        title: 'Login Failed',
        message: error.response?.data?.message || 'Invalid credentials'
      })
    }
  })
}

// Register mutation
export const useRegister = () => {
  const addNotification = useUIStore(state => state.addNotification)

  return useMutation({
    mutationFn: authApi.register,
    onSuccess: () => {
      addNotification({
        type: 'success',
        title: 'Registration Successful',
        message: 'Please check your email to verify your account'
      })
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        title: 'Registration Failed',
        message: error.response?.data?.message || 'Registration failed'
      })
    }
  })
}

// Logout mutation
export const useLogout = () => {
  const logout = useAuthStore(state => state.logout)
  const addNotification = useUIStore(state => state.addNotification)
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: authApi.logout,
    onSuccess: () => {
      logout()
      queryClient.clear() // Clear all cached data
      
      addNotification({
        type: 'info',
        title: 'Logged Out',
        message: 'You have been successfully logged out'
      })
    },
    onError: () => {
      // Even if API call fails, still logout locally
      logout()
      queryClient.clear()
    }
  })
}

// Get current user query
export const useCurrentUser = () => {
  const isAuthenticated = useAuthStore(state => state.isAuthenticated)
  const token = useAuthStore(state => state.token)

  return useQuery({
    queryKey: authKeys.user(),
    queryFn: authApi.getCurrentUser,
    enabled: isAuthenticated && !!token,
    staleTime: 5 * 60 * 1000, // 5 minutes
    retry: (failureCount, error: any) => {
      // Don't retry on auth errors
      if (error.response?.status === 401) {
        return false
      }
      return failureCount < 3
    }
  })
}

// Refresh token mutation
export const useRefreshToken = () => {
  const setUser = useAuthStore(state => state.setUser)
  const setToken = useAuthStore(state => state.setToken)
  const logout = useAuthStore(state => state.logout)
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: authApi.refreshToken,
    onSuccess: (response) => {
      const { user, token } = response.data
      setUser(user)
      setToken(token)
      
      // Update cached user data
      queryClient.setQueryData(authKeys.user(), user)
    },
    onError: () => {
      // If refresh fails, logout user
      logout()
      queryClient.clear()
    }
  })
}