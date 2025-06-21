import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'
import { authService } from '../services'
import type { User } from '../types/auth'

interface AuthState {
  // State
  user: User | null
  token: string | null
  isAuthenticated: boolean
  isLoading: boolean
  error: string | null

  // Actions
  login: (username: string, password: string) => Promise<void>
  logout: () => void
  refreshToken: () => Promise<void>
  setUser: (user: User) => void
  setToken: (token: string) => void
  clearError: () => void
  setLoading: (loading: boolean) => void
}

export const useAuthStore = create<AuthState>()((
  devtools(
    persist(
      (set, get) => ({
        // Initial state
        user: null,
        token: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,

        // Actions
        login: async (username: string, password: string) => {
          try {
            set({ isLoading: true, error: null })
            
            const response = await authService.login({ username, password })
            const { user, token } = response.data
            
            set({
              user,
              token,
              isAuthenticated: true,
              isLoading: false,
              error: null
            })
          } catch (error: any) {
            set({
              user: null,
              token: null,
              isAuthenticated: false,
              isLoading: false,
              error: error.message || 'Login failed'
            })
            throw error
          }
        },

        logout: () => {
          set({
            user: null,
            token: null,
            isAuthenticated: false,
            error: null
          })
          
          // Clear token from localStorage
          localStorage.removeItem('auth-storage')
        },

        refreshToken: async () => {
          try {
            const { token } = get()
            if (!token) {
              throw new Error('No token available')
            }

            const response = await authService.refreshToken()
            const { token: newToken, user } = response.data
            
            set({
              user,
              token: newToken,
              isAuthenticated: true,
              error: null
            })
          } catch (error: any) {
            // If refresh fails, logout user
            get().logout()
            throw error
          }
        },

        setUser: (user: User) => {
          set({ user })
        },

        setToken: (token: string) => {
          set({ token, isAuthenticated: true })
        },

        clearError: () => {
          set({ error: null })
        },

        setLoading: (loading: boolean) => {
          set({ isLoading: loading })
        }
      }),
      {
        name: 'auth-storage',
        partialize: (state) => ({
          user: state.user,
          token: state.token,
          isAuthenticated: state.isAuthenticated
        })
      }
    ),
    {
      name: 'auth-store'
    }
  )
))