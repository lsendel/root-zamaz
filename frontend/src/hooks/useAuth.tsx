import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { User, LoginCredentials } from '../types/auth'
import { authAPI } from '../services/api'

interface AuthContextType {
  user: User | null
  isLoading: boolean
  isAuthenticated: boolean
  isAdmin: boolean
  login: (credentials: LoginCredentials) => Promise<void>
  logout: () => Promise<void>
  error: string | null
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

interface AuthProviderProps {
  children: ReactNode
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const isAuthenticated = !!user
  const isAdmin = user?.is_admin || false

  useEffect(() => {
    const initAuth = async () => {
      const token = localStorage.getItem('authToken')
      const storedUser = localStorage.getItem('user')

      if (token && storedUser) {
        try {
          // Verify token is still valid
          const currentUser = await authAPI.getCurrentUser()
          setUser(currentUser)
        } catch (error) {
          // Token invalid, clear storage
          localStorage.removeItem('authToken')
          localStorage.removeItem('user')
        }
      }
      setIsLoading(false)
    }

    initAuth()
  }, [])

  const login = async (credentials: LoginCredentials) => {
    try {
      setError(null)
      setIsLoading(true)
      
      const response = await authAPI.login(credentials)
      
      localStorage.setItem('authToken', response.token)
      localStorage.setItem('user', JSON.stringify(response.user))
      setUser(response.user)
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || 'Login failed'
      setError(errorMessage)
      throw error
    } finally {
      setIsLoading(false)
    }
  }

  const logout = async () => {
    try {
      await authAPI.logout()
    } catch (error) {
      // Continue with logout even if API call fails
      console.error('Logout API call failed:', error)
    } finally {
      localStorage.removeItem('authToken')
      localStorage.removeItem('user')
      setUser(null)
    }
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        isAuthenticated,
        isAdmin,
        login,
        logout,
        error,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}