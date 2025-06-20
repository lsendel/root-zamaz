// Enhanced API service with service discovery and resilience patterns
import axios, { AxiosInstance, AxiosError, AxiosRequestConfig } from 'axios'
import { LoginRequest, LoginResponse, RefreshTokenResponse, RegisterCredentials, User, DeviceAttestation, Role, Permission, UserWithRoles } from '../types/auth'
import { apiConfig } from '../config/api'
import { serviceDiscovery, getDiscoveryAwareApiUrl } from '../config/service-discovery'

interface RetryConfig {
  retries: number
  retryDelay: number
  retryCondition?: (error: AxiosError) => boolean
}

interface CircuitBreakerConfig {
  failureThreshold: number
  resetTimeout: number
  halfOpenRetries: number
}

enum CircuitState {
  CLOSED = 'CLOSED',
  OPEN = 'OPEN',
  HALF_OPEN = 'HALF_OPEN'
}

class CircuitBreaker {
  private failureCount = 0
  private lastFailureTime = 0
  private successCount = 0
  private state: CircuitState = CircuitState.CLOSED

  constructor(private config: CircuitBreakerConfig) {}

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === CircuitState.OPEN) {
      if (Date.now() - this.lastFailureTime > this.config.resetTimeout) {
        this.state = CircuitState.HALF_OPEN
        this.successCount = 0
      } else {
        throw new Error('Circuit breaker is OPEN')
      }
    }

    try {
      const result = await fn()
      this.onSuccess()
      return result
    } catch (error) {
      this.onFailure()
      throw error
    }
  }

  private onSuccess(): void {
    this.failureCount = 0
    
    if (this.state === CircuitState.HALF_OPEN) {
      this.successCount++
      if (this.successCount >= this.config.halfOpenRetries) {
        this.state = CircuitState.CLOSED
      }
    }
  }

  private onFailure(): void {
    this.failureCount++
    this.lastFailureTime = Date.now()
    
    if (this.failureCount >= this.config.failureThreshold) {
      this.state = CircuitState.OPEN
    }
  }

  getState(): CircuitState {
    return this.state
  }
}

class ResilientApiClient {
  private axiosInstance: AxiosInstance
  private circuitBreaker: CircuitBreaker
  private retryConfig: RetryConfig = {
    retries: 3,
    retryDelay: 1000,
    retryCondition: (error: AxiosError) => {
      // Retry on network errors or 5xx status codes
      return !error.response || (error.response.status >= 500 && error.response.status < 600)
    }
  }

  constructor() {
    this.circuitBreaker = new CircuitBreaker({
      failureThreshold: 5,
      resetTimeout: 30000, // 30 seconds
      halfOpenRetries: 3
    })

    this.axiosInstance = this.createAxiosInstance()
    this.setupInterceptors()
  }

  private createAxiosInstance(): AxiosInstance {
    const config = apiConfig.getConfig()
    
    return axios.create({
      baseURL: getDiscoveryAwareApiUrl(),
      timeout: config.timeout,
      headers: {
        'Content-Type': 'application/json',
        'X-Client-Version': '1.0.0',
        'X-Service-Discovery': serviceDiscovery['config'].provider
      }
    })
  }

  private setupInterceptors(): void {
    // Request interceptor
    this.axiosInstance.interceptors.request.use(
      (config) => {
        // Add auth token
        const token = localStorage.getItem('authToken')
        if (token) {
          config.headers.Authorization = `Bearer ${token}`
        }

        // Add correlation ID for tracing
        config.headers['X-Correlation-ID'] = this.generateCorrelationId()

        // Update base URL if service discovery found a better endpoint
        const dynamicUrl = getDiscoveryAwareApiUrl()
        if (dynamicUrl && dynamicUrl !== config.baseURL) {
          config.baseURL = dynamicUrl
          console.log('🔄 Using discovered endpoint:', dynamicUrl)
        }

        return config
      },
      (error) => Promise.reject(error)
    )

    // Response interceptor
    this.axiosInstance.interceptors.response.use(
      (response) => {
        // Log successful responses in development
        if (import.meta.env.DEV) {
          console.log(`✅ ${response.config.method?.toUpperCase()} ${response.config.url} - ${response.status}`)
        }
        return response
      },
      async (error: AxiosError) => {
        const originalRequest = error.config as AxiosRequestConfig & { _retry?: number }

        // Handle authentication errors
        if (error.response?.status === 401 && !originalRequest.url?.includes('/auth/')) {
          localStorage.removeItem('authToken')
          localStorage.removeItem('user')
          window.location.href = '/login'
          return Promise.reject(error)
        }

        // Implement retry logic
        if (this.retryConfig.retryCondition?.(error) && originalRequest) {
          originalRequest._retry = (originalRequest._retry || 0) + 1

          if (originalRequest._retry <= this.retryConfig.retries) {
            console.log(`🔄 Retrying request (${originalRequest._retry}/${this.retryConfig.retries})...`)
            
            // Exponential backoff
            const delay = this.retryConfig.retryDelay * Math.pow(2, originalRequest._retry - 1)
            await new Promise(resolve => setTimeout(resolve, delay))

            // Try a different endpoint if available
            if (originalRequest._retry > 1) {
              const alternativeUrl = serviceDiscovery.buildApiUrl({ healthCheck: true })
              if (alternativeUrl && alternativeUrl !== originalRequest.baseURL) {
                originalRequest.baseURL = alternativeUrl
                console.log('🔀 Switching to alternative endpoint:', alternativeUrl)
              }
            }

            return this.axiosInstance(originalRequest)
          }
        }

        // Log errors in development
        if (import.meta.env.DEV) {
          console.error(`❌ ${error.config?.method?.toUpperCase()} ${error.config?.url} - ${error.response?.status || 'Network Error'}`)
        }

        return Promise.reject(error)
      }
    )
  }

  private generateCorrelationId(): string {
    return `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`
  }

  // Circuit breaker wrapper for API calls
  private async executeWithCircuitBreaker<T>(
    fn: () => Promise<T>,
    fallback?: () => T
  ): Promise<T> {
    try {
      return await this.circuitBreaker.execute(fn)
    } catch (error) {
      if (fallback && this.circuitBreaker.getState() === CircuitState.OPEN) {
        console.warn('⚡ Circuit breaker OPEN, using fallback')
        return fallback()
      }
      throw error
    }
  }

  // Create a new instance with updated configuration
  reconfigure(): void {
    this.axiosInstance = this.createAxiosInstance()
    this.setupInterceptors()
  }

  // Get the axios instance for direct use
  getInstance(): AxiosInstance {
    return this.axiosInstance
  }

  // Execute requests with circuit breaker
  async get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return this.executeWithCircuitBreaker(async () => {
      const response = await this.axiosInstance.get<T>(url, config)
      return response.data
    })
  }

  async post<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    return this.executeWithCircuitBreaker(async () => {
      const response = await this.axiosInstance.post<T>(url, data, config)
      return response.data
    })
  }

  async put<T>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    return this.executeWithCircuitBreaker(async () => {
      const response = await this.axiosInstance.put<T>(url, data, config)
      return response.data
    })
  }

  async delete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    return this.executeWithCircuitBreaker(async () => {
      const response = await this.axiosInstance.delete<T>(url, config)
      return response.data
    })
  }
}

// Create singleton instance
const resilientClient = new ResilientApiClient()

// Enhanced API services with resilience patterns
export const authApi = {
  login: async (credentials: LoginRequest): Promise<{ data: LoginResponse }> => {
    const data = await resilientClient.post<LoginResponse>('/auth/login', credentials)
    return { data }
  },

  register: async (credentials: RegisterCredentials): Promise<User> => {
    return resilientClient.post<User>('/auth/register', credentials)
  },

  logout: async (): Promise<void> => {
    return resilientClient.post('/auth/logout')
  },

  getCurrentUser: async (): Promise<User> => {
    return resilientClient.get<User>('/auth/me')
  },

  refreshToken: async (): Promise<{ data: RefreshTokenResponse }> => {
    const data = await resilientClient.post<RefreshTokenResponse>('/auth/refresh')
    return { data }
  },
}

export const deviceAPI = {
  getDevices: async (): Promise<DeviceAttestation[]> => {
    return resilientClient.get<DeviceAttestation[]>('/devices')
  },

  attestDevice: async (deviceData: Record<string, any>): Promise<DeviceAttestation> => {
    return resilientClient.post<DeviceAttestation>('/devices/attest', deviceData)
  },

  verifyDevice: async (deviceId: string): Promise<DeviceAttestation> => {
    return resilientClient.post<DeviceAttestation>(`/devices/${deviceId}/verify`)
  },
}

export const healthAPI = {
  getSystemHealth: async (): Promise<{ status: string; services: Record<string, string> }> => {
    return resilientClient.get<{ status: string; services: Record<string, string> }>('/health')
  },

  // Enhanced health check with service discovery
  checkServiceHealth: async (): Promise<{
    api: { healthy: boolean; latency?: number }
    discovery: { provider: string; endpoints: number; healthy: number }
  }> => {
    const apiHealth = await apiConfig.checkHealth()
    const discoveryEndpoints = serviceDiscovery.getHealthyEndpoints()
    
    return {
      api: {
        healthy: apiHealth.healthy,
        latency: apiHealth.latency
      },
      discovery: {
        provider: serviceDiscovery['config'].provider,
        endpoints: serviceDiscovery['config'].endpoints.length,
        healthy: discoveryEndpoints.length
      }
    }
  }
}

export const adminAPI = {
  // Role management
  getRoles: async (): Promise<Role[]> => {
    return resilientClient.get<Role[]>('/admin/roles')
  },

  createRole: async (role: { name: string; description: string }): Promise<Role> => {
    return resilientClient.post<Role>('/admin/roles', role)
  },

  updateRole: async (id: number, role: { name?: string; description?: string; is_active?: boolean }): Promise<Role> => {
    return resilientClient.put<Role>(`/admin/roles/${id}`, role)
  },

  deleteRole: async (id: number): Promise<void> => {
    return resilientClient.delete(`/admin/roles/${id}`)
  },

  // Permission management
  getPermissions: async (): Promise<Permission[]> => {
    return resilientClient.get<Permission[]>('/admin/permissions')
  },

  // Role-Permission assignments
  assignPermissionToRole: async (roleId: number, permissionId: number): Promise<void> => {
    return resilientClient.post(`/admin/roles/${roleId}/permissions/${permissionId}`)
  },

  removePermissionFromRole: async (roleId: number, permissionId: number): Promise<void> => {
    return resilientClient.delete(`/admin/roles/${roleId}/permissions/${permissionId}`)
  },

  // User management
  getUsers: async (): Promise<UserWithRoles[]> => {
    return resilientClient.get<UserWithRoles[]>('/admin/users')
  },

  getUserById: async (id: number): Promise<UserWithRoles> => {
    return resilientClient.get<UserWithRoles>(`/admin/users/${id}`)
  },

  updateUser: async (id: number, user: { 
    username?: string; 
    email?: string; 
    first_name?: string; 
    last_name?: string; 
    is_active?: boolean; 
    is_admin?: boolean 
  }): Promise<User> => {
    return resilientClient.put<User>(`/admin/users/${id}`, user)
  },

  deleteUser: async (id: number): Promise<void> => {
    return resilientClient.delete(`/admin/users/${id}`)
  },

  // User-Role assignments
  assignRoleToUser: async (userId: number, roleId: number): Promise<void> => {
    return resilientClient.post(`/admin/users/${userId}/roles/${roleId}`)
  },

  removeRoleFromUser: async (userId: number, roleId: number): Promise<void> => {
    return resilientClient.delete(`/admin/users/${userId}/roles/${roleId}`)
  },
}

// Export the enhanced client for direct use if needed
export const api = resilientClient.getInstance()
export default api

// Utility functions for service management
export const serviceUtils = {
  // Refresh service endpoints from discovery
  refreshEndpoints: async (): Promise<void> => {
    await serviceDiscovery.refreshHealth()
    resilientClient.reconfigure()
  },

  // Get current circuit breaker state
  getCircuitBreakerState: (): string => {
    return resilientClient['circuitBreaker'].getState()
  },

  // Force circuit breaker reset
  resetCircuitBreaker: (): void => {
    // This would need to be implemented in the CircuitBreaker class
    console.log('Circuit breaker reset requested')
  }
}