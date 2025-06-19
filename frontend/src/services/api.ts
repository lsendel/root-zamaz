import axios from 'axios'
import { LoginRequest, LoginResponse, RefreshTokenResponse, RegisterCredentials, User, DeviceAttestation, Role, Permission, UserWithRoles } from '../types/auth'

const api = axios.create({
  baseURL: '/api',
  timeout: 10000,
})

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('authToken')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Handle auth errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('authToken')
      localStorage.removeItem('user')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export const authApi = {
  login: async (credentials: LoginRequest): Promise<{ data: LoginResponse }> => {
    const response = await api.post('/auth/login', credentials)
    return { data: response.data }
  },

  register: async (credentials: RegisterCredentials): Promise<User> => {
    const response = await api.post('/auth/register', credentials)
    return response.data
  },

  logout: async (): Promise<void> => {
    await api.post('/auth/logout')
  },

  getCurrentUser: async (): Promise<User> => {
    const response = await api.get('/auth/me')
    return response.data
  },

  refreshToken: async (): Promise<{ data: RefreshTokenResponse }> => {
    const response = await api.post('/auth/refresh')
    return { data: response.data }
  },
}

// Keep backward compatibility
export const authAPI = authApi

export const deviceAPI = {
  getDevices: async (): Promise<DeviceAttestation[]> => {
    const response = await api.get('/devices')
    return response.data
  },

  attestDevice: async (deviceData: Record<string, any>): Promise<DeviceAttestation> => {
    const response = await api.post('/devices/attest', deviceData)
    return response.data
  },

  verifyDevice: async (deviceId: string): Promise<DeviceAttestation> => {
    const response = await api.post(`/devices/${deviceId}/verify`)
    return response.data
  },
}

export const healthAPI = {
  getSystemHealth: async (): Promise<{ status: string; services: Record<string, string> }> => {
    const response = await api.get('/health')
    return response.data
  },
}

// Admin APIs for role and user management
export const adminAPI = {
  // Role management
  getRoles: async (): Promise<Role[]> => {
    const response = await api.get('/admin/roles')
    return response.data
  },

  createRole: async (role: { name: string; description: string }): Promise<Role> => {
    const response = await api.post('/admin/roles', role)
    return response.data
  },

  updateRole: async (id: number, role: { name?: string; description?: string; is_active?: boolean }): Promise<Role> => {
    const response = await api.put(`/admin/roles/${id}`, role)
    return response.data
  },

  deleteRole: async (id: number): Promise<void> => {
    await api.delete(`/admin/roles/${id}`)
  },

  // Permission management
  getPermissions: async (): Promise<Permission[]> => {
    const response = await api.get('/admin/permissions')
    return response.data
  },

  // Role-Permission assignments
  assignPermissionToRole: async (roleId: number, permissionId: number): Promise<void> => {
    await api.post(`/admin/roles/${roleId}/permissions/${permissionId}`)
  },

  removePermissionFromRole: async (roleId: number, permissionId: number): Promise<void> => {
    await api.delete(`/admin/roles/${roleId}/permissions/${permissionId}`)
  },

  // User management
  getUsers: async (): Promise<UserWithRoles[]> => {
    const response = await api.get('/admin/users')
    return response.data
  },

  getUserById: async (id: number): Promise<UserWithRoles> => {
    const response = await api.get(`/admin/users/${id}`)
    return response.data
  },

  updateUser: async (id: number, user: { 
    username?: string; 
    email?: string; 
    first_name?: string; 
    last_name?: string; 
    is_active?: boolean; 
    is_admin?: boolean 
  }): Promise<User> => {
    const response = await api.put(`/admin/users/${id}`, user)
    return response.data
  },

  deleteUser: async (id: number): Promise<void> => {
    await api.delete(`/admin/users/${id}`)
  },

  // User-Role assignments
  assignRoleToUser: async (userId: number, roleId: number): Promise<void> => {
    await api.post(`/admin/users/${userId}/roles/${roleId}`)
  },

  removeRoleFromUser: async (userId: number, roleId: number): Promise<void> => {
    await api.delete(`/admin/users/${userId}/roles/${roleId}`)
  },
}

export default api