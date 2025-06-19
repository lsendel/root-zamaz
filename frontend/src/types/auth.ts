export interface User {
  id: string
  username: string
  email: string
  first_name?: string
  last_name?: string
  is_active: boolean
  is_admin: boolean
  created_at: string
  updated_at: string
  roles?: string[]
}

export interface LoginCredentials {
  username: string
  password: string
}

export interface RegisterCredentials {
  username: string
  email: string
  password: string
  first_name?: string
  last_name?: string
}

export interface AuthResponse {
  user: User
  token: string
  refresh_token: string
  expires_at: string
}

export interface Role {
  id: string
  name: string
  description: string
  is_active: boolean
  created_at: string
  updated_at: string
  permissions?: Permission[]
}

export interface Permission {
  id: string
  name: string
  resource: string
  action: string
  description: string
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface UserWithRoles extends Omit<User, 'roles'> {
  roles: Role[]
}

export interface DeviceAttestation {
  id: string
  deviceId: string
  trustLevel: number
  isVerified: boolean
  attestationData: Record<string, any>
  verifiedAt?: string
}

export interface Session {
  id: string
  sessionToken: string
  expiresAt: string
  lastAccessed: string
}