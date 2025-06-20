export interface User {
  id: string
  email: string
  username: string
  first_name: string
  last_name: string
  is_active: boolean
  is_admin: boolean
  created_at: string
  updated_at: string
  last_login_at?: string
  last_login_ip?: string
  failed_login_attempts: number
  account_locked_until?: string
  mfa_enabled: boolean
  roles?: string[]
}

export interface LoginCredentials {
  username: string
  password: string
  device_id?: string
}

export interface LoginRequest {
  username: string
  password: string
  device_id?: string
}

export interface LoginResponse {
  user: User
  token: string
  expires_at: string
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

export interface RefreshTokenResponse {
  token: string
  user: User
  expires_at: string
}

export interface AuthError {
  message: string
  code?: string
  details?: Record<string, any>
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