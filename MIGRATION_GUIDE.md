# API Client Migration Guide

This guide helps you migrate from the old duplicate API clients (`api.ts` and `api-enhanced.ts`) to the new unified API client system.

## Overview

The new unified API client system provides:
- ✅ Consolidated API client with circuit breaker pattern
- ✅ Automatic retry logic with exponential backoff
- ✅ Token refresh automation
- ✅ Comprehensive error handling
- ✅ TypeScript type safety
- ✅ Service-oriented architecture

## Migration Steps

### 1. Update Import Statements

**Old way:**
```typescript
// Before - Multiple imports from different files
import { authApi, adminAPI, deviceAPI, healthAPI } from '../services/api'
import { authApi as enhancedAuthApi } from '../services/api-enhanced'
```

**New way:**
```typescript
// After - Clean service imports
import { authService, adminService, deviceService, healthService } from '../services'
```

### 2. Update API Call Patterns

#### Authentication Calls

**Old way:**
```typescript
// Old api.ts pattern
const response = await authApi.login(credentials)
const user = response.data

// Old api-enhanced.ts pattern  
const data = await authApi.login(credentials)
const user = data.data
```

**New way:**
```typescript
// New unified pattern
const response = await authService.login(credentials)
const user = response.data // Consistent ApiResponse<T> format
```

#### Admin Operations

**Old way:**
```typescript
// Old pattern
const roles = await adminAPI.getRoles()
const newRole = await adminAPI.createRole({ name: 'manager', description: 'Manager role' })
```

**New way:**
```typescript
// New pattern with better error handling
try {
  const rolesResponse = await adminService.getRoles()
  const roles = rolesResponse.data
  
  const newRoleResponse = await adminService.createRole({ 
    name: 'manager', 
    description: 'Manager role' 
  })
  const newRole = newRoleResponse.data
} catch (error) {
  // Standardized error format
  console.error('API Error:', error.message)
  console.error('Request ID:', error.request_id)
}
```

#### Device Management

**Old way:**
```typescript
const devices = await deviceAPI.getDevices()
const attestation = await deviceAPI.attestDevice(deviceData)
```

**New way:**
```typescript
const devicesResponse = await deviceService.getDevices()
const devices = devicesResponse.data

const attestationResponse = await deviceService.attestDevice(deviceData)
const attestation = attestationResponse.data
```

### 3. Update Error Handling

**Old way:**
```typescript
try {
  const user = await authApi.getCurrentUser()
} catch (error) {
  if (error.response?.status === 401) {
    // Handle auth error
  }
  console.error(error.message)
}
```

**New way:**
```typescript
try {
  const response = await authService.getCurrentUser()
  const user = response.data
} catch (error) {
  // Standardized error format with more details
  console.error('Error code:', error.code)
  console.error('Message:', error.message)
  console.error('Request ID:', error.request_id)
  console.error('Field errors:', error.fields)
}
```

### 4. Update Component Patterns

#### React Component Migration

**Old way:**
```typescript
const UserProfile = () => {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const userData = await authApi.getCurrentUser()
        setUser(userData)
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }
    fetchUser()
  }, [])

  if (loading) return <div>Loading...</div>
  if (error) return <div>Error: {error}</div>
  
  return <div>Welcome, {user?.name}</div>
}
```

**New way:**
```typescript
const UserProfile = () => {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const response = await authService.getCurrentUser()
        setUser(response.data)
      } catch (err) {
        setError(err.message)
        // Automatic token refresh is handled by the client
        // Circuit breaker provides resilience
      } finally {
        setLoading(false)
      }
    }
    fetchUser()
  }, [])

  if (loading) return <div>Loading...</div>
  if (error) return <div>Error: {error}</div>
  
  return <div>Welcome, {user?.name}</div>
}
```

### 5. Update Configuration

**Old way:**
```typescript
// Multiple configurations to maintain
const config = apiConfig.getConfig()
const api = axios.create({ baseURL: config.baseURL })
```

**New way:**
```typescript
// Single configuration in api-client.ts
import { apiClient } from '../services'

// Configuration is handled automatically
// Circuit breaker, retries, and error handling are built-in
```

## Advanced Features

### Circuit Breaker Monitoring

```typescript
// Check circuit breaker state
const circuitState = apiClient.getCircuitBreakerState()
console.log('Circuit breaker state:', circuitState.state)
console.log('Failure count:', circuitState.failure_count)
```

### Custom Request Options

```typescript
// Use custom timeout and retry settings
const response = await authService.login(credentials, {
  timeout: 5000,
  retries: 1,
  retry_delay: 500
})
```

### Request Cancellation

```typescript
// Cancel requests using AbortController
const controller = new AbortController()

const response = await authService.getCurrentUser({
  signal: controller.signal
})

// Cancel if needed
controller.abort()
```

## Breaking Changes

### 1. Response Format

All API responses now follow a consistent format:

```typescript
interface ApiResponse<T> {
  data: T
  success: boolean
  timestamp: string
  request_id?: string
  message?: string
}
```

### 2. Error Format

Errors now have a standardized structure:

```typescript
interface ApiError {
  code: string
  message: string
  details?: Record<string, any>
  fields?: Record<string, string>
  request_id?: string
}
```

### 3. Service Methods

Some methods have been renamed for consistency:

- `authAPI.getCurrentUser()` → `authService.getCurrentUser()`
- `adminAPI.getRoles()` → `adminService.getRoles()`
- `deviceAPI.getDevices()` → `deviceService.getDevices()`

## Migration Checklist

- [ ] Update all import statements to use new services
- [ ] Change API call patterns to use new response format
- [ ] Update error handling to use standardized error format
- [ ] Test authentication flows with automatic token refresh
- [ ] Verify circuit breaker behavior under failure conditions
- [ ] Update TypeScript types if using custom interfaces
- [ ] Remove old `api.ts` and `api-enhanced.ts` files
- [ ] Update tests to use new service interfaces

## Benefits After Migration

1. **Reliability**: Circuit breaker pattern prevents cascade failures
2. **Performance**: Automatic retry with exponential backoff
3. **Security**: Automatic token refresh and secure storage
4. **Debugging**: Request IDs for tracing and error correlation
5. **Type Safety**: Comprehensive TypeScript types
6. **Maintainability**: Single source of truth for API configuration
7. **Monitoring**: Built-in metrics and health checking

## Rollback Plan

If issues arise during migration:

1. Keep old files temporarily: `api.ts.backup` and `api-enhanced.ts.backup`
2. Update imports back to old services
3. Investigate and fix issues with new system
4. Re-attempt migration with fixes

## Support

For questions or issues during migration:

1. Check the TypeScript compiler errors for type mismatches
2. Review the console for circuit breaker status messages
3. Use the browser's Network tab to verify API calls
4. Check the `request_id` in error messages for correlation