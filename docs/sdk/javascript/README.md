# JavaScript/TypeScript SDK for MVP Zero Trust Authentication

The JavaScript/TypeScript SDK provides a modern, type-safe interface for integrating with the MVP Zero Trust Authentication system. It works in both browser and Node.js environments with full TypeScript support.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Authentication](#authentication)
- [Token Management](#token-management)
- [User Management](#user-management)
- [OAuth Integration](#oauth-integration)
- [React Integration](#react-integration)
- [Vue.js Integration](#vuejs-integration)
- [Node.js Backend Integration](#nodejs-backend-integration)
- [Error Handling](#error-handling)
- [Utilities](#utilities)
- [API Reference](#api-reference)

## Installation

### NPM

```bash
npm install @mvp/zerotrust-sdk
```

### Yarn

```bash
yarn add @mvp/zerotrust-sdk
```

### CDN (Browser)

```html
<script src="https://unpkg.com/@mvp/zerotrust-sdk@latest/dist/index.min.js"></script>
```

## Quick Start

### TypeScript/ES6

```typescript
import { ZeroTrustClient } from '@mvp/zerotrust-sdk';

const client = new ZeroTrustClient({
  baseURL: 'https://auth.example.com',
  apiKey: 'your-api-key',
  timeout: 30000,
  debug: true
});

// Test connection
async function initialize() {
  try {
    await client.healthCheck();
    console.log('✅ Connected to Zero Trust Auth service!');
  } catch (error) {
    console.error('❌ Connection failed:', error);
  }
}

initialize();
```

### CommonJS (Node.js)

```javascript
const { ZeroTrustClient } = require('@mvp/zerotrust-sdk');

const client = new ZeroTrustClient({
  baseURL: 'https://auth.example.com',
  apiKey: 'your-api-key'
});
```

### Browser (Global)

```html
<script src="https://unpkg.com/@mvp/zerotrust-sdk@latest/dist/index.min.js"></script>
<script>
  const client = new ZeroTrust.ZeroTrustClient({
    baseURL: 'https://auth.example.com',
    apiKey: 'your-api-key'
  });
</script>
```

## Authentication

### User Login

```typescript
import { ZeroTrustClient, AuthenticationRequest } from '@mvp/zerotrust-sdk';

const client = new ZeroTrustClient({
  baseURL: 'https://auth.example.com',
  apiKey: 'your-api-key'
});

async function login(email: string, password: string) {
  try {
    const response = await client.authenticate({
      email,
      password,
      remember: true
    });

    if (response.requiresMFA) {
      console.log('MFA required:', response.mfaChallenge);
      // Handle MFA flow
      return { requiresMFA: true, challenge: response.mfaChallenge };
    }

    console.log('✅ Login successful!');
    console.log('Access Token:', response.accessToken);
    console.log('User:', response.user.displayName);
    console.log('Trust Score:', response.trustScore);

    // Store tokens securely
    localStorage.setItem('accessToken', response.accessToken);
    localStorage.setItem('refreshToken', response.refreshToken);
    
    return response;
  } catch (error) {
    console.error('❌ Login failed:', error);
    throw error;
  }
}

// Usage
login('user@example.com', 'secure-password');
```

### Token Validation

```typescript
async function validateToken(token: string) {
  try {
    const response = await client.validateToken({
      token,
      requiredScopes: ['read:profile', 'write:profile']
    });

    if (!response.valid) {
      console.log('❌ Token is invalid');
      return false;
    }

    console.log('✅ Token is valid!');
    console.log('User ID:', response.claims?.sub);
    console.log('Email:', response.claims?.email);
    console.log('Roles:', response.claims?.roles);
    console.log('Trust Score:', response.trustScore);
    
    return true;
  } catch (error) {
    console.error('Token validation error:', error);
    return false;
  }
}
```

### Token Refresh

```typescript
async function refreshAccessToken(refreshToken: string) {
  try {
    const response = await client.refreshToken({
      refreshToken
    });

    console.log('✅ Token refreshed successfully!');
    
    // Update stored tokens
    localStorage.setItem('accessToken', response.accessToken);
    localStorage.setItem('refreshToken', response.refreshToken);
    
    return response;
  } catch (error) {
    console.error('❌ Token refresh failed:', error);
    // Redirect to login
    throw error;
  }
}
```

### Logout

```typescript
async function logout(token?: string) {
  try {
    await client.logout({
      token: token || localStorage.getItem('accessToken'),
      everywhere: true // Logout from all devices
    });

    // Clear stored tokens
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    
    console.log('✅ Logged out successfully');
  } catch (error) {
    console.error('Logout error:', error);
  }
}
```

## Token Management

### Automatic Token Refresh

```typescript
import { ZeroTrustUtils } from '@mvp/zerotrust-sdk';

class TokenManager {
  private client: ZeroTrustClient;
  private refreshTimeout?: NodeJS.Timeout;

  constructor(client: ZeroTrustClient) {
    this.client = client;
  }

  async getValidToken(): Promise<string | null> {
    const accessToken = localStorage.getItem('accessToken');
    const refreshToken = localStorage.getItem('refreshToken');
    const expiresAt = localStorage.getItem('tokenExpiresAt');

    if (!accessToken || !expiresAt) {
      return null;
    }

    // Check if token is expiring soon (within 5 minutes)
    if (ZeroTrustUtils.isTokenExpiringSoon(expiresAt, 300)) {
      if (!refreshToken) {
        return null;
      }

      try {
        const response = await this.client.refreshToken({ refreshToken });
        
        localStorage.setItem('accessToken', response.accessToken);
        localStorage.setItem('refreshToken', response.refreshToken);
        localStorage.setItem('tokenExpiresAt', response.expiresAt);
        
        this.scheduleRefresh(response.expiresAt);
        return response.accessToken;
      } catch (error) {
        console.error('Token refresh failed:', error);
        this.clearTokens();
        return null;
      }
    }

    return accessToken;
  }

  scheduleRefresh(expiresAt: string) {
    if (this.refreshTimeout) {
      clearTimeout(this.refreshTimeout);
    }

    const expiryTime = new Date(expiresAt).getTime();
    const now = Date.now();
    const refreshTime = expiryTime - now - (5 * 60 * 1000); // 5 minutes before expiry

    if (refreshTime > 0) {
      this.refreshTimeout = setTimeout(() => {
        this.getValidToken();
      }, refreshTime);
    }
  }

  clearTokens() {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('tokenExpiresAt');
    
    if (this.refreshTimeout) {
      clearTimeout(this.refreshTimeout);
    }
  }
}

// Usage
const tokenManager = new TokenManager(client);

async function makeAuthenticatedRequest(url: string) {
  const token = await tokenManager.getValidToken();
  if (!token) {
    throw new Error('No valid token available');
  }

  return fetch(url, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
}
```

## User Management

### Get User Profile

```typescript
async function getUserProfile() {
  const token = localStorage.getItem('accessToken');
  if (!token) {
    throw new Error('No access token available');
  }

  try {
    const user = await client.getUserProfile(token);
    
    console.log('User Profile:');
    console.log('  ID:', user.id);
    console.log('  Email:', user.email);
    console.log('  Name:', `${user.firstName} ${user.lastName}`);
    console.log('  Display Name:', user.displayName);
    console.log('  Roles:', user.roles);
    console.log('  Trust Score:', user.trustScore);
    console.log('  Active:', user.isActive);
    console.log('  Verified:', user.isVerified);
    console.log('  MFA Enabled:', user.mfaEnabled);
    
    return user;
  } catch (error) {
    console.error('Failed to get user profile:', error);
    throw error;
  }
}
```

### Update User Profile

```typescript
async function updateUserProfile(updates: Partial<User>) {
  const token = localStorage.getItem('accessToken');
  if (!token) {
    throw new Error('No access token available');
  }

  try {
    const updatedUser = await client.updateUserProfile(token, updates);
    
    console.log('✅ Profile updated successfully!');
    console.log('Updated Name:', updatedUser.displayName);
    
    return updatedUser;
  } catch (error) {
    console.error('Failed to update profile:', error);
    throw error;
  }
}

// Usage
updateUserProfile({
  firstName: 'John',
  lastName: 'Doe',
  displayName: 'John Doe',
  metadata: {
    department: 'Engineering',
    location: 'San Francisco'
  }
});
```

## OAuth Integration

### OAuth Flow Implementation

```typescript
import { ZeroTrustUtils } from '@mvp/zerotrust-sdk';

class OAuthManager {
  private clientId: string;
  private redirectUri: string;
  private baseUrl: string;

  constructor(clientId: string, redirectUri: string, baseUrl: string) {
    this.clientId = clientId;
    this.redirectUri = redirectUri;
    this.baseUrl = baseUrl;
  }

  async initiateOAuthFlow(scopes: string[] = []): Promise<string> {
    // Generate state and PKCE parameters
    const state = ZeroTrustUtils.generateState();
    const codeVerifier = ZeroTrustUtils.generateCodeVerifier();
    const codeChallenge = await ZeroTrustUtils.generateCodeChallenge(codeVerifier);

    // Store PKCE verifier and state for later verification
    sessionStorage.setItem('oauth_state', state);
    sessionStorage.setItem('code_verifier', codeVerifier);

    // Build authorization URL
    const authUrl = ZeroTrustUtils.buildAuthURLWithPKCE(
      this.baseUrl,
      this.clientId,
      this.redirectUri,
      state,
      codeChallenge,
      scopes
    );

    // Redirect to authorization server
    window.location.href = authUrl;
    
    return authUrl;
  }

  async handleCallback(): Promise<{ code: string; state: string }> {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    const error = urlParams.get('error');

    if (error) {
      const errorDescription = urlParams.get('error_description');
      throw new Error(`OAuth error: ${error} - ${errorDescription}`);
    }

    if (!code || !state) {
      throw new Error('Authorization code or state missing from callback');
    }

    // Verify state parameter
    const storedState = sessionStorage.getItem('oauth_state');
    if (state !== storedState) {
      throw new Error('State parameter mismatch - possible CSRF attack');
    }

    // Clean up stored parameters
    sessionStorage.removeItem('oauth_state');

    return { code, state };
  }

  getCodeVerifier(): string | null {
    return sessionStorage.getItem('code_verifier');
  }

  clearCodeVerifier(): void {
    sessionStorage.removeItem('code_verifier');
  }
}

// Usage
const oauthManager = new OAuthManager(
  'your-client-id',
  'https://app.example.com/callback',
  'https://auth.example.com'
);

// Initiate OAuth flow
document.getElementById('login-button')?.addEventListener('click', () => {
  oauthManager.initiateOAuthFlow(['read:profile', 'write:profile']);
});

// Handle callback (in your callback page)
async function handleOAuthCallback() {
  try {
    const { code } = await oauthManager.handleCallback();
    const codeVerifier = oauthManager.getCodeVerifier();
    
    if (!codeVerifier) {
      throw new Error('Code verifier not found');
    }

    // Exchange code for tokens (implement token exchange endpoint)
    const tokenResponse = await fetch('/api/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code,
        codeVerifier,
        clientId: 'your-client-id',
        redirectUri: 'https://app.example.com/callback'
      })
    });

    const tokens = await tokenResponse.json();
    
    // Store tokens
    localStorage.setItem('accessToken', tokens.accessToken);
    localStorage.setItem('refreshToken', tokens.refreshToken);
    
    oauthManager.clearCodeVerifier();
    
    // Redirect to app
    window.location.href = '/dashboard';
  } catch (error) {
    console.error('OAuth callback error:', error);
  }
}
```

## React Integration

### React Hook for Authentication

```typescript
import React, { createContext, useContext, useEffect, useState } from 'react';
import { ZeroTrustClient, User, AuthenticationResponse } from '@mvp/zerotrust-sdk';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<AuthenticationResponse>;
  logout: () => Promise<void>;
  refreshToken: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: React.ReactNode;
  client: ZeroTrustClient;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children, client }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const isAuthenticated = !!user;

  useEffect(() => {
    initializeAuth();
  }, []);

  const initializeAuth = async () => {
    const token = localStorage.getItem('accessToken');
    if (!token) {
      setIsLoading(false);
      return;
    }

    try {
      const validationResponse = await client.validateToken({ token });
      if (validationResponse.valid) {
        const userProfile = await client.getUserProfile(token);
        setUser(userProfile);
      } else {
        localStorage.removeItem('accessToken');
        localStorage.removeItem('refreshToken');
      }
    } catch (error) {
      console.error('Auth initialization error:', error);
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (email: string, password: string): Promise<AuthenticationResponse> => {
    setIsLoading(true);
    try {
      const response = await client.authenticate({ email, password });
      
      if (!response.requiresMFA) {
        localStorage.setItem('accessToken', response.accessToken);
        localStorage.setItem('refreshToken', response.refreshToken);
        setUser(response.user);
      }
      
      return response;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    setIsLoading(true);
    try {
      const token = localStorage.getItem('accessToken');
      if (token) {
        await client.logout({ token });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');
      setUser(null);
      setIsLoading(false);
    }
  };

  const refreshToken = async () => {
    const refreshTokenValue = localStorage.getItem('refreshToken');
    if (!refreshTokenValue) {
      throw new Error('No refresh token available');
    }

    try {
      const response = await client.refreshToken({ refreshToken: refreshTokenValue });
      localStorage.setItem('accessToken', response.accessToken);
      localStorage.setItem('refreshToken', response.refreshToken);
    } catch (error) {
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');
      setUser(null);
      throw error;
    }
  };

  const value: AuthContextType = {
    user,
    isAuthenticated,
    isLoading,
    login,
    logout,
    refreshToken
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
```

### Login Component

```typescript
import React, { useState } from 'react';
import { useAuth } from './AuthProvider';

const LoginForm: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  
  const { login } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      const response = await login(email, password);
      
      if (response.requiresMFA) {
        // Handle MFA flow
        console.log('MFA required:', response.mfaChallenge);
      } else {
        console.log('Login successful!');
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Login failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label htmlFor="email" className="block text-sm font-medium text-gray-700">
          Email
        </label>
        <input
          id="email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md"
        />
      </div>
      
      <div>
        <label htmlFor="password" className="block text-sm font-medium text-gray-700">
          Password
        </label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md"
        />
      </div>

      {error && (
        <div className="text-red-600 text-sm">{error}</div>
      )}

      <button
        type="submit"
        disabled={isLoading}
        className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50"
      >
        {isLoading ? 'Signing in...' : 'Sign in'}
      </button>
    </form>
  );
};

export default LoginForm;
```

### Protected Route Component

```typescript
import React from 'react';
import { useAuth } from './AuthProvider';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRoles?: string[];
  fallback?: React.ReactNode;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  requiredRoles = [],
  fallback = <div>Access denied</div>
}) => {
  const { user, isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    return <div>Please log in to access this page</div>;
  }

  if (requiredRoles.length > 0 && user) {
    const hasRequiredRole = requiredRoles.some(role => user.roles.includes(role));
    if (!hasRequiredRole) {
      return fallback;
    }
  }

  return <>{children}</>;
};

export default ProtectedRoute;
```

## Vue.js Integration

### Vue Composition API

```typescript
import { ref, computed, onMounted } from 'vue';
import { ZeroTrustClient, User } from '@mvp/zerotrust-sdk';

const client = new ZeroTrustClient({
  baseURL: 'https://auth.example.com',
  apiKey: 'your-api-key'
});

export function useAuth() {
  const user = ref<User | null>(null);
  const isLoading = ref(false);
  const error = ref<string | null>(null);

  const isAuthenticated = computed(() => !!user.value);

  onMounted(() => {
    initializeAuth();
  });

  const initializeAuth = async () => {
    const token = localStorage.getItem('accessToken');
    if (!token) return;

    try {
      isLoading.value = true;
      const validationResponse = await client.validateToken({ token });
      
      if (validationResponse.valid) {
        const userProfile = await client.getUserProfile(token);
        user.value = userProfile;
      } else {
        clearTokens();
      }
    } catch (err) {
      console.error('Auth initialization error:', err);
      clearTokens();
    } finally {
      isLoading.value = false;
    }
  };

  const login = async (email: string, password: string) => {
    try {
      isLoading.value = true;
      error.value = null;
      
      const response = await client.authenticate({ email, password });
      
      if (!response.requiresMFA) {
        localStorage.setItem('accessToken', response.accessToken);
        localStorage.setItem('refreshToken', response.refreshToken);
        user.value = response.user;
      }
      
      return response;
    } catch (err) {
      error.value = err instanceof Error ? err.message : 'Login failed';
      throw err;
    } finally {
      isLoading.value = false;
    }
  };

  const logout = async () => {
    try {
      const token = localStorage.getItem('accessToken');
      if (token) {
        await client.logout({ token });
      }
    } finally {
      clearTokens();
      user.value = null;
    }
  };

  const clearTokens = () => {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
  };

  return {
    user: readonly(user),
    isAuthenticated,
    isLoading: readonly(isLoading),
    error: readonly(error),
    login,
    logout
  };
}
```

## Node.js Backend Integration

### Express.js Middleware

```typescript
import express, { Request, Response, NextFunction } from 'express';
import { ZeroTrustClient, Claims } from '@mvp/zerotrust-sdk';

const client = new ZeroTrustClient({
  baseURL: 'https://auth.example.com',
  apiKey: 'your-api-key'
});

interface AuthenticatedRequest extends Request {
  claims?: Claims;
  userId?: string;
}

// Authentication middleware
export const authenticate = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  const token = extractBearerToken(req);
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const response = await client.validateToken({ token });
    
    if (!response.valid) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.claims = response.claims;
    req.userId = response.claims?.sub;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(401).json({ error: 'Authentication failed' });
  }
};

// Role-based authorization middleware
export const requireRoles = (requiredRoles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.claims) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const userRoles = req.claims.roles || [];
    const hasRequiredRole = requiredRoles.some(role => userRoles.includes(role));

    if (!hasRequiredRole) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        required: requiredRoles,
        current: userRoles
      });
    }

    next();
  };
};

function extractBearerToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (!authHeader) return null;
  
  const match = authHeader.match(/^Bearer (.+)$/);
  return match ? match[1] : null;
}

// Usage
const app = express();

// Public routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const response = await client.authenticate({ email, password });
    res.json(response);
  } catch (error) {
    res.status(401).json({ error: 'Authentication failed' });
  }
});

// Protected routes
app.get('/api/profile', authenticate, async (req: AuthenticatedRequest, res) => {
  try {
    const token = extractBearerToken(req);
    const user = await client.getUserProfile(token!);
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get profile' });
  }
});

// Admin-only routes
app.get('/api/admin/users', 
  authenticate, 
  requireRoles(['admin']), 
  (req, res) => {
    res.json({ message: 'Admin access granted' });
  }
);
```

## Error Handling

### Comprehensive Error Handling

```typescript
import { ZeroTrustAPIError, ZeroTrustUtils } from '@mvp/zerotrust-sdk';

class AuthService {
  private client: ZeroTrustClient;

  constructor(client: ZeroTrustClient) {
    this.client = client;
  }

  async authenticateWithRetry(email: string, password: string, maxRetries = 3) {
    let lastError: Error;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await this.client.authenticate({ email, password });
      } catch (error) {
        lastError = error as Error;

        // Don't retry authentication errors
        if (ZeroTrustUtils.isAuthenticationError(error as Error)) {
          throw error;
        }

        // Only retry if error is retryable
        if (!ZeroTrustUtils.isRetryableError(error as Error)) {
          throw error;
        }

        if (attempt < maxRetries) {
          const delay = Math.min(1000 * Math.pow(2, attempt - 1), 10000);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    throw new Error(`Authentication failed after ${maxRetries} attempts: ${lastError.message}`);
  }

  handleAuthError(error: Error): string {
    if (error instanceof ZeroTrustAPIError) {
      switch (error.code) {
        case 'INVALID_CREDENTIALS':
          return 'Invalid email or password';
        case 'ACCOUNT_LOCKED':
          return 'Account is temporarily locked. Please try again later.';
        case 'MFA_REQUIRED':
          return 'Multi-factor authentication is required';
        case 'RATE_LIMITED':
          return 'Too many attempts. Please wait before trying again.';
        default:
          return error.message;
      }
    }

    return 'An unexpected error occurred. Please try again.';
  }
}

// Usage
const authService = new AuthService(client);

async function loginWithErrorHandling(email: string, password: string) {
  try {
    const response = await authService.authenticateWithRetry(email, password);
    console.log('Login successful:', response);
    return response;
  } catch (error) {
    const errorMessage = authService.handleAuthError(error as Error);
    console.error('Login error:', errorMessage);
    throw new Error(errorMessage);
  }
}
```

## Utilities

### Email and Security Utilities

```typescript
import { ZeroTrustUtils } from '@mvp/zerotrust-sdk';

// Email validation
const email = '  USER@EXAMPLE.COM  ';
const sanitizedEmail = ZeroTrustUtils.sanitizeEmail(email);
const isValid = ZeroTrustUtils.validateEmail(sanitizedEmail);
console.log(`Sanitized: ${sanitizedEmail}, Valid: ${isValid}`);

// Token expiration checking
const expiresAt = '2024-12-31T23:59:59Z';
const isExpired = ZeroTrustUtils.isTokenExpired(expiresAt);
const expiringSoon = ZeroTrustUtils.isTokenExpiringSoon(expiresAt, 300); // 5 minutes
console.log(`Expired: ${isExpired}, Expiring soon: ${expiringSoon}`);

// OAuth state and PKCE generation
const state = ZeroTrustUtils.generateState();
const verifier = ZeroTrustUtils.generateCodeVerifier();
const challenge = await ZeroTrustUtils.generateCodeChallenge(verifier);
console.log('OAuth State:', state);
console.log('PKCE Verifier:', verifier);
console.log('PKCE Challenge:', challenge);

// Error classification
try {
  await client.authenticate({ email: 'invalid', password: 'wrong' });
} catch (error) {
  const isAuthError = ZeroTrustUtils.isAuthenticationError(error as Error);
  const isRetryable = ZeroTrustUtils.isRetryableError(error as Error);
  console.log(`Auth error: ${isAuthError}, Retryable: ${isRetryable}`);
}
```

## API Reference

### Client Configuration

```typescript
interface ClientConfig {
  baseURL: string;        // Required: Base URL of the auth service
  apiKey: string;         // Required: API key for authentication
  timeout?: number;       // Request timeout in milliseconds (default: 30000)
  maxRetries?: number;    // Max retry attempts (default: 3)
  retryDelay?: number;    // Delay between retries in milliseconds (default: 1000)
  fetch?: typeof fetch;   // Custom fetch implementation
  debug?: boolean;        // Enable debug logging
}
```

### Authentication Methods

```typescript
// Authenticate user
authenticate(request: AuthenticationRequest): Promise<AuthenticationResponse>

// Validate token
validateToken(request: TokenValidationRequest): Promise<TokenValidationResponse>

// Refresh token
refreshToken(request: RefreshTokenRequest): Promise<AuthenticationResponse>

// Logout user
logout(request: LogoutRequest): Promise<void>

// Health check
healthCheck(): Promise<void>
```

### User Management Methods

```typescript
// Get user profile
getUserProfile(token: string): Promise<User>

// Update user profile
updateUserProfile(token: string, user: Partial<User>): Promise<User>
```

### Utility Methods

```typescript
// Token utilities
static isTokenExpired(expiresAt: string): boolean
static isTokenExpiringSoon(expiresAt: string, thresholdSeconds: number): boolean
static generateState(): string
static generateCodeVerifier(): string
static generateCodeChallenge(verifier: string): Promise<string>

// URL utilities
static buildAuthURL(baseURL: string, clientId: string, redirectURI: string, state: string, scopes?: string[]): string
static buildAuthURLWithPKCE(baseURL: string, clientId: string, redirectURI: string, state: string, codeChallenge: string, scopes?: string[]): string
static extractAuthCode(callbackURL: string): { code: string; state: string }

// Security utilities
static sanitizeEmail(email: string): string
static validateEmail(email: string): boolean
static isAuthenticationError(error: Error): boolean
static isRetryableError(error: Error): boolean
```

For complete TypeScript type definitions, see the [type definitions file](./types.d.ts).