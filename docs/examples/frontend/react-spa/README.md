# React SPA with Zero Trust Authentication

This example demonstrates how to integrate Zero Trust Authentication into a React Single Page Application (SPA) using modern React patterns with hooks and context.

## Features

- ✅ User authentication with login/logout
- ✅ Protected routes with role-based access
- ✅ Automatic token refresh
- ✅ Loading states and error handling
- ✅ TypeScript support
- ✅ Material-UI components
- ✅ JWT token management
- ✅ Responsive design

## Prerequisites

- Node.js 18+ and npm/yarn
- Zero Trust Auth service running
- Basic React knowledge

## Quick Start

```bash
# Clone and setup
npx create-react-app zerotrust-spa --template typescript
cd zerotrust-spa

# Install dependencies
npm install @mvp/zerotrust-sdk @mui/material @emotion/react @emotion/styled
npm install @mui/icons-material react-router-dom

# Copy example files (see below)
# Start development server
npm start
```

## Project Structure

```
src/
├── components/
│   ├── Auth/
│   │   ├── LoginForm.tsx
│   │   ├── LogoutButton.tsx
│   │   └── ProtectedRoute.tsx
│   ├── Layout/
│   │   ├── AppBar.tsx
│   │   ├── Navigation.tsx
│   │   └── Layout.tsx
│   └── Pages/
│       ├── Dashboard.tsx
│       ├── Profile.tsx
│       └── AdminPanel.tsx
├── contexts/
│   └── AuthContext.tsx
├── hooks/
│   ├── useAuth.ts
│   └── useApi.ts
├── services/
│   ├── authService.ts
│   └── apiClient.ts
├── utils/
│   ├── tokenManager.ts
│   └── constants.ts
├── App.tsx
└── index.tsx
```

## Core Implementation

### Authentication Context

```typescript
// src/contexts/AuthContext.tsx
import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { ZeroTrustClient, User, AuthenticationResponse } from '@mvp/zerotrust-sdk';
import { authService } from '../services/authService';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<AuthenticationResponse>;
  logout: () => Promise<void>;
  clearError: () => void;
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
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const isAuthenticated = !!user;

  useEffect(() => {
    initializeAuth();
  }, []);

  const initializeAuth = async () => {
    try {
      setIsLoading(true);
      const currentUser = await authService.getCurrentUser();
      setUser(currentUser);
    } catch (err) {
      console.error('Auth initialization failed:', err);
      // Clear invalid tokens
      authService.clearTokens();
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (email: string, password: string): Promise<AuthenticationResponse> => {
    try {
      setIsLoading(true);
      setError(null);
      
      const response = await authService.login(email, password);
      
      if (!response.requiresMFA) {
        setUser(response.user);
      }
      
      return response;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Login failed';
      setError(errorMessage);
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    try {
      setIsLoading(true);
      await authService.logout();
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      setUser(null);
      setIsLoading(false);
    }
  };

  const clearError = () => setError(null);

  const value: AuthContextType = {
    user,
    isAuthenticated,
    isLoading,
    error,
    login,
    logout,
    clearError
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
```

### Authentication Service

```typescript
// src/services/authService.ts
import { ZeroTrustClient, User, AuthenticationResponse } from '@mvp/zerotrust-sdk';
import { tokenManager } from '../utils/tokenManager';

class AuthService {
  private client: ZeroTrustClient;

  constructor() {
    this.client = new ZeroTrustClient({
      baseURL: process.env.REACT_APP_AUTH_BASE_URL || 'http://localhost:8080',
      apiKey: process.env.REACT_APP_AUTH_API_KEY || 'dev-api-key',
      timeout: 30000
    });
  }

  async login(email: string, password: string): Promise<AuthenticationResponse> {
    const response = await this.client.authenticate({
      email,
      password,
      remember: true
    });

    if (!response.requiresMFA) {
      tokenManager.setTokens(
        response.accessToken,
        response.refreshToken,
        response.expiresAt
      );
    }

    return response;
  }

  async logout(): Promise<void> {
    const token = tokenManager.getAccessToken();
    
    if (token) {
      try {
        await this.client.logout({ token, everywhere: true });
      } catch (error) {
        console.error('Logout API call failed:', error);
      }
    }
    
    tokenManager.clearTokens();
  }

  async getCurrentUser(): Promise<User | null> {
    const token = await tokenManager.getValidToken();
    if (!token) {
      return null;
    }

    try {
      // Validate token first
      const validation = await this.client.validateToken({ token });
      if (!validation.valid) {
        tokenManager.clearTokens();
        return null;
      }

      // Get user profile
      return await this.client.getUserProfile(token);
    } catch (error) {
      console.error('Failed to get current user:', error);
      tokenManager.clearTokens();
      return null;
    }
  }

  async refreshToken(): Promise<string | null> {
    const refreshToken = tokenManager.getRefreshToken();
    if (!refreshToken) {
      return null;
    }

    try {
      const response = await this.client.refreshToken({ refreshToken });
      
      tokenManager.setTokens(
        response.accessToken,
        response.refreshToken,
        response.expiresAt
      );
      
      return response.accessToken;
    } catch (error) {
      console.error('Token refresh failed:', error);
      tokenManager.clearTokens();
      return null;
    }
  }

  clearTokens(): void {
    tokenManager.clearTokens();
  }
}

export const authService = new AuthService();
```

### Token Manager

```typescript
// src/utils/tokenManager.ts
import { ZeroTrustUtils } from '@mvp/zerotrust-sdk';
import { authService } from '../services/authService';

class TokenManager {
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private expiresAt: string | null = null;
  private refreshTimeout: NodeJS.Timeout | null = null;

  constructor() {
    this.loadTokensFromStorage();
  }

  setTokens(accessToken: string, refreshToken: string, expiresAt: string): void {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.expiresAt = expiresAt;

    // Store in localStorage
    localStorage.setItem('accessToken', accessToken);
    localStorage.setItem('refreshToken', refreshToken);
    localStorage.setItem('tokenExpiresAt', expiresAt);

    this.scheduleRefresh();
  }

  async getValidToken(): Promise<string | null> {
    if (!this.accessToken || !this.expiresAt) {
      return null;
    }

    // Check if token is expiring soon (within 5 minutes)
    if (ZeroTrustUtils.isTokenExpiringSoon(this.expiresAt, 300)) {
      const newToken = await this.performRefresh();
      return newToken;
    }

    return this.accessToken;
  }

  getAccessToken(): string | null {
    return this.accessToken;
  }

  getRefreshToken(): string | null {
    return this.refreshToken;
  }

  clearTokens(): void {
    this.accessToken = null;
    this.refreshToken = null;
    this.expiresAt = null;

    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('tokenExpiresAt');

    if (this.refreshTimeout) {
      clearTimeout(this.refreshTimeout);
      this.refreshTimeout = null;
    }
  }

  private loadTokensFromStorage(): void {
    this.accessToken = localStorage.getItem('accessToken');
    this.refreshToken = localStorage.getItem('refreshToken');
    this.expiresAt = localStorage.getItem('tokenExpiresAt');

    if (this.expiresAt) {
      this.scheduleRefresh();
    }
  }

  private scheduleRefresh(): void {
    if (this.refreshTimeout) {
      clearTimeout(this.refreshTimeout);
    }

    if (!this.expiresAt) return;

    const expiryTime = new Date(this.expiresAt).getTime();
    const now = Date.now();
    const refreshTime = expiryTime - now - (5 * 60 * 1000); // 5 minutes before expiry

    if (refreshTime > 0) {
      this.refreshTimeout = setTimeout(() => {
        this.performRefresh();
      }, refreshTime);
    }
  }

  private async performRefresh(): Promise<string | null> {
    try {
      return await authService.refreshToken();
    } catch (error) {
      console.error('Automatic token refresh failed:', error);
      this.clearTokens();
      // Optionally redirect to login
      window.location.href = '/login';
      return null;
    }
  }
}

export const tokenManager = new TokenManager();
```

### Login Component

```typescript
// src/components/Auth/LoginForm.tsx
import React, { useState } from 'react';
import {
  Paper,
  TextField,
  Button,
  Typography,
  Alert,
  Box,
  CircularProgress
} from '@mui/material';
import { useAuth } from '../../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';

const LoginForm: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [showMFA, setShowMFA] = useState(false);
  
  const { login, isLoading, error, clearError } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();

    try {
      const response = await login(email, password);
      
      if (response.requiresMFA) {
        setShowMFA(true);
        // Handle MFA flow here
        console.log('MFA required:', response.mfaChallenge);
      } else {
        navigate('/dashboard');
      }
    } catch (err) {
      // Error is handled by context
    }
  };

  return (
    <Paper elevation={3} sx={{ p: 4, maxWidth: 400, mx: 'auto', mt: 8 }}>
      <Typography variant="h4" component="h1" gutterBottom align="center">
        Sign In
      </Typography>
      
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={clearError}>
          {error}
        </Alert>
      )}

      <Box component="form" onSubmit={handleSubmit}>
        <TextField
          fullWidth
          label="Email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          margin="normal"
          required
          disabled={isLoading || showMFA}
        />
        
        <TextField
          fullWidth
          label="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          margin="normal"
          required
          disabled={isLoading || showMFA}
        />

        {showMFA && (
          <TextField
            fullWidth
            label="MFA Code"
            value={mfaCode}
            onChange={(e) => setMfaCode(e.target.value)}
            margin="normal"
            required
            disabled={isLoading}
            placeholder="Enter 6-digit code"
          />
        )}

        <Button
          type="submit"
          fullWidth
          variant="contained"
          sx={{ mt: 3, mb: 2 }}
          disabled={isLoading}
          startIcon={isLoading && <CircularProgress size={20} />}
        >
          {isLoading ? 'Signing In...' : showMFA ? 'Verify MFA' : 'Sign In'}
        </Button>
      </Box>
    </Paper>
  );
};

export default LoginForm;
```

### Protected Route Component

```typescript
// src/components/Auth/ProtectedRoute.tsx
import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { CircularProgress, Box } from '@mui/material';
import { useAuth } from '../../contexts/AuthContext';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRoles?: string[];
  fallback?: React.ReactNode;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  requiredRoles = [],
  fallback
}) => {
  const { isAuthenticated, isLoading, user } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="60vh">
        <CircularProgress />
      </Box>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requiredRoles.length > 0 && user) {
    const hasRequiredRole = requiredRoles.some(role => 
      user.roles.includes(role)
    );
    
    if (!hasRequiredRole) {
      return fallback || (
        <Box p={3}>
          <Typography variant="h6" color="error">
            Access Denied
          </Typography>
          <Typography>
            You don't have permission to access this page.
          </Typography>
        </Box>
      );
    }
  }

  return <>{children}</>;
};

export default ProtectedRoute;
```

### Main App Component

```typescript
// src/App.tsx
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';

import { AuthProvider } from './contexts/AuthContext';
import Layout from './components/Layout/Layout';
import LoginForm from './components/Auth/LoginForm';
import ProtectedRoute from './components/Auth/ProtectedRoute';
import Dashboard from './components/Pages/Dashboard';
import Profile from './components/Pages/Profile';
import AdminPanel from './components/Pages/AdminPanel';

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
});

const App: React.FC = () => {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <AuthProvider>
        <Router>
          <Routes>
            <Route path="/login" element={<LoginForm />} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route
              path="/*"
              element={
                <ProtectedRoute>
                  <Layout>
                    <Routes>
                      <Route path="/dashboard" element={<Dashboard />} />
                      <Route path="/profile" element={<Profile />} />
                      <Route
                        path="/admin"
                        element={
                          <ProtectedRoute requiredRoles={['admin']}>
                            <AdminPanel />
                          </ProtectedRoute>
                        }
                      />
                    </Routes>
                  </Layout>
                </ProtectedRoute>
              }
            />
          </Routes>
        </Router>
      </AuthProvider>
    </ThemeProvider>
  );
};

export default App;
```

## Environment Configuration

```bash
# .env
REACT_APP_AUTH_BASE_URL=https://auth.example.com
REACT_APP_AUTH_API_KEY=your-api-key

# .env.local (for development)
REACT_APP_AUTH_BASE_URL=http://localhost:8080
REACT_APP_AUTH_API_KEY=dev-api-key
```

## Package.json

```json
{
  "name": "zerotrust-react-spa",
  "version": "1.0.0",
  "dependencies": {
    "@mvp/zerotrust-sdk": "^1.0.0",
    "@mui/material": "^5.14.0",
    "@mui/icons-material": "^5.14.0",
    "@emotion/react": "^11.11.0",
    "@emotion/styled": "^11.11.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.15.0",
    "typescript": "^5.0.0"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject"
  },
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ],
    "development": [
      "last 1 chrome version",
      "last 1 firefox version",
      "last 1 safari version"
    ]
  }
}
```

## Testing

```typescript
// src/components/Auth/__tests__/LoginForm.test.tsx
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import LoginForm from '../LoginForm';
import { AuthProvider } from '../../../contexts/AuthContext';

const renderWithProviders = (ui: React.ReactElement) => {
  return render(
    <BrowserRouter>
      <AuthProvider>
        {ui}
      </AuthProvider>
    </BrowserRouter>
  );
};

describe('LoginForm', () => {
  test('renders login form', () => {
    renderWithProviders(<LoginForm />);
    
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
  });

  test('submits form with email and password', async () => {
    renderWithProviders(<LoginForm />);
    
    const emailInput = screen.getByLabelText(/email/i);
    const passwordInput = screen.getByLabelText(/password/i);
    const submitButton = screen.getByRole('button', { name: /sign in/i });

    fireEvent.change(emailInput, { target: { value: 'test@example.com' } });
    fireEvent.change(passwordInput, { target: { value: 'password123' } });
    fireEvent.click(submitButton);

    await waitFor(() => {
      expect(submitButton).toBeDisabled();
    });
  });
});
```

## Deployment

### Build for Production

```bash
# Install dependencies
npm install

# Build optimized bundle
npm run build

# Serve static files
npx serve -s build
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM node:18-alpine as builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

## Best Practices

1. **Security**
   - Store tokens securely
   - Implement automatic token refresh
   - Use HTTPS in production
   - Validate all user inputs

2. **Performance**
   - Implement code splitting
   - Lazy load components
   - Cache API responses
   - Optimize bundle size

3. **User Experience**
   - Show loading states
   - Handle errors gracefully
   - Implement proper navigation
   - Provide clear feedback

4. **Testing**
   - Unit test components
   - Integration test auth flows
   - End-to-end test critical paths
   - Mock external dependencies

## Troubleshooting

### Common Issues

1. **CORS Errors**
   - Configure CORS on the auth service
   - Use proxy in development

2. **Token Refresh Failures**
   - Check refresh token expiration
   - Implement fallback to login

3. **Route Protection Issues**
   - Verify role requirements
   - Check token validation

### Debug Mode

```typescript
// Enable debug logging
const client = new ZeroTrustClient({
  baseURL: process.env.REACT_APP_AUTH_BASE_URL,
  apiKey: process.env.REACT_APP_AUTH_API_KEY,
  debug: process.env.NODE_ENV === 'development'
});
```

For more examples and advanced patterns, see the [examples directory](../) and [SDK documentation](../../sdk/).