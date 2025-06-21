/**
 * Enhanced Authentication Store - Consolidated Auth State Management
 * 
 * Replaces both the existing Zustand store and React Context to provide
 * a single source of truth for authentication with enhanced features.
 */

import { create } from 'zustand';
import { devtools, persist, subscribeWithSelector } from 'zustand/middleware';
import { authService } from '../services';
import type { User, LoginCredentials } from '../types/auth';

// Enhanced auth state interface
interface AuthState {
  // Core state
  user: User | null;
  token: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  
  // Enhanced state
  isInitialized: boolean;
  lastActivity: number;
  tokenExpiry: number | null;
  isRefreshing: boolean;
  
  // User role helpers
  isAdmin: boolean;
  userRoles: string[];
  permissions: string[];
  
  // Actions - Authentication
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => Promise<void>;
  refreshTokens: () => Promise<void>;
  
  // Actions - State management
  setUser: (user: User) => void;
  setTokens: (token: string, refreshToken?: string, expiry?: number) => void;
  clearError: () => void;
  setLoading: (loading: boolean) => void;
  updateLastActivity: () => void;
  
  // Actions - Initialization
  initialize: () => Promise<void>;
  checkTokenExpiry: () => boolean;
  
  // Actions - Security
  clearSensitiveData: () => void;
  validateSession: () => Promise<boolean>;
}

// Token management utilities
const TOKEN_KEY = 'auth_token';
const REFRESH_TOKEN_KEY = 'auth_refresh_token';
const USER_KEY = 'auth_user';

const isTokenExpired = (expiry: number | null): boolean => {
  if (!expiry) return true;
  return Date.now() >= expiry - 60000; // Refresh 1 minute before expiry
};

const parseJWTExpiry = (token: string): number | null => {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.exp ? payload.exp * 1000 : null;
  } catch {
    return null;
  }
};

export const useAuthStore = create<AuthState>()(
  devtools(
    subscribeWithSelector(
      persist(
        (set, get) => ({
          // Initial state
          user: null,
          token: null,
          refreshToken: null,
          isAuthenticated: false,
          isLoading: false,
          error: null,
          isInitialized: false,
          lastActivity: Date.now(),
          tokenExpiry: null,
          isRefreshing: false,
          isAdmin: false,
          userRoles: [],
          permissions: [],

          // Authentication actions
          login: async (credentials: LoginCredentials) => {
            try {
              set({ isLoading: true, error: null });
              
              const response = await authService.login(credentials);
              const { user, token, refreshToken } = response.data;
              
              const tokenExpiry = parseJWTExpiry(token);
              const isAdmin = user.is_admin || user.roles?.some(role => role.name === 'admin') || false;
              const userRoles = user.roles?.map(role => role.name) || [];
              const permissions = user.roles?.flatMap(role => role.permissions?.map(p => p.name) || []) || [];

              // Store tokens securely
              localStorage.setItem(TOKEN_KEY, token);
              if (refreshToken) {
                localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
              }
              localStorage.setItem(USER_KEY, JSON.stringify(user));

              set({
                user,
                token,
                refreshToken,
                tokenExpiry,
                isAuthenticated: true,
                isLoading: false,
                error: null,
                lastActivity: Date.now(),
                isAdmin,
                userRoles,
                permissions,
              });
            } catch (error: any) {
              const errorMessage = error.message || 'Login failed';
              set({
                user: null,
                token: null,
                refreshToken: null,
                isAuthenticated: false,
                isLoading: false,
                error: errorMessage,
                isAdmin: false,
                userRoles: [],
                permissions: [],
              });
              throw error;
            }
          },

          logout: async () => {
            const { token } = get();
            
            try {
              // Attempt to logout on server
              if (token) {
                await authService.logout();
              }
            } catch (error) {
              console.error('Server logout failed:', error);
            } finally {
              // Always clear local state
              get().clearSensitiveData();
            }
          },

          refreshTokens: async () => {
            const { refreshToken, isRefreshing } = get();
            
            if (isRefreshing) {
              return; // Prevent concurrent refresh attempts
            }
            
            if (!refreshToken) {
              throw new Error('No refresh token available');
            }

            try {
              set({ isRefreshing: true, error: null });
              
              const response = await authService.refreshToken();
              const { token: newToken, refreshToken: newRefreshToken, user } = response.data;
              
              const tokenExpiry = parseJWTExpiry(newToken);
              
              // Update stored tokens
              localStorage.setItem(TOKEN_KEY, newToken);
              if (newRefreshToken) {
                localStorage.setItem(REFRESH_TOKEN_KEY, newRefreshToken);
              }
              if (user) {
                localStorage.setItem(USER_KEY, JSON.stringify(user));
              }

              set({
                token: newToken,
                refreshToken: newRefreshToken || refreshToken,
                tokenExpiry,
                user: user || get().user,
                isAuthenticated: true,
                isRefreshing: false,
                lastActivity: Date.now(),
              });
            } catch (error: any) {
              console.error('Token refresh failed:', error);
              set({ isRefreshing: false });
              // If refresh fails, logout user
              await get().logout();
              throw error;
            }
          },

          // State management actions
          setUser: (user: User) => {
            const isAdmin = user.is_admin || user.roles?.some(role => role.name === 'admin') || false;
            const userRoles = user.roles?.map(role => role.name) || [];
            const permissions = user.roles?.flatMap(role => role.permissions?.map(p => p.name) || []) || [];
            
            set({ 
              user, 
              isAdmin, 
              userRoles, 
              permissions 
            });
            localStorage.setItem(USER_KEY, JSON.stringify(user));
          },

          setTokens: (token: string, refreshToken?: string, expiry?: number) => {
            const tokenExpiry = expiry || parseJWTExpiry(token);
            
            set({
              token,
              refreshToken: refreshToken || get().refreshToken,
              tokenExpiry,
              isAuthenticated: true,
            });
            
            localStorage.setItem(TOKEN_KEY, token);
            if (refreshToken) {
              localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
            }
          },

          clearError: () => {
            set({ error: null });
          },

          setLoading: (loading: boolean) => {
            set({ isLoading: loading });
          },

          updateLastActivity: () => {
            set({ lastActivity: Date.now() });
          },

          // Initialization
          initialize: async () => {
            try {
              set({ isLoading: true });
              
              const storedToken = localStorage.getItem(TOKEN_KEY);
              const storedRefreshToken = localStorage.getItem(REFRESH_TOKEN_KEY);
              const storedUser = localStorage.getItem(USER_KEY);
              
              if (storedToken && storedUser) {
                const user = JSON.parse(storedUser);
                const tokenExpiry = parseJWTExpiry(storedToken);
                
                // Check if token is expired
                if (isTokenExpired(tokenExpiry)) {
                  if (storedRefreshToken) {
                    // Try to refresh token
                    set({
                      token: storedToken,
                      refreshToken: storedRefreshToken,
                      tokenExpiry,
                      user,
                    });
                    await get().refreshTokens();
                  } else {
                    // No refresh token, clear storage
                    get().clearSensitiveData();
                  }
                } else {
                  // Token is valid, restore session
                  const isAdmin = user.is_admin || user.roles?.some(role => role.name === 'admin') || false;
                  const userRoles = user.roles?.map(role => role.name) || [];
                  const permissions = user.roles?.flatMap(role => role.permissions?.map(p => p.name) || []) || [];
                  
                  set({
                    user,
                    token: storedToken,
                    refreshToken: storedRefreshToken,
                    tokenExpiry,
                    isAuthenticated: true,
                    isAdmin,
                    userRoles,
                    permissions,
                  });
                  
                  // Validate session with server
                  try {
                    await get().validateSession();
                  } catch (error) {
                    console.error('Session validation failed:', error);
                    get().clearSensitiveData();
                  }
                }
              }
            } catch (error) {
              console.error('Auth initialization failed:', error);
              get().clearSensitiveData();
            } finally {
              set({ isLoading: false, isInitialized: true });
            }
          },

          checkTokenExpiry: () => {
            const { tokenExpiry } = get();
            return isTokenExpired(tokenExpiry);
          },

          // Security actions
          clearSensitiveData: () => {
            localStorage.removeItem(TOKEN_KEY);
            localStorage.removeItem(REFRESH_TOKEN_KEY);
            localStorage.removeItem(USER_KEY);
            
            set({
              user: null,
              token: null,
              refreshToken: null,
              tokenExpiry: null,
              isAuthenticated: false,
              error: null,
              isAdmin: false,
              userRoles: [],
              permissions: [],
            });
          },

          validateSession: async () => {
            try {
              const response = await authService.getCurrentUser();
              get().setUser(response.data);
              return true;
            } catch (error) {
              console.error('Session validation failed:', error);
              return false;
            }
          },
        }),
        {
          name: 'zamaz-auth-storage',
          // Only persist non-sensitive state
          partialize: (state) => ({
            lastActivity: state.lastActivity,
            isInitialized: state.isInitialized,
          }),
        }
      )
    ),
    {
      name: 'zamaz-auth-store',
    }
  )
);

// Auto-refresh token when it's about to expire
useAuthStore.subscribe(
  (state) => state.tokenExpiry,
  (tokenExpiry) => {
    if (tokenExpiry && isTokenExpired(tokenExpiry)) {
      const { refreshTokens, isAuthenticated, refreshToken } = useAuthStore.getState();
      if (isAuthenticated && refreshToken) {
        refreshTokens().catch((error) => {
          console.error('Auto token refresh failed:', error);
        });
      }
    }
  }
);

// Track user activity for security
let activityTimer: NodeJS.Timeout;
const trackActivity = () => {
  const { isAuthenticated, updateLastActivity } = useAuthStore.getState();
  if (isAuthenticated) {
    updateLastActivity();
  }
};

// Set up activity tracking
if (typeof window !== 'undefined') {
  ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'].forEach((event) => {
    document.addEventListener(event, trackActivity, { passive: true });
  });
  
  // Check for token expiry every minute
  setInterval(() => {
    const { checkTokenExpiry, isAuthenticated, refreshTokens, refreshToken } = useAuthStore.getState();
    if (isAuthenticated && checkTokenExpiry() && refreshToken) {
      refreshTokens().catch((error) => {
        console.error('Scheduled token refresh failed:', error);
      });
    }
  }, 60000);
}