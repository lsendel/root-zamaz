/**
 * Enhanced Auth Hook - Clean Component Interface
 *
 * Provides a React hook interface for the enhanced Zustand auth store,
 * maintaining component-friendly patterns while leveraging Zustand benefits.
 */

import { useEffect } from "react";
import { useAuthStore } from "../stores/auth-store-enhanced";
import type { LoginCredentials } from "../types/auth";

// Hook return type interface
interface UseAuthReturn {
  // Core state
  user: typeof useAuthStore extends (...args: any[]) => infer R
    ? R["user"]
    : never;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  isInitialized: boolean;

  // Enhanced state
  isAdmin: boolean;
  userRoles: string[];
  permissions: string[];
  lastActivity: number;

  // Actions
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => Promise<void>;
  clearError: () => void;

  // Security helpers
  hasRole: (role: string) => boolean;
  hasPermission: (permission: string) => boolean;
  hasAnyRole: (roles: string[]) => boolean;
  hasAllRoles: (roles: string[]) => boolean;
  hasAnyPermission: (permissions: string[]) => boolean;
  hasAllPermissions: (permissions: string[]) => boolean;

  // Session helpers
  isSessionExpired: () => boolean;
  refreshSession: () => Promise<void>;
  getTimeUntilExpiry: () => number | null;
}

/**
 * Enhanced authentication hook
 *
 * Provides component-friendly interface to the Zustand auth store with
 * additional helper functions for role-based access control.
 */
export function useAuth(): UseAuthReturn {
  // Subscribe to auth store state
  const {
    user,
    isAuthenticated,
    isLoading,
    error,
    isInitialized,
    isAdmin,
    userRoles,
    permissions,
    lastActivity,
    tokenExpiry,
    login,
    logout,
    clearError,
    initialize,
    refreshTokens,
    checkTokenExpiry,
  } = useAuthStore();

  // Initialize auth on first use
  useEffect(() => {
    if (!isInitialized) {
      initialize();
    }
  }, [isInitialized, initialize]);

  // Role and permission helpers
  const hasRole = (role: string): boolean => {
    return userRoles.includes(role);
  };

  const hasPermission = (permission: string): boolean => {
    return permissions.includes(permission);
  };

  const hasAnyRole = (roles: string[]): boolean => {
    return roles.some((role) => userRoles.includes(role));
  };

  const hasAllRoles = (roles: string[]): boolean => {
    return roles.every((role) => userRoles.includes(role));
  };

  const hasAnyPermission = (perms: string[]): boolean => {
    return perms.some((permission) => permissions.includes(permission));
  };

  const hasAllPermissions = (perms: string[]): boolean => {
    return perms.every((permission) => permissions.includes(permission));
  };

  // Session helpers
  const isSessionExpired = (): boolean => {
    return checkTokenExpiry();
  };

  const refreshSession = async (): Promise<void> => {
    return refreshTokens();
  };

  const getTimeUntilExpiry = (): number | null => {
    if (!tokenExpiry) return null;
    const timeLeft = tokenExpiry - Date.now();
    return timeLeft > 0 ? timeLeft : 0;
  };

  return {
    // Core state
    user,
    isAuthenticated,
    isLoading,
    error,
    isInitialized,

    // Enhanced state
    isAdmin,
    userRoles,
    permissions,
    lastActivity,

    // Actions
    login,
    logout,
    clearError,

    // Security helpers
    hasRole,
    hasPermission,
    hasAnyRole,
    hasAllRoles,
    hasAnyPermission,
    hasAllPermissions,

    // Session helpers
    isSessionExpired,
    refreshSession,
    getTimeUntilExpiry,
  };
}

/**
 * Hook for auth loading state only
 * Useful for app-level loading indicators
 */
export function useAuthLoading() {
  return useAuthStore((state) => ({
    isLoading: state.isLoading,
    isInitialized: state.isInitialized,
  }));
}

/**
 * Hook for user info only
 * Optimized for components that only need user data
 */
export function useUser() {
  return useAuthStore((state) => ({
    user: state.user,
    isAuthenticated: state.isAuthenticated,
    isAdmin: state.isAdmin,
    userRoles: state.userRoles,
  }));
}

/**
 * Hook for permissions only
 * Optimized for role-based access control
 */
export function usePermissions() {
  const { userRoles, permissions, isAuthenticated } = useAuthStore((state) => ({
    userRoles: state.userRoles,
    permissions: state.permissions,
    isAuthenticated: state.isAuthenticated,
  }));

  const hasRole = (role: string): boolean => {
    return isAuthenticated && userRoles.includes(role);
  };

  const hasPermission = (permission: string): boolean => {
    return isAuthenticated && permissions.includes(permission);
  };

  const hasAnyRole = (roles: string[]): boolean => {
    return isAuthenticated && roles.some((role) => userRoles.includes(role));
  };

  const hasAnyPermission = (perms: string[]): boolean => {
    return (
      isAuthenticated &&
      perms.some((permission) => permissions.includes(permission))
    );
  };

  return {
    userRoles,
    permissions,
    isAuthenticated,
    hasRole,
    hasPermission,
    hasAnyRole,
    hasAnyPermission,
  };
}

/**
 * Legacy compatibility hook
 *
 * Provides the same interface as the old useAuth hook for
 * backward compatibility during migration.
 */
export function useAuthLegacy() {
  const auth = useAuth();

  return {
    user: auth.user,
    isLoading: auth.isLoading,
    isAuthenticated: auth.isAuthenticated,
    isAdmin: auth.isAdmin,
    login: auth.login,
    logout: auth.logout,
    error: auth.error,
  };
}
