/**
 * Authentication Service
 * 
 * Standardized authentication API calls using the unified API client.
 * Provides type-safe methods for all auth-related operations.
 */

import { apiClient } from './api-client';
import type { 
  LoginCredentials, 
  LoginResponse, 
  RefreshTokenResponse,
  RegisterCredentials,
  User,
  ApiResponse 
} from '../types';

export class AuthService {
  private readonly baseUrl = '/auth';

  /**
   * Login with username/email and password
   */
  async login(credentials: LoginCredentials): Promise<ApiResponse<LoginResponse>> {
    return apiClient.post<LoginResponse>(`${this.baseUrl}/login`, credentials);
  }

  /**
   * Register new user account
   */
  async register(credentials: RegisterCredentials): Promise<ApiResponse<User>> {
    return apiClient.post<User>(`${this.baseUrl}/register`, credentials);
  }

  /**
   * Logout current session
   */
  async logout(): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`${this.baseUrl}/logout`);
  }

  /**
   * Refresh authentication token
   */
  async refreshToken(): Promise<ApiResponse<RefreshTokenResponse>> {
    return apiClient.post<RefreshTokenResponse>(`${this.baseUrl}/refresh`);
  }

  /**
   * Get current user profile
   */
  async getCurrentUser(): Promise<ApiResponse<User>> {
    return apiClient.get<User>(`${this.baseUrl}/me`);
  }

  /**
   * Update user profile
   */
  async updateProfile(updates: Partial<User>): Promise<ApiResponse<User>> {
    return apiClient.patch<User>(`${this.baseUrl}/me`, updates);
  }

  /**
   * Change password
   */
  async changePassword(data: {
    current_password: string;
    new_password: string;
  }): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`${this.baseUrl}/change-password`, data);
  }

  /**
   * Request password reset
   */
  async requestPasswordReset(email: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`${this.baseUrl}/password-reset/request`, { email });
  }

  /**
   * Reset password with token
   */
  async resetPassword(data: {
    token: string;
    new_password: string;
  }): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`${this.baseUrl}/password-reset/confirm`, data);
  }

  /**
   * Verify email address
   */
  async verifyEmail(token: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`${this.baseUrl}/verify-email`, { token });
  }

  /**
   * Resend email verification
   */
  async resendEmailVerification(): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`${this.baseUrl}/verify-email/resend`);
  }

  /**
   * Enable two-factor authentication
   */
  async enableTwoFactor(): Promise<ApiResponse<{ qr_code: string; secret: string }>> {
    return apiClient.post<{ qr_code: string; secret: string }>(`${this.baseUrl}/2fa/enable`);
  }

  /**
   * Confirm two-factor authentication setup
   */
  async confirmTwoFactor(code: string): Promise<ApiResponse<{ recovery_codes: string[] }>> {
    return apiClient.post<{ recovery_codes: string[] }>(`${this.baseUrl}/2fa/confirm`, { code });
  }

  /**
   * Disable two-factor authentication
   */
  async disableTwoFactor(password: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`${this.baseUrl}/2fa/disable`, { password });
  }

  /**
   * Verify two-factor authentication code
   */
  async verifyTwoFactor(code: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`${this.baseUrl}/2fa/verify`, { code });
  }

  /**
   * Get user sessions
   */
  async getSessions(): Promise<ApiResponse<Array<{
    id: string;
    device: string;
    ip_address: string;
    location?: string;
    last_activity: string;
    is_current: boolean;
  }>>> {
    return apiClient.get(`${this.baseUrl}/sessions`);
  }

  /**
   * Revoke specific session
   */
  async revokeSession(sessionId: string): Promise<ApiResponse<void>> {
    return apiClient.delete(`${this.baseUrl}/sessions/${sessionId}`);
  }

  /**
   * Revoke all other sessions
   */
  async revokeAllOtherSessions(): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`${this.baseUrl}/sessions/revoke-all`);
  }
}

// Export singleton instance
export const authService = new AuthService();