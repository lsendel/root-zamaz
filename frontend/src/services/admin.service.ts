/**
 * Admin Service
 * 
 * Standardized admin API calls using the unified API client.
 * Provides type-safe methods for all admin-related operations.
 */

import { apiClient } from './api-client';
import type { 
  Role, 
  Permission, 
  User, 
  UserWithRoles,
  ApiResponse 
} from '../types';

export class AdminService {
  private readonly baseUrl = '/admin';

  // Role management
  async getRoles(): Promise<ApiResponse<Role[]>> {
    return apiClient.get<Role[]>(`${this.baseUrl}/roles`);
  }

  async createRole(role: { name: string; description: string }): Promise<ApiResponse<Role>> {
    return apiClient.post<Role>(`${this.baseUrl}/roles`, role);
  }

  async updateRole(
    id: string, 
    role: { name?: string; description?: string; is_active?: boolean }
  ): Promise<ApiResponse<Role>> {
    return apiClient.put<Role>(`${this.baseUrl}/roles/${id}`, role);
  }

  async deleteRole(id: string): Promise<ApiResponse<void>> {
    return apiClient.delete(`${this.baseUrl}/roles/${id}`);
  }

  // Permission management
  async getPermissions(): Promise<ApiResponse<Permission[]>> {
    return apiClient.get<Permission[]>(`${this.baseUrl}/permissions`);
  }

  // Role-Permission assignments
  async assignPermissionToRole(roleId: string, permissionId: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`${this.baseUrl}/roles/${roleId}/permissions/${permissionId}`);
  }

  async removePermissionFromRole(roleId: string, permissionId: string): Promise<ApiResponse<void>> {
    return apiClient.delete(`${this.baseUrl}/roles/${roleId}/permissions/${permissionId}`);
  }

  // User management
  async getUsers(): Promise<ApiResponse<UserWithRoles[]>> {
    return apiClient.get<UserWithRoles[]>(`${this.baseUrl}/users`);
  }

  async getUserById(id: number): Promise<ApiResponse<UserWithRoles>> {
    return apiClient.get<UserWithRoles>(`${this.baseUrl}/users/${id}`);
  }

  async updateUser(
    id: number, 
    user: { 
      username?: string; 
      email?: string; 
      first_name?: string; 
      last_name?: string; 
      is_active?: boolean; 
      is_admin?: boolean 
    }
  ): Promise<ApiResponse<User>> {
    return apiClient.put<User>(`${this.baseUrl}/users/${id}`, user);
  }

  async deleteUser(id: number): Promise<ApiResponse<void>> {
    return apiClient.delete(`${this.baseUrl}/users/${id}`);
  }

  // User-Role assignments
  async assignRoleToUser(userId: number, roleId: string): Promise<ApiResponse<void>> {
    return apiClient.post<void>(`${this.baseUrl}/users/${userId}/roles/${roleId}`);
  }

  async removeRoleFromUser(userId: number, roleId: string): Promise<ApiResponse<void>> {
    return apiClient.delete(`${this.baseUrl}/users/${userId}/roles/${roleId}`);
  }
}

// Export singleton instance
export const adminService = new AdminService();