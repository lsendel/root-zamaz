/**
 * Device Service
 * 
 * Standardized device API calls using the unified API client.
 * Provides type-safe methods for all device-related operations.
 */

import { apiClient } from './api-client';
import type { 
  DeviceAttestation,
  ApiResponse 
} from '../types';

export class DeviceService {
  private readonly baseUrl = '/devices';

  /**
   * Get all devices for the current user
   */
  async getDevices(): Promise<ApiResponse<DeviceAttestation[]>> {
    return apiClient.get<DeviceAttestation[]>(this.baseUrl);
  }

  /**
   * Attest a new device
   */
  async attestDevice(deviceData: Record<string, any>): Promise<ApiResponse<DeviceAttestation>> {
    return apiClient.post<DeviceAttestation>(`${this.baseUrl}/attest`, deviceData);
  }

  /**
   * Verify an existing device
   */
  async verifyDevice(deviceId: string): Promise<ApiResponse<DeviceAttestation>> {
    return apiClient.post<DeviceAttestation>(`${this.baseUrl}/${deviceId}/verify`);
  }

  /**
   * Get device details by ID
   */
  async getDeviceById(deviceId: string): Promise<ApiResponse<DeviceAttestation>> {
    return apiClient.get<DeviceAttestation>(`${this.baseUrl}/${deviceId}`);
  }

  /**
   * Update device information
   */
  async updateDevice(
    deviceId: string, 
    updates: Partial<DeviceAttestation>
  ): Promise<ApiResponse<DeviceAttestation>> {
    return apiClient.patch<DeviceAttestation>(`${this.baseUrl}/${deviceId}`, updates);
  }

  /**
   * Remove/deregister a device
   */
  async removeDevice(deviceId: string): Promise<ApiResponse<void>> {
    return apiClient.delete(`${this.baseUrl}/${deviceId}`);
  }

  /**
   * Get device attestation history
   */
  async getDeviceHistory(deviceId: string): Promise<ApiResponse<Array<{
    id: string;
    action: 'registered' | 'verified' | 'updated' | 'removed';
    timestamp: string;
    details?: Record<string, any>;
  }>>> {
    return apiClient.get(`${this.baseUrl}/${deviceId}/history`);
  }

  /**
   * Check device trust status
   */
  async checkDeviceTrust(deviceId: string): Promise<ApiResponse<{
    is_trusted: boolean;
    trust_score: number;
    last_verified: string;
    risk_factors: string[];
  }>> {
    return apiClient.get(`${this.baseUrl}/${deviceId}/trust`);
  }

  /**
   * Bulk device operations
   */
  async bulkVerifyDevices(deviceIds: string[]): Promise<ApiResponse<{
    verified: string[];
    failed: Array<{ device_id: string; error: string }>;
  }>> {
    return apiClient.post(`${this.baseUrl}/bulk/verify`, { device_ids: deviceIds });
  }

  async bulkRemoveDevices(deviceIds: string[]): Promise<ApiResponse<{
    removed: string[];
    failed: Array<{ device_id: string; error: string }>;
  }>> {
    return apiClient.post(`${this.baseUrl}/bulk/remove`, { device_ids: deviceIds });
  }
}

// Export singleton instance
export const deviceService = new DeviceService();