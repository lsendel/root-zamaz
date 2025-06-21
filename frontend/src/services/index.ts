/**
 * Services Index
 * 
 * Central export point for all API services.
 * Provides a unified interface for importing services throughout the application.
 */

// Core API client
export { apiClient, ApiClient } from './api-client';

// Service implementations
export { authService, AuthService } from './auth.service';
export { adminService, AdminService } from './admin.service';
export { deviceService, DeviceService } from './device.service';
export { healthService, HealthService } from './health.service';

// Type exports for service interfaces
export type {
  SystemHealth,
  ServiceHealth,
  HealthMetrics
} from './health.service';

// Re-export common types from api-client
export type {
  ApiResponse,
  ApiError,
  PaginatedResponse,
  RequestOptions,
  CircuitBreakerState
} from '../types/api';