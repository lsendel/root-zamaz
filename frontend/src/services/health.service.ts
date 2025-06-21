/**
 * Health Service
 * 
 * Standardized health/monitoring API calls using the unified API client.
 * Provides type-safe methods for all health check and system monitoring operations.
 */

import { apiClient } from './api-client';
import type { ApiResponse } from '../types';

export interface SystemHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  services: Record<string, 'healthy' | 'degraded' | 'unhealthy'>;
  timestamp: string;
  uptime: number;
  version: string;
}

export interface ServiceHealth {
  name: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  latency_ms: number;
  last_check: string;
  details?: Record<string, any>;
}

export interface HealthMetrics {
  cpu_usage: number;
  memory_usage: number;
  disk_usage: number;
  active_connections: number;
  requests_per_minute: number;
  error_rate: number;
  timestamp: string;
}

export class HealthService {
  private readonly baseUrl = '/health';

  /**
   * Get overall system health status
   */
  async getSystemHealth(): Promise<ApiResponse<SystemHealth>> {
    return apiClient.get<SystemHealth>(this.baseUrl);
  }

  /**
   * Get detailed health status for all services
   */
  async getServiceHealth(): Promise<ApiResponse<ServiceHealth[]>> {
    return apiClient.get<ServiceHealth[]>(`${this.baseUrl}/services`);
  }

  /**
   * Get health status for a specific service
   */
  async getServiceHealthById(serviceName: string): Promise<ApiResponse<ServiceHealth>> {
    return apiClient.get<ServiceHealth>(`${this.baseUrl}/services/${serviceName}`);
  }

  /**
   * Get current system metrics
   */
  async getMetrics(): Promise<ApiResponse<HealthMetrics>> {
    return apiClient.get<HealthMetrics>(`${this.baseUrl}/metrics`);
  }

  /**
   * Get historical metrics data
   */
  async getMetricsHistory(options: {
    start_time: string;
    end_time: string;
    interval?: '1m' | '5m' | '15m' | '1h' | '1d';
  }): Promise<ApiResponse<HealthMetrics[]>> {
    const params = new URLSearchParams({
      start_time: options.start_time,
      end_time: options.end_time,
      ...(options.interval && { interval: options.interval }),
    });

    return apiClient.get<HealthMetrics[]>(`${this.baseUrl}/metrics/history?${params}`);
  }

  /**
   * Perform a deep health check (may take longer)
   */
  async performDeepHealthCheck(): Promise<ApiResponse<{
    database: ServiceHealth;
    redis: ServiceHealth;
    external_apis: ServiceHealth[];
    file_system: ServiceHealth;
    network: ServiceHealth;
    overall_status: 'healthy' | 'degraded' | 'unhealthy';
  }>> {
    return apiClient.post(`${this.baseUrl}/deep-check`);
  }

  /**
   * Get readiness probe status (Kubernetes-style)
   */
  async getReadiness(): Promise<ApiResponse<{
    ready: boolean;
    checks: Array<{
      name: string;
      status: 'pass' | 'fail';
      message?: string;
    }>;
  }>> {
    return apiClient.get(`${this.baseUrl}/ready`);
  }

  /**
   * Get liveness probe status (Kubernetes-style)
   */
  async getLiveness(): Promise<ApiResponse<{
    alive: boolean;
    uptime_seconds: number;
  }>> {
    return apiClient.get(`${this.baseUrl}/live`);
  }

  /**
   * Get application info and version
   */
  async getAppInfo(): Promise<ApiResponse<{
    name: string;
    version: string;
    build_time: string;
    git_commit: string;
    go_version: string;
    environment: string;
  }>> {
    return apiClient.get(`${this.baseUrl}/info`);
  }

  /**
   * Get API circuit breaker status
   */
  async getCircuitBreakerStatus(): Promise<ApiResponse<{
    state: 'closed' | 'open' | 'half_open';
    failure_count: number;
    success_count: number;
    last_failure_time?: string;
    next_attempt_time?: string;
  }>> {
    return apiClient.get(`${this.baseUrl}/circuit-breaker`);
  }

  /**
   * Reset circuit breaker (admin operation)
   */
  async resetCircuitBreaker(): Promise<ApiResponse<void>> {
    return apiClient.post(`${this.baseUrl}/circuit-breaker/reset`);
  }

  /**
   * Get database connection health
   */
  async getDatabaseHealth(): Promise<ApiResponse<{
    connected: boolean;
    connection_pool: {
      active: number;
      idle: number;
      max: number;
    };
    query_stats: {
      total_queries: number;
      avg_query_time_ms: number;
      slow_queries: number;
    };
  }>> {
    return apiClient.get(`${this.baseUrl}/database`);
  }

  /**
   * Trigger health alerts testing (admin operation)
   */
  async testHealthAlerts(): Promise<ApiResponse<{
    alerts_sent: number;
    channels_tested: string[];
    test_timestamp: string;
  }>> {
    return apiClient.post(`${this.baseUrl}/test-alerts`);
  }
}

// Export singleton instance
export const healthService = new HealthService();