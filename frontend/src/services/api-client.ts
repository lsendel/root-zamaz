/**
 * Unified API Client - Consolidated & Enhanced
 * 
 * Single source of truth for all API interactions with advanced features:
 * - Circuit breaker pattern for resilience
 * - Automatic retry with exponential backoff
 * - Request/response interceptors
 * - Token refresh automation
 * - Comprehensive error handling
 * - TypeScript type safety
 */

import axios, { AxiosInstance, AxiosError, AxiosRequestConfig, AxiosResponse } from 'axios';
import type { 
  ApiResponse, 
  ApiError, 
  PaginatedResponse, 
  RequestOptions,
  CircuitBreakerState 
} from '../types/api';

// Circuit breaker configuration
interface CircuitBreakerConfig {
  failureThreshold: number;
  resetTimeout: number;
  halfOpenRetries: number;
}

// Circuit breaker states
enum CircuitState {
  CLOSED = 'CLOSED',
  OPEN = 'OPEN',
  HALF_OPEN = 'HALF_OPEN'
}

// Circuit breaker implementation
class CircuitBreaker {
  private failureCount = 0;
  private lastFailureTime = 0;
  private successCount = 0;
  private state: CircuitState = CircuitState.CLOSED;

  constructor(private config: CircuitBreakerConfig) {}

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === CircuitState.OPEN) {
      if (Date.now() - this.lastFailureTime > this.config.resetTimeout) {
        this.state = CircuitState.HALF_OPEN;
        this.successCount = 0;
      } else {
        throw new Error('Circuit breaker is OPEN - service temporarily unavailable');
      }
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.failureCount = 0;
    
    if (this.state === CircuitState.HALF_OPEN) {
      this.successCount++;
      if (this.successCount >= this.config.halfOpenRetries) {
        this.state = CircuitState.CLOSED;
      }
    }
  }

  private onFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    
    if (this.failureCount >= this.config.failureThreshold) {
      this.state = CircuitState.OPEN;
    }
  }

  getState(): CircuitBreakerState {
    return {
      state: this.state,
      failure_count: this.failureCount,
      success_count: this.successCount,
      last_failure_time: this.lastFailureTime ? new Date(this.lastFailureTime).toISOString() : undefined,
      next_attempt_time: this.state === CircuitState.OPEN 
        ? new Date(this.lastFailureTime + this.config.resetTimeout).toISOString() 
        : undefined,
    };
  }
}

// API Client configuration
interface ApiClientConfig {
  baseURL: string;
  timeout: number;
  retries: number;
  retryDelay: number;
  circuitBreaker: CircuitBreakerConfig;
}

// Default configuration
const defaultConfig: ApiClientConfig = {
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8080/api',
  timeout: 10000,
  retries: 3,
  retryDelay: 1000,
  circuitBreaker: {
    failureThreshold: 5,
    resetTimeout: 30000,
    halfOpenRetries: 2,
  },
};

// Token management
class TokenManager {
  private static readonly TOKEN_KEY = 'auth_token';
  private static readonly REFRESH_TOKEN_KEY = 'auth_refresh_token';

  static getToken(): string | null {
    return localStorage.getItem(this.TOKEN_KEY);
  }

  static setToken(token: string): void {
    localStorage.setItem(this.TOKEN_KEY, token);
  }

  static getRefreshToken(): string | null {
    return localStorage.getItem(this.REFRESH_TOKEN_KEY);
  }

  static setRefreshToken(token: string): void {
    localStorage.setItem(this.REFRESH_TOKEN_KEY, token);
  }

  static clearTokens(): void {
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.REFRESH_TOKEN_KEY);
  }

  static isTokenExpired(token: string): boolean {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return Date.now() >= (payload.exp * 1000) - 60000; // 1 minute buffer
    } catch {
      return true;
    }
  }
}

// Enhanced API Client
export class ApiClient {
  private axiosInstance: AxiosInstance;
  private circuitBreaker: CircuitBreaker;
  private isRefreshing = false;
  private refreshSubscribers: Array<(token: string) => void> = [];

  constructor(private config: ApiClientConfig = defaultConfig) {
    this.circuitBreaker = new CircuitBreaker(config.circuitBreaker);
    this.axiosInstance = this.createAxiosInstance();
    this.setupInterceptors();
  }

  private createAxiosInstance(): AxiosInstance {
    return axios.create({
      baseURL: this.config.baseURL,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  private setupInterceptors(): void {
    // Request interceptor - Add auth token
    this.axiosInstance.interceptors.request.use(
      (config) => {
        const token = TokenManager.getToken();
        if (token && !TokenManager.isTokenExpired(token)) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        
        // Add request ID for tracing
        config.headers['X-Request-ID'] = this.generateRequestId();
        
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor - Handle auth errors and retry logic
    this.axiosInstance.interceptors.response.use(
      (response) => response,
      async (error: AxiosError) => {
        const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean };

        // Handle 401 Unauthorized
        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;

          try {
            const newToken = await this.refreshToken();
            if (newToken && originalRequest.headers) {
              originalRequest.headers.Authorization = `Bearer ${newToken}`;
              return this.axiosInstance(originalRequest);
            }
          } catch (refreshError) {
            this.handleAuthFailure();
            return Promise.reject(refreshError);
          }
        }

        return Promise.reject(this.normalizeError(error));
      }
    );
  }

  private async refreshToken(): Promise<string | null> {
    if (this.isRefreshing) {
      // Wait for ongoing refresh
      return new Promise((resolve) => {
        this.refreshSubscribers.push(resolve);
      });
    }

    this.isRefreshing = true;
    const refreshToken = TokenManager.getRefreshToken();

    if (!refreshToken) {
      this.isRefreshing = false;
      throw new Error('No refresh token available');
    }

    try {
      const response = await axios.post(`${this.config.baseURL}/auth/refresh`, {
        refresh_token: refreshToken,
      });

      const { token, refresh_token: newRefreshToken } = response.data;
      
      TokenManager.setToken(token);
      if (newRefreshToken) {
        TokenManager.setRefreshToken(newRefreshToken);
      }

      // Notify waiting requests
      this.refreshSubscribers.forEach(callback => callback(token));
      this.refreshSubscribers = [];
      
      return token;
    } catch (error) {
      this.handleAuthFailure();
      throw error;
    } finally {
      this.isRefreshing = false;
    }
  }

  private handleAuthFailure(): void {
    TokenManager.clearTokens();
    
    // Notify auth store or redirect to login
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('auth:logout'));
    }
  }

  private normalizeError(error: AxiosError): ApiError {
    const response = error.response;
    
    return {
      code: response?.data?.code || 'NETWORK_ERROR',
      message: response?.data?.message || error.message || 'An unexpected error occurred',
      details: response?.data?.details,
      fields: response?.data?.fields,
      request_id: response?.headers?.['x-request-id'],
    };
  }

  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private async executeWithRetry<T>(
    operation: () => Promise<AxiosResponse<T>>,
    options: RequestOptions = {}
  ): Promise<ApiResponse<T>> {
    const retries = options.retries ?? this.config.retries;
    const retryDelay = options.retry_delay ?? this.config.retryDelay;

    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const response = await this.circuitBreaker.execute(operation);
        
        return {
          data: response.data,
          success: true,
          timestamp: new Date().toISOString(),
          request_id: response.headers['x-request-id'],
        };
      } catch (error) {
        const isLastAttempt = attempt === retries;
        const shouldRetry = this.shouldRetry(error as AxiosError, attempt);

        if (isLastAttempt || !shouldRetry) {
          throw error;
        }

        // Exponential backoff
        const delay = retryDelay * Math.pow(2, attempt);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    throw new Error('Maximum retry attempts exceeded');
  }

  private shouldRetry(error: AxiosError, attempt: number): boolean {
    // Don't retry on client errors (4xx) except 401, 408, 429
    if (error.response?.status) {
      const status = error.response.status;
      if (status >= 400 && status < 500) {
        return [401, 408, 429].includes(status);
      }
    }

    // Retry on network errors and 5xx errors
    return !error.response || error.response.status >= 500;
  }

  // Public API methods
  async get<T>(url: string, options: RequestOptions = {}): Promise<ApiResponse<T>> {
    return this.executeWithRetry(() => this.axiosInstance.get<T>(url, {
      signal: options.signal,
      timeout: options.timeout,
    }), options);
  }

  async post<T>(url: string, data?: any, options: RequestOptions = {}): Promise<ApiResponse<T>> {
    return this.executeWithRetry(() => this.axiosInstance.post<T>(url, data, {
      signal: options.signal,
      timeout: options.timeout,
      headers: options.headers,
    }), options);
  }

  async put<T>(url: string, data?: any, options: RequestOptions = {}): Promise<ApiResponse<T>> {
    return this.executeWithRetry(() => this.axiosInstance.put<T>(url, data, {
      signal: options.signal,
      timeout: options.timeout,
      headers: options.headers,
    }), options);
  }

  async patch<T>(url: string, data?: any, options: RequestOptions = {}): Promise<ApiResponse<T>> {
    return this.executeWithRetry(() => this.axiosInstance.patch<T>(url, data, {
      signal: options.signal,
      timeout: options.timeout,
      headers: options.headers,
    }), options);
  }

  async delete<T>(url: string, options: RequestOptions = {}): Promise<ApiResponse<T>> {
    return this.executeWithRetry(() => this.axiosInstance.delete<T>(url, {
      signal: options.signal,
      timeout: options.timeout,
    }), options);
  }

  // Utility methods
  getCircuitBreakerState(): CircuitBreakerState {
    return this.circuitBreaker.getState();
  }

  updateConfig(newConfig: Partial<ApiClientConfig>): void {
    this.config = { ...this.config, ...newConfig };
    this.axiosInstance.defaults.baseURL = this.config.baseURL;
    this.axiosInstance.defaults.timeout = this.config.timeout;
  }
}

// Singleton instance
export const apiClient = new ApiClient();

// Export default instance for backward compatibility
export default apiClient;