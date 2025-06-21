/**
 * API Response Types - Comprehensive Type Definitions
 * 
 * Standardized TypeScript types for all API interactions,
 * providing type safety and consistency across the application.
 */

// Generic API response wrapper
export interface ApiResponse<T = any> {
  data: T;
  message?: string;
  success: boolean;
  timestamp: string;
  request_id?: string;
}

// Error response structure
export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, any>;
  fields?: Record<string, string>;
  request_id?: string;
}

// Paginated response structure
export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    total_pages: number;
    has_next: boolean;
    has_prev: boolean;
  };
}

// Pagination parameters
export interface PaginationParams {
  page?: number;
  limit?: number;
  sort?: string;
  order?: 'asc' | 'desc';
  search?: string;
  filters?: Record<string, any>;
}

// Filter operators
export type FilterOperator = 
  | 'eq'     // equal
  | 'ne'     // not equal
  | 'gt'     // greater than
  | 'gte'    // greater than or equal
  | 'lt'     // less than
  | 'lte'    // less than or equal
  | 'like'   // contains
  | 'ilike'  // case insensitive contains
  | 'in'     // in array
  | 'notin'  // not in array
  | 'null'   // is null
  | 'notnull'; // is not null

export interface FilterCondition {
  field: string;
  operator: FilterOperator;
  value: any;
}

// Sorting parameters
export interface SortParams {
  field: string;
  order: 'asc' | 'desc';
}

// Bulk operation types
export interface BulkOperationRequest<T = any> {
  operation: 'create' | 'update' | 'delete';
  items: T[];
  options?: {
    batch_size?: number;
    continue_on_error?: boolean;
  };
}

export interface BulkOperationResponse<T = any> {
  total_items: number;
  processed_items: number;
  successful_items: number;
  failed_items: number;
  results: Array<{
    item: T;
    success: boolean;
    error?: ApiError;
  }>;
}

// Upload/download types
export interface UploadRequest {
  file: File;
  metadata?: Record<string, any>;
  options?: {
    chunk_size?: number;
    resumable?: boolean;
  };
}

export interface UploadResponse {
  file_id: string;
  filename: string;
  size: number;
  mime_type: string;
  url?: string;
  metadata?: Record<string, any>;
}

export interface DownloadRequest {
  file_id: string;
  options?: {
    format?: string;
    quality?: number;
  };
}

// Search types
export interface SearchRequest {
  query: string;
  filters?: FilterCondition[];
  sort?: SortParams[];
  pagination?: PaginationParams;
  options?: {
    fuzzy?: boolean;
    highlight?: boolean;
    facets?: string[];
  };
}

export interface SearchResponse<T> {
  results: T[];
  total_hits: number;
  query_time_ms: number;
  facets?: Record<string, Array<{ value: string; count: number }>>;
  suggestions?: string[];
}

// Cache control
export interface CacheOptions {
  ttl?: number; // Time to live in seconds
  tags?: string[]; // Cache tags for invalidation
  key?: string; // Custom cache key
  strategy?: 'cache-first' | 'network-first' | 'cache-only' | 'network-only';
}

// Request options
export interface RequestOptions {
  timeout?: number;
  retries?: number;
  retry_delay?: number;
  cache?: CacheOptions;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

// WebSocket message types
export interface WebSocketMessage<T = any> {
  type: string;
  data: T;
  timestamp: string;
  message_id: string;
}

export interface WebSocketEvent<T = any> extends WebSocketMessage<T> {
  event: string;
  channel?: string;
}

// Health check response
export interface HealthCheckResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  version: string;
  uptime: number;
  checks: Record<string, {
    status: 'pass' | 'warn' | 'fail';
    time: string;
    details?: any;
  }>;
}

// Metrics response
export interface MetricsResponse {
  timestamp: string;
  metrics: Record<string, {
    value: number;
    unit?: string;
    labels?: Record<string, string>;
  }>;
}

// Export format options
export type ExportFormat = 'json' | 'csv' | 'xlsx' | 'pdf' | 'xml';

export interface ExportRequest {
  format: ExportFormat;
  filters?: FilterCondition[];
  fields?: string[];
  options?: {
    include_headers?: boolean;
    date_format?: string;
    timezone?: string;
  };
}

export interface ExportResponse {
  export_id: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  download_url?: string;
  expires_at?: string;
  file_size?: number;
  row_count?: number;
}

// Batch job types
export interface BatchJob {
  job_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress: number; // 0-100
  created_at: string;
  started_at?: string;
  completed_at?: string;
  error?: string;
  result?: any;
}

// Audit log entry
export interface AuditLogEntry {
  id: string;
  user_id?: string;
  action: string;
  resource: string;
  resource_id?: string;
  details?: Record<string, any>;
  ip_address?: string;
  user_agent?: string;
  timestamp: string;
  success: boolean;
  error?: string;
}

// Rate limiting info
export interface RateLimitInfo {
  limit: number;
  remaining: number;
  reset_time: string;
  retry_after?: number;
}

// API client configuration
export interface ApiClientConfig {
  baseURL: string;
  timeout: number;
  retries: number;
  retry_delay: number;
  headers: Record<string, string>;
  interceptors?: {
    request?: Array<(config: any) => any>;
    response?: Array<(response: any) => any>;
    error?: Array<(error: any) => any>;
  };
}

// Request/Response interceptor types
export interface RequestInterceptor {
  onRequest?: (config: any) => any | Promise<any>;
  onRequestError?: (error: any) => any | Promise<any>;
}

export interface ResponseInterceptor {
  onResponse?: (response: any) => any | Promise<any>;
  onResponseError?: (error: any) => any | Promise<any>;
}

// Circuit breaker state
export interface CircuitBreakerState {
  state: 'closed' | 'open' | 'half-open';
  failure_count: number;
  success_count: number;
  last_failure_time?: string;
  next_attempt_time?: string;
}

// API client state
export interface ApiClientState {
  is_online: boolean;
  last_request_time?: string;
  circuit_breaker: CircuitBreakerState;
  rate_limit?: RateLimitInfo;
}

// Utility types for form handling
export interface FormState<T> {
  data: T;
  errors: Partial<Record<keyof T, string>>;
  touched: Partial<Record<keyof T, boolean>>;
  isSubmitting: boolean;
  isValid: boolean;
  isDirty: boolean;
}

export interface FormFieldError {
  field: string;
  message: string;
  code?: string;
}

export interface ValidationResult {
  isValid: boolean;
  errors: FormFieldError[];
}

// Generic list state
export interface ListState<T> {
  items: T[];
  loading: boolean;
  error: string | null;
  pagination: {
    page: number;
    limit: number;
    total: number;
    has_more: boolean;
  };
  filters: Record<string, any>;
  sort: {
    field: string;
    order: 'asc' | 'desc';
  };
  selected: Set<string>;
}

// Loading state utility type
export interface LoadingState {
  isLoading: boolean;
  error: string | null;
  lastUpdated?: string;
}

// Selection state utility type
export interface SelectionState<T> {
  selected: Set<string>;
  items: T[];
  selectAll: boolean;
  indeterminate: boolean;
}