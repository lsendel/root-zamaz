/**
 * Zero Trust Auth SDK for JavaScript/TypeScript
 * 
 * A comprehensive SDK for integrating with the MVP Zero Trust Authentication system.
 * Provides type-safe methods for authentication, token management, and user operations.
 * 
 * @example
 * ```typescript
 * import { ZeroTrustClient } from '@mvp/zerotrust-sdk';
 * 
 * const client = new ZeroTrustClient({
 *   baseURL: 'https://auth.example.com',
 *   apiKey: 'your-api-key'
 * });
 * 
 * // Authenticate user
 * const response = await client.authenticate({
 *   email: 'user@example.com',
 *   password: 'password123'
 * });
 * 
 * // Validate token
 * const validation = await client.validateToken({
 *   token: response.accessToken
 * });
 * ```
 */

export interface ClientConfig {
  /** Base URL of the Zero Trust Auth service */
  baseURL: string;
  /** API key for authenticating SDK requests */
  apiKey: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Maximum number of retry attempts (default: 3) */
  maxRetries?: number;
  /** Delay between retry attempts in milliseconds (default: 1000) */
  retryDelay?: number;
  /** Custom fetch implementation */
  fetch?: typeof fetch;
  /** Enable debug logging */
  debug?: boolean;
}

export interface AuthenticationRequest {
  email: string;
  password: string;
  mfa?: string;
  remember?: boolean;
}

export interface AuthenticationResponse {
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  expiresIn: number;
  expiresAt: string;
  scope: string;
  requiresMFA: boolean;
  mfaChallenge?: string;
  partialToken?: string;
  user: User;
  sessionId: string;
  trustScore: number;
  riskFactors?: string[];
  recommendedActions?: string[];
}

export interface TokenValidationRequest {
  token: string;
  audience?: string;
  requiredScopes?: string[];
}

export interface TokenValidationResponse {
  valid: boolean;
  claims?: Claims;
  expiresAt: string;
  issuedAt: string;
  trustScore: number;
  permissions: string[];
  roles: string[];
  metadata?: Record<string, unknown>;
}

export interface Claims {
  sub: string;
  aud: string[];
  iss: string;
  exp: number;
  iat: number;
  nbf: number;
  jti: string;
  email: string;
  roles: string[];
  permissions: string[];
  trustScore: number;
  sessionId: string;
  custom?: Record<string, unknown>;
}

export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  displayName: string;
  avatar?: string;
  roles: string[];
  permissions: string[];
  trustScore: number;
  lastLoginAt?: string;
  createdAt: string;
  updatedAt: string;
  isActive: boolean;
  isVerified: boolean;
  mfaEnabled: boolean;
  metadata?: Record<string, unknown>;
}

export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface LogoutRequest {
  token?: string;
  sessionId?: string;
  everywhere?: boolean;
}

export interface APIError extends Error {
  code: string;
  message: string;
  details?: string;
  traceId?: string;
}

export class ZeroTrustAPIError extends Error implements APIError {
  constructor(
    public code: string,
    message: string,
    public details?: string,
    public traceId?: string
  ) {
    super(message);
    this.name = 'ZeroTrustAPIError';
  }
}

export class ZeroTrustClient {
  private config: Required<ClientConfig>;
  private fetch: typeof fetch;

  constructor(config: ClientConfig) {
    this.config = {
      timeout: 30000,
      maxRetries: 3,
      retryDelay: 1000,
      debug: false,
      ...config,
      fetch: config.fetch || globalThis.fetch
    };

    if (!this.config.baseURL) {
      throw new Error('baseURL is required');
    }
    if (!this.config.apiKey) {
      throw new Error('apiKey is required');
    }

    this.fetch = this.config.fetch;
  }

  /**
   * Authenticate a user with email and password
   */
  async authenticate(request: AuthenticationRequest): Promise<AuthenticationResponse> {
    return this.makeRequest<AuthenticationResponse>('POST', '/api/v1/auth/login', request);
  }

  /**
   * Validate an access token
   */
  async validateToken(request: TokenValidationRequest): Promise<TokenValidationResponse> {
    return this.makeRequest<TokenValidationResponse>('POST', '/api/v1/auth/validate', request);
  }

  /**
   * Refresh an access token using a refresh token
   */
  async refreshToken(request: RefreshTokenRequest): Promise<AuthenticationResponse> {
    return this.makeRequest<AuthenticationResponse>('POST', '/api/v1/auth/refresh', request);
  }

  /**
   * Logout a user session
   */
  async logout(request: LogoutRequest): Promise<void> {
    await this.makeRequest<void>('POST', '/api/v1/auth/logout', request);
  }

  /**
   * Get the current user's profile
   */
  async getUserProfile(token: string): Promise<User> {
    return this.makeRequestWithAuth<User>('GET', '/api/v1/user/profile', undefined, token);
  }

  /**
   * Update the current user's profile
   */
  async updateUserProfile(token: string, user: Partial<User>): Promise<User> {
    return this.makeRequestWithAuth<User>('PUT', '/api/v1/user/profile', user, token);
  }

  /**
   * Check the health of the Zero Trust Auth service
   */
  async healthCheck(): Promise<void> {
    const url = new URL('/health', this.config.baseURL);
    
    const response = await this.fetch(url.toString(), {
      method: 'GET',
      headers: {
        'User-Agent': 'MVP-ZeroTrust-SDK/1.0.0 (JavaScript)'
      },
      signal: AbortSignal.timeout(this.config.timeout)
    });

    if (!response.ok) {
      throw new Error(`Health check failed with status: ${response.status}`);
    }
  }

  /**
   * Enable or disable debug logging
   */
  setDebug(debug: boolean): void {
    this.config.debug = debug;
  }

  /**
   * Get the current client configuration
   */
  getConfig(): Readonly<ClientConfig> {
    const { fetch, ...config } = this.config;
    return config;
  }

  private async makeRequest<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    return this.makeRequestWithAuth<T>(method, path, body);
  }

  private async makeRequestWithAuth<T>(
    method: string,
    path: string,
    body?: unknown,
    token?: string
  ): Promise<T> {
    const url = new URL(path, this.config.baseURL);
    
    let lastError: Error;
    
    for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
      if (attempt > 0) {
        await this.delay(this.config.retryDelay);
      }

      try {
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'User-Agent': 'MVP-ZeroTrust-SDK/1.0.0 (JavaScript)',
          'X-API-Key': this.config.apiKey,
          'X-Request-ID': this.generateRequestId()
        };

        if (token) {
          headers['Authorization'] = `Bearer ${token}`;
        }

        if (this.config.debug) {
          console.log(`SDK Request: ${method} ${url.toString()}`);
        }

        const response = await this.fetch(url.toString(), {
          method,
          headers,
          body: body ? JSON.stringify(body) : undefined,
          signal: AbortSignal.timeout(this.config.timeout)
        });

        const responseText = await response.text();
        
        if (this.config.debug) {
          console.log(`SDK Response: ${response.status} ${responseText}`);
        }

        if (!response.ok) {
          let apiError: ZeroTrustAPIError;
          
          try {
            const errorData = JSON.parse(responseText);
            apiError = new ZeroTrustAPIError(
              errorData.code || 'UNKNOWN_ERROR',
              errorData.message || 'An unknown error occurred',
              errorData.details,
              errorData.traceId
            );
          } catch {
            apiError = new ZeroTrustAPIError(
              'HTTP_ERROR',
              `HTTP ${response.status}: ${responseText}`
            );
          }

          // Don't retry client errors (4xx) except 429
          if (response.status >= 400 && response.status < 500 && response.status !== 429) {
            throw apiError;
          }

          lastError = apiError;
          continue;
        }

        // Parse successful response
        if (responseText) {
          try {
            return JSON.parse(responseText) as T;
          } catch (error) {
            throw new Error(`Failed to parse response: ${error}`);
          }
        }

        return undefined as T;
      } catch (error) {
        lastError = error as Error;
        
        // Don't retry non-retryable errors
        if (error instanceof ZeroTrustAPIError) {
          const status = this.extractStatusFromError(error);
          if (status >= 400 && status < 500 && status !== 429) {
            throw error;
          }
        }
      }
    }

    throw new Error(`Max retries exceeded, last error: ${lastError.message}`);
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private generateRequestId(): string {
    return crypto.randomUUID?.() || Math.random().toString(36).substring(2);
  }

  private extractStatusFromError(error: ZeroTrustAPIError): number {
    const match = error.message.match(/HTTP (\d+):/);
    return match ? parseInt(match[1], 10) : 500;
  }
}

/**
 * Utility functions for common operations
 */
export class ZeroTrustUtils {
  /**
   * Check if a token is expired based on expiration time
   */
  static isTokenExpired(expiresAt: string): boolean {
    return new Date() > new Date(expiresAt);
  }

  /**
   * Check if a token will expire within the specified duration (in seconds)
   */
  static isTokenExpiringSoon(expiresAt: string, thresholdSeconds: number): boolean {
    const expiryTime = new Date(expiresAt);
    const thresholdTime = new Date(Date.now() + thresholdSeconds * 1000);
    return thresholdTime > expiryTime;
  }

  /**
   * Generate a random state parameter for OAuth flows
   */
  static generateState(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Generate a code verifier for PKCE
   */
  static generateCodeVerifier(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Generate a code challenge from a code verifier for PKCE
   */
  static async generateCodeChallenge(verifier: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Build an authorization URL for OAuth flows
   */
  static buildAuthURL(
    baseURL: string,
    clientId: string,
    redirectURI: string,
    state: string,
    scopes?: string[]
  ): string {
    const url = new URL('/oauth/authorize', baseURL);
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectURI,
      state: state
    });

    if (scopes && scopes.length > 0) {
      params.set('scope', scopes.join(' '));
    }

    url.search = params.toString();
    return url.toString();
  }

  /**
   * Build an authorization URL with PKCE for OAuth flows
   */
  static buildAuthURLWithPKCE(
    baseURL: string,
    clientId: string,
    redirectURI: string,
    state: string,
    codeChallenge: string,
    scopes?: string[]
  ): string {
    const url = new URL('/oauth/authorize', baseURL);
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectURI,
      state: state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256'
    });

    if (scopes && scopes.length > 0) {
      params.set('scope', scopes.join(' '));
    }

    url.search = params.toString();
    return url.toString();
  }

  /**
   * Extract authorization code from callback URL
   */
  static extractAuthCode(callbackURL: string): { code: string; state: string } {
    const url = new URL(callbackURL);
    const params = new URLSearchParams(url.search);

    const error = params.get('error');
    if (error) {
      const errorDescription = params.get('error_description');
      throw new Error(`Authorization error: ${error} - ${errorDescription}`);
    }

    const code = params.get('code');
    const state = params.get('state');

    if (!code) {
      throw new Error('Authorization code not found in callback URL');
    }

    return { code, state: state || '' };
  }

  /**
   * Sanitize an email address
   */
  static sanitizeEmail(email: string): string {
    return email.toLowerCase().trim();
  }

  /**
   * Validate an email address
   */
  static validateEmail(email: string): boolean {
    const sanitized = this.sanitizeEmail(email);
    const parts = sanitized.split('@');
    return parts.length === 2 && parts[0].length > 0 && parts[1].length > 0 && parts[1].includes('.');
  }

  /**
   * Check if an error is an authentication error
   */
  static isAuthenticationError(error: Error): boolean {
    if (error instanceof ZeroTrustAPIError) {
      const code = error.code.toLowerCase();
      return code.includes('auth') || code.includes('token') || code.includes('unauthorized');
    }
    return false;
  }

  /**
   * Check if an error is retryable
   */
  static isRetryableError(error: Error): boolean {
    if (error instanceof ZeroTrustAPIError) {
      return error.code === 'RATE_LIMITED' ||
             error.code.toLowerCase().includes('timeout') ||
             error.code.toLowerCase().includes('network');
    }
    return true;
  }
}

// Default export
export default ZeroTrustClient;