/**
 * JWT authentication services with Zero Trust principles
 */

import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { Blacklist, MemoryBlacklist } from '../blacklist/blacklist.js';
import { TrustLevel } from '../trust/calculator.js';

/**
 * JWT Manager configuration
 */
export interface JWTConfig {
  secret: string;
  expiryDuration: number; // milliseconds
  refreshDuration: number; // milliseconds
  issuer: string;
  rotationDuration?: number; // milliseconds
}

/**
 * JWT claims with Zero Trust attributes
 */
export interface JWTClaims {
  userId: string;
  email: string;
  roles: string[];
  permissions: string[];
  deviceId?: string;
  trustLevel: number;
  iat: number;
  exp: number;
  iss: string;
  sub: string;
  jti: string;
  nbf?: number;
}

/**
 * Token response
 */
export interface Token {
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  expiresAt: Date;
  trustLevel: number;
}

/**
 * Token generation request
 */
export interface TokenRequest {
  userId: string;
  email: string;
  roles: string[];
  permissions: string[];
  deviceId?: string;
  trustLevel: number;
}

/**
 * JWT signing key with metadata
 */
export interface JWTKey {
  id: string;
  key: string;
  createdAt: Date;
  expiresAt: Date;
  isActive: boolean;
}

/**
 * Custom JWT errors
 */
export class JWTError extends Error {
  constructor(message: string, public code: string) {
    super(message);
    this.name = 'JWTError';
  }
}

export class TokenBlacklistedError extends JWTError {
  constructor() {
    super('Token has been blacklisted', 'TOKEN_BLACKLISTED');
  }
}

export class InvalidTokenError extends JWTError {
  constructor(message = 'Invalid token') {
    super(message, 'INVALID_TOKEN');
  }
}

export class ExpiredTokenError extends JWTError {
  constructor() {
    super('Token has expired', 'EXPIRED_TOKEN');
  }
}

export class TokenNotActiveError extends JWTError {
  constructor() {
    super('Token not yet active', 'TOKEN_NOT_ACTIVE');
  }
}

/**
 * Key manager for JWT signing keys with rotation support
 */
export class KeyManager {
  private keys = new Map<string, JWTKey>();
  private currentKeyId: string;
  private rotationDuration: number;

  constructor(initialSecret: string, rotationDuration: number = 24 * 60 * 60 * 1000) {
    this.rotationDuration = rotationDuration;
    
    const keyId = this.generateKeyId();
    const now = new Date();
    
    const key: JWTKey = {
      id: keyId,
      key: initialSecret,
      createdAt: now,
      expiresAt: new Date(now.getTime() + rotationDuration * 2), // Allow overlap
      isActive: true
    };

    this.keys.set(keyId, key);
    this.currentKeyId = keyId;
  }

  /**
   * Get the current active signing key
   */
  getCurrentKey(): JWTKey | null {
    const key = this.keys.get(this.currentKeyId);
    return key && key.isActive ? key : null;
  }

  /**
   * Get a specific key by ID for token validation
   */
  getKey(keyId: string): JWTKey | null {
    return this.keys.get(keyId) || null;
  }

  /**
   * Rotate the signing key
   */
  rotateKey(): void {
    // Generate new key
    const newKeyBytes = this.generateSecureKey();
    const newKeyId = this.generateKeyId();
    const now = new Date();

    const newKey: JWTKey = {
      id: newKeyId,
      key: newKeyBytes,
      createdAt: now,
      expiresAt: new Date(now.getTime() + this.rotationDuration * 2),
      isActive: true
    };

    // Mark current key as inactive
    const currentKey = this.keys.get(this.currentKeyId);
    if (currentKey) {
      currentKey.isActive = false;
    }

    // Add new key and update current
    this.keys.set(newKeyId, newKey);
    this.currentKeyId = newKeyId;

    // Clean up expired keys
    this.cleanupExpiredKeys();
  }

  /**
   * Get key manager statistics
   */
  getStats(): Record<string, any> {
    const now = new Date();
    let activeKeys = 0;
    let expiredKeys = 0;

    for (const key of this.keys.values()) {
      if (key.isActive && now < key.expiresAt) {
        activeKeys++;
      } else if (now > key.expiresAt) {
        expiredKeys++;
      }
    }

    return {
      totalKeys: this.keys.size,
      activeKeys,
      expiredKeys,
      currentKeyId: this.currentKeyId,
      rotationPeriod: `${this.rotationDuration / 1000}s`
    };
  }

  /**
   * Generate a unique key identifier
   */
  private generateKeyId(): string {
    return Buffer.from(uuidv4().replace(/-/g, '')).toString('base64').substring(0, 16);
  }

  /**
   * Generate a secure key
   */
  private generateSecureKey(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let result = '';
    for (let i = 0; i < 64; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  /**
   * Clean up expired keys
   */
  private cleanupExpiredKeys(): void {
    const now = new Date();
    for (const [keyId, key] of this.keys) {
      if (now > key.expiresAt && keyId !== this.currentKeyId) {
        this.keys.delete(keyId);
      }
    }
  }
}

/**
 * JWT Manager with Zero Trust capabilities
 */
export class JWTManager {
  private keyManager: KeyManager;
  private blacklist: Blacklist;
  private config: JWTConfig;

  constructor(config: JWTConfig) {
    this.validateConfig(config);
    this.config = config;
    this.keyManager = new KeyManager(config.secret, config.rotationDuration);
    this.blacklist = new MemoryBlacklist(); // Default implementation
  }

  /**
   * Generate a new JWT token with trust level
   */
  async generateToken(request: TokenRequest): Promise<Token> {
    this.validateTokenRequest(request);

    const now = Math.floor(Date.now() / 1000);
    const expiresAt = new Date(Date.now() + this.config.expiryDuration);
    const jti = uuidv4();

    const claims: JWTClaims = {
      userId: request.userId,
      email: request.email,
      roles: request.roles,
      permissions: request.permissions,
      deviceId: request.deviceId,
      trustLevel: request.trustLevel,
      iat: now,
      exp: Math.floor(expiresAt.getTime() / 1000),
      iss: this.config.issuer,
      sub: request.userId,
      jti,
      nbf: now
    };

    // Get current signing key
    const currentKey = this.keyManager.getCurrentKey();
    if (!currentKey) {
      throw new Error('No active signing key available');
    }

    // Create token with key ID in header
    const token = jwt.sign(claims, currentKey.key, {
      algorithm: 'HS256',
      header: { kid: currentKey.id }
    });

    // Generate refresh token
    const refreshToken = await this.generateRefreshToken(request.userId);

    return {
      accessToken: token,
      refreshToken,
      tokenType: 'Bearer',
      expiresAt,
      trustLevel: request.trustLevel
    };
  }

  /**
   * Validate a JWT token and return claims
   */
  async validateToken(tokenString: string): Promise<JWTClaims> {
    if (!tokenString) {
      throw new InvalidTokenError();
    }

    // Check blacklist first
    const blacklisted = await this.blacklist.isBlacklisted(tokenString);
    if (blacklisted) {
      throw new TokenBlacklistedError();
    }

    try {
      const decoded = jwt.verify(tokenString, (header, callback) => {
        // Check for key ID in token header
        if (header.kid) {
          const key = this.keyManager.getKey(header.kid);
          if (key) {
            callback(null, key.key);
            return;
          }
        }

        // Fallback to current key for tokens without key ID
        const currentKey = this.keyManager.getCurrentKey();
        if (currentKey) {
          callback(null, currentKey.key);
          return;
        }

        callback(new Error('No valid signing key found'));
      }, {
        algorithms: ['HS256'],
        issuer: this.config.issuer
      }) as JWTClaims;

      return decoded;
    } catch (error: any) {
      throw this.parseJWTError(error);
    }
  }

  /**
   * Blacklist a token
   */
  async blacklistToken(tokenString: string, reason: string): Promise<void> {
    if (!tokenString) {
      throw new Error('Token string cannot be empty');
    }
    if (!reason) {
      throw new Error('Reason cannot be empty');
    }

    try {
      // Extract JTI and expiration from token for efficient blacklisting
      const decoded = jwt.decode(tokenString, { complete: true });
      
      if (!decoded || typeof decoded === 'string') {
        throw new Error('Invalid token format');
      }

      const payload = decoded.payload as any;
      const jti = payload.jti;
      const exp = payload.exp;

      if (!jti) {
        throw new Error('Token missing JTI claim');
      }

      const expiresAt = new Date(exp * 1000);
      await this.blacklist.add(jti, reason, expiresAt);
    } catch (error) {
      throw new Error(`Failed to blacklist token: ${error}`);
    }
  }

  /**
   * Refresh a token using a valid refresh token
   */
  async refreshToken(refreshToken: string, request: TokenRequest): Promise<Token> {
    try {
      const currentKey = this.keyManager.getCurrentKey();
      if (!currentKey) {
        throw new Error('No active signing key available');
      }

      const decoded = jwt.verify(refreshToken, currentKey.key, {
        algorithms: ['HS256']
      }) as any;

      if (decoded.type !== 'refresh') {
        throw new Error('Not a refresh token');
      }

      if (decoded.user_id !== request.userId) {
        throw new Error('User ID mismatch');
      }

      // Generate new access token
      return await this.generateToken(request);
    } catch (error) {
      throw new Error(`Invalid refresh token: ${error}`);
    }
  }

  /**
   * Set the blacklist implementation
   */
  setBlacklist(blacklist: Blacklist): void {
    this.blacklist = blacklist;
  }

  /**
   * Get configuration (without secrets)
   */
  getConfig(): Omit<JWTConfig, 'secret'> {
    const { secret, ...config } = this.config;
    return config;
  }

  /**
   * Validate JWT configuration
   */
  private validateConfig(config: JWTConfig): void {
    if (!config) {
      throw new Error('Config cannot be null');
    }
    if (config.secret.length < 32) {
      throw new Error('JWT secret must be at least 32 characters');
    }
    if (config.expiryDuration <= 0) {
      throw new Error('Expiry duration must be positive');
    }
    if (config.refreshDuration <= 0) {
      throw new Error('Refresh duration must be positive');
    }
    if (!config.issuer) {
      throw new Error('Issuer cannot be empty');
    }
    if (!config.rotationDuration) {
      config.rotationDuration = 24 * 60 * 60 * 1000; // Default to 24 hours
    }
  }

  /**
   * Validate token generation request
   */
  private validateTokenRequest(request: TokenRequest): void {
    if (!request) {
      throw new Error('Token request cannot be null');
    }
    if (!request.userId) {
      throw new Error('User ID cannot be empty');
    }
    if (!request.email) {
      throw new Error('Email cannot be empty');
    }
    if (request.trustLevel < 0 || request.trustLevel > 100) {
      throw new Error('Trust level must be between 0 and 100');
    }
  }

  /**
   * Generate a refresh token
   */
  private async generateRefreshToken(userId: string): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = Math.floor((Date.now() + this.config.refreshDuration) / 1000);

    const claims = {
      user_id: userId,
      type: 'refresh',
      exp: expiresAt,
      iat: now,
      jti: uuidv4()
    };

    const currentKey = this.keyManager.getCurrentKey();
    if (!currentKey) {
      throw new Error('No active signing key available');
    }

    return jwt.sign(claims, currentKey.key, { algorithm: 'HS256' });
  }

  /**
   * Parse JWT errors to custom errors
   */
  private parseJWTError(error: any): Error {
    const errMsg = error.message || '';
    
    if (errMsg.includes('expired')) {
      return new ExpiredTokenError();
    } else if (errMsg.includes('not active')) {
      return new TokenNotActiveError();
    } else if (errMsg.includes('malformed') || errMsg.includes('invalid')) {
      return new InvalidTokenError();
    }
    
    return new InvalidTokenError(`Token validation failed: ${errMsg}`);
  }
}