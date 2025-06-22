/**
 * Token blacklisting implementations for JWT revocation
 */

import jwt from 'jsonwebtoken';

/**
 * Blacklist interface for token blacklisting implementations
 */
export interface Blacklist {
  add(jti: string, reason: string, expiresAt: Date): Promise<void>;
  isBlacklisted(tokenString: string): Promise<boolean>;
  remove(jti: string): Promise<void>;
  cleanup(): Promise<void>;
  getStats(): Promise<BlacklistStats>;
}

/**
 * Blacklist entry representation
 */
export interface BlacklistEntry {
  jti: string;
  reason: string;
  expiresAt: Date;
  createdAt: Date;
  userId?: string;
}

/**
 * Blacklist statistics
 */
export interface BlacklistStats {
  totalEntries: number;
  expiredEntries: number;
  activeEntries: number;
  lastCleanup: Date;
  memoryUsage?: number; // bytes
}

/**
 * Memory-based blacklist implementation
 */
export class MemoryBlacklist implements Blacklist {
  private entries = new Map<string, BlacklistEntry>();
  private lastCleanup = new Date();
  private readonly cleanupInterval = 60 * 60 * 1000; // 1 hour

  /**
   * Add a token to the blacklist
   */
  async add(jti: string, reason: string, expiresAt: Date): Promise<void> {
    if (!jti) {
      throw new Error('JTI cannot be empty');
    }
    if (!reason) {
      throw new Error('Reason cannot be empty');
    }

    const entry: BlacklistEntry = {
      jti,
      reason,
      expiresAt,
      createdAt: new Date()
    };

    this.entries.set(jti, entry);

    // Auto-cleanup if needed
    if (Date.now() - this.lastCleanup.getTime() > this.cleanupInterval) {
      setImmediate(() => this.cleanup());
    }
  }

  /**
   * Check if a token is blacklisted
   */
  async isBlacklisted(tokenString: string): Promise<boolean> {
    const jti = await this.extractJTI(tokenString);
    
    const entry = this.entries.get(jti);
    if (!entry) {
      return false;
    }

    // Check if entry has expired
    if (new Date() > entry.expiresAt) {
      // Remove expired entry
      this.entries.delete(jti);
      return false;
    }

    return true;
  }

  /**
   * Remove a token from the blacklist
   */
  async remove(jti: string): Promise<void> {
    if (!jti) {
      throw new Error('JTI cannot be empty');
    }

    this.entries.delete(jti);
  }

  /**
   * Clean up expired entries from the blacklist
   */
  async cleanup(): Promise<void> {
    const now = new Date();
    let expiredCount = 0;

    for (const [jti, entry] of this.entries) {
      if (now > entry.expiresAt) {
        this.entries.delete(jti);
        expiredCount++;
      }
    }

    this.lastCleanup = now;
  }

  /**
   * Get blacklist statistics
   */
  async getStats(): Promise<BlacklistStats> {
    const now = new Date();
    let activeEntries = 0;
    let expiredEntries = 0;

    for (const entry of this.entries.values()) {
      if (now > entry.expiresAt) {
        expiredEntries++;
      } else {
        activeEntries++;
      }
    }

    // Estimate memory usage (rough estimate: 200 bytes per entry)
    const memoryUsage = this.entries.size * 200;

    return {
      totalEntries: activeEntries + expiredEntries,
      expiredEntries,
      activeEntries,
      lastCleanup: this.lastCleanup,
      memoryUsage
    };
  }

  /**
   * Extract JTI from token string
   */
  private async extractJTI(tokenString: string): Promise<string> {
    if (!tokenString) {
      throw new Error('Token string cannot be empty');
    }

    // Remove Bearer prefix if present
    tokenString = tokenString.replace(/^Bearer\s+/, '');

    try {
      // Decode without verification to extract JTI
      const decoded = jwt.decode(tokenString, { complete: true });
      
      if (!decoded || typeof decoded === 'string') {
        throw new Error('Invalid token format');
      }

      const payload = decoded.payload as any;
      if (!payload.jti) {
        throw new Error('JTI not found in token');
      }

      return payload.jti;
    } catch (error) {
      throw new Error(`Failed to extract JTI: ${error}`);
    }
  }
}

/**
 * Redis client interface for Redis-based blacklist
 */
export interface RedisClient {
  set(key: string, value: string, expireSeconds?: number): Promise<void>;
  get(key: string): Promise<string | null>;
  del(key: string): Promise<void>;
  exists(key: string): Promise<boolean>;
  keys(pattern: string): Promise<string[]>;
  ttl(key: string): Promise<number>;
}

/**
 * Redis-based blacklist implementation
 */
export class RedisBlacklist implements Blacklist {
  private readonly prefix: string;

  constructor(
    private client: RedisClient,
    prefix: string = 'jwt:blacklist'
  ) {
    this.prefix = prefix;
  }

  /**
   * Add a token to the Redis blacklist
   */
  async add(jti: string, reason: string, expiresAt: Date): Promise<void> {
    if (!jti) {
      throw new Error('JTI cannot be empty');
    }
    if (!reason) {
      throw new Error('Reason cannot be empty');
    }

    const key = this.getKey(jti);
    const entry: BlacklistEntry = {
      jti,
      reason,
      expiresAt,
      createdAt: new Date()
    };

    const ttl = Math.floor((expiresAt.getTime() - Date.now()) / 1000);
    if (ttl <= 0) {
      throw new Error('Token already expired');
    }

    await this.client.set(key, JSON.stringify(entry), ttl);
  }

  /**
   * Check if a token is blacklisted in Redis
   */
  async isBlacklisted(tokenString: string): Promise<boolean> {
    const jti = await this.extractJTI(tokenString);
    const key = this.getKey(jti);
    
    return await this.client.exists(key);
  }

  /**
   * Remove a token from the Redis blacklist
   */
  async remove(jti: string): Promise<void> {
    if (!jti) {
      throw new Error('JTI cannot be empty');
    }

    const key = this.getKey(jti);
    await this.client.del(key);
  }

  /**
   * Clean up expired entries (Redis handles this automatically via TTL)
   */
  async cleanup(): Promise<void> {
    // Redis automatically removes expired keys, but we can force cleanup
    // by checking for keys with negative TTL and removing them
    const pattern = `${this.prefix}:*`;
    const keys = await this.client.keys(pattern);

    const expiredKeys: string[] = [];
    for (const key of keys) {
      const ttl = await this.client.ttl(key);
      if (ttl < 0) {
        expiredKeys.push(key);
      }
    }

    for (const key of expiredKeys) {
      await this.client.del(key);
    }
  }

  /**
   * Get blacklist statistics from Redis
   */
  async getStats(): Promise<BlacklistStats> {
    const pattern = `${this.prefix}:*`;
    const keys = await this.client.keys(pattern);

    let activeEntries = 0;
    let expiredEntries = 0;

    for (const key of keys) {
      const ttl = await this.client.ttl(key);
      if (ttl > 0) {
        activeEntries++;
      } else {
        expiredEntries++;
      }
    }

    return {
      totalEntries: activeEntries + expiredEntries,
      expiredEntries,
      activeEntries,
      lastCleanup: new Date() // Redis cleanup is continuous
    };
  }

  /**
   * Generate Redis key for a JTI
   */
  private getKey(jti: string): string {
    return `${this.prefix}:${jti}`;
  }

  /**
   * Extract JTI from token string
   */
  private async extractJTI(tokenString: string): Promise<string> {
    if (!tokenString) {
      throw new Error('Token string cannot be empty');
    }

    // Remove Bearer prefix if present
    tokenString = tokenString.replace(/^Bearer\s+/, '');

    try {
      // Decode without verification to extract JTI
      const decoded = jwt.decode(tokenString, { complete: true });
      
      if (!decoded || typeof decoded === 'string') {
        throw new Error('Invalid token format');
      }

      const payload = decoded.payload as any;
      if (!payload.jti) {
        throw new Error('JTI not found in token');
      }

      return payload.jti;
    } catch (error) {
      throw new Error(`Failed to extract JTI: ${error}`);
    }
  }
}

/**
 * Hybrid blacklist combining memory and Redis for high performance
 */
export class HybridBlacklist implements Blacklist {
  private memory: MemoryBlacklist;
  private redis: RedisBlacklist;
  private syncEnabled: boolean;

  constructor(redisClient: RedisClient, prefix?: string) {
    this.memory = new MemoryBlacklist();
    this.redis = new RedisBlacklist(redisClient, prefix);
    this.syncEnabled = true;
  }

  /**
   * Add a token to both memory and Redis blacklists
   */
  async add(jti: string, reason: string, expiresAt: Date): Promise<void> {
    // Add to memory first (fast)
    await this.memory.add(jti, reason, expiresAt);

    // Add to Redis for persistence (may be slower)
    if (this.syncEnabled) {
      try {
        await this.redis.add(jti, reason, expiresAt);
      } catch (error) {
        // Log error but don't fail - memory blacklist is still active
        throw new Error(`Failed to sync to Redis: ${error}`);
      }
    }
  }

  /**
   * Check memory first, then Redis if not found
   */
  async isBlacklisted(tokenString: string): Promise<boolean> {
    // Check memory first (fastest)
    const memoryResult = await this.memory.isBlacklisted(tokenString);
    if (memoryResult) {
      return true;
    }

    // Check Redis if not in memory
    if (this.syncEnabled) {
      return await this.redis.isBlacklisted(tokenString);
    }

    return false;
  }

  /**
   * Remove from both memory and Redis
   */
  async remove(jti: string): Promise<void> {
    // Remove from memory
    await this.memory.remove(jti);

    // Remove from Redis
    if (this.syncEnabled) {
      await this.redis.remove(jti);
    }
  }

  /**
   * Clean up both memory and Redis
   */
  async cleanup(): Promise<void> {
    // Cleanup memory
    await this.memory.cleanup();

    // Cleanup Redis
    if (this.syncEnabled) {
      await this.redis.cleanup();
    }
  }

  /**
   * Get combined statistics
   */
  async getStats(): Promise<BlacklistStats> {
    const memStats = await this.memory.getStats();

    if (!this.syncEnabled) {
      return memStats;
    }

    try {
      const redisStats = await this.redis.getStats();
      
      // Combine stats (Redis is authoritative for total counts)
      return {
        totalEntries: redisStats.totalEntries,
        expiredEntries: redisStats.expiredEntries,
        activeEntries: redisStats.activeEntries,
        lastCleanup: memStats.lastCleanup,
        memoryUsage: memStats.memoryUsage
      };
    } catch {
      // Return memory stats if Redis fails
      return memStats;
    }
  }

  /**
   * Enable or disable Redis synchronization
   */
  setSyncEnabled(enabled: boolean): void {
    this.syncEnabled = enabled;
  }
}