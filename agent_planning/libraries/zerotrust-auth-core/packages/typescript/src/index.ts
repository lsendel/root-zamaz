/**
 * Zero Trust Authentication Core Library - TypeScript Implementation
 * 
 * @description Multi-language authentication library implementing Zero Trust security principles
 * @version 1.0.0
 * @license MIT
 */

// JWT Management
export {
  JWTManager,
  KeyManager,
  JWTConfig,
  JWTClaims,
  Token,
  TokenRequest,
  JWTKey,
  JWTError,
  TokenBlacklistedError,
  InvalidTokenError,
  ExpiredTokenError,
  TokenNotActiveError
} from './jwt/manager.js';

// Trust Level Calculation
export {
  TrustLevel,
  TrustLevelUtils,
  TrustFactors,
  Location,
  CalculationRequest,
  DeviceHistory,
  BehaviorAnalysis,
  CalculatorConfig,
  DeviceService,
  BehaviorService,
  LocationService,
  TrustCalculator,
  DEFAULT_CALCULATOR_CONFIG
} from './trust/calculator.js';

// Token Blacklisting
export {
  Blacklist,
  BlacklistEntry,
  BlacklistStats,
  MemoryBlacklist,
  RedisClient,
  RedisBlacklist,
  HybridBlacklist
} from './blacklist/blacklist.js';

/**
 * Library version
 */
export const VERSION = '1.0.0';

/**
 * Default configuration factory
 */
export function createDefaultJWTConfig(overrides: Partial<JWTConfig> = {}): JWTConfig {
  return {
    secret: process.env.JWT_SECRET || 'your-secret-key-32-characters-long',
    expiryDuration: 30 * 60 * 1000, // 30 minutes
    refreshDuration: 7 * 24 * 60 * 60 * 1000, // 7 days
    issuer: 'zerotrust-auth-core',
    rotationDuration: 24 * 60 * 60 * 1000, // 24 hours
    ...overrides
  };
}

/**
 * Quick setup factory for JWT Manager with sensible defaults
 */
export function createJWTManager(config?: Partial<JWTConfig>): JWTManager {
  const defaultConfig = createDefaultJWTConfig(config);
  return new JWTManager(defaultConfig);
}

/**
 * Quick setup factory for Trust Calculator with default services
 */
export function createTrustCalculator(
  deviceService?: DeviceService,
  behaviorService?: BehaviorService,
  locationService?: LocationService,
  config?: Partial<CalculatorConfig>
): TrustCalculator {
  return new TrustCalculator(deviceService, behaviorService, locationService, config);
}

/**
 * Utility function to validate trust level requirements
 */
export function requiresTrustLevel(operation: string): TrustLevel {
  return TrustCalculator.getTrustLevelForOperation(operation);
}

/**
 * Utility function to check if trust level meets requirement
 */
export function checkTrustLevel(actual: TrustLevel, required: TrustLevel): boolean {
  return TrustLevelUtils.meetsRequirement(actual, required);
}