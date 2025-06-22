/**
 * Trust level calculation for Zero Trust authentication
 */

/**
 * Trust levels in Zero Trust architecture
 */
export enum TrustLevel {
  None = 0,    // Untrusted - failed authentication, suspicious activity
  Low = 25,    // Basic authentication - new devices, minimal verification
  Medium = 50, // Known device - standard authentication with known device
  High = 75,   // Verified device + location - trusted environment
  Full = 100   // Hardware attestation - TPM, secure enclave, biometrics
}

/**
 * Trust level utilities
 */
export class TrustLevelUtils {
  static toString(level: TrustLevel): string {
    switch (level) {
      case TrustLevel.None:
        return 'None';
      case TrustLevel.Low:
        return 'Low';
      case TrustLevel.Medium:
        return 'Medium';
      case TrustLevel.High:
        return 'High';
      case TrustLevel.Full:
        return 'Full';
      default:
        return `Unknown(${level})`;
    }
  }

  static fromValue(value: number): TrustLevel {
    if (value >= 100) return TrustLevel.Full;
    if (value >= 75) return TrustLevel.High;
    if (value >= 50) return TrustLevel.Medium;
    if (value >= 25) return TrustLevel.Low;
    return TrustLevel.None;
  }

  static meetsRequirement(actual: TrustLevel, required: TrustLevel): boolean {
    return actual >= required;
  }
}

/**
 * Factors used in trust calculation
 */
export interface TrustFactors {
  deviceVerified: boolean;
  locationVerified: boolean;
  behaviorNormal: boolean;
  recentActivity: boolean;
  hardwareAttestation: boolean;
  biometricVerified: boolean;
  networkTrusted: boolean;
  sessionAge: Date;
  previousTrustLevel: TrustLevel;
}

/**
 * Geographic location for trust calculation
 */
export interface Location {
  country: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  ipAddress: string;
}

/**
 * Trust calculation request
 */
export interface CalculationRequest {
  userId: string;
  deviceId?: string;
  location?: Location;
  action?: string;
  lastActivity: Date;
  sessionStart: Date;
  ipAddress?: string;
  userAgent?: string;
  factors?: TrustFactors;
}

/**
 * Device history information
 */
export interface DeviceHistory {
  firstSeen: Date;
  lastSeen: Date;
  loginCount: number;
  failureCount: number;
  isTrusted: boolean;
  riskScore: number;
  platform: string;
  userAgent: string;
  lastTrustLevel: TrustLevel;
}

/**
 * Behavior analysis results
 */
export interface BehaviorAnalysis {
  isSuspicious: boolean;
  anomalyScore: number;
  typicalLoginTimes: number[]; // Hours of day
  typicalLocations: string[];
  unusualActivity: string[];
  lastAnalyzed: Date;
  confidenceScore: number;
}

/**
 * Configuration for trust calculation
 */
export interface CalculatorConfig {
  baseScore: number;
  deviceWeight: number;
  locationWeight: number;
  behaviorWeight: number;
  activityWeight: number;
  hardwareWeight: number;
  biometricWeight: number;
  networkWeight: number;
  maxInactivityDuration: number; // milliseconds
  suspiciousActivityPenalty: number;
  newDevicePenalty: number;
}

/**
 * Service interfaces for trust calculation dependencies
 */
export interface DeviceService {
  verifyDevice(deviceId: string): Promise<boolean>;
  getDeviceHistory(deviceId: string): Promise<DeviceHistory | null>;
  checkHardwareAttestation(deviceId: string): Promise<boolean>;
  isDeviceTrusted(deviceId: string): Promise<boolean>;
  markDeviceAsTrusted(deviceId: string): Promise<void>;
}

export interface BehaviorService {
  analyzeBehavior(userId: string, action: string): Promise<BehaviorAnalysis>;
  isActionSuspicious(userId: string, action: string): Promise<boolean>;
  updateBehaviorProfile(userId: string, action: string, timestamp: Date): Promise<void>;
  getTypicalPatterns(userId: string): Promise<BehaviorAnalysis>;
}

export interface LocationService {
  verifyLocation(userId: string, location: Location): Promise<boolean>;
  isLocationTrusted(location: Location): Promise<boolean>;
  getLocationFromIP(ipAddress: string): Promise<Location | null>;
  addTrustedLocation(userId: string, location: Location): Promise<void>;
}

/**
 * Default configuration for trust calculation
 */
export const DEFAULT_CALCULATOR_CONFIG: CalculatorConfig = {
  baseScore: 10,
  deviceWeight: 25,
  locationWeight: 20,
  behaviorWeight: 15,
  activityWeight: 10,
  hardwareWeight: 15,
  biometricWeight: 10,
  networkWeight: 5,
  maxInactivityDuration: 30 * 60 * 1000, // 30 minutes
  suspiciousActivityPenalty: 50,
  newDevicePenalty: 15
};

/**
 * Trust level calculator
 */
export class TrustCalculator {
  private config: CalculatorConfig;

  constructor(
    private deviceService?: DeviceService,
    private behaviorService?: BehaviorService,
    private locationService?: LocationService,
    config?: Partial<CalculatorConfig>
  ) {
    this.config = { ...DEFAULT_CALCULATOR_CONFIG, ...config };
  }

  /**
   * Calculate trust level based on provided factors
   */
  calculate(factors: TrustFactors): TrustLevel {
    let score = this.config.baseScore;

    // Device verification
    if (factors.deviceVerified) {
      score += this.config.deviceWeight;
    } else {
      score -= this.config.newDevicePenalty;
    }

    // Location verification
    if (factors.locationVerified) {
      score += this.config.locationWeight;
    }

    // Behavior analysis
    if (factors.behaviorNormal) {
      score += this.config.behaviorWeight;
    } else {
      score -= this.config.suspiciousActivityPenalty;
    }

    // Recent activity
    if (factors.recentActivity) {
      score += this.config.activityWeight;
    }

    // Hardware attestation (high security feature)
    if (factors.hardwareAttestation) {
      score += this.config.hardwareWeight;
    }

    // Biometric verification
    if (factors.biometricVerified) {
      score += this.config.biometricWeight;
    }

    // Trusted network
    if (factors.networkTrusted) {
      score += this.config.networkWeight;
    }

    // Session age consideration
    if (factors.sessionAge) {
      const sessionDuration = Date.now() - factors.sessionAge.getTime();
      if (sessionDuration > 4 * 60 * 60 * 1000) { // 4 hours
        score -= 10;
      } else if (sessionDuration > 8 * 60 * 60 * 1000) { // 8 hours
        score -= 20;
      }
    }

    // Consider previous trust level for gradual changes
    if (factors.previousTrustLevel > TrustLevel.None) {
      const previousScore = factors.previousTrustLevel;
      if (Math.abs(score - previousScore) > 25) {
        // Limit trust level changes to 25 points per calculation
        if (score > previousScore) {
          score = previousScore + 25;
        } else {
          score = previousScore - 25;
        }
      }
    }

    // Ensure score is within bounds
    score = Math.max(0, Math.min(100, score));

    return TrustLevelUtils.fromValue(score);
  }

  /**
   * Perform comprehensive trust calculation for a user
   */
  async calculateForUser(request: CalculationRequest): Promise<TrustLevel> {
    const factors: TrustFactors = {
      deviceVerified: false,
      locationVerified: false,
      behaviorNormal: true,
      recentActivity: false,
      hardwareAttestation: false,
      biometricVerified: false,
      networkTrusted: false,
      sessionAge: request.sessionStart,
      previousTrustLevel: TrustLevel.None,
      ...request.factors
    };

    // Device verification
    if (request.deviceId && this.deviceService) {
      try {
        factors.deviceVerified = await this.deviceService.verifyDevice(request.deviceId);

        if (factors.deviceVerified) {
          // Check hardware attestation
          try {
            factors.hardwareAttestation = await this.deviceService.checkHardwareAttestation(request.deviceId);
          } catch {
            // Non-critical, continue if it fails
          }
        }

        // Get device history for additional context
        try {
          const history = await this.deviceService.getDeviceHistory(request.deviceId);
          if (history) {
            if (history.isTrusted && history.failureCount < 3) {
              factors.deviceVerified = true;
            }
            factors.previousTrustLevel = history.lastTrustLevel;
          }
        } catch {
          // Non-critical
        }
      } catch (error) {
        throw new Error(`Device verification failed: ${error}`);
      }
    }

    // Location verification
    if (request.location && this.locationService) {
      try {
        factors.locationVerified = await this.locationService.verifyLocation(request.userId, request.location);
        
        // Check if location is on trusted network
        try {
          factors.networkTrusted = await this.locationService.isLocationTrusted(request.location);
        } catch {
          // Non-critical
        }
      } catch (error) {
        throw new Error(`Location verification failed: ${error}`);
      }
    } else if (request.ipAddress && this.locationService) {
      // Derive location from IP address
      try {
        const location = await this.locationService.getLocationFromIP(request.ipAddress);
        if (location) {
          factors.locationVerified = await this.locationService.verifyLocation(request.userId, location);
          factors.networkTrusted = await this.locationService.isLocationTrusted(location);
        }
      } catch {
        // Non-critical
      }
    }

    // Behavior analysis
    if (request.action && this.behaviorService) {
      try {
        factors.behaviorNormal = !(await this.behaviorService.isActionSuspicious(request.userId, request.action));

        // Update behavior profile for future analysis
        if (request.lastActivity) {
          await this.behaviorService.updateBehaviorProfile(request.userId, request.action, request.lastActivity);
        }
      } catch (error) {
        throw new Error(`Behavior analysis failed: ${error}`);
      }
    }

    // Recent activity check
    if (request.lastActivity) {
      const timeSinceActivity = Date.now() - request.lastActivity.getTime();
      factors.recentActivity = timeSinceActivity < this.config.maxInactivityDuration;
    }

    return this.calculate(factors);
  }

  /**
   * Calculate trust level during authentication
   */
  async calculateForAuthentication(userId: string, deviceId?: string, ipAddress?: string): Promise<TrustLevel> {
    const now = new Date();
    const request: CalculationRequest = {
      userId,
      deviceId,
      ipAddress,
      lastActivity: now,
      sessionStart: now,
      action: 'login'
    };

    return this.calculateForUser(request);
  }

  /**
   * Get required trust level for different operations
   */
  static getTrustLevelForOperation(operation: string): TrustLevel {
    switch (operation) {
      case 'login':
      case 'read_profile':
      case 'view_dashboard':
        return TrustLevel.Low;

      case 'update_profile':
      case 'create_resource':
      case 'view_reports':
        return TrustLevel.Medium;

      case 'delete_resource':
      case 'admin_action':
      case 'financial_transaction':
        return TrustLevel.High;

      case 'system_admin':
      case 'security_settings':
      case 'user_management':
        return TrustLevel.Full;

      default:
        return TrustLevel.Medium; // Default to medium for unknown operations
    }
  }

  /**
   * Validate trust calculation factors
   */
  static validateFactors(factors: TrustFactors): void {
    // Check for logical inconsistencies
    if (factors.hardwareAttestation && !factors.deviceVerified) {
      throw new Error('Hardware attestation requires device verification');
    }

    if (factors.biometricVerified && !factors.deviceVerified) {
      throw new Error('Biometric verification requires device verification');
    }
  }

  /**
   * Create a requirement checker for a minimum trust level
   */
  static requireTrustLevel(required: TrustLevel): (actual: TrustLevel) => boolean {
    return (actual: TrustLevel) => TrustLevelUtils.meetsRequirement(actual, required);
  }
}