# Zero Trust Authentication Core - TypeScript

> **TypeScript implementation of the Zero Trust Authentication Core library**  
> **Version**: 1.0.0  
> **License**: MIT

## 🚀 **Quick Start**

### **Installation**

```bash
npm install @zerotrust/auth-core
```

### **Basic Usage**

```typescript
import { JWTManager, TrustLevel, createDefaultJWTConfig } from '@zerotrust/auth-core';

// Configure JWT manager
const config = createDefaultJWTConfig({
  secret: 'your-secret-key-32-characters-long',
  expiryDuration: 30 * 60 * 1000, // 30 minutes
  issuer: 'my-service'
});

const jwtManager = new JWTManager(config);

// Generate token with trust level
const tokenRequest = {
  userId: 'user123',
  email: 'user@example.com',
  roles: ['user'],
  permissions: ['read', 'write'],
  trustLevel: TrustLevel.Medium,
  deviceId: 'device-fingerprint-123'
};

const token = await jwtManager.generateToken(tokenRequest);
console.log('Access Token:', token.accessToken);
console.log('Trust Level:', token.trustLevel);

// Validate token
const claims = await jwtManager.validateToken(token.accessToken);
console.log('User ID:', claims.userId);
console.log('Trust Level:', claims.trustLevel);
```

## 🔐 **Trust Level System**

```typescript
import { TrustCalculator, TrustLevel, TrustLevelUtils } from '@zerotrust/auth-core';

// Create trust calculator
const calculator = new TrustCalculator();

// Calculate trust based on factors
const factors = {
  deviceVerified: true,
  locationVerified: true,
  behaviorNormal: true,
  recentActivity: true,
  hardwareAttestation: false,
  biometricVerified: false,
  networkTrusted: true,
  sessionAge: new Date(),
  previousTrustLevel: TrustLevel.Medium
};

const trustLevel = calculator.calculate(factors);
console.log('Trust Level:', TrustLevelUtils.toString(trustLevel));

// Check if trust level meets requirement
const required = TrustLevel.Medium;
const meetsRequirement = TrustLevelUtils.meetsRequirement(trustLevel, required);
console.log('Meets requirement:', meetsRequirement);
```

## 🛡️ **Token Blacklisting**

```typescript
import { MemoryBlacklist, RedisBlacklist } from '@zerotrust/auth-core';

// Memory-based blacklist (for single-instance applications)
const memoryBlacklist = new MemoryBlacklist();

// Add token to blacklist
await memoryBlacklist.add('token-jti', 'User logout', new Date(Date.now() + 3600000));

// Check if token is blacklisted
const isBlacklisted = await memoryBlacklist.isBlacklisted(tokenString);

// Set custom blacklist on JWT manager
jwtManager.setBlacklist(memoryBlacklist);

// Redis-based blacklist (for distributed applications)
const redisBlacklist = new RedisBlacklist(redisClient, 'jwt:blacklist');
jwtManager.setBlacklist(redisBlacklist);
```

## 🔄 **Advanced Configuration**

### **Custom Trust Calculator with Services**

```typescript
import { 
  TrustCalculator, 
  DeviceService, 
  BehaviorService, 
  LocationService 
} from '@zerotrust/auth-core';

// Implement service interfaces
class MyDeviceService implements DeviceService {
  async verifyDevice(deviceId: string): Promise<boolean> {
    // Your device verification logic
    return true;
  }

  async getDeviceHistory(deviceId: string): Promise<DeviceHistory | null> {
    // Your device history logic
    return null;
  }

  // ... implement other methods
}

class MyBehaviorService implements BehaviorService {
  async analyzeBehavior(userId: string, action: string): Promise<BehaviorAnalysis> {
    // Your behavior analysis logic
    return {
      isSuspicious: false,
      anomalyScore: 0.1,
      typicalLoginTimes: [9, 10, 11, 14, 15, 16],
      typicalLocations: ['office', 'home'],
      unusualActivity: [],
      lastAnalyzed: new Date(),
      confidenceScore: 0.95
    };
  }

  // ... implement other methods
}

// Create calculator with custom services
const deviceService = new MyDeviceService();
const behaviorService = new MyBehaviorService();

const calculator = new TrustCalculator(
  deviceService,
  behaviorService,
  undefined, // locationService
  {
    baseScore: 15,
    deviceWeight: 30,
    behaviorWeight: 20
  }
);

// Calculate trust for user with comprehensive analysis
const request = {
  userId: 'user123',
  deviceId: 'device456',
  action: 'login',
  lastActivity: new Date(),
  sessionStart: new Date(),
  ipAddress: '192.168.1.100'
};

const trustLevel = await calculator.calculateForUser(request);
```

### **Hybrid Blacklist for High Availability**

```typescript
import { HybridBlacklist, RedisClient } from '@zerotrust/auth-core';

// Implement Redis client interface
class MyRedisClient implements RedisClient {
  async set(key: string, value: string, expireSeconds?: number): Promise<void> {
    // Your Redis set implementation
  }

  async get(key: string): Promise<string | null> {
    // Your Redis get implementation
    return null;
  }

  // ... implement other methods
}

// Create hybrid blacklist (memory + Redis for performance and persistence)
const redisClient = new MyRedisClient();
const hybridBlacklist = new HybridBlacklist(redisClient, 'jwt:blacklist');

jwtManager.setBlacklist(hybridBlacklist);
```

## 🧪 **Testing**

```bash
# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch

# Lint code
npm run lint

# Build library
npm run build
```

### **Example Test**

```typescript
import { JWTManager, TrustLevel, createDefaultJWTConfig } from '@zerotrust/auth-core';

describe('JWTManager', () => {
  let jwtManager: JWTManager;

  beforeEach(() => {
    const config = createDefaultJWTConfig({
      secret: 'test-secret-key-32-characters-long'
    });
    jwtManager = new JWTManager(config);
  });

  it('should generate valid JWT token', async () => {
    const request = {
      userId: 'test-user',
      email: 'test@example.com',
      roles: ['user'],
      permissions: ['read'],
      trustLevel: TrustLevel.Medium
    };

    const token = await jwtManager.generateToken(request);

    expect(token.accessToken).toBeValidJWT();
    expect(token).toHaveTrustLevel(TrustLevel.Medium);
    expect(token.tokenType).toBe('Bearer');
  });

  it('should validate token and return claims', async () => {
    const request = {
      userId: 'test-user',
      email: 'test@example.com',
      roles: ['user'],
      permissions: ['read'],
      trustLevel: TrustLevel.High
    };

    const token = await jwtManager.generateToken(request);
    const claims = await jwtManager.validateToken(token.accessToken);

    expect(claims.userId).toBe('test-user');
    expect(claims.trustLevel).toBe(TrustLevel.High);
    expect(claims.roles).toContain('user');
  });
});
```

## 📚 **API Reference**

### **JWTManager**

```typescript
class JWTManager {
  constructor(config: JWTConfig);
  
  async generateToken(request: TokenRequest): Promise<Token>;
  async validateToken(tokenString: string): Promise<JWTClaims>;
  async blacklistToken(tokenString: string, reason: string): Promise<void>;
  async refreshToken(refreshToken: string, request: TokenRequest): Promise<Token>;
  
  setBlacklist(blacklist: Blacklist): void;
  getConfig(): Omit<JWTConfig, 'secret'>;
}
```

### **TrustCalculator**

```typescript
class TrustCalculator {
  constructor(
    deviceService?: DeviceService,
    behaviorService?: BehaviorService,
    locationService?: LocationService,
    config?: Partial<CalculatorConfig>
  );
  
  calculate(factors: TrustFactors): TrustLevel;
  async calculateForUser(request: CalculationRequest): Promise<TrustLevel>;
  async calculateForAuthentication(userId: string, deviceId?: string, ipAddress?: string): Promise<TrustLevel>;
  
  static getTrustLevelForOperation(operation: string): TrustLevel;
  static validateFactors(factors: TrustFactors): void;
  static requireTrustLevel(required: TrustLevel): (actual: TrustLevel) => boolean;
}
```

### **Trust Levels**

```typescript
enum TrustLevel {
  None = 0,    // Untrusted
  Low = 25,    // Basic authentication
  Medium = 50, // Known device
  High = 75,   // Verified device + location
  Full = 100   // Hardware attestation
}
```

## 🔗 **Integration Examples**

### **Express.js Middleware**

```typescript
import express from 'express';
import { JWTManager, TrustLevel, createDefaultJWTConfig } from '@zerotrust/auth-core';

const app = express();
const jwtManager = new JWTManager(createDefaultJWTConfig());

// Authentication middleware
const authenticateJWT = async (req: any, res: any, next: any) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  try {
    const claims = await jwtManager.validateToken(token);
    req.user = claims;
    next();
  } catch (error) {
    return res.sendStatus(403);
  }
};

// Trust level middleware
const requireTrustLevel = (minLevel: TrustLevel) => {
  return (req: any, res: any, next: any) => {
    if (req.user.trustLevel < minLevel) {
      return res.status(403).json({ error: 'Insufficient trust level' });
    }
    next();
  };
};

// Protected routes
app.get('/api/profile', authenticateJWT, (req, res) => {
  res.json({ message: 'Profile data', user: req.user });
});

app.delete('/api/resource/:id', 
  authenticateJWT, 
  requireTrustLevel(TrustLevel.High), 
  (req, res) => {
    res.json({ message: 'Resource deleted' });
  }
);
```

### **Next.js API Route**

```typescript
import type { NextApiRequest, NextApiResponse } from 'next';
import { JWTManager, createDefaultJWTConfig } from '@zerotrust/auth-core';

const jwtManager = new JWTManager(createDefaultJWTConfig());

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { email, password } = req.body;
    
    // Validate credentials (your logic here)
    const user = await validateCredentials(email, password);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = await jwtManager.generateToken({
      userId: user.id,
      email: user.email,
      roles: user.roles,
      permissions: user.permissions,
      trustLevel: 50 // Calculate based on login context
    });

    res.json(token);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
}
```

## 🔒 **Security Considerations**

- **Secret Management**: Store JWT secrets securely (environment variables, key vaults)
- **Token Expiration**: Use short expiration times for access tokens
- **Blacklisting**: Implement token blacklisting for immediate revocation
- **Trust Levels**: Adjust trust calculations based on your security requirements
- **Key Rotation**: Enable automatic key rotation for enhanced security
- **Input Validation**: Always validate inputs before processing

## 📄 **License**

MIT License - see [LICENSE](../../LICENSE) file for details.

---

**Zero Trust Authentication Core** - Building secure, scalable authentication for TypeScript applications.