# Zero Trust Authentication Core Library - Implementation Plan

> **Library**: `@zerotrust/auth-core` (Multi-language)  
> **Priority**: 🔴 **CRITICAL** - Extract First  
> **Timeline**: 4 weeks for MVP, 8 weeks for production-ready  
> **Goal**: Centralized, consistent authentication patterns across all Zero Trust projects

## 🎯 **Implementation Overview**

This document outlines the step-by-step implementation of the Authentication Core library, the most critical component for establishing consistent Zero Trust security patterns across all projects.

### **Why Auth Core First?**
1. **Security Consistency**: Prevents security implementation drift between projects
2. **Highest Code Duplication**: Auth patterns repeated in all 4 templates
3. **Security-Critical**: Authentication bugs have the highest impact
4. **Foundational**: Other libraries depend on consistent auth patterns

## 📋 **Week-by-Week Implementation Plan**

### **Week 1: Repository Setup and Go Implementation**

#### **Day 1-2: Repository Structure**
```bash
# Create monorepo structure
mkdir zerotrust-auth-core
cd zerotrust-auth-core

# Initialize monorepo with Lerna
npm init -y
npm install --save-dev lerna nx @commitlint/cli @commitlint/config-conventional
npx lerna init

# Create directory structure
mkdir -p packages/{go,typescript,python,java}
mkdir -p docs examples tests
```

#### **Repository Configuration**
```json
// lerna.json
{
  "version": "independent",
  "npmClient": "npm",
  "command": {
    "publish": {
      "conventionalCommits": true,
      "message": "chore(release): publish",
      "registry": "https://registry.npmjs.org/"
    },
    "version": {
      "allowBranch": ["main", "release/*"],
      "conventionalCommits": true
    }
  },
  "packages": [
    "packages/*"
  ]
}
```

#### **Day 3-5: Go Implementation Core**
```go
// packages/go/pkg/jwt/manager.go
package jwt

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "strings"
    "sync"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
)

// Manager handles JWT operations with Zero Trust principles
type Manager struct {
    keyManager *KeyManager
    blacklist  Blacklist
    config     *Config
}

// Config represents JWT configuration
type Config struct {
    Secret           string
    ExpiryDuration   time.Duration
    RefreshDuration  time.Duration
    Issuer           string
    RotationDuration time.Duration
}

// Claims represents JWT claims with Zero Trust attributes
type Claims struct {
    UserID      string   `json:"user_id"`
    Email       string   `json:"email"`
    Roles       []string `json:"roles"`
    Permissions []string `json:"permissions"`
    DeviceID    string   `json:"device_id,omitempty"`
    TrustLevel  int      `json:"trust_level"`
    jwt.RegisteredClaims
}

// Token represents a complete token response
type Token struct {
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token"`
    TokenType    string    `json:"token_type"`
    ExpiresAt    time.Time `json:"expires_at"`
    TrustLevel   int       `json:"trust_level"`
}

// NewManager creates a new JWT manager with Zero Trust capabilities
func NewManager(config *Config) (*Manager, error) {
    if len(config.Secret) < 32 {
        return nil, fmt.Errorf("JWT secret must be at least 32 characters")
    }

    keyManager := NewKeyManager([]byte(config.Secret), config.RotationDuration)
    blacklist := NewMemoryBlacklist() // Default implementation

    return &Manager{
        keyManager: keyManager,
        blacklist:  blacklist,
        config:     config,
    }, nil
}

// GenerateToken creates a new JWT token with trust level
func (m *Manager) GenerateToken(ctx context.Context, req *TokenRequest) (*Token, error) {
    now := time.Now()
    expiresAt := now.Add(m.config.ExpiryDuration)
    jti := uuid.New().String()

    claims := &Claims{
        UserID:      req.UserID,
        Email:       req.Email,
        Roles:       req.Roles,
        Permissions: req.Permissions,
        DeviceID:    req.DeviceID,
        TrustLevel:  req.TrustLevel,
        RegisteredClaims: jwt.RegisteredClaims{
            Issuer:    m.config.Issuer,
            Subject:   req.UserID,
            ExpiresAt: jwt.NewNumericDate(expiresAt),
            IssuedAt:  jwt.NewNumericDate(now),
            NotBefore: jwt.NewNumericDate(now),
            ID:        jti,
        },
    }

    // Get current signing key
    currentKey := m.keyManager.GetCurrentKey()
    if currentKey == nil {
        return nil, fmt.Errorf("no active signing key available")
    }

    // Create token
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    token.Header["kid"] = currentKey.ID

    tokenString, err := token.SignedString(currentKey.Key)
    if err != nil {
        return nil, fmt.Errorf("failed to sign token: %w", err)
    }

    // Generate refresh token
    refreshToken, err := m.generateRefreshToken(req.UserID)
    if err != nil {
        return nil, fmt.Errorf("failed to generate refresh token: %w", err)
    }

    return &Token{
        AccessToken:  tokenString,
        RefreshToken: refreshToken,
        TokenType:    "Bearer",
        ExpiresAt:    expiresAt,
        TrustLevel:   req.TrustLevel,
    }, nil
}

// ValidateToken validates a JWT token and returns claims
func (m *Manager) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
    // Check blacklist first
    if blacklisted, err := m.blacklist.IsBlacklisted(ctx, tokenString); err != nil {
        return nil, fmt.Errorf("blacklist check failed: %w", err)
    } else if blacklisted {
        return nil, ErrTokenBlacklisted
    }

    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }

        // Check for key ID in token header
        if kidInterface, ok := token.Header["kid"]; ok {
            if kid, ok := kidInterface.(string); ok {
                if key := m.keyManager.GetKey(kid); key != nil {
                    return key.Key, nil
                }
            }
        }

        // Fallback to current key
        if currentKey := m.keyManager.GetCurrentKey(); currentKey != nil {
            return currentKey.Key, nil
        }

        return nil, fmt.Errorf("no valid signing key found")
    })

    if err != nil {
        return nil, fmt.Errorf("token validation failed: %w", err)
    }

    if claims, ok := token.Claims.(*Claims); ok && token.Valid {
        return claims, nil
    }

    return nil, ErrInvalidToken
}

// BlacklistToken adds a token to the blacklist
func (m *Manager) BlacklistToken(ctx context.Context, tokenString, reason string) error {
    // Extract JTI and expiration from token for efficient blacklisting
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // We don't validate here, just extract claims
        return []byte("dummy"), nil
    })

    if err != nil && !strings.Contains(err.Error(), "signature is invalid") {
        return fmt.Errorf("failed to parse token for blacklisting: %w", err)
    }

    if claims, ok := token.Claims.(jwt.MapClaims); ok {
        jti, _ := claims["jti"].(string)
        expUnix, _ := claims["exp"].(float64)
        exp := time.Unix(int64(expUnix), 0)

        return m.blacklist.Add(ctx, jti, reason, exp)
    }

    return fmt.Errorf("failed to extract claims for blacklisting")
}
```

#### **Trust Level Calculation**
```go
// packages/go/pkg/trust/calculator.go
package trust

import (
    "context"
    "time"
)

// Level represents trust levels in Zero Trust architecture
type Level int

const (
    None   Level = 0   // Untrusted
    Low    Level = 25  // Basic authentication
    Medium Level = 50  // Known device
    High   Level = 75  // Verified device + location
    Full   Level = 100 // Hardware attestation
)

// Factors represents factors used in trust calculation
type Factors struct {
    DeviceVerified     bool
    LocationVerified   bool
    BehaviorNormal     bool
    RecentActivity     bool
    HardwareAttestation bool
    BiometricVerified  bool
    NetworkTrusted     bool
}

// Calculator calculates trust levels based on various factors
type Calculator struct {
    deviceService    DeviceService
    behaviorService  BehaviorService
    locationService  LocationService
}

// DeviceService interface for device verification
type DeviceService interface {
    VerifyDevice(ctx context.Context, deviceID string) (bool, error)
    GetDeviceHistory(ctx context.Context, deviceID string) (*DeviceHistory, error)
    CheckHardwareAttestation(ctx context.Context, deviceID string) (bool, error)
}

// BehaviorService interface for behavior analysis
type BehaviorService interface {
    AnalyzeBehavior(ctx context.Context, userID string, action string) (*BehaviorAnalysis, error)
    IsActionSuspicious(ctx context.Context, userID string, action string) (bool, error)
}

// LocationService interface for location verification
type LocationService interface {
    VerifyLocation(ctx context.Context, userID string, location *Location) (bool, error)
    IsLocationTrusted(ctx context.Context, location *Location) (bool, error)
}

// NewCalculator creates a new trust calculator
func NewCalculator(deviceSvc DeviceService, behaviorSvc BehaviorService, locationSvc LocationService) *Calculator {
    return &Calculator{
        deviceService:   deviceSvc,
        behaviorService: behaviorSvc,
        locationService: locationSvc,
    }
}

// Calculate computes trust level based on provided factors
func (c *Calculator) Calculate(ctx context.Context, factors *Factors) Level {
    baseScore := 10 // Minimum score for authenticated user

    // Device verification (25 points)
    if factors.DeviceVerified {
        baseScore += 25
    }

    // Location verification (20 points)
    if factors.LocationVerified {
        baseScore += 20
    }

    // Behavior analysis (15 points)
    if factors.BehaviorNormal {
        baseScore += 15
    }

    // Recent activity (10 points)
    if factors.RecentActivity {
        baseScore += 10
    }

    // Hardware attestation (15 points)
    if factors.HardwareAttestation {
        baseScore += 15
    }

    // Biometric verification (10 points)
    if factors.BiometricVerified {
        baseScore += 10
    }

    // Trusted network (5 points)
    if factors.NetworkTrusted {
        baseScore += 5
    }

    // Cap at 100
    if baseScore > 100 {
        baseScore = 100
    }

    return Level(baseScore)
}

// CalculateForUser performs comprehensive trust calculation for a user
func (c *Calculator) CalculateForUser(ctx context.Context, req *CalculationRequest) (Level, error) {
    factors := &Factors{}

    // Device verification
    if req.DeviceID != "" {
        verified, err := c.deviceService.VerifyDevice(ctx, req.DeviceID)
        if err != nil {
            return None, fmt.Errorf("device verification failed: %w", err)
        }
        factors.DeviceVerified = verified

        // Check hardware attestation
        hwAttested, err := c.deviceService.CheckHardwareAttestation(ctx, req.DeviceID)
        if err == nil { // Non-critical, continue if it fails
            factors.HardwareAttestation = hwAttested
        }
    }

    // Location verification
    if req.Location != nil {
        verified, err := c.locationService.VerifyLocation(ctx, req.UserID, req.Location)
        if err != nil {
            return None, fmt.Errorf("location verification failed: %w", err)
        }
        factors.LocationVerified = verified

        trusted, err := c.locationService.IsLocationTrusted(ctx, req.Location)
        if err == nil {
            factors.NetworkTrusted = trusted
        }
    }

    // Behavior analysis
    if req.Action != "" {
        suspicious, err := c.behaviorService.IsActionSuspicious(ctx, req.UserID, req.Action)
        if err != nil {
            return None, fmt.Errorf("behavior analysis failed: %w", err)
        }
        factors.BehaviorNormal = !suspicious
    }

    // Recent activity check
    factors.RecentActivity = time.Since(req.LastActivity) < 30*time.Minute

    return c.Calculate(ctx, factors), nil
}
```

### **Week 2: TypeScript Implementation**

#### **Day 8-10: TypeScript Core Implementation**
```typescript
// packages/typescript/src/jwt/Manager.ts
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

export interface Config {
    secret: string;
    expiryDuration: number; // milliseconds
    refreshDuration: number; // milliseconds
    issuer: string;
    rotationDuration?: number;
}

export interface Claims {
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
}

export interface Token {
    accessToken: string;
    refreshToken: string;
    tokenType: string;
    expiresAt: Date;
    trustLevel: number;
}

export interface TokenRequest {
    userId: string;
    email: string;
    roles: string[];
    permissions: string[];
    deviceId?: string;
    trustLevel: number;
}

export class JWTManager {
    private keyManager: KeyManager;
    private blacklist: Blacklist;
    private config: Config;

    constructor(config: Config) {
        if (config.secret.length < 32) {
            throw new Error('JWT secret must be at least 32 characters');
        }

        this.config = config;
        this.keyManager = new KeyManager(config.secret, config.rotationDuration || 24 * 60 * 60 * 1000);
        this.blacklist = new MemoryBlacklist(); // Default implementation
    }

    async generateToken(request: TokenRequest): Promise<Token> {
        const now = Date.now();
        const expiresAt = new Date(now + this.config.expiryDuration);
        const jti = uuidv4();

        const claims: Partial<Claims> = {
            userId: request.userId,
            email: request.email,
            roles: request.roles,
            permissions: request.permissions,
            deviceId: request.deviceId,
            trustLevel: request.trustLevel,
            iat: Math.floor(now / 1000),
            exp: Math.floor(expiresAt.getTime() / 1000),
            iss: this.config.issuer,
            sub: request.userId,
            jti,
        };

        // Get current signing key
        const currentKey = this.keyManager.getCurrentKey();
        if (!currentKey) {
            throw new Error('No active signing key available');
        }

        const tokenString = jwt.sign(claims, currentKey.key, {
            algorithm: 'HS256',
            header: { kid: currentKey.id },
        });

        // Generate refresh token
        const refreshToken = await this.generateRefreshToken(request.userId);

        return {
            accessToken: tokenString,
            refreshToken,
            tokenType: 'Bearer',
            expiresAt,
            trustLevel: request.trustLevel,
        };
    }

    async validateToken(tokenString: string): Promise<Claims> {
        // Check blacklist first
        const isBlacklisted = await this.blacklist.isBlacklisted(tokenString);
        if (isBlacklisted) {
            throw new Error('Token has been revoked');
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

                // Fallback to current key
                const currentKey = this.keyManager.getCurrentKey();
                if (currentKey) {
                    callback(null, currentKey.key);
                } else {
                    callback(new Error('No valid signing key found'), null);
                }
            }, {
                algorithms: ['HS256'],
            }) as Claims;

            return decoded;
        } catch (error) {
            throw new Error(`Token validation failed: ${error.message}`);
        }
    }

    async blacklistToken(tokenString: string, reason: string): Promise<void> {
        try {
            // Extract JTI and expiration for efficient blacklisting
            const decoded = jwt.decode(tokenString) as any;
            if (decoded && decoded.jti && decoded.exp) {
                const exp = new Date(decoded.exp * 1000);
                await this.blacklist.add(decoded.jti, reason, exp);
            } else {
                throw new Error('Failed to extract claims for blacklisting');
            }
        } catch (error) {
            throw new Error(`Failed to blacklist token: ${error.message}`);
        }
    }

    private async generateRefreshToken(userId: string): Promise<string> {
        const now = Date.now();
        const expiresAt = new Date(now + this.config.refreshDuration);

        const payload = {
            userId,
            type: 'refresh',
            iat: Math.floor(now / 1000),
            exp: Math.floor(expiresAt.getTime() / 1000),
            jti: uuidv4(),
        };

        const currentKey = this.keyManager.getCurrentKey();
        if (!currentKey) {
            throw new Error('No active signing key available');
        }

        return jwt.sign(payload, currentKey.key, { algorithm: 'HS256' });
    }
}
```

### **Week 3: Python and Java Implementation**

#### **Day 15-17: Python Implementation**
```python
# packages/python/zerotrust_auth/jwt/manager.py
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .blacklist import Blacklist, MemoryBlacklist
from .key_manager import KeyManager
from ..trust.calculator import TrustLevel


class Config:
    def __init__(
        self,
        secret: str,
        expiry_duration: timedelta = timedelta(minutes=30),
        refresh_duration: timedelta = timedelta(days=7),
        issuer: str = "zerotrust-auth",
        rotation_duration: timedelta = timedelta(hours=24),
    ):
        if len(secret) < 32:
            raise ValueError("JWT secret must be at least 32 characters")
        
        self.secret = secret
        self.expiry_duration = expiry_duration
        self.refresh_duration = refresh_duration
        self.issuer = issuer
        self.rotation_duration = rotation_duration


class Claims:
    def __init__(
        self,
        user_id: str,
        email: str,
        roles: List[str],
        permissions: List[str],
        trust_level: int,
        device_id: Optional[str] = None,
        iat: Optional[int] = None,
        exp: Optional[int] = None,
        iss: Optional[str] = None,
        sub: Optional[str] = None,
        jti: Optional[str] = None,
    ):
        self.user_id = user_id
        self.email = email
        self.roles = roles
        self.permissions = permissions
        self.device_id = device_id
        self.trust_level = trust_level
        self.iat = iat or int(time.time())
        self.exp = exp
        self.iss = iss
        self.sub = sub or user_id
        self.jti = jti or str(uuid.uuid4())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "email": self.email,
            "roles": self.roles,
            "permissions": self.permissions,
            "device_id": self.device_id,
            "trust_level": self.trust_level,
            "iat": self.iat,
            "exp": self.exp,
            "iss": self.iss,
            "sub": self.sub,
            "jti": self.jti,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Claims":
        return cls(
            user_id=data["user_id"],
            email=data["email"],
            roles=data["roles"],
            permissions=data["permissions"],
            trust_level=data["trust_level"],
            device_id=data.get("device_id"),
            iat=data.get("iat"),
            exp=data.get("exp"),
            iss=data.get("iss"),
            sub=data.get("sub"),
            jti=data.get("jti"),
        )


class Token:
    def __init__(
        self,
        access_token: str,
        refresh_token: str,
        token_type: str = "Bearer",
        expires_at: Optional[datetime] = None,
        trust_level: int = 50,
    ):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_type = token_type
        self.expires_at = expires_at
        self.trust_level = trust_level


class TokenRequest:
    def __init__(
        self,
        user_id: str,
        email: str,
        roles: List[str],
        permissions: List[str],
        trust_level: int,
        device_id: Optional[str] = None,
    ):
        self.user_id = user_id
        self.email = email
        self.roles = roles
        self.permissions = permissions
        self.device_id = device_id
        self.trust_level = trust_level


class JWTManager:
    def __init__(self, config: Config):
        self.config = config
        self.key_manager = KeyManager(config.secret.encode(), config.rotation_duration)
        self.blacklist: Blacklist = MemoryBlacklist()

    async def generate_token(self, request: TokenRequest) -> Token:
        now = datetime.utcnow()
        expires_at = now + self.config.expiry_duration
        jti = str(uuid.uuid4())

        claims = Claims(
            user_id=request.user_id,
            email=request.email,
            roles=request.roles,
            permissions=request.permissions,
            device_id=request.device_id,
            trust_level=request.trust_level,
            iat=int(now.timestamp()),
            exp=int(expires_at.timestamp()),
            iss=self.config.issuer,
            sub=request.user_id,
            jti=jti,
        )

        # Get current signing key
        current_key = self.key_manager.get_current_key()
        if not current_key:
            raise RuntimeError("No active signing key available")

        # Create token with key ID in header
        token_string = jwt.encode(
            claims.to_dict(),
            current_key.key,
            algorithm="HS256",
            headers={"kid": current_key.id},
        )

        # Generate refresh token
        refresh_token = await self._generate_refresh_token(request.user_id)

        return Token(
            access_token=token_string,
            refresh_token=refresh_token,
            expires_at=expires_at,
            trust_level=request.trust_level,
        )

    async def validate_token(self, token_string: str) -> Claims:
        # Check blacklist first
        is_blacklisted = await self.blacklist.is_blacklisted(token_string)
        if is_blacklisted:
            raise jwt.InvalidTokenError("Token has been revoked")

        try:
            # Decode header to get key ID
            header = jwt.get_unverified_header(token_string)
            
            # Get signing key
            signing_key = None
            if "kid" in header:
                key = self.key_manager.get_key(header["kid"])
                if key:
                    signing_key = key.key
            
            if not signing_key:
                current_key = self.key_manager.get_current_key()
                if current_key:
                    signing_key = current_key.key
                else:
                    raise jwt.InvalidKeyError("No valid signing key found")

            # Validate token
            payload = jwt.decode(
                token_string,
                signing_key,
                algorithms=["HS256"],
                options={"verify_signature": True},
            )

            return Claims.from_dict(payload)

        except jwt.InvalidTokenError as e:
            raise jwt.InvalidTokenError(f"Token validation failed: {str(e)}")

    async def blacklist_token(self, token_string: str, reason: str) -> None:
        try:
            # Extract JTI and expiration for efficient blacklisting
            payload = jwt.decode(token_string, options={"verify_signature": False})
            
            if "jti" in payload and "exp" in payload:
                jti = payload["jti"]
                exp_timestamp = payload["exp"]
                exp_datetime = datetime.utcfromtimestamp(exp_timestamp)
                
                await self.blacklist.add(jti, reason, exp_datetime)
            else:
                raise ValueError("Token missing required claims for blacklisting")
                
        except Exception as e:
            raise RuntimeError(f"Failed to blacklist token: {str(e)}")

    async def _generate_refresh_token(self, user_id: str) -> str:
        now = datetime.utcnow()
        expires_at = now + self.config.refresh_duration

        payload = {
            "user_id": user_id,
            "type": "refresh",
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": str(uuid.uuid4()),
        }

        current_key = self.key_manager.get_current_key()
        if not current_key:
            raise RuntimeError("No active signing key available")

        return jwt.encode(payload, current_key.key, algorithm="HS256")
```

### **Week 4: Testing, Documentation, and Release Preparation**

#### **Day 22-24: Comprehensive Testing**
```go
// packages/go/pkg/jwt/manager_test.go
package jwt_test

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "github.com/zerotrust/auth-core-go/pkg/jwt"
)

func TestJWTManager_GenerateToken(t *testing.T) {
    config := &jwt.Config{
        Secret:           "test-secret-key-32-characters-long",
        ExpiryDuration:   30 * time.Minute,
        RefreshDuration:  7 * 24 * time.Hour,
        Issuer:           "test-issuer",
        RotationDuration: 24 * time.Hour,
    }

    manager, err := jwt.NewManager(config)
    require.NoError(t, err)

    tests := []struct {
        name    string
        request *jwt.TokenRequest
        wantErr bool
    }{
        {
            name: "valid token generation",
            request: &jwt.TokenRequest{
                UserID:      "user123",
                Email:       "test@example.com",
                Roles:       []string{"user", "admin"},
                Permissions: []string{"read", "write"},
                DeviceID:    "device123",
                TrustLevel:  75,
            },
            wantErr: false,
        },
        {
            name: "minimal token generation",
            request: &jwt.TokenRequest{
                UserID:     "user456",
                Email:      "minimal@example.com",
                Roles:      []string{"user"},
                TrustLevel: 50,
            },
            wantErr: false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            ctx := context.Background()
            token, err := manager.GenerateToken(ctx, tt.request)

            if tt.wantErr {
                assert.Error(t, err)
                assert.Nil(t, token)
            } else {
                assert.NoError(t, err)
                assert.NotNil(t, token)
                assert.NotEmpty(t, token.AccessToken)
                assert.NotEmpty(t, token.RefreshToken)
                assert.Equal(t, "Bearer", token.TokenType)
                assert.Equal(t, tt.request.TrustLevel, token.TrustLevel)
                assert.True(t, token.ExpiresAt.After(time.Now()))
            }
        })
    }
}

func TestJWTManager_ValidateToken(t *testing.T) {
    config := &jwt.Config{
        Secret:           "test-secret-key-32-characters-long",
        ExpiryDuration:   30 * time.Minute,
        RefreshDuration:  7 * 24 * time.Hour,
        Issuer:           "test-issuer",
        RotationDuration: 24 * time.Hour,
    }

    manager, err := jwt.NewManager(config)
    require.NoError(t, err)

    ctx := context.Background()

    // Generate a token first
    request := &jwt.TokenRequest{
        UserID:      "user123",
        Email:       "test@example.com",
        Roles:       []string{"user", "admin"},
        Permissions: []string{"read", "write"},
        DeviceID:    "device123",
        TrustLevel:  75,
    }

    token, err := manager.GenerateToken(ctx, request)
    require.NoError(t, err)

    // Validate the token
    claims, err := manager.ValidateToken(ctx, token.AccessToken)
    assert.NoError(t, err)
    assert.NotNil(t, claims)
    assert.Equal(t, request.UserID, claims.UserID)
    assert.Equal(t, request.Email, claims.Email)
    assert.Equal(t, request.Roles, claims.Roles)
    assert.Equal(t, request.Permissions, claims.Permissions)
    assert.Equal(t, request.DeviceID, claims.DeviceID)
    assert.Equal(t, request.TrustLevel, claims.TrustLevel)
}

func TestJWTManager_BlacklistToken(t *testing.T) {
    config := &jwt.Config{
        Secret:           "test-secret-key-32-characters-long",
        ExpiryDuration:   30 * time.Minute,
        RefreshDuration:  7 * 24 * time.Hour,
        Issuer:           "test-issuer",
        RotationDuration: 24 * time.Hour,
    }

    manager, err := jwt.NewManager(config)
    require.NoError(t, err)

    ctx := context.Background()

    // Generate a token
    request := &jwt.TokenRequest{
        UserID:     "user123",
        Email:      "test@example.com",
        Roles:      []string{"user"},
        TrustLevel: 50,
    }

    token, err := manager.GenerateToken(ctx, request)
    require.NoError(t, err)

    // Blacklist the token
    err = manager.BlacklistToken(ctx, token.AccessToken, "test reason")
    assert.NoError(t, err)

    // Try to validate the blacklisted token
    _, err = manager.ValidateToken(ctx, token.AccessToken)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "blacklisted")
}
```

#### **Cross-Language Integration Tests**
```typescript
// tests/integration/cross-language.test.ts
import { describe, it, expect } from 'vitest';
import { JWTManager as GoManager } from '../packages/go/dist';
import { JWTManager as TypeScriptManager } from '../packages/typescript/dist';

describe('Cross-Language Token Compatibility', () => {
    const config = {
        secret: 'test-secret-key-32-characters-long',
        expiryDuration: 30 * 60 * 1000, // 30 minutes
        refreshDuration: 7 * 24 * 60 * 60 * 1000, // 7 days
        issuer: 'test-issuer',
    };

    it('should validate Go-generated tokens in TypeScript', async () => {
        const goManager = new GoManager(config);
        const tsManager = new TypeScriptManager(config);

        const tokenRequest = {
            userId: 'user123',
            email: 'test@example.com',
            roles: ['user', 'admin'],
            permissions: ['read', 'write'],
            trustLevel: 75,
        };

        // Generate token with Go implementation
        const goToken = await goManager.generateToken(tokenRequest);

        // Validate with TypeScript implementation
        const claims = await tsManager.validateToken(goToken.accessToken);

        expect(claims.userId).toBe(tokenRequest.userId);
        expect(claims.email).toBe(tokenRequest.email);
        expect(claims.roles).toEqual(tokenRequest.roles);
        expect(claims.permissions).toEqual(tokenRequest.permissions);
        expect(claims.trustLevel).toBe(tokenRequest.trustLevel);
    });

    it('should validate TypeScript-generated tokens in Go', async () => {
        const goManager = new GoManager(config);
        const tsManager = new TypeScriptManager(config);

        const tokenRequest = {
            userId: 'user456',
            email: 'typescript@example.com',
            roles: ['user'],
            permissions: ['read'],
            trustLevel: 50,
        };

        // Generate token with TypeScript implementation
        const tsToken = await tsManager.generateToken(tokenRequest);

        // Validate with Go implementation
        const claims = await goManager.validateToken(tsToken.accessToken);

        expect(claims.userID).toBe(tokenRequest.userId);
        expect(claims.email).toBe(tokenRequest.email);
        expect(claims.roles).toEqual(tokenRequest.roles);
        expect(claims.permissions).toEqual(tokenRequest.permissions);
        expect(claims.trustLevel).toBe(tokenRequest.trustLevel);
    });
});
```

## 📚 **Documentation Strategy**

### **API Documentation**
```markdown
# Zero Trust Authentication Core - API Reference

## Installation

### Go
```bash
go get github.com/zerotrust/auth-core-go/v1
```

### TypeScript/JavaScript
```bash
npm install @zerotrust/auth-core
```

### Python
```bash
pip install zerotrust-auth-core
```

### Java
```xml
<dependency>
    <groupId>com.zerotrust</groupId>
    <artifactId>auth-core</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Quick Start

### Go Example
```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/zerotrust/auth-core-go/v1/pkg/jwt"
    "github.com/zerotrust/auth-core-go/v1/pkg/trust"
)

func main() {
    config := &jwt.Config{
        Secret:           "your-secret-key-32-characters-long",
        ExpiryDuration:   30 * time.Minute,
        RefreshDuration:  7 * 24 * time.Hour,
        Issuer:           "my-service",
        RotationDuration: 24 * time.Hour,
    }

    manager, err := jwt.NewManager(config)
    if err != nil {
        log.Fatal(err)
    }

    // Generate token
    request := &jwt.TokenRequest{
        UserID:      "user123",
        Email:       "user@example.com",
        Roles:       []string{"user"},
        Permissions: []string{"read"},
        TrustLevel:  trust.Medium.Value(),
    }

    token, err := manager.GenerateToken(context.Background(), request)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Generated token: %s", token.AccessToken)
}
```

## Security Considerations

### Trust Levels
The library implements a 0-100 trust level system:

- **0 (None)**: Untrusted device or user
- **25 (Low)**: Basic authentication only
- **50 (Medium)**: Known device, standard authentication
- **75 (High)**: Verified device + location
- **100 (Full)**: Hardware attestation + biometric verification

### Token Security
- Tokens are signed with HMAC-SHA256
- Key rotation is supported with grace periods
- Blacklisting prevents token reuse after revocation
- Refresh tokens have longer expiry for UX balance

### Best Practices
1. **Use HTTPS**: Always transmit tokens over secure connections
2. **Short Expiry**: Use 15-30 minute access token expiry
3. **Trust Levels**: Require higher trust for sensitive operations
4. **Key Rotation**: Rotate signing keys every 24 hours in production
5. **Blacklist Management**: Clean up expired blacklist entries regularly
```

## 🚀 **Release Strategy**

### **Version 1.0.0 Release Checklist**

#### **Pre-Release (Day 26-28)**
- [ ] Complete all language implementations
- [ ] Cross-language compatibility tests passing
- [ ] Security audit completed
- [ ] Performance benchmarks established
- [ ] Documentation complete
- [ ] Examples tested

#### **Release Day (Day 28)**
```bash
# Automated release script
#!/bin/bash

# Run all tests
echo "Running comprehensive test suite..."
make test-all

# Build all packages
echo "Building packages..."
make build-all

# Security audit
echo "Running security audit..."
make security-audit

# Publish packages simultaneously
echo "Publishing Go package..."
git tag go/v1.0.0
git push origin go/v1.0.0

echo "Publishing TypeScript package..."
cd packages/typescript && npm publish

echo "Publishing Python package..."
cd packages/python && python -m build && twine upload dist/*

echo "Publishing Java package..."
cd packages/java && mvn deploy

echo "Release v1.0.0 complete!"
```

### **Post-Release (Week 5)**
- Monitor adoption and feedback
- Address any critical issues
- Plan v1.1.0 features based on user feedback
- Begin work on next library (E2E Testing Framework)

## 📊 **Success Metrics**

### **Technical Metrics**
- **Package Downloads**: Target 1000+ downloads in first month
- **Cross-Language Compatibility**: 100% test passing rate
- **Security**: Zero critical vulnerabilities
- **Performance**: < 1ms token generation, < 0.5ms validation

### **Adoption Metrics**
- **GitHub Stars**: Target 500+ stars
- **Community Contributions**: 10+ external contributors
- **Production Usage**: 5+ companies using in production
- **Documentation**: < 5 minute onboarding time

This implementation plan provides a solid foundation for the most critical library in the Zero Trust ecosystem, establishing patterns and practices that will be replicated across all subsequent libraries.