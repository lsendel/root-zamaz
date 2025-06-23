# Device Attestation Guide

This guide explains how to implement and configure device attestation in the Keycloak Zero Trust library.

## Overview

Device attestation is a critical component of Zero Trust security that verifies the integrity and trustworthiness of devices accessing your systems. It ensures that only verified, secure devices can authenticate users and access resources.

## Supported Platforms

### Android
- **SafetyNet Attestation API** (Legacy)
- **Play Integrity API** (Recommended)
- **Hardware Security Module (HSM)** support
- **Bootloader and root detection**

### iOS
- **DeviceCheck API**
- **Secure Enclave verification**
- **Jailbreak detection**
- **App Attest API** (iOS 14+)

### Windows
- **Trusted Platform Module (TPM)**
- **Windows Hello verification**
- **Secure Boot validation**
- **Device Guard integration**

### macOS
- **Secure Enclave** (T2/M1/M2 chips)
- **Touch ID/Face ID verification**
- **System Integrity Protection (SIP)**
- **Notarization validation**

### Linux
- **TPM 2.0 support**
- **IMA/EVM (Integrity Measurement Architecture)**
- **UEFI Secure Boot**
- **Hardware attestation**

### Web/Browser
- **WebAuthn support**
- **Browser fingerprinting**
- **Hardware token verification**
- **Secure context validation**

## How Device Attestation Works

### 1. Device Registration

```go
import (
    "github.com/yourorg/go-keycloak-zerotrust/pkg/zerotrust"
    "github.com/yourorg/go-keycloak-zerotrust/pkg/types"
)

// Initialize device attestation service
config := &types.ZeroTrustConfig{
    ZeroTrust: &types.ZeroTrustSettings{
        EnableDeviceAttestation: true,
        DeviceVerificationTTL:   24 * time.Hour,
    },
}

deviceService := zerotrust.NewDeviceAttestationService(config, storage)

// Generate nonce for attestation
nonce, err := deviceService.GenerateNonce()
if err != nil {
    return err
}

// Client creates attestation data
attestation := &zerotrust.DeviceAttestation{
    DeviceID:          "device-unique-id",
    UserID:            "user-123", 
    Platform:          "android",
    DeviceFingerprint: "hardware-fingerprint",
    HardwareData:      hardwareInfo,
    SoftwareData:      softwareInfo,
    Timestamp:         time.Now(),
    Nonce:             nonce,
    Signature:         signedAttestation,
}

// Verify attestation
result, err := deviceService.AttestDevice(ctx, attestation)
if err != nil {
    return fmt.Errorf("attestation failed: %w", err)
}

if result.IsValid {
    log.Printf("Device verified with trust score: %d", result.TrustScore)
}
```

### 2. Continuous Verification

```go
// Verify existing device
device, err := deviceService.VerifyDevice(ctx, "device-id")
if err != nil {
    return err
}

// Check if verification is still valid
if !device.IsVerified {
    // Require re-attestation
    return errors.New("device verification expired")
}

// Check trust level
if device.TrustLevel < requiredTrustLevel {
    return errors.New("insufficient device trust")
}
```

## Platform-Specific Implementation

### Android Implementation

#### SafetyNet Integration

```kotlin
// Android client code
class SafetyNetAttestationClient {
    fun performAttestation(nonce: String, callback: AttestationCallback) {
        SafetyNet.getClient(context)
            .attest(nonce.toByteArray(), BuildConfig.API_KEY)
            .addOnSuccessListener { response ->
                val attestationData = DeviceAttestation(
                    deviceId = getDeviceId(),
                    platform = "android",
                    deviceFingerprint = getDeviceFingerprint(),
                    hardwareData = mapOf(
                        "bootloader_unlocked" to isBootloaderUnlocked(),
                        "safetynet_enabled" to true,
                        "hardware_backed_keystore" to hasHardwareKeystore()
                    ),
                    softwareData = mapOf(
                        "os_version" to Build.VERSION.RELEASE,
                        "security_patch" to Build.VERSION.SECURITY_PATCH,
                        "play_protect_enabled" to isPlayProtectEnabled()
                    ),
                    nonce = nonce,
                    signature = response.jwsResult
                )
                callback.onSuccess(attestationData)
            }
            .addOnFailureListener { exception ->
                callback.onFailure(exception)
            }
    }
}
```

#### Go Server Verification

```go
type AndroidVerifier struct {
    apiKey string
}

func (v *AndroidVerifier) VerifyDevice(ctx context.Context, attestation *DeviceAttestation) (*VerificationResult, error) {
    // Parse SafetyNet JWS response
    token, err := jwt.Parse(attestation.Signature, func(token *jwt.Token) (interface{}, error) {
        // Verify signing certificate chain
        return getGooglePublicKey(token.Header["x5c"])
    })
    
    if err != nil {
        return &VerificationResult{
            IsValid: false,
            Reasons: []string{"invalid_signature"},
        }, nil
    }
    
    claims := token.Claims.(jwt.MapClaims)
    
    // Verify nonce
    if claims["nonce"] != attestation.Nonce {
        return &VerificationResult{
            IsValid: false,
            Reasons: []string{"nonce_mismatch"},
        }, nil
    }
    
    // Check basic integrity
    basicIntegrity := claims["basicIntegrity"].(bool)
    ctsProfileMatch := claims["ctsProfileMatch"].(bool)
    
    trustScore := 75
    riskFactors := []string{}
    
    if !basicIntegrity {
        trustScore -= 40
        riskFactors = append(riskFactors, "basic_integrity_failed")
    }
    
    if !ctsProfileMatch {
        trustScore -= 20
        riskFactors = append(riskFactors, "cts_profile_mismatch")
    }
    
    // Check for rooting indicators
    if bootloaderUnlocked, ok := attestation.HardwareData["bootloader_unlocked"].(bool); ok && bootloaderUnlocked {
        trustScore -= 30
        riskFactors = append(riskFactors, "bootloader_unlocked")
    }
    
    return &VerificationResult{
        IsValid:           basicIntegrity,
        TrustScore:        trustScore,
        VerificationLevel: "hardware",
        RiskFactors:       riskFactors,
        ExpiresAt:         time.Now().Add(24 * time.Hour),
    }, nil
}
```

### iOS Implementation

#### DeviceCheck Integration

```swift
// iOS client code
import DeviceCheck

class DeviceCheckAttestationClient {
    func performAttestation(nonce: String, completion: @escaping (AttestationResult) -> Void) {
        guard DCDevice.current.isSupported else {
            completion(.failure(.deviceNotSupported))
            return
        }
        
        DCDevice.current.generateToken { [weak self] data, error in
            if let error = error {
                completion(.failure(.tokenGenerationFailed(error)))
                return
            }
            
            guard let tokenData = data else {
                completion(.failure(.noTokenData))
                return
            }
            
            let attestationData = DeviceAttestation(
                deviceId: self?.getDeviceId() ?? "",
                platform: "ios",
                deviceFingerprint: self?.getDeviceFingerprint() ?? "",
                hardwareData: [
                    "secure_enclave": self?.hasSecureEnclave() ?? false,
                    "biometry_available": self?.isBiometryAvailable() ?? false,
                    "devicecheck_token": tokenData.base64EncodedString()
                ],
                softwareData: [
                    "ios_version": UIDevice.current.systemVersion,
                    "jailbroken": self?.isJailbroken() ?? false,
                    "app_store_receipt": self?.hasAppStoreReceipt() ?? false
                ],
                nonce: nonce,
                signature: self?.signAttestation(data: tokenData, nonce: nonce) ?? ""
            )
            
            completion(.success(attestationData))
        }
    }
}
```

#### Go Server Verification

```go
type IOSVerifier struct {
    teamID    string
    keyID     string
    appleURL  string
}

func (v *IOSVerifier) VerifyDevice(ctx context.Context, attestation *DeviceAttestation) (*VerificationResult, error) {
    // Extract DeviceCheck token
    tokenData, ok := attestation.HardwareData["devicecheck_token"].(string)
    if !ok {
        return &VerificationResult{
            IsValid: false,
            Reasons: []string{"missing_devicecheck_token"},
        }, nil
    }
    
    // Verify with Apple's DeviceCheck API
    deviceCheckResult, err := v.verifyWithApple(ctx, tokenData, attestation.DeviceID)
    if err != nil {
        return &VerificationResult{
            IsValid: false,
            Reasons: []string{"apple_verification_failed"},
        }, nil
    }
    
    trustScore := 80
    riskFactors := []string{}
    
    // Check for jailbreak
    if jailbroken, ok := attestation.SoftwareData["jailbroken"].(bool); ok && jailbroken {
        trustScore -= 40
        riskFactors = append(riskFactors, "jailbroken")
    }
    
    // Check Secure Enclave availability
    if secureEnclave, ok := attestation.HardwareData["secure_enclave"].(bool); ok && secureEnclave {
        trustScore += 10
    }
    
    return &VerificationResult{
        IsValid:           deviceCheckResult.Valid,
        TrustScore:        trustScore,
        VerificationLevel: "hardware",
        RiskFactors:       riskFactors,
        ExpiresAt:         time.Now().Add(24 * time.Hour),
        Metadata: map[string]interface{}{
            "devicecheck_verified": true,
            "apple_fraud_metric":   deviceCheckResult.FraudMetric,
        },
    }, nil
}

func (v *IOSVerifier) verifyWithApple(ctx context.Context, token, deviceID string) (*DeviceCheckResult, error) {
    // Create JWT for Apple API authentication
    jwt, err := v.createAppleJWT()
    if err != nil {
        return nil, err
    }
    
    // Call Apple DeviceCheck API
    payload := map[string]interface{}{
        "device_token": token,
        "transaction_id": generateTransactionID(),
        "timestamp": time.Now().Unix(),
    }
    
    // Make request to Apple
    resp, err := v.makeAppleRequest(ctx, jwt, payload)
    if err != nil {
        return nil, err
    }
    
    return parseDeviceCheckResponse(resp)
}
```

### Web/Browser Implementation

#### WebAuthn Integration

```javascript
// Browser client code
class WebAuthnAttestationClient {
    async performAttestation(nonce) {
        try {
            // Check WebAuthn support
            if (!window.PublicKeyCredential) {
                throw new Error('WebAuthn not supported');
            }
            
            // Generate device fingerprint
            const fingerprint = await this.generateFingerprint();
            
            // Create WebAuthn credential for attestation
            const credential = await navigator.credentials.create({
                publicKey: {
                    challenge: new TextEncoder().encode(nonce),
                    rp: { name: "Zero Trust Demo" },
                    user: {
                        id: new TextEncoder().encode("demo-user"),
                        name: "demo@example.com",
                        displayName: "Demo User"
                    },
                    pubKeyCredParams: [{alg: -7, type: "public-key"}],
                    attestation: "direct",
                    authenticatorSelection: {
                        authenticatorAttachment: "platform",
                        requireResidentKey: false,
                        userVerification: "preferred"
                    }
                }
            });
            
            return {
                deviceId: await this.getDeviceId(),
                platform: "web",
                deviceFingerprint: fingerprint,
                hardwareData: {
                    user_agent: navigator.userAgent,
                    webgl_hash: await this.getWebGLFingerprint(),
                    canvas_hash: await this.getCanvasFingerprint(),
                    webauthn_available: true,
                    credential_id: Array.from(new Uint8Array(credential.rawId))
                },
                softwareData: {
                    browser_name: this.getBrowserName(),
                    browser_version: this.getBrowserVersion(),
                    platform: navigator.platform,
                    language: navigator.language,
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
                },
                nonce: nonce,
                signature: Array.from(new Uint8Array(credential.response.signature))
            };
        } catch (error) {
            throw new Error(`Attestation failed: ${error.message}`);
        }
    }
    
    async generateFingerprint() {
        const components = [
            navigator.userAgent,
            screen.width + "x" + screen.height,
            screen.colorDepth,
            new Date().getTimezoneOffset(),
            navigator.language,
            navigator.platform
        ];
        
        // Add WebGL fingerprint
        const webglFingerprint = await this.getWebGLFingerprint();
        components.push(webglFingerprint);
        
        // Hash all components
        const fingerprint = components.join('|');
        const hashBuffer = await crypto.subtle.digest('SHA-256', 
            new TextEncoder().encode(fingerprint));
        
        return Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
}
```

## Configuration

### Basic Configuration

```yaml
zero_trust:
  device_attestation:
    supported_platforms:
      - "android"
      - "ios"
      - "windows"
      - "macos"
      - "linux"
      - "web"
    
    # Global settings
    device_verification_ttl: "24h"
    require_hardware_attestation: true
    allow_emulators: false
```

### Platform-Specific Settings

```yaml
zero_trust:
  device_attestation:
    android:
      require_safetynet: true
      require_play_protect: true
      allow_unlocked_bootloader: false
      min_security_patch_days: 90
      api_key: "${SAFETYNET_API_KEY}"
    
    ios:
      require_devicecheck: true
      require_secure_enclave: true
      allow_jailbroken: false
      min_ios_version: "15.0"
      team_id: "${APPLE_TEAM_ID}"
      key_id: "${APPLE_KEY_ID}"
    
    web:
      require_webauthn: false
      fingerprinting_enabled: true
      require_secure_context: true
      max_trust_score: 60
    
    windows:
      require_tpm: true
      require_secure_boot: true
      allow_test_signed: false
    
    macos:
      require_secure_enclave: true
      require_sip: true
      allow_unsigned_code: false
    
    linux:
      require_tpm: false
      require_secure_boot: false
      require_ima: true
```

## Trust Scoring

Device attestation contributes to the overall trust score based on several factors:

### Scoring Factors

1. **Hardware Security**
   - TPM/Secure Enclave: +20 points
   - Hardware keystore: +15 points
   - Biometric capability: +10 points

2. **Software Integrity**
   - Verified boot: +15 points
   - App signature verification: +10 points
   - No tampering detected: +10 points

3. **Platform Security**
   - Latest security patches: +10 points
   - Security features enabled: +5 points
   - Strong encryption: +5 points

4. **Risk Factors**
   - Rooted/Jailbroken: -40 points
   - Unlocked bootloader: -30 points
   - Emulator detected: -50 points
   - Unsigned code: -20 points

### Example Trust Scores

| Device Type | Conditions | Trust Score |
|-------------|------------|-------------|
| iPhone 14 Pro | Latest iOS, Face ID, not jailbroken | 90-95 |
| Pixel 7 | Android 13, SafetyNet, locked bootloader | 85-90 |
| MacBook Pro M2 | macOS 13, Secure Enclave, SIP enabled | 85-90 |
| Windows 11 | TPM 2.0, Secure Boot, Windows Hello | 80-85 |
| Linux Workstation | TPM 2.0, IMA enabled, signed kernel | 75-80 |
| Web Browser | WebAuthn, HTTPS, modern browser | 40-60 |
| Rooted Android | Custom ROM, no SafetyNet | 10-30 |

## Security Considerations

### Best Practices

1. **Use Hardware Attestation** when available
2. **Verify Attestation Signatures** cryptographically
3. **Check Certificate Chains** for platform attestation
4. **Implement Nonce Verification** to prevent replay attacks
5. **Monitor for Anomalies** in device behavior
6. **Regular Re-attestation** to maintain trust
7. **Graceful Degradation** for unsupported platforms

### Common Attacks and Mitigations

#### 1. Emulator Detection Bypass

**Attack**: Running apps in emulators to bypass device checks
**Mitigation**: 
- Multiple emulator detection techniques
- Hardware feature verification
- Performance-based detection

#### 2. Root/Jailbreak Hiding

**Attack**: Using tools to hide root/jailbreak status
**Mitigation**:
- Multiple detection methods
- Kernel-level checks
- Runtime application self-protection (RASP)

#### 3. Attestation Replay

**Attack**: Reusing valid attestation responses
**Mitigation**:
- Time-bound nonces
- Device-specific challenges
- Short-lived attestations

#### 4. Man-in-the-Middle

**Attack**: Intercepting attestation communications
**Mitigation**:
- Certificate pinning
- End-to-end encryption
- Secure communication channels

## Troubleshooting

### Common Issues

#### Attestation Failures

```go
// Check device compatibility
supported := deviceService.IsPlatformSupported("android")
if !supported {
    log.Println("Platform not supported")
}

// Verify nonce freshness
if time.Since(attestation.Timestamp) > 5*time.Minute {
    return errors.New("attestation too old")
}

// Check signature validity
if attestation.Signature == "" {
    return errors.New("missing attestation signature")
}
```

#### Trust Score Issues

```go
// Debug trust score calculation
result, err := deviceService.AttestDevice(ctx, attestation)
if err != nil {
    return err
}

log.Printf("Trust Score: %d", result.TrustScore)
log.Printf("Verification Level: %s", result.VerificationLevel)
log.Printf("Risk Factors: %v", result.RiskFactors)

// Check individual factors
for _, reason := range result.Reasons {
    log.Printf("Verification reason: %s", reason)
}
```

#### Platform-Specific Debugging

**Android:**
```bash
# Check SafetyNet status
adb shell getprop ro.boot.verifiedbootstate
adb shell getprop ro.boot.flash.locked

# Verify Play Protect
adb shell dumpsys package com.google.android.gms | grep -i "play protect"
```

**iOS:**
```bash
# Check jailbreak indicators
ls /Applications/Cydia.app
ls /bin/bash
ls /etc/apt
```

**Web:**
```javascript
// Check WebAuthn support
console.log('WebAuthn supported:', !!window.PublicKeyCredential);

// Check secure context
console.log('Secure context:', window.isSecureContext);

// Check available authenticators
navigator.credentials.get({
    publicKey: { challenge: new Uint8Array(32) }
}).then(result => console.log('Authenticator available'));
```

## Testing

### Unit Tests

```go
func TestDeviceAttestation(t *testing.T) {
    config := getTestConfig()
    storage := NewMockDeviceStorage()
    service := NewDeviceAttestationService(config, storage)
    
    // Test valid attestation
    attestation := createValidAttestation("android")
    result, err := service.AttestDevice(ctx, attestation)
    
    assert.NoError(t, err)
    assert.True(t, result.IsValid)
    assert.Greater(t, result.TrustScore, 50)
}

func TestRootedDeviceDetection(t *testing.T) {
    attestation := createValidAttestation("android")
    attestation.HardwareData["bootloader_unlocked"] = true
    
    result, err := service.AttestDevice(ctx, attestation)
    
    assert.NoError(t, err)
    assert.Contains(t, result.RiskFactors, "bootloader_unlocked")
    assert.Less(t, result.TrustScore, 50)
}
```

### Integration Tests

```go
func TestRealDeviceAttestation(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }
    
    // Use real device for integration testing
    deviceID := os.Getenv("TEST_DEVICE_ID")
    if deviceID == "" {
        t.Skip("No test device configured")
    }
    
    // Test with real attestation data
    // ... integration test code
}
```

## Metrics and Monitoring

### Key Metrics

```go
// Device attestation metrics
attestationTotal := prometheus.NewCounterVec(
    prometheus.CounterOpts{
        Name: "device_attestation_total",
        Help: "Total device attestation attempts",
    },
    []string{"platform", "result"},
)

attestationDuration := prometheus.NewHistogramVec(
    prometheus.HistogramOpts{
        Name: "device_attestation_duration_seconds",
        Help: "Device attestation processing time",
    },
    []string{"platform"},
)

trustScoreGauge := prometheus.NewGaugeVec(
    prometheus.GaugeOpts{
        Name: "device_trust_score",
        Help: "Current device trust scores",
    },
    []string{"device_id", "platform"},
)
```

### Monitoring Alerts

```yaml
# Prometheus alerts
- alert: HighAttestationFailureRate
  expr: rate(device_attestation_total{result="failure"}[5m]) > 0.1
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "High device attestation failure rate"

- alert: LowAverageTrustScore
  expr: avg(device_trust_score) < 60
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "Average device trust score is low"
```

This comprehensive guide covers all aspects of device attestation implementation in the Zero Trust library. Follow platform-specific best practices and continuously monitor attestation health for optimal security.