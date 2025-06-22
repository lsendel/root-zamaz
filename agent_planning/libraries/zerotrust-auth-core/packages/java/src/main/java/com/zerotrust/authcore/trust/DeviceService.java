package com.zerotrust.authcore.trust;

import java.util.concurrent.CompletableFuture;

/**
 * Device service interface for device verification.
 */
public interface DeviceService {
    
    /**
     * Verify device authenticity.
     * 
     * @param deviceId the device identifier
     * @return a CompletableFuture that resolves to true if device is verified
     */
    CompletableFuture<Boolean> verifyDevice(String deviceId);
    
    /**
     * Get device history information.
     * 
     * @param deviceId the device identifier
     * @return a CompletableFuture that resolves to device history or null if not found
     */
    CompletableFuture<TrustCalculator.DeviceHistory> getDeviceHistory(String deviceId);
    
    /**
     * Check hardware attestation status.
     * 
     * @param deviceId the device identifier
     * @return a CompletableFuture that resolves to true if hardware attestation is valid
     */
    CompletableFuture<Boolean> checkHardwareAttestation(String deviceId);
    
    /**
     * Check if device is trusted.
     * 
     * @param deviceId the device identifier
     * @return a CompletableFuture that resolves to true if device is trusted
     */
    CompletableFuture<Boolean> isDeviceTrusted(String deviceId);
    
    /**
     * Mark device as trusted.
     * 
     * @param deviceId the device identifier
     * @return a CompletableFuture that completes when the operation is done
     */
    CompletableFuture<Void> markDeviceAsTrusted(String deviceId);
}