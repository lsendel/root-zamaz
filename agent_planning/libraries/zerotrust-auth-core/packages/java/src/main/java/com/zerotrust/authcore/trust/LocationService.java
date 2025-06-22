package com.zerotrust.authcore.trust;

import java.util.concurrent.CompletableFuture;

/**
 * Location service interface for location verification.
 */
public interface LocationService {
    
    /**
     * Verify location authenticity.
     * 
     * @param userId the user identifier
     * @param location the location to verify
     * @return a CompletableFuture that resolves to true if location is verified
     */
    CompletableFuture<Boolean> verifyLocation(String userId, TrustCalculator.Location location);
    
    /**
     * Check if location is trusted.
     * 
     * @param location the location to check
     * @return a CompletableFuture that resolves to true if location is trusted
     */
    CompletableFuture<Boolean> isLocationTrusted(TrustCalculator.Location location);
    
    /**
     * Get location from IP address.
     * 
     * @param ipAddress the IP address
     * @return a CompletableFuture that resolves to location or null if not found
     */
    CompletableFuture<TrustCalculator.Location> getLocationFromIP(String ipAddress);
    
    /**
     * Add trusted location.
     * 
     * @param userId the user identifier
     * @param location the location to add as trusted
     * @return a CompletableFuture that completes when the location is added
     */
    CompletableFuture<Void> addTrustedLocation(String userId, TrustCalculator.Location location);
}