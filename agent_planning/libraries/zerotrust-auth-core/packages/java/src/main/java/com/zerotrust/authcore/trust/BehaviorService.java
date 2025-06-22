package com.zerotrust.authcore.trust;

import java.time.Instant;
import java.util.concurrent.CompletableFuture;

/**
 * Behavior service interface for behavior analysis.
 */
public interface BehaviorService {
    
    /**
     * Analyze user behavior.
     * 
     * @param userId the user identifier
     * @param action the action being performed
     * @return a CompletableFuture that resolves to behavior analysis results
     */
    CompletableFuture<TrustCalculator.BehaviorAnalysis> analyzeBehavior(String userId, String action);
    
    /**
     * Check if action is suspicious.
     * 
     * @param userId the user identifier
     * @param action the action being performed
     * @return a CompletableFuture that resolves to true if action is suspicious
     */
    CompletableFuture<Boolean> isActionSuspicious(String userId, String action);
    
    /**
     * Update behavior profile.
     * 
     * @param userId the user identifier
     * @param action the action being performed
     * @param timestamp the timestamp of the action
     * @return a CompletableFuture that completes when the profile is updated
     */
    CompletableFuture<Void> updateBehaviorProfile(String userId, String action, Instant timestamp);
    
    /**
     * Get typical behavior patterns.
     * 
     * @param userId the user identifier
     * @return a CompletableFuture that resolves to typical behavior patterns
     */
    CompletableFuture<TrustCalculator.BehaviorAnalysis> getTypicalPatterns(String userId);
}