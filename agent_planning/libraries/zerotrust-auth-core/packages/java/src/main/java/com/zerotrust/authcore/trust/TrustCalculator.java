package com.zerotrust.authcore.trust;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Trust level calculator for Zero Trust authentication.
 */
public class TrustCalculator {
    
    private final DeviceService deviceService;
    private final BehaviorService behaviorService;
    private final LocationService locationService;
    private final CalculatorConfig config;

    /**
     * Factors used in trust calculation.
     */
    public static class TrustFactors {
        @JsonProperty("device_verified")
        private boolean deviceVerified = false;
        
        @JsonProperty("location_verified")
        private boolean locationVerified = false;
        
        @JsonProperty("behavior_normal")
        private boolean behaviorNormal = true;
        
        @JsonProperty("recent_activity")
        private boolean recentActivity = false;
        
        @JsonProperty("hardware_attestation")
        private boolean hardwareAttestation = false;
        
        @JsonProperty("biometric_verified")
        private boolean biometricVerified = false;
        
        @JsonProperty("network_trusted")
        private boolean networkTrusted = false;
        
        @JsonProperty("session_age")
        private Instant sessionAge;
        
        @JsonProperty("previous_trust_level")
        private TrustLevel previousTrustLevel = TrustLevel.NONE;

        // Constructors
        public TrustFactors() {}

        // Getters and setters
        public boolean isDeviceVerified() { return deviceVerified; }
        public void setDeviceVerified(boolean deviceVerified) { this.deviceVerified = deviceVerified; }

        public boolean isLocationVerified() { return locationVerified; }
        public void setLocationVerified(boolean locationVerified) { this.locationVerified = locationVerified; }

        public boolean isBehaviorNormal() { return behaviorNormal; }
        public void setBehaviorNormal(boolean behaviorNormal) { this.behaviorNormal = behaviorNormal; }

        public boolean isRecentActivity() { return recentActivity; }
        public void setRecentActivity(boolean recentActivity) { this.recentActivity = recentActivity; }

        public boolean isHardwareAttestation() { return hardwareAttestation; }
        public void setHardwareAttestation(boolean hardwareAttestation) { this.hardwareAttestation = hardwareAttestation; }

        public boolean isBiometricVerified() { return biometricVerified; }
        public void setBiometricVerified(boolean biometricVerified) { this.biometricVerified = biometricVerified; }

        public boolean isNetworkTrusted() { return networkTrusted; }
        public void setNetworkTrusted(boolean networkTrusted) { this.networkTrusted = networkTrusted; }

        public Instant getSessionAge() { return sessionAge; }
        public void setSessionAge(Instant sessionAge) { this.sessionAge = sessionAge; }

        public TrustLevel getPreviousTrustLevel() { return previousTrustLevel; }
        public void setPreviousTrustLevel(TrustLevel previousTrustLevel) { this.previousTrustLevel = previousTrustLevel; }
    }

    /**
     * Geographic location for trust calculation.
     */
    public static class Location {
        @NotNull
        private String country;
        
        @NotNull
        private String region;
        
        @NotNull
        private String city;
        
        private double latitude;
        private double longitude;
        
        @JsonProperty("ip_address")
        private String ipAddress;

        // Constructors
        public Location() {}

        public Location(String country, String region, String city, double latitude, double longitude, String ipAddress) {
            this.country = country;
            this.region = region;
            this.city = city;
            this.latitude = latitude;
            this.longitude = longitude;
            this.ipAddress = ipAddress;
        }

        // Getters and setters
        public String getCountry() { return country; }
        public void setCountry(String country) { this.country = country; }

        public String getRegion() { return region; }
        public void setRegion(String region) { this.region = region; }

        public String getCity() { return city; }
        public void setCity(String city) { this.city = city; }

        public double getLatitude() { return latitude; }
        public void setLatitude(double latitude) { this.latitude = latitude; }

        public double getLongitude() { return longitude; }
        public void setLongitude(double longitude) { this.longitude = longitude; }

        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
    }

    /**
     * Trust calculation request.
     */
    public static class CalculationRequest {
        @NotNull
        @JsonProperty("user_id")
        private String userId;
        
        @JsonProperty("device_id")
        private String deviceId;
        
        private Location location;
        
        private String action;
        
        @NotNull
        @JsonProperty("last_activity")
        private Instant lastActivity;
        
        @NotNull
        @JsonProperty("session_start")
        private Instant sessionStart;
        
        @JsonProperty("ip_address")
        private String ipAddress;
        
        @JsonProperty("user_agent")
        private String userAgent;
        
        private TrustFactors factors;

        // Constructors
        public CalculationRequest() {}

        // Getters and setters
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }

        public String getDeviceId() { return deviceId; }
        public void setDeviceId(String deviceId) { this.deviceId = deviceId; }

        public Location getLocation() { return location; }
        public void setLocation(Location location) { this.location = location; }

        public String getAction() { return action; }
        public void setAction(String action) { this.action = action; }

        public Instant getLastActivity() { return lastActivity; }
        public void setLastActivity(Instant lastActivity) { this.lastActivity = lastActivity; }

        public Instant getSessionStart() { return sessionStart; }
        public void setSessionStart(Instant sessionStart) { this.sessionStart = sessionStart; }

        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

        public String getUserAgent() { return userAgent; }
        public void setUserAgent(String userAgent) { this.userAgent = userAgent; }

        public TrustFactors getFactors() { return factors; }
        public void setFactors(TrustFactors factors) { this.factors = factors; }
    }

    /**
     * Configuration for trust calculation.
     */
    public static class CalculatorConfig {
        @JsonProperty("base_score")
        private int baseScore = 10;
        
        @JsonProperty("device_weight")
        private int deviceWeight = 25;
        
        @JsonProperty("location_weight")
        private int locationWeight = 20;
        
        @JsonProperty("behavior_weight")
        private int behaviorWeight = 15;
        
        @JsonProperty("activity_weight")
        private int activityWeight = 10;
        
        @JsonProperty("hardware_weight")
        private int hardwareWeight = 15;
        
        @JsonProperty("biometric_weight")
        private int biometricWeight = 10;
        
        @JsonProperty("network_weight")
        private int networkWeight = 5;
        
        @JsonProperty("max_inactivity_duration")
        private Duration maxInactivityDuration = Duration.ofMinutes(30);
        
        @JsonProperty("suspicious_activity_penalty")
        private int suspiciousActivityPenalty = 50;
        
        @JsonProperty("new_device_penalty")
        private int newDevicePenalty = 15;

        // Getters and setters
        public int getBaseScore() { return baseScore; }
        public void setBaseScore(int baseScore) { this.baseScore = baseScore; }

        public int getDeviceWeight() { return deviceWeight; }
        public void setDeviceWeight(int deviceWeight) { this.deviceWeight = deviceWeight; }

        public int getLocationWeight() { return locationWeight; }
        public void setLocationWeight(int locationWeight) { this.locationWeight = locationWeight; }

        public int getBehaviorWeight() { return behaviorWeight; }
        public void setBehaviorWeight(int behaviorWeight) { this.behaviorWeight = behaviorWeight; }

        public int getActivityWeight() { return activityWeight; }
        public void setActivityWeight(int activityWeight) { this.activityWeight = activityWeight; }

        public int getHardwareWeight() { return hardwareWeight; }
        public void setHardwareWeight(int hardwareWeight) { this.hardwareWeight = hardwareWeight; }

        public int getBiometricWeight() { return biometricWeight; }
        public void setBiometricWeight(int biometricWeight) { this.biometricWeight = biometricWeight; }

        public int getNetworkWeight() { return networkWeight; }
        public void setNetworkWeight(int networkWeight) { this.networkWeight = networkWeight; }

        public Duration getMaxInactivityDuration() { return maxInactivityDuration; }
        public void setMaxInactivityDuration(Duration maxInactivityDuration) { this.maxInactivityDuration = maxInactivityDuration; }

        public int getSuspiciousActivityPenalty() { return suspiciousActivityPenalty; }
        public void setSuspiciousActivityPenalty(int suspiciousActivityPenalty) { this.suspiciousActivityPenalty = suspiciousActivityPenalty; }

        public int getNewDevicePenalty() { return newDevicePenalty; }
        public void setNewDevicePenalty(int newDevicePenalty) { this.newDevicePenalty = newDevicePenalty; }
    }

    /**
     * Device history information.
     */
    public static class DeviceHistory {
        @JsonProperty("first_seen")
        private Instant firstSeen;
        
        @JsonProperty("last_seen")
        private Instant lastSeen;
        
        @JsonProperty("login_count")
        private int loginCount;
        
        @JsonProperty("failure_count")
        private int failureCount;
        
        @JsonProperty("is_trusted")
        private boolean isTrusted;
        
        @JsonProperty("risk_score")
        @Min(0) @Max(100)
        private int riskScore;
        
        private String platform;
        
        @JsonProperty("user_agent")
        private String userAgent;
        
        @JsonProperty("last_trust_level")
        private TrustLevel lastTrustLevel;

        // Constructors
        public DeviceHistory() {}

        // Getters and setters
        public Instant getFirstSeen() { return firstSeen; }
        public void setFirstSeen(Instant firstSeen) { this.firstSeen = firstSeen; }

        public Instant getLastSeen() { return lastSeen; }
        public void setLastSeen(Instant lastSeen) { this.lastSeen = lastSeen; }

        public int getLoginCount() { return loginCount; }
        public void setLoginCount(int loginCount) { this.loginCount = loginCount; }

        public int getFailureCount() { return failureCount; }
        public void setFailureCount(int failureCount) { this.failureCount = failureCount; }

        public boolean isTrusted() { return isTrusted; }
        public void setTrusted(boolean trusted) { isTrusted = trusted; }

        public int getRiskScore() { return riskScore; }
        public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

        public String getPlatform() { return platform; }
        public void setPlatform(String platform) { this.platform = platform; }

        public String getUserAgent() { return userAgent; }
        public void setUserAgent(String userAgent) { this.userAgent = userAgent; }

        public TrustLevel getLastTrustLevel() { return lastTrustLevel; }
        public void setLastTrustLevel(TrustLevel lastTrustLevel) { this.lastTrustLevel = lastTrustLevel; }
    }

    /**
     * Behavior analysis results.
     */
    public static class BehaviorAnalysis {
        @JsonProperty("is_suspicious")
        private boolean isSuspicious;
        
        @JsonProperty("anomaly_score")
        @Min(0) @Max(1)
        private double anomalyScore;
        
        @JsonProperty("typical_login_times")
        private List<Integer> typicalLoginTimes; // Hours of day
        
        @JsonProperty("typical_locations")
        private List<String> typicalLocations;
        
        @JsonProperty("unusual_activity")
        private List<String> unusualActivity;
        
        @JsonProperty("last_analyzed")
        private Instant lastAnalyzed;
        
        @JsonProperty("confidence_score")
        @Min(0) @Max(1)
        private double confidenceScore;

        // Constructors
        public BehaviorAnalysis() {}

        // Getters and setters
        public boolean isSuspicious() { return isSuspicious; }
        public void setSuspicious(boolean suspicious) { isSuspicious = suspicious; }

        public double getAnomalyScore() { return anomalyScore; }
        public void setAnomalyScore(double anomalyScore) { this.anomalyScore = anomalyScore; }

        public List<Integer> getTypicalLoginTimes() { return typicalLoginTimes; }
        public void setTypicalLoginTimes(List<Integer> typicalLoginTimes) { this.typicalLoginTimes = typicalLoginTimes; }

        public List<String> getTypicalLocations() { return typicalLocations; }
        public void setTypicalLocations(List<String> typicalLocations) { this.typicalLocations = typicalLocations; }

        public List<String> getUnusualActivity() { return unusualActivity; }
        public void setUnusualActivity(List<String> unusualActivity) { this.unusualActivity = unusualActivity; }

        public Instant getLastAnalyzed() { return lastAnalyzed; }
        public void setLastAnalyzed(Instant lastAnalyzed) { this.lastAnalyzed = lastAnalyzed; }

        public double getConfidenceScore() { return confidenceScore; }
        public void setConfidenceScore(double confidenceScore) { this.confidenceScore = confidenceScore; }
    }

    /**
     * Constructor with all services and custom configuration.
     */
    public TrustCalculator(DeviceService deviceService, BehaviorService behaviorService, 
                          LocationService locationService, CalculatorConfig config) {
        this.deviceService = deviceService;
        this.behaviorService = behaviorService;
        this.locationService = locationService;
        this.config = config != null ? config : new CalculatorConfig();
    }

    /**
     * Constructor with default configuration.
     */
    public TrustCalculator(DeviceService deviceService, BehaviorService behaviorService, 
                          LocationService locationService) {
        this(deviceService, behaviorService, locationService, new CalculatorConfig());
    }

    /**
     * Calculate trust level based on provided factors.
     * 
     * @param factors the trust factors to evaluate
     * @return the calculated trust level
     */
    public TrustLevel calculate(TrustFactors factors) {
        if (factors == null) {
            return TrustLevel.NONE;
        }

        int score = config.getBaseScore();

        // Device verification
        if (factors.isDeviceVerified()) {
            score += config.getDeviceWeight();
        } else {
            score -= config.getNewDevicePenalty();
        }

        // Location verification
        if (factors.isLocationVerified()) {
            score += config.getLocationWeight();
        }

        // Behavior analysis
        if (factors.isBehaviorNormal()) {
            score += config.getBehaviorWeight();
        } else {
            score -= config.getSuspiciousActivityPenalty();
        }

        // Recent activity
        if (factors.isRecentActivity()) {
            score += config.getActivityWeight();
        }

        // Hardware attestation (high security feature)
        if (factors.isHardwareAttestation()) {
            score += config.getHardwareWeight();
        }

        // Biometric verification
        if (factors.isBiometricVerified()) {
            score += config.getBiometricWeight();
        }

        // Trusted network
        if (factors.isNetworkTrusted()) {
            score += config.getNetworkWeight();
        }

        // Session age consideration
        if (factors.getSessionAge() != null) {
            Duration sessionDuration = Duration.between(factors.getSessionAge(), Instant.now());
            if (sessionDuration.toHours() > 4) {
                score -= 10; // Reduce trust for very old sessions
            } else if (sessionDuration.toHours() > 8) {
                score -= 20; // Significant reduction for very stale sessions
            }
        }

        // Consider previous trust level for gradual changes
        if (factors.getPreviousTrustLevel() != TrustLevel.NONE) {
            int previousScore = factors.getPreviousTrustLevel().getValue();
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

        return TrustLevel.fromValue(score);
    }

    /**
     * Perform comprehensive trust calculation for a user.
     * 
     * @param request the calculation request
     * @return a CompletableFuture that resolves to the calculated trust level
     */
    public CompletableFuture<TrustLevel> calculateForUser(CalculationRequest request) {
        if (request == null) {
            return CompletableFuture.completedFuture(TrustLevel.NONE);
        }

        TrustFactors factors = request.getFactors() != null ? 
            request.getFactors() : new TrustFactors();

        CompletableFuture<Void> deviceFuture = CompletableFuture.completedFuture(null);
        CompletableFuture<Void> locationFuture = CompletableFuture.completedFuture(null);
        CompletableFuture<Void> behaviorFuture = CompletableFuture.completedFuture(null);

        // Device verification
        if (request.getDeviceId() != null && deviceService != null) {
            deviceFuture = deviceService.verifyDevice(request.getDeviceId())
                .thenCompose(verified -> {
                    factors.setDeviceVerified(verified);
                    
                    if (verified) {
                        return deviceService.checkHardwareAttestation(request.getDeviceId())
                            .thenAccept(factors::setHardwareAttestation)
                            .exceptionally(ex -> null); // Non-critical
                    }
                    return CompletableFuture.completedFuture(null);
                })
                .thenCompose(v -> {
                    if (deviceService != null) {
                        return deviceService.getDeviceHistory(request.getDeviceId())
                            .thenAccept(history -> {
                                if (history != null) {
                                    if (history.isTrusted() && history.getFailureCount() < 3) {
                                        factors.setDeviceVerified(true);
                                    }
                                    factors.setPreviousTrustLevel(history.getLastTrustLevel());
                                }
                            })
                            .exceptionally(ex -> null); // Non-critical
                    }
                    return CompletableFuture.completedFuture(null);
                })
                .exceptionally(ex -> {
                    throw new RuntimeException("Device verification failed: " + ex.getMessage(), ex);
                });
        }

        // Location verification
        if (request.getLocation() != null && locationService != null) {
            locationFuture = locationService.verifyLocation(request.getUserId(), request.getLocation())
                .thenAccept(factors::setLocationVerified)
                .thenCompose(v -> locationService.isLocationTrusted(request.getLocation())
                    .thenAccept(factors::setNetworkTrusted)
                    .exceptionally(ex -> null)) // Non-critical
                .exceptionally(ex -> {
                    throw new RuntimeException("Location verification failed: " + ex.getMessage(), ex);
                });
        } else if (request.getIpAddress() != null && locationService != null) {
            locationFuture = locationService.getLocationFromIP(request.getIpAddress())
                .thenCompose(location -> {
                    if (location != null) {
                        return locationService.verifyLocation(request.getUserId(), location)
                            .thenAccept(factors::setLocationVerified)
                            .thenCompose(v -> locationService.isLocationTrusted(location)
                                .thenAccept(factors::setNetworkTrusted)
                                .exceptionally(ex -> null)); // Non-critical
                    }
                    return CompletableFuture.completedFuture(null);
                })
                .exceptionally(ex -> null); // Non-critical
        }

        // Behavior analysis
        if (request.getAction() != null && behaviorService != null) {
            behaviorFuture = behaviorService.isActionSuspicious(request.getUserId(), request.getAction())
                .thenAccept(suspicious -> factors.setBehaviorNormal(!suspicious))
                .thenCompose(v -> behaviorService.updateBehaviorProfile(
                    request.getUserId(), request.getAction(), request.getLastActivity()))
                .exceptionally(ex -> {
                    throw new RuntimeException("Behavior analysis failed: " + ex.getMessage(), ex);
                });
        }

        // Recent activity check
        Duration timeSinceActivity = Duration.between(request.getLastActivity(), Instant.now());
        factors.setRecentActivity(timeSinceActivity.compareTo(config.getMaxInactivityDuration()) < 0);

        // Session age
        factors.setSessionAge(request.getSessionStart());

        return CompletableFuture.allOf(deviceFuture, locationFuture, behaviorFuture)
            .thenApply(v -> calculate(factors));
    }

    /**
     * Calculate trust level during authentication.
     * 
     * @param userId the user ID
     * @param deviceId the device ID (optional)
     * @param ipAddress the IP address (optional)
     * @return a CompletableFuture that resolves to the calculated trust level
     */
    public CompletableFuture<TrustLevel> calculateForAuthentication(String userId, String deviceId, String ipAddress) {
        Instant now = Instant.now();
        CalculationRequest request = new CalculationRequest();
        request.setUserId(userId);
        request.setDeviceId(deviceId);
        request.setIpAddress(ipAddress);
        request.setLastActivity(now);
        request.setSessionStart(now);
        request.setAction("login");

        return calculateForUser(request);
    }

    /**
     * Get required trust level for different operations.
     * 
     * @param operation the operation name
     * @return the required trust level
     */
    public static TrustLevel getTrustLevelForOperation(String operation) {
        switch (operation.toLowerCase()) {
            case "login":
            case "read_profile":
            case "view_dashboard":
                return TrustLevel.LOW;

            case "update_profile":
            case "create_resource":
            case "view_reports":
                return TrustLevel.MEDIUM;

            case "delete_resource":
            case "admin_action":
            case "financial_transaction":
                return TrustLevel.HIGH;

            case "system_admin":
            case "security_settings":
            case "user_management":
                return TrustLevel.FULL;

            default:
                return TrustLevel.MEDIUM; // Default to medium for unknown operations
        }
    }

    /**
     * Validate trust calculation factors.
     * 
     * @param factors the factors to validate
     * @throws IllegalArgumentException if factors are invalid
     */
    public static void validateFactors(TrustFactors factors) {
        if (factors == null) {
            throw new IllegalArgumentException("Factors cannot be null");
        }

        // Check for logical inconsistencies
        if (factors.isHardwareAttestation() && !factors.isDeviceVerified()) {
            throw new IllegalArgumentException("Hardware attestation requires device verification");
        }

        if (factors.isBiometricVerified() && !factors.isDeviceVerified()) {
            throw new IllegalArgumentException("Biometric verification requires device verification");
        }
    }

    /**
     * Create a requirement checker for a minimum trust level.
     * 
     * @param required the required trust level
     * @return a function that checks if a trust level meets the requirement
     */
    public static java.util.function.Predicate<TrustLevel> requireTrustLevel(TrustLevel required) {
        return actual -> actual.meetsRequirement(required);
    }
}