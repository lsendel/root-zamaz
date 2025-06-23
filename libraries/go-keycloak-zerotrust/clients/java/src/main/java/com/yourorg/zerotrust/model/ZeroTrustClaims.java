package com.yourorg.zerotrust.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Zero Trust claims extracted from a validated JWT token.
 * 
 * Contains both standard OIDC claims and Zero Trust specific attributes
 * such as trust level, device verification status, and risk assessment.
 */
@JsonDeserialize(builder = ZeroTrustClaims.Builder.class)
public class ZeroTrustClaims {
    
    // Standard OIDC claims
    private final String userId;
    private final String email;
    private final String username;
    private final String firstName;
    private final String lastName;
    private final String issuer;
    private final List<String> audience;
    private final Instant expiresAt;
    private final Instant issuedAt;
    
    // Authorization claims
    private final List<String> roles;
    private final List<String> groups;
    
    // Zero Trust claims
    private final int trustLevel;
    private final String deviceId;
    private final boolean deviceVerified;
    private final String lastVerification;
    private final boolean requiresDeviceAuth;
    
    // Session information
    private final String sessionState;
    private final int sessionTimeout;
    
    // Risk assessment
    private final int riskScore;
    private final List<String> riskFactors;
    private final LocationInfo locationInfo;
    
    private ZeroTrustClaims(Builder builder) {
        this.userId = builder.userId;
        this.email = builder.email;
        this.username = builder.username;
        this.firstName = builder.firstName;
        this.lastName = builder.lastName;
        this.issuer = builder.issuer;
        this.audience = builder.audience;
        this.expiresAt = builder.expiresAt;
        this.issuedAt = builder.issuedAt;
        this.roles = builder.roles;
        this.groups = builder.groups;
        this.trustLevel = builder.trustLevel;
        this.deviceId = builder.deviceId;
        this.deviceVerified = builder.deviceVerified;
        this.lastVerification = builder.lastVerification;
        this.requiresDeviceAuth = builder.requiresDeviceAuth;
        this.sessionState = builder.sessionState;
        this.sessionTimeout = builder.sessionTimeout;
        this.riskScore = builder.riskScore;
        this.riskFactors = builder.riskFactors;
        this.locationInfo = builder.locationInfo;
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    // Getters
    @JsonProperty("user_id")
    public String getUserId() { return userId; }
    
    public String getEmail() { return email; }
    
    @JsonProperty("preferred_username")
    public String getUsername() { return username; }
    
    @JsonProperty("given_name")
    public String getFirstName() { return firstName; }
    
    @JsonProperty("family_name")
    public String getLastName() { return lastName; }
    
    public String getIssuer() { return issuer; }
    
    public List<String> getAudience() { return audience; }
    
    @JsonProperty("expires_at")
    public Instant getExpiresAt() { return expiresAt; }
    
    @JsonProperty("issued_at")
    public Instant getIssuedAt() { return issuedAt; }
    
    public List<String> getRoles() { return roles; }
    
    public List<String> getGroups() { return groups; }
    
    @JsonProperty("trust_level")
    public int getTrustLevel() { return trustLevel; }
    
    @JsonProperty("device_id")
    public String getDeviceId() { return deviceId; }
    
    @JsonProperty("device_verified")
    public boolean isDeviceVerified() { return deviceVerified; }
    
    @JsonProperty("last_verification")
    public String getLastVerification() { return lastVerification; }
    
    @JsonProperty("requires_device_auth")
    public boolean isRequiresDeviceAuth() { return requiresDeviceAuth; }
    
    @JsonProperty("session_state")
    public String getSessionState() { return sessionState; }
    
    @JsonProperty("session_timeout")
    public int getSessionTimeout() { return sessionTimeout; }
    
    @JsonProperty("risk_score")
    public int getRiskScore() { return riskScore; }
    
    @JsonProperty("risk_factors")
    public List<String> getRiskFactors() { return riskFactors; }
    
    @JsonProperty("location_info")
    public LocationInfo getLocationInfo() { return locationInfo; }
    
    @JsonPOJOBuilder(withPrefix = "")
    public static class Builder {
        private String userId;
        private String email;
        private String username;
        private String firstName;
        private String lastName;
        private String issuer;
        private List<String> audience;
        private Instant expiresAt;
        private Instant issuedAt;
        private List<String> roles;
        private List<String> groups;
        private int trustLevel = 25; // Default trust level
        private String deviceId;
        private boolean deviceVerified = false;
        private String lastVerification;
        private boolean requiresDeviceAuth = false;
        private String sessionState;
        private int sessionTimeout;
        private int riskScore = 0;
        private List<String> riskFactors;
        private LocationInfo locationInfo;
        
        public Builder userId(String userId) {
            this.userId = userId;
            return this;
        }
        
        public Builder email(String email) {
            this.email = email;
            return this;
        }
        
        public Builder username(String username) {
            this.username = username;
            return this;
        }
        
        public Builder firstName(String firstName) {
            this.firstName = firstName;
            return this;
        }
        
        public Builder lastName(String lastName) {
            this.lastName = lastName;
            return this;
        }
        
        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }
        
        public Builder audience(List<String> audience) {
            this.audience = audience;
            return this;
        }
        
        public Builder expiresAt(Instant expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }
        
        public Builder issuedAt(Instant issuedAt) {
            this.issuedAt = issuedAt;
            return this;
        }
        
        public Builder roles(List<String> roles) {
            this.roles = roles;
            return this;
        }
        
        public Builder groups(List<String> groups) {
            this.groups = groups;
            return this;
        }
        
        public Builder trustLevel(int trustLevel) {
            this.trustLevel = trustLevel;
            return this;
        }
        
        public Builder deviceId(String deviceId) {
            this.deviceId = deviceId;
            return this;
        }
        
        public Builder deviceVerified(boolean deviceVerified) {
            this.deviceVerified = deviceVerified;
            return this;
        }
        
        public Builder lastVerification(String lastVerification) {
            this.lastVerification = lastVerification;
            return this;
        }
        
        public Builder requiresDeviceAuth(boolean requiresDeviceAuth) {
            this.requiresDeviceAuth = requiresDeviceAuth;
            return this;
        }
        
        public Builder sessionState(String sessionState) {
            this.sessionState = sessionState;
            return this;
        }
        
        public Builder sessionTimeout(int sessionTimeout) {
            this.sessionTimeout = sessionTimeout;
            return this;
        }
        
        public Builder riskScore(int riskScore) {
            this.riskScore = riskScore;
            return this;
        }
        
        public Builder riskFactors(List<String> riskFactors) {
            this.riskFactors = riskFactors;
            return this;
        }
        
        public Builder locationInfo(LocationInfo locationInfo) {
            this.locationInfo = locationInfo;
            return this;
        }
        
        public ZeroTrustClaims build() {
            return new ZeroTrustClaims(this);
        }
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        ZeroTrustClaims that = (ZeroTrustClaims) obj;
        return Objects.equals(userId, that.userId) &&
               Objects.equals(email, that.email) &&
               Objects.equals(username, that.username);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(userId, email, username);
    }
    
    @Override
    public String toString() {
        return "ZeroTrustClaims{" +
               "userId='" + userId + '\'' +
               ", username='" + username + '\'' +
               ", trustLevel=" + trustLevel +
               ", deviceVerified=" + deviceVerified +
               ", riskScore=" + riskScore +
               '}';
    }
}