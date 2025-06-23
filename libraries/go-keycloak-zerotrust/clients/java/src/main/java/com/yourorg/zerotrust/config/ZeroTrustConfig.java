package com.yourorg.zerotrust.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import java.time.Duration;
import java.util.Objects;

/**
 * Configuration for the Keycloak Zero Trust client.
 * 
 * Supports configuration via builder pattern, environment variables,
 * or JSON/YAML files.
 * 
 * Example usage:
 * <pre>
 * ZeroTrustConfig config = ZeroTrustConfig.builder()
 *     .baseUrl("https://keycloak.company.com")
 *     .realm("company")
 *     .clientId("api-service")
 *     .clientSecret("secret")
 *     .cache(CacheConfig.builder()
 *         .enabled(true)
 *         .provider("redis")
 *         .redisUrl("redis://localhost:6379")
 *         .build())
 *     .zeroTrust(ZeroTrustSettings.builder()
 *         .deviceAttestation(true)
 *         .riskAssessment(true)
 *         .build())
 *     .build();
 * </pre>
 */
@JsonDeserialize(builder = ZeroTrustConfig.Builder.class)
public class ZeroTrustConfig {
    
    // Core Keycloak settings
    private final String baseUrl;
    private final String realm;
    private final String clientId;
    private final String clientSecret;
    private final String adminUser;
    private final String adminPassword;
    
    // HTTP configuration
    private final Duration timeout;
    private final int retryAttempts;
    
    // Feature configuration
    private final CacheConfig cache;
    private final ZeroTrustSettings zeroTrust;
    private final boolean multiTenant;
    
    private ZeroTrustConfig(Builder builder) {
        this.baseUrl = builder.baseUrl;
        this.realm = builder.realm;
        this.clientId = builder.clientId;
        this.clientSecret = builder.clientSecret;
        this.adminUser = builder.adminUser;
        this.adminPassword = builder.adminPassword;
        this.timeout = builder.timeout;
        this.retryAttempts = builder.retryAttempts;
        this.cache = builder.cache;
        this.zeroTrust = builder.zeroTrust;
        this.multiTenant = builder.multiTenant;
    }
    
    /**
     * Creates a new configuration builder.
     * 
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }
    
    /**
     * Creates configuration from environment variables.
     * 
     * Expected environment variables:
     * - KEYCLOAK_BASE_URL
     * - KEYCLOAK_REALM
     * - KEYCLOAK_CLIENT_ID
     * - KEYCLOAK_CLIENT_SECRET
     * - KEYCLOAK_ADMIN_USER (optional)
     * - KEYCLOAK_ADMIN_PASSWORD (optional)
     * - KEYCLOAK_CACHE_PROVIDER (optional, default: memory)
     * - KEYCLOAK_REDIS_URL (optional)
     * 
     * @return configuration built from environment variables
     */
    public static ZeroTrustConfig fromEnvironment() {
        Builder builder = builder()
            .baseUrl(getEnvOrThrow("KEYCLOAK_BASE_URL"))
            .realm(getEnvOrThrow("KEYCLOAK_REALM"))
            .clientId(getEnvOrThrow("KEYCLOAK_CLIENT_ID"))
            .clientSecret(getEnvOrThrow("KEYCLOAK_CLIENT_SECRET"));
        
        // Optional settings
        String adminUser = System.getenv("KEYCLOAK_ADMIN_USER");
        if (adminUser != null) {
            builder.adminUser(adminUser);
        }
        
        String adminPassword = System.getenv("KEYCLOAK_ADMIN_PASSWORD");
        if (adminPassword != null) {
            builder.adminPassword(adminPassword);
        }
        
        // Cache configuration
        CacheConfig.Builder cacheBuilder = CacheConfig.builder();
        String cacheProvider = System.getenv("KEYCLOAK_CACHE_PROVIDER");
        if (cacheProvider != null) {
            cacheBuilder.provider(cacheProvider);
        }
        
        String redisUrl = System.getenv("KEYCLOAK_REDIS_URL");
        if (redisUrl != null) {
            cacheBuilder.redisUrl(redisUrl);
        }
        
        builder.cache(cacheBuilder.build());
        
        // Zero Trust configuration
        ZeroTrustSettings.Builder ztBuilder = ZeroTrustSettings.builder();
        
        String deviceAttestation = System.getenv("KEYCLOAK_DEVICE_ATTESTATION");
        if ("true".equalsIgnoreCase(deviceAttestation)) {
            ztBuilder.deviceAttestation(true);
        }
        
        String riskAssessment = System.getenv("KEYCLOAK_RISK_ASSESSMENT");
        if ("true".equalsIgnoreCase(riskAssessment)) {
            ztBuilder.riskAssessment(true);
        }
        
        builder.zeroTrust(ztBuilder.build());
        
        return builder.build();
    }
    
    // Getters
    @JsonProperty("base_url")
    public String getBaseUrl() { return baseUrl; }
    
    public String getRealm() { return realm; }
    
    @JsonProperty("client_id")
    public String getClientId() { return clientId; }
    
    @JsonProperty("client_secret")
    public String getClientSecret() { return clientSecret; }
    
    @JsonProperty("admin_user")
    public String getAdminUser() { return adminUser; }
    
    @JsonProperty("admin_password")
    public String getAdminPassword() { return adminPassword; }
    
    public Duration getTimeout() { return timeout; }
    
    @JsonProperty("retry_attempts")
    public int getRetryAttempts() { return retryAttempts; }
    
    public CacheConfig getCache() { return cache; }
    
    @JsonProperty("zero_trust")
    public ZeroTrustSettings getZeroTrust() { return zeroTrust; }
    
    @JsonProperty("multi_tenant")
    public boolean isMultiTenant() { return multiTenant; }
    
    @JsonPOJOBuilder(withPrefix = "")
    public static class Builder {
        private String baseUrl;
        private String realm;
        private String clientId;
        private String clientSecret;
        private String adminUser;
        private String adminPassword;
        private Duration timeout = Duration.ofSeconds(30);
        private int retryAttempts = 3;
        private CacheConfig cache = CacheConfig.defaultConfig();
        private ZeroTrustSettings zeroTrust = ZeroTrustSettings.defaultSettings();
        private boolean multiTenant = false;
        
        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }
        
        public Builder realm(String realm) {
            this.realm = realm;
            return this;
        }
        
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }
        
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }
        
        public Builder adminUser(String adminUser) {
            this.adminUser = adminUser;
            return this;
        }
        
        public Builder adminPassword(String adminPassword) {
            this.adminPassword = adminPassword;
            return this;
        }
        
        public Builder timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }
        
        public Builder retryAttempts(int retryAttempts) {
            this.retryAttempts = retryAttempts;
            return this;
        }
        
        public Builder cache(CacheConfig cache) {
            this.cache = cache;
            return this;
        }
        
        public Builder zeroTrust(ZeroTrustSettings zeroTrust) {
            this.zeroTrust = zeroTrust;
            return this;
        }
        
        public Builder multiTenant(boolean multiTenant) {
            this.multiTenant = multiTenant;
            return this;
        }
        
        public ZeroTrustConfig build() {
            Objects.requireNonNull(baseUrl, "Base URL is required");
            Objects.requireNonNull(realm, "Realm is required");
            Objects.requireNonNull(clientId, "Client ID is required");
            Objects.requireNonNull(clientSecret, "Client secret is required");
            
            return new ZeroTrustConfig(this);
        }
    }
    
    private static String getEnvOrThrow(String key) {
        String value = System.getenv(key);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalStateException("Required environment variable not set: " + key);
        }
        return value;
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        ZeroTrustConfig that = (ZeroTrustConfig) obj;
        return Objects.equals(baseUrl, that.baseUrl) &&
               Objects.equals(realm, that.realm) &&
               Objects.equals(clientId, that.clientId);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(baseUrl, realm, clientId);
    }
    
    @Override
    public String toString() {
        return "ZeroTrustConfig{" +
               "baseUrl='" + baseUrl + '\'' +
               ", realm='" + realm + '\'' +
               ", clientId='" + clientId + '\'' +
               ", multiTenant=" + multiTenant +
               '}';
    }
}