package com.yourorg.zerotrust;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.yourorg.zerotrust.config.ZeroTrustConfig;
import com.yourorg.zerotrust.model.*;
import com.yourorg.zerotrust.exception.AuthenticationException;
import com.yourorg.zerotrust.exception.ConfigurationException;
import com.yourorg.zerotrust.cache.TokenCache;
import com.yourorg.zerotrust.cache.MemoryTokenCache;
import com.yourorg.zerotrust.cache.RedisTokenCache;

import okhttp3.*;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;
import java.util.Map;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

/**
 * Keycloak Zero Trust authentication client for Java applications.
 * 
 * This client provides comprehensive Zero Trust authentication features including:
 * - Token validation with caching
 * - Trust level enforcement
 * - Device attestation
 * - Risk assessment
 * - User management operations
 * 
 * Example usage:
 * <pre>
 * ZeroTrustConfig config = ZeroTrustConfig.builder()
 *     .baseUrl("https://keycloak.company.com")
 *     .realm("company")
 *     .clientId("api-service")
 *     .clientSecret("secret")
 *     .build();
 * 
 * KeycloakZeroTrustClient client = new KeycloakZeroTrustClient(config);
 * 
 * try {
 *     ZeroTrustClaims claims = client.validateToken("Bearer jwt-token").get();
 *     System.out.println("User: " + claims.getUsername() + ", Trust Level: " + claims.getTrustLevel());
 * } catch (AuthenticationException e) {
 *     System.err.println("Authentication failed: " + e.getMessage());
 * }
 * </pre>
 * 
 * @author Zero Trust Team
 * @version 1.0.0
 * @since 1.0.0
 */
public class KeycloakZeroTrustClient implements AutoCloseable {
    
    private static final Logger logger = LoggerFactory.getLogger(KeycloakZeroTrustClient.class);
    
    private final ZeroTrustConfig config;
    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final TokenCache tokenCache;
    private final ClientMetrics metrics;
    
    private static final String TOKEN_INTROSPECT_PATH = "/realms/%s/protocol/openid-connect/token/introspect";
    private static final String USERINFO_PATH = "/realms/%s/protocol/openid-connect/userinfo";
    private static final String ADMIN_USERS_PATH = "/admin/realms/%s/users";
    private static final String ADMIN_TOKEN_PATH = "/realms/master/protocol/openid-connect/token";
    
    /**
     * Creates a new Keycloak Zero Trust client with the specified configuration.
     * 
     * @param config the Zero Trust configuration
     * @throws ConfigurationException if the configuration is invalid
     */
    public KeycloakZeroTrustClient(ZeroTrustConfig config) {
        this.config = validateConfig(config);
        this.objectMapper = createObjectMapper();
        this.httpClient = createHttpClient();
        this.tokenCache = createTokenCache();
        this.metrics = new ClientMetrics();
        
        logger.info("Keycloak Zero Trust client initialized for realm: {}", config.getRealm());
    }
    
    /**
     * Validates a JWT token and returns Zero Trust claims.
     * 
     * @param token the JWT token to validate (with or without "Bearer " prefix)
     * @return CompletableFuture containing the Zero Trust claims
     * @throws AuthenticationException if token validation fails
     */
    public CompletableFuture<ZeroTrustClaims> validateToken(String token) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                metrics.incrementTokenValidations();
                Instant start = Instant.now();
                
                String cleanToken = cleanToken(token);
                if (cleanToken.isEmpty()) {
                    throw new AuthenticationException("MISSING_TOKEN", "Token cannot be empty");
                }
                
                // Check cache first
                String cacheKey = "token:" + cleanToken.hashCode();
                ZeroTrustClaims cachedClaims = tokenCache.get(cacheKey);
                if (cachedClaims != null && !isExpired(cachedClaims)) {
                    metrics.incrementCacheHits();
                    return cachedClaims;
                }
                
                metrics.incrementCacheMisses();
                
                // Introspect token with Keycloak
                TokenIntrospectionResponse introspection = introspectToken(cleanToken);
                if (!introspection.isActive()) {
                    throw new AuthenticationException("INVALID_TOKEN", "Token is not active");
                }
                
                // Get user info for additional claims
                UserInfo userInfo = getUserInfo(cleanToken);
                
                // Parse JWT claims for Zero Trust attributes
                ZeroTrustClaims claims = parseJwtClaims(cleanToken, userInfo);
                
                // Apply Zero Trust policies
                validateZeroTrustPolicies(claims);
                
                // Cache the validated claims
                Duration cacheTtl = config.getCache().getTtl();
                tokenCache.put(cacheKey, claims, cacheTtl);
                
                Duration latency = Duration.between(start, Instant.now());
                metrics.updateAverageLatency(latency);
                
                return claims;
                
            } catch (Exception e) {
                metrics.incrementErrorCount();
                if (e instanceof AuthenticationException) {
                    throw e;
                } else {
                    throw new AuthenticationException("VALIDATION_ERROR", "Token validation failed", e);
                }
            }
        });
    }
    
    /**
     * Refreshes an access token using a refresh token.
     * 
     * @param refreshToken the refresh token
     * @return CompletableFuture containing the new token pair
     */
    public CompletableFuture<TokenPair> refreshToken(String refreshToken) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                RequestBody formBody = new FormBody.Builder()
                    .add("grant_type", "refresh_token")
                    .add("refresh_token", refreshToken)
                    .add("client_id", config.getClientId())
                    .add("client_secret", config.getClientSecret())
                    .build();
                
                String tokenEndpoint = config.getBaseUrl() + 
                    String.format("/realms/%s/protocol/openid-connect/token", config.getRealm());
                
                Request request = new Request.Builder()
                    .url(tokenEndpoint)
                    .post(formBody)
                    .build();
                
                try (Response response = httpClient.newCall(request).execute()) {
                    if (!response.isSuccessful()) {
                        throw new AuthenticationException("REFRESH_FAILED", 
                            "Failed to refresh token: " + response.message());
                    }
                    
                    return objectMapper.readValue(response.body().string(), TokenPair.class);
                }
                
            } catch (Exception e) {
                metrics.incrementErrorCount();
                if (e instanceof AuthenticationException) {
                    throw e;
                } else {
                    throw new AuthenticationException("REFRESH_ERROR", "Token refresh failed", e);
                }
            }
        });
    }
    
    /**
     * Registers a new user in Keycloak with Zero Trust attributes.
     * 
     * @param request the user registration request
     * @return CompletableFuture containing the created user
     */
    public CompletableFuture<User> registerUser(UserRegistrationRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // This would require admin token - implementation depends on admin setup
                throw new UnsupportedOperationException("User registration requires admin implementation");
            } catch (Exception e) {
                metrics.incrementErrorCount();
                throw new AuthenticationException("REGISTRATION_ERROR", "User registration failed", e);
            }
        });
    }
    
    /**
     * Updates a user's trust level.
     * 
     * @param request the trust level update request
     * @return CompletableFuture that completes when the update is done
     */
    public CompletableFuture<Void> updateUserTrustLevel(TrustLevelUpdateRequest request) {
        return CompletableFuture.runAsync(() -> {
            try {
                // This would require admin token - implementation depends on admin setup
                throw new UnsupportedOperationException("Trust level update requires admin implementation");
            } catch (Exception e) {
                metrics.incrementErrorCount();
                throw new AuthenticationException("UPDATE_ERROR", "Trust level update failed", e);
            }
        });
    }
    
    /**
     * Performs a health check against the Keycloak server.
     * 
     * @return CompletableFuture that completes successfully if healthy
     */
    public CompletableFuture<Void> healthCheck() {
        return CompletableFuture.runAsync(() -> {
            try {
                String healthUrl = config.getBaseUrl() + "/realms/" + config.getRealm();
                
                Request request = new Request.Builder()
                    .url(healthUrl)
                    .get()
                    .build();
                
                try (Response response = httpClient.newCall(request).execute()) {
                    if (!response.isSuccessful()) {
                        throw new AuthenticationException("HEALTH_CHECK_FAILED", 
                            "Health check failed: " + response.message());
                    }
                }
                
                metrics.setHealthStatus("healthy");
                metrics.setLastHealthCheck(Instant.now());
                
            } catch (Exception e) {
                metrics.incrementErrorCount();
                metrics.setHealthStatus("unhealthy");
                throw new AuthenticationException("HEALTH_CHECK_ERROR", "Health check error", e);
            }
        });
    }
    
    /**
     * Gets current client metrics.
     * 
     * @return the client metrics
     */
    public ClientMetrics getMetrics() {
        return metrics;
    }
    
    // Private helper methods
    
    private ZeroTrustConfig validateConfig(ZeroTrustConfig config) {
        if (config == null) {
            throw new ConfigurationException("Configuration cannot be null");
        }
        if (config.getBaseUrl() == null || config.getBaseUrl().isEmpty()) {
            throw new ConfigurationException("Base URL is required");
        }
        if (config.getRealm() == null || config.getRealm().isEmpty()) {
            throw new ConfigurationException("Realm is required");
        }
        if (config.getClientId() == null || config.getClientId().isEmpty()) {
            throw new ConfigurationException("Client ID is required");
        }
        if (config.getClientSecret() == null || config.getClientSecret().isEmpty()) {
            throw new ConfigurationException("Client secret is required");
        }
        return config;
    }
    
    private ObjectMapper createObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        return mapper;
    }
    
    private OkHttpClient createHttpClient() {
        return new OkHttpClient.Builder()
            .connectTimeout(config.getTimeout())
            .readTimeout(config.getTimeout())
            .writeTimeout(config.getTimeout())
            .retryOnConnectionFailure(true)
            .build();
    }
    
    private TokenCache createTokenCache() {
        if (config.getCache().isEnabled()) {
            if ("redis".equalsIgnoreCase(config.getCache().getProvider())) {
                return new RedisTokenCache(config.getCache());
            } else {
                return new MemoryTokenCache(config.getCache().getMaxSize());
            }
        } else {
            return new MemoryTokenCache(0); // Disabled cache
        }
    }
    
    private String cleanToken(String token) {
        if (token == null) {
            return "";
        }
        token = token.trim();
        if (token.toLowerCase().startsWith("bearer ")) {
            return token.substring(7);
        }
        return token;
    }
    
    private TokenIntrospectionResponse introspectToken(String token) throws Exception {
        RequestBody formBody = new FormBody.Builder()
            .add("token", token)
            .add("client_id", config.getClientId())
            .add("client_secret", config.getClientSecret())
            .build();
        
        String introspectUrl = config.getBaseUrl() + 
            String.format(TOKEN_INTROSPECT_PATH, config.getRealm());
        
        Request request = new Request.Builder()
            .url(introspectUrl)
            .post(formBody)
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new AuthenticationException("INTROSPECTION_FAILED", 
                    "Token introspection failed: " + response.message());
            }
            
            return objectMapper.readValue(response.body().string(), TokenIntrospectionResponse.class);
        }
    }
    
    private UserInfo getUserInfo(String token) throws Exception {
        String userInfoUrl = config.getBaseUrl() + 
            String.format(USERINFO_PATH, config.getRealm());
        
        Request request = new Request.Builder()
            .url(userInfoUrl)
            .header("Authorization", "Bearer " + token)
            .get()
            .build();
        
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new AuthenticationException("USERINFO_FAILED", 
                    "User info request failed: " + response.message());
            }
            
            return objectMapper.readValue(response.body().string(), UserInfo.class);
        }
    }
    
    private ZeroTrustClaims parseJwtClaims(String token, UserInfo userInfo) {
        try {
            // Simple JWT parsing without signature verification (since we already introspected)
            JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setSkipSignatureVerification()
                .setSkipAllValidators()
                .build();
            
            JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
            
            ZeroTrustClaims.Builder claimsBuilder = ZeroTrustClaims.builder()
                .userId(userInfo.getSub())
                .email(userInfo.getEmail())
                .username(userInfo.getPreferredUsername())
                .firstName(userInfo.getGivenName())
                .lastName(userInfo.getFamilyName())
                .issuer(jwtClaims.getIssuer())
                .audience(jwtClaims.getAudience())
                .expiresAt(Instant.ofEpochSecond(jwtClaims.getExpirationTime().getValue()));
            
            // Extract Zero Trust claims
            if (jwtClaims.hasClaim("trust_level")) {
                claimsBuilder.trustLevel(((Number) jwtClaims.getClaimValue("trust_level")).intValue());
            } else {
                claimsBuilder.trustLevel(config.getZeroTrust().getDefaultTrustLevel());
            }
            
            if (jwtClaims.hasClaim("device_id")) {
                claimsBuilder.deviceId((String) jwtClaims.getClaimValue("device_id"));
            }
            
            if (jwtClaims.hasClaim("device_verified")) {
                claimsBuilder.deviceVerified((Boolean) jwtClaims.getClaimValue("device_verified"));
            }
            
            if (jwtClaims.hasClaim("risk_score")) {
                claimsBuilder.riskScore(((Number) jwtClaims.getClaimValue("risk_score")).intValue());
            }
            
            if (jwtClaims.hasClaim("session_state")) {
                claimsBuilder.sessionState((String) jwtClaims.getClaimValue("session_state"));
            }
            
            // Extract roles
            if (jwtClaims.hasClaim("realm_access")) {
                Map<String, Object> realmAccess = jwtClaims.getClaimValue("realm_access", Map.class);
                if (realmAccess.containsKey("roles")) {
                    @SuppressWarnings("unchecked")
                    List<String> roles = (List<String>) realmAccess.get("roles");
                    claimsBuilder.roles(roles);
                }
            }
            
            return claimsBuilder.build();
            
        } catch (Exception e) {
            throw new AuthenticationException("JWT_PARSING_ERROR", "Failed to parse JWT claims", e);
        }
    }
    
    private void validateZeroTrustPolicies(ZeroTrustClaims claims) {
        if (config.getZeroTrust().isDeviceAttestation() && !claims.isDeviceVerified()) {
            throw new AuthenticationException("DEVICE_NOT_VERIFIED", "Device verification required");
        }
        
        if (config.getZeroTrust().isRiskAssessment()) {
            int criticalThreshold = config.getZeroTrust().getRiskThresholds().getCritical();
            if (claims.getRiskScore() >= criticalThreshold) {
                throw new AuthenticationException("RISK_SCORE_TOO_HIGH", 
                    "Risk score too high for access: " + claims.getRiskScore());
            }
        }
    }
    
    private boolean isExpired(ZeroTrustClaims claims) {
        return claims.getExpiresAt() != null && Instant.now().isAfter(claims.getExpiresAt());
    }
    
    @Override
    public void close() {
        try {
            if (httpClient != null) {
                httpClient.dispatcher().executorService().shutdown();
                httpClient.connectionPool().evictAll();
            }
            if (tokenCache != null) {
                tokenCache.close();
            }
            logger.info("Keycloak Zero Trust client closed");
        } catch (Exception e) {
            logger.warn("Error closing client", e);
        }
    }
}