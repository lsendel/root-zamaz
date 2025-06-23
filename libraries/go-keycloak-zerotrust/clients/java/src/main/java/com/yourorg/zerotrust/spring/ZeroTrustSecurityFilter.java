package com.yourorg.zerotrust.spring;

import com.yourorg.zerotrust.KeycloakZeroTrustClient;
import com.yourorg.zerotrust.model.ZeroTrustClaims;
import com.yourorg.zerotrust.exception.AuthenticationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.CompletionException;
import java.util.stream.Collectors;

/**
 * Spring Security filter for Zero Trust authentication.
 * 
 * This filter integrates with Spring Security to provide Zero Trust
 * authentication using Keycloak. It validates JWT tokens and enforces
 * trust levels, device verification, and other Zero Trust policies.
 * 
 * Example configuration:
 * <pre>
 * {@code
 * @Configuration
 * @EnableWebSecurity
 * public class SecurityConfig {
 * 
 *     @Bean
 *     public ZeroTrustSecurityFilter zeroTrustFilter(KeycloakZeroTrustClient client) {
 *         return new ZeroTrustSecurityFilter(client);
 *     }
 * 
 *     @Bean
 *     public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
 *         return http
 *             .addFilterBefore(zeroTrustFilter(client), UsernamePasswordAuthenticationFilter.class)
 *             .authorizeHttpRequests(auth -> auth
 *                 .requestMatchers("/public/**").permitAll()
 *                 .requestMatchers("/admin/**").hasRole("ADMIN")
 *                 .anyRequest().authenticated()
 *             )
 *             .build();
 *     }
 * }
 * }
 * </pre>
 */
public class ZeroTrustSecurityFilter extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(ZeroTrustSecurityFilter.class);
    
    private final KeycloakZeroTrustClient keycloakClient;
    private final List<String> skipPaths;
    
    public ZeroTrustSecurityFilter(KeycloakZeroTrustClient keycloakClient) {
        this.keycloakClient = keycloakClient;
        this.skipPaths = List.of("/health", "/metrics", "/public");
    }
    
    public ZeroTrustSecurityFilter(KeycloakZeroTrustClient keycloakClient, List<String> skipPaths) {
        this.keycloakClient = keycloakClient;
        this.skipPaths = skipPaths;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        String path = request.getRequestURI();
        
        // Skip authentication for configured paths
        if (shouldSkipPath(path)) {
            filterChain.doFilter(request, response);
            return;
        }
        
        try {
            // Extract token from Authorization header
            String token = extractToken(request);
            if (token == null || token.trim().isEmpty()) {
                sendUnauthorizedResponse(response, "Missing or invalid authorization header");
                return;
            }
            
            // Validate token asynchronously
            ZeroTrustClaims claims = keycloakClient.validateToken(token)
                .exceptionally(throwable -> {
                    Throwable cause = throwable instanceof CompletionException ? 
                        throwable.getCause() : throwable;
                    logger.warn("Token validation failed: {}", cause.getMessage());
                    throw new RuntimeException(cause);
                })
                .join(); // Block for synchronous processing in filter
            
            // Create Spring Security authentication
            Authentication authentication = createAuthentication(claims);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            
            // Add claims to request attributes for easy access in controllers
            request.setAttribute("zeroTrustClaims", claims);
            request.setAttribute("trustLevel", claims.getTrustLevel());
            request.setAttribute("deviceVerified", claims.isDeviceVerified());
            
            logger.debug("Authentication successful for user: {} with trust level: {}", 
                claims.getUsername(), claims.getTrustLevel());
            
            filterChain.doFilter(request, response);
            
        } catch (Exception e) {
            logger.warn("Authentication failed: {}", e.getMessage());
            
            if (e.getCause() instanceof AuthenticationException) {
                AuthenticationException authException = (AuthenticationException) e.getCause();
                sendAuthenticationErrorResponse(response, authException);
            } else {
                sendUnauthorizedResponse(response, "Authentication failed");
            }
        }
    }
    
    private boolean shouldSkipPath(String path) {
        return skipPaths.stream().anyMatch(skipPath -> 
            path.equals(skipPath) || path.startsWith(skipPath + "/"));
    }
    
    private String extractToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null) {
            return null;
        }
        
        if (authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        
        return authHeader;
    }
    
    private Authentication createAuthentication(ZeroTrustClaims claims) {
        // Convert roles to Spring Security authorities
        List<SimpleGrantedAuthority> authorities = claims.getRoles().stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
            .collect(Collectors.toList());
        
        // Create custom principal with Zero Trust information
        ZeroTrustPrincipal principal = new ZeroTrustPrincipal(
            claims.getUserId(),
            claims.getUsername(),
            claims.getEmail(),
            claims.getTrustLevel(),
            claims.isDeviceVerified(),
            claims.getRiskScore(),
            claims
        );
        
        return new UsernamePasswordAuthenticationToken(principal, null, authorities);
    }
    
    private void sendUnauthorizedResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        response.getWriter().write(String.format(
            "{\"error\":{\"code\":\"UNAUTHORIZED\",\"message\":\"%s\"}}", message));
    }
    
    private void sendAuthenticationErrorResponse(HttpServletResponse response, 
                                               AuthenticationException authException) throws IOException {
        HttpStatus status = mapErrorCodeToHttpStatus(authException.getErrorCode());
        
        response.setStatus(status.value());
        response.setContentType("application/json");
        response.getWriter().write(String.format(
            "{\"error\":{\"code\":\"%s\",\"message\":\"%s\"}}", 
            authException.getErrorCode(), authException.getMessage()));
    }
    
    private HttpStatus mapErrorCodeToHttpStatus(String errorCode) {
        switch (errorCode) {
            case "INVALID_TOKEN":
            case "EXPIRED_TOKEN":
            case "MISSING_TOKEN":
                return HttpStatus.UNAUTHORIZED;
            case "INSUFFICIENT_TRUST_LEVEL":
            case "DEVICE_NOT_VERIFIED":
            case "INSUFFICIENT_ROLE":
            case "RISK_SCORE_TOO_HIGH":
                return HttpStatus.FORBIDDEN;
            case "CONNECTION_ERROR":
            case "CONFIGURATION_ERROR":
                return HttpStatus.INTERNAL_SERVER_ERROR;
            default:
                return HttpStatus.UNAUTHORIZED;
        }
    }
    
    /**
     * Custom principal that includes Zero Trust information.
     */
    public static class ZeroTrustPrincipal {
        private final String userId;
        private final String username;
        private final String email;
        private final int trustLevel;
        private final boolean deviceVerified;
        private final int riskScore;
        private final ZeroTrustClaims claims;
        
        public ZeroTrustPrincipal(String userId, String username, String email, 
                                 int trustLevel, boolean deviceVerified, int riskScore,
                                 ZeroTrustClaims claims) {
            this.userId = userId;
            this.username = username;
            this.email = email;
            this.trustLevel = trustLevel;
            this.deviceVerified = deviceVerified;
            this.riskScore = riskScore;
            this.claims = claims;
        }
        
        public String getUserId() { return userId; }
        public String getUsername() { return username; }
        public String getEmail() { return email; }
        public int getTrustLevel() { return trustLevel; }
        public boolean isDeviceVerified() { return deviceVerified; }
        public int getRiskScore() { return riskScore; }
        public ZeroTrustClaims getClaims() { return claims; }
        
        @Override
        public String toString() {
            return username;
        }
    }
}