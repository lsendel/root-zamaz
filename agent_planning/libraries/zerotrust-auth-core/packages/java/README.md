# Zero Trust Authentication Core - Java

> **Java implementation of the Zero Trust Authentication Core library**  
> **Version**: 1.0.0  
> **License**: MIT

## 🚀 **Quick Start**

### **Installation**

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>com.zerotrust</groupId>
    <artifactId>auth-core</artifactId>
    <version>1.0.0</version>
</dependency>
```

Or for Gradle (`build.gradle`):

```gradle
implementation 'com.zerotrust:auth-core:1.0.0'
```

### **Basic Usage**

```java
import com.zerotrust.authcore.jwt.JWTManager;
import com.zerotrust.authcore.jwt.JWTConfig;
import com.zerotrust.authcore.jwt.TokenRequest;
import com.zerotrust.authcore.jwt.Token;
import com.zerotrust.authcore.trust.TrustLevel;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;

public class Example {
    public static void main(String[] args) {
        // Configure JWT manager
        JWTConfig config = JWTConfig.builder()
            .secret("your-secret-key-32-characters-long")
            .expiryDuration(Duration.ofMinutes(30))
            .refreshDuration(Duration.ofDays(7))
            .issuer("my-service")
            .rotationDuration(Duration.ofDays(1))
            .build();
        
        JWTManager jwtManager = new JWTManager(config);
        
        // Generate token with trust level
        TokenRequest tokenRequest = TokenRequest.builder()
            .userId("user123")
            .email("user@example.com")
            .roles(List.of("user"))
            .permissions(List.of("read", "write"))
            .trustLevel(TrustLevel.MEDIUM.getValue())
            .deviceId("device-fingerprint-123")
            .build();
        
        CompletableFuture<Token> tokenFuture = jwtManager.generateToken(tokenRequest);
        
        tokenFuture.thenAccept(token -> {
            System.out.println("Access Token: " + token.getAccessToken());
            System.out.println("Trust Level: " + token.getTrustLevel());
            
            // Validate token
            jwtManager.validateToken(token.getAccessToken())
                .thenAccept(claims -> {
                    System.out.println("User ID: " + claims.getUserId());
                    System.out.println("Trust Level: " + claims.getTrustLevel());
                });
        });
    }
}
```

## 🔐 **Trust Level System**

```java
import com.zerotrust.authcore.trust.TrustCalculator;
import com.zerotrust.authcore.trust.TrustLevel;

public class TrustExample {
    public static void main(String[] args) {
        // Create trust calculator
        TrustCalculator calculator = new TrustCalculator(null, null, null);
        
        // Calculate trust based on factors
        TrustCalculator.TrustFactors factors = new TrustCalculator.TrustFactors();
        factors.setDeviceVerified(true);
        factors.setLocationVerified(true);
        factors.setBehaviorNormal(true);
        factors.setRecentActivity(true);
        factors.setHardwareAttestation(false);
        factors.setBiometricVerified(false);
        factors.setNetworkTrusted(true);
        factors.setPreviousTrustLevel(TrustLevel.MEDIUM);
        
        TrustLevel trustLevel = calculator.calculate(factors);
        System.out.println("Trust Level: " + trustLevel + " (" + trustLevel.getValue() + ")");
        
        // Check if trust level meets requirement
        TrustLevel required = TrustLevel.MEDIUM;
        boolean meetsRequirement = trustLevel.meetsRequirement(required);
        System.out.println("Meets requirement: " + meetsRequirement);
    }
}
```

## 🛡️ **Token Blacklisting**

```java
import com.zerotrust.authcore.blacklist.MemoryBlacklist;
import com.zerotrust.authcore.blacklist.RedisBlacklist;

import java.time.Instant;
import java.time.Duration;

public class BlacklistExample {
    public static void main(String[] args) {
        // Memory-based blacklist (for single-instance applications)
        MemoryBlacklist memoryBlacklist = new MemoryBlacklist();
        
        // Add token to blacklist
        Instant expiresAt = Instant.now().plus(Duration.ofHours(1));
        memoryBlacklist.add("token-jti", "User logout", expiresAt)
            .thenRun(() -> System.out.println("Token blacklisted"));
        
        // Check if token is blacklisted
        String tokenString = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...";
        memoryBlacklist.isBlacklisted(tokenString)
            .thenAccept(isBlacklisted -> 
                System.out.println("Token blacklisted: " + isBlacklisted));
        
        // Set custom blacklist on JWT manager
        jwtManager.setBlacklist(memoryBlacklist);
    }
}
```

## 🔄 **Advanced Configuration**

### **Custom Trust Calculator with Services**

```java
import com.zerotrust.authcore.trust.*;
import java.util.concurrent.CompletableFuture;
import java.time.Instant;
import java.util.List;

// Implement service interfaces
public class MyDeviceService implements DeviceService {
    @Override
    public CompletableFuture<Boolean> verifyDevice(String deviceId) {
        // Your device verification logic
        return CompletableFuture.completedFuture(true);
    }
    
    @Override
    public CompletableFuture<TrustCalculator.DeviceHistory> getDeviceHistory(String deviceId) {
        // Your device history logic
        return CompletableFuture.completedFuture(null);
    }
    
    @Override
    public CompletableFuture<Boolean> checkHardwareAttestation(String deviceId) {
        // Your hardware attestation logic
        return CompletableFuture.completedFuture(false);
    }
    
    @Override
    public CompletableFuture<Boolean> isDeviceTrusted(String deviceId) {
        // Your device trust logic
        return CompletableFuture.completedFuture(true);
    }
    
    @Override
    public CompletableFuture<Void> markDeviceAsTrusted(String deviceId) {
        // Your device trust marking logic
        return CompletableFuture.completedFuture(null);
    }
}

public class MyBehaviorService implements BehaviorService {
    @Override
    public CompletableFuture<TrustCalculator.BehaviorAnalysis> analyzeBehavior(String userId, String action) {
        // Your behavior analysis logic
        TrustCalculator.BehaviorAnalysis analysis = new TrustCalculator.BehaviorAnalysis();
        analysis.setSuspicious(false);
        analysis.setAnomalyScore(0.1);
        analysis.setTypicalLoginTimes(List.of(9, 10, 11, 14, 15, 16));
        analysis.setTypicalLocations(List.of("office", "home"));
        analysis.setUnusualActivity(List.of());
        analysis.setLastAnalyzed(Instant.now());
        analysis.setConfidenceScore(0.95);
        return CompletableFuture.completedFuture(analysis);
    }
    
    @Override
    public CompletableFuture<Boolean> isActionSuspicious(String userId, String action) {
        // Your suspicion detection logic
        return CompletableFuture.completedFuture(false);
    }
    
    // ... implement other methods
}

public class AdvancedTrustExample {
    public static void main(String[] args) {
        // Create calculator with custom services
        DeviceService deviceService = new MyDeviceService();
        BehaviorService behaviorService = new MyBehaviorService();
        
        TrustCalculator.CalculatorConfig config = new TrustCalculator.CalculatorConfig();
        config.setBaseScore(15);
        config.setDeviceWeight(30);
        config.setBehaviorWeight(20);
        
        TrustCalculator calculator = new TrustCalculator(
            deviceService, behaviorService, null, config);
        
        // Calculate trust for user with comprehensive analysis
        TrustCalculator.CalculationRequest request = new TrustCalculator.CalculationRequest();
        request.setUserId("user123");
        request.setDeviceId("device456");
        request.setAction("login");
        request.setLastActivity(Instant.now());
        request.setSessionStart(Instant.now());
        request.setIpAddress("192.168.1.100");
        
        calculator.calculateForUser(request)
            .thenAccept(trustLevel -> 
                System.out.println("Calculated trust level: " + trustLevel));
    }
}
```

### **Redis-based Blacklist**

```java
import com.zerotrust.authcore.blacklist.RedisBlacklist;
import com.zerotrust.authcore.blacklist.HybridBlacklist;
import com.zerotrust.authcore.blacklist.RedisClient;

import java.util.concurrent.CompletableFuture;
import java.time.Duration;

// Implement Redis client interface
public class MyRedisClient implements RedisClient {
    private final YourRedisConnection connection; // Your Redis implementation
    
    @Override
    public CompletableFuture<Void> set(String key, String value, Duration expiration) {
        // Your Redis set implementation
        return connection.setAsync(key, value, expiration);
    }
    
    @Override
    public CompletableFuture<String> get(String key) {
        // Your Redis get implementation
        return connection.getAsync(key);
    }
    
    // ... implement other methods
}

public class RedisBlacklistExample {
    public static void main(String[] args) {
        // Create Redis client
        MyRedisClient redisClient = new MyRedisClient();
        
        // Redis-based blacklist (for distributed applications)
        RedisBlacklist redisBlacklist = new RedisBlacklist(redisClient, "jwt:blacklist");
        jwtManager.setBlacklist(redisBlacklist);
        
        // Hybrid blacklist (memory + Redis for performance and persistence)
        HybridBlacklist hybridBlacklist = new HybridBlacklist(redisClient, "jwt:blacklist");
        jwtManager.setBlacklist(hybridBlacklist);
    }
}
```

## 🧪 **Testing**

```bash
# Run tests
mvn test

# Run tests with coverage
mvn test jacoco:report

# Run integration tests
mvn failsafe:integration-test

# Run all quality checks
mvn verify

# Build project
mvn clean package
```

### **Example Test**

```java
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

import com.zerotrust.authcore.jwt.JWTManager;
import com.zerotrust.authcore.jwt.JWTConfig;
import com.zerotrust.authcore.jwt.TokenRequest;
import com.zerotrust.authcore.trust.TrustLevel;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;

public class JWTManagerTest {
    
    private JWTManager jwtManager;
    
    @BeforeEach
    void setUp() {
        JWTConfig config = JWTConfig.builder()
            .secret("test-secret-key-32-characters-long")
            .expiryDuration(Duration.ofMinutes(30))
            .refreshDuration(Duration.ofDays(7))
            .issuer("test-service")
            .build();
        
        jwtManager = new JWTManager(config);
    }
    
    @Test
    void shouldGenerateValidJWTToken() {
        TokenRequest request = TokenRequest.builder()
            .userId("test-user")
            .email("test@example.com")
            .roles(List.of("user"))
            .permissions(List.of("read"))
            .trustLevel(TrustLevel.MEDIUM.getValue())
            .build();
        
        CompletableFuture<Token> tokenFuture = jwtManager.generateToken(request);
        
        Token token = tokenFuture.join();
        assertNotNull(token.getAccessToken());
        assertEquals(TrustLevel.MEDIUM.getValue(), token.getTrustLevel());
        assertEquals("Bearer", token.getTokenType());
        
        // Validate JWT format (3 parts separated by dots)
        String[] parts = token.getAccessToken().split("\\.");
        assertEquals(3, parts.length);
    }
    
    @Test
    void shouldValidateTokenAndReturnClaims() {
        TokenRequest request = TokenRequest.builder()
            .userId("test-user")
            .email("test@example.com")
            .roles(List.of("user"))
            .permissions(List.of("read"))
            .trustLevel(TrustLevel.HIGH.getValue())
            .build();
        
        Token token = jwtManager.generateToken(request).join();
        JWTClaims claims = jwtManager.validateToken(token.getAccessToken()).join();
        
        assertEquals("test-user", claims.getUserId());
        assertEquals(TrustLevel.HIGH.getValue(), claims.getTrustLevel());
        assertTrue(claims.getRoles().contains("user"));
    }
}
```

## 📚 **API Reference**

### **JWTManager**

```java
public class JWTManager {
    public JWTManager(JWTConfig config);
    
    public CompletableFuture<Token> generateToken(TokenRequest request);
    public CompletableFuture<JWTClaims> validateToken(String tokenString);
    public CompletableFuture<Void> blacklistToken(String tokenString, String reason);
    public CompletableFuture<Token> refreshToken(String refreshToken, TokenRequest request);
    
    public void setBlacklist(Blacklist blacklist);
    public JWTConfig getConfig();
}
```

### **TrustCalculator**

```java
public class TrustCalculator {
    public TrustCalculator(DeviceService deviceService, BehaviorService behaviorService, 
                          LocationService locationService, CalculatorConfig config);
    
    public TrustLevel calculate(TrustFactors factors);
    public CompletableFuture<TrustLevel> calculateForUser(CalculationRequest request);
    public CompletableFuture<TrustLevel> calculateForAuthentication(String userId, String deviceId, String ipAddress);
    
    public static TrustLevel getTrustLevelForOperation(String operation);
    public static void validateFactors(TrustFactors factors);
    public static Predicate<TrustLevel> requireTrustLevel(TrustLevel required);
}
```

### **Trust Levels**

```java
public enum TrustLevel {
    NONE(0),      // Untrusted
    LOW(25),      // Basic authentication  
    MEDIUM(50),   // Known device
    HIGH(75),     // Verified device + location
    FULL(100);    // Hardware attestation
}
```

## 🔗 **Integration Examples**

### **Spring Boot Integration**

```java
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.zerotrust.authcore.jwt.JWTManager;
import com.zerotrust.authcore.jwt.JWTConfig;
import com.zerotrust.authcore.trust.TrustLevel;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public JWTManager jwtManager() {
        JWTConfig config = JWTConfig.builder()
            .secret("your-secret-key-32-characters-long")
            .expiryDuration(Duration.ofMinutes(30))
            .issuer("my-service")
            .build();
        return new JWTManager(config);
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.addFilterBefore(new JWTAuthenticationFilter(jwtManager()), 
                           UsernamePasswordAuthenticationFilter.class);
        
        http.authorizeHttpRequests(authz -> authz
            .requestMatchers("/api/public/**").permitAll()
            .requestMatchers("/api/profile").hasAuthority("USER")
            .requestMatchers("/api/admin/**").hasAuthority("ADMIN")
            .anyRequest().authenticated()
        );
        
        return http.build();
    }
}

@RestController
public class AuthController {
    
    @Autowired
    private JWTManager jwtManager;
    
    @PostMapping("/api/auth/login")
    public CompletableFuture<ResponseEntity<Token>> login(@RequestBody LoginRequest request) {
        // Validate credentials (your logic here)
        User user = validateCredentials(request.getEmail(), request.getPassword());
        
        if (user == null) {
            return CompletableFuture.completedFuture(ResponseEntity.status(401).build());
        }
        
        TokenRequest tokenRequest = TokenRequest.builder()
            .userId(user.getId())
            .email(user.getEmail())
            .roles(user.getRoles())
            .permissions(user.getPermissions())
            .trustLevel(50) // Calculate based on login context
            .build();
        
        return jwtManager.generateToken(tokenRequest)
            .thenApply(token -> ResponseEntity.ok(token));
    }
    
    @DeleteMapping("/api/resource/{id}")
    @PreAuthorize("@trustLevelChecker.checkTrustLevel(authentication, T(com.zerotrust.authcore.trust.TrustLevel).HIGH)")
    public ResponseEntity<Void> deleteResource(@PathVariable String id) {
        // Delete resource logic
        return ResponseEntity.ok().build();
    }
}

@Component
public class TrustLevelChecker {
    public boolean checkTrustLevel(Authentication auth, TrustLevel required) {
        if (auth.getPrincipal() instanceof JWTClaims) {
            JWTClaims claims = (JWTClaims) auth.getPrincipal();
            TrustLevel actual = TrustLevel.fromValue(claims.getTrustLevel());
            return actual.meetsRequirement(required);
        }
        return false;
    }
}
```

### **JAX-RS Integration**

```java
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerRequestContext;

import com.zerotrust.authcore.jwt.JWTManager;
import com.zerotrust.authcore.trust.TrustLevel;

@Provider
public class JWTAuthenticationFilter implements ContainerRequestFilter {
    
    private final JWTManager jwtManager;
    
    public JWTAuthenticationFilter(JWTManager jwtManager) {
        this.jwtManager = jwtManager;
    }
    
    @Override
    public void filter(ContainerRequestContext requestContext) {
        String authHeader = requestContext.getHeaderString("Authorization");
        
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            requestContext.abortWith(Response.status(401).build());
            return;
        }
        
        String token = authHeader.substring(7);
        
        try {
            JWTClaims claims = jwtManager.validateToken(token).get();
            requestContext.setProperty("user_claims", claims);
        } catch (Exception e) {
            requestContext.abortWith(Response.status(403).build());
        }
    }
}

@Path("/api")
public class ResourceController {
    
    @GET
    @Path("/profile")
    public Response getProfile(@Context ContainerRequestContext context) {
        JWTClaims claims = (JWTClaims) context.getProperty("user_claims");
        return Response.ok(Map.of("user", claims)).build();
    }
    
    @DELETE
    @Path("/resource/{id}")
    @RequiresTrustLevel(TrustLevel.HIGH)
    public Response deleteResource(@PathParam("id") String id, 
                                 @Context ContainerRequestContext context) {
        return Response.ok().build();
    }
}

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresTrustLevel {
    TrustLevel value();
}
```

## 🔒 **Security Considerations**

- **Secret Management**: Store JWT secrets securely (environment variables, key vaults)
- **Token Expiration**: Use short expiration times for access tokens
- **Blacklisting**: Implement token blacklisting for immediate revocation
- **Trust Levels**: Adjust trust calculations based on your security requirements
- **Key Rotation**: Enable automatic key rotation for enhanced security
- **Input Validation**: Always validate inputs before processing
- **Thread Safety**: All components are designed to be thread-safe
- **Async Operations**: Use CompletableFuture properly to avoid blocking threads

## 📄 **License**

MIT License - see [LICENSE](../../LICENSE) file for details.

---

**Zero Trust Authentication Core** - Building secure, scalable authentication for Java applications.