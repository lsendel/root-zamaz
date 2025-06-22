# Java Spring Boot Template - Zero Trust Architecture

> **Template**: Production-ready Java Spring Boot service with Zero Trust security  
> **Based On**: Zero Trust Authentication MVP patterns  
> **Version**: 1.0  
> **Last Updated**: 2025-06-21

## 🎯 **Template Overview**

This template provides a complete Java Spring Boot microservice foundation implementing Zero Trust security principles, enterprise Java patterns, and production-ready features.

### **Key Features**
- **Zero Trust Security**: JWT authentication, device attestation, continuous verification
- **Spring Security Integration**: Comprehensive security configuration
- **Enterprise Patterns**: Clean architecture with Spring best practices
- **JPA/Hibernate**: Database access with migration support
- **Testing Framework**: JUnit 5 with TestContainers and WireMock
- **Observability**: Micrometer metrics and structured logging

## 📁 **Directory Structure**

```
{service-name}/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/
│   │   │       └── {company}/
│   │   │           └── {service}/
│   │   │               ├── Application.java                # Main application class
│   │   │               ├── config/                         # Configuration classes
│   │   │               │   ├── SecurityConfig.java
│   │   │               │   ├── DatabaseConfig.java
│   │   │               │   ├── RedisConfig.java
│   │   │               │   └── ObservabilityConfig.java
│   │   │               ├── security/                       # Security components
│   │   │               │   ├── jwt/
│   │   │               │   │   ├── JwtAuthenticationFilter.java
│   │   │               │   │   ├── JwtTokenProvider.java
│   │   │               │   │   └── JwtAuthenticationEntryPoint.java
│   │   │               │   ├── trust/
│   │   │               │   │   ├── TrustLevel.java
│   │   │               │   │   └── TrustCalculator.java
│   │   │               │   └── UserPrincipal.java
│   │   │               ├── domain/                         # Domain entities
│   │   │               │   ├── entity/
│   │   │               │   │   ├── User.java
│   │   │               │   │   ├── Role.java
│   │   │               │   │   ├── Permission.java
│   │   │               │   │   └── AuditableEntity.java
│   │   │               │   ├── repository/
│   │   │               │   │   ├── UserRepository.java
│   │   │               │   │   └── RoleRepository.java
│   │   │               │   └── service/
│   │   │               │       ├── UserService.java
│   │   │               │       └── AuthenticationService.java
│   │   │               ├── api/                            # REST controllers
│   │   │               │   ├── controller/
│   │   │               │   │   ├── AuthController.java
│   │   │               │   │   ├── UserController.java
│   │   │               │   │   └── HealthController.java
│   │   │               │   ├── dto/                        # Data transfer objects
│   │   │               │   │   ├── request/
│   │   │               │   │   └── response/
│   │   │               │   └── exception/
│   │   │               │       ├── GlobalExceptionHandler.java
│   │   │               │       └── CustomExceptions.java
│   │   │               ├── infrastructure/                 # External integrations
│   │   │               │   ├── cache/
│   │   │               │   ├── messaging/
│   │   │               │   └── external/
│   │   │               └── util/                          # Utility classes
│   │   │                   ├── SecurityUtils.java
│   │   │                   └── ValidationUtils.java
│   │   └── resources/
│   │       ├── application.yml                           # Main configuration
│   │       ├── application-dev.yml                       # Development config
│   │       ├── application-prod.yml                      # Production config
│   │       ├── db/migration/                            # Flyway migrations
│   │       │   └── V1__Initial_schema.sql
│   │       └── static/                                  # Static resources
│   └── test/
│       ├── java/
│       │   └── com/
│       │       └── {company}/
│       │           └── {service}/
│       │               ├── integration/                  # Integration tests
│       │               ├── unit/                        # Unit tests
│       │               └── testcontainers/              # Container tests
│       └── resources/
│           ├── application-test.yml                     # Test configuration
│           └── test-data/                              # Test data files
├── docker/
│   ├── Dockerfile                                      # Container definition
│   └── docker-compose.yml                             # Local development
├── k8s/                                               # Kubernetes manifests
│   ├── deployment.yaml
│   ├── service.yaml
│   └── configmap.yaml
├── .github/
│   └── workflows/
│       └── ci.yml                                     # GitHub Actions CI
├── .gitignore                                         # Git ignore patterns
├── .env.template                                      # Environment template
├── Makefile                                           # Build automation
├── pom.xml                                           # Maven configuration
├── mvnw                                              # Maven wrapper
├── mvnw.cmd                                          # Windows Maven wrapper
└── README.md                                         # Project documentation
```

## 🛠️ **Template Files**

### **Main Application Class (Application.java)**
```java
package com.{company}.{service};

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * Main application class for the Zero Trust microservice.
 */
@SpringBootApplication
@EnableJpaAuditing
@EnableAsync
@EnableTransactionManagement
@ConfigurationPropertiesScan
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

### **Security Configuration (config/SecurityConfig.java)**
```java
package com.{company}.{service}.config;

import com.{company}.{service}.security.jwt.JwtAuthenticationEntryPoint;
import com.{company}.{service}.security.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * Spring Security configuration implementing Zero Trust principles.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    /**
     * Password encoder bean using BCrypt with strength 12.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * Authentication manager bean.
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    /**
     * Main security filter chain configuration.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                // Disable CSRF for stateless API
                .csrf(csrf -> csrf.disable())
                
                // Configure CORS
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                
                // Configure session management
                .sessionManagement(session -> 
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                
                // Configure exception handling
                .exceptionHandling(ex -> 
                    ex.authenticationEntryPoint(jwtAuthenticationEntryPoint))
                
                // Configure authorization rules
                .authorizeHttpRequests(auth -> auth
                    // Public endpoints
                    .requestMatchers(HttpMethod.POST, "/api/v1/auth/**").permitAll()
                    .requestMatchers(HttpMethod.GET, "/health/**").permitAll()
                    .requestMatchers(HttpMethod.GET, "/actuator/health").permitAll()
                    .requestMatchers(HttpMethod.GET, "/actuator/info").permitAll()
                    .requestMatchers(HttpMethod.GET, "/actuator/metrics").permitAll()
                    .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                    
                    // Admin endpoints
                    .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                    
                    // All other endpoints require authentication
                    .anyRequest().authenticated()
                )
                
                // Add JWT filter
                .addFilterBefore(jwtAuthenticationFilter, 
                    UsernamePasswordAuthenticationFilter.class)
                
                // Security headers
                .headers(headers -> headers
                    .frameOptions().deny()
                    .contentTypeOptions().and()
                    .httpStrictTransportSecurity(hstsConfig -> hstsConfig
                        .maxAgeInSeconds(31536000)
                        .includeSubdomains(true))
                )
                
                .build();
    }

    /**
     * CORS configuration for cross-origin requests.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        configuration.setAllowedOriginPatterns(List.of(
            "http://localhost:3000",
            "http://localhost:5173",
            "https://*.yourdomain.com"
        ));
        
        configuration.setAllowedMethods(Arrays.asList(
            "GET", "POST", "PUT", "DELETE", "OPTIONS"
        ));
        
        configuration.setAllowedHeaders(Arrays.asList(
            "Authorization", "Content-Type", "X-Request-ID", "X-Correlation-ID"
        ));
        
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        
        return source;
    }
}
```

### **JWT Token Provider (security/jwt/JwtTokenProvider.java)**
```java
package com.{company}.{service}.security.jwt;

import com.{company}.{service}.security.UserPrincipal;
import com.{company}.{service}.security.trust.TrustLevel;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

/**
 * JWT token provider for creating and validating JWT tokens with Zero Trust features.
 */
@Component
@Slf4j
public class JwtTokenProvider {

    private final SecretKey jwtSecret;
    private final int jwtExpirationInMs;
    private final int refreshTokenExpirationInMs;

    public JwtTokenProvider(
            @Value("${app.jwt.secret}") String jwtSecret,
            @Value("${app.jwt.access-token-expiration-ms}") int jwtExpirationInMs,
            @Value("${app.jwt.refresh-token-expiration-ms}") int refreshTokenExpirationInMs) {
        this.jwtSecret = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        this.jwtExpirationInMs = jwtExpirationInMs;
        this.refreshTokenExpirationInMs = refreshTokenExpirationInMs;
    }

    /**
     * Generate access token with trust level information.
     */
    public String generateAccessToken(Authentication authentication, TrustLevel trustLevel, String deviceId) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        
        Instant now = Instant.now();
        Instant expiryDate = now.plus(jwtExpirationInMs, ChronoUnit.MILLIS);

        return Jwts.builder()
                .setSubject(userPrincipal.getId().toString())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiryDate))
                .setId(UUID.randomUUID().toString()) // JTI for blacklisting
                .claim("email", userPrincipal.getEmail())
                .claim("roles", userPrincipal.getAuthorities().stream()
                    .map(authority -> authority.getAuthority())
                    .toList())
                .claim("trustLevel", trustLevel.getValue())
                .claim("deviceId", deviceId)
                .signWith(jwtSecret, SignatureAlgorithm.HS512)
                .compact();
    }

    /**
     * Generate refresh token.
     */
    public String generateRefreshToken(String userId) {
        Instant now = Instant.now();
        Instant expiryDate = now.plus(refreshTokenExpirationInMs, ChronoUnit.MILLIS);

        return Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiryDate))
                .setId(UUID.randomUUID().toString())
                .claim("type", "refresh")
                .signWith(jwtSecret, SignatureAlgorithm.HS512)
                .compact();
    }

    /**
     * Get user ID from JWT token.
     */
    public String getUserIdFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(jwtSecret)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }

    /**
     * Get trust level from JWT token.
     */
    public TrustLevel getTrustLevelFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(jwtSecret)
                .build()
                .parseClaimsJws(token)
                .getBody();

        Integer trustValue = claims.get("trustLevel", Integer.class);
        return TrustLevel.fromValue(trustValue != null ? trustValue : 50);
    }

    /**
     * Get JWT ID for blacklisting.
     */
    public String getJwtIdFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(jwtSecret)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getId();
    }

    /**
     * Validate JWT token.
     */
    public boolean validateToken(String authToken) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(jwtSecret)
                .build()
                .parseClaimsJws(authToken);
            return true;
        } catch (SecurityException ex) {
            log.error("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty");
        }
        return false;
    }

    /**
     * Get expiration date from token.
     */
    public Date getExpirationDateFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(jwtSecret)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getExpiration();
    }

    /**
     * Check if token is expired.
     */
    public boolean isTokenExpired(String token) {
        Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }
}
```

### **Trust Level Enum (security/trust/TrustLevel.java)**
```java
package com.{company}.{service}.security.trust;

import lombok.Getter;

/**
 * Trust levels for Zero Trust authentication.
 */
@Getter
public enum TrustLevel {
    NONE(0, "Untrusted"),
    LOW(25, "Basic authentication"),
    MEDIUM(50, "Known device"),
    HIGH(75, "Verified device + location"),
    FULL(100, "Hardware attestation");

    private final int value;
    private final String description;

    TrustLevel(int value, String description) {
        this.value = value;
        this.description = description;
    }

    /**
     * Get trust level from integer value.
     */
    public static TrustLevel fromValue(int value) {
        for (TrustLevel level : values()) {
            if (level.value <= value) {
                continue;
            }
            return values()[Math.max(0, level.ordinal() - 1)];
        }
        return FULL;
    }

    /**
     * Check if this trust level meets the required minimum.
     */
    public boolean meetsRequirement(TrustLevel required) {
        return this.value >= required.value;
    }
}
```

### **User Entity (domain/entity/User.java)**
```java
package com.{company}.{service}.domain.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.hibernate.annotations.NaturalId;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * User entity with Zero Trust attributes.
 */
@Entity
@Table(name = "users", indexes = {
    @Index(name = "idx_user_email", columnList = "email"),
    @Index(name = "idx_user_active", columnList = "active")
})
@Data
@EqualsAndHashCode(callSuper = true)
@NoArgsConstructor
@AllArgsConstructor
public class User extends AuditableEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @NotBlank
    @Size(max = 255)
    @Email
    @NaturalId
    @Column(nullable = false, unique = true)
    private String email;

    @NotBlank
    @Size(max = 100)
    @Column(name = "first_name")
    private String firstName;

    @NotBlank
    @Size(max = 100)
    @Column(name = "last_name")
    private String lastName;

    @NotBlank
    @Size(max = 120)
    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private Boolean active = true;

    @Column(nullable = false)
    private Boolean emailVerified = false;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    @Column(name = "failed_login_attempts")
    private Integer failedLoginAttempts = 0;

    @Column(name = "account_locked_until")
    private LocalDateTime accountLockedUntil;

    @Column(name = "password_changed_at")
    private LocalDateTime passwordChangedAt;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    /**
     * Check if user account is locked.
     */
    public boolean isAccountLocked() {
        return accountLockedUntil != null && accountLockedUntil.isAfter(LocalDateTime.now());
    }

    /**
     * Check if user needs to change password.
     */
    public boolean needsPasswordChange() {
        if (passwordChangedAt == null) {
            return true;
        }
        // Password expires after 90 days
        return passwordChangedAt.plusDays(90).isBefore(LocalDateTime.now());
    }

    /**
     * Get full name.
     */
    public String getFullName() {
        return firstName + " " + lastName;
    }

    /**
     * Add role to user.
     */
    public void addRole(Role role) {
        roles.add(role);
        role.getUsers().add(this);
    }

    /**
     * Remove role from user.
     */
    public void removeRole(Role role) {
        roles.remove(role);
        role.getUsers().remove(this);
    }
}
```

### **Application Configuration (application.yml)**
```yaml
# Main application configuration
spring:
  application:
    name: {service-name}

  profiles:
    active: ${SPRING_PROFILES_ACTIVE:dev}

  # Database configuration
  datasource:
    url: ${DATABASE_URL:jdbc:postgresql://localhost:5432/{service_name}_db}
    username: ${DATABASE_USERNAME:postgres}
    password: ${DATABASE_PASSWORD:password}
    driver-class-name: org.postgresql.Driver
    hikari:
      minimum-idle: ${DATABASE_MIN_POOL_SIZE:5}
      maximum-pool-size: ${DATABASE_MAX_POOL_SIZE:20}
      idle-timeout: ${DATABASE_IDLE_TIMEOUT:300000}
      max-lifetime: ${DATABASE_MAX_LIFETIME:1200000}
      connection-timeout: ${DATABASE_CONNECTION_TIMEOUT:20000}

  # JPA configuration
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
        format_sql: true
        use_sql_comments: true
        jdbc:
          batch_size: 20
        order_inserts: true
        order_updates: true

  # Redis configuration
  data:
    redis:
      url: ${REDIS_URL:redis://localhost:6379}
      password: ${REDIS_PASSWORD:}
      timeout: ${REDIS_TIMEOUT:2000ms}
      lettuce:
        pool:
          min-idle: ${REDIS_MIN_IDLE:0}
          max-idle: ${REDIS_MAX_IDLE:8}
          max-active: ${REDIS_MAX_ACTIVE:8}

  # Flyway migration
  flyway:
    enabled: true
    baseline-on-migrate: true
    locations: classpath:db/migration

# Server configuration
server:
  port: ${SERVER_PORT:8080}
  servlet:
    context-path: /
  compression:
    enabled: true
    mime-types: text/html,text/xml,text/plain,text/css,text/javascript,application/javascript,application/json
    min-response-size: 1024

# Application-specific configuration
app:
  jwt:
    secret: ${JWT_SECRET:your-secret-key-here-must-be-at-least-256-bits-long}
    access-token-expiration-ms: ${JWT_ACCESS_TOKEN_EXPIRATION:1800000} # 30 minutes
    refresh-token-expiration-ms: ${JWT_REFRESH_TOKEN_EXPIRATION:604800000} # 7 days

  security:
    password:
      min-length: ${PASSWORD_MIN_LENGTH:8}
      max-failed-attempts: ${MAX_FAILED_LOGIN_ATTEMPTS:5}
      lockout-duration-minutes: ${ACCOUNT_LOCKOUT_DURATION:30}
    
    rate-limiting:
      enabled: ${RATE_LIMITING_ENABLED:true}
      requests-per-minute: ${RATE_LIMIT_REQUESTS_PER_MINUTE:60}

  cors:
    allowed-origins: ${CORS_ALLOWED_ORIGINS:http://localhost:3000,http://localhost:5173}
    allowed-methods: ${CORS_ALLOWED_METHODS:GET,POST,PUT,DELETE,OPTIONS}
    allowed-headers: ${CORS_ALLOWED_HEADERS:Authorization,Content-Type,X-Request-ID}
    allow-credentials: ${CORS_ALLOW_CREDENTIALS:true}

# Actuator configuration
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
      base-path: /actuator
  endpoint:
    health:
      show-details: when-authorized
      show-components: always
      probes:
        enabled: true
  metrics:
    export:
      prometheus:
        enabled: true
    tags:
      application: ${spring.application.name}
      environment: ${spring.profiles.active}

# Logging configuration
logging:
  level:
    com.{company}.{service}: ${LOG_LEVEL:INFO}
    org.springframework.security: ${SECURITY_LOG_LEVEL:WARN}
    org.hibernate.SQL: ${SQL_LOG_LEVEL:WARN}
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level [%X{correlationId}] %logger{36} - %msg%n"
    file: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level [%X{correlationId}] %logger{36} - %msg%n"

# OpenAPI documentation
springdoc:
  api-docs:
    path: /v3/api-docs
  swagger-ui:
    path: /swagger-ui.html
    operationsSorter: method
    tagsSorter: alpha
    disable-swagger-default-url: true
```

### **Maven Configuration (pom.xml)**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.0</version>
        <relativePath/>
    </parent>

    <groupId>com.{company}</groupId>
    <artifactId>{service-name}</artifactId>
    <version>1.0.0</version>
    <name>{service-name}</name>
    <description>Zero Trust microservice with Spring Boot</description>

    <properties>
        <java.version>21</java.version>
        <maven.compiler.source>21</maven.compiler.source>
        <maven.compiler.target>21</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        
        <!-- Dependency versions -->
        <jjwt.version>0.12.3</jjwt.version>
        <testcontainers.version>1.19.3</testcontainers.version>
        <mapstruct.version>1.5.5.Final</mapstruct.version>
        <springdoc.version>2.3.0</springdoc.version>
        <archunit.version>1.2.1</archunit.version>
    </properties>

    <dependencies>
        <!-- Spring Boot Starters -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>
        
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
        
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>

        <!-- JWT -->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
            <version>${jjwt.version}</version>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <version>${jjwt.version}</version>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-jackson</artifactId>
            <version>${jjwt.version}</version>
            <scope>runtime</scope>
        </dependency>

        <!-- Database -->
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <scope>runtime</scope>
        </dependency>
        
        <dependency>
            <groupId>org.flywaydb</groupId>
            <artifactId>flyway-core</artifactId>
        </dependency>

        <!-- Metrics -->
        <dependency>
            <groupId>io.micrometer</groupId>
            <artifactId>micrometer-registry-prometheus</artifactId>
        </dependency>

        <!-- Utilities -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
        
        <dependency>
            <groupId>org.mapstruct</groupId>
            <artifactId>mapstruct</artifactId>
            <version>${mapstruct.version}</version>
        </dependency>

        <!-- Documentation -->
        <dependency>
            <groupId>org.springdoc</groupId>
            <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
            <version>${springdoc.version}</version>
        </dependency>

        <!-- Test Dependencies -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
        
        <dependency>
            <groupId>org.testcontainers</groupId>
            <artifactId>junit-jupiter</artifactId>
            <version>${testcontainers.version}</version>
            <scope>test</scope>
        </dependency>
        
        <dependency>
            <groupId>org.testcontainers</groupId>
            <artifactId>postgresql</artifactId>
            <version>${testcontainers.version}</version>
            <scope>test</scope>
        </dependency>
        
        <dependency>
            <groupId>com.tngtech.archunit</groupId>
            <artifactId>archunit-junit5</artifactId>
            <version>${archunit.version}</version>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <configuration>
                    <excludes>
                        <exclude>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok</artifactId>
                        </exclude>
                    </excludes>
                </configuration>
            </plugin>
            
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <configuration>
                    <annotationProcessorPaths>
                        <path>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok</artifactId>
                            <version>${lombok.version}</version>
                        </path>
                        <path>
                            <groupId>org.mapstruct</groupId>
                            <artifactId>mapstruct-processor</artifactId>
                            <version>${mapstruct.version}</version>
                        </path>
                    </annotationProcessorPaths>
                </configuration>
            </plugin>
            
            <plugin>
                <groupId>org.flywaydb</groupId>
                <artifactId>flyway-maven-plugin</artifactId>
                <configuration>
                    <url>${DATABASE_URL}</url>
                    <user>${DATABASE_USERNAME}</user>
                    <password>${DATABASE_PASSWORD}</password>
                </configuration>
            </plugin>
            
            <plugin>
                <groupId>org.jacoco</groupId>
                <artifactId>jacoco-maven-plugin</artifactId>
                <version>0.8.11</version>
                <executions>
                    <execution>
                        <goals>
                            <goal>prepare-agent</goal>
                        </goals>
                    </execution>
                    <execution>
                        <id>report</id>
                        <phase>test</phase>
                        <goals>
                            <goal>report</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
</project>
```

### **Environment Template (.env.template)**
```bash
# {SERVICE_NAME} Environment Configuration

# Application Configuration
SPRING_PROFILES_ACTIVE=dev
SERVER_PORT=8080

# Database Configuration
DATABASE_URL=jdbc:postgresql://localhost:5432/{service_name}_db
DATABASE_USERNAME=postgres
DATABASE_PASSWORD=your_secure_password_here
DATABASE_MIN_POOL_SIZE=5
DATABASE_MAX_POOL_SIZE=20

# Redis Configuration
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=
REDIS_TIMEOUT=2000ms

# JWT Configuration
JWT_SECRET=your-jwt-secret-key-here-must-be-at-least-256-bits-long-for-security
JWT_ACCESS_TOKEN_EXPIRATION=1800000
JWT_REFRESH_TOKEN_EXPIRATION=604800000

# Security Configuration
PASSWORD_MIN_LENGTH=8
MAX_FAILED_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION=30
RATE_LIMITING_ENABLED=true
RATE_LIMIT_REQUESTS_PER_MINUTE=60

# CORS Configuration
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
CORS_ALLOWED_METHODS=GET,POST,PUT,DELETE,OPTIONS
CORS_ALLOWED_HEADERS=Authorization,Content-Type,X-Request-ID
CORS_ALLOW_CREDENTIALS=true

# Logging Configuration
LOG_LEVEL=INFO
SECURITY_LOG_LEVEL=WARN
SQL_LOG_LEVEL=WARN

# External Services
EXTERNAL_API_URL=https://api.external-service.com
EXTERNAL_API_KEY=your_external_api_key_here

# Monitoring
METRICS_ENABLED=true
HEALTH_CHECK_ENABLED=true
```

### **Makefile Template**
```makefile
# Java Spring Boot Makefile
.PHONY: help dev build test lint clean install

# Configuration
SERVICE_NAME := {service-name}
JAVA_VERSION := $(shell java -version 2>&1 | head -1 | cut -d'"' -f2)
MAVEN_VERSION := $(shell mvn --version 2>/dev/null | head -1 | cut -d' ' -f3)

help: ## 📖 Show this help message
	@echo "🚀 $(SERVICE_NAME) - Java Spring Boot Service"
	@echo "============================================="
	@echo "📋 DEVELOPMENT:"
	@echo "  make dev          ⚡ Start development server"
	@echo "  make build        🔨 Build the application"
	@echo "  make test         🧪 Run all tests"
	@echo "  make package      📦 Create JAR package"
	@echo ""
	@echo "🗃️  DATABASE:"
	@echo "  make db-migrate   🗃️  Run database migrations"
	@echo "  make db-clean     🧹 Clean database"
	@echo ""
	@echo "🔍 QUALITY:"
	@echo "  make lint         🔍 Run code quality checks"
	@echo "  make format       ✨ Format code"
	@echo ""
	@echo "🧹 UTILITIES:"
	@echo "  make clean        🧹 Clean build artifacts"
	@echo "  make install      📥 Install dependencies"

## Development Commands

dev: ## ⚡ Start development server
	@echo "⚡ Starting development server..."
	./mvnw spring-boot:run -Dspring.profiles.active=dev

build: ## 🔨 Build the application
	@echo "🔨 Building application..."
	./mvnw clean compile

package: ## 📦 Create JAR package
	@echo "📦 Creating JAR package..."
	./mvnw clean package -DskipTests

package-with-tests: ## 📦 Create JAR package with tests
	@echo "📦 Creating JAR package with tests..."
	./mvnw clean package

## Testing Commands

test: ## 🧪 Run all tests
	@echo "🧪 Running all tests..."
	./mvnw test

test-unit: ## 🧪 Run unit tests only
	@echo "🧪 Running unit tests..."
	./mvnw test -Dtest="**/unit/**/*Test"

test-integration: ## 🔗 Run integration tests
	@echo "🔗 Running integration tests..."
	./mvnw test -Dtest="**/integration/**/*Test"

test-coverage: ## 📊 Run tests with coverage
	@echo "📊 Running tests with coverage..."
	./mvnw clean test jacoco:report

## Quality Commands

lint: ## 🔍 Run code quality checks
	@echo "🔍 Running code quality checks..."
	./mvnw checkstyle:check
	./mvnw spotbugs:check
	./mvnw pmd:check

format: ## ✨ Format code
	@echo "✨ Formatting code..."
	./mvnw spotless:apply

## Database Commands

db-migrate: ## 🗃️ Run database migrations
	@echo "🗃️ Running database migrations..."
	./mvnw flyway:migrate

db-info: ## ℹ️ Show migration info
	@echo "ℹ️ Showing migration info..."
	./mvnw flyway:info

db-clean: ## 🧹 Clean database
	@echo "🧹 Cleaning database..."
	./mvnw flyway:clean

db-validate: ## ✅ Validate migrations
	@echo "✅ Validating migrations..."
	./mvnw flyway:validate

## Utility Commands

install: ## 📥 Install dependencies
	@echo "📥 Installing dependencies..."
	./mvnw dependency:resolve

clean: ## 🧹 Clean build artifacts
	@echo "🧹 Cleaning build artifacts..."
	./mvnw clean

dependency-check: ## 🔒 Check for vulnerabilities
	@echo "🔒 Checking dependencies for vulnerabilities..."
	./mvnw org.owasp:dependency-check-maven:check

## Docker Commands

docker-build: ## 📦 Build Docker image
	@echo "📦 Building Docker image..."
	docker build -t $(SERVICE_NAME):latest .

docker-run: ## 🐳 Run with Docker Compose
	@echo "🐳 Starting services with Docker Compose..."
	docker-compose up --build

## Environment Commands

env-setup: ## 🔧 Setup environment file
	@echo "🔧 Setting up environment..."
	@if [ ! -f .env ]; then \
		cp .env.template .env; \
		echo "✅ Created .env file from template"; \
		echo "📝 Please edit .env with your configuration"; \
	else \
		echo "⚠️  .env file already exists"; \
	fi

env-check: ## ✅ Check environment setup
	@echo "✅ Checking environment..."
	@echo "Java: $(JAVA_VERSION)"
	@echo "Maven: $(MAVEN_VERSION)"
	@echo "Service: $(SERVICE_NAME)"

## Documentation Commands

docs-generate: ## 📚 Generate documentation
	@echo "📚 Generating documentation..."
	./mvnw javadoc:javadoc
	./mvnw springdoc-openapi:generate

## Monitoring Commands

status: ## 📊 Check service status
	@echo "📊 Service Status:"
	@curl -s http://localhost:8080/actuator/health | jq . || echo "Service not running"

metrics: ## 📊 View metrics
	@echo "📊 Metrics:"
	@curl -s http://localhost:8080/actuator/metrics | jq . || echo "Metrics not available"

info: ## ℹ️ View application info
	@echo "ℹ️ Application Info:"
	@curl -s http://localhost:8080/actuator/info | jq . || echo "Info not available"
```

## 📋 **Setup Instructions**

### **1. Initialize New Service**
```bash
# Create new service from template
mkdir my-new-service
cd my-new-service

# Copy template files
# Update package names in all Java files

# Set up environment
make env-setup
# Edit .env with your configuration
```

### **2. Database Setup**
```bash
# Install and configure PostgreSQL
# Update DATABASE_URL in .env

# Run migrations
make db-migrate

# Verify setup
make db-info
```

### **3. Development Workflow**
```bash
# Start development server
make dev

# Run tests
make test

# Code quality checks
make lint format

# Build application
make package
```

## 🔒 **Security Features Included**

- **Spring Security Integration** with JWT authentication
- **Zero Trust Architecture** with trust level management
- **Password Security** with BCrypt and complexity requirements
- **Account Lockout** protection against brute force attacks
- **Rate Limiting** middleware
- **CORS Configuration** for cross-origin security
- **Input Validation** with Bean Validation
- **SQL Injection Prevention** with JPA/Hibernate
- **Security Headers** configuration

## 🚀 **Production Features**

- **Connection Pooling** with HikariCP
- **Database Migrations** with Flyway
- **Metrics Integration** with Micrometer and Prometheus
- **Health Checks** for Kubernetes
- **Structured Logging** with correlation IDs
- **Documentation** with SpringDoc OpenAPI
- **Testing Strategy** with TestContainers and WireMock
- **Build Optimization** with Maven profiles

This template provides a solid foundation for building secure, scalable Java Spring Boot services following the patterns established in the Zero Trust Authentication MVP.