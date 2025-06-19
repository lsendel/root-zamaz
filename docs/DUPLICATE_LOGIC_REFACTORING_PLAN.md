# Duplicate Logic Refactoring Plan

## Overview

This document outlines a comprehensive plan to address duplicate logic identified across the codebase. The plan is organized by priority (High, Medium, Low) and includes specific refactoring strategies, estimated effort, and expected benefits.

## Summary of Findings

The analysis identified duplicate logic patterns in the following areas:
- **Error handling** (gorm.ErrRecordNotFound, parameter parsing)
- **Audit logging** across handlers
- **Session management** logic
- **Context data extraction** patterns
- **Authorization checks** (nil enforcer validations)
- **JWT token generation** patterns
- **HTTP status/error code mapping**

## Refactoring Plan

### 🔥 **Phase 1: High Priority (Week 1-2)**

#### 1.1 Database Error Handling Utilities

**Problem**: Identical `gorm.ErrRecordNotFound` handling across all handlers
**Impact**: High - Appears in 15+ locations

**Solution**: Create shared error handling utilities

```go
// pkg/handlers/common/errors.go
package common

import (
    "github.com/gofiber/fiber/v2"
    "gorm.io/gorm"
    "mvp.local/pkg/errors"
)

// HandleDatabaseError provides standardized database error handling
func HandleDatabaseError(c *fiber.Ctx, err error, resourceName string) error {
    if err == gorm.ErrRecordNotFound {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
            "error":   "Not Found",
            "message": fmt.Sprintf("%s not found", resourceName),
        })
    }
    
    return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
        "error":   "Internal Server Error", 
        "message": "Database error",
    })
}

// FindByID provides standardized record retrieval with error handling
func FindByID[T any](db *gorm.DB, id uint, dest *T, resourceName string) error {
    if err := db.First(dest, id).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            return errors.NotFound(fmt.Sprintf("%s not found", resourceName))
        }
        return errors.Internal("Database error")
    }
    return nil
}
```

**Files to Update**:
- `pkg/handlers/auth.go` (5 locations)
- `pkg/handlers/admin.go` (3 locations)  
- `pkg/handlers/device.go` (2 locations)
- `pkg/handlers/system.go` (1 location)

**Estimated Effort**: 4 hours
**Benefit**: Eliminates 11+ duplicate error handling blocks

#### 1.2 URL Parameter Parsing Utilities

**Problem**: Repeated `strconv.ParseUint` logic with identical error responses
**Impact**: Medium - Appears in 8+ locations

**Solution**: Create parameter parsing utilities

```go
// pkg/handlers/common/params.go
package common

import (
    "strconv"
    "github.com/gofiber/fiber/v2"
)

// ParseUintParam parses a URL parameter as uint with standardized error handling
func ParseUintParam(c *fiber.Ctx, paramName, displayName string) (uint, error) {
    paramStr := c.Params(paramName)
    if paramStr == "" {
        return 0, c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error":   "Bad Request",
            "message": fmt.Sprintf("Missing %s parameter", displayName),
        })
    }
    
    id, err := strconv.ParseUint(paramStr, 10, 32)
    if err != nil {
        return 0, c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error":   "Bad Request", 
            "message": fmt.Sprintf("Invalid %s", displayName),
        })
    }
    
    return uint(id), nil
}

// ParseOptionalUintParam parses an optional URL parameter
func ParseOptionalUintParam(c *fiber.Ctx, paramName string) (uint, bool) {
    paramStr := c.Params(paramName)
    if paramStr == "" {
        return 0, false
    }
    
    id, err := strconv.ParseUint(paramStr, 10, 32)
    if err != nil {
        return 0, false
    }
    
    return uint(id), true
}
```

**Files to Update**:
- `pkg/handlers/admin.go` (4 locations)
- `pkg/handlers/device.go` (2 locations)

**Estimated Effort**: 2 hours
**Benefit**: Eliminates 6+ duplicate parsing blocks

#### 1.3 Audit Logging Service

**Problem**: Near-identical audit logging logic across handlers
**Impact**: High - Complex logic duplicated in 2+ handlers

**Solution**: Create shared audit logging service

```go
// pkg/audit/service.go
package audit

import (
    "context"
    "encoding/json"
    "time"
    "github.com/gofiber/fiber/v2"
    "github.com/google/uuid"
    "gorm.io/gorm"
    "mvp.local/pkg/models"
    "mvp.local/pkg/observability"
)

type Service struct {
    db  *gorm.DB
    obs *observability.Observability
}

type LogEntry struct {
    UserID    string
    Action    string
    Resource  string
    Details   map[string]interface{}
    Success   bool
    Context   *fiber.Ctx
}

func NewService(db *gorm.DB, obs *observability.Observability) *Service {
    return &Service{db: db, obs: obs}
}

func (s *Service) LogEvent(entry LogEntry) {
    detailsJSON, _ := json.Marshal(entry.Details)
    
    var userIDPtr *uuid.UUID
    if entry.UserID != "" {
        if parsed, err := uuid.Parse(entry.UserID); err == nil {
            userIDPtr = &parsed
        }
    }
    
    auditLog := models.AuditLog{
        UserID:    userIDPtr,
        Action:    entry.Action,
        Resource:  entry.Resource,
        Details:   string(detailsJSON),
        IPAddress: entry.Context.IP(),
        UserAgent: entry.Context.Get("User-Agent"),
        RequestID: entry.Context.Get("X-Correlation-ID"),
        Success:   entry.Success,
    }
    
    // Save audit log (non-blocking) with timeout protection
    go func() {
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        
        if err := s.db.WithContext(ctx).Create(&auditLog).Error; err != nil {
            s.obs.Logger.Error().Err(err).Msg("Failed to save audit log")
        }
    }()
}

// Convenient methods for common scenarios
func (s *Service) LogAuthEvent(ctx *fiber.Ctx, userID, event string, success bool, details map[string]interface{}) {
    s.LogEvent(LogEntry{
        UserID:   userID,
        Action:   event,
        Resource: "auth",
        Details:  details,
        Success:  success,
        Context:  ctx,
    })
}

func (s *Service) LogDeviceEvent(ctx *fiber.Ctx, userID, deviceID, event string, success bool, details map[string]interface{}) {
    if details == nil {
        details = make(map[string]interface{})
    }
    details["device_id"] = deviceID
    
    s.LogEvent(LogEntry{
        UserID:   userID,
        Action:   event,
        Resource: "device", 
        Details:  details,
        Success:  success,
        Context:  ctx,
    })
}
```

**Files to Update**:
- `pkg/handlers/auth.go` (remove `logAuthEvent` method)
- `pkg/handlers/device.go` (remove `logDeviceEvent` method)
- Update handler constructors to inject audit service

**Estimated Effort**: 6 hours
**Benefit**: Eliminates 60+ lines of duplicate code, centralizes audit logic

### 🔶 **Phase 2: Medium Priority (Week 3-4)**

#### 2.1 Context Data Extraction Utilities

**Problem**: Repeated patterns for extracting user ID, tenant ID from context
**Impact**: Medium - Appears in 10+ locations

**Solution**: Create context utilities package

```go
// pkg/context/utils.go
package context

import (
    "github.com/gofiber/fiber/v2"
    "github.com/golang-jwt/jwt/v5"
    "mvp.local/pkg/auth"
)

// GetUserID extracts user ID from fiber context with fallback to JWT claims
func GetUserID(c *fiber.Ctx) string {
    // Try from locals first (set by auth middleware)
    if userID := c.Locals("user_id"); userID != nil {
        if id, ok := userID.(string); ok && id != "" {
            return id
        }
    }
    
    // Fallback to JWT claims
    if claims := c.Locals("jwt_claims"); claims != nil {
        if jwtClaims, ok := claims.(*auth.JWTClaims); ok {
            return jwtClaims.UserID
        }
    }
    
    return ""
}

// GetTenantID extracts tenant ID from context
func GetTenantID(c *fiber.Ctx) string {
    if tenantID := c.Locals("tenant_id"); tenantID != nil {
        if id, ok := tenantID.(string); ok {
            return id
        }
    }
    return ""
}

// GetUserRoles extracts user roles from context
func GetUserRoles(c *fiber.Ctx) []string {
    if roles := c.Locals("roles"); roles != nil {
        if roleSlice, ok := roles.([]string); ok {
            return roleSlice
        }
    }
    return []string{}
}

// GetUserPermissions extracts user permissions from context
func GetUserPermissions(c *fiber.Ctx) []string {
    if permissions := c.Locals("permissions"); permissions != nil {
        if permSlice, ok := permissions.([]string); ok {
            return permSlice
        }
    }
    return []string{}
}

// MustGetUserID gets user ID or panics (for cases where auth is required)
func MustGetUserID(c *fiber.Ctx) string {
    userID := GetUserID(c)
    if userID == "" {
        panic("user ID not found in context")
    }
    return userID
}
```

**Files to Update**:
- `pkg/middleware/rate_limiter.go`
- `pkg/middleware/logging.go`
- `pkg/handlers/auth.go`
- `pkg/handlers/device.go`
- `pkg/handlers/admin.go`

**Estimated Effort**: 3 hours
**Benefit**: Centralizes context extraction, eliminates 10+ duplicate functions

#### 2.2 Authorization Service Nil Check Decorator

**Problem**: Repeated `if a.enforcer == nil` checks in AuthorizationService
**Impact**: Medium - Appears in 10 methods

**Solution**: Use method decorator pattern or embed checks in base method

```go
// pkg/auth/authorization.go - Enhanced version
type AuthorizationService struct {
    enforcer casbin.IEnforcer
}

// ensureInitialized checks if enforcer is initialized
func (a *AuthorizationService) ensureInitialized() error {
    if a.enforcer == nil {
        return errors.Internal("Authorization service not initialized")
    }
    return nil
}

// Enforce checks if a user can perform an action on a resource
func (a *AuthorizationService) Enforce(user, resource, action string) (bool, error) {
    if err := a.ensureInitialized(); err != nil {
        return false, err
    }
    
    allowed, err := a.enforcer.Enforce(user, resource, action)
    if err != nil {
        return false, errors.Wrap(err, errors.CodeInternal, "Authorization check failed")
    }
    return allowed, nil
}

// Alternative: Use a method wrapper
func (a *AuthorizationService) withEnforcer(fn func() error) error {
    if err := a.ensureInitialized(); err != nil {
        return err
    }
    return fn()
}
```

**Files to Update**:
- `pkg/auth/authorization.go` (10 methods)

**Estimated Effort**: 2 hours
**Benefit**: Eliminates 10 duplicate nil checks

#### 2.3 Session Management Utilities

**Problem**: Complex session creation logic duplicated between login and password change
**Impact**: Medium - 40+ lines duplicated

**Solution**: Extract session management utilities

```go
// pkg/session/utils.go
package session

import (
    "github.com/gofiber/fiber/v2"
    "mvp.local/pkg/config"
    "mvp.local/pkg/observability"
)

type SessionCreator struct {
    sessionManager *SessionManager
    config         *config.Config
    obs            *observability.Observability
}

type SessionParams struct {
    UserID      string
    Email       string
    Username    string
    Roles       []string
    Permissions []string
    IPAddress   string
    UserAgent   string
    DeviceID    string
    Metadata    map[string]interface{}
}

func NewSessionCreator(sm *SessionManager, cfg *config.Config, obs *observability.Observability) *SessionCreator {
    return &SessionCreator{
        sessionManager: sm,
        config:         cfg,
        obs:            obs,
    }
}

func (sc *SessionCreator) CreateUserSession(c *fiber.Ctx, params SessionParams) error {
    if sc.sessionManager == nil {
        return nil // No error if session manager not available
    }
    
    sessionData := SessionData{
        UserID:      params.UserID,
        Email:       params.Email,
        Username:    params.Username,
        Roles:       params.Roles,
        Permissions: params.Permissions,
        IPAddress:   params.IPAddress,
        UserAgent:   params.UserAgent,
        DeviceID:    params.DeviceID,
        IsActive:    true,
        Metadata:    params.Metadata,
    }
    
    createdSession, err := sc.sessionManager.CreateSession(c.Context(), params.UserID, sessionData)
    if err != nil {
        sc.obs.Logger.Error().Err(err).Str("user_id", params.UserID).Msg("Failed to create session")
        return err // Don't fail the operation for session creation failure
    }
    
    // Set secure session cookie
    c.Cookie(&fiber.Cookie{
        Name:     "session_id",
        Value:    createdSession.SessionID,
        Expires:  createdSession.ExpiresAt,
        HTTPOnly: true,
        Secure:   sc.config.HTTP.TLS.Enabled,
        SameSite: "Strict",
        Path:     "/",
    })
    
    sc.obs.Logger.Info().
        Str("user_id", params.UserID).
        Str("session_id", createdSession.SessionID).
        Msg("Session created successfully")
        
    return nil
}
```

**Files to Update**:
- `pkg/handlers/auth.go` (Login and ChangePassword methods)

**Estimated Effort**: 4 hours
**Benefit**: Eliminates 40+ lines of duplicate session logic

### 🔷 **Phase 3: Low Priority (Week 5-6)**

#### 3.1 HTTP Status/Error Code Mapping

**Problem**: Mirrored logic in `getHTTPStatusCode` and `getErrorCodeFromStatus`
**Impact**: Low - Contained to one file but creates maintenance burden

**Solution**: Use bidirectional mapping structure

```go
// pkg/middleware/error_handler.go - Enhanced version
type StatusCodeMapping struct {
    ErrorCode  errors.Code
    HTTPStatus int
}

var statusCodeMappings = []StatusCodeMapping{
    {errors.CodeValidation, fiber.StatusBadRequest},
    {errors.CodeAuthentication, fiber.StatusUnauthorized},
    {errors.CodeUnauthorized, fiber.StatusUnauthorized},
    {errors.CodeAuthorization, fiber.StatusForbidden},
    {errors.CodeForbidden, fiber.StatusForbidden},
    {errors.CodeNotFound, fiber.StatusNotFound},
    {errors.CodeConflict, fiber.StatusConflict},
    {errors.CodeTimeout, fiber.StatusRequestTimeout},
    {errors.CodeUnavailable, fiber.StatusServiceUnavailable},
    {errors.CodeRateLimit, fiber.StatusTooManyRequests},
    {errors.CodeInternal, fiber.StatusInternalServerError},
}

var (
    errorToHTTPMap = make(map[errors.Code]int)
    httpToErrorMap = make(map[int]errors.Code)
)

func init() {
    for _, mapping := range statusCodeMappings {
        errorToHTTPMap[mapping.ErrorCode] = mapping.HTTPStatus
        httpToErrorMap[mapping.HTTPStatus] = mapping.ErrorCode
    }
}

func getHTTPStatusCode(code errors.Code) int {
    if status, exists := errorToHTTPMap[code]; exists {
        return status
    }
    return fiber.StatusInternalServerError
}

func getErrorCodeFromStatus(status int) errors.Code {
    if code, exists := httpToErrorMap[status]; exists {
        return code
    }
    return errors.CodeInternal
}
```

**Files to Update**:
- `pkg/middleware/error_handler.go`

**Estimated Effort**: 1 hour
**Benefit**: Single source of truth for status mappings

#### 3.2 JWT Token Generation Patterns

**Problem**: Similar claim structure patterns between access and refresh tokens
**Impact**: Low - Acceptable duplication for different token types

**Solution**: Extract common claim building utilities

```go
// pkg/auth/jwt_utils.go
package auth

import (
    "fmt"
    "time"
    "github.com/golang-jwt/jwt/v5"
)

// buildBaseRegisteredClaims creates common JWT registered claims
func (j *JWTService) buildBaseRegisteredClaims(subject string, expiresAt time.Time) jwt.RegisteredClaims {
    now := time.Now()
    return jwt.RegisteredClaims{
        Subject:   subject,
        Audience:  jwt.ClaimStrings{j.config.Audience},
        Issuer:    j.config.Issuer,
        IssuedAt:  jwt.NewNumericDate(now),
        ExpiresAt: jwt.NewNumericDate(expiresAt),
        NotBefore: jwt.NewNumericDate(now),
    }
}

// buildAccessTokenClaims creates claims for access tokens
func (j *JWTService) buildAccessTokenClaims(user *models.User, roles, permissions []string, deviceID string, trustLevel int, expiresAt time.Time) *JWTClaims {
    now := time.Now()
    baseClaims := j.buildBaseRegisteredClaims(user.ID.String(), expiresAt)
    baseClaims.ID = fmt.Sprintf("%s-%d", user.ID.String(), now.Unix())
    
    return &JWTClaims{
        UserID:           user.ID.String(),
        Username:         user.Username,
        Email:            user.Email,
        Roles:            roles,
        Permissions:      permissions,
        DeviceID:         deviceID,
        TrustLevel:       trustLevel,
        RegisteredClaims: baseClaims,
    }
}

// buildRefreshTokenClaims creates claims for refresh tokens
func (j *JWTService) buildRefreshTokenClaims(userID string, expiresAt time.Time) *jwt.RegisteredClaims {
    now := time.Now()
    baseClaims := j.buildBaseRegisteredClaims(userID, expiresAt)
    baseClaims.ID = fmt.Sprintf("refresh-%s-%d", userID, now.Unix())
    return &baseClaims
}
```

**Files to Update**:
- `pkg/auth/jwt.go`

**Estimated Effort**: 2 hours
**Benefit**: Reduces JWT claim building duplication

#### 3.3 Logging Request/Response Patterns

**Problem**: Similar structure for `logRequest` and `logResponse`
**Impact**: Low - Different enough to justify separate functions

**Solution**: Extract common logging utilities if beneficial

```go
// pkg/middleware/logging_utils.go
package middleware

// extractCommonLogData extracts data common to both request and response logs
func extractCommonLogData(c *fiber.Ctx) map[string]interface{} {
    return map[string]interface{}{
        "request_id": c.Get("X-Correlation-ID"),
        "user_id":    getUserIDFromContext(c),
        "tenant_id":  getTenantIDFromContext(c),
        "ip":         c.IP(),
        "user_agent": c.Get("User-Agent"),
    }
}
```

**Files to Update**:
- `pkg/middleware/logging.go`

**Estimated Effort**: 1 hour
**Benefit**: Minor - may not be worth the effort

## Implementation Strategy

### Week 1: Foundation
1. Create `pkg/handlers/common` package
2. Implement database error handling utilities
3. Implement URL parameter parsing utilities
4. Update 2-3 handler files as proof of concept

### Week 2: Core Services  
1. Create audit logging service
2. Update all handlers to use new audit service
3. Create context utilities package
4. Update middleware files

### Week 3: Authorization & Sessions
1. Refactor AuthorizationService nil checks
2. Create session management utilities
3. Update auth handlers

### Week 4: Testing & Validation
1. Comprehensive testing of refactored code
2. Performance testing to ensure no regression
3. Code review and documentation updates

### Week 5-6: Polish (Optional)
1. Implement low-priority refactoring
2. Additional cleanup and optimization
3. Update documentation

## Migration Strategy

### Backward Compatibility
- All refactoring will maintain existing API contracts
- No breaking changes to public interfaces
- Gradual migration with coexistence period

### Testing Strategy
- Unit tests for all new utility functions
- Integration tests to ensure no behavior changes
- Performance benchmarks for critical paths

### Rollback Plan
- Git feature branches for each phase
- Ability to revert individual changes
- Comprehensive test suite to catch regressions

## Expected Benefits

### Code Quality
- **Reduced duplication**: 200+ lines of duplicate code eliminated
- **Improved maintainability**: Single source of truth for common patterns
- **Better testability**: Centralized utilities easier to test

### Development Velocity
- **Faster feature development**: Reusable utilities
- **Reduced bugs**: Centralized error handling
- **Easier onboarding**: Clear patterns for new developers

### Technical Debt
- **Reduced technical debt**: Elimination of copy-paste code
- **Improved architecture**: Better separation of concerns
- **Enhanced reliability**: Consistent error handling

## Metrics for Success

### Quantitative
- Lines of code reduced by ~200+
- Number of duplicate patterns eliminated: 20+
- Test coverage maintained or improved
- No performance regression (< 5% impact)

### Qualitative  
- Improved code review feedback
- Faster feature implementation
- Reduced bug reports related to error handling
- Better developer satisfaction scores

## Risk Assessment

### Low Risk
- Database error handling (well-defined patterns)
- URL parameter parsing (simple logic)
- Context utilities (read-only operations)

### Medium Risk
- Audit logging service (complex async operations)
- Session management (security implications)

### Mitigation Strategies
- Extensive testing for medium-risk changes
- Gradual rollout with monitoring
- Feature flags for new utilities
- Comprehensive documentation

## Conclusion

This refactoring plan addresses significant code duplication while maintaining system stability. The phased approach allows for gradual improvement with minimal risk. The expected benefits in code quality, maintainability, and developer productivity justify the investment.

The plan prioritizes high-impact, low-risk improvements first, ensuring immediate value while building confidence for more complex refactoring in later phases.