// Package common provides shared path matching utilities
package common

import (
	"path/filepath"
	"strings"
)

// PathMatcher provides path matching utilities for middleware implementations
type PathMatcher struct {
	skipPaths []string
	compiled  []pathPattern
}

// pathPattern represents a compiled path pattern for efficient matching
type pathPattern struct {
	pattern    string
	isWildcard bool
	prefix     string
}

// NewPathMatcher creates a new path matcher with skip paths
func NewPathMatcher(skipPaths []string) *PathMatcher {
	pm := &PathMatcher{
		skipPaths: skipPaths,
		compiled:  make([]pathPattern, 0, len(skipPaths)),
	}
	
	// Compile patterns for efficiency
	for _, pattern := range skipPaths {
		pm.compiled = append(pm.compiled, pm.compilePattern(pattern))
	}
	
	return pm
}

// ShouldSkip checks if the given path should be skipped from authentication
func (pm *PathMatcher) ShouldSkip(path string) bool {
	if path == "" {
		return false
	}
	
	// Clean the path to handle edge cases
	cleanPath := filepath.Clean(path)
	
	// Check against compiled patterns
	for _, pattern := range pm.compiled {
		if pm.matchPattern(cleanPath, pattern) {
			return true
		}
	}
	
	return false
}

// AddSkipPath adds a new path to skip list
func (pm *PathMatcher) AddSkipPath(path string) {
	if path == "" {
		return
	}
	
	pm.skipPaths = append(pm.skipPaths, path)
	pm.compiled = append(pm.compiled, pm.compilePattern(path))
}

// RemoveSkipPath removes a path from skip list
func (pm *PathMatcher) RemoveSkipPath(path string) {
	if path == "" {
		return
	}
	
	newSkipPaths := make([]string, 0, len(pm.skipPaths))
	newCompiled := make([]pathPattern, 0, len(pm.compiled))
	
	for i, skipPath := range pm.skipPaths {
		if skipPath != path {
			newSkipPaths = append(newSkipPaths, skipPath)
			newCompiled = append(newCompiled, pm.compiled[i])
		}
	}
	
	pm.skipPaths = newSkipPaths
	pm.compiled = newCompiled
}

// GetSkipPaths returns the current skip paths
func (pm *PathMatcher) GetSkipPaths() []string {
	result := make([]string, len(pm.skipPaths))
	copy(result, pm.skipPaths)
	return result
}

// compilePattern compiles a path pattern for efficient matching
func (pm *PathMatcher) compilePattern(pattern string) pathPattern {
	if pattern == "" {
		return pathPattern{pattern: pattern}
	}
	
	// Handle wildcard patterns
	if strings.Contains(pattern, "*") {
		return pathPattern{
			pattern:    pattern,
			isWildcard: true,
		}
	}
	
	// Handle prefix patterns (ending with /)
	if strings.HasSuffix(pattern, "/") {
		return pathPattern{
			pattern: pattern,
			prefix:  pattern,
		}
	}
	
	// Exact match pattern
	return pathPattern{
		pattern: pattern,
	}
}

// matchPattern checks if path matches the compiled pattern
func (pm *PathMatcher) matchPattern(path string, pattern pathPattern) bool {
	// Handle wildcard patterns
	if pattern.isWildcard {
		matched, err := filepath.Match(pattern.pattern, path)
		if err != nil {
			// Fallback to simple string matching if filepath.Match fails
			return pm.simpleWildcardMatch(path, pattern.pattern)
		}
		return matched
	}
	
	// Handle prefix patterns
	if pattern.prefix != "" {
		return strings.HasPrefix(path, pattern.prefix)
	}
	
	// Exact match
	return path == pattern.pattern
}

// simpleWildcardMatch provides basic wildcard matching as fallback
func (pm *PathMatcher) simpleWildcardMatch(path, pattern string) bool {
	// Handle simple cases
	if pattern == "*" {
		return true
	}
	
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		// Pattern like "*api*"
		middle := pattern[1 : len(pattern)-1]
		return strings.Contains(path, middle)
	}
	
	if strings.HasPrefix(pattern, "*") {
		// Pattern like "*.html"
		suffix := pattern[1:]
		return strings.HasSuffix(path, suffix)
	}
	
	if strings.HasSuffix(pattern, "*") {
		// Pattern like "/api/*"
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(path, prefix)
	}
	
	// No wildcards, exact match
	return path == pattern
}

// StandardSkipPaths returns commonly used paths to skip authentication
func StandardSkipPaths() []string {
	return []string{
		"/health",
		"/healthz",
		"/ready",
		"/readiness",
		"/liveness",
		"/metrics",
		"/ping",
		"/status",
		"/favicon.ico",
		"/robots.txt",
		"/sitemap.xml",
		"/login",
		"/logout",
		"/register",
		"/forgot-password",
		"/reset-password",
		"/public/*",
		"/assets/*",
		"/static/*",
		"/css/*",
		"/js/*",
		"/images/*",
		"/img/*",
		"/fonts/*",
		"/.well-known/*",
	}
}

// APISkipPaths returns common API paths to skip authentication
func APISkipPaths() []string {
	return []string{
		"/api/health",
		"/api/v1/health",
		"/api/v2/health",
		"/api/ping",
		"/api/status",
		"/api/login",
		"/api/logout",
		"/api/register",
		"/api/auth/login",
		"/api/auth/logout",
		"/api/auth/register",
		"/api/auth/refresh",
		"/api/public/*",
		"/api/docs/*",
		"/api/swagger/*",
		"/swagger/*",
		"/docs/*",
	}
}

// AdminSkipPaths returns admin-specific paths that might need special handling
func AdminSkipPaths() []string {
	return []string{
		"/admin/health",
		"/admin/metrics",
		"/admin/debug/*",
		"/admin/pprof/*",
	}
}

// DefaultSkipPaths returns a comprehensive list of default skip paths
func DefaultSkipPaths() []string {
	paths := StandardSkipPaths()
	paths = append(paths, APISkipPaths()...)
	return paths
}

// SecuritySkipPaths returns security-related paths that should be carefully considered
func SecuritySkipPaths() []string {
	return []string{
		"/security/csp-report",
		"/security/cors-preflight",
		"/.well-known/security.txt",
		"/.well-known/openid_configuration",
		"/.well-known/jwks.json",
	}
}

// PathMatcherBuilder provides a builder pattern for creating path matchers
type PathMatcherBuilder struct {
	skipPaths []string
}

// NewPathMatcherBuilder creates a new path matcher builder
func NewPathMatcherBuilder() *PathMatcherBuilder {
	return &PathMatcherBuilder{
		skipPaths: make([]string, 0),
	}
}

// WithStandardPaths adds standard skip paths
func (pmb *PathMatcherBuilder) WithStandardPaths() *PathMatcherBuilder {
	pmb.skipPaths = append(pmb.skipPaths, StandardSkipPaths()...)
	return pmb
}

// WithAPIPaths adds API skip paths
func (pmb *PathMatcherBuilder) WithAPIPaths() *PathMatcherBuilder {
	pmb.skipPaths = append(pmb.skipPaths, APISkipPaths()...)
	return pmb
}

// WithAdminPaths adds admin skip paths
func (pmb *PathMatcherBuilder) WithAdminPaths() *PathMatcherBuilder {
	pmb.skipPaths = append(pmb.skipPaths, AdminSkipPaths()...)
	return pmb
}

// WithSecurityPaths adds security-related skip paths
func (pmb *PathMatcherBuilder) WithSecurityPaths() *PathMatcherBuilder {
	pmb.skipPaths = append(pmb.skipPaths, SecuritySkipPaths()...)
	return pmb
}

// WithCustomPaths adds custom skip paths
func (pmb *PathMatcherBuilder) WithCustomPaths(paths []string) *PathMatcherBuilder {
	pmb.skipPaths = append(pmb.skipPaths, paths...)
	return pmb
}

// WithPath adds a single custom skip path
func (pmb *PathMatcherBuilder) WithPath(path string) *PathMatcherBuilder {
	if path != "" {
		pmb.skipPaths = append(pmb.skipPaths, path)
	}
	return pmb
}

// Build creates the path matcher
func (pmb *PathMatcherBuilder) Build() *PathMatcher {
	return NewPathMatcher(pmb.skipPaths)
}