# Zero Trust Authorization Policies
# Part of Framework Integration Plan - Week 3
# 
# This policy implements comprehensive Zero Trust authorization combining:
# - User identity from Keycloak (JWT claims)
# - Workload identity from SPIRE (SPIFFE IDs)
# - Trust levels (0-100 scale)
# - Time-based restrictions
# - Device verification requirements
# - Contextual access controls

package zero_trust.authz

import future.keywords.if
import future.keywords.in
import future.keywords.every

# =============================================================================
# MAIN AUTHORIZATION DECISION
# =============================================================================

# Main authorization decision - all conditions must be met
allow if {
    # Basic authorization checks
    user_authenticated
    action_permitted
    
    # Trust level requirements
    sufficient_trust_level
    
    # Time-based restrictions
    within_allowed_time
    
    # Device requirements
    device_requirements_met
    
    # Rate limiting
    not rate_limited
    
    # Additional security checks
    security_checks_passed
}

# Detailed authorization decision with reasons
authorization_decision := {
    "allow": allow,
    "reasons": denial_reasons,
    "trust_level": user_trust_level,
    "required_trust_level": required_trust_level_for_resource,
    "audit_required": audit_required,
    "additional_checks": additional_security_checks
}

# =============================================================================
# USER AUTHENTICATION
# =============================================================================

# Check if user is properly authenticated
user_authenticated if {
    # User has valid JWT token from Keycloak
    input.user.user_id
    input.user.email
    
    # Token is not expired
    now := time.now_ns()
    exp := input.user.expires_at * 1000000000  # Convert to nanoseconds
    now < exp
}

# Extract user trust level
user_trust_level := level if {
    level := input.user.trust_level
} else := 25  # Default to LOW trust if not specified

# =============================================================================
# ACTION PERMISSIONS
# =============================================================================

# Check if the requested action is permitted for the user's roles
action_permitted if {
    required_roles := role_requirements[input.resource][input.action]
    user_has_required_role(required_roles)
}

# Check if user has any of the required roles
user_has_required_role(required_roles) if {
    some role in required_roles
    role in input.user.roles
}

# Role-based access control matrix
role_requirements := {
    "profile": {
        "read": ["user", "manager", "admin"],
        "update": ["user", "manager", "admin"],
        "delete": ["admin"]
    },
    "users": {
        "list": ["manager", "admin"],
        "read": ["manager", "admin"],
        "create": ["admin"],
        "update": ["admin"],
        "delete": ["admin"]
    },
    "admin": {
        "read": ["admin"],
        "write": ["admin"],
        "delete": ["admin"]
    },
    "financial": {
        "view": ["admin", "finance", "manager"],
        "transact": ["admin", "finance"],
        "audit": ["admin", "audit"]
    },
    "reports": {
        "view": ["user", "manager", "admin"],
        "generate": ["manager", "admin"],
        "export": ["admin"]
    },
    "system": {
        "status": ["user", "manager", "admin"],
        "configure": ["admin"],
        "restart": ["admin"]
    }
}

# =============================================================================
# TRUST LEVEL REQUIREMENTS
# =============================================================================

# Check if user has sufficient trust level for the resource/action
sufficient_trust_level if {
    user_trust_level >= required_trust_level_for_resource
}

# Determine required trust level based on resource and action
required_trust_level_for_resource := level if {
    level := trust_level_requirements[input.resource][input.action]
} else := level if {
    level := trust_level_requirements[input.resource]["default"]
} else := 25  # Default minimum trust level

# Trust level requirements matrix
trust_level_requirements := {
    "profile": {
        "read": 25,      # LOW - basic authentication
        "update": 50,    # MEDIUM - verified session
        "delete": 75     # HIGH - MFA required
    },
    "users": {
        "list": 50,      # MEDIUM
        "read": 50,      # MEDIUM  
        "create": 75,    # HIGH
        "update": 75,    # HIGH
        "delete": 100    # FULL - hardware attestation
    },
    "admin": {
        "read": 75,      # HIGH
        "write": 100,    # FULL
        "delete": 100    # FULL
    },
    "financial": {
        "view": 75,      # HIGH
        "transact": 100, # FULL - requires hardware attestation
        "audit": 75      # HIGH
    },
    "reports": {
        "view": 25,      # LOW
        "generate": 50,  # MEDIUM
        "export": 75     # HIGH
    },
    "system": {
        "status": 25,    # LOW
        "configure": 100, # FULL
        "restart": 100   # FULL
    }
}

# =============================================================================
# TIME-BASED ACCESS CONTROL
# =============================================================================

# Check if access is within allowed time windows
within_allowed_time if {
    # Always allow for FULL trust level users
    user_trust_level >= 100
}

within_allowed_time if {
    # Business hours access (9 AM - 6 PM UTC)
    hour := time.clock(time.now_ns())[0]
    hour >= 9
    hour < 18
}

within_allowed_time if {
    # Extended hours for HIGH trust users (7 AM - 10 PM UTC)
    user_trust_level >= 75
    hour := time.clock(time.now_ns())[0]
    hour >= 7
    hour < 22
}

within_allowed_time if {
    # Emergency access patterns
    emergency_access_granted
}

# Emergency access for critical operations
emergency_access_granted if {
    input.context.emergency == true
    "admin" in input.user.roles
    user_trust_level >= 75
}

# =============================================================================
# DEVICE VERIFICATION REQUIREMENTS
# =============================================================================

# Check device verification requirements
device_requirements_met if {
    # No device verification required for LOW trust operations
    required_trust_level_for_resource < 50
}

device_requirements_met if {
    # Device verification required for MEDIUM+ trust operations
    required_trust_level_for_resource >= 50
    input.user.device_verified == true
    device_verification_recent
}

device_requirements_met if {
    # Hardware attestation required for FULL trust operations
    required_trust_level_for_resource >= 100
    input.workload.spiffe_id
    workload_hardware_verified
}

# Check if device verification is recent (within last 24 hours)
device_verification_recent if {
    last_verification := input.user.last_verification
    last_verification != ""
    
    # Parse RFC3339 timestamp and check if within 24 hours
    verification_time := time.parse_rfc3339_ns(last_verification)
    now := time.now_ns()
    age_hours := (now - verification_time) / 1000000000 / 3600
    age_hours <= 24
}

# Check if workload has hardware verification via SPIRE
workload_hardware_verified if {
    input.workload.hardware_verified == true
    input.workload.attestation_type in ["tpm", "aws_nitro", "gcp_shielded"]
}

# =============================================================================
# RATE LIMITING
# =============================================================================

# Simple rate limiting check (would integrate with external rate limiter)
rate_limited if {
    # Check if user has exceeded rate limits
    input.context.rate_limit_exceeded == true
}

rate_limited if {
    # Special rate limiting for sensitive operations
    input.action in ["transact", "delete", "restart"]
    sensitive_operation_rate_exceeded
}

sensitive_operation_rate_exceeded if {
    # This would integrate with Redis or external rate limiter
    # For now, we'll use a simple check
    input.context.sensitive_operations_count > 10
}

# =============================================================================
# ADDITIONAL SECURITY CHECKS
# =============================================================================

# Comprehensive security checks
security_checks_passed if {
    geo_location_allowed
    not suspicious_activity_detected
    workload_identity_verified
    session_integrity_valid
}

# Geographic location restrictions
geo_location_allowed if {
    # Always allow for FULL trust users
    user_trust_level >= 100
}

geo_location_allowed if {
    # Check allowed countries/regions
    input.context.country in allowed_countries
}

geo_location_allowed if {
    # VPN access with proper verification
    input.context.vpn_verified == true
    user_trust_level >= 50
}

# Allowed countries for access
allowed_countries := {
    "US", "CA", "GB", "DE", "FR", "JP", "AU", "NZ"
}

# Suspicious activity detection
suspicious_activity_detected if {
    # Multiple failed attempts
    input.context.failed_attempts > 5
}

suspicious_activity_detected if {
    # Unusual access patterns
    input.context.unusual_access_pattern == true
}

suspicious_activity_detected if {
    # Known malicious IP ranges
    ip_in_blacklist(input.context.ip_address)
}

# Workload identity verification via SPIRE
workload_identity_verified if {
    # No workload verification required for user-only operations
    not input.workload.spiffe_id
}

workload_identity_verified if {
    # Workload has valid SPIFFE ID
    input.workload.spiffe_id
    spiffe_id_valid(input.workload.spiffe_id)
    workload_trust_sufficient
}

# Session integrity checks
session_integrity_valid if {
    # Session fingerprint matches
    input.context.session_fingerprint == input.user.session_fingerprint
}

session_integrity_valid if {
    # No session fingerprint provided (backward compatibility)
    not input.context.session_fingerprint
    not input.user.session_fingerprint
}

# =============================================================================
# SPIFFE/SPIRE INTEGRATION
# =============================================================================

# Validate SPIFFE ID format and trust domain
spiffe_id_valid(spiffe_id) if {
    startswith(spiffe_id, "spiffe://zero-trust.dev/")
    not contains(spiffe_id, "..")  # Prevent path traversal
    not contains(spiffe_id, "//")  # Prevent double slashes
}

# Check if workload trust level is sufficient
workload_trust_sufficient if {
    input.workload.trust_level >= workload_required_trust_level
}

# Determine required trust level for workload based on SPIFFE ID
workload_required_trust_level := level if {
    spiffe_id := input.workload.spiffe_id
    some pattern, requirements in workload_trust_requirements
    regex.match(pattern, spiffe_id)
    level := requirements.min_trust_level
} else := 25  # Default workload trust level

# Workload trust requirements by SPIFFE ID pattern
workload_trust_requirements := {
    "^spiffe://zero-trust.dev/admin/.*": {
        "min_trust_level": 100,
        "required_attestors": ["k8s_sat", "tpm"]
    },
    "^spiffe://zero-trust.dev/api/.*": {
        "min_trust_level": 75,
        "required_attestors": ["k8s_sat"]
    },
    "^spiffe://zero-trust.dev/worker/.*": {
        "min_trust_level": 50,
        "required_attestors": ["k8s_sat", "docker"]
    },
    "^spiffe://zero-trust.dev/public/.*": {
        "min_trust_level": 25,
        "required_attestors": ["k8s_sat"]
    }
}

# =============================================================================
# AUDIT AND COMPLIANCE
# =============================================================================

# Determine if this operation requires audit logging
audit_required if {
    # Always audit HIGH and FULL trust operations
    user_trust_level >= 75
}

audit_required if {
    # Always audit sensitive resources
    input.resource in sensitive_resources
}

audit_required if {
    # Always audit administrative actions
    input.action in administrative_actions
}

audit_required if {
    # Always audit financial transactions
    input.resource == "financial"
    input.action in ["transact", "audit"]
}

# Resources that always require audit logging
sensitive_resources := {
    "admin", "users", "financial", "system"
}

# Actions that always require audit logging
administrative_actions := {
    "create", "update", "delete", "configure", "restart"
}

# Additional security checks summary
additional_security_checks := {
    "geo_location_check": geo_location_allowed,
    "suspicious_activity_check": not suspicious_activity_detected,
    "workload_identity_check": workload_identity_verified,
    "session_integrity_check": session_integrity_valid,
    "rate_limit_check": not rate_limited,
    "time_restriction_check": within_allowed_time,
    "device_verification_check": device_requirements_met
}

# =============================================================================
# DENIAL REASONS
# =============================================================================

# Collect all denial reasons for debugging and user feedback
denial_reasons := reasons if {
    reasons := [reason |
        deny_rule[reason]
    ]
    count(reasons) > 0
} else := []

# Individual denial rules with specific reasons
deny_rule["user_not_authenticated"] if {
    not user_authenticated
}

deny_rule["action_not_permitted"] if {
    not action_permitted
}

deny_rule["insufficient_trust_level"] if {
    user_trust_level < required_trust_level_for_resource
}

deny_rule["outside_allowed_time"] if {
    not within_allowed_time
}

deny_rule["device_verification_required"] if {
    not device_requirements_met
}

deny_rule["rate_limit_exceeded"] if {
    rate_limited
}

deny_rule["geo_location_restricted"] if {
    not geo_location_allowed
}

deny_rule["suspicious_activity_detected"] if {
    suspicious_activity_detected
}

deny_rule["workload_identity_invalid"] if {
    not workload_identity_verified
}

deny_rule["session_integrity_failed"] if {
    not session_integrity_valid
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Check if IP address is in blacklist (simplified)
ip_in_blacklist(ip) if {
    ip in blacklisted_ips
}

ip_in_blacklist(ip) if {
    some cidr in blacklisted_cidrs
    net.cidr_contains(cidr, ip)
}

# Blacklisted IP addresses
blacklisted_ips := {
    "192.168.1.100",  # Example malicious IP
    "10.0.0.50"       # Example blocked IP
}

# Blacklisted CIDR ranges
blacklisted_cidrs := {
    "192.168.100.0/24",  # Example blocked subnet
    "10.10.0.0/16"       # Example restricted range
}

# Trust level name mapping for human-readable output
trust_level_name(level) := name if {
    level >= 100
    name := "FULL"
} else := name if {
    level >= 75
    name := "HIGH"
} else := name if {
    level >= 50
    name := "MEDIUM"
} else := name if {
    level >= 25
    name := "LOW"
} else := "NONE"