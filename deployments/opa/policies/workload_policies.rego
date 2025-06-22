# Workload-Specific Authorization Policies
# Part of Framework Integration Plan - Week 3
#
# This policy module handles authorization decisions specifically for 
# service-to-service communication using SPIRE/SPIFFE workload identities

package zero_trust.workload

import future.keywords.if
import future.keywords.in

# =============================================================================
# WORKLOAD-TO-WORKLOAD AUTHORIZATION
# =============================================================================

# Allow workload-to-workload communication
allow if {
    # Source workload is properly attested
    source_workload_valid
    
    # Target workload accepts the communication
    target_workload_accessible
    
    # Communication pattern is allowed
    communication_pattern_allowed
    
    # Trust levels are compatible
    trust_levels_compatible
    
    # Time-based restrictions for workload communication
    workload_time_restrictions_met
}

# Detailed workload authorization decision
workload_authorization := {
    "allow": allow,
    "source_workload": input.source.spiffe_id,
    "target_workload": input.target.spiffe_id,
    "trust_compatibility": trust_compatibility_check,
    "communication_type": communication_type,
    "restrictions": active_restrictions
}

# =============================================================================
# SOURCE WORKLOAD VALIDATION
# =============================================================================

# Validate source workload identity
source_workload_valid if {
    # Valid SPIFFE ID format
    input.source.spiffe_id
    spiffe_id_valid(input.source.spiffe_id)
    
    # Workload is properly attested
    input.source.attested == true
    
    # Certificate is not expired
    not certificate_expired(input.source.cert_expiry)
    
    # Workload trust level meets minimum requirements
    input.source.trust_level >= minimum_source_trust_level
}

# Minimum trust level for source workloads
minimum_source_trust_level := 25

# =============================================================================
# TARGET WORKLOAD ACCESSIBILITY
# =============================================================================

# Check if target workload accepts the communication
target_workload_accessible if {
    # Target workload exists and is attested
    input.target.spiffe_id
    input.target.attested == true
    
    # Source is in target's allowlist
    source_in_target_allowlist
    
    # No explicit denial rules
    not source_explicitly_denied
}

# Check if source is in target's communication allowlist
source_in_target_allowlist if {
    source_spiffe_id := input.source.spiffe_id
    target_spiffe_id := input.target.spiffe_id
    
    # Get allowed communication patterns for target
    allowed_patterns := workload_communication_matrix[target_spiffe_id]
    
    # Check if source matches any allowed pattern
    some pattern in allowed_patterns
    regex.match(pattern, source_spiffe_id)
}

# Check for explicit denial rules
source_explicitly_denied if {
    source_spiffe_id := input.source.spiffe_id
    target_spiffe_id := input.target.spiffe_id
    
    # Check deny list
    denied_patterns := workload_deny_matrix[target_spiffe_id]
    
    some pattern in denied_patterns
    regex.match(pattern, source_spiffe_id)
}

# =============================================================================
# COMMUNICATION PATTERNS
# =============================================================================

# Determine communication type
communication_type := "service_mesh" if {
    input.context.protocol == "grpc"
    input.context.envoy_proxy == true
} else := "direct_api" if {
    input.context.protocol in ["http", "https"]
} else := "database" if {
    input.context.protocol in ["postgres", "mysql", "redis"]
} else := "messaging" if {
    input.context.protocol in ["amqp", "kafka", "nats"]
} else := "unknown"

# Check if communication pattern is allowed
communication_pattern_allowed if {
    # Get allowed patterns for this communication type
    allowed := communication_patterns[communication_type]
    
    # Check if current communication matches allowed patterns
    current_pattern := sprintf("%s->%s", [
        extract_service_name(input.source.spiffe_id),
        extract_service_name(input.target.spiffe_id)
    ])
    
    some pattern in allowed
    regex.match(pattern, current_pattern)
}

# Extract service name from SPIFFE ID
extract_service_name(spiffe_id) := name if {
    # Extract service name from path
    parts := split(spiffe_id, "/")
    count(parts) >= 4  # spiffe://domain/service/name
    name := parts[3]
} else := "unknown"

# =============================================================================
# TRUST LEVEL COMPATIBILITY
# =============================================================================

# Check if trust levels are compatible between workloads
trust_levels_compatible if {
    source_trust := input.source.trust_level
    target_trust := input.target.trust_level
    
    # Source must have at least minimum trust for target communication
    source_trust >= minimum_trust_for_target(input.target.spiffe_id)
    
    # Trust differential should not be too high (security concern)
    trust_differential := abs(source_trust - target_trust)
    trust_differential <= max_trust_differential
}

# Maximum allowed trust level differential
max_trust_differential := 50

# Determine minimum trust level required to communicate with target
minimum_trust_for_target(target_spiffe_id) := min_trust if {
    # Extract target service type from SPIFFE ID
    target_service := extract_service_name(target_spiffe_id)
    min_trust := target_trust_requirements[target_service]
} else := 25  # Default minimum trust

# Trust requirements for different target services
target_trust_requirements := {
    "admin": 100,      # Admin services require FULL trust
    "financial": 75,   # Financial services require HIGH trust
    "api": 50,         # API services require MEDIUM trust
    "worker": 25,      # Worker services require LOW trust
    "public": 25       # Public services require LOW trust
}

# Trust compatibility check details
trust_compatibility_check := {
    "source_trust": input.source.trust_level,
    "target_trust": input.target.trust_level,
    "required_minimum": minimum_trust_for_target(input.target.spiffe_id),
    "trust_differential": abs(input.source.trust_level - input.target.trust_level),
    "max_allowed_differential": max_trust_differential,
    "compatible": trust_levels_compatible
}

# =============================================================================
# TIME-BASED WORKLOAD RESTRICTIONS
# =============================================================================

# Check time-based restrictions for workload communication
workload_time_restrictions_met if {
    # No time restrictions for HIGH+ trust workloads
    input.source.trust_level >= 75
    input.target.trust_level >= 75
}

workload_time_restrictions_met if {
    # Business hours for MEDIUM trust workloads
    input.source.trust_level >= 50
    within_business_hours
}

workload_time_restrictions_met if {
    # Extended hours for specific service patterns
    extended_hours_allowed
}

# Business hours check (9 AM - 6 PM UTC)
within_business_hours if {
    hour := time.clock(time.now_ns())[0]
    hour >= 9
    hour < 18
}

# Extended hours for critical services
extended_hours_allowed if {
    source_service := extract_service_name(input.source.spiffe_id)
    target_service := extract_service_name(input.target.spiffe_id)
    
    # Critical service communications allowed 24/7
    source_service in critical_services
    target_service in critical_services
}

critical_services := {
    "health-check", "monitoring", "logging", "alerting"
}

# =============================================================================
# WORKLOAD COMMUNICATION MATRIX
# =============================================================================

# Define allowed communication patterns per workload
workload_communication_matrix := {
    "spiffe://zero-trust.dev/admin/controller": [
        "^spiffe://zero-trust.dev/.*"  # Admin can communicate with all
    ],
    "spiffe://zero-trust.dev/api/auth-service": [
        "^spiffe://zero-trust.dev/api/user-service$",
        "^spiffe://zero-trust.dev/worker/.*",
        "^spiffe://zero-trust.dev/public/.*"
    ],
    "spiffe://zero-trust.dev/api/user-service": [
        "^spiffe://zero-trust.dev/worker/.*",
        "^spiffe://zero-trust.dev/public/health-check$"
    ],
    "spiffe://zero-trust.dev/worker/job-processor": [
        "^spiffe://zero-trust.dev/api/.*",
        "^spiffe://zero-trust.dev/worker/.*",
        "^spiffe://zero-trust.dev/public/health-check$"
    ],
    "spiffe://zero-trust.dev/public/health-check": [
        # Health check can only communicate with monitoring
        "^spiffe://zero-trust.dev/public/monitoring$"
    ]
}

# Define explicit deny patterns per workload
workload_deny_matrix := {
    "spiffe://zero-trust.dev/public/health-check": [
        "^spiffe://zero-trust.dev/admin/.*",      # No admin access
        "^spiffe://zero-trust.dev/financial/.*"   # No financial access
    ],
    "spiffe://zero-trust.dev/worker/job-processor": [
        "^spiffe://zero-trust.dev/admin/.*"       # Workers can't access admin
    ]
}

# Define allowed communication patterns by type
communication_patterns := {
    "service_mesh": [
        "api->worker",
        "api->api", 
        "worker->worker",
        "worker->public",
        "admin->.*"
    ],
    "direct_api": [
        "worker->api",
        "public->api",
        "admin->.*"
    ],
    "database": [
        "api->database",
        "worker->database",
        "admin->database"
    ],
    "messaging": [
        "worker->messaging",
        "api->messaging",
        "admin->messaging"
    ]
}

# =============================================================================
# ACTIVE RESTRICTIONS
# =============================================================================

# Collect all active restrictions for this communication
active_restrictions := restrictions if {
    restrictions := [restriction |
        restriction_rule[restriction]
    ]
} else := []

# Individual restriction rules
restriction_rule["time_based"] if {
    not workload_time_restrictions_met
}

restriction_rule["trust_level_insufficient"] if {
    not trust_levels_compatible
}

restriction_rule["communication_pattern_denied"] if {
    not communication_pattern_allowed
}

restriction_rule["source_not_in_allowlist"] if {
    not source_in_target_allowlist
}

restriction_rule["source_explicitly_denied"] if {
    source_explicitly_denied
}

restriction_rule["certificate_expired"] if {
    certificate_expired(input.source.cert_expiry)
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Validate SPIFFE ID format
spiffe_id_valid(spiffe_id) if {
    startswith(spiffe_id, "spiffe://zero-trust.dev/")
    not contains(spiffe_id, "..")
    not contains(spiffe_id, "//")
    count(split(spiffe_id, "/")) >= 4
}

# Check if certificate is expired
certificate_expired(cert_expiry) if {
    expiry_time := time.parse_rfc3339_ns(cert_expiry)
    current_time := time.now_ns()
    current_time >= expiry_time
}

# Absolute value function
abs(x) := x if x >= 0
abs(x) := -x if x < 0