# Data Classification and Protection Policies
# Part of Framework Integration Plan - Week 3
#
# This policy module implements data classification-based access controls
# ensuring that users and workloads can only access data appropriate for their trust level

package zero_trust.data

import future.keywords.if
import future.keywords.in

# =============================================================================
# DATA ACCESS AUTHORIZATION
# =============================================================================

# Main data access decision
allow if {
    # User/workload authentication verified
    principal_authenticated
    
    # Data classification level is appropriate for principal trust level
    data_access_authorized
    
    # Purpose limitation compliance (GDPR)
    purpose_limitation_met
    
    # Data minimization principle
    data_minimization_complied
    
    # Retention policies respected
    retention_policy_complied
}

# Detailed data access decision
data_access_decision := {
    "allow": allow,
    "data_classification": data_classification_level,
    "required_trust_level": required_trust_for_data,
    "principal_trust_level": principal_trust_level,
    "access_purpose": input.purpose,
    "data_minimization": data_minimization_check,
    "retention_compliance": retention_compliance_check,
    "audit_required": data_audit_required
}

# =============================================================================
# PRINCIPAL AUTHENTICATION
# =============================================================================

# Check if principal (user or workload) is authenticated
principal_authenticated if {
    # User authentication via Keycloak
    input.user.user_id
    input.user.trust_level
}

principal_authenticated if {
    # Workload authentication via SPIRE
    input.workload.spiffe_id
    input.workload.trust_level
    input.workload.attested == true
}

# Get principal trust level
principal_trust_level := level if {
    # User trust level
    input.user.trust_level
    level := input.user.trust_level
} else := level if {
    # Workload trust level
    input.workload.trust_level
    level := input.workload.trust_level
} else := 0

# =============================================================================
# DATA CLASSIFICATION
# =============================================================================

# Determine data classification level based on data attributes
data_classification_level := classification if {
    # Check for explicit classification
    input.data.classification
    classification := input.data.classification
} else := classification if {
    # Classify based on data type and content
    classification := classify_data_by_type(input.data.type)
} else := "unclassified"

# Classify data based on type and sensitivity
classify_data_by_type(data_type) := "top_secret" if {
    data_type in top_secret_data_types
} else := "secret" if {
    data_type in secret_data_types
} else := "confidential" if {
    data_type in confidential_data_types
} else := "internal" if {
    data_type in internal_data_types
} else := "public"

# Data type classification mappings
top_secret_data_types := {
    "encryption_keys", "root_passwords", "financial_records", 
    "personal_health_information", "government_classified"
}

secret_data_types := {
    "user_passwords", "api_keys", "database_credentials",
    "financial_transactions", "audit_logs", "security_events"
}

confidential_data_types := {
    "user_profiles", "business_data", "internal_communications",
    "performance_metrics", "access_logs"
}

internal_data_types := {
    "user_preferences", "application_logs", "system_status",
    "non_sensitive_metrics"
}

# =============================================================================
# DATA ACCESS AUTHORIZATION
# =============================================================================

# Check if data access is authorized based on classification and trust level
data_access_authorized if {
    principal_trust_level >= required_trust_for_data
    data_handling_capabilities_sufficient
}

# Determine required trust level for data classification
required_trust_for_data := trust_level if {
    classification := data_classification_level
    trust_level := classification_trust_requirements[classification]
} else := 100  # Default to maximum trust for unknown classifications

# Trust level requirements for data classifications
classification_trust_requirements := {
    "top_secret": 100,    # FULL trust - hardware attestation required
    "secret": 75,         # HIGH trust - MFA and device verification
    "confidential": 50,   # MEDIUM trust - verified session
    "internal": 25,       # LOW trust - basic authentication
    "public": 0,          # No trust requirement
    "unclassified": 25    # Default to LOW trust
}

# Check if principal has sufficient data handling capabilities
data_handling_capabilities_sufficient if {
    classification := data_classification_level
    required_capabilities := data_handling_requirements[classification]
    
    # Check each required capability
    every capability in required_capabilities {
        principal_has_capability(capability)
    }
}

# Data handling capability requirements
data_handling_requirements := {
    "top_secret": [
        "hardware_security_module",
        "encrypted_storage",
        "audit_logging",
        "data_loss_prevention",
        "secure_communication"
    ],
    "secret": [
        "encrypted_storage",
        "audit_logging", 
        "secure_communication"
    ],
    "confidential": [
        "audit_logging",
        "secure_communication"
    ],
    "internal": [
        "audit_logging"
    ],
    "public": []
}

# Check if principal has specific capability
principal_has_capability(capability) if {
    # User capabilities based on trust level and attributes
    input.user.user_id
    user_capability_check(capability)
}

principal_has_capability(capability) if {
    # Workload capabilities based on attestation and configuration
    input.workload.spiffe_id
    workload_capability_check(capability)
}

# User capability verification
user_capability_check("hardware_security_module") if {
    input.user.trust_level >= 100
    input.user.device_verified == true
}

user_capability_check("encrypted_storage") if {
    input.user.trust_level >= 50
}

user_capability_check("audit_logging") if {
    input.user.trust_level >= 25
}

user_capability_check("data_loss_prevention") if {
    input.user.trust_level >= 75
    "admin" in input.user.roles
}

user_capability_check("secure_communication") if {
    input.user.trust_level >= 25
}

# Workload capability verification
workload_capability_check("hardware_security_module") if {
    input.workload.hardware_verified == true
    input.workload.trust_level >= 100
}

workload_capability_check("encrypted_storage") if {
    input.workload.encryption_enabled == true
}

workload_capability_check("audit_logging") if {
    input.workload.audit_enabled == true
}

workload_capability_check("data_loss_prevention") if {
    input.workload.dlp_enabled == true
}

workload_capability_check("secure_communication") if {
    input.workload.tls_enabled == true
}

# =============================================================================
# PURPOSE LIMITATION (GDPR COMPLIANCE)
# =============================================================================

# Check if data access purpose is legitimate and documented
purpose_limitation_met if {
    # Purpose is explicitly stated
    input.purpose
    
    # Purpose is in allowed purposes for this data type
    purpose_allowed_for_data_type
    
    # Purpose matches user's role and permissions
    purpose_matches_user_role
}

# Check if purpose is allowed for this data type
purpose_allowed_for_data_type if {
    data_type := input.data.type
    purpose := input.purpose
    
    allowed_purposes := data_type_purposes[data_type]
    purpose in allowed_purposes
}

# Check if purpose matches user's role
purpose_matches_user_role if {
    purpose := input.purpose
    user_roles := input.user.roles
    
    # Get allowed roles for this purpose
    allowed_roles := purpose_role_mapping[purpose]
    
    # Check if user has any allowed role
    some role in user_roles
    role in allowed_roles
}

# Allowed purposes for different data types
data_type_purposes := {
    "user_profiles": [
        "authentication", "personalization", "support", "analytics"
    ],
    "financial_transactions": [
        "payment_processing", "fraud_detection", "accounting", "audit"
    ],
    "personal_health_information": [
        "medical_treatment", "insurance_claims", "research", "emergency_care"
    ],
    "user_preferences": [
        "personalization", "service_improvement", "analytics"
    ],
    "system_logs": [
        "troubleshooting", "security_monitoring", "performance_optimization"
    ]
}

# Role mapping for different purposes
purpose_role_mapping := {
    "authentication": ["user", "admin", "system"],
    "personalization": ["user", "service"],
    "support": ["support", "admin"],
    "analytics": ["analyst", "admin"],
    "payment_processing": ["finance", "admin"],
    "fraud_detection": ["security", "admin"],
    "audit": ["auditor", "admin"],
    "troubleshooting": ["support", "admin", "engineer"],
    "security_monitoring": ["security", "admin"]
}

# =============================================================================
# DATA MINIMIZATION
# =============================================================================

# Check if data access follows data minimization principle
data_minimization_complied if {
    # Only requested fields are being accessed
    requested_fields_justified
    
    # No excessive data being retrieved
    not excessive_data_requested
    
    # Purpose justifies the scope of data
    scope_matches_purpose
}

# Data minimization check details
data_minimization_check := {
    "requested_fields": input.data.fields,
    "justified_fields": justified_fields_for_purpose,
    "excessive_fields": excessive_fields,
    "compliant": data_minimization_complied
}

# Check if requested fields are justified for the purpose
requested_fields_justified if {
    purpose := input.purpose
    requested := input.data.fields
    justified := justified_fields_for_purpose
    
    # All requested fields must be in justified set
    every field in requested {
        field in justified
    }
}

# Get justified fields for the current purpose
justified_fields_for_purpose := fields if {
    purpose := input.purpose
    data_type := input.data.type
    
    # Get purpose-specific field requirements
    purpose_fields := purpose_data_requirements[purpose]
    type_fields := purpose_fields[data_type]
    fields := type_fields
} else := []

# Identify excessive fields being requested
excessive_fields := [field | 
    field := input.data.fields[_]
    not field in justified_fields_for_purpose
]

# Check if there are excessive data requests
excessive_data_requested if {
    count(excessive_fields) > 0
}

# Check if scope matches purpose
scope_matches_purpose if {
    purpose := input.purpose
    scope := input.data.scope
    
    allowed_scopes := purpose_scope_requirements[purpose]
    scope in allowed_scopes
}

# Purpose-specific data field requirements
purpose_data_requirements := {
    "authentication": {
        "user_profiles": ["user_id", "email", "password_hash", "roles"],
        "sessions": ["session_id", "user_id", "expires_at"]
    },
    "personalization": {
        "user_profiles": ["user_id", "preferences", "language", "timezone"],
        "user_preferences": ["preference_key", "preference_value"]
    },
    "support": {
        "user_profiles": ["user_id", "email", "name", "account_status"],
        "support_tickets": ["ticket_id", "user_id", "issue_description", "status"]
    },
    "analytics": {
        "user_profiles": ["user_id", "registration_date", "last_login"],
        "usage_metrics": ["metric_name", "metric_value", "timestamp"]
    }
}

# Purpose-specific scope requirements
purpose_scope_requirements := {
    "authentication": ["single_user", "session_specific"],
    "personalization": ["single_user"],
    "support": ["single_user", "limited_user_set"],
    "analytics": ["aggregated", "anonymized"],
    "audit": ["full_dataset", "filtered_dataset"]
}

# =============================================================================
# RETENTION POLICY COMPLIANCE
# =============================================================================

# Check if data access complies with retention policies
retention_policy_complied if {
    # Data is within retention period
    within_retention_period
    
    # Legal hold requirements met
    legal_hold_requirements_met
    
    # Deletion schedule appropriate
    deletion_schedule_appropriate
}

# Retention compliance check details
retention_compliance_check := {
    "data_age_days": data_age_days,
    "retention_period_days": retention_period_days,
    "within_retention": within_retention_period,
    "legal_hold": legal_hold_active,
    "deletion_scheduled": deletion_scheduled
}

# Check if data is within retention period
within_retention_period if {
    data_age_days <= retention_period_days
}

# Calculate data age in days
data_age_days := age if {
    created_at := input.data.created_at
    created_time := time.parse_rfc3339_ns(created_at)
    current_time := time.now_ns()
    age_ns := current_time - created_time
    age := age_ns / (24 * 60 * 60 * 1000000000)  # Convert to days
}

# Get retention period for data type
retention_period_days := period if {
    data_type := input.data.type
    period := data_retention_periods[data_type]
} else := 2555  # Default: 7 years

# Data retention periods by type (in days)
data_retention_periods := {
    "personal_health_information": 2555,  # 7 years
    "financial_transactions": 2555,       # 7 years
    "user_profiles": 1095,                # 3 years
    "audit_logs": 2555,                   # 7 years
    "access_logs": 365,                   # 1 year
    "system_logs": 90,                    # 3 months
    "user_preferences": 1095,             # 3 years
    "session_data": 30                    # 30 days
}

# Check legal hold requirements
legal_hold_requirements_met if {
    # No legal hold active
    not legal_hold_active
}

legal_hold_requirements_met if {
    # Legal hold active but user has appropriate access
    legal_hold_active
    "legal" in input.user.roles
}

# Check if legal hold is active for this data
legal_hold_active if {
    input.data.legal_hold == true
}

# Check deletion schedule
deletion_schedule_appropriate if {
    # Data has appropriate deletion date
    input.data.deletion_scheduled == true
    deletion_date := input.data.deletion_date
    
    # Deletion date is after retention period
    deletion_time := time.parse_rfc3339_ns(deletion_date)
    retention_end := time.add_date(
        time.parse_rfc3339_ns(input.data.created_at),
        0, 0, retention_period_days
    )
    deletion_time >= retention_end
}

# Check if deletion is scheduled
deletion_scheduled if {
    input.data.deletion_scheduled == true
}

# =============================================================================
# AUDIT REQUIREMENTS
# =============================================================================

# Determine if data access requires audit logging
data_audit_required if {
    # Always audit TOP SECRET and SECRET data
    data_classification_level in ["top_secret", "secret"]
}

data_audit_required if {
    # Audit based on data type sensitivity
    input.data.type in audit_required_data_types
}

data_audit_required if {
    # Audit based on purpose
    input.purpose in audit_required_purposes
}

data_audit_required if {
    # Audit for privileged users
    "admin" in input.user.roles
}

# Data types that always require audit
audit_required_data_types := {
    "personal_health_information",
    "financial_transactions", 
    "encryption_keys",
    "user_passwords",
    "audit_logs"
}

# Purposes that always require audit
audit_required_purposes := {
    "audit", "compliance_check", "legal_discovery", "incident_investigation"
}