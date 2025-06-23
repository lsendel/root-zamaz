package zero_trust.authz

import future.keywords.if

# Test valid user with sufficient trust level
test_allow_valid_user if {
    allow with input as {
        "jwt_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
        "resource": "user_profile",
        "action": "read"
    }
}

# Test user with insufficient trust level
test_deny_insufficient_trust if {
    not allow with input as {
        "jwt_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
        "resource": "admin_panel",
        "action": "write"
    }
}
