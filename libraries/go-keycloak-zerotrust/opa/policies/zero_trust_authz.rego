# Zero Trust Authorization Policy
# Simplified version for testing

package zero_trust.authz

import future.keywords.if
import future.keywords.in

# Main authorization decision
allow if {
    user_authenticated
    sufficient_trust_level
    action_permitted
}

# Basic user authentication check
user_authenticated if {
    input.jwt_token != ""
}

# Trust level enforcement (simplified)
sufficient_trust_level if {
    input.trust_level >= 25
}

# Action permission check (simplified)
action_permitted if {
    input.resource != ""
    input.action != ""
}

# Decision with basic reasoning
decision := {
    "allow": allow,
    "timestamp": time.now_ns(),
    "resource": input.resource,
    "action": input.action
}