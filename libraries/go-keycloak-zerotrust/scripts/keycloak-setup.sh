#!/bin/bash

# ==================================================
# Keycloak Auto-Setup Script
# ==================================================
# This script automatically configures Keycloak with a test realm and client
# for the go-keycloak-zerotrust development environment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
KEYCLOAK_URL="http://localhost:8080"
ADMIN_USER="admin"
ADMIN_PASSWORD="admin"
REALM_NAME="zerotrust-test"
CLIENT_ID="zerotrust-client"
CLIENT_SECRET="zerotrust-secret-$(date +%s)"
CONTAINER_NAME="keycloak-zerotrust-kc"

# Functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

# Check if Keycloak is running
check_keycloak() {
    log "Checking if Keycloak is running..."
    
    if ! docker ps | grep -q "$CONTAINER_NAME"; then
        error "Keycloak container is not running. Please run 'make start' first."
    fi
    
    # Wait for Keycloak to be ready
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s "$KEYCLOAK_URL/health/ready" >/dev/null 2>&1; then
            success "Keycloak is ready"
            return 0
        fi
        
        log "Waiting for Keycloak... (attempt $attempt/$max_attempts)"
        sleep 3
        ((attempt++))
    done
    
    error "Keycloak failed to become ready after $max_attempts attempts"
}

# Get admin access token
get_admin_token() {
    log "Getting admin access token..."
    
    local response
    response=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$ADMIN_USER" \
        -d "password=$ADMIN_PASSWORD" \
        -d "grant_type=password" \
        -d "client_id=admin-cli")
    
    if [[ $response == *"access_token"* ]]; then
        echo "$response" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4
    else
        error "Failed to get admin token: $response"
    fi
}

# Create test realm
create_realm() {
    local token=$1
    log "Creating test realm: $REALM_NAME"
    
    # Check if realm already exists
    local existing_realm
    existing_realm=$(curl -s -H "Authorization: Bearer $token" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME" | grep -o '"realm":"[^"]*' | cut -d'"' -f4 || echo "")
    
    if [[ "$existing_realm" == "$REALM_NAME" ]]; then
        warning "Realm $REALM_NAME already exists, skipping creation"
        return 0
    fi
    
    # Create realm
    local realm_config='{
        "realm": "'$REALM_NAME'",
        "displayName": "Zero Trust Test Realm",
        "enabled": true,
        "registrationAllowed": false,
        "registrationEmailAsUsername": true,
        "rememberMe": true,
        "verifyEmail": false,
        "loginWithEmailAllowed": true,
        "duplicateEmailsAllowed": false,
        "resetPasswordAllowed": true,
        "editUsernameAllowed": false,
        "bruteForceProtected": true,
        "permanentLockout": false,
        "maxFailureWaitSeconds": 900,
        "minimumQuickLoginWaitSeconds": 60,
        "waitIncrementSeconds": 60,
        "quickLoginCheckMilliSeconds": 1000,
        "maxDeltaTimeSeconds": 43200,
        "failureFactor": 30,
        "defaultRoles": ["uma_authorization"],
        "requiredCredentials": ["password"],
        "otpPolicyType": "totp",
        "otpPolicyAlgorithm": "HmacSHA1",
        "otpPolicyInitialCounter": 0,
        "otpPolicyDigits": 6,
        "otpPolicyLookAheadWindow": 1,
        "otpPolicyPeriod": 30,
        "accessTokenLifespan": 300,
        "accessTokenLifespanForImplicitFlow": 900,
        "ssoSessionIdleTimeout": 1800,
        "ssoSessionMaxLifespan": 36000,
        "offlineSessionIdleTimeout": 2592000,
        "accessCodeLifespan": 60,
        "accessCodeLifespanUserAction": 300,
        "accessCodeLifespanLogin": 1800,
        "actionTokenGeneratedByAdminLifespan": 43200,
        "actionTokenGeneratedByUserLifespan": 300
    }'
    
    local response
    response=$(curl -s -w "%{http_code}" -X POST "$KEYCLOAK_URL/admin/realms" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "$realm_config")
    
    local http_code="${response: -3}"
    if [[ "$http_code" -eq 201 ]]; then
        success "Realm $REALM_NAME created successfully"
    else
        error "Failed to create realm. HTTP code: $http_code, Response: ${response%???}"
    fi
}

# Create test client
create_client() {
    local token=$1
    log "Creating test client: $CLIENT_ID"
    
    # Check if client already exists
    local existing_clients
    existing_clients=$(curl -s -H "Authorization: Bearer $token" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients?clientId=$CLIENT_ID")
    
    if [[ $existing_clients != "[]" ]]; then
        warning "Client $CLIENT_ID already exists, updating configuration"
        local client_uuid
        client_uuid=$(echo "$existing_clients" | grep -o '"id":"[^"]*' | cut -d'"' -f4)
        update_client "$token" "$client_uuid"
        return 0
    fi
    
    # Create client
    local client_config='{
        "clientId": "'$CLIENT_ID'",
        "name": "Zero Trust Test Client",
        "description": "Test client for go-keycloak-zerotrust development",
        "enabled": true,
        "clientAuthenticatorType": "client-secret",
        "secret": "'$CLIENT_SECRET'",
        "redirectUris": [
            "http://localhost:8081/*",
            "http://localhost:3000/*",
            "http://127.0.0.1:8081/*",
            "http://127.0.0.1:3000/*"
        ],
        "webOrigins": [
            "http://localhost:8081",
            "http://localhost:3000",
            "http://127.0.0.1:8081",
            "http://127.0.0.1:3000"
        ],
        "protocol": "openid-connect",
        "publicClient": false,
        "bearerOnly": false,
        "standardFlowEnabled": true,
        "implicitFlowEnabled": false,
        "directAccessGrantsEnabled": true,
        "serviceAccountsEnabled": true,
        "authorizationServicesEnabled": false,
        "fullScopeAllowed": true,
        "nodeReRegistrationTimeout": 0,
        "defaultClientScopes": [
            "web-origins",
            "role_list",
            "profile",
            "roles",
            "email"
        ],
        "optionalClientScopes": [
            "address",
            "phone",
            "offline_access",
            "microprofile-jwt"
        ],
        "attributes": {
            "access.token.lifespan": "300",
            "client.secret.creation.time": "'$(date +%s)'",
            "oauth2.device.authorization.grant.enabled": "false",
            "oidc.ciba.grant.enabled": "false"
        }
    }'
    
    local response
    response=$(curl -s -w "%{http_code}" -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "$client_config")
    
    local http_code="${response: -3}"
    if [[ "$http_code" -eq 201 ]]; then
        success "Client $CLIENT_ID created successfully"
    else
        error "Failed to create client. HTTP code: $http_code, Response: ${response%???}"
    fi
}

# Update existing client
update_client() {
    local token=$1
    local client_uuid=$2
    log "Updating existing client: $CLIENT_ID"
    
    local client_config='{
        "secret": "'$CLIENT_SECRET'",
        "redirectUris": [
            "http://localhost:8081/*",
            "http://localhost:3000/*",
            "http://127.0.0.1:8081/*",
            "http://127.0.0.1:3000/*"
        ],
        "webOrigins": [
            "http://localhost:8081",
            "http://localhost:3000",
            "http://127.0.0.1:8081",
            "http://127.0.0.1:3000"
        ],
        "directAccessGrantsEnabled": true,
        "serviceAccountsEnabled": true
    }'
    
    local response
    response=$(curl -s -w "%{http_code}" -X PUT "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$client_uuid" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "$client_config")
    
    local http_code="${response: -3}"
    if [[ "$http_code" -eq 204 ]]; then
        success "Client $CLIENT_ID updated successfully"
    else
        error "Failed to update client. HTTP code: $http_code, Response: ${response%???}"
    fi
}

# Create client mappers for Zero Trust claims
create_client_mappers() {
    local token=$1
    log "Creating client mappers for Zero Trust claims..."
    
    # Get client UUID
    local client_data
    client_data=$(curl -s -H "Authorization: Bearer $token" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients?clientId=$CLIENT_ID")
    
    local client_uuid
    client_uuid=$(echo "$client_data" | grep -o '"id":"[^"]*' | cut -d'"' -f4)
    
    if [[ -z "$client_uuid" ]]; then
        error "Could not find client UUID for $CLIENT_ID"
    fi
    
    # Define mappers
    local mappers=(
        '{"name":"trust-level","protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper","config":{"userinfo.token.claim":"true","user.attribute":"trust_level","id.token.claim":"true","access.token.claim":"true","claim.name":"trust_level","jsonType.label":"int"}}'
        '{"name":"device-id","protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper","config":{"userinfo.token.claim":"true","user.attribute":"device_id","id.token.claim":"true","access.token.claim":"true","claim.name":"device_id","jsonType.label":"String"}}'
        '{"name":"device-verified","protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper","config":{"userinfo.token.claim":"true","user.attribute":"device_verified","id.token.claim":"true","access.token.claim":"true","claim.name":"device_verified","jsonType.label":"boolean"}}'
        '{"name":"risk-score","protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper","config":{"userinfo.token.claim":"true","user.attribute":"risk_score","id.token.claim":"true","access.token.claim":"true","claim.name":"risk_score","jsonType.label":"double"}}'
    )
    
    for mapper in "${mappers[@]}"; do
        local mapper_name
        mapper_name=$(echo "$mapper" | grep -o '"name":"[^"]*' | cut -d'"' -f4)
        
        local response
        response=$(curl -s -w "%{http_code}" -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$client_uuid/protocol-mappers/models" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "$mapper")
        
        local http_code="${response: -3}"
        if [[ "$http_code" -eq 201 ]]; then
            success "Created mapper: $mapper_name"
        elif [[ "$http_code" -eq 409 ]]; then
            warning "Mapper $mapper_name already exists"
        else
            warning "Failed to create mapper $mapper_name. HTTP code: $http_code"
        fi
    done
}

# Create test users
create_test_users() {
    local token=$1
    log "Creating test users..."
    
    local users=(
        '{"username":"testuser","email":"test@example.com","firstName":"Test","lastName":"User","enabled":true,"emailVerified":true,"attributes":{"trust_level":["75"],"device_verified":["true"],"risk_score":["25.5"]},"credentials":[{"type":"password","value":"password","temporary":false}]}'
        '{"username":"adminuser","email":"admin@example.com","firstName":"Admin","lastName":"User","enabled":true,"emailVerified":true,"attributes":{"trust_level":["90"],"device_verified":["true"],"risk_score":["15.0"]},"credentials":[{"type":"password","value":"password","temporary":false}]}'
        '{"username":"lowtrustuser","email":"lowrust@example.com","firstName":"LowTrust","lastName":"User","enabled":true,"emailVerified":true,"attributes":{"trust_level":["20"],"device_verified":["false"],"risk_score":["75.0"]},"credentials":[{"type":"password","value":"password","temporary":false}]}'
    )
    
    for user in "${users[@]}"; do
        local username
        username=$(echo "$user" | grep -o '"username":"[^"]*' | cut -d'"' -f4)
        
        local response
        response=$(curl -s -w "%{http_code}" -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "$user")
        
        local http_code="${response: -3}"
        if [[ "$http_code" -eq 201 ]]; then
            success "Created user: $username"
        elif [[ "$http_code" -eq 409 ]]; then
            warning "User $username already exists"
        else
            warning "Failed to create user $username. HTTP code: $http_code"
        fi
    done
}

# Update .env file with new client secret
update_env_file() {
    log "Updating .env file with client configuration..."
    
    local env_file=".env"
    
    if [[ ! -f "$env_file" ]]; then
        log "Creating .env file from template..."
        cp .env.template "$env_file"
    fi
    
    # Update environment variables
    sed -i.bak "s/KEYCLOAK_REALM=.*/KEYCLOAK_REALM=$REALM_NAME/" "$env_file"
    sed -i.bak "s/KEYCLOAK_CLIENT_ID=.*/KEYCLOAK_CLIENT_ID=$CLIENT_ID/" "$env_file"
    sed -i.bak "s/KEYCLOAK_CLIENT_SECRET=.*/KEYCLOAK_CLIENT_SECRET=$CLIENT_SECRET/" "$env_file"
    
    # Remove backup file
    rm -f "$env_file.bak"
    
    success "Updated $env_file with new configuration"
}

# Display setup information
display_setup_info() {
    echo ""
    echo -e "${CYAN}=================================================${NC}"
    echo -e "${CYAN}🎉 Keycloak Setup Complete!${NC}"
    echo -e "${CYAN}=================================================${NC}"
    echo ""
    echo -e "${GREEN}📋 Configuration Details:${NC}"
    echo -e "   🌐 Keycloak URL: ${YELLOW}$KEYCLOAK_URL${NC}"
    echo -e "   🏠 Realm: ${YELLOW}$REALM_NAME${NC}"
    echo -e "   🔑 Client ID: ${YELLOW}$CLIENT_ID${NC}"
    echo -e "   🔐 Client Secret: ${YELLOW}$CLIENT_SECRET${NC}"
    echo ""
    echo -e "${GREEN}👤 Test Users:${NC}"
    echo -e "   • ${YELLOW}testuser${NC} / password (Trust: 75, Risk: 25.5)"
    echo -e "   • ${YELLOW}adminuser${NC} / password (Trust: 90, Risk: 15.0)"
    echo -e "   • ${YELLOW}lowtrustuser${NC} / password (Trust: 20, Risk: 75.0)"
    echo ""
    echo -e "${GREEN}🚀 Next Steps:${NC}"
    echo -e "   1. Run ${YELLOW}make test-e2e${NC} to test the configuration"
    echo -e "   2. Visit ${YELLOW}$KEYCLOAK_URL/admin${NC} to manage Keycloak"
    echo -e "   3. Check the updated ${YELLOW}.env${NC} file for configuration"
    echo ""
    echo -e "${GREEN}🔗 Useful URLs:${NC}"
    echo -e "   • Admin Console: ${YELLOW}$KEYCLOAK_URL/admin${NC}"
    echo -e "   • Realm Console: ${YELLOW}$KEYCLOAK_URL/admin/master/console/#/$REALM_NAME${NC}"
    echo -e "   • OpenID Config: ${YELLOW}$KEYCLOAK_URL/realms/$REALM_NAME/.well-known/openid-configuration${NC}"
    echo ""
}

# Main execution
main() {
    echo -e "${CYAN}=================================================${NC}"
    echo -e "${CYAN}🔐 Keycloak Zero Trust Setup${NC}"
    echo -e "${CYAN}=================================================${NC}"
    echo ""
    
    check_keycloak
    
    local admin_token
    admin_token=$(get_admin_token)
    
    create_realm "$admin_token"
    create_client "$admin_token"
    create_client_mappers "$admin_token"
    create_test_users "$admin_token"
    update_env_file
    
    display_setup_info
}

# Run main function
main "$@"