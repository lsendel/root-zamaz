#!/bin/bash

echo "🔐 Zero Trust Keycloak Initialization Script"
echo "============================================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
KEYCLOAK_URL="http://localhost:8082"
ADMIN_USER="admin"
ADMIN_PASS="admin"
REALM_NAME="zerotrust-test"
CLIENT_ID="zerotrust-client"
CLIENT_SECRET="zerotrust-secret-12345"

# Function to get admin token
get_admin_token() {
    echo -e "${BLUE}🔑 Getting admin access token...${NC}"
    
    TOKEN_RESPONSE=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=admin-cli" \
        -d "username=$ADMIN_USER" \
        -d "password=$ADMIN_PASS")
    
    if echo "$TOKEN_RESPONSE" | grep -q "access_token"; then
        ADMIN_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token' 2>/dev/null)
        if [ -n "$ADMIN_TOKEN" ] && [ "$ADMIN_TOKEN" != "null" ]; then
            echo -e "${GREEN}✅ Admin token obtained${NC}"
            return 0
        fi
    fi
    
    echo -e "${RED}❌ Failed to get admin token${NC}"
    echo "Response: $TOKEN_RESPONSE"
    return 1
}

# Function to check if realm exists
check_realm_exists() {
    echo -e "${BLUE}🔍 Checking if realm '$REALM_NAME' exists...${NC}"
    
    REALM_CHECK=$(curl -s -w "%{http_code}" -o /dev/null \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        "$KEYCLOAK_URL/admin/realms/$REALM_NAME")
    
    if [ "$REALM_CHECK" = "200" ]; then
        echo -e "${YELLOW}⚠️  Realm '$REALM_NAME' already exists${NC}"
        return 0
    else
        echo -e "${BLUE}ℹ️  Realm '$REALM_NAME' does not exist${NC}"
        return 1
    fi
}

# Function to create realm
create_realm() {
    echo -e "${BLUE}🏗️  Creating Zero Trust realm...${NC}"
    
    # Create realm JSON
    REALM_JSON=$(cat << 'EOF'
{
  "realm": "zerotrust-test",
  "displayName": "Zero Trust Test Realm",
  "displayNameHtml": "<strong>Zero Trust</strong> Test Realm",
  "enabled": true,
  "sslRequired": "external",
  "registrationAllowed": false,
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
  "accessTokenLifespan": 300,
  "accessTokenLifespanForImplicitFlow": 900,
  "ssoSessionIdleTimeout": 1800,
  "ssoSessionMaxLifespan": 36000,
  "accessCodeLifespan": 60,
  "accessCodeLifespanUserAction": 300,
  "accessCodeLifespanLogin": 1800,
  "defaultSignatureAlgorithm": "RS256",
  "revokeRefreshToken": false,
  "refreshTokenMaxReuse": 0,
  "attributes": {
    "frontendUrl": "",
    "acr.loa.map": "{}",
    "displayName": "Zero Trust Test Realm",
    "displayNameHtml": "<strong>Zero Trust</strong> Test Realm"
  }
}
EOF
)
    
    CREATE_RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/realm_create.log \
        -X POST "$KEYCLOAK_URL/admin/realms" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$REALM_JSON")
    
    if [ "$CREATE_RESPONSE" = "201" ]; then
        echo -e "${GREEN}✅ Realm '$REALM_NAME' created successfully${NC}"
        return 0
    else
        echo -e "${RED}❌ Failed to create realm (HTTP $CREATE_RESPONSE)${NC}"
        cat /tmp/realm_create.log
        return 1
    fi
}

# Function to create test user
create_test_user() {
    echo -e "${BLUE}👤 Creating test user...${NC}"
    
    USER_JSON=$(cat << 'EOF'
{
  "username": "testuser",
  "enabled": true,
  "emailVerified": true,
  "firstName": "Test",
  "lastName": "User",
  "email": "testuser@example.com",
  "credentials": [
    {
      "type": "password",
      "value": "password123",
      "temporary": false
    }
  ],
  "attributes": {
    "department": ["Engineering"],
    "location": ["Remote"],
    "trust_level": ["75"]
  }
}
EOF
)
    
    USER_RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/user_create.log \
        -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$USER_JSON")
    
    if [ "$USER_RESPONSE" = "201" ]; then
        echo -e "${GREEN}✅ Test user 'testuser' created${NC}"
        echo -e "${CYAN}   Username: testuser${NC}"
        echo -e "${CYAN}   Password: password123${NC}"
        echo -e "${CYAN}   Email: testuser@example.com${NC}"
    else
        echo -e "${YELLOW}⚠️  Test user creation failed or already exists (HTTP $USER_RESPONSE)${NC}"
    fi
}

# Function to create Zero Trust client
create_zerotrust_client() {
    echo -e "${BLUE}🔧 Creating Zero Trust client...${NC}"
    
    CLIENT_JSON=$(cat << EOF
{
  "clientId": "$CLIENT_ID",
  "name": "Zero Trust Client",
  "description": "Client for Zero Trust authentication integration",
  "enabled": true,
  "clientAuthenticatorType": "client-secret",
  "secret": "$CLIENT_SECRET",
  "redirectUris": [
    "http://localhost:8080/*",
    "http://localhost:5173/*",
    "http://localhost:3000/*"
  ],
  "webOrigins": [
    "http://localhost:8080",
    "http://localhost:5173",
    "http://localhost:3000"
  ],
  "protocol": "openid-connect",
  "publicClient": false,
  "bearerOnly": false,
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": true,
  "serviceAccountsEnabled": true,
  "attributes": {
    "access.token.lifespan": "300",
    "client_credentials.use_refresh_token": "false",
    "display.on.consent.screen": "false",
    "oauth2.device.authorization.grant.enabled": "false",
    "oidc.ciba.grant.enabled": "false",
    "use.refresh.tokens": "true",
    "id.token.as.detached.signature": "false",
    "tls.client.certificate.bound.access.tokens": "false",
    "require.pushed.authorization.requests": "false",
    "client.secret.creation.time": "$(date +%s)",
    "backchannel.logout.session.required": "true",
    "backchannel.logout.revoke.offline.tokens": "false"
  },
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
  ]
}
EOF
)
    
    CLIENT_RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/client_create.log \
        -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$CLIENT_JSON")
    
    if [ "$CLIENT_RESPONSE" = "201" ]; then
        echo -e "${GREEN}✅ Zero Trust client created successfully${NC}"
        echo -e "${CYAN}   Client ID: $CLIENT_ID${NC}"
        echo -e "${CYAN}   Client Secret: $CLIENT_SECRET${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠️  Client creation failed or already exists (HTTP $CLIENT_RESPONSE)${NC}"
        cat /tmp/client_create.log
        return 1
    fi
}

# Function to configure realm settings for Zero Trust
configure_zerotrust_settings() {
    echo -e "${BLUE}⚙️  Configuring Zero Trust security settings...${NC}"
    
    # Update realm with security-focused settings
    REALM_UPDATE_JSON=$(cat << 'EOF'
{
  "bruteForceProtected": true,
  "permanentLockout": false,
  "maxFailureWaitSeconds": 900,
  "minimumQuickLoginWaitSeconds": 60,
  "waitIncrementSeconds": 60,
  "quickLoginCheckMilliSeconds": 1000,
  "maxDeltaTimeSeconds": 43200,
  "failureFactor": 5,
  "accessTokenLifespan": 300,
  "ssoSessionIdleTimeout": 1800,
  "ssoSessionMaxLifespan": 7200,
  "requiredCredentials": ["password"],
  "passwordPolicy": "length(8) and digits(2) and lowerCase(1) and upperCase(1) and specialChars(1) and notUsername(undefined) and notEmail(undefined)",
  "otpPolicyType": "totp",
  "otpPolicyAlgorithm": "HmacSHA1",
  "otpPolicyInitialCounter": 0,
  "otpPolicyDigits": 6,
  "otpPolicyLookAheadWindow": 1,
  "otpPolicyPeriod": 30,
  "attributes": {
    "bruteForceProtected": "true",
    "failureFactor": "5",
    "maxDeltaTimeSeconds": "43200",
    "maxFailureWaitSeconds": "900",
    "minimumQuickLoginWaitSeconds": "60",
    "quickLoginCheckMilliSeconds": "1000",
    "waitIncrementSeconds": "60"
  }
}
EOF
)
    
    UPDATE_RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/realm_update.log \
        -X PUT "$KEYCLOAK_URL/admin/realms/$REALM_NAME" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$REALM_UPDATE_JSON")
    
    if [ "$UPDATE_RESPONSE" = "204" ]; then
        echo -e "${GREEN}✅ Zero Trust security settings configured${NC}"
        echo -e "${CYAN}   - Brute force protection enabled${NC}"
        echo -e "${CYAN}   - Strong password policy enforced${NC}"
        echo -e "${CYAN}   - Session timeouts configured${NC}"
        echo -e "${CYAN}   - Token lifespans optimized${NC}"
    else
        echo -e "${YELLOW}⚠️  Security settings update failed (HTTP $UPDATE_RESPONSE)${NC}"
    fi
}

# Function to test the setup
test_setup() {
    echo -e "\n${PURPLE}🧪 Testing Zero Trust setup...${NC}"
    
    # Test token endpoint
    echo -e "${BLUE}1. Testing token endpoint with test user...${NC}"
    
    TOKEN_RESPONSE=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=$CLIENT_ID" \
        -d "client_secret=$CLIENT_SECRET" \
        -d "username=testuser" \
        -d "password=password123")
    
    if echo "$TOKEN_RESPONSE" | grep -q "access_token"; then
        ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token' 2>/dev/null)
        echo -e "${GREEN}✅ Token obtained successfully${NC}"
        echo -e "${CYAN}   Token (first 50 chars): ${ACCESS_TOKEN:0:50}...${NC}"
        
        # Test userinfo endpoint
        echo -e "${BLUE}2. Testing userinfo endpoint...${NC}"
        USER_INFO=$(curl -s "$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/userinfo" \
            -H "Authorization: Bearer $ACCESS_TOKEN")
        
        if echo "$USER_INFO" | grep -q "sub"; then
            echo -e "${GREEN}✅ Userinfo endpoint working${NC}"
            echo -e "${CYAN}   User: $(echo $USER_INFO | jq -r '.preferred_username' 2>/dev/null)${NC}"
        else
            echo -e "${RED}❌ Userinfo endpoint failed${NC}"
        fi
        
        # Test token introspection
        echo -e "${BLUE}3. Testing token introspection...${NC}"
        INTROSPECT=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/token/introspect" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "token=$ACCESS_TOKEN" \
            -d "client_id=$CLIENT_ID" \
            -d "client_secret=$CLIENT_SECRET")
        
        if echo "$INTROSPECT" | grep -q '"active":true'; then
            echo -e "${GREEN}✅ Token introspection working${NC}"
        else
            echo -e "${RED}❌ Token introspection failed${NC}"
        fi
        
    else
        echo -e "${RED}❌ Token request failed${NC}"
        echo "Response: $TOKEN_RESPONSE"
    fi
}

# Main execution
main() {
    echo -e "\n${BLUE}🚀 Starting Zero Trust Keycloak setup...${NC}"
    
    # Step 1: Check Keycloak health
    echo -e "\n${BLUE}Step 1: Checking Keycloak health...${NC}"
    HEALTH_CHECK=$(curl -s -o /dev/null -w "%{http_code}" "$KEYCLOAK_URL/health/ready" 2>/dev/null)
    
    if [ "$HEALTH_CHECK" != "200" ]; then
        # Try alternative health check
        HEALTH_CHECK=$(curl -s -o /dev/null -w "%{http_code}" "$KEYCLOAK_URL/admin" 2>/dev/null)
        if [ "$HEALTH_CHECK" != "302" ] && [ "$HEALTH_CHECK" != "200" ]; then
            echo -e "${RED}❌ Keycloak is not accessible (Status: $HEALTH_CHECK)${NC}"
            echo -e "${YELLOW}Please make sure Keycloak is running on $KEYCLOAK_URL${NC}"
            exit 1
        fi
    fi
    echo -e "${GREEN}✅ Keycloak is accessible${NC}"
    
    # Step 2: Get admin token
    echo -e "\n${BLUE}Step 2: Authenticating as admin...${NC}"
    if ! get_admin_token; then
        echo -e "${RED}❌ Failed to authenticate. Please check admin credentials.${NC}"
        exit 1
    fi
    
    # Step 3: Check/Create realm
    echo -e "\n${BLUE}Step 3: Setting up Zero Trust realm...${NC}"
    if check_realm_exists; then
        echo -e "${YELLOW}ℹ️  Using existing realm${NC}"
    else
        if ! create_realm; then
            echo -e "${RED}❌ Failed to create realm${NC}"
            exit 1
        fi
    fi
    
    # Step 4: Create test user
    echo -e "\n${BLUE}Step 4: Creating test user...${NC}"
    create_test_user
    
    # Step 5: Create client
    echo -e "\n${BLUE}Step 5: Creating Zero Trust client...${NC}"
    create_zerotrust_client
    
    # Step 6: Configure security settings
    echo -e "\n${BLUE}Step 6: Configuring Zero Trust security...${NC}"
    configure_zerotrust_settings
    
    # Step 7: Test setup
    echo -e "\n${BLUE}Step 7: Testing configuration...${NC}"
    test_setup
    
    # Final summary
    echo -e "\n${GREEN}🎉 Zero Trust Keycloak setup completed!${NC}"
    echo -e "\n${CYAN}===========================================${NC}"
    echo -e "${CYAN}📋 Configuration Summary:${NC}"
    echo -e "${CYAN}===========================================${NC}"
    echo -e "${GREEN}🔗 Keycloak Admin Console:${NC} $KEYCLOAK_URL/admin"
    echo -e "${GREEN}👤 Admin Username:${NC} $ADMIN_USER"
    echo -e "${GREEN}🔐 Admin Password:${NC} $ADMIN_PASS"
    echo -e "${GREEN}🏰 Realm Name:${NC} $REALM_NAME"
    echo -e "${GREEN}🔑 Client ID:${NC} $CLIENT_ID"
    echo -e "${GREEN}🗝️  Client Secret:${NC} $CLIENT_SECRET"
    echo -e "${GREEN}👨‍💻 Test User:${NC} testuser / password123"
    echo -e "\n${CYAN}🔌 Token Endpoint:${NC} $KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/token"
    echo -e "${CYAN}📋 UserInfo Endpoint:${NC} $KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/userinfo"
    echo -e "${CYAN}🔍 Introspect Endpoint:${NC} $KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/token/introspect"
    echo -e "\n${BLUE}💡 Next steps:${NC}"
    echo -e "1. Update your application's .env file with these credentials"
    echo -e "2. Run: ./test-keycloak.sh to verify integration"
    echo -e "3. Test your application's authentication flow"
    echo -e "${CYAN}===========================================${NC}"
}

# Execute main function
main "$@"