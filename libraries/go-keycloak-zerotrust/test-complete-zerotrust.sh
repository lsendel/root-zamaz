#!/bin/bash

echo "🧪 Testing Complete Zero Trust Integration"
echo "========================================"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test 1: Keycloak health
echo -e "\n${BLUE}1. Testing Keycloak...${NC}"
KEYCLOAK_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8082/admin)
if [ "$KEYCLOAK_STATUS" = "302" ]; then
    echo -e "${GREEN}✅ Keycloak is running${NC}"
else
    echo -e "${RED}❌ Keycloak failed (Status: $KEYCLOAK_STATUS)${NC}"
fi

# Test 2: OPA health
echo -e "\n${BLUE}2. Testing OPA...${NC}"
OPA_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8181/health)
if [ "$OPA_STATUS" = "200" ]; then
    echo -e "${GREEN}✅ OPA is running${NC}"
else
    echo -e "${RED}❌ OPA failed (Status: $OPA_STATUS)${NC}"
fi

# Test 3: OPA policy evaluation
echo -e "\n${BLUE}3. Testing OPA policy evaluation...${NC}"
POLICY_TEST=$(curl -s -X POST http://localhost:8181/v1/data/zero_trust/authz/allow \
    -H "Content-Type: application/json" \
    -d '{
        "input": {
            "jwt_token": "test-token",
            "resource": "user_profile", 
            "action": "read",
            "trust_level": 50
        }
    }')

if echo "$POLICY_TEST" | grep -q "result"; then
    echo -e "${GREEN}✅ OPA policy evaluation working${NC}"
    echo "Policy result: $POLICY_TEST"
else
    echo -e "${RED}❌ OPA policy evaluation failed${NC}"
    echo "Response: $POLICY_TEST"
fi

# Test 4: Application integration
echo -e "\n${BLUE}4. Testing application...${NC}"
APP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health)
if [ "$APP_STATUS" = "200" ]; then
    echo -e "${GREEN}✅ Application is running${NC}"
else
    echo -e "${RED}❌ Application failed (Status: $APP_STATUS)${NC}"
fi

echo -e "\n${BLUE}Zero Trust Integration Test Complete${NC}"
echo -e "${BLUE}====================================${NC}"
echo -e "${GREEN}Architecture Components:${NC}"
echo -e "🔐 Keycloak (Identity): http://localhost:8082/admin"
echo -e "🔍 OPA (Authorization): http://localhost:8181"
echo -e "🌐 Application: http://localhost:8080"
echo -e "🔀 Envoy Proxy: http://localhost:10000"
