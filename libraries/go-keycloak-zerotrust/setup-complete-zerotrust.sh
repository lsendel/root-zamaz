#!/bin/bash

echo "🛡️ Complete Zero Trust Architecture Setup"
echo "========================================"
echo "Implementing: Keycloak + OPA + Istio Integration"

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
OPA_URL="http://localhost:8181"
ISTIO_GATEWAY_PORT="15021"

echo -e "\n${CYAN}🏗️ Zero Trust Architecture Components:${NC}"
echo -e "${BLUE}1. Keycloak${NC} - Identity Provider (Authentication)"
echo -e "${BLUE}2. OPA${NC} - Policy Engine (Authorization)" 
echo -e "${BLUE}3. Istio${NC} - Service Mesh (Network Policy Enforcement)"
echo -e "${BLUE}4. SPIRE${NC} - Workload Identity (Service Authentication)"

# Step 1: Setup OPA (Open Policy Agent)
setup_opa() {
    echo -e "\n${BLUE}🔧 Step 1: Setting up OPA (Policy Engine)...${NC}"
    
    # Create OPA directory structure
    mkdir -p opa/{policies,data,tests}
    
    # Create Zero Trust authorization policy
    cat > opa/policies/zero_trust_authz.rego << 'EOF'
# Zero Trust Authorization Policy
# Combines Keycloak JWT claims with OPA decision logic

package zero_trust.authz

import future.keywords.if
import future.keywords.in

# Main authorization decision
allow if {
    user_authenticated
    sufficient_trust_level
    action_permitted
    within_time_constraints
    device_verified
    not rate_limited
}

# User authentication check (JWT validation)
user_authenticated if {
    input.jwt_token
    jwt_payload := io.jwt.decode(input.jwt_token)[1]
    jwt_payload.iss == "http://localhost:8082/realms/zerotrust-test"
    jwt_payload.exp > time.now_ns() / 1000000000
}

# Trust level enforcement
sufficient_trust_level if {
    jwt_payload := io.jwt.decode(input.jwt_token)[1]
    trust_level := to_number(jwt_payload.trust_level)
    required_level := required_trust_levels[input.resource][input.action]
    trust_level >= required_level
}

# Action permission matrix
action_permitted if {
    jwt_payload := io.jwt.decode(input.jwt_token)[1]
    user_roles := jwt_payload.realm_access.roles
    allowed_roles := resource_permissions[input.resource][input.action]
    intersection := user_roles & allowed_roles
    count(intersection) > 0
}

# Time-based access control
within_time_constraints if {
    current_hour := time.now_ns() / 1000000000 / 3600 % 24
    time_restrictions := resource_time_restrictions[input.resource]
    current_hour >= time_restrictions.start_hour
    current_hour <= time_restrictions.end_hour
}

# Device verification (from JWT claims)
device_verified if {
    jwt_payload := io.jwt.decode(input.jwt_token)[1]
    device_id := jwt_payload.device_id
    device_id != ""
    # Additional device verification logic can be added here
}

# Rate limiting check
rate_limited if {
    jwt_payload := io.jwt.decode(input.jwt_token)[1]
    user_id := jwt_payload.sub
    current_requests := data.rate_limits[user_id].count
    max_requests := data.rate_limits[user_id].limit
    current_requests >= max_requests
}

# Trust level requirements per resource/action
required_trust_levels := {
    "user_profile": {
        "read": 25,
        "write": 50
    },
    "admin_panel": {
        "read": 75,
        "write": 90
    },
    "financial_data": {
        "read": 80,
        "write": 95
    }
}

# Role-based permissions
resource_permissions := {
    "user_profile": {
        "read": {"user", "admin"},
        "write": {"user", "admin"}
    },
    "admin_panel": {
        "read": {"admin"},
        "write": {"admin"}
    },
    "financial_data": {
        "read": {"admin", "finance"},
        "write": {"admin"}
    }
}

# Time-based restrictions (24-hour format)
resource_time_restrictions := {
    "user_profile": {
        "start_hour": 0,
        "end_hour": 23
    },
    "admin_panel": {
        "start_hour": 8,
        "end_hour": 18
    },
    "financial_data": {
        "start_hour": 9,
        "end_hour": 17
    }
}

# Detailed decision with reasoning
decision := {
    "allow": allow,
    "reasons": denial_reasons,
    "trust_level": jwt_payload.trust_level,
    "user_roles": jwt_payload.realm_access.roles,
    "timestamp": time.now_ns(),
    "resource": input.resource,
    "action": input.action
} if {
    jwt_payload := io.jwt.decode(input.jwt_token)[1]
}

denial_reasons := reasons if {
    reasons := [reason |
        checks := [
            {"condition": user_authenticated, "reason": "user_not_authenticated"},
            {"condition": sufficient_trust_level, "reason": "insufficient_trust_level"},
            {"condition": action_permitted, "reason": "action_not_permitted"},
            {"condition": within_time_constraints, "reason": "outside_allowed_hours"},
            {"condition": device_verified, "reason": "device_not_verified"},
            {"condition": not rate_limited, "reason": "rate_limit_exceeded"}
        ]
        check := checks[_]
        not check.condition
        reason := check.reason
    ]
}
EOF

    # Create OPA data file
    cat > opa/data/rate_limits.json << 'EOF'
{
    "rate_limits": {
        "user1": {
            "count": 5,
            "limit": 100,
            "window": 3600
        },
        "user2": {
            "count": 150,
            "limit": 100,
            "window": 3600
        }
    }
}
EOF

    # Create OPA test file
    cat > opa/tests/zero_trust_test.rego << 'EOF'
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
EOF

    echo -e "${GREEN}✅ OPA policies created${NC}"
}

# Step 2: Setup Istio integration
setup_istio() {
    echo -e "\n${BLUE}🕸️ Step 2: Setting up Istio Service Mesh...${NC}"
    
    # Create Istio configuration directory
    mkdir -p istio/{gateway,virtual-service,authorization-policy,peer-authentication}
    
    # Create Gateway configuration
    cat > istio/gateway/zero-trust-gateway.yaml << 'EOF'
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: zero-trust-gateway
  namespace: default
spec:
  selector:
    istio: ingressgateway
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - "*"
    tls:
      httpsRedirect: true
  - port:
      number: 443
      name: https
      protocol: HTTPS
    tls:
      mode: SIMPLE
      credentialName: zero-trust-tls
    hosts:
    - "*"
EOF

    # Create VirtualService for OPA integration
    cat > istio/virtual-service/zero-trust-vs.yaml << 'EOF'
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: zero-trust-app
  namespace: default
spec:
  hosts:
  - "*"
  gateways:
  - zero-trust-gateway
  http:
  - match:
    - uri:
        prefix: "/api/"
    route:
    - destination:
        host: impl-zamaz-app
        port:
          number: 8080
    headers:
      request:
        add:
          x-opa-authz: "enabled"
    fault:
      delay:
        percentage:
          value: 0.1
        fixedDelay: 5s
    retries:
      attempts: 3
      perTryTimeout: 2s
EOF

    # Create AuthorizationPolicy with OPA integration
    cat > istio/authorization-policy/opa-authz-policy.yaml << 'EOF'
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: opa-zero-trust-policy
  namespace: default
spec:
  selector:
    matchLabels:
      app: impl-zamaz-app
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/default/sa/impl-zamaz-app"]
  - to:
    - operation:
        methods: ["GET", "POST", "PUT", "DELETE"]
  - when:
    - key: custom.opa_decision
      values: ["allow"]
EOF

    # Create PeerAuthentication for mTLS
    cat > istio/peer-authentication/mtls-policy.yaml << 'EOF'
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: default
spec:
  mtls:
    mode: STRICT
EOF

    echo -e "${GREEN}✅ Istio configuration created${NC}"
}

# Step 3: Update Docker Compose with OPA
update_docker_compose() {
    echo -e "\n${BLUE}🐳 Step 3: Updating Docker Compose with OPA...${NC}"
    
    # Check if docker-compose.yml exists
    if [ -f docker-compose.yml ]; then
        cp docker-compose.yml docker-compose.yml.backup
        echo -e "${GREEN}✅ Backed up existing docker-compose.yml${NC}"
    else
        echo -e "${YELLOW}⚠️  No existing docker-compose.yml found, creating new one${NC}"
        # Create a basic docker-compose.yml structure
        cat > docker-compose.yml << 'EOF'
version: '3.8'

networks:
  zerotrust-network:
    driver: bridge

volumes:
  postgres_data:

services:
  # Placeholder for existing services
  placeholder:
    image: busybox
    command: "echo 'This will be replaced by existing services'"
    networks:
      - zerotrust-network
EOF
    fi
    
    # Add OPA service to docker-compose
    cat >> docker-compose.yml << 'EOF'

  # Open Policy Agent for Zero Trust Authorization
  opa:
    image: openpolicyagent/opa:latest-envoy
    container_name: impl-zamaz-opa
    ports:
      - "8181:8181"
    command: 
      - "run"
      - "--server" 
      - "--addr=0.0.0.0:8181"
      - "--diagnostic-addr=0.0.0.0:8282"
      - "--set=plugins.envoy_ext_authz_grpc.addr=:9191"
      - "--set=plugins.envoy_ext_authz_grpc.enable_reflection=true"
      - "--set=decision_logs.console=true"
      - "--config-file=/config/opa-config.yaml"
      - "/policies"
    volumes:
      - ./opa/policies:/policies
      - ./opa/data:/data
      - ./opa/config:/config
    environment:
      - OPA_LOG_LEVEL=debug
    networks:
      - zerotrust-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8181/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Envoy proxy for OPA integration
  envoy:
    image: envoyproxy/envoy:v1.28-latest
    container_name: impl-zamaz-envoy
    ports:
      - "10000:10000"
      - "9901:9901"
    volumes:
      - ./envoy/envoy.yaml:/etc/envoy/envoy.yaml
    networks:
      - zerotrust-network
    depends_on:
      - opa
    restart: unless-stopped
EOF

    echo -e "${GREEN}✅ Docker Compose updated with OPA${NC}"
}

# Step 4: Create OPA configuration
create_opa_config() {
    echo -e "\n${BLUE}⚙️ Step 4: Creating OPA configuration...${NC}"
    
    mkdir -p opa/config
    
    cat > opa/config/opa-config.yaml << 'EOF'
services:
  authz:
    url: http://localhost:8181

bundles:
  authz:
    service: authz
    resource: "/policies/zero_trust_authz.rego"
    polling:
      min_delay_seconds: 10
      max_delay_seconds: 20

decision_logs:
  console: true
  reporting:
    min_delay_seconds: 5
    max_delay_seconds: 10

plugins:
  envoy_ext_authz_grpc:
    addr: :9191
    enable_reflection: true
EOF

    echo -e "${GREEN}✅ OPA configuration created${NC}"
}

# Step 5: Create Envoy configuration  
create_envoy_config() {
    echo -e "\n${BLUE}🔀 Step 5: Creating Envoy proxy configuration...${NC}"
    
    mkdir -p envoy
    
    cat > envoy/envoy.yaml << 'EOF'
admin:
  address:
    socket_address:
      protocol: TCP
      address: 0.0.0.0
      port_value: 9901

static_resources:
  listeners:
  - name: listener_0
    address:
      socket_address:
        protocol: TCP
        address: 0.0.0.0
        port_value: 10000
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          scheme_header_transformation:
            scheme_to_overwrite: https
          stat_prefix: ingress_http
          access_log:
          - name: envoy.access_loggers.stdout
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
          http_filters:
          - name: envoy.filters.http.ext_authz
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
              transport_api_version: V3
              grpc_service:
                envoy_grpc:
                  cluster_name: opa_authz
                timeout: 0.25s
              include_peer_certificate: true
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match:
                  prefix: "/"
                route:
                  cluster: impl_zamaz_app

  clusters:
  - name: impl_zamaz_app
    connect_timeout: 0.25s
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: impl_zamaz_app
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: impl-zamaz-app
                port_value: 8080
  
  - name: opa_authz
    connect_timeout: 0.25s
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    lb_policy: ROUND_ROBIN
    http2_protocol_options: {}
    load_assignment:
      cluster_name: opa_authz
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: impl-zamaz-opa
                port_value: 9191
EOF

    echo -e "${GREEN}✅ Envoy configuration created${NC}"
}

# Step 6: Update application for OPA integration
update_application() {
    echo -e "\n${BLUE}🔧 Step 6: Updating application for OPA integration...${NC}"
    
    # Create OPA client package
    mkdir -p pkg/opa
    
    cat > pkg/opa/client.go << 'EOF'
package opa

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

// OPAClient represents an OPA client
type OPAClient struct {
    baseURL string
    client  *http.Client
}

// AuthorizationRequest represents a request to OPA
type AuthorizationRequest struct {
    JWT      string `json:"jwt_token"`
    Resource string `json:"resource"`
    Action   string `json:"action"`
    UserID   string `json:"user_id"`
    DeviceID string `json:"device_id"`
}

// AuthorizationResponse represents OPA's response
type AuthorizationResponse struct {
    Result struct {
        Allow     bool     `json:"allow"`
        Reasons   []string `json:"reasons"`
        TrustLevel int     `json:"trust_level"`
        UserRoles []string `json:"user_roles"`
        Timestamp int64    `json:"timestamp"`
    } `json:"result"`
}

// NewOPAClient creates a new OPA client
func NewOPAClient(baseURL string) *OPAClient {
    return &OPAClient{
        baseURL: baseURL,
        client: &http.Client{
            Timeout: 5 * time.Second,
        },
    }
}

// Authorize checks authorization with OPA
func (c *OPAClient) Authorize(ctx context.Context, req AuthorizationRequest) (*AuthorizationResponse, error) {
    input := map[string]interface{}{
        "input": req,
    }
    
    jsonData, err := json.Marshal(input)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }
    
    url := fmt.Sprintf("%s/v1/data/zero_trust/authz/decision", c.baseURL)
    httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }
    
    httpReq.Header.Set("Content-Type", "application/json")
    
    resp, err := c.client.Do(httpReq)
    if err != nil {
        return nil, fmt.Errorf("failed to send request: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("OPA returned status %d", resp.StatusCode)
    }
    
    var opaResp AuthorizationResponse
    if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }
    
    return &opaResp, nil
}

// HealthCheck checks OPA health
func (c *OPAClient) HealthCheck(ctx context.Context) error {
    url := fmt.Sprintf("%s/health", c.baseURL)
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return fmt.Errorf("failed to create health check request: %w", err)
    }
    
    resp, err := c.client.Do(req)
    if err != nil {
        return fmt.Errorf("failed to send health check: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("OPA health check failed with status %d", resp.StatusCode)
    }
    
    return nil
}
EOF

    echo -e "${GREEN}✅ OPA client package created${NC}"
}

# Step 7: Create integration test
create_integration_test() {
    echo -e "\n${BLUE}🧪 Step 7: Creating integration test...${NC}"
    
    cat > test-complete-zerotrust.sh << 'EOF'
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
            "action": "read"
        }
    }')

if echo "$POLICY_TEST" | grep -q "result"; then
    echo -e "${GREEN}✅ OPA policy evaluation working${NC}"
    echo "Policy result: $POLICY_TEST"
else
    echo -e "${RED}❌ OPA policy evaluation failed${NC}"
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
EOF

    chmod +x test-complete-zerotrust.sh
    echo -e "${GREEN}✅ Integration test created${NC}"
}

# Main execution
main() {
    echo -e "\n${PURPLE}🚀 Starting Complete Zero Trust Architecture Setup...${NC}"
    
    setup_opa
    setup_istio
    update_docker_compose
    create_opa_config
    create_envoy_config
    update_application
    create_integration_test
    
    echo -e "\n${GREEN}🎉 Complete Zero Trust Architecture Setup Finished!${NC}"
    echo -e "\n${CYAN}=============================================${NC}"
    echo -e "${CYAN}📋 Zero Trust Architecture Summary:${NC}"
    echo -e "${CYAN}=============================================${NC}"
    echo -e "${GREEN}🔐 Keycloak (Identity Provider):${NC}"
    echo -e "   - User authentication and JWT token issuance"
    echo -e "   - Admin Console: http://localhost:8082/admin"
    echo -e "\n${GREEN}🔍 OPA (Policy Engine):${NC}"
    echo -e "   - Centralized authorization decisions"
    echo -e "   - Trust level and role-based access control"
    echo -e "   - API: http://localhost:8181"
    echo -e "\n${GREEN}🔀 Envoy Proxy (Policy Enforcement):${NC}"
    echo -e "   - Request interception and OPA integration"
    echo -e "   - Proxy endpoint: http://localhost:10000"
    echo -e "\n${GREEN}🕸️ Istio Service Mesh (Network Security):${NC}"
    echo -e "   - mTLS between services"
    echo -e "   - Network-level policy enforcement"
    echo -e "\n${BLUE}💡 Next Steps:${NC}"
    echo -e "1. Start services: docker-compose up -d"
    echo -e "2. Run integration test: ./test-complete-zerotrust.sh"
    echo -e "3. Test authorization flow with different trust levels"
    echo -e "4. Deploy to Kubernetes with Istio for production"
    echo -e "${CYAN}=============================================${NC}"
}

# Execute main function
main "$@"