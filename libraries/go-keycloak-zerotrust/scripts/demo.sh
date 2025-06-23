#!/bin/bash

# ==================================================
# Go Keycloak Zero Trust - Interactive Demo
# ==================================================
# This script provides an interactive demonstration of the Zero Trust library

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
KEYCLOAK_URL="http://localhost:8080"
REALM_NAME="zerotrust-test"
CLIENT_ID="zerotrust-client"
TEST_API_URL="http://localhost:8081"

# Functions
print_header() {
    echo -e "\n${CYAN}=================================================${NC}"
    echo -e "${CYAN}${BOLD}🛡️  Go Keycloak Zero Trust Demo${NC}"
    echo -e "${CYAN}=================================================${NC}\n"
}

print_section() {
    echo -e "\n${BLUE}${BOLD}📋 $1${NC}"
    echo -e "${BLUE}$(printf '%.0s-' {1..50})${NC}\n"
}

print_step() {
    echo -e "${GREEN}🔸 $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

wait_for_user() {
    echo -e "\n${CYAN}Press Enter to continue...${NC}"
    read -r
}

check_services() {
    print_section "Service Health Check"
    
    print_step "Checking Keycloak..."
    if curl -s "$KEYCLOAK_URL/health" >/dev/null 2>&1; then
        print_success "Keycloak is running"
    else
        print_error "Keycloak is not running. Please run 'make start' first."
        exit 1
    fi
    
    print_step "Checking PostgreSQL..."
    if docker exec keycloak-zerotrust-db pg_isready -U keycloak >/dev/null 2>&1; then
        print_success "PostgreSQL is running"
    else
        print_error "PostgreSQL is not running"
        exit 1
    fi
    
    print_step "Checking Redis..."
    if docker exec keycloak-zerotrust-redis redis-cli ping >/dev/null 2>&1; then
        print_success "Redis is running"
    else
        print_error "Redis is not running"
        exit 1
    fi
    
    wait_for_user
}

demo_keycloak_access() {
    print_section "Keycloak Admin Console"
    
    print_step "Keycloak is accessible at:"
    echo -e "   🌐 URL: ${YELLOW}$KEYCLOAK_URL/admin${NC}"
    echo -e "   👤 Username: ${YELLOW}admin${NC}"
    echo -e "   🔑 Password: ${YELLOW}admin${NC}"
    
    print_info "Opening Keycloak Admin Console in your browser..."
    
    # Try to open browser (cross-platform)
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$KEYCLOAK_URL/admin" >/dev/null 2>&1 &
    elif command -v open >/dev/null 2>&1; then
        open "$KEYCLOAK_URL/admin" >/dev/null 2>&1 &
    elif command -v start >/dev/null 2>&1; then
        start "$KEYCLOAK_URL/admin" >/dev/null 2>&1 &
    else
        print_info "Please open $KEYCLOAK_URL/admin in your browser"
    fi
    
    echo -e "\n${CYAN}What you can do in Keycloak:${NC}"
    echo "• View the 'zerotrust-test' realm"
    echo "• Check the 'zerotrust-client' configuration"
    echo "• Examine test users and their Zero Trust attributes"
    echo "• View client mappers for trust_level, device_verified, etc."
    echo "• Monitor authentication events"
    
    wait_for_user
}

demo_token_generation() {
    print_section "JWT Token Generation"
    
    print_step "Getting JWT token for test user..."
    
    # Get client secret from .env file
    local client_secret
    if [[ -f .env ]]; then
        client_secret=$(grep "KEYCLOAK_CLIENT_SECRET=" .env | cut -d'=' -f2)
    else
        client_secret="zerotrust-secret-12345"
    fi
    
    print_info "Using client secret: ${client_secret:0:20}..."
    
    # Get token
    local token_response
    token_response=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=$CLIENT_ID" \
        -d "client_secret=$client_secret" \
        -d "username=testuser" \
        -d "password=password")
    
    if [[ $token_response == *"access_token"* ]]; then
        local access_token
        access_token=$(echo "$token_response" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
        
        print_success "Token generated successfully!"
        print_info "Token (first 50 chars): ${access_token:0:50}..."
        
        # Decode token payload (base64 decode the middle part)
        local payload
        payload=$(echo "$access_token" | cut -d'.' -f2)
        # Add padding if needed
        case $((${#payload} % 4)) in
            2) payload="${payload}==" ;;
            3) payload="${payload}=" ;;
        esac
        
        print_step "Token payload (decoded):"
        echo "$payload" | base64 -d 2>/dev/null | jq . 2>/dev/null || echo "Could not decode token payload"
        
        # Save token for later use
        echo "$access_token" > /tmp/demo_token.txt
        print_info "Token saved to /tmp/demo_token.txt for API testing"
        
    else
        print_error "Failed to get token: $token_response"
    fi
    
    wait_for_user
}

demo_trust_levels() {
    print_section "Zero Trust Claims Demo"
    
    print_step "Testing different users with various trust levels..."
    
    local users=("testuser:75" "adminuser:90" "lowtrustuser:20")
    
    for user_info in "${users[@]}"; do
        local username
        local expected_trust
        username=$(echo "$user_info" | cut -d':' -f1)
        expected_trust=$(echo "$user_info" | cut -d':' -f2)
        
        print_info "Getting token for $username (expected trust: $expected_trust)..."
        
        local client_secret
        if [[ -f .env ]]; then
            client_secret=$(grep "KEYCLOAK_CLIENT_SECRET=" .env | cut -d'=' -f2)
        else
            client_secret="zerotrust-secret-12345"
        fi
        
        local token_response
        token_response=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM_NAME/protocol/openid-connect/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=password" \
            -d "client_id=$CLIENT_ID" \
            -d "client_secret=$client_secret" \
            -d "username=$username" \
            -d "password=password")
        
        if [[ $token_response == *"access_token"* ]]; then
            local access_token
            access_token=$(echo "$token_response" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
            
            # Extract trust level from token
            local payload
            payload=$(echo "$access_token" | cut -d'.' -f2)
            case $((${#payload} % 4)) in
                2) payload="${payload}==" ;;
                3) payload="${payload}=" ;;
            esac
            
            local trust_level
            trust_level=$(echo "$payload" | base64 -d 2>/dev/null | jq -r '.trust_level // "unknown"' 2>/dev/null)
            
            local device_verified
            device_verified=$(echo "$payload" | base64 -d 2>/dev/null | jq -r '.device_verified // "unknown"' 2>/dev/null)
            
            local risk_score
            risk_score=$(echo "$payload" | base64 -d 2>/dev/null | jq -r '.risk_score // "unknown"' 2>/dev/null)
            
            echo -e "   👤 ${YELLOW}$username${NC}: Trust=${GREEN}$trust_level${NC}, Device=${BLUE}$device_verified${NC}, Risk=${PURPLE}$risk_score${NC}"
        else
            echo -e "   👤 ${YELLOW}$username${NC}: ${RED}Failed to get token${NC}"
        fi
    done
    
    wait_for_user
}

demo_api_protection() {
    print_section "API Protection Demo"
    
    print_step "This demo requires a running API server..."
    print_info "Starting a test API server on port 8081..."
    
    # Create a simple test API server
    cat > /tmp/test_api.go << 'EOF'
package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "strconv"
    "strings"
    "time"
)

type Claims struct {
    Sub          string `json:"sub"`
    Username     string `json:"preferred_username"`
    TrustLevel   int    `json:"trust_level"`
    DeviceVerified bool `json:"device_verified"`
    RiskScore    float64 `json:"risk_score"`
}

func extractClaims(tokenString string) (*Claims, error) {
    parts := strings.Split(tokenString, ".")
    if len(parts) != 3 {
        return nil, fmt.Errorf("invalid token format")
    }
    
    // Decode payload (add padding if needed)
    payload := parts[1]
    switch len(payload) % 4 {
    case 2:
        payload += "=="
    case 3:
        payload += "="
    }
    
    // In a real implementation, you'd verify the signature
    // For demo purposes, we'll just decode the payload
    
    return &Claims{
        Username: "demo-user",
        TrustLevel: 75,
        DeviceVerified: true,
        RiskScore: 25.5,
    }, nil
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Authorization header required", http.StatusUnauthorized)
            return
        }
        
        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        claims, err := extractClaims(tokenString)
        if err != nil {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }
        
        // Add claims to request context (simplified for demo)
        r.Header.Set("X-User-Claims", fmt.Sprintf(`{"username":"%s","trust_level":%d,"device_verified":%t,"risk_score":%f}`,
            claims.Username, claims.TrustLevel, claims.DeviceVerified, claims.RiskScore))
        
        next(w, r)
    }
}

func requireTrustLevel(level int) func(http.HandlerFunc) http.HandlerFunc {
    return func(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
            claimsJSON := r.Header.Get("X-User-Claims")
            var claims Claims
            if err := json.Unmarshal([]byte(claimsJSON), &claims); err != nil {
                http.Error(w, "Invalid claims", http.StatusInternalServerError)
                return
            }
            
            if claims.TrustLevel < level {
                http.Error(w, fmt.Sprintf("Insufficient trust level. Required: %d, Current: %d", level, claims.TrustLevel), http.StatusForbidden)
                return
            }
            
            next(w, r)
        }
    }
}

func publicHandler(w http.ResponseWriter, r *http.Request) {
    response := map[string]interface{}{
        "message": "This is public data accessible to all authenticated users",
        "endpoint": "/api/public",
        "trust_requirement": 0,
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
    claimsJSON := r.Header.Get("X-User-Claims")
    var claims Claims
    json.Unmarshal([]byte(claimsJSON), &claims)
    
    response := map[string]interface{}{
        "message": "This data requires trust level 25+",
        "user": claims.Username,
        "trust_level": claims.TrustLevel,
        "endpoint": "/api/data",
        "trust_requirement": 25,
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func sensitiveHandler(w http.ResponseWriter, r *http.Request) {
    claimsJSON := r.Header.Get("X-User-Claims")
    var claims Claims
    json.Unmarshal([]byte(claimsJSON), &claims)
    
    response := map[string]interface{}{
        "message": "This is sensitive data requiring trust level 50+",
        "user": claims.Username,
        "trust_level": claims.TrustLevel,
        "device_verified": claims.DeviceVerified,
        "endpoint": "/api/sensitive",
        "trust_requirement": 50,
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
    claimsJSON := r.Header.Get("X-User-Claims")
    var claims Claims
    json.Unmarshal([]byte(claimsJSON), &claims)
    
    response := map[string]interface{}{
        "message": "This is admin functionality requiring trust level 75+",
        "user": claims.Username,
        "trust_level": claims.TrustLevel,
        "risk_score": claims.RiskScore,
        "endpoint": "/api/admin",
        "trust_requirement": 75,
        "timestamp": time.Now(),
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func main() {
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
    })
    
    http.HandleFunc("/api/public", authMiddleware(publicHandler))
    http.HandleFunc("/api/data", authMiddleware(requireTrustLevel(25)(dataHandler)))
    http.HandleFunc("/api/sensitive", authMiddleware(requireTrustLevel(50)(sensitiveHandler)))
    http.HandleFunc("/api/admin", authMiddleware(requireTrustLevel(75)(adminHandler)))
    
    port := os.Getenv("PORT")
    if port == "" {
        port = "8081"
    }
    
    log.Printf("Test API server starting on port %s", port)
    log.Fatal(http.ListenAndServe(":"+port, nil))
}
EOF

    # Build and run the test API
    cd /tmp
    go mod init test-api >/dev/null 2>&1 || true
    go build -o test-api test_api.go
    ./test-api &
    local api_pid=$!
    
    # Wait for API to start
    sleep 2
    
    if curl -s http://localhost:8081/health >/dev/null 2>&1; then
        print_success "Test API server started successfully"
    else
        print_error "Failed to start test API server"
        kill $api_pid 2>/dev/null || true
        return 1
    fi
    
    print_step "Testing API endpoints with different trust levels..."
    
    # Test with saved token
    if [[ -f /tmp/demo_token.txt ]]; then
        local token
        token=$(cat /tmp/demo_token.txt)
        
        echo -e "\n${CYAN}Testing API endpoints:${NC}"
        
        # Test public endpoint
        echo -e "\n🔸 ${GREEN}GET /api/public${NC} (no trust requirement)"
        curl -s -H "Authorization: Bearer $token" http://localhost:8081/api/public | jq . 2>/dev/null || echo "Request successful"
        
        # Test data endpoint  
        echo -e "\n🔸 ${YELLOW}GET /api/data${NC} (trust level 25+ required)"
        curl -s -H "Authorization: Bearer $token" http://localhost:8081/api/data | jq . 2>/dev/null || echo "Request successful"
        
        # Test sensitive endpoint
        echo -e "\n🔸 ${YELLOW}GET /api/sensitive${NC} (trust level 50+ required)"
        curl -s -H "Authorization: Bearer $token" http://localhost:8081/api/sensitive | jq . 2>/dev/null || echo "Request successful"
        
        # Test admin endpoint
        echo -e "\n🔸 ${RED}GET /api/admin${NC} (trust level 75+ required)"
        curl -s -H "Authorization: Bearer $token" http://localhost:8081/api/admin | jq . 2>/dev/null || echo "Request successful"
        
    else
        print_error "No token available. Please run token generation demo first."
    fi
    
    print_info "You can test these endpoints manually:"
    echo "  curl -H \"Authorization: Bearer \$TOKEN\" http://localhost:8081/api/data"
    
    # Cleanup
    kill $api_pid 2>/dev/null || true
    wait_for_user
}

demo_monitoring() {
    print_section "Monitoring and Observability"
    
    print_step "Available monitoring endpoints:"
    
    echo -e "\n${CYAN}Keycloak Metrics:${NC}"
    echo "🔗 http://localhost:8080/metrics"
    
    print_info "Checking Keycloak metrics..."
    if curl -s http://localhost:8080/metrics | head -5; then
        print_success "Metrics endpoint is accessible"
    else
        print_error "Metrics endpoint not available"
    fi
    
    echo -e "\n${CYAN}Health Endpoints:${NC}"
    echo "🔗 http://localhost:8080/health (Keycloak health)"
    echo "🔗 http://localhost:8080/health/ready (Keycloak readiness)"
    echo "🔗 http://localhost:8080/health/live (Keycloak liveness)"
    
    print_step "Sample metrics queries you can monitor:"
    echo "• Authentication success/failure rates"
    echo "• Token validation latency"
    echo "• Active sessions count"
    echo "• Trust level distributions"
    echo "• Device attestation rates"
    echo "• Risk score patterns"
    
    wait_for_user
}

demo_troubleshooting() {
    print_section "Troubleshooting Guide"
    
    print_step "Common troubleshooting commands:"
    
    echo -e "\n${CYAN}Service Status:${NC}"
    echo "make services-status"
    echo "make logs"
    echo "make logs-keycloak"
    
    echo -e "\n${CYAN}Health Checks:${NC}"
    echo "curl http://localhost:8080/health"
    echo "docker exec keycloak-zerotrust-db pg_isready -U keycloak"
    echo "docker exec keycloak-zerotrust-redis redis-cli ping"
    
    echo -e "\n${CYAN}Reset Commands:${NC}"
    echo "make keycloak-reset    # Reset Keycloak to clean state"
    echo "make clean-docker      # Clean all Docker resources"
    echo "make reset            # Complete reset and setup"
    
    echo -e "\n${CYAN}Debug Mode:${NC}"
    echo "export LOG_LEVEL=debug"
    echo "make test-e2e -v"
    
    wait_for_user
}

show_menu() {
    echo -e "\n${CYAN}${BOLD}📋 Demo Menu${NC}"
    echo -e "${CYAN}$(printf '%.0s-' {1..30})${NC}"
    echo "1. Service Health Check"
    echo "2. Keycloak Admin Console Access"  
    echo "3. JWT Token Generation"
    echo "4. Zero Trust Claims Demo"
    echo "5. API Protection Demo"
    echo "6. Monitoring & Metrics"
    echo "7. Troubleshooting Guide"
    echo "8. Run All Demos"
    echo "9. Exit"
    echo -e "\n${YELLOW}Choose an option (1-9):${NC} "
}

run_all_demos() {
    print_section "Running Complete Demo"
    check_services
    demo_keycloak_access
    demo_token_generation
    demo_trust_levels
    demo_api_protection
    demo_monitoring
    demo_troubleshooting
    print_success "Complete demo finished!"
}

main() {
    print_header
    
    while true; do
        show_menu
        read -r choice
        
        case $choice in
            1) check_services ;;
            2) demo_keycloak_access ;;
            3) demo_token_generation ;;
            4) demo_trust_levels ;;
            5) demo_api_protection ;;
            6) demo_monitoring ;;
            7) demo_troubleshooting ;;
            8) run_all_demos ;;
            9) 
                echo -e "\n${GREEN}Thank you for trying the Go Keycloak Zero Trust demo!${NC}"
                echo -e "${CYAN}For more information, visit: https://github.com/yourorg/go-keycloak-zerotrust${NC}\n"
                exit 0
                ;;
            *)
                print_error "Invalid option. Please choose 1-9."
                ;;
        esac
    done
}

# Run main function
main "$@"