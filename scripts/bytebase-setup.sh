#!/bin/bash

# Bytebase Setup and Configuration Script
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BYTEBASE_URL="${BYTEBASE_URL:-http://localhost:5678}"
BYTEBASE_USER="${BYTEBASE_USER:-admin@bytebase.com}"
BYTEBASE_PASSWORD="${BYTEBASE_PASSWORD:-admin}"
PROJECT_NAME="MVP Zero Trust Auth"
PROJECT_KEY="mvp-zero-trust-auth"

log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Wait for Bytebase to be ready
wait_for_bytebase() {
    log "Waiting for Bytebase to be ready..."
    for i in {1..30}; do
        if curl -f -s "${BYTEBASE_URL}/healthz" > /dev/null 2>&1; then
            success "Bytebase is ready!"
            return 0
        fi
        echo -n "."
        sleep 2
    done
    error "Bytebase failed to start within 60 seconds"
    return 1
}

# Get authentication token
get_auth_token() {
    log "Authenticating with Bytebase..."
    
    local response
    response=$(curl -s -X POST "${BYTEBASE_URL}/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{
            \"email\": \"${BYTEBASE_USER}\",
            \"password\": \"${BYTEBASE_PASSWORD}\"
        }")
    
    local token
    token=$(echo "$response" | jq -r '.token // empty')
    
    if [[ -z "$token" ]]; then
        error "Failed to authenticate with Bytebase"
        echo "Response: $response"
        return 1
    fi
    
    echo "$token"
}

# Create project
create_project() {
    local token="$1"
    
    log "Creating project: $PROJECT_NAME"
    
    curl -s -X POST "${BYTEBASE_URL}/v1/projects" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "{
            \"project\": {
                \"name\": \"projects/${PROJECT_KEY}\",
                \"title\": \"${PROJECT_NAME}\",
                \"key\": \"${PROJECT_KEY}\",
                \"workflow\": \"VCS\"
            }
        }" | jq '.'
}

# Create environments
create_environments() {
    local token="$1"
    
    log "Creating environments..."
    
    # Development environment
    curl -s -X POST "${BYTEBASE_URL}/v1/environments" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d '{
            "environment": {
                "name": "environments/dev",
                "title": "Development",
                "order": 0,
                "tier": "UNPROTECTED"
            }
        }' | jq '.'
    
    # Staging environment
    curl -s -X POST "${BYTEBASE_URL}/v1/environments" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d '{
            "environment": {
                "name": "environments/staging",
                "title": "Staging",
                "order": 1,
                "tier": "PROTECTED"
            }
        }' | jq '.'
    
    # Production environment
    curl -s -X POST "${BYTEBASE_URL}/v1/environments" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d '{
            "environment": {
                "name": "environments/prod",
                "title": "Production",
                "order": 2,
                "tier": "CRITICAL"
            }
        }' | jq '.'
}

# Create database instances
create_instances() {
    local token="$1"
    
    log "Creating database instances..."
    
    # Development instance
    curl -s -X POST "${BYTEBASE_URL}/v1/instances" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d '{
            "instance": {
                "name": "instances/dev-postgres",
                "title": "Development PostgreSQL",
                "engine": "POSTGRES",
                "externalLink": "",
                "dataSources": [{
                    "type": "ADMIN",
                    "host": "localhost",
                    "port": "5432",
                    "username": "mvp_user",
                    "database": "mvp_db",
                    "sslCa": "",
                    "sslCert": "",
                    "sslKey": ""
                }],
                "environment": "environments/dev"
            }
        }' | jq '.'
}

# Configure VCS integration
configure_vcs() {
    local token="$1"
    
    log "Configuring VCS integration..."
    
    # Note: This would require actual VCS provider setup
    warn "VCS integration requires manual configuration in Bytebase UI"
    warn "Please configure the following in the Bytebase UI:"
    echo "  1. Go to Settings > Version Control"
    echo "  2. Add your Git repository"
    echo "  3. Configure branch and file path templates"
    echo "  4. Link project to VCS"
}

# Setup SQL Review policies
setup_sql_review() {
    local token="$1"
    
    log "Setting up SQL Review policies..."
    
    curl -s -X POST "${BYTEBASE_URL}/v1/policies" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d '{
            "policy": {
                "name": "environments/prod/policies/sql-review",
                "type": "SQL_REVIEW",
                "sqlReviewPolicy": {
                    "ruleList": [
                        {
                            "type": "naming.table.snake_case",
                            "level": "ERROR"
                        },
                        {
                            "type": "naming.column.snake_case", 
                            "level": "ERROR"
                        },
                        {
                            "type": "statement.select.no_select_all",
                            "level": "WARNING"
                        },
                        {
                            "type": "statement.where.require",
                            "level": "ERROR"
                        }
                    ]
                }
            }
        }' | jq '.'
}

# Main execution
main() {
    log "Starting Bytebase setup..."
    
    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        error "jq is required but not installed. Please install jq first."
        return 1
    fi
    
    # Start Bytebase if not running
    if ! curl -f -s "${BYTEBASE_URL}/healthz" > /dev/null 2>&1; then
        log "Starting Bytebase..."
        docker-compose -f docker-compose.bytebase.yml up -d
        wait_for_bytebase
    else
        success "Bytebase is already running"
    fi
    
    # Get authentication token
    local token
    token=$(get_auth_token)
    
    if [[ -z "$token" ]]; then
        error "Failed to get authentication token"
        return 1
    fi
    
    success "Successfully authenticated with Bytebase"
    
    # Setup Bytebase components
    create_environments "$token"
    create_project "$token"
    create_instances "$token"
    setup_sql_review "$token"
    configure_vcs "$token"
    
    success "Bytebase setup completed!"
    log "Access Bytebase at: ${BYTEBASE_URL}"
    log "Default credentials: ${BYTEBASE_USER} / ${BYTEBASE_PASSWORD}"
}

# Run main function
main "$@"