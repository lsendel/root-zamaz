#!/bin/bash

# Consul Setup and Configuration Script for MVP Zero Trust Auth
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CONSUL_URL="${CONSUL_URL:-http://localhost:8500}"
CONSUL_DATACENTER="${CONSUL_DATACENTER:-dc1}"
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

# Wait for Consul to be ready
wait_for_consul() {
    log "Waiting for Consul to be ready..."
    for i in {1..30}; do
        if curl -f -s "${CONSUL_URL}/v1/status/leader" > /dev/null 2>&1; then
            success "Consul is ready!"
            return 0
        fi
        echo -n "."
        sleep 2
    done
    error "Consul failed to start within 60 seconds"
    return 1
}

# Configure Consul ACLs (if enabled)
setup_acls() {
    log "Setting up Consul ACLs..."
    
    # Check if ACLs are enabled
    acl_status=$(curl -s "${CONSUL_URL}/v1/acl/bootstrap" | jq -r '.SecretID // empty' 2>/dev/null || echo "")
    
    if [[ -n "$acl_status" ]]; then
        log "ACLs already bootstrapped"
        return 0
    fi
    
    # Bootstrap ACLs (commented out for development)
    warn "ACLs are disabled in development mode"
    warn "For production, enable ACLs in consul.hcl and run bootstrap"
}

# Create service definitions
create_service_definitions() {
    log "Creating service definitions..."
    
    # MVP Auth API Service
    curl -s -X PUT "${CONSUL_URL}/v1/agent/service/register" \
        -H "Content-Type: application/json" \
        -d '{
            "ID": "mvp-auth-api",
            "Name": "mvp-auth-api",
            "Tags": ["api", "auth", "mvp", "go", "fiber"],
            "Address": "host.docker.internal",
            "Port": 8080,
            "Meta": {
                "version": "1.0.0",
                "environment": "development",
                "project": "mvp-zero-trust-auth",
                "namespace": "zamaz"
            },
            "Check": {
                "HTTP": "http://host.docker.internal:8080/health",
                "Interval": "10s",
                "Timeout": "3s",
                "DeregisterCriticalServiceAfter": "60s"
            }
        }' | jq '.'
    
    # Frontend Service
    curl -s -X PUT "${CONSUL_URL}/v1/agent/service/register" \
        -H "Content-Type: application/json" \
        -d '{
            "ID": "mvp-auth-frontend",
            "Name": "mvp-auth-frontend",
            "Tags": ["frontend", "react", "mvp", "ui"],
            "Address": "host.docker.internal",
            "Port": 3000,
            "Meta": {
                "version": "1.0.0",
                "environment": "development",
                "project": "mvp-zero-trust-auth",
                "namespace": "zamaz"
            },
            "Check": {
                "HTTP": "http://host.docker.internal:3000",
                "Interval": "15s",
                "Timeout": "5s",
                "DeregisterCriticalServiceAfter": "90s"
            }
        }' | jq '.'
    
    # Database Service
    curl -s -X PUT "${CONSUL_URL}/v1/agent/service/register" \
        -H "Content-Type: application/json" \
        -d '{
            "ID": "mvp-postgres",
            "Name": "postgres",
            "Tags": ["database", "postgres", "mvp"],
            "Address": "host.docker.internal",
            "Port": 5432,
            "Meta": {
                "version": "15",
                "environment": "development",
                "project": "mvp-zero-trust-auth",
                "namespace": "zamaz"
            },
            "Check": {
                "TCP": "host.docker.internal:5432",
                "Interval": "10s",
                "Timeout": "3s",
                "DeregisterCriticalServiceAfter": "60s"
            }
        }' | jq '.'
    
    # Redis Service
    curl -s -X PUT "${CONSUL_URL}/v1/agent/service/register" \
        -H "Content-Type: application/json" \
        -d '{
            "ID": "mvp-redis",
            "Name": "redis",
            "Tags": ["cache", "redis", "mvp"],
            "Address": "host.docker.internal",
            "Port": 6379,
            "Meta": {
                "version": "7",
                "environment": "development",
                "project": "mvp-zero-trust-auth",
                "namespace": "zamaz"
            },
            "Check": {
                "TCP": "host.docker.internal:6379",
                "Interval": "10s",
                "Timeout": "3s",
                "DeregisterCriticalServiceAfter": "60s"
            }
        }' | jq '.'
    
    success "Service definitions created"
}

# Create KV store configurations
setup_kv_store() {
    log "Setting up KV store configurations..."
    
    # Service discovery configuration
    curl -s -X PUT "${CONSUL_URL}/v1/kv/mvp-zero-trust-auth/config/service-discovery" \
        -d '{
            "provider": "consul",
            "consul": {
                "address": "localhost:8500",
                "datacenter": "dc1",
                "health_check_interval": "10s",
                "deregister_after": "60s"
            },
            "load_balancer": {
                "strategy": "round_robin",
                "health_check": true,
                "circuit_breaker": true
            }
        }'
    
    # Environment-specific configurations
    curl -s -X PUT "${CONSUL_URL}/v1/kv/mvp-zero-trust-auth/config/development/database" \
        -d '{
            "host": "localhost",
            "port": 5432,
            "database": "mvp_db",
            "username": "mvp_user",
            "ssl_mode": "disable",
            "max_connections": 25,
            "max_idle_connections": 5
        }'
    
    curl -s -X PUT "${CONSUL_URL}/v1/kv/mvp-zero-trust-auth/config/development/redis" \
        -d '{
            "address": "localhost:6379",
            "password": "",
            "database": 0,
            "pool_size": 10,
            "max_retries": 3
        }'
    
    # Feature flags
    curl -s -X PUT "${CONSUL_URL}/v1/kv/mvp-zero-trust-auth/features/consul-discovery" -d "true"
    curl -s -X PUT "${CONSUL_URL}/v1/kv/mvp-zero-trust-auth/features/load-balancing" -d "true"
    curl -s -X PUT "${CONSUL_URL}/v1/kv/mvp-zero-trust-auth/features/circuit-breaker" -d "true"
    curl -s -X PUT "${CONSUL_URL}/v1/kv/mvp-zero-trust-auth/features/health-monitoring" -d "true"
    
    success "KV store configurations created"
}

# Setup service intentions (Connect/Service Mesh)
setup_service_intentions() {
    log "Setting up service intentions for Connect..."
    
    # Allow API to access database
    curl -s -X PUT "${CONSUL_URL}/v1/connect/intentions" \
        -H "Content-Type: application/json" \
        -d '{
            "SourceName": "mvp-auth-api",
            "DestinationName": "postgres",
            "Action": "allow",
            "Description": "Allow API access to database"
        }' | jq '.'
    
    # Allow API to access Redis
    curl -s -X PUT "${CONSUL_URL}/v1/connect/intentions" \
        -H "Content-Type: application/json" \
        -d '{
            "SourceName": "mvp-auth-api",
            "DestinationName": "redis",
            "Action": "allow",
            "Description": "Allow API access to Redis cache"
        }' | jq '.'
    
    # Allow frontend to access API
    curl -s -X PUT "${CONSUL_URL}/v1/connect/intentions" \
        -H "Content-Type: application/json" \
        -d '{
            "SourceName": "mvp-auth-frontend",
            "DestinationName": "mvp-auth-api",
            "Action": "allow",
            "Description": "Allow frontend access to API"
        }' | jq '.'
    
    success "Service intentions configured"
}

# Create health checks and monitoring
setup_monitoring() {
    log "Setting up monitoring configurations..."
    
    # Global health check configuration
    curl -s -X PUT "${CONSUL_URL}/v1/kv/mvp-zero-trust-auth/monitoring/health-checks" \
        -d '{
            "default_interval": "10s",
            "default_timeout": "3s",
            "default_deregister_after": "60s",
            "critical_threshold": 3,
            "warning_threshold": 1
        }'
    
    # Service-specific monitoring
    curl -s -X PUT "${CONSUL_URL}/v1/kv/mvp-zero-trust-auth/monitoring/services/api" \
        -d '{
            "health_endpoint": "/health",
            "metrics_endpoint": "/metrics",
            "readiness_endpoint": "/ready",
            "liveness_endpoint": "/health",
            "check_interval": "10s"
        }'
    
    success "Monitoring configurations created"
}

# Display service information
show_service_info() {
    log "Consul setup completed successfully!"
    echo ""
    echo "🔗 Consul UI: ${CONSUL_URL}/ui"
    echo "📊 Service Catalog: ${CONSUL_URL}/ui/dc1/services"
    echo "🗂️  KV Store: ${CONSUL_URL}/ui/dc1/kv"
    echo "🔒 Service Intentions: ${CONSUL_URL}/ui/dc1/intentions"
    echo ""
    log "Registered services:"
    curl -s "${CONSUL_URL}/v1/agent/services" | jq -r 'to_entries[] | "  - \(.value.Service) (\(.value.ID)) - \(.value.Address):\(.value.Port)"'
    echo ""
    log "KV store entries:"
    curl -s "${CONSUL_URL}/v1/kv/mvp-zero-trust-auth/?recurse" | jq -r '.[] | "  - \(.Key)"'
}

# Main execution
main() {
    log "Starting Consul setup for ${PROJECT_NAME}..."
    
    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        error "jq is required but not installed. Please install jq first."
        return 1
    fi
    
    # Start Consul if not running
    if ! curl -f -s "${CONSUL_URL}/v1/status/leader" > /dev/null 2>&1; then
        log "Starting Consul..."
        docker-compose -f docker-compose.consul.yml up -d
        wait_for_consul
    else
        success "Consul is already running"
    fi
    
    # Setup components
    setup_acls
    create_service_definitions
    setup_kv_store
    setup_service_intentions
    setup_monitoring
    
    # Show information
    show_service_info
    
    success "Consul setup completed!"
    log "You can now configure your application to use Consul for service discovery"
}

# Run main function
main "$@"