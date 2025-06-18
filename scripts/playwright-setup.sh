#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "Makefile" ] || [ ! -d "frontend" ]; then
    print_error "This script must be run from the project root directory"
    exit 1
fi

# Check if backend services are running
check_backend_services() {
    print_status "Checking backend services..."
    
    # Check if API is responsive
    if curl -f -s http://localhost:8080/health > /dev/null 2>&1; then
        print_success "Backend API is running"
    else
        print_warning "Backend API is not running. Starting services..."
        make dev-up
        
        # Wait for services to be ready
        print_status "Waiting for services to start..."
        local attempts=0
        while ! curl -f -s http://localhost:8080/health > /dev/null 2>&1; do
            attempts=$((attempts + 1))
            if [ $attempts -gt 30 ]; then
                print_error "Backend services failed to start after 30 seconds"
                exit 1
            fi
            sleep 1
            printf "."
        done
        echo ""
        print_success "Backend services are ready"
    fi
}

# Check if frontend is running
check_frontend() {
    print_status "Checking frontend..."
    
    if curl -f -s http://localhost:5175 > /dev/null 2>&1 || curl -f -s http://localhost:5173 > /dev/null 2>&1; then
        print_success "Frontend is running"
    else
        print_warning "Frontend is not running. You may want to run 'make dev-frontend' in another terminal"
    fi
}

# Install Playwright browsers if needed
install_playwright_browsers() {
    print_status "Checking Playwright browsers..."
    
    cd frontend
    
    if [ ! -d "node_modules/@playwright/test" ]; then
        print_error "Playwright is not installed. Run 'make frontend-install' first"
        exit 1
    fi
    
    # Check if browsers are installed
    if ! npx playwright install --help > /dev/null 2>&1; then
        print_status "Installing Playwright browsers..."
        npx playwright install
        print_success "Playwright browsers installed"
    else
        # Check if browsers need updating
        print_status "Checking Playwright browser versions..."
        npx playwright install
    fi
    
    cd ..
}

# Show test URLs
show_test_info() {
    echo ""
    echo "========================================="
    echo "        E2E Test Environment Ready       "
    echo "========================================="
    echo "Backend API: http://localhost:8080"
    echo "Frontend:    http://localhost:5175"
    echo "Grafana:     http://localhost:3000"
    echo "Jaeger:      http://localhost:16686"
    echo ""
    echo "Test Credentials:"
    echo "  Username: admin"
    echo "  Password: password"
    echo "========================================="
    echo ""
}

# Main function
main() {
    print_status "Setting up Playwright E2E test environment..."
    
    # Check backend services
    check_backend_services
    
    # Check frontend
    check_frontend
    
    # Install Playwright browsers
    install_playwright_browsers
    
    # Show test information
    show_test_info
    
    print_success "E2E test environment is ready!"
    print_status "You can now run: make test-e2e"
}

# Run main function
main "$@"