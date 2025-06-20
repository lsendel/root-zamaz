#!/bin/bash

# Complete documentation generation script
# Generates schema docs, API docs, and builds MkDocs

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}📚 Generating Complete Documentation${NC}"
echo "===================================="

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to run step with logging
run_step() {
    local step_name="$1"
    local command="$2"
    
    echo -e "${YELLOW}🔄 ${step_name}...${NC}"
    
    if eval "$command"; then
        echo -e "${GREEN}✅ ${step_name} completed${NC}"
    else
        echo -e "${RED}❌ ${step_name} failed${NC}"
        exit 1
    fi
}

# Check for required tools
echo -e "${BLUE}🔍 Checking required tools...${NC}"

if ! command_exists make; then
    echo -e "${RED}❌ make is required but not installed${NC}"
    exit 1
fi

if ! command_exists python3; then
    echo -e "${RED}❌ Python 3 is required but not installed${NC}"
    exit 1
fi

# Generate documentation components
run_step "Installing tbls CLI" "make install-tbls"

# Only generate schema docs if database is available
if make docs-schema >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Schema documentation generated${NC}"
else
    echo -e "${YELLOW}⚠️  Database unavailable, using existing schema documentation${NC}"
fi

run_step "Generating API documentation" "make docs-generate"
run_step "Building MkDocs documentation" "make docs-mkdocs-build"

echo ""
echo -e "${GREEN}🎉 Documentation generation complete!${NC}"
echo -e "${BLUE}📍 Documentation available at: file://$(pwd)/site/index.html${NC}"
echo ""
echo -e "${YELLOW}💡 To serve locally, run: make docs-mkdocs-serve${NC}"
echo -e "${YELLOW}💡 To deploy to GitHub Pages, push to main branch${NC}"