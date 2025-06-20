#!/bin/bash

# GitHub Wiki Sync Script (API-based) - Test Version
# Syncs MkDocs documentation to GitHub Wiki using GitHub API

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_OWNER="${REPO_OWNER:-zamaz}"
REPO_NAME="${REPO_NAME:-root-zamaz}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
DOCS_DIR="docs"

echo -e "${BLUE}📚 GitHub Wiki Sync (API) - Test Version${NC}"
echo "=========================================="

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required tools
echo -e "${BLUE}🔍 Checking required tools...${NC}"

if ! command_exists curl; then
    echo -e "${RED}❌ curl is required but not installed${NC}"
    exit 1
fi

if ! command_exists jq; then
    echo -e "${RED}❌ jq is required but not installed${NC}"
    exit 1
fi

if [ -z "$GITHUB_TOKEN" ]; then
    echo -e "${RED}❌ GITHUB_TOKEN environment variable is required${NC}"
    echo -e "${YELLOW}💡 To test with a real token:${NC}"
    echo -e "${YELLOW}   export GITHUB_TOKEN=your_token${NC}"
    echo -e "${YELLOW}   make docs-wiki-sync-api${NC}"
    exit 1
fi

if [ ! -d "$DOCS_DIR" ]; then
    echo -e "${RED}❌ docs directory not found${NC}"
    exit 1
fi

echo -e "${GREEN}✅ All requirements met${NC}"
echo -e "${YELLOW}📊 Repository: ${REPO_OWNER}/${REPO_NAME}${NC}"
echo -e "${YELLOW}📁 Docs directory: ${DOCS_DIR}${NC}"

# Test GitHub API access
echo -e "${BLUE}🔍 Testing GitHub API access...${NC}"
api_response=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}")

if echo "$api_response" | jq -e '.id' >/dev/null 2>&1; then
    repo_name=$(echo "$api_response" | jq -r '.name')
    echo -e "${GREEN}✅ Repository access confirmed: $repo_name${NC}"
else
    echo -e "${RED}❌ Cannot access repository${NC}"
    echo -e "${YELLOW}Response: $(echo "$api_response" | jq -r '.message // "Unknown error"')${NC}"
    exit 1
fi

# Count documentation files
doc_count=$(find "$DOCS_DIR" -name "*.md" -type f | wc -l)
echo -e "${YELLOW}📄 Found $doc_count documentation files${NC}"

# List key files that would be synced
echo -e "${BLUE}🔍 Key files that would be synced:${NC}"

if [ -f "$DOCS_DIR/index.md" ]; then
    echo -e "${GREEN}  ✓ Home page: $DOCS_DIR/index.md${NC}"
fi

if [ -f "$DOCS_DIR/schema/README.md" ]; then
    echo -e "${GREEN}  ✓ Schema overview: $DOCS_DIR/schema/README.md${NC}"
fi

schema_domains=$(find "$DOCS_DIR/schema" -name "*-domain.md" 2>/dev/null | wc -l)
if [ "$schema_domains" -gt 0 ]; then
    echo -e "${GREEN}  ✓ Schema domains: $schema_domains files${NC}"
fi

if [ -f "$DOCS_DIR/api/README.md" ]; then
    echo -e "${GREEN}  ✓ API documentation: $DOCS_DIR/api/README.md${NC}"
fi

arch_files=$(find "$DOCS_DIR/architecture" -name "*.md" 2>/dev/null | wc -l)
if [ "$arch_files" -gt 0 ]; then
    echo -e "${GREEN}  ✓ Architecture docs: $arch_files files${NC}"
fi

dev_files=$(find "$DOCS_DIR/development" -name "*.md" 2>/dev/null | wc -l)
if [ "$dev_files" -gt 0 ]; then
    echo -e "${GREEN}  ✓ Development docs: $dev_files files${NC}"
fi

echo ""
echo -e "${GREEN}🎉 Wiki sync test completed successfully!${NC}"
echo -e "${BLUE}📍 Wiki would be available at: https://github.com/${REPO_OWNER}/${REPO_NAME}/wiki${NC}"
echo ""
echo -e "${YELLOW}💡 To perform actual sync:${NC}"
echo -e "${YELLOW}   1. Enable wiki in repository settings${NC}"
echo -e "${YELLOW}   2. Create at least one wiki page manually${NC}"
echo -e "${YELLOW}   3. Run: make docs-wiki-sync-api${NC}"