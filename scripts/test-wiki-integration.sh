#!/bin/bash

# Wiki Integration Testing Script
# Combines automated testing with manual verification steps

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🧪 Wiki Integration Test Suite${NC}"
echo "====================================="

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check URL accessibility
check_url() {
    local url="$1"
    local description="$2"
    
    echo -e "${YELLOW}🔍 Checking: $description${NC}"
    
    if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q "200\|302"; then
        echo -e "${GREEN}✅ $description - Accessible${NC}"
        return 0
    else
        echo -e "${RED}❌ $description - Not accessible${NC}"
        return 1
    fi
}

# Pre-flight checks
echo -e "${YELLOW}📋 Pre-flight checks...${NC}"

if ! command_exists npx; then
    echo -e "${RED}❌ Node.js/npm not found${NC}"
    exit 1
fi

if ! command_exists playwright; then
    echo -e "${YELLOW}⚠️  Installing Playwright...${NC}"
    npx playwright install
fi

# Check if documentation is prepared
echo -e "${YELLOW}📚 Checking documentation preparation...${NC}"

if [ ! -d "docs/combined" ]; then
    echo -e "${YELLOW}⚠️  Combined documentation not found, generating...${NC}"
    make docs-combined
fi

# Check local MkDocs server
echo -e "${YELLOW}🌐 Checking local documentation server...${NC}"

if check_url "http://127.0.0.1:8001" "Local MkDocs Server"; then
    LOCAL_DOCS_READY=true
else
    echo -e "${BLUE}💡 Starting local documentation server...${NC}"
    make docs-mkdocs-serve &
    MKDOCS_PID=$!
    sleep 5
    
    if check_url "http://127.0.0.1:8001" "Local MkDocs Server (after start)"; then
        LOCAL_DOCS_READY=true
    else
        LOCAL_DOCS_READY=false
        echo -e "${RED}❌ Unable to start local documentation server${NC}"
    fi
fi

# Check GitHub Wiki accessibility
echo -e "${YELLOW}🔗 Checking GitHub Wiki accessibility...${NC}"
WIKI_URL="https://github.com/lsendel/root-zamaz/wiki"

if check_url "$WIKI_URL" "GitHub Wiki"; then
    WIKI_ACCESSIBLE=true
else
    WIKI_ACCESSIBLE=false
fi

# Run Playwright tests
echo -e "${YELLOW}🎭 Running Playwright tests...${NC}"

if [ -f "tests/e2e/wiki-verification.spec.js" ]; then
    echo -e "${BLUE}Running automated wiki verification tests...${NC}"
    
    # Run tests with proper configuration
    npx playwright test tests/e2e/wiki-verification.spec.js --reporter=list --project=chromium
    
    PLAYWRIGHT_EXIT_CODE=$?
    
    if [ $PLAYWRIGHT_EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}✅ Playwright tests passed${NC}"
    else
        echo -e "${YELLOW}⚠️  Some Playwright tests failed (exit code: $PLAYWRIGHT_EXIT_CODE)${NC}"
    fi
else
    echo -e "${RED}❌ Playwright test file not found${NC}"
fi

# Manual verification steps
echo -e "${YELLOW}📝 Manual verification checklist...${NC}"

echo -e "${BLUE}Manual steps to verify:${NC}"
echo "1. Visit: $WIKI_URL"
echo "2. Check for Documentation section"
echo "3. Verify schema domain pages exist:"
echo "   - Authentication & Authorization"
echo "   - Security & Monitoring" 
echo "   - Zero Trust & Device Security"
echo "   - Compliance & Data Governance"
echo "4. Verify Mermaid diagrams render properly"
echo "5. Test navigation between wiki pages"

# Wiki sync verification
echo -e "${YELLOW}🔄 Testing wiki sync functionality...${NC}"

if [ -f "scripts/sync-wiki-safe.sh" ]; then
    echo -e "${BLUE}Testing safe wiki sync...${NC}"
    bash scripts/sync-wiki-safe.sh
    
    echo -e "${BLUE}💡 After sync, manually verify:${NC}"
    echo "   - Visit: $WIKI_URL/Documentation"
    echo "   - Check if content updated"
    echo "   - Verify no existing content was overwritten"
else
    echo -e "${RED}❌ Wiki sync script not found${NC}"
fi

# Generate test report
echo -e "${YELLOW}📊 Test Summary${NC}"
echo "===================="

echo -e "Local Documentation: $([ "$LOCAL_DOCS_READY" = true ] && echo -e "${GREEN}✅ Ready${NC}" || echo -e "${RED}❌ Not Ready${NC}")"
echo -e "GitHub Wiki Access: $([ "$WIKI_ACCESSIBLE" = true ] && echo -e "${GREEN}✅ Accessible${NC}" || echo -e "${RED}❌ Not Accessible${NC}")"

if [ -n "${PLAYWRIGHT_EXIT_CODE:-}" ]; then
    echo -e "Automated Tests: $([ $PLAYWRIGHT_EXIT_CODE -eq 0 ] && echo -e "${GREEN}✅ Passed${NC}" || echo -e "${YELLOW}⚠️  Some Issues${NC}")"
fi

# Best practices recommendations
echo -e "${BLUE}💡 Best Practices for Wiki Verification:${NC}"
echo "1. Run this script before major releases"
echo "2. Test both local and remote documentation"
echo "3. Verify Mermaid diagrams render correctly"
echo "4. Check wiki sync doesn't overwrite existing content"
echo "5. Ensure navigation works between documentation sections"

# Cleanup
if [ -n "${MKDOCS_PID:-}" ]; then
    echo -e "${YELLOW}🧹 Cleaning up local server...${NC}"
    kill $MKDOCS_PID 2>/dev/null || true
fi

echo -e "${GREEN}🎯 Wiki integration testing complete!${NC}"