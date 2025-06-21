#!/bin/bash

# Sync Mermaid Test to GitHub Wiki for Verification
# Tests if GitHub Wiki properly renders Mermaid diagrams

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

REPO_OWNER="lsendel"
REPO_NAME="root-zamaz"
WIKI_API_BASE="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/wiki"

echo -e "${BLUE}🧪 Testing Mermaid Diagrams in GitHub Wiki${NC}"
echo "============================================="

# Check if GitHub token is available
if [ -z "${GITHUB_TOKEN:-}" ]; then
    echo -e "${RED}❌ GITHUB_TOKEN environment variable not set${NC}"
    echo -e "${BLUE}💡 Setup instructions:${NC}"
    echo -e "  1. Run: make env-setup"
    echo -e "  2. Edit .env file and add: GITHUB_TOKEN=your_token_here"
    echo -e "  3. Get token at: https://github.com/settings/tokens"
    echo -e "  4. Required scopes: repo, wiki, workflow"
    exit 1
fi

# Function to create a wiki page with Mermaid test
create_mermaid_test_page() {
    local page_title="Mermaid-Test"
    local wiki_url="https://github.com/${REPO_OWNER}/${REPO_NAME}/wiki"
    
    echo -e "${YELLOW}📝 Creating Mermaid test page in wiki...${NC}"
    
    # Read the test content
    if [ ! -f "docs/combined/mermaid-test.md" ]; then
        echo -e "${RED}❌ Mermaid test file not found${NC}"
        return 1
    fi
    
    local content
    content=$(cat docs/combined/mermaid-test.md)
    
    # Create the wiki page using git (more reliable than API)
    echo -e "${BLUE}🔧 Using git method to create wiki page...${NC}"
    
    # Clone wiki repository
    local temp_dir="/tmp/wiki-mermaid-test-$$"
    mkdir -p "$temp_dir"
    cd "$temp_dir"
    
    echo -e "${YELLOW}📥 Cloning wiki repository...${NC}"
    if git clone "https://${GITHUB_TOKEN}@github.com/${REPO_OWNER}/${REPO_NAME}.wiki.git" .; then
        echo -e "${GREEN}✅ Wiki repository cloned${NC}"
        
        # Create or update the test page
        echo "$content" > "${page_title}.md"
        
        # Add and commit
        git add "${page_title}.md"
        git config user.email "noreply@github.com"
        git config user.name "Documentation Bot"
        
        if git commit -m "Add Mermaid diagram test page

Tests GitHub Wiki Mermaid rendering capability with:
- Simple graph diagrams
- Sequence diagrams  
- Flowchart diagrams

🤖 Generated with Claude Code"; then
            echo -e "${GREEN}✅ Test page committed${NC}"
            
            # Push to wiki
            if git push; then
                echo -e "${GREEN}✅ Mermaid test page published${NC}"
                echo -e "${BLUE}🔗 View at: ${wiki_url}/${page_title}${NC}"
                
                # Cleanup
                cd /
                rm -rf "$temp_dir"
                
                return 0
            else
                echo -e "${RED}❌ Failed to push to wiki${NC}"
            fi
        else
            echo -e "${YELLOW}⚠️  No changes to commit (page may already exist)${NC}"
            echo -e "${BLUE}🔗 Check existing page at: ${wiki_url}/${page_title}${NC}"
        fi
    else
        echo -e "${RED}❌ Failed to clone wiki repository${NC}"
        echo -e "${YELLOW}💡 Wiki may need manual initialization${NC}"
        echo -e "${BLUE}🔗 Visit: ${wiki_url}${NC}"
        echo -e "${BLUE}📝 Create an initial page manually, then retry${NC}"
    fi
    
    # Cleanup
    cd /
    rm -rf "$temp_dir"
    
    return 1
}

# Function to verify Mermaid rendering
verify_mermaid_rendering() {
    local wiki_url="https://github.com/${REPO_OWNER}/${REPO_NAME}/wiki/Mermaid-Test"
    
    echo -e "${YELLOW}🔍 Verifying Mermaid rendering...${NC}"
    
    # Check if page is accessible
    if curl -s -o /dev/null -w "%{http_code}" "$wiki_url" | grep -q "200"; then
        echo -e "${GREEN}✅ Mermaid test page is accessible${NC}"
        echo -e "${BLUE}🔗 Manual verification required at: $wiki_url${NC}"
        
        echo -e "${YELLOW}📋 Manual verification checklist:${NC}"
        echo "  1. Visit: $wiki_url"
        echo "  2. Check if all 3 Mermaid diagrams render properly"
        echo "  3. Verify diagram types: Graph, Sequence, Flowchart"
        echo "  4. Note any rendering issues or missing diagrams"
        
        return 0
    else
        echo -e "${RED}❌ Mermaid test page not accessible${NC}"
        return 1
    fi
}

# Main execution
echo -e "${YELLOW}🚀 Starting Mermaid test process...${NC}"

# Ensure test file exists
if [ ! -f "docs/combined/mermaid-test.md" ]; then
    echo -e "${YELLOW}⚠️  Mermaid test file not found, creating...${NC}"
    ./scripts/fix-mermaid-wiki.sh
fi

# Create test page
if create_mermaid_test_page; then
    echo -e "${GREEN}✅ Mermaid test page created successfully${NC}"
    
    # Wait a moment for GitHub to process
    echo -e "${YELLOW}⏳ Waiting for GitHub to process...${NC}"
    sleep 3
    
    # Verify rendering
    verify_mermaid_rendering
    
    echo -e "${BLUE}🎯 Mermaid test results:${NC}"
    echo "  📍 Test page: https://github.com/${REPO_OWNER}/${REPO_NAME}/wiki/Mermaid-Test"
    echo "  🔍 Manual verification needed to confirm diagram rendering"
    echo "  📝 If diagrams render correctly, Mermaid is working in wiki"
    
else
    echo -e "${RED}❌ Failed to create Mermaid test page${NC}"
    echo -e "${BLUE}💡 Try manual wiki initialization:${NC}"
    echo "  1. Visit: https://github.com/${REPO_OWNER}/${REPO_NAME}/wiki"
    echo "  2. Create any initial page"
    echo "  3. Run this script again"
fi

echo -e "${GREEN}🧪 Mermaid testing process complete!${NC}"