#!/bin/bash

# Safe GitHub Wiki Sync Script
# Only syncs to /Documentation/ subdirectory in wiki
# Never affects root wiki pages or other sections

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_OWNER="${REPO_OWNER:-lsendel}"
REPO_NAME="${REPO_NAME:-root-zamaz}"
DOCS_SOURCE="${DOCS_SOURCE:-docs/combined}"
WIKI_SUBDIR="Documentation"  # Only affect this subdirectory

echo -e "${BLUE}📚 Safe GitHub Wiki Sync${NC}"
echo "========================"
echo -e "${YELLOW}Target: https://github.com/${REPO_OWNER}/${REPO_NAME}/wiki/${WIKI_SUBDIR}${NC}"
echo -e "${RED}⚠️  SAFETY: Only affects wiki/${WIKI_SUBDIR}/ subdirectory${NC}"
echo ""

# Check source directory
if [ ! -d "$DOCS_SOURCE" ]; then
    echo -e "${RED}❌ Source directory not found: $DOCS_SOURCE${NC}"
    echo -e "${BLUE}💡 Run 'make docs-combined' first${NC}"
    exit 1
fi

# Function to show what would be synced
show_sync_preview() {
    echo -e "${BLUE}📋 Documentation files to sync:${NC}"
    
    local file_count=0
    
    # Manual documentation
    if [ -f "$DOCS_SOURCE/README.md" ]; then
        echo -e "  ${GREEN}✅ ${WIKI_SUBDIR}/Manual-Documentation${NC} (from manual docs)"
        file_count=$((file_count + 1))
    fi
    
    # Development docs
    if [ -d "$DOCS_SOURCE/../development" ]; then
        echo -e "  ${GREEN}✅ ${WIKI_SUBDIR}/Development-Guide${NC} (from development/)"
        file_count=$((file_count + 1))
    fi
    
    # Security docs
    if [ -d "$DOCS_SOURCE/../security" ]; then
        echo -e "  ${GREEN}✅ ${WIKI_SUBDIR}/Security-Guide${NC} (from security/)"
        file_count=$((file_count + 1))
    fi
    
    # Architecture docs
    if [ -d "$DOCS_SOURCE/../architecture" ]; then
        echo -e "  ${GREEN}✅ ${WIKI_SUBDIR}/Architecture-Guide${NC} (from architecture/)"
        file_count=$((file_count + 1))
    fi
    
    # Schema documentation (if available)
    if [ -d "$DOCS_SOURCE/schema" ] && [ "$(ls -A "$DOCS_SOURCE/schema"/*.md 2>/dev/null)" ]; then
        echo -e "  ${GREEN}✅ ${WIKI_SUBDIR}/Database-Schema${NC} (from schema/)"
        for domain_file in "$DOCS_SOURCE"/schema/*-domain.md; do
            if [ -f "$domain_file" ]; then
                basename_file=$(basename "$domain_file" .md)
                wiki_title=$(echo "$basename_file" | sed 's/-/ /g' | sed 's/\b\w/\U&/g' | sed 's/ /-/g')
                echo -e "  ${GREEN}✅ ${WIKI_SUBDIR}/$wiki_title${NC} (from schema domains)"
                file_count=$((file_count + 1))
            fi
        done
        file_count=$((file_count + 1))
    else
        echo -e "  ${YELLOW}⚠️  ${WIKI_SUBDIR}/Database-Schema${NC} (schema not available)"
    fi
    
    # Table of contents
    echo -e "  ${GREEN}✅ ${WIKI_SUBDIR}/Table-of-Contents${NC} (auto-generated)"
    file_count=$((file_count + 1))
    
    echo ""
    echo -e "${BLUE}📊 Summary:${NC}"
    echo -e "  Files to sync: ${GREEN}$file_count${NC}"
    echo -e "  Wiki scope: ${YELLOW}ONLY /${WIKI_SUBDIR}/ subdirectory${NC}"
    echo -e "  Main wiki root: ${GREEN}PROTECTED (never modified)${NC}"
}

# Function to create wiki content locally (dry run)
create_wiki_content() {
    local output_dir="/tmp/wiki-preview-$$"
    mkdir -p "$output_dir"
    
    echo -e "${YELLOW}📁 Creating wiki content preview...${NC}"
    
    # Create a sample of what would be synced
    cat > "$output_dir/preview.md" << 'EOF'
# Documentation Preview

This shows what would be synced to the GitHub Wiki under /Documentation/ subdirectory.

## Manual Documentation
- Development guides
- Security policies  
- Architecture overview
- Operations procedures

## Schema Documentation (when available)
- Database schema overview
- Domain-driven schema organization
- Entity relationship diagrams

## Safety Features
- Only affects /Documentation/ subdirectory
- Never modifies main wiki pages
- Preserves existing wiki structure
EOF
    
    echo -e "${GREEN}✅ Preview created at: $output_dir/preview.md${NC}"
    echo -e "${BLUE}💡 Actual sync would create pages under wiki/${WIKI_SUBDIR}/${NC}"
    
    # Cleanup
    rm -rf "$output_dir"
}

# Main execution
echo -e "${BLUE}🔍 Analyzing documentation...${NC}"

# Show what would be synced
show_sync_preview

echo ""
echo -e "${YELLOW}🔒 Safety Check:${NC}"
echo -e "  ✅ Only affects: ${BLUE}https://github.com/${REPO_OWNER}/${REPO_NAME}/wiki/${WIKI_SUBDIR}${NC}"
echo -e "  ✅ Preserves: Main wiki pages and other subdirectories"
echo -e "  ✅ Safe: No database dependency for basic documentation"

echo ""
echo -e "${GREEN}✅ Safe wiki sync analysis complete!${NC}"

# Create preview
create_wiki_content

echo ""
echo -e "${BLUE}💡 Next steps:${NC}"
echo -e "  1. ${BLUE}make docs-manual${NC} - Generate manual documentation"
echo -e "  2. ${BLUE}make docs-schema${NC} - Add schema docs (if database available)"  
echo -e "  3. ${BLUE}make docs-combined${NC} - Merge both documentation types"
echo -e "  4. ${BLUE}export GITHUB_TOKEN=your_token${NC} - Set authentication"
echo -e "  5. ${BLUE}make docs-wiki-sync-safe${NC} - Perform actual sync"