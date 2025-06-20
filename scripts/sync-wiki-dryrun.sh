#!/bin/bash

# GitHub Wiki Sync Script (Dry Run)
# Shows what would be synced to GitHub Wiki without actually syncing

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
DOCS_DIR="docs"

echo -e "${BLUE}📚 GitHub Wiki Sync (Dry Run)${NC}"
echo "=========================="

if [ ! -d "$DOCS_DIR" ]; then
    echo -e "${RED}❌ docs directory not found${NC}"
    exit 1
fi

# Get commit info
COMMIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

echo -e "${YELLOW}📄 Documentation files that would be synced:${NC}"

# Home page
if [ -f "$DOCS_DIR/index.md" ]; then
    echo -e "  ${GREEN}✅ Home${NC} (from $DOCS_DIR/index.md)"
elif [ -f "README.md" ]; then
    echo -e "  ${GREEN}✅ Home${NC} (from README.md)"
else
    echo -e "  ${RED}❌ Home${NC} (no index.md or README.md found)"
fi

# Schema documentation
if [ -f "$DOCS_DIR/schema/README.md" ]; then
    echo -e "  ${GREEN}✅ Database-Schema${NC} (from $DOCS_DIR/schema/README.md)"
else
    echo -e "  ${RED}❌ Database-Schema${NC} (no schema/README.md found)"
fi

# Domain documentation
domain_count=0
for domain_file in "$DOCS_DIR"/schema/*-domain.md; do
    if [ -f "$domain_file" ]; then
        basename_file=$(basename "$domain_file" .md)
        wiki_title=$(echo "$basename_file" | sed 's/-/ /g' | sed 's/\b\w/\U&/g' | sed 's/ /-/g')
        echo -e "  ${GREEN}✅ $wiki_title${NC} (from $domain_file)"
        domain_count=$((domain_count + 1))
    fi
done

if [ $domain_count -eq 0 ]; then
    echo -e "  ${YELLOW}⚠️  No domain documentation found${NC}"
fi

# API documentation
if [ -f "$DOCS_DIR/api/README.md" ]; then
    echo -e "  ${GREEN}✅ API-Documentation${NC} (from $DOCS_DIR/api/README.md)"
else
    echo -e "  ${YELLOW}⚠️  API-Documentation${NC} (no api/README.md found)"
fi

# Development documentation
if [ -f "$DOCS_DIR/development/README.md" ]; then
    echo -e "  ${GREEN}✅ Development-Guide${NC} (from $DOCS_DIR/development/README.md)"
else
    echo -e "  ${YELLOW}⚠️  Development-Guide${NC} (no development/README.md found)"
fi

# Table of Contents
echo -e "  ${GREEN}✅ Table-of-Contents${NC} (auto-generated)"

echo ""
echo -e "${BLUE}📊 Summary:${NC}"
echo -e "  Target Wiki: ${BLUE}https://github.com/${REPO_OWNER}/${REPO_NAME}/wiki${NC}"
echo -e "  Commit SHA: ${YELLOW}$COMMIT_SHA${NC}"
echo -e "  Total files found: ${GREEN}$(find "$DOCS_DIR" -name "*.md" | wc -l | tr -d ' ')${NC}"

echo ""
echo -e "${GREEN}✅ Dry run complete!${NC}"
echo -e "${BLUE}💡 To actually sync: export GITHUB_TOKEN=your_token && make docs-wiki-sync-api${NC}"