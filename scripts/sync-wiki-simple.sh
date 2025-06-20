#!/bin/bash

# Simple GitHub Wiki Sync Script
# Syncs key documentation to GitHub Wiki using GitHub API

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
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
DOCS_DIR="docs"

echo -e "${BLUE}📚 GitHub Wiki Sync (Simple)${NC}"
echo "========================="

# Check for required tools
if ! command -v curl >/dev/null 2>&1; then
    echo -e "${RED}❌ curl is required${NC}"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo -e "${RED}❌ jq is required${NC}"
    exit 1
fi

if [ -z "$GITHUB_TOKEN" ]; then
    echo -e "${RED}❌ GITHUB_TOKEN environment variable is required${NC}"
    exit 1
fi

if [ ! -d "$DOCS_DIR" ]; then
    echo -e "${RED}❌ docs directory not found${NC}"
    exit 1
fi

# Function to make GitHub API call
github_api() {
    local method="$1"
    local endpoint="$2"
    local data="${3:-}"
    
    local curl_args=(-X "$method" -H "Authorization: token $GITHUB_TOKEN" -H "Accept: application/vnd.github.v3+json")
    
    if [ -n "$data" ]; then
        curl_args+=(-H "Content-Type: application/json" -d "$data")
    fi
    
    curl -s "${curl_args[@]}" "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/${endpoint}"
}

# Function to create or update wiki page
create_wiki_page() {
    local page_title="$1"
    local content="$2"
    local message="$3"
    
    echo -e "${YELLOW}📄 Creating/updating: $page_title${NC}"
    
    # Create the wiki page data
    local wiki_data=$(jq -n \
        --arg title "$page_title" \
        --arg content "$content" \
        --arg message "$message" \
        '{
            title: $title,
            content: $content,
            message: $message
        }')
    
    # Try to create/update the page
    local response=$(github_api "PUT" "wiki/$page_title" "$wiki_data")
    
    if echo "$response" | jq -e '.title' >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Success: $page_title${NC}"
    else
        echo -e "${YELLOW}⚠️  Note: $page_title${NC}"
    fi
}

# Get commit info
COMMIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
SYNC_MESSAGE="📚 Auto-sync documentation (commit: $COMMIT_SHA)"

echo -e "${YELLOW}📄 Syncing documentation files...${NC}"

# Sync Home page
if [ -f "$DOCS_DIR/index.md" ]; then
    content=$(cat "$DOCS_DIR/index.md")
    create_wiki_page "Home" "$content" "$SYNC_MESSAGE"
elif [ -f "README.md" ]; then
    content=$(cat "README.md")
    create_wiki_page "Home" "$content" "$SYNC_MESSAGE"
fi

# Sync Schema documentation
if [ -f "$DOCS_DIR/schema/README.md" ]; then
    echo -e "${BLUE}📊 Syncing schema documentation...${NC}"
    content=$(cat "$DOCS_DIR/schema/README.md")
    create_wiki_page "Database-Schema" "$content" "$SYNC_MESSAGE"
fi

# Sync domain documentation
for domain_file in "$DOCS_DIR"/schema/*-domain.md; do
    if [ -f "$domain_file" ]; then
        basename_file=$(basename "$domain_file" .md)
        wiki_title=$(echo "$basename_file" | sed 's/-/ /g' | sed 's/\b\w/\U&/g' | sed 's/ /-/g')
        content=$(cat "$domain_file")
        create_wiki_page "$wiki_title" "$content" "$SYNC_MESSAGE"
    fi
done

# Create Table of Contents
echo -e "${YELLOW}📋 Creating Table of Contents...${NC}"
current_date=$(date -u +'%Y-%m-%d %H:%M:%S UTC')

# Create TOC using printf for better control
toc_content=$(printf "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s" \
    "# Zamaz Zero Trust Platform Wiki" \
    "" \
    "Welcome to the Zamaz Zero Trust Platform documentation wiki." \
    "" \
    "## 📚 Documentation Sections" \
    "" \
    "### 🔐 Database Schema" \
    "- [[Database Schema|Database-Schema]] - Complete schema overview" \
    "- [[Auth Domain|Auth-Domain]] - Authentication & Authorization" \
    "- [[Security Domain|Security-Domain]] - Security & Monitoring" \
    "- [[Zero Trust Domain|Zero-Trust-Domain]] - Device Security" \
    "- [[Compliance Domain|Compliance-Domain]] - GDPR & Compliance" \
    "" \
    "### 📡 API Reference" \
    "- [[API Documentation|API-Documentation]] - Complete API reference" \
    "" \
    "### 🏗️ Architecture" \
    "- [[Architecture Overview|Architecture-Overview]] - System overview" \
    "- [[Architecture Security|Architecture-Security]] - Security architecture" \
    "" \
    "### 💻 Development" \
    "- [[Development Guide|Development-Guide]] - Getting started" \
    "- [[Development Setup|Development-Setup]] - Environment setup" \
    "" \
    "---" \
    "" \
    "📍 Live Documentation: https://lsendel.github.io/root-zamaz" \
    "🔄 Last Updated: $current_date" \
    "📝 Source: Automatically synced from main repository")

create_wiki_page "Table-of-Contents" "$toc_content" "$SYNC_MESSAGE"

echo ""
echo -e "${GREEN}🎉 GitHub Wiki sync complete!${NC}"
echo -e "${BLUE}📍 Wiki available at: https://github.com/${REPO_OWNER}/${REPO_NAME}/wiki${NC}"