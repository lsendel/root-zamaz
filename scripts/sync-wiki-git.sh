#!/bin/bash

# GitHub Wiki Sync Script (Git-based)
# Syncs documentation to GitHub Wiki using Git

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
WIKI_DIR="/tmp/wiki-sync-$$"

echo -e "${BLUE}📚 GitHub Wiki Sync (Git-based)${NC}"
echo "============================="

# Function to cleanup on exit
cleanup() {
    if [ -d "$WIKI_DIR" ]; then
        rm -rf "$WIKI_DIR"
    fi
}
trap cleanup EXIT

# Check for required tools
if ! command -v git >/dev/null 2>&1; then
    echo -e "${RED}❌ git is required${NC}"
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

# Function to convert markdown content for wiki
convert_content_for_wiki() {
    local content="$1"
    
    # Convert relative links to wiki links
    echo "$content" | sed -E 's/\[([^\]]+)\]\(([^)]+)\.md\)/[[\1|\2]]/g' | \
                     sed -E 's/\[([^\]]+)\]\(\.\/([^)]+)\.md\)/[[\1|\2]]/g' | \
                     sed -E 's/\[([^\]]+)\]\(\.\.\/([^)]+)\.md\)/[[\1|\2]]/g'
}

# Function to create wiki page
create_wiki_page() {
    local file_path="$1"
    local wiki_filename="$2"
    local title="$3"
    
    echo -e "${YELLOW}📄 Creating: $wiki_filename${NC}"
    
    if [ -f "$file_path" ]; then
        # Convert content for wiki format
        local content=$(cat "$file_path")
        local wiki_content=$(convert_content_for_wiki "$content")
        
        # Add title if not present
        if ! echo "$wiki_content" | head -1 | grep -q "^# "; then
            wiki_content="# $title\n\n$wiki_content"
        fi
        
        echo -e "$wiki_content" > "$WIKI_DIR/$wiki_filename"
        echo -e "${GREEN}✅ Created: $wiki_filename${NC}"
    else
        echo -e "${YELLOW}⚠️  File not found: $file_path${NC}"
    fi
}

# Get commit info
COMMIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
SYNC_MESSAGE="📚 Auto-sync documentation from main repository (commit: $COMMIT_SHA)"

echo -e "${YELLOW}📋 Cloning wiki repository...${NC}"

# Clone the wiki repository
WIKI_URL="https://${GITHUB_TOKEN}@github.com/${REPO_OWNER}/${REPO_NAME}.wiki.git"

if git clone "$WIKI_URL" "$WIKI_DIR" 2>/dev/null; then
    echo -e "${GREEN}✅ Wiki repository cloned${NC}"
    cd "$WIKI_DIR"
else
    echo -e "${YELLOW}⚠️  Wiki not initialized, creating new wiki...${NC}"
    mkdir -p "$WIKI_DIR"
    cd "$WIKI_DIR"
    git init
    git remote add origin "$WIKI_URL"
fi

# Configure git
git config user.name "GitHub Actions"
git config user.email "github-actions@users.noreply.github.com"

echo -e "${YELLOW}📄 Creating wiki pages...${NC}"

# Create Home page
if [ -f "../$DOCS_DIR/index.md" ]; then
    create_wiki_page "../$DOCS_DIR/index.md" "Home.md" "Zamaz Zero Trust Platform"
elif [ -f "../README.md" ]; then
    create_wiki_page "../README.md" "Home.md" "Zamaz Zero Trust Platform"
fi

# Create Schema documentation
if [ -f "../$DOCS_DIR/schema/README.md" ]; then
    create_wiki_page "../$DOCS_DIR/schema/README.md" "Database-Schema.md" "Database Schema"
fi

# Create domain documentation
for domain_file in "../$DOCS_DIR"/schema/*-domain.md; do
    if [ -f "$domain_file" ]; then
        basename_file=$(basename "$domain_file" .md)
        wiki_filename="$(echo "$basename_file" | sed 's/-/ /g' | sed 's/\b\w/\U&/g' | sed 's/ /-/g').md"
        title=$(echo "$basename_file" | sed 's/-/ /g' | sed 's/\b\w/\U&/g')
        create_wiki_page "$domain_file" "$wiki_filename" "$title"
    fi
done

# Create API documentation
if [ -f "../$DOCS_DIR/api/README.md" ]; then
    create_wiki_page "../$DOCS_DIR/api/README.md" "API-Documentation.md" "API Documentation"
fi

# Create Development documentation
if [ -f "../$DOCS_DIR/development/README.md" ]; then
    create_wiki_page "../$DOCS_DIR/development/README.md" "Development-Guide.md" "Development Guide"
fi

# Create Table of Contents
echo -e "${YELLOW}📋 Creating Table of Contents...${NC}"
current_date=$(date -u +'%Y-%m-%d %H:%M:%S UTC')

cat > "Table-of-Contents.md" << 'EOF'
# Zamaz Zero Trust Platform Wiki

Welcome to the Zamaz Zero Trust Platform documentation wiki. This wiki is automatically synchronized from our main documentation.

## 📚 Documentation Sections

### 🔐 Database Schema
- [[Database Schema]] - Complete schema overview
- [[Auth Domain]] - Authentication & Authorization
- [[Security Domain]] - Security & Monitoring  
- [[Zero Trust Domain]] - Device Security
- [[Compliance Domain]] - GDPR & Compliance

### 📡 API Reference  
- [[API Documentation]] - Complete API reference

### 💻 Development
- [[Development Guide]] - Getting started with development

---

📍 Live Documentation: https://lsendel.github.io/root-zamaz  
📝 Source: Automatically synced from main repository
EOF

echo "🔄 Last Updated: $current_date" >> "Table-of-Contents.md"

echo -e "${GREEN}✅ Table of Contents created${NC}"

# Add all files and commit
echo -e "${YELLOW}📤 Committing changes...${NC}"

git add .
if git diff --staged --quiet; then
    echo -e "${YELLOW}⚠️  No changes to commit${NC}"
else
    git commit -m "$SYNC_MESSAGE"
    
    echo -e "${YELLOW}📤 Pushing to GitHub Wiki...${NC}"
    if git push origin master 2>/dev/null || git push origin main 2>/dev/null; then
        echo -e "${GREEN}✅ Successfully pushed to GitHub Wiki!${NC}"
    else
        echo -e "${RED}❌ Failed to push to GitHub Wiki${NC}"
        exit 1
    fi
fi

echo ""
echo -e "${GREEN}🎉 GitHub Wiki sync complete!${NC}"
echo -e "${BLUE}📍 Wiki available at: https://github.com/${REPO_OWNER}/${REPO_NAME}/wiki${NC}"