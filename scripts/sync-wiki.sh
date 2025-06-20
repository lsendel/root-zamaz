#!/bin/bash

# GitHub Wiki Sync Script
# Syncs MkDocs documentation to GitHub Wiki

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_NAME="zamaz/root-zamaz"
WIKI_REPO="git@github.com:${REPO_NAME}.wiki.git"
DOCS_DIR="docs"
WIKI_DIR=".wiki-temp"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

echo -e "${BLUE}📚 GitHub Wiki Sync${NC}"
echo "==================="

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

if ! command_exists git; then
    echo -e "${RED}❌ git is required but not installed${NC}"
    exit 1
fi

if [ ! -d "$DOCS_DIR" ]; then
    echo -e "${RED}❌ docs directory not found${NC}"
    exit 1
fi

# Clean up previous wiki clone
if [ -d "$WIKI_DIR" ]; then
    echo -e "${YELLOW}🧹 Cleaning previous wiki clone...${NC}"
    rm -rf "$WIKI_DIR"
fi

# Clone the wiki repository
run_step "Cloning GitHub Wiki" "git clone $WIKI_REPO $WIKI_DIR"

# Function to convert markdown for wiki
convert_to_wiki() {
    local file="$1"
    local output="$2"
    
    # Convert relative links to wiki links
    sed -E 's/\[([^\]]+)\]\(([^)]+)\.md\)/[[\1|\2]]/g' "$file" > "$output.tmp"
    
    # Remove .md extension from links
    sed -E 's/\[([^\]]+)\]\(([^)]+)\.md\)/[\1](\2)/g' "$output.tmp" > "$output"
    
    # Clean up
    rm -f "$output.tmp"
}

# Sync documentation files
echo -e "${YELLOW}📄 Syncing documentation files...${NC}"

# Create wiki structure
cd "$WIKI_DIR"

# Home page (from main README or index)
if [ -f "../$DOCS_DIR/index.md" ]; then
    convert_to_wiki "../$DOCS_DIR/index.md" "Home.md"
elif [ -f "../README.md" ]; then
    convert_to_wiki "../README.md" "Home.md"
fi

# Schema documentation
if [ -d "../$DOCS_DIR/schema" ]; then
    echo -e "${BLUE}📊 Syncing schema documentation...${NC}"
    mkdir -p schema
    
    # Main schema overview
    if [ -f "../$DOCS_DIR/schema/README.md" ]; then
        convert_to_wiki "../$DOCS_DIR/schema/README.md" "Database-Schema.md"
    fi
    
    # Domain documentation
    for domain_file in ../docs/schema/*-domain.md; do
        if [ -f "$domain_file" ]; then
            basename_file=$(basename "$domain_file" .md)
            wiki_name=$(echo "$basename_file" | sed 's/-/ /g' | sed 's/\b\w/\U&/g' | sed 's/ /-/g')
            convert_to_wiki "$domain_file" "${wiki_name}.md"
        fi
    done
    
    # Individual table documentation (create index)
    echo "# Database Tables" > "Database-Tables.md"
    echo "" >> "Database-Tables.md"
    echo "## Complete Table Reference" >> "Database-Tables.md"
    echo "" >> "Database-Tables.md"
    
    for table_file in ../docs/schema/public.*.md; do
        if [ -f "$table_file" ]; then
            table_name=$(basename "$table_file" .md | sed 's/public\.//')
            echo "- [${table_name}](${table_file})" >> "Database-Tables.md"
        fi
    done
fi

# API documentation
if [ -d "../$DOCS_DIR/api" ]; then
    echo -e "${BLUE}📡 Syncing API documentation...${NC}"
    
    if [ -f "../$DOCS_DIR/api/README.md" ]; then
        convert_to_wiki "../$DOCS_DIR/api/README.md" "API-Documentation.md"
    fi
    
    for api_file in ../docs/api/*.md; do
        if [ -f "$api_file" ] && [ "$(basename "$api_file")" != "README.md" ]; then
            basename_file=$(basename "$api_file" .md)
            wiki_name="API-$(echo "$basename_file" | sed 's/\b\w/\U&/g')"
            convert_to_wiki "$api_file" "${wiki_name}.md"
        fi
    done
fi

# Architecture documentation
if [ -d "../$DOCS_DIR/architecture" ]; then
    echo -e "${BLUE}🏗️ Syncing architecture documentation...${NC}"
    
    for arch_file in ../docs/architecture/*.md; do
        if [ -f "$arch_file" ]; then
            basename_file=$(basename "$arch_file" .md)
            wiki_name="Architecture-$(echo "$basename_file" | sed 's/\b\w/\U&/g')"
            convert_to_wiki "$arch_file" "${wiki_name}.md"
        fi
    done
fi

# Development documentation
if [ -d "../$DOCS_DIR/development" ]; then
    echo -e "${BLUE}💻 Syncing development documentation...${NC}"
    
    if [ -f "../$DOCS_DIR/development/README.md" ]; then
        convert_to_wiki "../$DOCS_DIR/development/README.md" "Development-Guide.md"
    fi
    
    for dev_file in ../docs/development/*.md; do
        if [ -f "$dev_file" ] && [ "$(basename "$dev_file")" != "README.md" ]; then
            basename_file=$(basename "$dev_file" .md)
            wiki_name="Development-$(echo "$basename_file" | sed 's/\b\w/\U&/g')"
            convert_to_wiki "$dev_file" "${wiki_name}.md"
        fi
    done
fi

# Security documentation
if [ -d "../$DOCS_DIR/security" ]; then
    echo -e "${BLUE}🔒 Syncing security documentation...${NC}"
    
    for sec_file in ../docs/security/*.md; do
        if [ -f "$sec_file" ]; then
            basename_file=$(basename "$sec_file" .md)
            wiki_name="Security-$(echo "$basename_file" | sed 's/\b\w/\U&/g')"
            convert_to_wiki "$sec_file" "${wiki_name}.md"
        fi
    done
fi

# Create sidebar navigation
echo -e "${YELLOW}📋 Creating wiki sidebar...${NC}"
cat > "_Sidebar.md" << 'EOF'
## Zamaz Zero Trust Platform

### 🏠 Overview
- [[Home]]
- [[Database Schema|Database-Schema]]

### 🔐 Database Schema
- [[Auth Domain|Auth-Domain]]
- [[Security Domain|Security-Domain]]
- [[Zero Trust Domain|Zero-Trust-Domain]]
- [[Compliance Domain|Compliance-Domain]]
- [[Database Tables|Database-Tables]]

### 📡 API Reference
- [[API Documentation|API-Documentation]]
- [[API Authentication|API-Authentication]]
- [[API Devices|API-Devices]]

### 🏗️ Architecture
- [[Architecture Overview|Architecture-Overview]]
- [[Architecture Security|Architecture-Security]]
- [[Architecture Zero Trust|Architecture-Zero-Trust]]

### 💻 Development
- [[Development Guide|Development-Guide]]
- [[Development Setup|Development-Setup]]
- [[Development Testing|Development-Testing]]

### 🔒 Security
- [[Security Threat Model|Security-Threat-Model]]
- [[Security Policies|Security-Policies]]
- [[Security Incident Response|Security-Incident-Response]]
EOF

# Commit and push changes
echo -e "${YELLOW}📤 Committing and pushing changes...${NC}"

git add .
if git diff --staged --quiet; then
    echo -e "${YELLOW}⚠️  No changes to commit${NC}"
else
    git commit -m "📚 Auto-sync documentation from main repository

- Updated from commit: $(cd .. && git rev-parse --short HEAD)
- Sync timestamp: $(date -u +'%Y-%m-%d %H:%M:%S UTC')
- Generated by: docs-ci automation"

    git push origin master
    echo -e "${GREEN}✅ Wiki updated successfully${NC}"
fi

# Clean up
cd ..
rm -rf "$WIKI_DIR"

echo ""
echo -e "${GREEN}🎉 GitHub Wiki sync complete!${NC}"
echo -e "${BLUE}📍 Wiki available at: https://github.com/${REPO_NAME}/wiki${NC}"