#!/bin/bash

# Documentation development server script
# Serves MkDocs documentation with auto-reload

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOCS_PORT=${DOCS_PORT:-8001}
DOCS_HOST=${DOCS_HOST:-127.0.0.1}
VENV_DIR=".venv-docs"

echo -e "${BLUE}📚 Zamaz Documentation Server${NC}"
echo "================================="

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if Python is available
if ! command_exists python3; then
    echo -e "${RED}❌ Python 3 is required but not installed${NC}"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}📦 Creating Python virtual environment...${NC}"
    python3 -m venv "$VENV_DIR"
fi

# Activate virtual environment
echo -e "${YELLOW}🔧 Activating virtual environment...${NC}"
source "$VENV_DIR/bin/activate"

# Install/upgrade dependencies
echo -e "${YELLOW}📥 Installing/updating documentation dependencies...${NC}"
pip install --quiet --upgrade pip
pip install --quiet -r requirements-docs.txt

# Check if mkdocs.yml exists
if [ ! -f "mkdocs.yml" ]; then
    echo -e "${RED}❌ mkdocs.yml not found in current directory${NC}"
    echo "Please run this script from the project root directory"
    exit 1
fi

# Start development server
echo -e "${GREEN}🚀 Starting MkDocs development server...${NC}"
echo -e "${BLUE}📍 Server will be available at: http://${DOCS_HOST}:${DOCS_PORT}${NC}"
echo -e "${YELLOW}⏹️  Press Ctrl+C to stop the server${NC}"
echo ""

# Start server with auto-reload
mkdocs serve \
    --dev-addr "${DOCS_HOST}:${DOCS_PORT}" \
    --livereload \
    --verbose

echo -e "${GREEN}✅ Documentation server stopped${NC}"