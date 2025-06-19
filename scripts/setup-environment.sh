#!/bin/bash

# Environment Setup Script for Istio Migration
# Sets up PATH and environment variables for development

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Setting up environment for Istio migration...${NC}"

# Add istioctl to PATH
export PATH="$PATH:$PROJECT_ROOT/istio-1.20.1/bin"

# Verify tools
echo -e "${GREEN}Verifying required tools:${NC}"
echo "✓ kubectl: $(kubectl version --client --short 2>/dev/null || echo 'Not found')"
echo "✓ helm: $(helm version --short 2>/dev/null || echo 'Not found')"
echo "✓ istioctl: $(istioctl version --remote=false 2>/dev/null || echo 'Not found')"

# Check cluster connectivity
echo -e "\n${GREEN}Checking cluster connectivity:${NC}"
if kubectl cluster-info &>/dev/null; then
    echo "✓ Connected to cluster: $(kubectl config current-context)"
    echo "✓ Cluster version: $(kubectl version --short 2>/dev/null | grep 'Server Version' || echo 'Unable to get server version')"
else
    echo -e "${YELLOW}⚠ No cluster connection found${NC}"
    echo "Please ensure kubectl is configured with a valid cluster context"
fi

echo -e "\n${GREEN}Environment setup complete!${NC}"
echo -e "\n${YELLOW}To use istioctl in your current session, run:${NC}"
echo "export PATH=\"\$PATH:$PROJECT_ROOT/istio-1.20.1/bin\""

echo -e "\n${YELLOW}To make this permanent, add the following to your ~/.bashrc or ~/.zshrc:${NC}"
echo "export PATH=\"\$PATH:$PROJECT_ROOT/istio-1.20.1/bin\""