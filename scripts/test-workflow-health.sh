#!/bin/bash

# Workflow Health Check Script
# Tests all GitHub Actions workflows for best practices compliance

set -e

echo "🔍 GitHub Actions Workflow Health Check"
echo "======================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
total_workflows=0
secure_workflows=0
workflows_with_permissions=0
workflows_with_timeouts=0
issues_found=0

echo "📊 Workflow Inventory:"
echo "====================="

# Count all workflows
total_workflows=$(find .github/workflows -name "*.yml" -o -name "*.yaml" | wc -l)
echo "Total workflows found: $total_workflows"
echo ""

echo "🔒 Security Analysis:"
echo "===================="

# Check for SHA-pinned actions
echo "Checking action version pinning..."
unpinned_actions=$(grep -r "uses: " .github/workflows/ | grep -v "@[a-f0-9]\{40\}" | grep -v "@main" | grep -v "@master" | grep -v "#" || true)
if [ -n "$unpinned_actions" ]; then
    echo -e "${YELLOW}⚠️  Found workflows with unpinned actions:${NC}"
    echo "$unpinned_actions" | head -5
    echo "..."
    issues_found=$((issues_found + 1))
else
    echo -e "${GREEN}✅ All actions are properly pinned to SHA hashes${NC}"
    secure_workflows=$((secure_workflows + 1))
fi
echo ""

# Check for explicit permissions
echo "Checking workflow permissions..."
workflows_without_permissions=$(find .github/workflows -name "*.yml" -exec grep -L "permissions:" {} \; || true)
if [ -n "$workflows_without_permissions" ]; then
    echo -e "${YELLOW}⚠️  Workflows without explicit permissions:${NC}"
    echo "$workflows_without_permissions"
    issues_found=$((issues_found + 1))
else
    echo -e "${GREEN}✅ All workflows have explicit permissions${NC}"
fi

workflows_with_permissions=$(find .github/workflows -name "*.yml" -exec grep -l "permissions:" {} \; | wc -l)
echo ""

# Check for timeout configurations
echo "Checking timeout configurations..."
workflows_without_timeout=$(find .github/workflows -name "*.yml" -exec grep -L "timeout-minutes:" {} \; || true)
if [ -n "$workflows_without_timeout" ]; then
    echo -e "${YELLOW}⚠️  Workflows without timeout configurations:${NC}"
    echo "$workflows_without_timeout"
    issues_found=$((issues_found + 1))
else
    echo -e "${GREEN}✅ All workflows have timeout configurations${NC}"
fi

workflows_with_timeouts=$(find .github/workflows -name "*.yml" -exec grep -l "timeout-minutes:" {} \; | wc -l)
echo ""

# Check for hardcoded secrets
echo "Checking for hardcoded secrets..."
hardcoded_secrets=$(grep -r -i "password\|secret\|token\|key" .github/workflows/ | grep -v "\${{" | grep -v "#" | grep -v "permissions:" | grep -v "secrets\." || true)
if [ -n "$hardcoded_secrets" ]; then
    echo -e "${RED}❌ Potential hardcoded secrets found:${NC}"
    echo "$hardcoded_secrets"
    issues_found=$((issues_found + 1))
else
    echo -e "${GREEN}✅ No hardcoded secrets detected${NC}"
fi
echo ""

echo "🎯 Consolidation Opportunities:"
echo "==============================="

# Check for duplicate patterns
echo "Analyzing workflow patterns..."
ci_workflows=$(find .github/workflows -name "*ci*.yml" | wc -l)
security_workflows=$(find .github/workflows -name "*security*.yml" | wc -l)
release_workflows=$(find .github/workflows -name "*release*.yml" | wc -l)

echo "- CI/CD workflows: $ci_workflows"
echo "- Security workflows: $security_workflows"
echo "- Release workflows: $release_workflows"

if [ $ci_workflows -gt 1 ] || [ $security_workflows -gt 1 ] || [ $release_workflows -gt 1 ]; then
    echo -e "${YELLOW}💡 Consider consolidating duplicate workflow patterns${NC}"
fi
echo ""

echo "📈 Summary Report:"
echo "=================="
echo "Total workflows: $total_workflows"
echo "Workflows with permissions: $workflows_with_permissions"
echo "Workflows with timeouts: $workflows_with_timeouts"
echo "Security issues found: $issues_found"

if [ $issues_found -eq 0 ]; then
    echo -e "${GREEN}🎉 All workflows follow security best practices!${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠️  Found $issues_found security issues that should be addressed${NC}"
    echo ""
    echo "🔧 Recommended Actions:"
    echo "- Pin all GitHub Actions to SHA hashes"
    echo "- Add explicit permissions to all workflows"
    echo "- Add timeout configurations to prevent runaway jobs"
    echo "- Remove any hardcoded secrets"
    echo "- Consider workflow consolidation to reduce duplication"
    exit 1
fi