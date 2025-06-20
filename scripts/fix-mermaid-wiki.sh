#!/bin/bash

# Fix Mermaid Diagrams for GitHub Wiki Compatibility
# Ensures diagrams render properly in GitHub Wiki

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🎨 Fixing Mermaid Diagrams for GitHub Wiki${NC}"
echo "============================================="

# Function to validate and fix Mermaid syntax
fix_mermaid_file() {
    local file="$1"
    local temp_file="${file}.tmp"
    local fixed=false
    
    echo -e "${YELLOW}🔧 Processing: $(basename "$file")${NC}"
    
    # Create temporary file for processing
    cp "$file" "$temp_file"
    
    # Fix common GitHub Wiki Mermaid issues
    
    # 1. Ensure proper code block syntax (triple backticks with mermaid)
    sed -i '' 's/^```mermaid$/```mermaid/g' "$temp_file"
    
    # 2. Remove any problematic characters that don't render in GitHub
    # Remove fa: fontawesome references (not supported in GitHub)
    if grep -q "fa:fa-" "$temp_file"; then
        sed -i '' 's/fa:fa-[^]]*//g' "$temp_file"
        fixed=true
        echo -e "  ${YELLOW}⚠️  Removed FontAwesome icons (not supported)${NC}"
    fi
    
    # 3. Fix arrow syntax for better compatibility
    sed -i '' 's/-->/→/g' "$temp_file"
    sed -i '' 's/→/-->/g' "$temp_file"  # Keep standard arrows
    
    # 4. Ensure no special characters that break rendering
    # Remove or replace problematic Unicode characters
    sed -i '' 's/[""]/"/g' "$temp_file"  # Replace smart quotes
    sed -i '' 's/['']/'"'"'/g' "$temp_file"  # Replace smart apostrophes
    
    # 5. Fix sequence diagram participant syntax
    sed -i '' 's/participant \([^:]*\):/participant \1 as/g' "$temp_file"
    sed -i '' 's/participant \([^ ]*\) as \([^ ]*\)$/participant \1 as \2/g' "$temp_file"
    
    # 6. Ensure proper line endings
    sed -i '' 's/\r$//' "$temp_file"  # Remove Windows line endings
    
    # 7. Validate Mermaid syntax structure
    local mermaid_blocks=$(grep -c '```mermaid' "$temp_file" || echo "0")
    local end_blocks=$(grep -c '^```$' "$temp_file" || echo "0")
    
    if [ "$mermaid_blocks" -ne "$end_blocks" ]; then
        echo -e "  ${RED}❌ Mismatched code blocks detected${NC}"
        return 1
    fi
    
    # 8. Check for valid diagram types
    if grep -q '```mermaid' "$temp_file"; then
        local has_valid_diagram=false
        
        # Check for supported diagram types
        if grep -A 5 '```mermaid' "$temp_file" | grep -q -E '(graph|sequenceDiagram|flowchart|classDiagram|stateDiagram|erDiagram|journey|timeline)'; then
            has_valid_diagram=true
        fi
        
        if [ "$has_valid_diagram" = false ]; then
            echo -e "  ${RED}❌ No valid diagram type found${NC}"
            return 1
        fi
    fi
    
    # Check if file was actually modified
    if ! cmp -s "$file" "$temp_file"; then
        mv "$temp_file" "$file"
        fixed=true
        echo -e "  ${GREEN}✅ Fixed Mermaid syntax${NC}"
    else
        rm "$temp_file"
        echo -e "  ${GREEN}✅ Already compatible${NC}"
    fi
    
    return 0
}

# Function to test Mermaid syntax online
test_mermaid_online() {
    local file="$1"
    echo -e "${YELLOW}🌐 Testing Mermaid syntax online...${NC}"
    
    # Extract mermaid code blocks and validate them
    awk '/```mermaid/,/```/' "$file" | grep -v '```' > /tmp/mermaid_test.txt
    
    if [ -s /tmp/mermaid_test.txt ]; then
        echo -e "  ${BLUE}💡 Test your diagrams at: https://mermaid.live/${NC}"
        echo -e "  ${BLUE}📋 Copy this content to test:${NC}"
        echo "  ----------------------------------------"
        head -10 /tmp/mermaid_test.txt | sed 's/^/  /'
        echo "  ----------------------------------------"
    fi
    
    rm -f /tmp/mermaid_test.txt
}

# Process all schema documentation files
echo -e "${YELLOW}📁 Processing schema documentation files...${NC}"

schema_files=(
    "docs/combined/schema/auth-domain.md"
    "docs/combined/schema/security-domain.md"
    "docs/combined/schema/zero-trust-domain.md"
    "docs/combined/schema/compliance-domain.md"
)

total_fixed=0
total_files=0

for file in "${schema_files[@]}"; do
    if [ -f "$file" ]; then
        total_files=$((total_files + 1))
        if fix_mermaid_file "$file"; then
            total_fixed=$((total_fixed + 1))
        fi
    else
        echo -e "${YELLOW}⚠️  File not found: $file${NC}"
    fi
done

# Create GitHub Wiki compatible test file
echo -e "${YELLOW}📝 Creating GitHub Wiki test file...${NC}"

cat > docs/combined/mermaid-test.md << 'EOF'
# Mermaid Diagram Test

This page tests Mermaid diagram rendering in GitHub Wiki.

## Simple Graph

```mermaid
graph TD
    A[Start] --> B{Is it working?}
    B -->|Yes| C[Great!]
    B -->|No| D[Fix it]
    D --> B
```

## Sequence Diagram

```mermaid
sequenceDiagram
    participant A as User
    participant B as System
    A->>B: Request
    B-->>A: Response
```

## Flowchart

```mermaid
flowchart LR
    A[Input] --> B[Process]
    B --> C[Output]
```

If these diagrams don't render, check:
1. GitHub Wiki Mermaid support is enabled
2. Syntax is correct
3. No unsupported features are used
EOF

echo -e "${GREEN}✅ Created Mermaid test file: docs/combined/mermaid-test.md${NC}"

# Generate summary report
echo -e "${BLUE}📊 Summary Report${NC}"
echo "==================="
echo -e "Files processed: ${GREEN}$total_files${NC}"
echo -e "Files fixed: ${GREEN}$total_fixed${NC}"

if [ $total_files -gt 0 ]; then
    # Test one file for online validation
    test_mermaid_online "${schema_files[0]}"
fi

echo ""
echo -e "${BLUE}🔍 Next steps:${NC}"
echo "1. Sync documentation to GitHub Wiki"
echo "2. Visit wiki to verify Mermaid rendering"
echo "3. Test with docs/combined/mermaid-test.md first"
echo "4. If issues persist, check GitHub Wiki settings"

echo ""
echo -e "${GREEN}🎯 Mermaid fix process complete!${NC}"