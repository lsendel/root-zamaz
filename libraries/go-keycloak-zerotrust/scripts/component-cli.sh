#!/bin/bash

# ==================================================
# Component CLI - GitHub Component Repository Manager
# ==================================================
# Provides easy management of versioned library components

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
REGISTRY_URL="ghcr.io"
NAMESPACE="${GITHUB_REPOSITORY_OWNER:-yourorg}"
REPO_NAME="${GITHUB_REPOSITORY##*/}"
COMPONENTS_DIR="components"
REGISTRY_DIR="registry"

# Available components
AVAILABLE_COMPONENTS=("core" "middleware" "clients" "examples")

# Functions
print_header() {
    echo -e "\n${CYAN}=================================================${NC}"
    echo -e "${CYAN}${BOLD}📦 Component Registry CLI${NC}"
    echo -e "${CYAN}=================================================${NC}\n"
}

print_section() {
    echo -e "\n${BLUE}${BOLD}📋 $1${NC}"
    echo -e "${BLUE}$(printf '%.0s-' {1..50})${NC}\n"
}

print_step() {
    echo -e "${GREEN}🔸 $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Component management functions
list_components() {
    print_section "Available Components"
    
    echo -e "${CYAN}Local Components:${NC}"
    for component in "${AVAILABLE_COMPONENTS[@]}"; do
        if [[ -f "$COMPONENTS_DIR/$component/VERSION" ]]; then
            version=$(cat "$COMPONENTS_DIR/$component/VERSION")
            echo -e "  📦 ${GREEN}$component${NC} v$version"
        else
            echo -e "  📦 ${YELLOW}$component${NC} (not versioned)"
        fi
    done
    
    echo -e "\n${CYAN}Registry Components:${NC}"
    if [[ -f "$REGISTRY_DIR/components.json" ]]; then
        # Parse registry components
        if command -v jq >/dev/null 2>&1; then
            jq -r '.components[] | "  📦 \(.name) v\(.version)"' "$REGISTRY_DIR/components.json"
        else
            print_info "Install 'jq' to see detailed registry information"
            echo "  📦 See registry/components.json for details"
        fi
    else
        print_info "No registry index found. Run 'component-cli build-registry' to create one."
    fi
}

get_component_info() {
    local component="$1"
    
    print_section "Component Information: $component"
    
    if [[ ! " ${AVAILABLE_COMPONENTS[*]} " =~ " $component " ]]; then
        print_error "Unknown component: $component"
        print_info "Available components: ${AVAILABLE_COMPONENTS[*]}"
        return 1
    fi
    
    local version_file="$COMPONENTS_DIR/$component/VERSION"
    local manifest_file="$COMPONENTS_DIR/$component/component.yaml"
    
    if [[ -f "$version_file" ]]; then
        local version=$(cat "$version_file")
        print_step "Version: $version"
    else
        print_warning "No version file found"
    fi
    
    if [[ -f "$manifest_file" ]]; then
        print_step "Manifest:"
        cat "$manifest_file" | sed 's/^/    /'
    else
        print_warning "No component manifest found"
    fi
    
    # Check container registry
    print_step "Checking container registry..."
    local image_name="$REGISTRY_URL/$NAMESPACE/zerotrust-$component"
    if docker manifest inspect "$image_name:latest" >/dev/null 2>&1; then
        print_success "Available in container registry: $image_name"
    else
        print_info "Not yet published to container registry"
    fi
}

install_component() {
    local component="$1"
    local version="${2:-latest}"
    
    print_section "Installing Component: $component@$version"
    
    # Method 1: Go module installation
    if [[ "$component" == "core" || "$component" == "middleware" ]]; then
        print_step "Installing as Go module..."
        local module_path="github.com/$NAMESPACE/$REPO_NAME/components/$component"
        if [[ "$version" != "latest" ]]; then
            module_path="$module_path@v$version"
        fi
        
        if go get "$module_path"; then
            print_success "Go module installed: $module_path"
        else
            print_error "Failed to install Go module"
        fi
    fi
    
    # Method 2: Container installation
    print_step "Pulling container image..."
    local image_name="$REGISTRY_URL/$NAMESPACE/zerotrust-$component:$version"
    if docker pull "$image_name"; then
        print_success "Container image pulled: $image_name"
        
        # Extract component files
        local extract_dir="vendor/components/$component"
        mkdir -p "$extract_dir"
        
        print_step "Extracting component files..."
        docker create --name temp-container "$image_name"
        docker cp temp-container:/component/. "$extract_dir/"
        docker rm temp-container
        
        print_success "Component files extracted to: $extract_dir"
    else
        print_warning "Container image not available or failed to pull"
    fi
}

publish_component() {
    local component="$1"
    local version_bump="${2:-patch}"
    
    print_section "Publishing Component: $component"
    
    if [[ ! " ${AVAILABLE_COMPONENTS[*]} " =~ " $component " ]]; then
        print_error "Unknown component: $component"
        return 1
    fi
    
    # Trigger GitHub Actions workflow
    print_step "Triggering component release workflow..."
    
    if command -v gh >/dev/null 2>&1; then
        gh workflow run components-release.yml \
            -f component="$component" \
            -f version_bump="$version_bump"
        
        print_success "Workflow triggered. Check GitHub Actions for progress."
        print_info "View at: https://github.com/$NAMESPACE/$REPO_NAME/actions"
    else
        print_error "GitHub CLI not found. Install 'gh' or trigger workflow manually."
        print_info "Manual trigger: Go to GitHub Actions -> Component Repository Release"
    fi
}

build_registry() {
    print_section "Building Component Registry"
    
    mkdir -p "$REGISTRY_DIR"
    
    print_step "Generating registry index..."
    
    # Create registry index
    cat > "$REGISTRY_DIR/index.yaml" << EOF
apiVersion: component.github.com/v1alpha1
kind: ComponentRegistry
metadata:
  name: go-keycloak-zerotrust-registry
  namespace: $NAMESPACE
spec:
  components:
EOF
    
    # Create JSON registry
    cat > "$REGISTRY_DIR/components.json" << EOF
{
  "registry": "github.com/$NAMESPACE/$REPO_NAME",
  "namespace": "$NAMESPACE",
  "components": [
EOF
    
    local first=true
    for component in "${AVAILABLE_COMPONENTS[@]}"; do
        if [[ -f "$COMPONENTS_DIR/$component/VERSION" ]]; then
            local version=$(cat "$COMPONENTS_DIR/$component/VERSION")
            
            # Add to YAML index
            cat >> "$REGISTRY_DIR/index.yaml" << EOF
    - name: $component
      version: $version
      source: $REGISTRY_URL/$NAMESPACE/zerotrust-$component:$version
      manifest: components/$component/component.yaml
      updated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
            
            # Add to JSON index
            if [[ "$first" == "false" ]]; then
                echo "," >> "$REGISTRY_DIR/components.json"
            fi
            
            cat >> "$REGISTRY_DIR/components.json" << EOF
    {
      "name": "$component",
      "version": "$version",
      "description": "Zero Trust $component component",
      "tags": ["zero-trust", "authentication", "$component"],
      "install": {
        "go": "go get github.com/$NAMESPACE/$REPO_NAME/components/$component@v$version",
        "container": "docker pull $REGISTRY_URL/$NAMESPACE/zerotrust-$component:$version",
        "script": "./scripts/component-cli.sh install $component $version"
      },
      "updated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    }
EOF
            first=false
            print_success "Added $component v$version to registry"
        fi
    done
    
    echo "]}" >> "$REGISTRY_DIR/components.json"
    
    print_success "Registry built successfully!"
    print_info "Registry files:"
    echo "  - $REGISTRY_DIR/index.yaml"
    echo "  - $REGISTRY_DIR/components.json"
}

bump_version() {
    local component="$1"
    local bump_type="${2:-patch}"
    
    print_section "Bumping Version: $component ($bump_type)"
    
    local version_file="$COMPONENTS_DIR/$component/VERSION"
    
    if [[ ! -f "$version_file" ]]; then
        print_info "No version file found. Creating with version 0.1.0"
        mkdir -p "$COMPONENTS_DIR/$component"
        echo "0.1.0" > "$version_file"
    fi
    
    local current_version=$(cat "$version_file")
    print_step "Current version: $current_version"
    
    # Parse version
    IFS='.' read -ra VERSION_PARTS <<< "$current_version"
    local major=${VERSION_PARTS[0]}
    local minor=${VERSION_PARTS[1]}
    local patch=${VERSION_PARTS[2]}
    
    # Bump version
    case $bump_type in
        major)
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        minor)
            minor=$((minor + 1))
            patch=0
            ;;
        patch)
            patch=$((patch + 1))
            ;;
        *)
            print_error "Invalid bump type: $bump_type (use: major, minor, patch)"
            return 1
            ;;
    esac
    
    local new_version="${major}.${minor}.${patch}"
    echo "$new_version" > "$version_file"
    
    print_success "Version bumped: $current_version → $new_version"
}

validate_components() {
    print_section "Validating Components"
    
    local errors=0
    
    for component in "${AVAILABLE_COMPONENTS[@]}"; do
        print_step "Validating $component..."
        
        local component_dir="$COMPONENTS_DIR/$component"
        local version_file="$component_dir/VERSION"
        local manifest_file="$component_dir/component.yaml"
        
        # Check version file
        if [[ ! -f "$version_file" ]]; then
            print_error "$component: Missing VERSION file"
            errors=$((errors + 1))
        fi
        
        # Check manifest file
        if [[ ! -f "$manifest_file" ]]; then
            print_warning "$component: Missing component.yaml manifest"
        fi
        
        # Validate Go modules for core/middleware
        if [[ "$component" == "core" || "$component" == "middleware" ]]; then
            local source_dir
            case $component in
                core) source_dir="pkg/zerotrust" ;;
                middleware) source_dir="middleware" ;;
            esac
            
            if [[ ! -d "$source_dir" ]]; then
                print_error "$component: Missing source directory: $source_dir"
                errors=$((errors + 1))
            fi
        fi
        
        if [[ $errors -eq 0 ]]; then
            print_success "$component: Valid"
        fi
    done
    
    if [[ $errors -eq 0 ]]; then
        print_success "All components validated successfully!"
    else
        print_error "Found $errors validation errors"
        return 1
    fi
}

show_usage() {
    print_header
    
    echo -e "${CYAN}Usage: $0 <command> [options]${NC}\n"
    
    echo -e "${YELLOW}Commands:${NC}"
    echo "  list                    List all available components"
    echo "  info <component>        Show component information"
    echo "  install <component> [version]  Install a component"
    echo "  publish <component> [bump]     Publish a component (patch|minor|major)"
    echo "  bump <component> [type]        Bump component version"
    echo "  build-registry          Build component registry index"
    echo "  validate                Validate all components"
    echo "  help                    Show this help message"
    
    echo -e "\n${YELLOW}Examples:${NC}"
    echo "  $0 list"
    echo "  $0 info core"
    echo "  $0 install middleware latest"
    echo "  $0 publish core minor"
    echo "  $0 bump examples patch"
    echo "  $0 build-registry"
    echo "  $0 validate"
    
    echo -e "\n${YELLOW}Available Components:${NC}"
    for component in "${AVAILABLE_COMPONENTS[@]}"; do
        echo "  - $component"
    done
}

# Main function
main() {
    case "${1:-help}" in
        list)
            list_components
            ;;
        info)
            if [[ $# -lt 2 ]]; then
                print_error "Usage: $0 info <component>"
                exit 1
            fi
            get_component_info "$2"
            ;;
        install)
            if [[ $# -lt 2 ]]; then
                print_error "Usage: $0 install <component> [version]"
                exit 1
            fi
            install_component "$2" "${3:-latest}"
            ;;
        publish)
            if [[ $# -lt 2 ]]; then
                print_error "Usage: $0 publish <component> [bump_type]"
                exit 1
            fi
            publish_component "$2" "${3:-patch}"
            ;;
        bump)
            if [[ $# -lt 2 ]]; then
                print_error "Usage: $0 bump <component> [type]"
                exit 1
            fi
            bump_version "$2" "${3:-patch}"
            ;;
        build-registry)
            build_registry
            ;;
        validate)
            validate_components
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            print_error "Unknown command: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"