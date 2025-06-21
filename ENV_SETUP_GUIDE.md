# Environment Setup Guide - GitHub Token & Local Development

> **Context**: Complete guide for setting up .env file with GitHub integration  
> **Last Updated**: 2025-06-20  
> **Focus**: GITHUB_TOKEN setup for wiki sync and local development

## 🚀 **Quick Setup**

### **1. Initial Environment Setup**
```bash
# Create .env file from template
make env-setup

# Check current configuration
make env-check

# Show environment status
make show-env
```

### **2. GitHub Token Configuration**
```bash
# Check if token is configured
make check-github-token

# After setting up token in .env
make docs-wiki-sync    # Sync documentation to GitHub Wiki
make docs-wiki-test    # Test Mermaid diagrams in wiki
```

## 🔑 **GitHub Token Setup**

### **Step 1: Create GitHub Personal Access Token**
1. **Visit GitHub Settings**: https://github.com/settings/tokens
2. **Click "Generate new token"** → "Generate new token (classic)"
3. **Configure Token**:
   - **Note**: `Zero Trust Auth - Wiki & Documentation`
   - **Expiration**: `90 days` (or as needed)
   - **Scopes** (Required):
     - ✅ `repo` - Full repository access
     - ✅ `wiki` - Wiki read/write access
     - ✅ `workflow` - GitHub Actions workflow access
     - ✅ `read:org` - Organization read access (if applicable)

### **Step 2: Add Token to .env File**
```bash
# 1. Create .env from template (if not done)
make env-setup

# 2. Edit .env file
nano .env  # or your preferred editor

# 3. Add your token (replace with actual token)
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### **Step 3: Verify Configuration**
```bash
# Check token is loaded
make check-github-token

# Should show: ✅ GitHub token configured

# Check full environment
make env-check
```

## 📋 **.env File Configuration**

### **Complete .env Template**
```bash
# Copy .env.template to .env and configure these key variables:

# GitHub Integration (REQUIRED for wiki sync)
GITHUB_TOKEN=your_github_token_here

# Database (Optional - has defaults)
DB_PASSWORD=your_secure_password_here

# Security (IMPORTANT for production)
JWT_SECRET=your_jwt_secret_minimum_32_characters_here
SESSION_SECRET=your_session_secret_minimum_32_characters_here

# Development (Optional)
LOG_LEVEL=debug
ENABLE_PPROF=true
```

### **Critical Variables Explained**

#### **GITHUB_TOKEN** 🔑
- **Purpose**: GitHub API operations, wiki sync, workflow triggers
- **Required for**: `make docs-wiki-sync`, `make docs-wiki-test`
- **Scopes needed**: `repo`, `wiki`, `workflow`
- **Security**: Never commit to Git (already in .gitignore)

#### **JWT_SECRET** 🛡️
- **Purpose**: JWT token signing and verification
- **Requirements**: Minimum 32 characters, cryptographically secure
- **Generation**: `openssl rand -base64 32`

#### **SESSION_SECRET** 🔐
- **Purpose**: Session encryption and CSRF protection
- **Requirements**: Minimum 32 characters, different from JWT_SECRET
- **Generation**: `openssl rand -base64 32`

#### **DB_PASSWORD** 💾
- **Purpose**: PostgreSQL database authentication
- **Default**: `mvp_password` (change for production)
- **Requirements**: Strong password for production use

## 🔧 **Makefile Integration**

### **Environment Commands**
```bash
# Setup & Verification
make env-setup          # Create .env from template
make env-check          # Check configuration status
make show-env           # Show current values (safely)
make check-github-token # Verify GitHub token specifically

# Documentation with GitHub Integration
make docs-wiki-sync     # Sync docs to GitHub Wiki (requires token)
make docs-wiki-test     # Test Mermaid diagrams (requires token)
make docs-help          # Show documentation commands
```

### **How Makefile Uses .env**
```makefile
# Load environment variables from .env file if it exists
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

# GitHub Configuration (from .env)
GITHUB_TOKEN ?= 
GITHUB_OWNER ?= lsendel
GITHUB_REPO ?= root-zamaz
GITHUB_WIKI_URL := https://github.com/$(GITHUB_OWNER)/$(GITHUB_REPO)/wiki

# Use in targets
docs-wiki-sync: check-github-token
	@GITHUB_TOKEN=$(GITHUB_TOKEN) bash scripts/sync-wiki-safe.sh
```

## 🧪 **Testing GitHub Integration**

### **Test GitHub Token Setup**
```bash
# 1. Verify token configuration
make check-github-token

# 2. Test wiki access (dry run)
make docs-wiki-test

# 3. Test full documentation sync
make docs-wiki-sync

# 4. Verify in browser
# Visit: https://github.com/lsendel/root-zamaz/wiki
```

### **Expected Results**
```bash
# Successful token check
✅ GitHub token configured

# Successful wiki test
✅ Mermaid test page created
🔗 View at: https://github.com/lsendel/root-zamaz/wiki/Mermaid-Test

# Successful wiki sync
📤 Syncing to https://github.com/lsendel/root-zamaz/wiki
✅ Documentation synced successfully
```

## 🚨 **Security Best Practices**

### **Token Security**
- **Never commit** `.env` file to version control
- **Use separate tokens** for different environments
- **Set appropriate expiration** (90 days recommended)
- **Revoke unused tokens** regularly
- **Monitor token usage** in GitHub settings

### **.env File Safety**
```bash
# Verify .env is in .gitignore
grep -q "^\.env$" .gitignore && echo "✅ .env ignored" || echo "❌ Add .env to .gitignore"

# Check file permissions (should be 600)
ls -la .env
# Should show: -rw------- (owner read/write only)

# Set secure permissions if needed
chmod 600 .env
```

### **Environment Separation**
```bash
# Development
.env              # Local development
.env.development  # Development team shared config

# Production (never in repository)
.env.production   # Production secrets (deploy separately)
.env.staging      # Staging environment secrets
```

## 🔄 **Maintenance & Updates**

### **Token Rotation**
```bash
# When rotating GitHub token:

# 1. Generate new token with same scopes
# 2. Update .env file
GITHUB_TOKEN=new_token_here

# 3. Test new token
make check-github-token

# 4. Revoke old token in GitHub settings
```

### **Environment Updates**
```bash
# When .env.template is updated:

# 1. Check for new variables
diff .env.template .env

# 2. Add missing variables to .env
# 3. Update documentation if needed
```

## 🛠️ **Troubleshooting**

### **Common Issues**

#### **Token Not Working**
```bash
# Check token format
echo $GITHUB_TOKEN | wc -c  # Should be 40+ characters

# Verify scopes
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user

# Test wiki access
curl -H "Authorization: token $GITHUB_TOKEN" \
     https://api.github.com/repos/lsendel/root-zamaz
```

#### **.env Not Loading**
```bash
# Check file exists
ls -la .env

# Check Makefile syntax
make show-env | grep GITHUB_TOKEN

# Manual test
source .env && echo $GITHUB_TOKEN
```

#### **Permission Errors**
```bash
# Check file permissions
ls -la .env

# Fix permissions
chmod 600 .env

# Check ownership
ls -la .env | awk '{print $3, $4}'  # Should be your user
```

### **Debugging Commands**
```bash
# Debug environment loading
make show-env

# Debug specific variables
make env-check

# Debug GitHub integration
make check-github-token

# Debug wiki sync
GITHUB_TOKEN=$GITHUB_TOKEN bash -x scripts/sync-wiki-safe.sh
```

## 📚 **Related Documentation**

### **Environment Management**
- **Root CLAUDE.md**: `/CLAUDE.md` - Project overview and workflows
- **Scripts CLAUDE.md**: `/scripts/CLAUDE.md` - Automation safety protocols
- **Documentation CLAUDE.md**: `/docs/CLAUDE.md` - Documentation system

### **GitHub Integration**
- **Wiki Sync Scripts**: `scripts/sync-wiki-safe.sh`
- **Mermaid Testing**: `scripts/sync-mermaid-test.sh`
- **Test Integration**: `scripts/test-wiki-integration.sh`

### **External References**
- **GitHub Tokens**: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token
- **GitHub Wiki API**: https://docs.github.com/en/rest/repos/repos#enable-or-disable-a-wiki
- **Environment Variables**: https://www.gnu.org/software/make/manual/html_node/Environment.html

## 🎯 **Summary**

### **Essential Steps**
1. **Run**: `make env-setup` to create .env file
2. **Get**: GitHub token with `repo`, `wiki`, `workflow` scopes
3. **Edit**: .env file with your `GITHUB_TOKEN`
4. **Test**: `make check-github-token` to verify
5. **Use**: `make docs-wiki-sync` for GitHub integration

### **Key Benefits**
- **Secure**: Token stored locally, not in repository
- **Flexible**: Easy to update and rotate tokens
- **Integrated**: Seamless Makefile integration
- **Safe**: Automatic validation and error messages
- **Documented**: Clear setup and troubleshooting guide

**Remember**: Keep your GitHub token secure, rotate it regularly, and never commit it to version control. The .env system provides a secure, flexible way to manage local development credentials while maintaining security best practices.