# Claude Notes: GitHub Actions & CI/CD

> **Context**: Workflow best practices and security improvements  
> **Last Updated**: 2025-06-20

## 🔒 **Security Improvements Applied**

### **Action Pinning**
- All actions pinned to SHA hashes for security
- Updated major workflows: cicd.yaml, docs.yml, wiki-sync.yml
- Created reusable workflow components

### **Permissions & Timeouts**
- Added explicit permissions to all workflows
- Implemented timeout configurations
- Enhanced error handling and caching

### **Key Workflows**
- `cicd.yaml` - Main CI/CD pipeline (security hardened)
- `docs.yml` - Documentation generation (DB-independent)
- `wiki-sync.yml` - Safe wiki deployment
- `workflow-test.yml` - Best practices validation

## 📊 **Workflow Health Monitoring**

### **Created Tools**
- `workflow-test.yml` - Automated best practices checking
- `dependabot.yml` - Automated dependency updates  
- `scripts/test-workflow-health.sh` - Comprehensive security scanner

### **Security Standards**
- SHA-pinned actions (no version tags)
- Explicit permissions declarations
- Timeout configurations on all jobs
- No hardcoded secrets or credentials

## 🔄 **Documentation CI/CD**

### **Action-Safe Approach**
```yaml
# ✅ Actions can run this (no DB dependency)
make docs-ci

# ⚠️  Local only (requires database)  
make docs-schema
```

### **Wiki Integration**
- Uses git-based approach for reliability
- Limited scope to Documentation subdirectory
- Graceful degradation when content unavailable

## 📋 **Maintenance Checklist**
- [ ] All new actions pinned to SHA
- [ ] Explicit permissions on new workflows
- [ ] Timeout configurations added
- [ ] No hardcoded secrets
- [ ] Documentation workflows DB-independent

**Remember**: Security first - pin actions, limit permissions, add timeouts, protect wiki scope.