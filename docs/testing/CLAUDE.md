# Claude Notes: Testing & Verification

> **Context**: Testing strategies and verification approaches  
> **Last Updated**: 2025-06-20

## 🧪 **Testing Architecture**

### **Wiki Integration Testing**
- **Playwright Tests**: Automated browser-based verification
- **Integration Script**: Combined automated + manual testing approach
- **URL Verification**: Always check URLs before suggesting to user

### **Test Locations**
```bash
tests/e2e/wiki-verification.spec.js  # Playwright browser tests
scripts/test-wiki-integration.sh    # Comprehensive test script
```

### **Key Test Coverage**
1. **Wiki Accessibility**: GitHub wiki pages load correctly
2. **Documentation Sync**: Content properly synced to wiki
3. **Mermaid Diagrams**: Schema diagrams render in wiki
4. **Navigation**: Wiki page navigation works
5. **Local Documentation**: MkDocs server accessibility

## 📋 **Test Results Analysis**

### **Current Status (2025-06-20)**
- ✅ **Local Documentation**: Working (http://127.0.0.1:8001)
- ✅ **GitHub Wiki Access**: Repository wiki accessible
- ⚠️  **Wiki Content**: Limited content, needs initialization
- ❌ **Schema Sync**: Mermaid diagrams not properly synced to wiki
- ✅ **Test Framework**: Playwright tests functional

### **Key Findings**
1. **Wiki Initialization**: GitHub wiki needs manual page creation before API sync
2. **Mermaid Rendering**: GitHub wiki may not render Mermaid diagrams correctly
3. **Sync Process**: Documentation sync is working but content not reaching wiki
4. **Local Testing**: All local documentation components working

## 🔄 **Best Practices for Wiki Verification**

### **Before Each Release**
```bash
# Run comprehensive test suite
./scripts/test-wiki-integration.sh

# Manual verification steps
1. Visit: https://github.com/lsendel/root-zamaz/wiki
2. Check Documentation section exists
3. Verify Mermaid diagrams render
4. Test navigation between pages
```

### **Automated Testing**
```bash
# Run Playwright tests
npx playwright test tests/e2e/wiki-verification.spec.js --project=chromium

# Generate test report
npx playwright show-report
```

### **Manual Verification Checklist**
- [ ] Wiki homepage loads without errors
- [ ] Documentation section accessible
- [ ] Schema domain pages exist
- [ ] Mermaid diagrams display correctly
- [ ] Internal wiki links work
- [ ] No existing content overwritten

## 🚨 **Critical Rules**

### **URL Verification Protocol**
1. **NEVER** suggest URLs without testing them first
2. **ALWAYS** use curl or browser to verify accessibility
3. **PROVIDE** alternative access methods if URLs fail
4. **UPDATE** this documentation when adding new verification steps

### **Wiki Safety Protocol**
1. **PREVIEW** all sync operations before execution
2. **LIMIT** sync to Documentation subdirectory only
3. **VERIFY** no existing wiki content is overwritten
4. **TEST** with small content changes first

## 🔧 **Troubleshooting Guide**

### **Common Issues**
1. **Wiki Not Accessible**: Check if repository wiki is enabled
2. **No Content in Wiki**: Manual page creation may be required
3. **Mermaid Not Rendering**: GitHub wiki limitations with Mermaid
4. **Sync Failures**: Check GitHub token permissions

### **Solutions**
- **Empty Wiki**: Create initial page manually, then run sync
- **Permission Issues**: Verify GitHub token has wiki write access
- **Mermaid Issues**: Consider alternative diagram formats for wiki
- **Local Testing**: Always test with local MkDocs first

## 🎯 **Next Steps for Improvement**

1. **Wiki Initialization**: Add automated wiki page creation
2. **Diagram Compatibility**: Research GitHub wiki Mermaid support
3. **Sync Verification**: Add post-sync content verification
4. **CI Integration**: Include wiki tests in CI pipeline

**Remember**: Test early, test often, and always verify URLs work before sharing them.