# Claude Notes: Scripts & Automation

> **Context**: Documentation sync and generation scripts  
> **Last Updated**: 2025-06-20

## 🔧 **Script Architecture**

### **Documentation Generation**
- `docs-generate.sh` - Main documentation pipeline
- Uses MkDocs + Swagger + tbls integration
- Handles missing dependencies gracefully

### **Wiki Sync Scripts**
- `sync-wiki-safe.sh` - **PREFERRED** - Safe subdirectory-only sync
- `sync-wiki-git.sh` - Git-based wiki sync (backup approach)
- `sync-wiki-simple.sh` - API-based sync (deprecated)

### **Safety Features**
- All scripts check for required tools
- Graceful error handling for missing dependencies
- Clear output formatting with colors
- Never affect wiki root or other sections

## 🚨 **Critical Safety Rules**

### **Wiki Sync Safety**
```bash
# ✅ SAFE - Only affects Documentation subdirectory
make docs-wiki-sync-safe

# ⚠️  CAUTION - Check scope before using
make docs-wiki-sync
```

### **Database Dependencies**
- Schema generation fails gracefully when DB unavailable
- Manual documentation always works
- Combined docs include whatever is available

### **Script Naming Convention**
- `sync-wiki-safe.sh` - Primary safe sync method
- `*-dryrun.sh` - Preview/testing scripts
- `*-generate.sh` - Content generation scripts

## 🔄 **Maintenance Notes**
- Test all wiki sync scripts in dry-run mode first
- Update safety checks when adding new sync methods
- Keep error messages clear and actionable
- Always provide fallback options

## 🚨 **Critical Rules**
- **URL Verification**: NEVER suggest URLs without testing them first
- **Service Verification**: Always check if servers/services are running
- **Path Verification**: Verify file/directory paths exist before suggesting access

**Remember**: Safety first - always preview wiki changes and limit scope to Documentation subdirectory only.