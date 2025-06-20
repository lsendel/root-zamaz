# Bytebase Database Change Management

This project uses [Bytebase](https://www.bytebase.com/) for enterprise-grade PostgreSQL change management with GitOps integration.

## Quick Start

1. **Start Bytebase Service:**
   ```bash
   make bytebase-start
   ```
   
2. **Initialize Configuration:**
   ```bash
   make bytebase-setup
   ```
   
3. **Access Web Console:**
   Open <http://localhost:5678> and login with `admin@bytebase.com` / `admin`

## Automated Setup

The project includes automated Bytebase configuration:

- **Docker Compose:** Latest Bytebase image with persistent data
- **Multi-Environment:** Development, Staging, Production environments
- **SQL Review Policies:** Enforced naming conventions and safety rules
- **GitOps Integration:** VCS-based change management ready

### Available Commands

```bash
make bytebase-start    # Start Bytebase service
make bytebase-stop     # Stop Bytebase service  
make bytebase-status   # Check service health
make bytebase-setup    # Run automated configuration
make bytebase-migrate  # Apply pending migrations
```

## GitOps Workflow

Bytebase is configured for GitOps with:

- **File Structure:** `{{ENV_ID}}/{{DB_NAME}}/{{VERSION}}__{{TYPE}}.sql`
- **Schema Templates:** Latest schema tracking per environment
- **Approval Policies:** 
  - Development: Automatic approval
  - Staging: Manual approval required
  - Production: Multi-approver with issue tracking

## SQL Review Policies

Enforced rules include:

- Snake_case naming for tables and columns
- Explicit WHERE clauses for DELETE/UPDATE
- No SELECT * in production queries
- Backward compatibility checks
- Commit transaction restrictions

## Best Practices (2025)

- **Schema Versioning:** All migrations in `db/migrations` with semantic versioning
- **Review Process:** Automated SQL review with configurable rule sets
- **Rollback Planning:** Comprehensive backup and rollback strategies
- **Multi-Environment:** Staged deployments with environment-specific policies
- **Observability:** Complete audit trails and migration monitoring
- **Security:** Role-based access control and compliance tracking

## Configuration Files

- `docker-compose.bytebase.yml` - Service configuration
- `scripts/bytebase-setup.sh` - Automated setup script
- `bytebase/config/gitops.yml` - GitOps workflow configuration