# Bytebase Setup for PostgreSQL Change Management

This project uses [Bytebase](https://www.bytebase.com/) to manage PostgreSQL schema changes.

## Running Bytebase Locally

1. Start Bytebase with Docker Compose:

   ```bash
   docker compose -f docker-compose.bytebase.yml up -d
   ```

   The service exposes the web console at <http://localhost:5678>.

2. Log in using the default administrator account (`admin@bytebase.com` / `admin`).
3. Create an instance using the credentials from your `.env` file.
4. Link the `zero-trust-auth` project to the `db/migrations` directory for VCS-based change management.

## Best Practices (2025)

- **Schema Versioning**: Store all migration scripts under `db/migrations` with incremental numbering.
- **Review Process**: Use Bytebase&#39;s SQL review features to enforce naming conventions and safety checks.
- **Rollback Planning**: Include reverse migrations for every change to support rollbacks.
- **Continuous Integration**: Configure Bytebase GitOps workflow so schema changes are automatically applied after review.
- **Observability**: Monitor migration history and database anomalies through Bytebase dashboards.

