pub mod app_repo;
pub mod audit_repo;
pub mod scan_repo;
pub mod user_repo;
pub mod vuln_repo;

pub use app_repo::PgAppRepo;
pub use audit_repo::PgAuditLogRepo;
pub use scan_repo::PgScanRepo;
pub use user_repo::PgUserRepo;
pub use vuln_repo::PgVulnRepo;

pub async fn run_migrations(pool: &sqlx::PgPool) -> Result<(), crate::error::InfraError> {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS _schema_migrations (
            version VARCHAR(255) PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );"
    )
    .execute(pool)
    .await
    .map_err(crate::error::InfraError::Database)?;

    // Check if initial schema is already recorded
    let migrated: Option<(bool,)> = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM _schema_migrations WHERE version = '0001_initial_schema');"
    )
    .fetch_optional(pool)
    .await
    .map_err(crate::error::InfraError::Database)?;

    let is_recorded = migrated.map(|r| r.0).unwrap_or(false);

    // Also check if users table already exists in public schema (e.g., from initdb script)
    let table_exists: (bool,) = sqlx::query_as(
        "SELECT EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'public' AND table_name = 'users'
        );"
    )
    .fetch_one(pool)
    .await
    .map_err(crate::error::InfraError::Database)?;

    if !is_recorded && !table_exists.0 {
        let ddl = include_str!("../../migrations/0001_initial_schema.sql");
        sqlx::raw_sql(ddl)
            .execute(pool)
            .await
            .map_err(crate::error::InfraError::Database)?;
    }

    sqlx::raw_sql(
        "INSERT INTO _schema_migrations (version) VALUES ('0001_initial_schema') ON CONFLICT DO NOTHING;"
    )
    .execute(pool)
    .await
    .map_err(crate::error::InfraError::Database)?;

    Ok(())
}
