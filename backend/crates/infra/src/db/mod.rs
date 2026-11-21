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
    let ddl = include_str!("../../migrations/0001_initial_schema.sql");
    sqlx::raw_sql(ddl)
        .execute(pool)
        .await
        .map_err(crate::error::InfraError::Database)?;
    Ok(())
}

