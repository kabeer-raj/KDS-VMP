use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use std::str::FromStr;
use uuid::Uuid;

use crate::error::InfraError;
use crate::traits::AppRepository;
use shared_types::{
    AppCriticality, AppEnvironment, AppTrendPoint, AppTrendsResponse, ApplicationResponse,
    ConfigureAuthRequest, CreateApplicationRequest, SeverityCounts, UpdateApplicationRequest,
};

pub struct PgAppRepo {
    pool: PgPool,
}

impl PgAppRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn row_to_app(r: &sqlx::postgres::PgRow) -> Result<ApplicationResponse, InfraError> {
        let env_str: String = r.get("environment");
        let environment = AppEnvironment::from_str(&env_str)
            .map_err(|e| InfraError::Database(sqlx::Error::Decode(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))))?;

        let crit_str: String = r.get("criticality");
        let criticality = AppCriticality::from_str(&crit_str)
            .map_err(|e| InfraError::Database(sqlx::Error::Decode(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))))?;

        let risk_f64: f64 = r
            .try_get::<f64, _>("latest_risk_score")
            .unwrap_or(0.0);

        let has_auth = r
            .try_get::<Option<Vec<u8>>, _>("auth_config_enc")
            .map(|opt| opt.is_some())
            .unwrap_or(false);

        Ok(ApplicationResponse {
            id: r.get("id"),
            name: r.get("name"),
            description: r.get("description"),
            base_url: r.get("base_url"),
            environment,
            criticality,
            owner_id: r.get("owner_id"),
            team_name: r.get("team_name"),
            include_regexes: r.get("include_regexes"),
            exclude_regexes: r.get("exclude_regexes"),
            has_auth_configured: has_auth,
            cron_schedule: r.get("cron_schedule"),
            is_authorized: r.get("is_authorized"),
            latest_risk_score: risk_f64,
            last_scanned_at: r.get("last_scanned_at"),
            open_counts: SeverityCounts::default(),
            created_at: r.get("created_at"),
        })
    }
}

#[async_trait]
impl AppRepository for PgAppRepo {
    async fn create(&self, req: &CreateApplicationRequest, owner_id: Option<Uuid>) -> Result<ApplicationResponse, InfraError> {
        let row = sqlx::query(
            r#"
            INSERT INTO applications (
                name, description, base_url, environment, criticality,
                owner_id, team_name, include_regexes, exclude_regexes,
                cron_schedule, is_authorized
            )
            VALUES ($1, $2, $3, $4::app_environment, $5::app_criticality, $6, $7, $8, $9, $10, $11)
            RETURNING id, name, description, base_url, environment::text as environment,
                      criticality::text as criticality, owner_id, team_name, include_regexes,
                      exclude_regexes, auth_config_enc, cron_schedule, is_authorized, latest_risk_score::float8 as latest_risk_score,
                      last_scanned_at, created_at, updated_at
            "#,
        )
        .bind(&req.name)
        .bind(&req.description)
        .bind(&req.base_url)
        .bind(req.environment.as_str())
        .bind(req.criticality.as_str())
        .bind(owner_id)
        .bind(&req.team_name)
        .bind(&req.include_regexes)
        .bind(&req.exclude_regexes)
        .bind(&req.cron_schedule)
        .bind(req.is_authorized)
        .fetch_one(&self.pool)
        .await?;

        Self::row_to_app(&row)
    }

    async fn get_by_id(&self, id: Uuid) -> Result<Option<ApplicationResponse>, InfraError> {
        let row = sqlx::query(
            r#"
            SELECT id, name, description, base_url, environment::text as environment,
                   criticality::text as criticality, owner_id, team_name, include_regexes,
                   exclude_regexes, auth_config_enc, cron_schedule, is_authorized, latest_risk_score::float8 as latest_risk_score,
                   last_scanned_at, created_at, updated_at
            FROM applications
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = row {
            Ok(Some(Self::row_to_app(&r)?))
        } else {
            Ok(None)
        }
    }

    async fn list(&self, owner_id: Option<Uuid>, env: Option<AppEnvironment>) -> Result<Vec<ApplicationResponse>, InfraError> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, description, base_url, environment::text as environment,
                   criticality::text as criticality, owner_id, team_name, include_regexes,
                   exclude_regexes, auth_config_enc, cron_schedule, is_authorized, latest_risk_score::float8 as latest_risk_score,
                   last_scanned_at, created_at, updated_at
            FROM applications
            WHERE ($1::uuid IS NULL OR owner_id = $1)
              AND ($2::text IS NULL OR environment = $2::app_environment)
            ORDER BY created_at DESC
            "#,
        )
        .bind(owner_id)
        .bind(env.map(|e| e.as_str()))
        .fetch_all(&self.pool)
        .await?;

        let mut apps = Vec::with_capacity(rows.len());
        for r in rows {
            apps.push(Self::row_to_app(&r)?);
        }
        Ok(apps)
    }

    async fn update(&self, id: Uuid, req: &UpdateApplicationRequest) -> Result<Option<ApplicationResponse>, InfraError> {
        let current = self.get_by_id(id).await?;
        let current = match current {
            Some(c) => c,
            None => return Ok(None),
        };

        let name = req.name.as_deref().unwrap_or(&current.name);
        let description = req.description.as_ref().or(current.description.as_ref());
        let environment = req.environment.unwrap_or(current.environment);
        let criticality = req.criticality.unwrap_or(current.criticality);
        let team_name = req.team_name.as_ref().or(current.team_name.as_ref());
        let include_regexes = req.include_regexes.as_ref().unwrap_or(&current.include_regexes);
        let exclude_regexes = req.exclude_regexes.as_ref().unwrap_or(&current.exclude_regexes);
        let cron_schedule = req.cron_schedule.as_ref().or(current.cron_schedule.as_ref());

        let row = sqlx::query(
            r#"
            UPDATE applications
            SET name = $1, description = $2, environment = $3::app_environment,
                criticality = $4::app_criticality, team_name = $5, include_regexes = $6,
                exclude_regexes = $7, cron_schedule = $8, updated_at = NOW()
            WHERE id = $9
            RETURNING id, name, description, base_url, environment::text as environment,
                      criticality::text as criticality, owner_id, team_name, include_regexes,
                      exclude_regexes, auth_config_enc, cron_schedule, is_authorized, latest_risk_score::float8 as latest_risk_score,
                      last_scanned_at, created_at, updated_at
            "#,
        )
        .bind(name)
        .bind(description)
        .bind(environment.as_str())
        .bind(criticality.as_str())
        .bind(team_name)
        .bind(include_regexes)
        .bind(exclude_regexes)
        .bind(cron_schedule)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = row {
            Ok(Some(Self::row_to_app(&r)?))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, id: Uuid) -> Result<bool, InfraError> {
        let rows_affected = sqlx::query("DELETE FROM applications WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(rows_affected > 0)
    }

    async fn get_trends(&self, app_id: Uuid) -> Result<AppTrendsResponse, InfraError> {
        let rows = sqlx::query(
            r#"
            SELECT id as scan_id, completed_at as timestamp, overall_risk_score::float8 as risk_score,
                   critical_count, high_count, medium_count, low_count, info_count
            FROM scans
            WHERE application_id = $1 AND status = 'completed' AND completed_at IS NOT NULL
            ORDER BY completed_at ASC
            "#,
        )
        .bind(app_id)
        .fetch_all(&self.pool)
        .await?;

        let data_points = rows
            .into_iter()
            .map(|r| AppTrendPoint {
                timestamp: r.get("timestamp"),
                scan_id: Some(r.get("scan_id")),
                risk_score: r.get("risk_score"),
                severity_counts: SeverityCounts {
                    critical: r.get("critical_count"),
                    high: r.get("high_count"),
                    medium: r.get("medium_count"),
                    low: r.get("low_count"),
                    info: r.get("info_count"),
                },
            })
            .collect();

        Ok(AppTrendsResponse {
            app_id,
            data_points,
        })
    }

    async fn update_auth_config(&self, app_id: Uuid, req: &ConfigureAuthRequest) -> Result<(), InfraError> {
        let bytes = serde_json::to_vec(req)?;
        let rows_affected = sqlx::query(
            r#"
            UPDATE applications
            SET auth_config_enc = $1, updated_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(bytes)
        .bind(app_id)
        .execute(&self.pool)
        .await?
        .rows_affected();

        if rows_affected == 0 {
            Err(InfraError::NotFound(format!("Application {} not found", app_id)))
        } else {
            Ok(())
        }
    }

    async fn update_latest_risk(&self, app_id: Uuid, risk_score: f64, last_scanned_at: DateTime<Utc>) -> Result<(), InfraError> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE applications
            SET latest_risk_score = $1, last_scanned_at = $2, updated_at = NOW()
            WHERE id = $3
            "#,
        )
        .bind(risk_score)
        .bind(last_scanned_at)
        .bind(app_id)
        .execute(&self.pool)
        .await?
        .rows_affected();

        if rows_affected == 0 {
            Err(InfraError::NotFound(format!("Application {} not found", app_id)))
        } else {
            Ok(())
        }
    }
}
