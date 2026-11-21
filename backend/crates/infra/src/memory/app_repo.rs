use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::InfraError;
use crate::traits::AppRepository;
use shared_types::{
    AppEnvironment, AppTrendPoint, AppTrendsResponse, ApplicationResponse, ConfigureAuthRequest,
    CreateApplicationRequest, SeverityCounts, UpdateApplicationRequest,
};

pub struct InMemoryAppRepo {
    apps: RwLock<HashMap<Uuid, ApplicationResponse>>,
    auth_configs: RwLock<HashMap<Uuid, Vec<u8>>>,
    trends: RwLock<HashMap<Uuid, Vec<AppTrendPoint>>>,
}

impl InMemoryAppRepo {
    pub fn new() -> Self {
        Self {
            apps: RwLock::new(HashMap::new()),
            auth_configs: RwLock::new(HashMap::new()),
            trends: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryAppRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AppRepository for InMemoryAppRepo {
    async fn create(&self, req: &CreateApplicationRequest, owner_id: Option<Uuid>) -> Result<ApplicationResponse, InfraError> {
        let app_id = Uuid::new_v4();
        let now = Utc::now();

        let app = ApplicationResponse {
            id: app_id,
            name: req.name.clone(),
            description: req.description.clone(),
            base_url: req.base_url.clone(),
            environment: req.environment,
            criticality: req.criticality,
            owner_id,
            team_name: req.team_name.clone(),
            include_regexes: req.include_regexes.clone(),
            exclude_regexes: req.exclude_regexes.clone(),
            has_auth_configured: false,
            cron_schedule: req.cron_schedule.clone(),
            is_authorized: req.is_authorized,
            latest_risk_score: 0.0,
            last_scanned_at: None,
            open_counts: SeverityCounts::default(),
            created_at: now,
        };

        let mut apps = self.apps.write().await;
        apps.insert(app_id, app.clone());

        let mut trends = self.trends.write().await;
        trends.insert(
            app_id,
            vec![AppTrendPoint {
                timestamp: now,
                scan_id: None,
                risk_score: 0.0,
                severity_counts: SeverityCounts::default(),
            }],
        );

        Ok(app)
    }

    async fn get_by_id(&self, id: Uuid) -> Result<Option<ApplicationResponse>, InfraError> {
        let apps = self.apps.read().await;
        Ok(apps.get(&id).cloned())
    }

    async fn list(&self, owner_id: Option<Uuid>, env: Option<AppEnvironment>) -> Result<Vec<ApplicationResponse>, InfraError> {
        let apps = self.apps.read().await;
        let mut result: Vec<ApplicationResponse> = apps
            .values()
            .filter(|app| {
                if let Some(owner) = owner_id {
                    if app.owner_id != Some(owner) {
                        return false;
                    }
                }
                if let Some(environment) = env {
                    if app.environment != environment {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        result.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(result)
    }

    async fn update(&self, id: Uuid, req: &UpdateApplicationRequest) -> Result<Option<ApplicationResponse>, InfraError> {
        let mut apps = self.apps.write().await;
        if let Some(app) = apps.get_mut(&id) {
            if let Some(ref name) = req.name {
                app.name = name.clone();
            }
            if let Some(ref desc) = req.description {
                app.description = Some(desc.clone());
            }
            if let Some(env) = req.environment {
                app.environment = env;
            }
            if let Some(crit) = req.criticality {
                app.criticality = crit;
            }
            if let Some(ref team) = req.team_name {
                app.team_name = Some(team.clone());
            }
            if let Some(ref inc) = req.include_regexes {
                app.include_regexes = inc.clone();
            }
            if let Some(ref exc) = req.exclude_regexes {
                app.exclude_regexes = exc.clone();
            }
            if let Some(ref cron) = req.cron_schedule {
                app.cron_schedule = Some(cron.clone());
            }
            Ok(Some(app.clone()))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, id: Uuid) -> Result<bool, InfraError> {
        let mut apps = self.apps.write().await;
        let removed = apps.remove(&id).is_some();
        if removed {
            let mut auth = self.auth_configs.write().await;
            auth.remove(&id);
            let mut trends = self.trends.write().await;
            trends.remove(&id);
        }
        Ok(removed)
    }

    async fn get_trends(&self, app_id: Uuid) -> Result<AppTrendsResponse, InfraError> {
        let trends = self.trends.read().await;
        let points = trends.get(&app_id).cloned().unwrap_or_default();
        Ok(AppTrendsResponse {
            app_id,
            data_points: points,
        })
    }

    async fn update_auth_config(&self, app_id: Uuid, req: &ConfigureAuthRequest) -> Result<(), InfraError> {
        let mut apps = self.apps.write().await;
        if let Some(app) = apps.get_mut(&app_id) {
            app.has_auth_configured = true;
            let serialized = serde_json::to_vec(req)?;
            let mut auth = self.auth_configs.write().await;
            auth.insert(app_id, serialized);
            Ok(())
        } else {
            Err(InfraError::NotFound(format!("Application {} not found", app_id)))
        }
    }

    async fn update_latest_risk(&self, app_id: Uuid, risk_score: f64, last_scanned_at: DateTime<Utc>) -> Result<(), InfraError> {
        let mut apps = self.apps.write().await;
        if let Some(app) = apps.get_mut(&app_id) {
            app.latest_risk_score = risk_score;
            app.last_scanned_at = Some(last_scanned_at);

            let mut trends = self.trends.write().await;
            trends.entry(app_id).or_default().push(AppTrendPoint {
                timestamp: last_scanned_at,
                scan_id: None,
                risk_score,
                severity_counts: app.open_counts,
            });

            Ok(())
        } else {
            Err(InfraError::NotFound(format!("Application {} not found", app_id)))
        }
    }
}
