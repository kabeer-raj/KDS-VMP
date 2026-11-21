use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::enums::{AppCriticality, AppEnvironment};
use crate::scan::SeverityCounts;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateApplicationRequest {
    pub name: String,
    pub description: Option<String>,
    pub base_url: String,
    pub environment: AppEnvironment,
    pub criticality: AppCriticality,
    pub team_name: Option<String>,
    #[serde(default)]
    pub include_regexes: Vec<String>,
    #[serde(default)]
    pub exclude_regexes: Vec<String>,
    pub cron_schedule: Option<String>,
    pub is_authorized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct UpdateApplicationRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub environment: Option<AppEnvironment>,
    pub criticality: Option<AppCriticality>,
    pub team_name: Option<String>,
    pub include_regexes: Option<Vec<String>>,
    pub exclude_regexes: Option<Vec<String>>,
    pub cron_schedule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfigureAuthRequest {
    pub auth_type: String,
    pub auth_data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApplicationResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub base_url: String,
    pub environment: AppEnvironment,
    pub criticality: AppCriticality,
    pub owner_id: Option<Uuid>,
    pub team_name: Option<String>,
    pub include_regexes: Vec<String>,
    pub exclude_regexes: Vec<String>,
    pub has_auth_configured: bool,
    pub cron_schedule: Option<String>,
    pub is_authorized: bool,
    pub latest_risk_score: f64,
    pub last_scanned_at: Option<DateTime<Utc>>,
    pub open_counts: SeverityCounts,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppTrendPoint {
    pub timestamp: DateTime<Utc>,
    pub scan_id: Option<Uuid>,
    pub risk_score: f64,
    pub severity_counts: SeverityCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppTrendsResponse {
    pub app_id: Uuid,
    pub data_points: Vec<AppTrendPoint>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_application_request_defaults_and_serde() {
        let json_input = r#"{
            "name": "Payments API",
            "base_url": "https://payments.example.com",
            "environment": "production",
            "criticality": "critical",
            "is_authorized": true
        }"#;

        let req: CreateApplicationRequest = serde_json::from_str(json_input).unwrap();
        assert_eq!(req.name, "Payments API");
        assert_eq!(req.base_url, "https://payments.example.com");
        assert_eq!(req.environment, AppEnvironment::Production);
        assert_eq!(req.criticality, AppCriticality::Critical);
        assert_eq!(req.description, None);
        assert_eq!(req.team_name, None);
        assert!(req.include_regexes.is_empty());
        assert!(req.exclude_regexes.is_empty());
        assert_eq!(req.cron_schedule, None);
        assert!(req.is_authorized);

        let roundtrip_json = serde_json::to_string(&req).unwrap();
        let parsed: CreateApplicationRequest = serde_json::from_str(&roundtrip_json).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn test_create_application_request_with_all_fields() {
        let req = CreateApplicationRequest {
            name: "Core Web".to_string(),
            description: Some("Main customer dashboard".to_string()),
            base_url: "https://app.example.com".to_string(),
            environment: AppEnvironment::Staging,
            criticality: AppCriticality::High,
            team_name: Some("SecOps".to_string()),
            include_regexes: vec!["^https://app\\.example\\.com/api/.*".to_string()],
            exclude_regexes: vec!["^https://app\\.example\\.com/logout".to_string()],
            cron_schedule: Some("0 2 * * *".to_string()),
            is_authorized: true,
        };

        let json = serde_json::to_string(&req).unwrap();
        let parsed: CreateApplicationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn test_create_application_request_missing_required_fields() {
        // Missing base_url
        let bad_json = r#"{
            "name": "Missing Base URL",
            "environment": "development",
            "criticality": "low",
            "is_authorized": true
        }"#;
        assert!(serde_json::from_str::<CreateApplicationRequest>(bad_json).is_err());

        // Missing is_authorized
        let bad_json2 = r#"{
            "name": "Missing Auth",
            "base_url": "https://test.com",
            "environment": "development",
            "criticality": "low"
        }"#;
        assert!(serde_json::from_str::<CreateApplicationRequest>(bad_json2).is_err());
    }

    #[test]
    fn test_application_response_serde() {
        let app_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let now = Utc::now();

        let resp = ApplicationResponse {
            id: app_id,
            name: "Internal Portal".to_string(),
            description: Some("Employee portal".to_string()),
            base_url: "https://portal.internal".to_string(),
            environment: AppEnvironment::Production,
            criticality: AppCriticality::Medium,
            owner_id: Some(owner_id),
            team_name: Some("Internal IT".to_string()),
            include_regexes: vec![],
            exclude_regexes: vec![],
            has_auth_configured: true,
            cron_schedule: None,
            is_authorized: true,
            latest_risk_score: 18.4,
            last_scanned_at: Some(now),
            open_counts: SeverityCounts::new(0, 1, 3, 5, 2),
            created_at: now,
        };

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ApplicationResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, resp.id);
        assert_eq!(parsed.name, resp.name);
        assert_eq!(parsed.has_auth_configured, true);
        assert_eq!(parsed.open_counts.total(), 11);
    }

    #[test]
    fn test_app_trends_response_serde() {
        let app_id = Uuid::new_v4();
        let scan_1 = Uuid::new_v4();
        let scan_2 = Uuid::new_v4();
        let now = Utc::now();

        let trends = AppTrendsResponse {
            app_id,
            data_points: vec![
                AppTrendPoint {
                    timestamp: now,
                    scan_id: Some(scan_1),
                    risk_score: 35.0,
                    severity_counts: SeverityCounts::new(2, 3, 5, 1, 0),
                },
                AppTrendPoint {
                    timestamp: now,
                    scan_id: Some(scan_2),
                    risk_score: 20.0,
                    severity_counts: SeverityCounts::new(1, 1, 4, 1, 0),
                },
            ],
        };

        let json = serde_json::to_string(&trends).unwrap();
        let parsed: AppTrendsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.app_id, app_id);
        assert_eq!(parsed.data_points.len(), 2);
        assert_eq!(parsed.data_points[0].risk_score, 35.0);
        assert_eq!(parsed.data_points[1].risk_score, 20.0);
    }

    #[test]
    fn test_update_app_and_configure_auth_serde() {
        let update = UpdateApplicationRequest {
            name: Some("New Name".to_string()),
            description: None,
            environment: Some(AppEnvironment::Qa),
            criticality: None,
            team_name: None,
            include_regexes: None,
            exclude_regexes: None,
            cron_schedule: None,
        };
        let json = serde_json::to_string(&update).unwrap();
        let parsed: UpdateApplicationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, Some("New Name".to_string()));
        assert_eq!(parsed.environment, Some(AppEnvironment::Qa));

        let auth_cfg = ConfigureAuthRequest {
            auth_type: "bearer".to_string(),
            auth_data: serde_json::json!({ "token": "xyz123" }),
        };
        let auth_json = serde_json::to_string(&auth_cfg).unwrap();
        let parsed_auth: ConfigureAuthRequest = serde_json::from_str(&auth_json).unwrap();
        assert_eq!(parsed_auth.auth_type, "bearer");
        assert_eq!(parsed_auth.auth_data["token"], "xyz123");
    }
}
