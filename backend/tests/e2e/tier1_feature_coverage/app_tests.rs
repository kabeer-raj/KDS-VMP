//! Tier 1: Feature Coverage Integration Tests — Application Inventory & Posture
//! Covers Features: F1 (AppEnvironment & AppCriticality Enums), F2 (Application DTOs),
//! F32 (App Inventory CRUD), F33 (App Auth Config), F34 (App Historical Trends)

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use axum::http::StatusCode;
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::common::*;

// =============================================================================
// F1: Custom Enums (AppEnvironment & AppCriticality) (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f1_app_environment_roundtrip_all_variants() {
    let variants = [
        AppEnvironment::Production,
        AppEnvironment::Staging,
        AppEnvironment::Development,
        AppEnvironment::Qa,
    ];

    for env in variants {
        let serialized = serde_json::to_string(&env).expect("Serialize AppEnvironment");
        let deserialized: AppEnvironment =
            serde_json::from_str(&serialized).expect("Deserialize AppEnvironment");
        assert_eq!(deserialized, env);

        assert_eq!(env.to_string(), env.as_str());
        let parsed = AppEnvironment::from_str(env.as_str()).expect("Parse from str");
        assert_eq!(parsed, env);
    }
}

#[tokio::test]
async fn test_f1_app_criticality_roundtrip_all_variants() {
    let variants = [
        AppCriticality::Critical,
        AppCriticality::High,
        AppCriticality::Medium,
        AppCriticality::Low,
    ];

    for crit in variants {
        let serialized = serde_json::to_string(&crit).expect("Serialize AppCriticality");
        let deserialized: AppCriticality =
            serde_json::from_str(&serialized).expect("Deserialize AppCriticality");
        assert_eq!(deserialized, crit);

        assert_eq!(crit.to_string(), crit.as_str());
        let parsed = AppCriticality::from_str(crit.as_str()).expect("Parse from str");
        assert_eq!(parsed, crit);
    }
}

#[tokio::test]
async fn test_f1_app_enums_embedded_in_json() {
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct TargetMeta {
        environment: AppEnvironment,
        criticality: AppCriticality,
    }

    let raw_json = r#"{"environment": "staging", "criticality": "high"}"#;
    let meta: TargetMeta = serde_json::from_str(raw_json).expect("Parse embedded enums");
    assert_eq!(meta.environment, AppEnvironment::Staging);
    assert_eq!(meta.criticality, AppCriticality::High);

    let reserialized = serde_json::to_string(&meta).unwrap();
    assert!(reserialized.contains("\"environment\":\"staging\""));
    assert!(reserialized.contains("\"criticality\":\"high\""));
}

#[tokio::test]
async fn test_f1_app_criticality_severity_weight_equivalence() {
    assert_eq!(AppCriticality::Critical.as_str(), "critical");
    assert_eq!(AppCriticality::High.as_str(), "high");
    assert_eq!(AppCriticality::Medium.as_str(), "medium");
    assert_eq!(AppCriticality::Low.as_str(), "low");
}

#[tokio::test]
async fn test_f1_app_enums_hash_and_equality() {
    let mut env_set = HashSet::new();
    env_set.insert(AppEnvironment::Production);
    env_set.insert(AppEnvironment::Staging);
    env_set.insert(AppEnvironment::Development);
    env_set.insert(AppEnvironment::Qa);
    env_set.insert(AppEnvironment::Production);
    assert_eq!(env_set.len(), 4);

    let mut crit_set = HashSet::new();
    crit_set.insert(AppCriticality::Critical);
    crit_set.insert(AppCriticality::High);
    crit_set.insert(AppCriticality::Medium);
    crit_set.insert(AppCriticality::Low);
    crit_set.insert(AppCriticality::Critical);
    assert_eq!(crit_set.len(), 4);

    let mut map = HashMap::new();
    map.insert(AppEnvironment::Production, 100);
    map.insert(AppEnvironment::Staging, 50);
    assert_eq!(map.get(&AppEnvironment::Production), Some(&100));
}

// =============================================================================
// F2: Application DTOs (6 tests)
// =============================================================================

#[tokio::test]
async fn test_f2_create_app_request_minimal_deserialization() {
    let raw = r#"{
        "name": "Minimal App",
        "base_url": "https://minimal.internal",
        "environment": "development",
        "criticality": "low",
        "is_authorized": true
    }"#;

    let req: CreateApplicationRequest = serde_json::from_str(raw).expect("Deserialize minimal DTO");
    assert_eq!(req.name, "Minimal App");
    assert_eq!(req.base_url, "https://minimal.internal");
    assert_eq!(req.environment, AppEnvironment::Development);
    assert_eq!(req.criticality, AppCriticality::Low);
    assert_eq!(req.description, None);
    assert_eq!(req.team_name, None);
    assert!(req.include_regexes.is_empty());
    assert!(req.exclude_regexes.is_empty());
    assert_eq!(req.cron_schedule, None);
    assert!(req.is_authorized);
}

#[tokio::test]
async fn test_f2_create_app_request_full_deserialization() {
    let raw = r#"{
        "name": "Full App",
        "description": "Full spec app",
        "base_url": "https://full.internal",
        "environment": "production",
        "criticality": "critical",
        "team_name": "CoreSec",
        "include_regexes": ["^https://full\\.internal/api/.*"],
        "exclude_regexes": ["^https://full\\.internal/logout"],
        "cron_schedule": "0 2 * * *",
        "is_authorized": true
    }"#;

    let req: CreateApplicationRequest = serde_json::from_str(raw).expect("Deserialize full DTO");
    assert_eq!(req.name, "Full App");
    assert_eq!(req.description.as_deref(), Some("Full spec app"));
    assert_eq!(req.team_name.as_deref(), Some("CoreSec"));
    assert_eq!(req.include_regexes.len(), 1);
    assert_eq!(req.exclude_regexes.len(), 1);
    assert_eq!(req.cron_schedule.as_deref(), Some("0 2 * * *"));
    assert!(req.is_authorized);
}

#[tokio::test]
async fn test_f2_application_response_all_fields_serialization() {
    let now = Utc::now();
    let app_id = Uuid::new_v4();
    let resp = ApplicationResponse {
        id: app_id,
        name: "Serialization Test App".to_string(),
        description: Some("App description".to_string()),
        base_url: "https://serde.internal".to_string(),
        environment: AppEnvironment::Staging,
        criticality: AppCriticality::High,
        owner_id: None,
        team_name: Some("SecOps".to_string()),
        include_regexes: vec!["https://serde.internal/.*".to_string()],
        exclude_regexes: vec!["/logout".to_string()],
        has_auth_configured: true,
        cron_schedule: Some("0 0 * * *".to_string()),
        is_authorized: true,
        latest_risk_score: 42.5,
        last_scanned_at: Some(now),
        open_counts: SeverityCounts::new(1, 2, 3, 4, 5),
        created_at: now,
    };

    let serialized = serde_json::to_string(&resp).expect("Serialize ApplicationResponse");
    let parsed: ApplicationResponse = serde_json::from_str(&serialized).expect("Deserialize");
    assert_eq!(parsed.id, resp.id);
    assert_eq!(parsed.name, resp.name);
    assert_eq!(parsed.latest_risk_score, 42.5);
    assert_eq!(parsed.open_counts.total(), 15);
    assert!(parsed.has_auth_configured);
}

#[tokio::test]
async fn test_f2_app_trends_response_structure() {
    let now = Utc::now();
    let app_id = Uuid::new_v4();
    let scan_id = Uuid::new_v4();

    let point = AppTrendPoint {
        timestamp: now,
        scan_id: Some(scan_id),
        risk_score: 30.0,
        severity_counts: SeverityCounts::new(1, 1, 2, 0, 0),
    };

    let trends = AppTrendsResponse {
        app_id,
        data_points: vec![point],
    };

    let json_str = serde_json::to_string(&trends).expect("Serialize trends");
    let parsed: AppTrendsResponse = serde_json::from_str(&json_str).expect("Deserialize trends");
    assert_eq!(parsed.app_id, app_id);
    assert_eq!(parsed.data_points.len(), 1);
    assert_eq!(parsed.data_points[0].risk_score, 30.0);
    assert_eq!(parsed.data_points[0].scan_id, Some(scan_id));
}

#[tokio::test]
async fn test_f2_update_application_request_partial_updates() {
    let patch_json = r#"{
        "criticality": "critical",
        "cron_schedule": "0 1 * * *"
    }"#;

    let req: UpdateApplicationRequest = serde_json::from_str(patch_json).expect("Partial update");
    assert_eq!(req.criticality, Some(AppCriticality::Critical));
    assert_eq!(req.cron_schedule.as_deref(), Some("0 1 * * *"));
    assert_eq!(req.name, None);
    assert_eq!(req.description, None);
    assert_eq!(req.environment, None);
}

#[tokio::test]
async fn test_f2_configure_auth_request_serde() {
    let bearer_json = r#"{
        "auth_type": "bearer_token",
        "auth_data": { "token": "ey12345" }
    }"#;
    let req: ConfigureAuthRequest = serde_json::from_str(bearer_json).expect("Bearer auth DTO");
    assert_eq!(req.auth_type, "bearer_token");
    assert_eq!(req.auth_data["token"], "ey12345");
}

// =============================================================================
// F32: App Inventory CRUD (6 tests)
// =============================================================================

#[tokio::test]
async fn test_f32_create_application_happy_path_201() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let payload = json!({
        "name": "Payments Portal",
        "description": "Customer payments gateway",
        "base_url": "https://payments.example.com",
        "environment": "production",
        "criticality": "critical",
        "team_name": "Billing",
        "include_regexes": ["^https://payments\\.example\\.com/.*"],
        "exclude_regexes": [],
        "cron_schedule": "0 3 * * *",
        "is_authorized": true
    });

    let (status, body) = app
        .client
        .post_json_auth("/api/v1/apps", payload, &admin_token)
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let created: ApplicationResponse = serde_json::from_slice(&body).expect("Valid ApplicationResponse");
    assert!(!created.id.is_nil());
    assert_eq!(created.name, "Payments Portal");
    assert_eq!(created.environment, AppEnvironment::Production);
    assert_eq!(created.criticality, AppCriticality::Critical);
    assert_eq!(created.latest_risk_score, 0.0);
    assert!(created.is_authorized);
    assert!(!created.has_auth_configured);
}

#[tokio::test]
async fn test_f32_get_application_by_id_200() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let seeded = app
        .seed_application("Get App Target", "https://getapp.internal", true)
        .await;

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}", seeded.id), &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);

    let retrieved: ApplicationResponse = serde_json::from_slice(&body).expect("Valid ApplicationResponse");
    assert_eq!(retrieved.id, seeded.id);
    assert_eq!(retrieved.name, "Get App Target");
    assert_eq!(retrieved.base_url, "https://getapp.internal");
}

#[tokio::test]
async fn test_f32_list_applications_returns_all_apps_200() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    app.seed_application("App Alpha", "https://alpha.internal", true).await;
    app.seed_application("App Beta", "https://beta.internal", true).await;
    app.seed_application("App Gamma", "https://gamma.internal", true).await;

    let (status, body) = app.client.get_auth("/api/v1/apps", &admin_token).await;
    assert_eq!(status, StatusCode::OK);

    let list: Vec<ApplicationResponse> = serde_json::from_slice(&body).expect("Valid app array");
    assert_eq!(list.len(), 3);
}

#[tokio::test]
async fn test_f32_patch_application_metadata_200() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let seeded = app
        .seed_application("Patchable App", "https://patchable.internal", true)
        .await;
    assert_eq!(seeded.criticality, AppCriticality::High);

    let patch_payload = json!({
        "criticality": "critical",
        "cron_schedule": "0 4 * * *"
    });

    let (status, body) = app
        .client
        .patch_json_auth(&format!("/api/v1/apps/{}", seeded.id), patch_payload, &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);

    let updated: ApplicationResponse = serde_json::from_slice(&body).expect("Valid ApplicationResponse");
    assert_eq!(updated.criticality, AppCriticality::Critical);
    assert_eq!(updated.cron_schedule.as_deref(), Some("0 4 * * *"));
    assert_eq!(updated.name, "Patchable App");
}

#[tokio::test]
async fn test_f32_delete_application_happy_path_200() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let seeded = app
        .seed_application("Deletable App", "https://deletable.internal", true)
        .await;

    let (del_status, _) = app
        .client
        .delete_auth(&format!("/api/v1/apps/{}", seeded.id), &admin_token)
        .await;
    assert_eq!(del_status, StatusCode::OK);

    let (get_status, err_body) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}", seeded.id), &admin_token)
        .await;
    assert_err_code!(
        get_status,
        &err_body,
        StatusCode::NOT_FOUND,
        "APPLICATION_NOT_FOUND"
    );
}

#[tokio::test]
async fn test_f32_list_applications_filter_by_environment() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let app_prod = ApplicationResponse {
        id: Uuid::new_v4(),
        name: "Prod App".to_string(),
        description: None,
        base_url: "https://prod.internal".to_string(),
        environment: AppEnvironment::Production,
        criticality: AppCriticality::Critical,
        owner_id: None,
        team_name: None,
        include_regexes: vec![],
        exclude_regexes: vec![],
        has_auth_configured: false,
        cron_schedule: None,
        is_authorized: true,
        latest_risk_score: 0.0,
        last_scanned_at: None,
        open_counts: SeverityCounts::default(),
        created_at: Utc::now(),
    };
    app.app_repo.insert_app(app_prod).await;

    let app_stage = ApplicationResponse {
        id: Uuid::new_v4(),
        name: "Staging App".to_string(),
        description: None,
        base_url: "https://staging.internal".to_string(),
        environment: AppEnvironment::Staging,
        criticality: AppCriticality::Medium,
        owner_id: None,
        team_name: None,
        include_regexes: vec![],
        exclude_regexes: vec![],
        has_auth_configured: false,
        cron_schedule: None,
        is_authorized: true,
        latest_risk_score: 0.0,
        last_scanned_at: None,
        open_counts: SeverityCounts::default(),
        created_at: Utc::now(),
    };
    app.app_repo.insert_app(app_stage).await;

    let (status, body) = app
        .client
        .get_auth("/api/v1/apps?environment=production", &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);

    let filtered: Vec<ApplicationResponse> = serde_json::from_slice(&body).unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].environment, AppEnvironment::Production);
    assert_eq!(filtered[0].name, "Prod App");
}

// =============================================================================
// F33: App Auth Config (6 tests)
// =============================================================================

#[tokio::test]
async fn test_f33_configure_auth_bearer_token() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Auth Bearer Target", "https://bearer.internal", true).await;

    let payload = json!({
        "auth_type": "bearer_token",
        "auth_data": { "token": "secret_jwt_bearer_token_xyz" }
    });

    let (status, body) = app
        .client
        .put_json_auth(&format!("/api/v1/apps/{}/auth", seeded.id), payload, &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);

    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["status"], "configured");
    assert_eq!(val["has_auth_configured"], true);
}

#[tokio::test]
async fn test_f33_configure_auth_cookie_session() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Auth Cookie Target", "https://cookie.internal", true).await;

    let payload = json!({
        "auth_type": "cookie",
        "auth_data": { "session_id": "sid_9876543210abcdef" }
    });

    let (status, body) = app
        .client
        .put_json_auth(&format!("/api/v1/apps/{}/auth", seeded.id), payload, &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);

    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["has_auth_configured"], true);
}

#[tokio::test]
async fn test_f33_configure_auth_custom_headers() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Auth Headers Target", "https://headers.internal", true).await;

    let payload = json!({
        "auth_type": "header",
        "auth_data": { "X-Custom-Auth": "SecretAPIKey123" }
    });

    let (status, body) = app
        .client
        .put_json_auth(&format!("/api/v1/apps/{}/auth", seeded.id), payload, &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);

    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["has_auth_configured"], true);
}

#[tokio::test]
async fn test_f33_configure_auth_basic_authentication() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Auth Basic Target", "https://basic.internal", true).await;

    let payload = json!({
        "auth_type": "basic",
        "auth_data": { "username": "scanner", "password": "ScanPassword123!" }
    });

    let (status, body) = app
        .client
        .put_json_auth(&format!("/api/v1/apps/{}/auth", seeded.id), payload, &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);

    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["has_auth_configured"], true);
}

#[tokio::test]
async fn test_f33_configure_auth_updates_app_has_auth_flag() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Flag Test Target", "https://flag.internal", true).await;
    assert!(!seeded.has_auth_configured);

    let payload = json!({
        "auth_type": "bearer_token",
        "auth_data": { "token": "flag_test_token" }
    });

    app.client
        .put_json_auth(&format!("/api/v1/apps/{}/auth", seeded.id), payload, &admin_token)
        .await;

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}", seeded.id), &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);

    let updated: ApplicationResponse = serde_json::from_slice(&body).unwrap();
    assert!(updated.has_auth_configured);
}

#[tokio::test]
async fn test_f33_configure_auth_overwrite_existing() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Overwrite Target", "https://overwrite.internal", true).await;

    // Config 1: Bearer
    let p1 = json!({
        "auth_type": "bearer_token",
        "auth_data": { "token": "first_token" }
    });
    let (s1, _) = app
        .client
        .put_json_auth(&format!("/api/v1/apps/{}/auth", seeded.id), p1, &admin_token)
        .await;
    assert_eq!(s1, StatusCode::OK);

    // Config 2: Cookie overwrite
    let p2 = json!({
        "auth_type": "cookie",
        "auth_data": { "session_id": "new_session" }
    });
    let (s2, _) = app
        .client
        .put_json_auth(&format!("/api/v1/apps/{}/auth", seeded.id), p2, &admin_token)
        .await;
    assert_eq!(s2, StatusCode::OK);

    let (get_status, body) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}", seeded.id), &admin_token)
        .await;
    assert_eq!(get_status, StatusCode::OK);
    let app_res: ApplicationResponse = serde_json::from_slice(&body).unwrap();
    assert!(app_res.has_auth_configured);
}

// =============================================================================
// F34: App Historical Trends (6 tests)
// =============================================================================

#[tokio::test]
async fn test_f34_trends_empty_for_unscanned_application() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Unscanned App", "https://unscanned.internal", true).await;

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}/trends", seeded.id), &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);

    let trends: AppTrendsResponse = serde_json::from_slice(&body).expect("Valid AppTrendsResponse");
    assert_eq!(trends.app_id, seeded.id);
    assert!(trends.data_points.is_empty());
}

#[tokio::test]
async fn test_f34_trends_single_completed_scan() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Single Scan App", "https://singlescan.internal", true).await;

    let scan_id = Uuid::new_v4();
    let scan = ScanResponse {
        id: scan_id,
        application_id: seeded.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::new(1, 2, 0, 0, 0),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 35.0,
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        duration_seconds: Some(120),
        error_message: None,
    };
    app.scan_repo.insert_scan(scan).await;

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}/trends", seeded.id), &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);

    let trends: AppTrendsResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(trends.data_points.len(), 1);
    assert_eq!(trends.data_points[0].scan_id, Some(scan_id));
    assert_eq!(trends.data_points[0].risk_score, 35.0);
    assert_eq!(trends.data_points[0].severity_counts.critical, 1);
    assert_eq!(trends.data_points[0].severity_counts.high, 2);
}

#[tokio::test]
async fn test_f34_trends_multiple_completed_scans_chronological() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Multi Scan App", "https://multiscan.internal", true).await;

    let t1 = Utc::now() - chrono::Duration::hours(2);
    let t2 = Utc::now() - chrono::Duration::hours(1);

    let scan1 = ScanResponse {
        id: Uuid::new_v4(),
        application_id: seeded.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::new(2, 2, 0, 0, 0),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 50.0,
        started_at: Some(t1 - chrono::Duration::minutes(10)),
        completed_at: Some(t1),
        duration_seconds: Some(600),
        error_message: None,
    };
    let scan2 = ScanResponse {
        id: Uuid::new_v4(),
        application_id: seeded.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::new(1, 1, 0, 0, 0),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 25.0,
        started_at: Some(t2 - chrono::Duration::minutes(10)),
        completed_at: Some(t2),
        duration_seconds: Some(600),
        error_message: None,
    };
    app.scan_repo.insert_scan(scan1).await;
    app.scan_repo.insert_scan(scan2).await;

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}/trends", seeded.id), &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);

    let trends: AppTrendsResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(trends.data_points.len(), 2);
    assert!(trends.data_points[0].timestamp <= trends.data_points[1].timestamp);
}

#[tokio::test]
async fn test_f34_trends_risk_reduction_reflected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Risk Reduction App", "https://riskreduction.internal", true).await;

    let t1 = Utc::now() - chrono::Duration::days(2);
    let t2 = Utc::now() - chrono::Duration::days(1);

    let s1 = ScanResponse {
        id: Uuid::new_v4(),
        application_id: seeded.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::new(3, 4, 2, 1, 0),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 75.0,
        started_at: Some(t1),
        completed_at: Some(t1),
        duration_seconds: Some(300),
        error_message: None,
    };
    let s2 = ScanResponse {
        id: Uuid::new_v4(),
        application_id: seeded.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::new(0, 1, 1, 1, 0),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 15.0,
        started_at: Some(t2),
        completed_at: Some(t2),
        duration_seconds: Some(300),
        error_message: None,
    };
    app.scan_repo.insert_scan(s1).await;
    app.scan_repo.insert_scan(s2).await;

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}/trends", seeded.id), &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);

    let trends: AppTrendsResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(trends.data_points.len(), 2);
    assert_eq!(trends.data_points[0].risk_score, 75.0);
    assert_eq!(trends.data_points[1].risk_score, 15.0);
    assert!(trends.data_points[1].risk_score < trends.data_points[0].risk_score);
}

#[tokio::test]
async fn test_f34_trends_ignores_incomplete_scans() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Incomplete Scan App", "https://incomplete.internal", true).await;

    let queued_scan = ScanResponse {
        id: Uuid::new_v4(),
        application_id: seeded.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Queued,
        progress_percent: 0,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: None,
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    };
    let active_scan = ScanResponse {
        id: Uuid::new_v4(),
        application_id: seeded.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::ActiveScanning,
        progress_percent: 50,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    };
    app.scan_repo.insert_scan(queued_scan).await;
    app.scan_repo.insert_scan(active_scan).await;

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}/trends", seeded.id), &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);

    let trends: AppTrendsResponse = serde_json::from_slice(&body).unwrap();
    assert!(trends.data_points.is_empty(), "Incomplete scans must not appear in historical trends");
}

#[tokio::test]
async fn test_f34_trends_severity_counts_accuracy() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Counts Accuracy App", "https://counts.internal", true).await;

    let scan = ScanResponse {
        id: Uuid::new_v4(),
        application_id: seeded.id,
        scan_type: ScanType::BaselinePassive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::new(4, 3, 2, 1, 5),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 80.0,
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        duration_seconds: Some(60),
        error_message: None,
    };
    app.scan_repo.insert_scan(scan).await;

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}/trends", seeded.id), &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);

    let trends: AppTrendsResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(trends.data_points.len(), 1);
    let counts = &trends.data_points[0].severity_counts;
    assert_eq!(counts.critical, 4);
    assert_eq!(counts.high, 3);
    assert_eq!(counts.medium, 2);
    assert_eq!(counts.low, 1);
    assert_eq!(counts.info, 5);
    assert_eq!(counts.total(), 15);
}
