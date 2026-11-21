//! Tier 2: Boundary & Corner Cases — Application Validation & Inventory
//! Covers Features: F1 (App Enums), F2 (App DTOs), F32 (App Inventory CRUD),
//! F33 (App Auth Config), F34 (App Historical Trends)

use std::str::FromStr;
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

use crate::common::*;

// =============================================================================
// F2: Application DTOs Boundary & Deserialization Edge Cases (6 tests)
// =============================================================================

#[test]
fn tier2_dto_app_create_missing_name_rejected() {
    let bad_json = r#"{
        "base_url": "https://example.com",
        "environment": "production",
        "criticality": "high",
        "is_authorized": true
    }"#;
    let res = serde_json::from_str::<CreateApplicationRequest>(bad_json);
    assert!(res.is_err(), "Missing 'name' must fail deserialization");
}

#[test]
fn tier2_dto_app_create_missing_base_url_rejected() {
    let bad_json = r#"{
        "name": "App Without URL",
        "environment": "staging",
        "criticality": "low",
        "is_authorized": true
    }"#;
    let res = serde_json::from_str::<CreateApplicationRequest>(bad_json);
    assert!(res.is_err(), "Missing 'base_url' must fail deserialization");
}

#[test]
fn tier2_dto_app_create_missing_environment_rejected() {
    let bad_json = r#"{
        "name": "App Without Env",
        "base_url": "https://example.com",
        "criticality": "low",
        "is_authorized": true
    }"#;
    let res = serde_json::from_str::<CreateApplicationRequest>(bad_json);
    assert!(res.is_err(), "Missing 'environment' must fail deserialization");
}

#[test]
fn tier2_dto_app_create_missing_criticality_rejected() {
    let bad_json = r#"{
        "name": "App Without Crit",
        "base_url": "https://example.com",
        "environment": "development",
        "is_authorized": true
    }"#;
    let res = serde_json::from_str::<CreateApplicationRequest>(bad_json);
    assert!(res.is_err(), "Missing 'criticality' must fail deserialization");
}

#[test]
fn tier2_dto_app_create_missing_is_authorized_rejected() {
    let bad_json = r#"{
        "name": "App Without Auth Flag",
        "base_url": "https://example.com",
        "environment": "development",
        "criticality": "low"
    }"#;
    let res = serde_json::from_str::<CreateApplicationRequest>(bad_json);
    assert!(res.is_err(), "Missing 'is_authorized' must fail deserialization");
}

#[test]
fn tier2_dto_app_update_partial_fields_serde() {
    let json_data = r#"{ "name": "Renamed Application" }"#;
    let parsed: UpdateApplicationRequest = serde_json::from_str(json_data).unwrap();
    assert_eq!(parsed.name, Some("Renamed Application".to_string()));
    assert_eq!(parsed.description, None);
    assert_eq!(parsed.environment, None);
    assert_eq!(parsed.criticality, None);
}

// =============================================================================
// F32: Application Inventory CRUD Validation & Negative Cases (12 tests)
// =============================================================================

#[tokio::test]
async fn tier2_app_create_unauthorized_target_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let payload = json!({
        "name": "Unauthorized Target Test",
        "base_url": "https://target.internal",
        "environment": "staging",
        "criticality": "high",
        "is_authorized": false
    });

    let (status, body) = app
        .client
        .post_json_auth("/api/v1/apps", payload, &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "UNAUTHORIZED_TARGET");
}

#[tokio::test]
async fn tier2_app_create_empty_name_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let payload = json!({
        "name": "",
        "base_url": "https://target.internal",
        "environment": "staging",
        "criticality": "high",
        "is_authorized": true
    });

    let (status, body) = app
        .client
        .post_json_auth("/api/v1/apps", payload, &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_APPLICATION_NAME");
}

#[tokio::test]
async fn tier2_app_create_oversized_name_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let payload = json!({
        "name": "A".repeat(257),
        "base_url": "https://target.internal",
        "environment": "staging",
        "criticality": "high",
        "is_authorized": true
    });

    let (status, body) = app
        .client
        .post_json_auth("/api/v1/apps", payload, &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_APPLICATION_NAME");
}

#[tokio::test]
async fn tier2_app_create_malformed_url_missing_scheme_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let payload = json!({
        "name": "No Scheme App",
        "base_url": "internal.service.local/api",
        "environment": "staging",
        "criticality": "medium",
        "is_authorized": true
    });

    let (status, body) = app
        .client
        .post_json_auth("/api/v1/apps", payload, &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_APPLICATION_URL");
}

#[tokio::test]
async fn tier2_app_create_malformed_url_ftp_scheme_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let payload = json!({
        "name": "FTP Scheme App",
        "base_url": "ftp://files.example.com",
        "environment": "staging",
        "criticality": "medium",
        "is_authorized": true
    });

    let (status, body) = app
        .client
        .post_json_auth("/api/v1/apps", payload, &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_APPLICATION_URL");
}

#[tokio::test]
async fn tier2_app_create_malformed_url_invalid_port_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let payload = json!({
        "name": "Invalid Port App",
        "base_url": "https://example.com:99999",
        "environment": "staging",
        "criticality": "medium",
        "is_authorized": true
    });

    let (status, body) = app
        .client
        .post_json_auth("/api/v1/apps", payload, &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_APPLICATION_URL");
}

#[tokio::test]
async fn tier2_app_create_oversized_description_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let huge_desc = "D".repeat(5000);
    let payload = json!({
        "name": "Oversized Desc App",
        "description": huge_desc,
        "base_url": "https://example.com",
        "environment": "staging",
        "criticality": "medium",
        "is_authorized": true
    });

    let (status, body) = app
        .client
        .post_json_auth("/api/v1/apps", payload, &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_PAYLOAD");
}

#[tokio::test]
async fn tier2_app_create_invalid_cron_expression_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let payload = json!({
        "name": "Bad Cron App",
        "base_url": "https://example.com",
        "environment": "staging",
        "criticality": "medium",
        "cron_schedule": "not_a_valid_cron_string_with_five_fields",
        "is_authorized": true
    });

    let (status, body) = app
        .client
        .post_json_auth("/api/v1/apps", payload, &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_CRON_SCHEDULE");
}

#[tokio::test]
async fn tier2_app_create_duplicate_name_conflict() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let payload = json!({
        "name": "Duplicate Target App",
        "base_url": "https://duplicate.internal",
        "environment": "production",
        "criticality": "critical",
        "is_authorized": true
    });

    // First creation succeeds
    let (s1, _) = app
        .client
        .post_json_auth("/api/v1/apps", payload.clone(), &admin_token)
        .await;
    assert_eq!(s1, StatusCode::CREATED);

    // Duplicate creation returns 409 DUPLICATE_APPLICATION
    let (s2, body2) = app
        .client
        .post_json_auth("/api/v1/apps", payload, &admin_token)
        .await;
    assert_err_code!(s2, &body2, StatusCode::CONFLICT, "DUPLICATE_APPLICATION");
}

#[tokio::test]
async fn tier2_app_get_nonexistent_id_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let fake_id = Uuid::new_v4();

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}", fake_id), &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND");
}

#[tokio::test]
async fn tier2_app_patch_nonexistent_id_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let fake_id = Uuid::new_v4();

    let patch_payload = json!({ "name": "Nonexistent Patch" });
    let (status, body) = app
        .client
        .patch_json_auth(&format!("/api/v1/apps/{}", fake_id), patch_payload, &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND");
}

#[tokio::test]
async fn tier2_app_delete_nonexistent_id_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let fake_id = Uuid::new_v4();

    let (status, body) = app
        .client
        .delete_auth(&format!("/api/v1/apps/{}", fake_id), &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND");
}

// =============================================================================
// F33: Application Auth Configuration Boundary Cases (5 tests)
// =============================================================================

#[tokio::test]
async fn tier2_app_auth_config_nonexistent_app_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let fake_id = Uuid::new_v4();

    let payload = json!({
        "auth_type": "bearer_token",
        "auth_data": { "token": "test_token" }
    });

    let (status, body) = app
        .client
        .put_json_auth(&format!("/api/v1/apps/{}/auth", fake_id), payload, &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND");
}

#[tokio::test]
async fn tier2_app_auth_config_invalid_auth_type_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Auth Type Test", "https://authtype.internal", true).await;

    let payload = json!({
        "auth_type": "unsupported_magic_protocol",
        "auth_data": { "key": "val" }
    });

    let (status, body) = app
        .client
        .put_json_auth(&format!("/api/v1/apps/{}/auth", seeded.id), payload, &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_AUTH_TYPE");
}

#[tokio::test]
async fn tier2_app_auth_config_empty_auth_data_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Empty Auth Data Test", "https://emptyauth.internal", true).await;

    let payload = json!({
        "auth_type": "bearer_token",
        "auth_data": {}
    });

    let (status, body) = app
        .client
        .put_json_auth(&format!("/api/v1/apps/{}/auth", seeded.id), payload, &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_AUTH_DATA");
}

#[tokio::test]
async fn tier2_app_auth_config_unauthenticated_rejected() {
    let app = TestApp::new().await;
    let seeded = app.seed_application("Unauth Config Test", "https://unauth.internal", true).await;

    let payload = json!({
        "auth_type": "bearer_token",
        "auth_data": { "token": "secret" }
    });

    let req = http::Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/v1/apps/{}/auth", seeded.id))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let (status, _, body) = app.client.execute(req).await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn tier2_app_auth_config_malformed_json_body_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Malformed Auth Body", "https://malformed.internal", true).await;

    let req = http::Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/v1/apps/{}/auth", seeded.id))
        .header(http::header::AUTHORIZATION, format!("Bearer {}", admin_token))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(b"{not_valid_json".to_vec()))
        .unwrap();

    let (status, _, body) = app.client.execute(req).await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_PAYLOAD");
}

// =============================================================================
// F34: Application Historical Trends Boundary Cases (5 tests)
// =============================================================================

#[tokio::test]
async fn tier2_app_trends_nonexistent_app_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let fake_id = Uuid::new_v4();

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}/trends", fake_id), &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND");
}

#[tokio::test]
async fn tier2_app_trends_unauthenticated_rejected() {
    let app = TestApp::new().await;
    let seeded = app.seed_application("Trends Unauth Test", "https://trendsunauth.internal", true).await;

    let (status, body) = app.client.get(&format!("/api/v1/apps/{}/trends", seeded.id)).await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn tier2_app_trends_empty_history_returns_empty_array() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Empty History App", "https://emptyhistory.internal", true).await;

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}/trends", seeded.id), &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);

    let trends: AppTrendsResponse = serde_json::from_slice(&body).expect("Valid AppTrendsResponse");
    assert_eq!(trends.app_id, seeded.id);
    assert!(trends.data_points.is_empty(), "Brand new app must have 0 historical data points");
}

#[tokio::test]
async fn tier2_app_trends_negative_days_query_param_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Negative Days App", "https://negdays.internal", true).await;

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}/trends?days=-15", seeded.id), &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_QUERY_PARAMETER");
}

#[tokio::test]
async fn tier2_app_trends_malformed_uuid_in_path_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let (status, body) = app
        .client
        .get_auth("/api/v1/apps/not-a-valid-uuid/trends", &admin_token)
        .await;
    assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND);
    let envelope: ErrorEnvelope = serde_json::from_slice(&body).expect("Valid error envelope");
    assert!(!envelope.error.code.is_empty());
}

// =============================================================================
// F1: Custom Enums Serialization & String Parsing (App environment & criticality) (3 tests)
// =============================================================================

#[test]
fn tier2_enum_app_environment_from_str_and_serde_invalid() {
    assert!(AppEnvironment::from_str("sandbox").is_err());
    assert!(AppEnvironment::from_str("local").is_err());
    assert!(AppEnvironment::from_str("").is_err());
    assert!(serde_json::from_str::<AppEnvironment>("\"prod\"").is_err());
    assert!(serde_json::from_str::<AppEnvironment>("\"stage\"").is_err());
}

#[test]
fn tier2_enum_app_criticality_from_str_and_serde_invalid() {
    assert!(AppCriticality::from_str("urgent").is_err());
    assert!(AppCriticality::from_str("extreme").is_err());
    assert!(AppCriticality::from_str("negligible").is_err());
    assert!(serde_json::from_str::<AppCriticality>("\"zero\"").is_err());
}

#[test]
fn tier2_enum_app_environment_case_sensitivity() {
    assert!(AppEnvironment::from_str("Production").is_err());
    assert!(AppEnvironment::from_str("STAGING").is_err());
    assert!(AppEnvironment::from_str("Development").is_err());
    assert!(AppEnvironment::from_str("production").is_ok());
}
