//! Tier 2: Boundary & Corner Cases — Authentication, API Keys & RBAC
//! Covers Features: F1 (Auth Enums), F25 (JWT Middleware), F26 (API Key Middleware),
//! F27 (RBAC Authorization), F30 (Auth REST Endpoints), F31 (API Key REST Endpoints)

use std::str::FromStr;
use axum::http::{header, Method, StatusCode};
use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

use crate::common::*;

// =============================================================================
// F25: JWT Authentication Middleware Boundary & Negative Tests (7 tests)
// =============================================================================

#[tokio::test]
async fn tier2_auth_expired_jwt_rejected() {
    let app = TestApp::new().await;
    let expired_token = app.expired_token(UserRole::Developer);

    let (status, body) = app.client.get_auth("/api/v1/auth/me", &expired_token).await;
    let err = assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
    assert!(!err.message.is_empty());
    assert!(err.request_id.starts_with("req_"));
}

#[tokio::test]
async fn tier2_auth_tampered_signature_rejected() {
    let app = TestApp::new().await;
    let tampered_token = app.tampered_token(UserRole::SecurityEngineer);

    let (status, body) = app.client.get_auth("/api/v1/auth/me", &tampered_token).await;
    let err = assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
    assert!(!err.message.is_empty());
}

#[tokio::test]
async fn tier2_auth_missing_bearer_prefix_rejected() {
    let app = TestApp::new().await;
    let (_, valid_token) = app.seed_admin().await;

    // Send Authorization header without "Bearer " prefix
    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/me")
        .header(header::AUTHORIZATION, valid_token)
        .body(axum::body::Body::empty())
        .unwrap();

    let (status, _, body) = app.client.execute(req).await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn tier2_auth_empty_bearer_token_rejected() {
    let app = TestApp::new().await;

    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/api/v1/auth/me")
        .header(header::AUTHORIZATION, "Bearer ")
        .body(axum::body::Body::empty())
        .unwrap();

    let (status, _, body) = app.client.execute(req).await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn tier2_auth_missing_authorization_header_rejected() {
    let app = TestApp::new().await;

    let (status, body) = app.client.get("/api/v1/auth/me").await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn tier2_auth_malformed_jwt_payload_rejected() {
    let app = TestApp::new().await;

    let (status, body) = app
        .client
        .get_auth("/api/v1/auth/me", "header.notvalidbase64payload!@#.signature")
        .await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn tier2_auth_nonexistent_user_id_in_jwt_claims_rejected() {
    let app = TestApp::new().await;
    let ghost_id = Uuid::new_v4();
    let ghost_token =
        create_jwt_token(ghost_id, "ghost@kds.local", UserRole::Developer, &app.jwt_secret, 15);

    let (status, body) = app.client.get_auth("/api/v1/auth/me", &ghost_token).await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

// =============================================================================
// F26: API Key Middleware Boundary & Negative Tests (6 tests)
// =============================================================================

#[tokio::test]
async fn tier2_api_key_invalid_hash_not_found() {
    let app = TestApp::new().await;

    let (status, body) = app
        .client
        .get_api_key("/api/v1/apps", "appsec_live_completely_fake_key_hash_000000000000")
        .await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_API_KEY");
}

#[tokio::test]
async fn tier2_api_key_empty_header_value_rejected() {
    let app = TestApp::new().await;

    let (status, body) = app.client.get_api_key("/api/v1/apps", "").await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_API_KEY");
}

#[tokio::test]
async fn tier2_api_key_revoked_key_rejected() {
    let app = TestApp::new().await;
    let (admin_id, admin_token) = app.seed_admin().await;

    // Create an API key
    let raw_key = app.create_api_key(admin_id, "Revocation Test Key").await;
    let key_hash = hash_api_key(&raw_key);
    let key_record = app.user_repo.find_api_key_by_hash(&key_hash).await.unwrap();

    // Revoke key
    let (del_status, _) = app
        .client
        .delete_auth(&format!("/api/v1/auth/api-keys/{}", key_record.id), &admin_token)
        .await;
    assert_eq!(del_status, StatusCode::NO_CONTENT);

    // Attempt request using revoked key
    let (status, body) = app.client.get_api_key("/api/v1/apps", &raw_key).await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_API_KEY");
}

#[tokio::test]
async fn tier2_api_key_wrong_header_name_rejected() {
    let app = TestApp::new().await;
    let (admin_id, _) = app.seed_admin().await;
    let raw_key = app.create_api_key(admin_id, "Valid Key Wrong Header").await;

    let req = http::Request::builder()
        .method(Method::GET)
        .uri("/api/v1/apps")
        .header("X-Api-Token", raw_key)
        .body(axum::body::Body::empty())
        .unwrap();

    let (status, _, body) = app.client.execute(req).await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn tier2_api_key_expired_key_rejected() {
    let app = TestApp::new().await;
    let (admin_id, _) = app.seed_admin().await;

    let raw_key = format!("appsec_live_{}", Uuid::new_v4().simple());
    let key_hash = hash_api_key(&raw_key);
    let expired_at = Utc::now() - Duration::hours(2);

    app.user_repo
        .insert_api_key(
            Uuid::new_v4(),
            admin_id,
            "Expired Key",
            &raw_key[..12],
            &key_hash,
            Some(expired_at),
        )
        .await;

    let (status, body) = app.client.get_api_key("/api/v1/apps", &raw_key).await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "API_KEY_EXPIRED");
}

#[tokio::test]
async fn tier2_api_key_malformed_prefix_rejected() {
    let app = TestApp::new().await;

    let (status, body) = app
        .client
        .get_api_key("/api/v1/apps", "not_starting_with_appsec_live_xyz")
        .await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_API_KEY");
}

// =============================================================================
// F27: RBAC Authorization Negative Access Matrix (6 tests)
// =============================================================================

#[tokio::test]
async fn tier2_rbac_auditor_post_apps_forbidden() {
    let app = TestApp::new().await;
    let (_, auditor_token) = app.seed_auditor().await;

    let create_req = json!({
        "name": "Auditor Forbidden App",
        "base_url": "https://auditor.test.internal",
        "environment": "staging",
        "criticality": "medium",
        "is_authorized": true
    });

    let (status, body) = app
        .client
        .post_json_auth("/api/v1/apps", create_req, &auditor_token)
        .await;
    assert_err_code!(status, &body, StatusCode::FORBIDDEN, "FORBIDDEN_RESOURCE");
}

#[tokio::test]
async fn tier2_rbac_auditor_patch_apps_forbidden() {
    let app = TestApp::new().await;
    let (_, auditor_token) = app.seed_auditor().await;
    let seeded = app
        .seed_application("Auditor Patch Target", "https://patch.test.internal", true)
        .await;

    let patch_req = json!({ "name": "Auditor Renamed App" });
    let (status, body) = app
        .client
        .patch_json_auth(&format!("/api/v1/apps/{}", seeded.id), patch_req, &auditor_token)
        .await;
    assert_err_code!(status, &body, StatusCode::FORBIDDEN, "FORBIDDEN_RESOURCE");
}

#[tokio::test]
async fn tier2_rbac_auditor_put_app_auth_forbidden() {
    let app = TestApp::new().await;
    let (_, auditor_token) = app.seed_auditor().await;
    let seeded = app
        .seed_application("Auditor Auth Target", "https://auth.test.internal", true)
        .await;

    let auth_req = json!({
        "auth_type": "bearer_token",
        "auth_data": { "token": "secret123" }
    });

    let (status, body) = app
        .client
        .put_json_auth(&format!("/api/v1/apps/{}/auth", seeded.id), auth_req, &auditor_token)
        .await;
    assert_err_code!(status, &body, StatusCode::FORBIDDEN, "FORBIDDEN_RESOURCE");
}

#[tokio::test]
async fn tier2_rbac_auditor_delete_apps_forbidden() {
    let app = TestApp::new().await;
    let (_, auditor_token) = app.seed_auditor().await;
    let seeded = app
        .seed_application("Auditor Delete Target", "https://del.test.internal", true)
        .await;

    let (status, body) = app
        .client
        .delete_auth(&format!("/api/v1/apps/{}", seeded.id), &auditor_token)
        .await;
    assert_err_code!(status, &body, StatusCode::FORBIDDEN, "FORBIDDEN_RESOURCE");
}

#[tokio::test]
async fn tier2_rbac_developer_delete_apps_forbidden() {
    let app = TestApp::new().await;
    let (_, dev_token) = app.seed_developer().await;
    let seeded = app
        .seed_application("Dev Delete Target", "https://devdel.test.internal", true)
        .await;

    let (status, body) = app
        .client
        .delete_auth(&format!("/api/v1/apps/{}", seeded.id), &dev_token)
        .await;
    assert_err_code!(status, &body, StatusCode::FORBIDDEN, "FORBIDDEN_RESOURCE");
}

#[tokio::test]
async fn tier2_rbac_developer_manage_api_keys_forbidden() {
    let app = TestApp::new().await;
    let (_, dev_token) = app.seed_developer().await;

    let key_req = json!({ "name": "Dev Unauthorized Key" });
    let (status, body) = app
        .client
        .post_json_auth("/api/v1/auth/api-keys", key_req, &dev_token)
        .await;
    assert_err_code!(status, &body, StatusCode::FORBIDDEN, "FORBIDDEN_RESOURCE");
}

// =============================================================================
// F30: Auth REST Endpoints Boundary & Negative Tests (7 tests)
// =============================================================================

#[tokio::test]
async fn tier2_auth_login_invalid_password_rejected() {
    let app = TestApp::new().await;

    let req = json!({
        "email": "admin@kds.local",
        "password": "CompletelyWrongPassword999!"
    });
    let (status, body) = app.client.post_json("/api/v1/auth/login", req).await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_CREDENTIALS");
}

#[tokio::test]
async fn tier2_auth_login_unregistered_email_rejected() {
    let app = TestApp::new().await;

    let req = json!({
        "email": "unregistered_stranger@kds.local",
        "password": "Password123!"
    });
    let (status, body) = app.client.post_json("/api/v1/auth/login", req).await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_CREDENTIALS");
}

#[tokio::test]
async fn tier2_auth_login_deactivated_user_rejected() {
    let app = TestApp::new().await;
    let deact_id = Uuid::new_v4();
    let pass_hash = hash_password("DeactivatedPass123!");
    app.user_repo
        .insert_user(
            deact_id,
            "deactivated@kds.local",
            "Deactivated User",
            &pass_hash,
            UserRole::Developer,
            false,
        )
        .await;

    let req = json!({
        "email": "deactivated@kds.local",
        "password": "DeactivatedPass123!"
    });
    let (status, body) = app.client.post_json("/api/v1/auth/login", req).await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "USER_INACTIVE");
}

#[tokio::test]
async fn tier2_auth_login_empty_email_rejected() {
    let app = TestApp::new().await;

    let req = json!({
        "email": "",
        "password": "Password123!"
    });
    let (status, body) = app.client.post_json("/api/v1/auth/login", req).await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "VALIDATION_ERROR");
}

#[tokio::test]
async fn tier2_auth_login_empty_password_rejected() {
    let app = TestApp::new().await;

    let req = json!({
        "email": "admin@kds.local",
        "password": ""
    });
    let (status, body) = app.client.post_json("/api/v1/auth/login", req).await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "VALIDATION_ERROR");
}

#[tokio::test]
async fn tier2_auth_refresh_token_invalid_signature_rejected() {
    let app = TestApp::new().await;

    let req = json!({
        "refresh_token": "corrupted_or_forged_refresh_token_string"
    });
    let (status, body) = app.client.post_json("/api/v1/auth/refresh", req).await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_REFRESH_TOKEN");
}

#[tokio::test]
async fn tier2_auth_logout_without_token_rejected() {
    let app = TestApp::new().await;

    let (status, body) = app.client.post_json("/api/v1/auth/logout", json!({})).await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

// =============================================================================
// F31: API Key REST Endpoints Boundary & Negative Tests (6 tests)
// =============================================================================

#[tokio::test]
async fn tier2_api_key_create_empty_name_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let req = json!({ "name": "", "expires_at": null });
    let (status, body) = app
        .client
        .post_json_auth("/api/v1/auth/api-keys", req, &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_API_KEY_NAME");
}

#[tokio::test]
async fn tier2_api_key_create_oversized_name_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let req = json!({ "name": "A".repeat(120), "expires_at": null });
    let (status, body) = app
        .client
        .post_json_auth("/api/v1/auth/api-keys", req, &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_API_KEY_NAME");
}

#[tokio::test]
async fn tier2_api_key_create_past_expiration_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let past_time = Utc::now() - Duration::days(5);
    let req = json!({ "name": "Past Expiry Key", "expires_at": past_time });
    let (status, body) = app
        .client
        .post_json_auth("/api/v1/auth/api-keys", req, &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_EXPIRATION");
}

#[tokio::test]
async fn tier2_api_key_create_unauthenticated_rejected() {
    let app = TestApp::new().await;

    let req = json!({ "name": "Unauthorized Key" });
    let (status, body) = app.client.post_json("/api/v1/auth/api-keys", req).await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn tier2_api_key_delete_nonexistent_id_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let fake_id = Uuid::new_v4();
    let (status, body) = app
        .client
        .delete_auth(&format!("/api/v1/auth/api-keys/{}", fake_id), &admin_token)
        .await;
    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "API_KEY_NOT_FOUND");
}

#[tokio::test]
async fn tier2_api_key_delete_unauthenticated_rejected() {
    let app = TestApp::new().await;
    let fake_id = Uuid::new_v4();

    let req = http::Request::builder()
        .method(Method::DELETE)
        .uri(format!("/api/v1/auth/api-keys/{}", fake_id))
        .body(axum::body::Body::empty())
        .unwrap();

    let (status, _, body) = app.client.execute(req).await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

// =============================================================================
// F1: Custom Enums Serialization & String Parsing (Auth/Role types) (3 tests)
// =============================================================================

#[test]
fn tier2_enum_user_role_from_str_invalid() {
    assert!(UserRole::from_str("root").is_err());
    assert!(UserRole::from_str("superadmin").is_err());
    assert!(UserRole::from_str("").is_err());
    assert!(UserRole::from_str("guest").is_err());
}

#[test]
fn tier2_enum_user_role_json_deserialize_invalid() {
    assert!(serde_json::from_str::<UserRole>("\"superuser\"").is_err());
    assert!(serde_json::from_str::<UserRole>("123").is_err());
    assert!(serde_json::from_str::<UserRole>("null").is_err());
}

#[test]
fn tier2_enum_user_role_case_sensitivity() {
    assert!(UserRole::from_str("Admin").is_err());
    assert!(UserRole::from_str("ADMIN").is_err());
    assert!(UserRole::from_str("Developer").is_err());
    assert!(UserRole::from_str("auditor").is_ok());
}
