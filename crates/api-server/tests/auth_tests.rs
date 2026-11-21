mod common;
use common::*;

use axum::http::StatusCode;
use serde_json::json;
use shared_types::{
    ApiKeyResponse, CreateApiKeyResponse, TokenResponse, UserProfile, UserRole,
};

#[tokio::test]
async fn test_healthz() {
    let harness = TestHarness::new().await;
    let (status, body) = harness.get("/healthz").await;
    assert_eq!(status, StatusCode::OK);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["status"], "ok");

    let (status, body) = harness.get("/api/v1/healthz").await;
    assert_eq!(status, StatusCode::OK);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["status"], "ok");
}

#[tokio::test]
async fn test_login_success_all_roles() {
    let harness = TestHarness::new().await;

    let roles = [
        ("admin@kds.local", "AdminSecret123!", UserRole::Admin),
        ("seceng@kds.local", "SecEngSecret123!", UserRole::SecurityEngineer),
        ("dev@kds.local", "DevSecret123!", UserRole::Developer),
        ("auditor@kds.local", "AuditorSecret123!", UserRole::Auditor),
    ];

    for (email, pass, expected_role) in roles {
        let (status, body) = harness
            .post_json(
                "/api/v1/auth/login",
                json!({
                    "email": email,
                    "password": pass
                }),
            )
            .await;

        assert_eq!(status, StatusCode::OK);
        let resp: TokenResponse = parse_json(&body);
        assert!(!resp.access_token.is_empty());
        assert!(!resp.refresh_token.is_empty());
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 900);
        assert_eq!(resp.user.role, expected_role);
        assert_eq!(resp.user.email, email);
    }
}

#[tokio::test]
async fn test_login_invalid_credentials() {
    let harness = TestHarness::new().await;

    // Wrong password
    let (status, body) = harness
        .post_json(
            "/api/v1/auth/login",
            json!({
                "email": "admin@kds.local",
                "password": "WrongPassword999!"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "INVALID_CREDENTIALS");

    // Nonexistent email
    let (status, body) = harness
        .post_json(
            "/api/v1/auth/login",
            json!({
                "email": "ghost@kds.local",
                "password": "Password123!"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "INVALID_CREDENTIALS");

    // Empty credentials
    let (status, body) = harness
        .post_json(
            "/api/v1/auth/login",
            json!({
                "email": "",
                "password": ""
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn test_me_endpoint() {
    let harness = TestHarness::new().await;

    // Login to get token
    let (_, body) = harness
        .post_json(
            "/api/v1/auth/login",
            json!({
                "email": "admin@kds.local",
                "password": "AdminSecret123!"
            }),
        )
        .await;
    let login_resp: TokenResponse = parse_json(&body);

    // Call /me
    let (status, body) = harness
        .get_auth("/api/v1/auth/me", &login_resp.access_token)
        .await;
    assert_eq!(status, StatusCode::OK);
    let profile: UserProfile = parse_json(&body);
    assert_eq!(profile.email, "admin@kds.local");
    assert_eq!(profile.role, UserRole::Admin);

    // Unauthenticated call
    let (status, body) = harness.get("/api/v1/auth/me").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "INVALID_TOKEN");
}

#[tokio::test]
async fn test_refresh_token_flow() {
    let harness = TestHarness::new().await;

    // Login
    let (_, body) = harness
        .post_json(
            "/api/v1/auth/login",
            json!({
                "email": "seceng@kds.local",
                "password": "SecEngSecret123!"
            }),
        )
        .await;
    let login_resp: TokenResponse = parse_json(&body);

    // Refresh
    let (status, body) = harness
        .post_json(
            "/api/v1/auth/refresh",
            json!({
                "refresh_token": login_resp.refresh_token
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let refresh_resp: TokenResponse = parse_json(&body);
    assert!(!refresh_resp.access_token.is_empty());
    assert_ne!(refresh_resp.refresh_token, login_resp.refresh_token);

    // Old token should be rotated and fail
    let (status, body) = harness
        .post_json(
            "/api/v1/auth/refresh",
            json!({
                "refresh_token": login_resp.refresh_token
            }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "INVALID_REFRESH_TOKEN");
}

#[tokio::test]
async fn test_logout_flow() {
    let harness = TestHarness::new().await;

    let (_, body) = harness
        .post_json(
            "/api/v1/auth/login",
            json!({
                "email": "dev@kds.local",
                "password": "DevSecret123!"
            }),
        )
        .await;
    let login_resp: TokenResponse = parse_json(&body);

    // Logout
    let (status, body) = harness
        .post_json_auth(
            "/api/v1/auth/logout",
            json!({ "refresh_token": login_resp.refresh_token }),
            &login_resp.access_token,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["status"], "logged_out");

    // Using the refresh token should now fail
    let (status, body) = harness
        .post_json(
            "/api/v1/auth/refresh",
            json!({ "refresh_token": login_resp.refresh_token }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "INVALID_REFRESH_TOKEN");
}

#[tokio::test]
async fn test_api_keys_crud_and_rbac() {
    let harness = TestHarness::new().await;

    // Login as admin
    let (_, body) = harness
        .post_json(
            "/api/v1/auth/login",
            json!({
                "email": "admin@kds.local",
                "password": "AdminSecret123!"
            }),
        )
        .await;
    let admin_login: TokenResponse = parse_json(&body);

    // Login as dev (cannot manage API keys)
    let (_, body) = harness
        .post_json(
            "/api/v1/auth/login",
            json!({
                "email": "dev@kds.local",
                "password": "DevSecret123!"
            }),
        )
        .await;
    let dev_login: TokenResponse = parse_json(&body);

    // Dev tries to create API key -> FORBIDDEN
    let (status, body) = harness
        .post_json_auth(
            "/api/v1/auth/keys",
            json!({ "name": "Dev Unauthorized Key" }),
            &dev_login.access_token,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "FORBIDDEN_RESOURCE");

    // Admin creates API key via /api/v1/auth/keys
    let (status, body) = harness
        .post_json_auth(
            "/api/v1/auth/keys",
            json!({ "name": "CI Deployment Key" }),
            &admin_login.access_token,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: CreateApiKeyResponse = parse_json(&body);
    assert!(created.secret_key.starts_with("appsec_live_"));
    assert_eq!(created.name, "CI Deployment Key");

    // List API keys
    let (status, body) = harness
        .get_auth("/api/v1/auth/keys", &admin_login.access_token)
        .await;
    assert_eq!(status, StatusCode::OK);
    let keys: Vec<ApiKeyResponse> = parse_json(&body);
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].id, created.id);

    // Authenticate with the new API key to GET /api/v1/apps
    let (status, _, _) = harness
        .request(
            axum::http::Method::GET,
            "/api/v1/apps",
            None,
            Some(&created.secret_key),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Delete API key
    let (status, _) = harness
        .delete_auth(
            &format!("/api/v1/auth/keys/{}", created.id),
            &admin_login.access_token,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // API key should now be rejected
    let (status, _, err_body) = harness
        .request(
            axum::http::Method::GET,
            "/api/v1/apps",
            None,
            Some(&created.secret_key),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let val: serde_json::Value = parse_json(&err_body);
    assert_eq!(val["error"]["code"], "INVALID_API_KEY");
}
