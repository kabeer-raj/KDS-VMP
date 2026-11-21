//! Tier 3: Cross-Feature Combinations - Auth, App & Scan Interactions

use axum::http::StatusCode;
use infra::traits::UserRepository;
use serde_json::json;

use crate::common::*;

#[tokio::test]
async fn test_tier3_rbac_cross_role_access_boundaries() {
    let harness = IntegratedHarness::new().await;
    let admin_tok = harness.admin_token().await;
    let dev_tok = harness.dev_token().await;
    let auditor_tok = harness.auditor_token().await;

    // 1. Admin creates application
    let app_req = json!({
        "name": "RBAC Secured App",
        "description": "Multi-role boundary check",
        "base_url": "https://rbac.internal",
        "environment": "staging",
        "criticality": "high",
        "include_regexes": ["https://rbac.internal/.*"],
        "exclude_regexes": [],
        "cron_schedule": null,
        "is_authorized": true
    });
    let (s, b) = harness.client.post_json_auth("/api/v1/apps", app_req, &admin_tok).await;
    assert_eq!(s, StatusCode::CREATED);
    let app: ApplicationResponse = serde_json::from_slice(&b).unwrap();

    // 2. Auditor tries to trigger scan -> 403 Forbidden
    let scan_req = json!({ "scan_type": "full_active" });
    let (s_audit, _) = harness.client.post_json_auth(&format!("/api/v1/apps/{}/scans", app.id), scan_req.clone(), &auditor_tok).await;
    assert_eq!(s_audit, StatusCode::FORBIDDEN);

    // 3. Developer tries to delete app -> 403 Forbidden
    let (s_del_dev, _) = harness.client.delete_auth(&format!("/api/v1/apps/{}", app.id), &dev_tok).await;
    assert_eq!(s_del_dev, StatusCode::FORBIDDEN);

    // 4. Admin deletes app -> 200 OK
    let (s_del_admin, _) = harness.client.delete_auth(&format!("/api/v1/apps/{}", app.id), &admin_tok).await;
    assert_eq!(s_del_admin, StatusCode::OK);
}

#[tokio::test]
async fn test_tier3_api_key_ci_cd_scan_dispatch_and_polling() {
    let harness = IntegratedHarness::new().await;
    let admin_user = harness.user_repo.find_by_email("admin@kds.local").await.unwrap().unwrap();
    let api_key = harness.create_api_key(admin_user.id, "CI-CD GitHub Actions").await;

    // 1. Create app using API Key
    let app_req = json!({
        "name": "CI-CD Target App",
        "base_url": "https://cicd.internal",
        "environment": "production",
        "criticality": "critical",
        "include_regexes": ["https://cicd.internal/.*"],
        "exclude_regexes": [],
        "is_authorized": true
    });
    let (s_app, b_app) = harness.client.post_json_api_key("/api/v1/apps", app_req, &api_key).await;
    assert_eq!(s_app, StatusCode::CREATED);
    let app: ApplicationResponse = serde_json::from_slice(&b_app).unwrap();

    // 2. Trigger scan using API Key
    let scan_req = json!({ "scan_type": "full_active" });
    let (s_scan, b_scan) = harness.client.post_json_api_key(&format!("/api/v1/apps/{}/scans", app.id), scan_req, &api_key).await;
    assert_eq!(s_scan, StatusCode::ACCEPTED);
    let scan: ScanResponse = serde_json::from_slice(&b_scan).unwrap();

    // 3. Poll scan status using API Key
    let (s_poll, b_poll) = harness.client.get_api_key(&format!("/api/v1/scans/{}", scan.id), &api_key).await;
    assert_eq!(s_poll, StatusCode::OK);
    let polled_scan: ScanResponse = serde_json::from_slice(&b_poll).unwrap();
    assert_eq!(polled_scan.id, scan.id);
}

#[tokio::test]
async fn test_tier3_api_key_rotation_and_revocation_enforcement() {
    let harness = IntegratedHarness::new().await;
    let admin_tok = harness.admin_token().await;
    let admin_user = harness.user_repo.find_by_email("admin@kds.local").await.unwrap().unwrap();

    // 1. Create Key 1
    let key1 = harness.create_api_key(admin_user.id, "Key 1").await;
    let (s1, _) = harness.client.get_api_key("/api/v1/apps", &key1).await;
    assert_eq!(s1, StatusCode::OK);

    // 2. Create Key 2 via API
    let create_key_req = json!({ "name": "Key 2" });
    let (s2, b2) = harness.client.post_json_auth("/api/v1/auth/keys", create_key_req, &admin_tok).await;
    assert_eq!(s2, StatusCode::CREATED);
    let key2_resp: CreateApiKeyResponse = serde_json::from_slice(&b2).unwrap();

    // 3. Delete Key 2 via API
    let (s_del, _) = harness.client.delete_auth(&format!("/api/v1/auth/keys/{}", key2_resp.id), &admin_tok).await;
    assert_eq!(s_del, StatusCode::NO_CONTENT);

    // 4. Revoked Key 2 fails authentication -> 401 Unauthorized
    let (s_fail, _) = harness.client.get_api_key("/api/v1/apps", &key2_resp.secret_key).await;
    assert_eq!(s_fail, StatusCode::UNAUTHORIZED);

    // 5. Active Key 1 still works
    let (s_ok, _) = harness.client.get_api_key("/api/v1/apps", &key1).await;
    assert_eq!(s_ok, StatusCode::OK);
}

#[tokio::test]
async fn test_tier3_token_refresh_during_active_session() {
    let harness = IntegratedHarness::new().await;

    // Login
    let login_req = json!({
        "email": "dev@kds.local",
        "password": "DevSecret123!"
    });
    let (s_login, b_login) = harness.client.post_json("/api/v1/auth/login", login_req).await;
    assert_eq!(s_login, StatusCode::OK);
    let token_resp: TokenResponse = serde_json::from_slice(&b_login).unwrap();

    // Refresh token
    let refresh_req = json!({
        "refresh_token": token_resp.refresh_token
    });
    let (s_ref, b_ref) = harness.client.post_json("/api/v1/auth/refresh", refresh_req).await;
    assert_eq!(s_ref, StatusCode::OK);
    let new_token_resp: TokenResponse = serde_json::from_slice(&b_ref).unwrap();
    assert_ne!(new_token_resp.refresh_token, token_resp.refresh_token);

    // New token accesses resources
    let (s_me, b_me) = harness.client.get_auth("/api/v1/auth/me", &new_token_resp.access_token).await;
    assert_eq!(s_me, StatusCode::OK);
    let me: UserProfile = serde_json::from_slice(&b_me).unwrap();
    assert_eq!(me.email, "dev@kds.local");
}

#[tokio::test]
async fn test_tier3_app_auth_configuration_lifecycle() {
    let harness = IntegratedHarness::new().await;
    let admin_tok = harness.admin_token().await;
    let app = harness.seed_application("Auth Lifecycle App", "https://authtest.internal", true).await;

    // Configure Bearer auth
    let auth_cfg = json!({
        "auth_type": "bearer_token",
        "auth_data": {
            "token": "secret_oauth_bearer_token_123"
        }
    });
    let uri = format!("/api/v1/apps/{}/auth", app.id);
    let (s, _) = harness.client.put_json_auth(&uri, auth_cfg, &admin_tok).await;
    assert_eq!(s, StatusCode::OK);

    // Verify app state shows has_auth_configured: true
    let (_, b) = harness.client.get_auth(&format!("/api/v1/apps/{}", app.id), &admin_tok).await;
    let updated: ApplicationResponse = serde_json::from_slice(&b).unwrap();
    assert!(updated.has_auth_configured);
}
