mod common;
mod tier1_feature_coverage;
mod tier2_boundary_corner;
mod tier3_cross_feature;
mod tier4_real_world;

use axum::http::StatusCode;
use uuid::Uuid;
use common::*;

#[tokio::test]
async fn verify_test_harness_bootstrap() {
    // 1. Initialize TestApp with in-memory state and router
    let app = TestApp::new().await;

    // 2. Verify admin user seeding and JWT token creation
    let (admin_id, admin_token) = app.seed_admin().await;
    assert!(!admin_token.is_empty(), "Admin token should not be empty");
    assert!(!admin_id.is_nil(), "Admin ID should be valid UUID");

    // Verify claims inside token
    let claims = decode_jwt_token(&admin_token, &app.jwt_secret)
        .expect("Generated admin token must decode with secret");
    assert_eq!(claims.sub, admin_id.to_string());
    assert_eq!(claims.email, "admin@kds.local");
    assert_eq!(claims.role, UserRole::Admin);

    // 3. Verify other role seeding
    let (seceng_id, seceng_token) = app.seed_sec_eng().await;
    assert!(!seceng_id.is_nil());
    assert!(!seceng_token.is_empty());

    let (dev_id, dev_token) = app.seed_developer().await;
    assert!(!dev_id.is_nil());
    assert!(!dev_token.is_empty());

    let (auditor_id, auditor_token) = app.seed_auditor().await;
    assert!(!auditor_id.is_nil());
    assert!(!auditor_token.is_empty());

    // 4. Verify API Key generation
    let raw_api_key = app.create_api_key(admin_id, "CI Test Key").await;
    assert!(raw_api_key.starts_with("appsec_live_"), "API key must have standard prefix");
    let key_hash = hash_api_key(&raw_api_key);
    let key_record = app.user_repo.find_api_key_by_hash(&key_hash).await;
    assert!(key_record.is_some(), "API key record must be queryable by SHA-256 hash");

    // 5. Verify boundary tokens
    let exp_token = app.expired_token(UserRole::Developer);
    assert!(decode_jwt_token(&exp_token, &app.jwt_secret).is_err(), "Expired token must fail");

    let tamp_token = app.tampered_token(UserRole::SecurityEngineer);
    assert!(decode_jwt_token(&tamp_token, &app.jwt_secret).is_err(), "Tampered token must fail");

    // 6. Verify Mock ZAP Alert fixtures
    let sqli = AlertFixtureFactory::sqli_alert("https://test.example.com");
    assert_eq!(sqli.plugin_id, "40018");
    assert_eq!(sqli.risk, "High");
    assert_eq!(sqli.cweid, "89");

    let xss = AlertFixtureFactory::xss_alert("https://test.example.com");
    assert_eq!(xss.plugin_id, "40012");
    assert_eq!(xss.cweid, "79");

    let csrf = AlertFixtureFactory::csrf_alert("https://test.example.com");
    assert_eq!(csrf.plugin_id, "40026");

    let csp = AlertFixtureFactory::csp_alert("https://test.example.com");
    assert_eq!(csp.plugin_id, "10038");

    // 7. Verify Application Seeding and Mock Scan Pipeline
    let app_res = app.seed_application("Test Payment Gateway", "https://payments.internal", true).await;
    assert_eq!(app_res.name, "Test Payment Gateway");
    assert!(app_res.is_authorized);

    let scan_id = Uuid::new_v4();
    let initial_scan = ScanResponse {
        id: scan_id,
        application_id: app_res.id,
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
    app.scan_repo.insert_scan(initial_scan).await;

    app.run_mock_scan(scan_id, app_res.id, vec![sqli, xss, csrf, csp]).await;
    let completed_scan = app.scan_repo.get_scan(scan_id).await.expect("Scan must exist");
    assert_eq!(completed_scan.status, ScanStatus::Completed);
    assert_eq!(completed_scan.progress_percent, 100);
    assert_eq!(completed_scan.diff_summary.new_count, 4);

    // 8. Verify Axum tower::Service::oneshot execution via TestClient
    // 8a. Health check endpoint
    let (status, body) = app.client.get("/healthz").await;
    assert_eq!(status, StatusCode::OK);
    let val: serde_json::Value = serde_json::from_slice(&body).expect("Valid JSON");
    assert_eq!(val["status"], "ok");

    // 8b. Authenticated me endpoint
    let (me_status, me_body) = app.client.get_auth("/api/v1/auth/me", &admin_token).await;
    assert_eq!(me_status, StatusCode::OK);
    let user_info: UserRecord = serde_json::from_slice(&me_body).expect("Valid user record");
    assert_eq!(user_info.email, "admin@kds.local");

    // 8c. Unauthenticated request returning standardized ErrorEnvelope
    let (err_status, err_body) = app.client.get("/api/v1/auth/me").await;
    assert_err_code!(
        err_status,
        &err_body,
        StatusCode::UNAUTHORIZED,
        "INVALID_TOKEN"
    );

    // 8d. Unauthorized application creation returning UNAUTHORIZED_TARGET
    let unauth_app_req = serde_json::json!({
        "name": "Rogue Target",
        "description": "Unauthorized target attempt",
        "base_url": "https://rogue.example.com",
        "environment": "staging",
        "criticality": "high",
        "team_name": "Dev",
        "include_regexes": [],
        "exclude_regexes": [],
        "cron_schedule": null,
        "is_authorized": false
    });
    let (app_err_status, app_err_body) = app
        .client
        .post_json_auth("/api/v1/apps", unauth_app_req, &admin_token)
        .await;
    assert_err_code!(
        app_err_status,
        &app_err_body,
        StatusCode::BAD_REQUEST,
        "UNAUTHORIZED_TARGET"
    );
}
