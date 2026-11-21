mod common;
use common::*;

use axum::http::StatusCode;
use serde_json::json;
use shared_types::{
    AppCriticality, AppEnvironment, AppTrendsResponse, ApplicationResponse,
};
use uuid::Uuid;

#[tokio::test]
async fn test_apps_crud_and_validation() {
    let harness = TestHarness::new().await;
    let admin_tok = harness.admin_token().await;
    let dev_tok = harness.dev_token().await;
    let auditor_tok = harness.auditor_token().await;

    // 1. Initial list should be empty
    let (status, body) = harness.get_auth("/api/v1/apps", &admin_tok).await;
    assert_eq!(status, StatusCode::OK);
    let apps: Vec<ApplicationResponse> = parse_json(&body);
    assert!(apps.is_empty());

    // 2. Dev & Auditor forbidden from creating app
    let create_payload = json!({
        "name": "Payments Service",
        "description": "Core payments API",
        "base_url": "https://payments.example.com",
        "environment": "production",
        "criticality": "critical",
        "team_name": "FinTech",
        "include_regexes": ["^https://payments\\.example\\.com/api/.*"],
        "exclude_regexes": ["^https://payments\\.example\\.com/logout"],
        "cron_schedule": "0 2 * * *",
        "is_authorized": true
    });

    let (status, _body) = harness
        .post_json_auth("/api/v1/apps", create_payload.clone(), &dev_tok)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let val: serde_json::Value = parse_json(&_body);
    assert_eq!(val["error"]["code"], "FORBIDDEN_RESOURCE");

    let (status, _body) = harness
        .post_json_auth("/api/v1/apps", create_payload.clone(), &auditor_tok)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 3. Validation: is_authorized must be true
    let mut unauthorized_payload = create_payload.clone();
    unauthorized_payload["is_authorized"] = json!(false);
    let (status, body) = harness
        .post_json_auth("/api/v1/apps", unauthorized_payload, &admin_tok)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "UNAUTHORIZED_TARGET");

    // 4. Validation: invalid URL
    let mut invalid_url_payload = create_payload.clone();
    invalid_url_payload["base_url"] = json!("ftp://payments.example.com");
    let (status, body) = harness
        .post_json_auth("/api/v1/apps", invalid_url_payload, &admin_tok)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "INVALID_APPLICATION_URL");

    // 5. Validation: invalid cron format
    let mut invalid_cron_payload = create_payload.clone();
    invalid_cron_payload["cron_schedule"] = json!("every day at 2am");
    let (status, body) = harness
        .post_json_auth("/api/v1/apps", invalid_cron_payload, &admin_tok)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "INVALID_CRON_SCHEDULE");

    // 6. Successful creation by Admin
    let (status, body) = harness
        .post_json_auth("/api/v1/apps", create_payload.clone(), &admin_tok)
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: ApplicationResponse = parse_json(&body);
    assert_eq!(created.name, "Payments Service");
    assert_eq!(created.environment, AppEnvironment::Production);
    assert_eq!(created.criticality, AppCriticality::Critical);
    assert!(created.is_authorized);

    // 7. Duplicate app rejected
    let (status, body) = harness
        .post_json_auth("/api/v1/apps", create_payload.clone(), &admin_tok)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "DUPLICATE_APPLICATION");

    // 8. Get App by ID
    let (status, body) = harness
        .get_auth(&format!("/api/v1/apps/{}", created.id), &dev_tok)
        .await;
    assert_eq!(status, StatusCode::OK);
    let fetched: ApplicationResponse = parse_json(&body);
    assert_eq!(fetched.id, created.id);

    // 9. Patch App
    let (status, body) = harness
        .patch_json_auth(
            &format!("/api/v1/apps/{}", created.id),
            json!({ "team_name": "SecurityEngineering" }),
            &admin_tok,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let patched: ApplicationResponse = parse_json(&body);
    assert_eq!(patched.team_name, Some("SecurityEngineering".to_string()));

    // 10. Configure Auth
    let (status, body) = harness
        .put_json_auth(
            &format!("/api/v1/apps/{}/auth", created.id),
            json!({
                "auth_type": "bearer_token",
                "auth_data": { "token": "secret_session_token_123" }
            }),
            &admin_tok,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["has_auth_configured"], true);

    // 11. Get Trends
    let (status, body) = harness
        .get_auth(&format!("/api/v1/apps/{}/trends", created.id), &dev_tok)
        .await;
    assert_eq!(status, StatusCode::OK);
    let trends: AppTrendsResponse = parse_json(&body);
    assert_eq!(trends.app_id, created.id);

    // 12. Delete App by non-admin -> FORBIDDEN
    let (status, _) = harness
        .delete_auth(&format!("/api/v1/apps/{}", created.id), &dev_tok)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 13. Delete App by Admin -> OK
    let (status, body) = harness
        .delete_auth(&format!("/api/v1/apps/{}", created.id), &admin_tok)
        .await;
    assert_eq!(status, StatusCode::OK);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["status"], "deleted");

    // 14. Verify deletion
    let (status, _) = harness
        .get_auth(&format!("/api/v1/apps/{}", created.id), &admin_tok)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_apps_nonexistent_and_invalid_uuid() {
    let harness = TestHarness::new().await;
    let admin_tok = harness.admin_token().await;

    let fake_id = Uuid::new_v4();
    let (status, body) = harness
        .get_auth(&format!("/api/v1/apps/{}", fake_id), &admin_tok)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "APPLICATION_NOT_FOUND");

    let (status, body) = harness
        .get_auth("/api/v1/apps/not-a-valid-uuid/trends", &admin_tok)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let val: serde_json::Value = parse_json(&body);
    assert_eq!(val["error"]["code"], "INVALID_UUID");
}
