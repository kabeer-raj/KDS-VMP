//! Tier 1: Feature Coverage Integration Tests — Authentication, API Keys & RBAC
//! Covers Features: F1 (UserRole Enum), F25 (JWT Middleware), F26 (API Key Middleware),
//! F27 (RBAC Authorization), F30 (Auth REST Endpoints), F31 (API Key REST Endpoints)

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use axum::http::{Method, StatusCode};
use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

use crate::common::*;

// =============================================================================
// F1: Custom Enums (UserRole) (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f1_user_role_roundtrip_all_variants() {
    let variants = [
        UserRole::Admin,
        UserRole::SecurityEngineer,
        UserRole::Developer,
        UserRole::Auditor,
    ];

    for role in variants {
        let serialized = serde_json::to_string(&role).expect("Serialize UserRole");
        let deserialized: UserRole =
            serde_json::from_str(&serialized).expect("Deserialize UserRole");
        assert_eq!(deserialized, role);

        assert_eq!(role.to_string(), role.as_str());
        let parsed = UserRole::from_str(role.as_str()).expect("Parse from str");
        assert_eq!(parsed, role);
    }
}

#[tokio::test]
async fn test_f1_user_role_snake_case_format() {
    assert_eq!(
        serde_json::to_string(&UserRole::Admin).unwrap(),
        "\"admin\""
    );
    assert_eq!(
        serde_json::to_string(&UserRole::SecurityEngineer).unwrap(),
        "\"security_engineer\""
    );
    assert_eq!(
        serde_json::to_string(&UserRole::Developer).unwrap(),
        "\"developer\""
    );
    assert_eq!(
        serde_json::to_string(&UserRole::Auditor).unwrap(),
        "\"auditor\""
    );
}

#[tokio::test]
async fn test_f1_user_role_deserialization_from_valid_strings() {
    assert_eq!(
        serde_json::from_str::<UserRole>("\"admin\"").unwrap(),
        UserRole::Admin
    );
    assert_eq!(
        serde_json::from_str::<UserRole>("\"security_engineer\"").unwrap(),
        UserRole::SecurityEngineer
    );
    assert_eq!(
        serde_json::from_str::<UserRole>("\"developer\"").unwrap(),
        UserRole::Developer
    );
    assert_eq!(
        serde_json::from_str::<UserRole>("\"auditor\"").unwrap(),
        UserRole::Auditor
    );

    assert_eq!(UserRole::from_str("admin").unwrap(), UserRole::Admin);
    assert_eq!(
        UserRole::from_str("security_engineer").unwrap(),
        UserRole::SecurityEngineer
    );
    assert_eq!(
        UserRole::from_str("developer").unwrap(),
        UserRole::Developer
    );
    assert_eq!(UserRole::from_str("auditor").unwrap(), UserRole::Auditor);
}

#[tokio::test]
async fn test_f1_user_role_case_sensitivity_rejection() {
    assert!(UserRole::from_str("Admin").is_err());
    assert!(UserRole::from_str("ADMIN").is_err());
    assert!(UserRole::from_str("Security_Engineer").is_err());
    assert!(UserRole::from_str("DEVELOPER").is_err());
    assert!(UserRole::from_str("Auditor").is_err());
    assert!(UserRole::from_str("root").is_err());
    assert!(UserRole::from_str("").is_err());
}

#[tokio::test]
async fn test_f1_user_role_hash_and_equality() {
    let mut set = HashSet::new();
    set.insert(UserRole::Admin);
    set.insert(UserRole::SecurityEngineer);
    set.insert(UserRole::Developer);
    set.insert(UserRole::Auditor);
    set.insert(UserRole::Admin); // Duplicate insertion
    assert_eq!(set.len(), 4);

    let mut map = HashMap::new();
    map.insert(UserRole::Admin, "full_access");
    map.insert(UserRole::SecurityEngineer, "scan_access");
    map.insert(UserRole::Developer, "view_access");
    map.insert(UserRole::Auditor, "audit_access");

    assert_eq!(map.get(&UserRole::Admin), Some(&"full_access"));
    assert_eq!(map.get(&UserRole::Developer), Some(&"view_access"));
}

// =============================================================================
// F25: JWT Auth Middleware (6 tests)
// =============================================================================

#[tokio::test]
async fn test_f25_jwt_admin_token_authenticated_request() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let (status, body) = app.client.get_auth("/api/v1/auth/me", &admin_token).await;
    assert_eq!(status, StatusCode::OK);
    let profile: UserProfile = serde_json::from_slice(&body).expect("Valid UserProfile");
    assert_eq!(profile.role, UserRole::Admin);
    assert_eq!(profile.email, "admin@kds.local");
    assert!(profile.is_active);
}

#[tokio::test]
async fn test_f25_jwt_seceng_token_authenticated_request() {
    let app = TestApp::new().await;
    let (_, seceng_token) = app.seed_sec_eng().await;

    let (status, body) = app.client.get_auth("/api/v1/auth/me", &seceng_token).await;
    assert_eq!(status, StatusCode::OK);
    let profile: UserProfile = serde_json::from_slice(&body).expect("Valid UserProfile");
    assert_eq!(profile.role, UserRole::SecurityEngineer);
    assert_eq!(profile.email, "seceng@kds.local");
}

#[tokio::test]
async fn test_f25_jwt_developer_token_authenticated_request() {
    let app = TestApp::new().await;
    let (_, dev_token) = app.seed_developer().await;

    let (status, body) = app.client.get_auth("/api/v1/auth/me", &dev_token).await;
    assert_eq!(status, StatusCode::OK);
    let profile: UserProfile = serde_json::from_slice(&body).expect("Valid UserProfile");
    assert_eq!(profile.role, UserRole::Developer);
    assert_eq!(profile.email, "dev@kds.local");
}

#[tokio::test]
async fn test_f25_jwt_auditor_token_authenticated_request() {
    let app = TestApp::new().await;
    let (_, auditor_token) = app.seed_auditor().await;

    let (status, body) = app.client.get_auth("/api/v1/auth/me", &auditor_token).await;
    assert_eq!(status, StatusCode::OK);
    let profile: UserProfile = serde_json::from_slice(&body).expect("Valid UserProfile");
    assert_eq!(profile.role, UserRole::Auditor);
    assert_eq!(profile.email, "auditor@kds.local");
}

#[tokio::test]
async fn test_f25_jwt_claims_decoding_and_payload_integrity() {
    let app = TestApp::new().await;
    let (admin_id, token) = app.seed_admin().await;

    let claims = decode_jwt_token(&token, &app.jwt_secret).expect("Decoded claims");
    assert_eq!(claims.sub, admin_id.to_string());
    assert_eq!(claims.email, "admin@kds.local");
    assert_eq!(claims.role, UserRole::Admin);
    assert!(claims.exp > claims.iat);
}

#[tokio::test]
async fn test_f25_jwt_session_revalidation_multiple_requests() {
    let app = TestApp::new().await;
    let (_, token) = app.seed_admin().await;

    for _ in 0..5 {
        let (status, body) = app.client.get_auth("/api/v1/auth/me", &token).await;
        assert_eq!(status, StatusCode::OK);
        let profile: UserProfile = serde_json::from_slice(&body).expect("Valid UserProfile");
        assert_eq!(profile.email, "admin@kds.local");
    }
}

// =============================================================================
// F26: API Key Middleware (6 tests)
// =============================================================================

#[tokio::test]
async fn test_f26_api_key_admin_authentication_success() {
    let app = TestApp::new().await;
    let (admin_id, _) = app.seed_admin().await;
    let raw_key = app.create_api_key(admin_id, "Admin CI Key").await;

    let (status, body) = app.client.get_api_key("/api/v1/apps", &raw_key).await;
    assert_eq!(status, StatusCode::OK);
    let apps: Vec<ApplicationResponse> = serde_json::from_slice(&body).expect("Valid apps array");
    assert!(apps.is_empty());
}

#[tokio::test]
async fn test_f26_api_key_seceng_authentication_success() {
    let app = TestApp::new().await;
    let (seceng_id, _) = app.seed_sec_eng().await;
    let raw_key = app.create_api_key(seceng_id, "SecEng Automation Key").await;

    let (status, body) = app.client.get_api_key("/api/v1/apps", &raw_key).await;
    assert_eq!(status, StatusCode::OK);
    let apps: Vec<ApplicationResponse> = serde_json::from_slice(&body).expect("Valid apps array");
    assert!(apps.is_empty());
}

#[tokio::test]
async fn test_f26_api_key_sha256_hashing_verification() {
    let app = TestApp::new().await;
    let (admin_id, _) = app.seed_admin().await;
    let raw_key = app.create_api_key(admin_id, "Hash Verification Key").await;

    let hash = hash_api_key(&raw_key);
    assert_eq!(hash.len(), 64, "SHA-256 hex hash must be exactly 64 characters");

    let record = app
        .user_repo
        .find_api_key_by_hash(&hash)
        .await
        .expect("API key must be indexed by key_hash");
    assert_eq!(record.name, "Hash Verification Key");
    assert_eq!(record.user_id, admin_id);
    assert!(!record.key_prefix.is_empty());
}

#[tokio::test]
async fn test_f26_api_key_last_used_timestamp_updated() {
    let app = TestApp::new().await;
    let (admin_id, _) = app.seed_admin().await;
    let raw_key = app.create_api_key(admin_id, "Last Used Timestamp Key").await;
    let hash = hash_api_key(&raw_key);

    let initial = app.user_repo.find_api_key_by_hash(&hash).await.unwrap();
    assert!(initial.last_used_at.is_none());

    let (status, _) = app.client.get_api_key("/api/v1/apps", &raw_key).await;
    assert_eq!(status, StatusCode::OK);

    let updated = app.user_repo.find_api_key_by_hash(&hash).await.unwrap();
    assert!(updated.last_used_at.is_some());
}

#[tokio::test]
async fn test_f26_api_key_future_expiration_accepted() {
    let app = TestApp::new().await;
    let (admin_id, _) = app.seed_admin().await;

    let raw_key = format!("appsec_live_{}", Uuid::new_v4().simple());
    let prefix = &raw_key[..12];
    let key_hash = hash_api_key(&raw_key);
    let future_exp = Utc::now() + Duration::days(30);

    app.user_repo
        .insert_api_key(
            Uuid::new_v4(),
            admin_id,
            "Future Expiration Key",
            prefix,
            &key_hash,
            Some(future_exp),
        )
        .await;

    let (status, _) = app.client.get_api_key("/api/v1/apps", &raw_key).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_f26_api_key_header_case_handling() {
    let app = TestApp::new().await;
    let (admin_id, _) = app.seed_admin().await;
    let raw_key = app.create_api_key(admin_id, "Header Case Key").await;

    // Standard header: X-API-Key
    let req1 = http::Request::builder()
        .method(Method::GET)
        .uri("/api/v1/apps")
        .header("X-API-Key", &raw_key)
        .body(axum::body::Body::empty())
        .unwrap();
    let (status1, _, _) = app.client.execute(req1).await;
    assert_eq!(status1, StatusCode::OK);

    // Lower-case header: x-api-key
    let req2 = http::Request::builder()
        .method(Method::GET)
        .uri("/api/v1/apps")
        .header("x-api-key", &raw_key)
        .body(axum::body::Body::empty())
        .unwrap();
    let (status2, _, _) = app.client.execute(req2).await;
    assert_eq!(status2, StatusCode::OK);
}

// =============================================================================
// F27: RBAC Authorization (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f27_rbac_admin_allowed_endpoints() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    // 1. Create app
    let create_payload = json!({
        "name": "Admin Managed App",
        "base_url": "https://adminapp.internal",
        "environment": "production",
        "criticality": "critical",
        "is_authorized": true
    });
    let (s1, body1) = app
        .client
        .post_json_auth("/api/v1/apps", create_payload, &admin_token)
        .await;
    assert_eq!(s1, StatusCode::CREATED);
    let app_res: ApplicationResponse = serde_json::from_slice(&body1).unwrap();

    // 2. Patch app
    let patch_payload = json!({ "team_name": "CoreSec" });
    let (s2, _) = app
        .client
        .patch_json_auth(&format!("/api/v1/apps/{}", app_res.id), patch_payload, &admin_token)
        .await;
    assert_eq!(s2, StatusCode::OK);

    // 3. Configure auth
    let auth_payload = json!({
        "auth_type": "bearer_token",
        "auth_data": { "token": "admin_secret_auth" }
    });
    let (s3, _) = app
        .client
        .put_json_auth(&format!("/api/v1/apps/{}/auth", app_res.id), auth_payload, &admin_token)
        .await;
    assert_eq!(s3, StatusCode::OK);

    // 4. Delete app
    let (s4, _) = app
        .client
        .delete_auth(&format!("/api/v1/apps/{}", app_res.id), &admin_token)
        .await;
    assert_eq!(s4, StatusCode::OK);
}

#[tokio::test]
async fn test_f27_rbac_seceng_allowed_endpoints() {
    let app = TestApp::new().await;
    let (_, seceng_token) = app.seed_sec_eng().await;

    // 1. Create app
    let create_payload = json!({
        "name": "SecEng Managed App",
        "base_url": "https://secengapp.internal",
        "environment": "staging",
        "criticality": "high",
        "is_authorized": true
    });
    let (s1, body1) = app
        .client
        .post_json_auth("/api/v1/apps", create_payload, &seceng_token)
        .await;
    assert_eq!(s1, StatusCode::CREATED);
    let app_res: ApplicationResponse = serde_json::from_slice(&body1).unwrap();

    // 2. Patch app
    let patch_payload = json!({ "criticality": "medium" });
    let (s2, _) = app
        .client
        .patch_json_auth(&format!("/api/v1/apps/{}", app_res.id), patch_payload, &seceng_token)
        .await;
    assert_eq!(s2, StatusCode::OK);

    // 3. Trigger scan
    let scan_payload = json!({ "scan_type": "baseline_passive" });
    let (s3, _) = app
        .client
        .post_json_auth(&format!("/api/v1/apps/{}/scans", app_res.id), scan_payload, &seceng_token)
        .await;
    assert_eq!(s3, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn test_f27_rbac_developer_allowed_endpoints() {
    let app = TestApp::new().await;
    let (_, dev_token) = app.seed_developer().await;
    let seeded = app.seed_application("Dev Read Target", "https://devread.internal", true).await;

    // 1. List apps
    let (s1, body1) = app.client.get_auth("/api/v1/apps", &dev_token).await;
    assert_eq!(s1, StatusCode::OK);
    let apps: Vec<ApplicationResponse> = serde_json::from_slice(&body1).unwrap();
    assert!(!apps.is_empty());

    // 2. Get app detail
    let (s2, body2) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}", seeded.id), &dev_token)
        .await;
    assert_eq!(s2, StatusCode::OK);
    let app_detail: ApplicationResponse = serde_json::from_slice(&body2).unwrap();
    assert_eq!(app_detail.id, seeded.id);

    // 3. Get trends
    let (s3, _) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}/trends", seeded.id), &dev_token)
        .await;
    assert_eq!(s3, StatusCode::OK);
}

#[tokio::test]
async fn test_f27_rbac_auditor_read_only_access() {
    let app = TestApp::new().await;
    let (_, auditor_token) = app.seed_auditor().await;
    let seeded = app.seed_application("Auditor Read Target", "https://auditread.internal", true).await;

    // 1. Get current profile
    let (s1, _) = app.client.get_auth("/api/v1/auth/me", &auditor_token).await;
    assert_eq!(s1, StatusCode::OK);

    // 2. List apps
    let (s2, _) = app.client.get_auth("/api/v1/apps", &auditor_token).await;
    assert_eq!(s2, StatusCode::OK);

    // 3. Get app detail
    let (s3, _) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}", seeded.id), &auditor_token)
        .await;
    assert_eq!(s3, StatusCode::OK);

    // 4. Get trends
    let (s4, _) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}/trends", seeded.id), &auditor_token)
        .await;
    assert_eq!(s4, StatusCode::OK);
}

#[tokio::test]
async fn test_f27_rbac_role_hierarchy_matrix() {
    let app = TestApp::new().await;
    let (admin_id, _) = app.seed_admin().await;
    let (seceng_id, _) = app.seed_sec_eng().await;
    let (dev_id, _) = app.seed_developer().await;
    let (auditor_id, _) = app.seed_auditor().await;

    let admin_user = app.user_repo.find_by_id(admin_id).await.unwrap();
    let seceng_user = app.user_repo.find_by_id(seceng_id).await.unwrap();
    let dev_user = app.user_repo.find_by_id(dev_id).await.unwrap();
    let auditor_user = app.user_repo.find_by_id(auditor_id).await.unwrap();

    let admin_id_auth = AuthIdentity::User(admin_user);
    let seceng_id_auth = AuthIdentity::User(seceng_user);
    let dev_id_auth = AuthIdentity::User(dev_user);
    let auditor_id_auth = AuthIdentity::User(auditor_user);

    let admin_only = [UserRole::Admin];
    let privileged = [UserRole::Admin, UserRole::SecurityEngineer];
    let all_roles = [
        UserRole::Admin,
        UserRole::SecurityEngineer,
        UserRole::Developer,
        UserRole::Auditor,
    ];

    assert!(check_rbac(&admin_id_auth, &admin_only).is_ok());
    assert!(check_rbac(&seceng_id_auth, &admin_only).is_err());
    assert!(check_rbac(&dev_id_auth, &admin_only).is_err());
    assert!(check_rbac(&auditor_id_auth, &admin_only).is_err());

    assert!(check_rbac(&admin_id_auth, &privileged).is_ok());
    assert!(check_rbac(&seceng_id_auth, &privileged).is_ok());
    assert!(check_rbac(&dev_id_auth, &privileged).is_err());
    assert!(check_rbac(&auditor_id_auth, &privileged).is_err());

    assert!(check_rbac(&admin_id_auth, &all_roles).is_ok());
    assert!(check_rbac(&seceng_id_auth, &all_roles).is_ok());
    assert!(check_rbac(&dev_id_auth, &all_roles).is_ok());
    assert!(check_rbac(&auditor_id_auth, &all_roles).is_ok());
}

// =============================================================================
// F30: Auth REST Endpoints (6 tests)
// =============================================================================

#[tokio::test]
async fn test_f30_login_admin_credentials_success() {
    let app = TestApp::new().await;

    let payload = json!({
        "email": "admin@kds.local",
        "password": "AdminSecret123!"
    });

    let (status, body) = app.client.post_json("/api/v1/auth/login", payload).await;
    assert_eq!(status, StatusCode::OK);

    let resp: TokenResponse = serde_json::from_slice(&body).expect("Valid TokenResponse");
    assert!(!resp.access_token.is_empty());
    assert!(!resp.refresh_token.is_empty());
    assert_eq!(resp.token_type, "Bearer");
    assert_eq!(resp.expires_in, 900);
    assert_eq!(resp.user.role, UserRole::Admin);
    assert_eq!(resp.user.email, "admin@kds.local");
}

#[tokio::test]
async fn test_f30_login_all_user_roles_success() {
    let app = TestApp::new().await;

    let credentials = [
        ("seceng@kds.local", "SecEngSecret123!", UserRole::SecurityEngineer),
        ("dev@kds.local", "DevSecret123!", UserRole::Developer),
        ("auditor@kds.local", "AuditorSecret123!", UserRole::Auditor),
    ];

    for (email, pass, expected_role) in credentials {
        let payload = json!({ "email": email, "password": pass });
        let (status, body) = app.client.post_json("/api/v1/auth/login", payload).await;
        assert_eq!(status, StatusCode::OK);
        let resp: TokenResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.user.role, expected_role);
    }
}

#[tokio::test]
async fn test_f30_me_endpoint_returns_authenticated_profile() {
    let app = TestApp::new().await;
    let (_, token) = app.seed_admin().await;

    let (status, body) = app.client.get_auth("/api/v1/auth/me", &token).await;
    assert_eq!(status, StatusCode::OK);

    let profile: UserProfile = serde_json::from_slice(&body).expect("Valid UserProfile");
    assert_eq!(profile.email, "admin@kds.local");
    assert_eq!(profile.role, UserRole::Admin);
    assert!(profile.is_active);
}

#[tokio::test]
async fn test_f30_refresh_token_exchange_success() {
    let app = TestApp::new().await;

    // Login to obtain refresh token
    let login_payload = json!({
        "email": "admin@kds.local",
        "password": "AdminSecret123!"
    });
    let (_, login_body) = app
        .client
        .post_json("/api/v1/auth/login", login_payload)
        .await;
    let login_resp: TokenResponse = serde_json::from_slice(&login_body).unwrap();

    // Exchange refresh token
    let refresh_payload = json!({
        "refresh_token": login_resp.refresh_token
    });
    let (ref_status, ref_body) = app
        .client
        .post_json("/api/v1/auth/refresh", refresh_payload)
        .await;
    assert_eq!(ref_status, StatusCode::OK);

    let ref_resp: TokenResponse = serde_json::from_slice(&ref_body).unwrap();
    assert!(!ref_resp.access_token.is_empty());
    assert_ne!(ref_resp.refresh_token, login_resp.refresh_token);

    // Verify new access token works
    let (me_status, _) = app
        .client
        .get_auth("/api/v1/auth/me", &ref_resp.access_token)
        .await;
    assert_eq!(me_status, StatusCode::OK);
}

#[tokio::test]
async fn test_f30_logout_revokes_session() {
    let app = TestApp::new().await;

    // Login
    let login_payload = json!({
        "email": "admin@kds.local",
        "password": "AdminSecret123!"
    });
    let (_, login_body) = app
        .client
        .post_json("/api/v1/auth/login", login_payload)
        .await;
    let login_resp: TokenResponse = serde_json::from_slice(&login_body).unwrap();

    // Logout
    let (logout_status, _) = app
        .client
        .post_json_auth(
            "/api/v1/auth/logout",
            json!({ "refresh_token": login_resp.refresh_token }),
            &login_resp.access_token,
        )
        .await;
    assert_eq!(logout_status, StatusCode::OK);

    // Attempting refresh with revoked refresh token must fail
    let (ref_status, ref_body) = app
        .client
        .post_json(
            "/api/v1/auth/refresh",
            json!({ "refresh_token": login_resp.refresh_token }),
        )
        .await;
    assert_err_code!(
        ref_status,
        &ref_body,
        StatusCode::UNAUTHORIZED,
        "INVALID_REFRESH_TOKEN"
    );
}

#[tokio::test]
async fn test_f30_login_updates_last_login_at() {
    let app = TestApp::new().await;
    let admin_record = app.user_repo.find_by_email("admin@kds.local").await.unwrap();
    assert!(admin_record.last_login_at.is_none());

    let payload = json!({
        "email": "admin@kds.local",
        "password": "AdminSecret123!"
    });
    let (status, _) = app.client.post_json("/api/v1/auth/login", payload).await;
    assert_eq!(status, StatusCode::OK);

    let updated = app.user_repo.find_by_email("admin@kds.local").await.unwrap();
    assert!(updated.last_login_at.is_some());
}

// =============================================================================
// F31: API Key REST Endpoints (6 tests)
// =============================================================================

#[tokio::test]
async fn test_f31_create_api_key_returns_secret_once() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let payload = json!({ "name": "Production Deploy Key" });
    let (status, body) = app
        .client
        .post_json_auth("/api/v1/auth/api-keys", payload, &admin_token)
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let resp: CreateApiKeyResponse = serde_json::from_slice(&body).expect("Valid CreateApiKeyResponse");
    assert_eq!(resp.name, "Production Deploy Key");
    assert!(resp.secret_key.starts_with("appsec_live_"));
    assert_eq!(resp.key_prefix, resp.secret_key[..12]);
}

#[tokio::test]
async fn test_f31_list_api_keys_omits_secret_key() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let payload = json!({ "name": "List Test Key" });
    app.client
        .post_json_auth("/api/v1/auth/api-keys", payload, &admin_token)
        .await;

    let (status, body) = app.client.get_auth("/api/v1/auth/api-keys", &admin_token).await;
    assert_eq!(status, StatusCode::OK);

    let keys: Vec<ApiKeyResponse> = serde_json::from_slice(&body).expect("Valid array of keys");
    assert!(!keys.is_empty());

    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let first_key = &val[0];
    assert!(first_key.get("secret_key").is_none(), "secret_key must NOT be present in listing");
}

#[tokio::test]
async fn test_f31_delete_api_key_revokes_access() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    // Create key
    let create_payload = json!({ "name": "Key to Revoke" });
    let (_, body) = app
        .client
        .post_json_auth("/api/v1/auth/api-keys", create_payload, &admin_token)
        .await;
    let created: CreateApiKeyResponse = serde_json::from_slice(&body).unwrap();

    // Verify key works initially
    let (s1, _) = app.client.get_api_key("/api/v1/apps", &created.secret_key).await;
    assert_eq!(s1, StatusCode::OK);

    // Delete key
    let (del_status, _) = app
        .client
        .delete_auth(&format!("/api/v1/auth/api-keys/{}", created.id), &admin_token)
        .await;
    assert_eq!(del_status, StatusCode::NO_CONTENT);

    // Verify key no longer authenticates
    let (s2, err_body) = app.client.get_api_key("/api/v1/apps", &created.secret_key).await;
    assert_err_code!(s2, &err_body, StatusCode::UNAUTHORIZED, "INVALID_API_KEY");
}

#[tokio::test]
async fn test_f31_create_multiple_api_keys() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    for i in 1..=3 {
        let payload = json!({ "name": format!("Multi Key {}", i) });
        let (s, _) = app
            .client
            .post_json_auth("/api/v1/auth/api-keys", payload, &admin_token)
            .await;
        assert_eq!(s, StatusCode::CREATED);
    }

    let (status, body) = app.client.get_auth("/api/v1/auth/api-keys", &admin_token).await;
    assert_eq!(status, StatusCode::OK);
    let keys: Vec<ApiKeyResponse> = serde_json::from_slice(&body).unwrap();
    assert_eq!(keys.len(), 3);
}

#[tokio::test]
async fn test_f31_newly_created_api_key_immediately_authenticates() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let payload = json!({ "name": "Immediate Auth Key" });
    let (_, body) = app
        .client
        .post_json_auth("/api/v1/auth/api-keys", payload, &admin_token)
        .await;
    let created: CreateApiKeyResponse = serde_json::from_slice(&body).unwrap();

    let (status, get_body) = app.client.get_api_key("/api/v1/apps", &created.secret_key).await;
    assert_eq!(status, StatusCode::OK);
    let apps: Vec<ApplicationResponse> = serde_json::from_slice(&get_body).unwrap();
    assert!(apps.is_empty());
}

#[tokio::test]
async fn test_f31_create_api_key_with_explicit_expiration() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let target_exp = Utc::now() + Duration::days(14);
    let payload = json!({
        "name": "Expiring Key",
        "expires_at": target_exp
    });

    let (status, body) = app
        .client
        .post_json_auth("/api/v1/auth/api-keys", payload, &admin_token)
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let created: CreateApiKeyResponse = serde_json::from_slice(&body).unwrap();
    assert!(created.expires_at.is_some());
}
