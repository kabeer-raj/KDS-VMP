use chrono::Utc;
use uuid::Uuid;

use infra::error::InfraError;
use infra::memory::{InMemoryAppRepo, InMemoryScanRepo, InMemoryUserRepo, InMemoryVulnRepo};
use infra::traits::{
    AppRepository, FindingIngestionInput, ScanRepository, UserRepository, VulnFilter,
    VulnRepository,
};
use shared_types::{
    AppCriticality, AppEnvironment, BulkUpdateVulnsRequest, ConfigureAuthRequest,
    CreateApiKeyRequest, CreateApplicationRequest, RemediationStatus, ScanDiffSummary,
    ScanStatus, ScanType, SeverityCounts, SeverityLevel, TriggerScanRequest,
    UpdateApplicationRequest, UpdateVulnerabilityRequest, UserRole,
};

#[tokio::test]
async fn test_in_memory_user_repository() {
    let repo = InMemoryUserRepo::new();
    let email = "sec_lead@example.com";
    let password_hash = "$argon2id$v=19$m=19456,t=2,p=1$test$test";

    // Create user
    let user = repo
        .create(email, "Security Lead", password_hash, UserRole::SecurityEngineer)
        .await
        .expect("user creation failed");
    assert_eq!(user.email, email);
    assert_eq!(user.role, UserRole::SecurityEngineer);

    // Duplicate create returns conflict
    let dup = repo
        .create(email, "Duplicate Lead", password_hash, UserRole::Developer)
        .await;
    assert!(matches!(dup, Err(InfraError::Conflict(_))));

    // Find by email & id
    let found_email = repo.find_by_email(email).await.expect("find by email failed");
    assert!(found_email.is_some());
    assert_eq!(found_email.unwrap().id, user.id);

    let found_id = repo.find_by_id(user.id).await.expect("find by id failed");
    assert!(found_id.is_some());

    // Verify password
    let verified = repo.verify_password(email, password_hash).await.unwrap();
    assert!(verified.is_some());

    let wrong_pass = repo.verify_password(email, "wrong_hash").await.unwrap();
    assert!(wrong_pass.is_none());

    // Update last login
    repo.update_last_login(user.id).await.expect("update last login failed");

    // API Key lifecycle
    let api_key_req = CreateApiKeyRequest {
        name: "CI/CD Token".to_string(),
        expires_at: Some(Utc::now() + chrono::Duration::days(30)),
    };
    let prefix = "kds_live";
    let key_hash = "sha256_mock_key_hash_value_1234567890";

    let api_key = repo
        .create_api_key(user.id, &api_key_req, prefix, key_hash)
        .await
        .expect("create api key failed");
    assert_eq!(api_key.name, "CI/CD Token");
    assert_eq!(api_key.key_prefix, prefix);

    // Lookup by hash
    let lookup = repo.api_key_lookup(key_hash).await.expect("lookup failed");
    assert!(lookup.is_some());
    let (key_user, key_id) = lookup.unwrap();
    assert_eq!(key_user.id, user.id);
    assert_eq!(key_id, api_key.id);

    // List keys
    let keys = repo.list_api_keys(user.id).await.expect("list keys failed");
    assert_eq!(keys.len(), 1);

    // Revoke key
    let revoked = repo.revoke_api_key(api_key.id, user.id).await.expect("revoke failed");
    assert!(revoked);

    let lookup_after = repo.api_key_lookup(key_hash).await.expect("lookup failed");
    assert!(lookup_after.is_none());
}

#[tokio::test]
async fn test_in_memory_app_repository() {
    let repo = InMemoryAppRepo::new();
    let owner_id = Uuid::new_v4();

    let create_req = CreateApplicationRequest {
        name: "Payments Portal".to_string(),
        description: Some("Customer payment gateway API".to_string()),
        base_url: "https://payments.example.com".to_string(),
        environment: AppEnvironment::Production,
        criticality: AppCriticality::Critical,
        team_name: Some("SecOps".to_string()),
        include_regexes: vec!["https://payments.example.com/api/.*".to_string()],
        exclude_regexes: vec!["https://payments.example.com/api/health".to_string()],
        cron_schedule: Some("0 0 * * *".to_string()),
        is_authorized: true,
    };

    let app = repo.create(&create_req, Some(owner_id)).await.expect("create app failed");
    assert_eq!(app.name, "Payments Portal");
    assert_eq!(app.owner_id, Some(owner_id));
    assert_eq!(app.environment, AppEnvironment::Production);
    assert_eq!(app.criticality, AppCriticality::Critical);

    // Get by ID
    let found = repo.get_by_id(app.id).await.expect("get app failed");
    assert!(found.is_some());
    assert_eq!(found.unwrap().id, app.id);

    // List apps
    let all_apps = repo.list(Some(owner_id), None).await.expect("list apps failed");
    assert_eq!(all_apps.len(), 1);

    let env_filtered = repo
        .list(None, Some(AppEnvironment::Staging))
        .await
        .expect("list apps failed");
    assert_eq!(env_filtered.len(), 0);

    // Update app
    let update_req = UpdateApplicationRequest {
        name: Some("Payments Portal V2".to_string()),
        description: None,
        environment: None,
        criticality: Some(AppCriticality::High),
        team_name: None,
        include_regexes: None,
        exclude_regexes: None,
        cron_schedule: None,
    };
    let updated = repo.update(app.id, &update_req).await.expect("update app failed");
    assert!(updated.is_some());
    assert_eq!(updated.unwrap().name, "Payments Portal V2");

    // Configure auth
    let auth_req = ConfigureAuthRequest {
        auth_type: "bearer_token".to_string(),
        auth_data: serde_json::json!({ "token": "secret_bearer_token" }),
    };
    repo.update_auth_config(app.id, &auth_req).await.expect("auth config failed");

    // Update latest risk
    repo.update_latest_risk(app.id, 7.8, Utc::now()).await.expect("risk update failed");
    let after_risk = repo.get_by_id(app.id).await.unwrap().unwrap();
    assert_eq!(after_risk.latest_risk_score, 7.8);
    assert!(after_risk.has_auth_configured);

    // Trends
    let trends = repo.get_trends(app.id).await.expect("trends failed");
    assert_eq!(trends.app_id, app.id);
    assert!(!trends.data_points.is_empty());

    // Delete
    let deleted = repo.delete(app.id).await.expect("delete failed");
    assert!(deleted);
    let after_delete = repo.get_by_id(app.id).await.expect("get app failed");
    assert!(after_delete.is_none());
}

#[tokio::test]
async fn test_in_memory_scan_repository() {
    let repo = InMemoryScanRepo::new();
    let app_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    let trigger_req = TriggerScanRequest {
        scan_type: ScanType::FullActive,
        max_duration_minutes: Some(60),
        custom_headers: None,
    };

    let scan = repo
        .create(app_id, Some(user_id), &trigger_req, None)
        .await
        .expect("create scan failed");
    assert_eq!(scan.application_id, app_id);
    assert_eq!(scan.status, ScanStatus::Queued);
    assert_eq!(scan.progress_percent, 0);

    // Update status & progress
    repo.update_status(scan.id, ScanStatus::Spidering, None).await.expect("status update failed");
    repo.update_progress(scan.id, 25).await.expect("progress update failed");

    let s1 = repo.get_by_id(scan.id).await.unwrap().unwrap();
    assert_eq!(s1.status, ScanStatus::Spidering);
    assert_eq!(s1.progress_percent, 25);

    // Update metrics
    let counts = SeverityCounts::new(1, 2, 3, 4, 5);
    let diff = ScanDiffSummary {
        previous_scan_id: None,
        new_count: 5,
        persistent_count: 8,
        fixed_count: 2,
        regressed_count: 0,
        risk_score_delta: -1.2,
    };
    repo.update_metrics(scan.id, &counts, &diff, 6.5, Some(120))
        .await
        .expect("metrics update failed");

    let s2 = repo.get_by_id(scan.id).await.unwrap().unwrap();
    assert_eq!(s2.severity_counts.total(), 15);
    assert_eq!(s2.severity_counts.critical, 1);
    assert_eq!(s2.diff_summary.new_count, 5);
    assert_eq!(s2.overall_risk_score, 6.5);
    assert_eq!(s2.duration_seconds, Some(120));

    // List by app
    let list = repo.list_by_app(app_id, 1, 10).await.expect("list failed");
    assert_eq!(list.total, 1);
    assert_eq!(list.items.len(), 1);

    // Cancel scan
    let cancelled = repo.cancel(scan.id).await.expect("cancel failed");
    assert!(cancelled);
    let s3 = repo.get_by_id(scan.id).await.unwrap().unwrap();
    assert_eq!(s3.status, ScanStatus::Cancelled);
}

#[tokio::test]
async fn test_in_memory_vuln_repository_deduplication_and_lifecycle() {
    let repo = InMemoryVulnRepo::new();
    let app_id = Uuid::new_v4();
    let scan_1_id = Uuid::new_v4();

    // Finding 1: SQL Injection
    let sqli = FindingIngestionInput {
        zap_plugin_id: "40018".to_string(),
        title: "SQL Injection".to_string(),
        cwe_id: Some(89),
        wasc_id: Some(19),
        confidence: "High".to_string(),
        http_method: "POST".to_string(),
        affected_url: "https://example.com/api/login".to_string(),
        affected_param: Some("username".to_string()),
        attack_payload: Some("' OR '1'='1".to_string()),
        evidence_snippet: Some("syntax error near SELECT".to_string()),
        description: "SQL Injection flaw".to_string(),
        solution: "Use prepared statements".to_string(),
        reference_urls: vec!["https://owasp.org/sqli".to_string()],
        raw_request_header: Some("POST /api/login HTTP/1.1".to_string()),
        raw_response_header: Some("HTTP/1.1 500 Internal Server Error".to_string()),
        cvss_score: Some(8.8),
        severity: Some(SeverityLevel::High),
    };

    // Finding 2: Cross-Site Scripting (XSS)
    let xss = FindingIngestionInput {
        zap_plugin_id: "40012".to_string(),
        title: "Reflected XSS".to_string(),
        cwe_id: Some(79),
        wasc_id: Some(8),
        confidence: "Medium".to_string(),
        http_method: "GET".to_string(),
        affected_url: "https://example.com/search?q=test".to_string(),
        affected_param: Some("q".to_string()),
        attack_payload: Some("<script>alert(1)</script>".to_string()),
        evidence_snippet: Some("<script>alert(1)</script>".to_string()),
        description: "Cross-site scripting flaw".to_string(),
        solution: "HTML entity encode output".to_string(),
        reference_urls: vec![],
        raw_request_header: None,
        raw_response_header: None,
        cvss_score: Some(6.1),
        severity: Some(SeverityLevel::Medium),
    };

    // --- SCAN 1: Initial Ingestion ---
    let diff_1 = repo
        .upsert_findings(scan_1_id, app_id, &[sqli.clone(), xss.clone()], None)
        .await
        .expect("upsert scan 1 failed");

    assert_eq!(diff_1.summary.new_count, 2);
    assert_eq!(diff_1.summary.persistent_count, 0);
    assert_eq!(diff_1.summary.fixed_count, 0);
    assert_eq!(diff_1.summary.regressed_count, 0);

    // Check vulnerabilities listed
    let list = repo
        .list_with_filters(&VulnFilter { app_id: Some(app_id), ..Default::default() }, 1, 10)
        .await
        .expect("list vulns failed");
    assert_eq!(list.total, 2);

    let sqli_vuln = list.items.iter().find(|v| v.title == "SQL Injection").expect("SQLi missing");
    assert_eq!(sqli_vuln.status, RemediationStatus::Open);
    assert_eq!(sqli_vuln.seen_count, 1);
    assert_eq!(sqli_vuln.severity, SeverityLevel::High);

    // Verify detailed finding & history
    let sqli_detail = repo.get_by_id(sqli_vuln.id).await.unwrap().unwrap();
    assert_eq!(sqli_detail.summary.id, sqli_vuln.id);
    let initial_history = repo.get_history(sqli_vuln.id).await.unwrap();
    assert_eq!(initial_history.len(), 1); // 1 initial audit log

    // --- DEVELOPER TRIAGE: Mark SQLi as Resolved ---
    let user_id = Uuid::new_v4();
    let triage_req = UpdateVulnerabilityRequest {
        status: Some(RemediationStatus::Resolved),
        severity: None,
        assigned_to: Some(user_id),
        due_date: None,
        comment: Some("Patched with parameterized query".to_string()),
    };
    let triaged = repo
        .update_triage(sqli_vuln.id, &triage_req, Some(user_id))
        .await
        .expect("triage update failed");
    assert!(triaged.is_some());
    assert_eq!(triaged.unwrap().summary.status, RemediationStatus::Resolved);

    // --- SCAN 2: SQLi Reappears (Regression!) and XSS is Absent (Auto-Verified Fixed!) ---
    let scan_2_id = Uuid::new_v4();
    let diff_2 = repo
        .upsert_findings(scan_2_id, app_id, &[sqli.clone()], Some(scan_1_id))
        .await
        .expect("upsert scan 2 failed");

    // Diff summary: SQLi regressed, XSS fixed
    assert_eq!(diff_2.summary.regressed_count, 1, "SQLi should be flagged as regressed");
    assert_eq!(diff_2.summary.fixed_count, 1, "XSS should be auto-verified fixed");
    assert_eq!(diff_2.summary.new_count, 0);

    // Check SQLi vulnerability transitioned to Regressed
    let sqli_after = repo.get_by_id(sqli_vuln.id).await.unwrap().unwrap();
    assert_eq!(sqli_after.summary.status, RemediationStatus::Regressed);
    assert_eq!(sqli_after.summary.seen_count, 2); // Incremented seen count

    // Check XSS vulnerability transitioned to VerifiedFixed
    let xss_vuln = list.items.iter().find(|v| v.title == "Reflected XSS").unwrap();
    let xss_after = repo.get_by_id(xss_vuln.id).await.unwrap().unwrap();
    assert_eq!(xss_after.summary.status, RemediationStatus::VerifiedFixed);
    assert!(xss_after.resolved_at.is_some());

    // Check history / audit logs for SQLi
    let history = repo.get_history(sqli_vuln.id).await.expect("history failed");
    assert!(history.iter().any(|h| h.new_status == Some(RemediationStatus::Regressed)));

    // Bulk update
    let bulk_req = BulkUpdateVulnsRequest {
        vuln_ids: vec![sqli_vuln.id, xss_vuln.id],
        status: Some(RemediationStatus::InProgress),
        severity: None,
        assigned_to: Some(user_id),
        comment: None,
    };
    let count = repo.bulk_update(&bulk_req, Some(user_id)).await.expect("bulk update failed");
    assert_eq!(count, 2);

    let sqli_bulk = repo.get_by_id(sqli_vuln.id).await.unwrap().unwrap();
    assert_eq!(sqli_bulk.summary.status, RemediationStatus::InProgress);

    // Add comment
    let comment_log = repo
        .add_comment(sqli_vuln.id, "Second review required", Some(user_id))
        .await
        .expect("add comment failed");
    assert_eq!(comment_log.comment, Some("Second review required".to_string()));
}
