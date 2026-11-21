use std::collections::HashMap;
use chrono::Utc;
use shared_types::*;
use uuid::Uuid;

#[test]
fn test_all_enums_integration() {
    // 1. UserRole
    assert_eq!(serde_json::to_string(&UserRole::Admin).unwrap(), "\"admin\"");
    assert_eq!(serde_json::to_string(&UserRole::SecurityEngineer).unwrap(), "\"security_engineer\"");
    assert_eq!(serde_json::to_string(&UserRole::Developer).unwrap(), "\"developer\"");
    assert_eq!(serde_json::to_string(&UserRole::Auditor).unwrap(), "\"auditor\"");
    assert_eq!(UserRole::Admin.to_string(), "admin");
    assert_eq!("security_engineer".parse::<UserRole>().unwrap(), UserRole::SecurityEngineer);
    assert!("invalid_role".parse::<UserRole>().is_err());

    // 2. AppEnvironment
    assert_eq!(serde_json::to_string(&AppEnvironment::Production).unwrap(), "\"production\"");
    assert_eq!(serde_json::to_string(&AppEnvironment::Staging).unwrap(), "\"staging\"");
    assert_eq!(serde_json::to_string(&AppEnvironment::Development).unwrap(), "\"development\"");
    assert_eq!(serde_json::to_string(&AppEnvironment::Qa).unwrap(), "\"qa\"");
    assert_eq!(AppEnvironment::Production.to_string(), "production");
    assert_eq!("staging".parse::<AppEnvironment>().unwrap(), AppEnvironment::Staging);
    assert!("sandbox".parse::<AppEnvironment>().is_err());

    // 3. AppCriticality
    assert_eq!(serde_json::to_string(&AppCriticality::Critical).unwrap(), "\"critical\"");
    assert_eq!(serde_json::to_string(&AppCriticality::High).unwrap(), "\"high\"");
    assert_eq!(serde_json::to_string(&AppCriticality::Medium).unwrap(), "\"medium\"");
    assert_eq!(serde_json::to_string(&AppCriticality::Low).unwrap(), "\"low\"");
    assert_eq!(AppCriticality::High.to_string(), "high");
    assert_eq!("medium".parse::<AppCriticality>().unwrap(), AppCriticality::Medium);
    assert!("none".parse::<AppCriticality>().is_err());

    // 4. ScanType
    assert_eq!(serde_json::to_string(&ScanType::BaselinePassive).unwrap(), "\"baseline_passive\"");
    assert_eq!(serde_json::to_string(&ScanType::FullActive).unwrap(), "\"full_active\"");
    assert_eq!(serde_json::to_string(&ScanType::ApiOpenapi).unwrap(), "\"api_openapi\"");
    assert_eq!(serde_json::to_string(&ScanType::SpaAjax).unwrap(), "\"spa_ajax\"");
    assert_eq!(ScanType::BaselinePassive.to_string(), "baseline_passive");
    assert_eq!("full_active".parse::<ScanType>().unwrap(), ScanType::FullActive);
    assert!("quick".parse::<ScanType>().is_err());

    // 5. ScanStatus
    assert_eq!(serde_json::to_string(&ScanStatus::Queued).unwrap(), "\"queued\"");
    assert_eq!(serde_json::to_string(&ScanStatus::Spidering).unwrap(), "\"spidering\"");
    assert_eq!(serde_json::to_string(&ScanStatus::ActiveScanning).unwrap(), "\"active_scanning\"");
    assert_eq!(serde_json::to_string(&ScanStatus::Ingesting).unwrap(), "\"ingesting\"");
    assert_eq!(serde_json::to_string(&ScanStatus::Completed).unwrap(), "\"completed\"");
    assert_eq!(serde_json::to_string(&ScanStatus::Failed).unwrap(), "\"failed\"");
    assert_eq!(serde_json::to_string(&ScanStatus::Cancelled).unwrap(), "\"cancelled\"");
    assert_eq!(ScanStatus::Spidering.to_string(), "spidering");
    assert_eq!("active_scanning".parse::<ScanStatus>().unwrap(), ScanStatus::ActiveScanning);
    assert!("running".parse::<ScanStatus>().is_err());

    // 6. SeverityLevel (with Ordering)
    assert_eq!(serde_json::to_string(&SeverityLevel::Info).unwrap(), "\"info\"");
    assert_eq!(serde_json::to_string(&SeverityLevel::Low).unwrap(), "\"low\"");
    assert_eq!(serde_json::to_string(&SeverityLevel::Medium).unwrap(), "\"medium\"");
    assert_eq!(serde_json::to_string(&SeverityLevel::High).unwrap(), "\"high\"");
    assert_eq!(serde_json::to_string(&SeverityLevel::Critical).unwrap(), "\"critical\"");
    assert!(SeverityLevel::Info < SeverityLevel::Low);
    assert!(SeverityLevel::Low < SeverityLevel::Medium);
    assert!(SeverityLevel::Medium < SeverityLevel::High);
    assert!(SeverityLevel::High < SeverityLevel::Critical);

    // 7. RemediationStatus
    assert_eq!(serde_json::to_string(&RemediationStatus::Open).unwrap(), "\"open\"");
    assert_eq!(serde_json::to_string(&RemediationStatus::InProgress).unwrap(), "\"in_progress\"");
    assert_eq!(serde_json::to_string(&RemediationStatus::FalsePositive).unwrap(), "\"false_positive\"");
    assert_eq!(serde_json::to_string(&RemediationStatus::RiskAccepted).unwrap(), "\"risk_accepted\"");
    assert_eq!(serde_json::to_string(&RemediationStatus::Resolved).unwrap(), "\"resolved\"");
    assert_eq!(serde_json::to_string(&RemediationStatus::VerifiedFixed).unwrap(), "\"verified_fixed\"");
    assert_eq!(serde_json::to_string(&RemediationStatus::Regressed).unwrap(), "\"regressed\"");
    assert_eq!("verified_fixed".parse::<RemediationStatus>().unwrap(), RemediationStatus::VerifiedFixed);
    assert!("closed".parse::<RemediationStatus>().is_err());

    // 8. DiffClassification (confirming 'fixed' is rejected)
    assert_eq!(serde_json::to_string(&DiffClassification::New).unwrap(), "\"new\"");
    assert_eq!(serde_json::to_string(&DiffClassification::Persistent).unwrap(), "\"persistent\"");
    assert_eq!(serde_json::to_string(&DiffClassification::Regressed).unwrap(), "\"regressed\"");
    assert_eq!("persistent".parse::<DiffClassification>().unwrap(), DiffClassification::Persistent);
    assert!("fixed".parse::<DiffClassification>().is_err());
}

#[test]
fn test_app_dtos_integration() {
    let req_json = r#"{
        "name": "E-Commerce Frontend",
        "description": "Customer facing web store",
        "base_url": "https://store.example.com",
        "environment": "production",
        "criticality": "high",
        "team_name": "Storefront Team",
        "cron_schedule": "0 0 * * *",
        "is_authorized": true
    }"#;

    let req: CreateApplicationRequest = serde_json::from_str(req_json).unwrap();
    assert_eq!(req.name, "E-Commerce Frontend");
    assert_eq!(req.environment, AppEnvironment::Production);
    assert_eq!(req.criticality, AppCriticality::High);
    assert!(req.include_regexes.is_empty());
    assert!(req.exclude_regexes.is_empty());
    assert!(req.is_authorized);

    let app_id = Uuid::new_v4();
    let now = Utc::now();
    let resp = ApplicationResponse {
        id: app_id,
        name: req.name.clone(),
        description: req.description.clone(),
        base_url: req.base_url.clone(),
        environment: req.environment,
        criticality: req.criticality,
        owner_id: None,
        team_name: req.team_name.clone(),
        include_regexes: vec![],
        exclude_regexes: vec![],
        has_auth_configured: false,
        cron_schedule: req.cron_schedule.clone(),
        is_authorized: true,
        latest_risk_score: 25.5,
        last_scanned_at: Some(now),
        open_counts: SeverityCounts::new(1, 2, 3, 4, 5),
        created_at: now,
    };

    let resp_json = serde_json::to_string(&resp).unwrap();
    let parsed_resp: ApplicationResponse = serde_json::from_str(&resp_json).unwrap();
    assert_eq!(parsed_resp.id, app_id);
    assert_eq!(parsed_resp.open_counts.total(), 15);

    let trends = AppTrendsResponse {
        app_id,
        data_points: vec![AppTrendPoint {
            timestamp: now,
            scan_id: Some(Uuid::new_v4()),
            risk_score: 25.5,
            severity_counts: SeverityCounts::new(1, 2, 3, 4, 5),
        }],
    };
    let trends_json = serde_json::to_string(&trends).unwrap();
    let parsed_trends: AppTrendsResponse = serde_json::from_str(&trends_json).unwrap();
    assert_eq!(parsed_trends.data_points.len(), 1);
}

#[test]
fn test_scan_dtos_integration() {
    let mut headers = HashMap::new();
    headers.insert("X-Scan-Token".to_string(), "token_abc".to_string());
    let req = TriggerScanRequest {
        scan_type: ScanType::FullActive,
        max_duration_minutes: Some(120),
        custom_headers: Some(headers),
    };

    let req_json = serde_json::to_string(&req).unwrap();
    let parsed_req: TriggerScanRequest = serde_json::from_str(&req_json).unwrap();
    assert_eq!(parsed_req.scan_type, ScanType::FullActive);
    assert_eq!(parsed_req.max_duration_minutes, Some(120));

    let counts = SeverityCounts::default();
    assert_eq!(counts.total(), 0);

    let diff = ScanDiffSummary {
        previous_scan_id: Some(Uuid::new_v4()),
        new_count: 5,
        persistent_count: 12,
        fixed_count: 3,
        regressed_count: 1,
        risk_score_delta: -2.4,
    };

    let scan_resp = ScanResponse {
        id: Uuid::new_v4(),
        application_id: Uuid::new_v4(),
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::new(2, 4, 6, 8, 1),
        diff_summary: diff.clone(),
        overall_risk_score: 55.0,
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        duration_seconds: Some(450),
        error_message: None,
    };

    let scan_json = serde_json::to_string(&scan_resp).unwrap();
    let parsed_scan: ScanResponse = serde_json::from_str(&scan_json).unwrap();
    assert_eq!(parsed_scan.status, ScanStatus::Completed);
    assert_eq!(parsed_scan.diff_summary.new_count, 5);
}

#[test]
fn test_vuln_dtos_integration() {
    let vuln_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let now = Utc::now();

    let summary = VulnerabilitySummary {
        id: vuln_id,
        application_id: app_id,
        fingerprint: "hash_abcdef_123456".to_string(),
        title: "Remote Code Execution".to_string(),
        owasp_category: "A03:2021-Injection".to_string(),
        cwe_id: Some(78),
        severity: SeverityLevel::Critical,
        cvss_score: 9.8,
        status: RemediationStatus::Open,
        http_method: "POST".to_string(),
        normalized_path: "/api/exec".to_string(),
        affected_param: Some("cmd".to_string()),
        assigned_to: None,
        seen_count: 1,
        last_seen_at: now,
    };

    let evidence = HttpEvidence {
        scan_id: Uuid::new_v4(),
        diff_state: DiffClassification::New,
        attack_payload: Some("; cat /etc/passwd".to_string()),
        evidence_snippet: Some("root:x:0:0:root:/root:/bin/bash".to_string()),
        raw_request_header: Some("POST /api/exec HTTP/1.1".to_string()),
        raw_response_header: Some("HTTP/1.1 200 OK".to_string()),
    };

    let detail = VulnerabilityDetail {
        summary: summary.clone(),
        zap_plugin_id: "90020".to_string(),
        wasc_id: Some(31),
        cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
        confidence: "High".to_string(),
        affected_url: "https://store.example.com/api/exec".to_string(),
        description: "Command injection vulnerability allows arbitrary command execution".to_string(),
        solution: "Sanitize and validate inputs, avoid shell invocations".to_string(),
        reference_urls: vec!["https://owasp.org/www-community/attacks/Command_Injection".to_string()],
        due_date: Some(now),
        latest_evidence: Some(evidence),
        first_seen_at: now,
        resolved_at: None,
    };

    let detail_json = serde_json::to_string(&detail).unwrap();
    let v: serde_json::Value = serde_json::from_str(&detail_json).unwrap();
    // Verify flattening
    assert_eq!(v["fingerprint"], "hash_abcdef_123456");
    assert_eq!(v["zap_plugin_id"], "90020");
    assert_eq!(v["severity"], "critical");

    let parsed_detail: VulnerabilityDetail = serde_json::from_str(&detail_json).unwrap();
    assert_eq!(parsed_detail.summary.title, "Remote Code Execution");
    assert_eq!(parsed_detail.reference_urls.len(), 1);

    // Bulk update
    let bulk = BulkUpdateVulnsRequest {
        vuln_ids: vec![vuln_id],
        status: Some(RemediationStatus::InProgress),
        severity: None,
        assigned_to: None,
        comment: Some("Investigating fix".to_string()),
    };
    let bulk_json = serde_json::to_string(&bulk).unwrap();
    let parsed_bulk: BulkUpdateVulnsRequest = serde_json::from_str(&bulk_json).unwrap();
    assert_eq!(parsed_bulk.status, Some(RemediationStatus::InProgress));

    let bulk_resp = BulkUpdateResponse { updated_count: 1 };
    assert_eq!(bulk_resp.updated_count, 1);

    // Comment & Audit Log
    let comment_req = AddCommentRequest {
        comment: "Fix deployed to staging, awaiting next scan".to_string(),
    };
    let comment_json = serde_json::to_string(&comment_req).unwrap();
    let parsed_comment: AddCommentRequest = serde_json::from_str(&comment_json).unwrap();
    assert_eq!(parsed_comment.comment, comment_req.comment);

    let audit = RemediationAuditLogResponse {
        id: Uuid::new_v4(),
        vulnerability_id: vuln_id,
        actor_id: Some(Uuid::new_v4()),
        scan_id: None,
        action_type: "TRIAGE_COMMENT".to_string(),
        old_status: None,
        new_status: None,
        comment: Some("Fix deployed".to_string()),
        created_at: now,
    };
    let audit_json = serde_json::to_string(&audit).unwrap();
    let parsed_audit: RemediationAuditLogResponse = serde_json::from_str(&audit_json).unwrap();
    assert_eq!(parsed_audit.id, audit.id);
}

#[test]
fn test_auth_dtos_integration() {
    let login = LoginRequest {
        email: "seceng@company.com".to_string(),
        password: "SuperSecretPassword123!".to_string(),
    };
    let login_json = serde_json::to_string(&login).unwrap();
    let parsed_login: LoginRequest = serde_json::from_str(&login_json).unwrap();
    assert_eq!(parsed_login.email, login.email);

    let user_id = Uuid::new_v4();
    let now = Utc::now();
    let profile = UserProfile {
        id: user_id,
        email: login.email.clone(),
        full_name: "Security Lead".to_string(),
        role: UserRole::SecurityEngineer,
        is_active: true,
        last_login_at: Some(now),
        created_at: now,
    };

    let token_resp = TokenResponse {
        access_token: "header.payload.signature".to_string(),
        refresh_token: "refresh.payload.signature".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 900,
        user: profile.clone(),
    };
    let token_json = serde_json::to_string(&token_resp).unwrap();
    let parsed_token: TokenResponse = serde_json::from_str(&token_json).unwrap();
    assert_eq!(parsed_token.user.role, UserRole::SecurityEngineer);

    let refresh = RefreshTokenRequest {
        refresh_token: "refresh.payload.signature".to_string(),
    };
    let refresh_json = serde_json::to_string(&refresh).unwrap();
    let parsed_refresh: RefreshTokenRequest = serde_json::from_str(&refresh_json).unwrap();
    assert_eq!(parsed_refresh.refresh_token, refresh.refresh_token);

    let create_key_req = CreateApiKeyRequest {
        name: "GitLab CI Runner".to_string(),
        expires_at: None,
    };
    let create_key_resp = CreateApiKeyResponse {
        id: Uuid::new_v4(),
        name: create_key_req.name.clone(),
        key_prefix: "kds_ci_9f8e".to_string(),
        secret_key: "kds_ci_9f8e_secret_secret".to_string(),
        expires_at: None,
        created_at: now,
    };
    let key_resp_json = serde_json::to_string(&create_key_resp).unwrap();
    let parsed_key_resp: CreateApiKeyResponse = serde_json::from_str(&key_resp_json).unwrap();
    assert_eq!(parsed_key_resp.secret_key, create_key_resp.secret_key);

    let list_key_resp = ApiKeyResponse {
        id: create_key_resp.id,
        name: create_key_resp.name.clone(),
        key_prefix: create_key_resp.key_prefix.clone(),
        expires_at: None,
        last_used_at: None,
        created_at: now,
    };
    let list_json = serde_json::to_string(&list_key_resp).unwrap();
    let v: serde_json::Value = serde_json::from_str(&list_json).unwrap();
    assert!(v.get("secret_key").is_none());
}

#[test]
fn test_cvss_v31_vector_and_metrics_integration() {
    let vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    let vector = CvssVector::new(vector_str);
    let metrics = vector.parse_metrics().unwrap();

    assert_eq!(metrics.attack_vector, AttackVector::Network);
    assert_eq!(metrics.attack_complexity, AttackComplexity::Low);
    assert_eq!(metrics.privileges_required, PrivilegesRequired::None);
    assert_eq!(metrics.user_interaction, UserInteraction::None);
    assert_eq!(metrics.scope, Scope::Unchanged);
    assert_eq!(metrics.confidentiality, CiaImpact::High);
    assert_eq!(metrics.integrity, CiaImpact::High);
    assert_eq!(metrics.availability, CiaImpact::High);

    assert_eq!(metrics.to_vector_string(), vector_str);
    assert_eq!(vector.to_string(), vector_str);

    // Test error cases
    assert!(matches!(
        CvssVector::new("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").parse_metrics(),
        Err(CvssParseError::InvalidPrefix(_))
    ));
    assert!(matches!(
        CvssVector::new("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").parse_metrics(),
        Err(CvssParseError::InvalidPrefix(_))
    ));
    assert!(matches!(
        CvssVector::new("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H").parse_metrics(),
        Err(CvssParseError::MissingMetric("Scope (S)"))
    ));
    assert!(matches!(
        CvssVector::new("CVSS:3.1/AV:INVALID/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").parse_metrics(),
        Err(CvssParseError::InvalidMetricValue { .. })
    ));
}

#[test]
fn test_websocket_server_events_integration() {
    let scan_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();

    // 1. ScanProgress
    let progress_event = WsServerEvent::ScanProgress(ScanProgressEvent {
        scan_id,
        application_id: app_id,
        status: ScanStatus::Spidering,
        progress_percent: 25,
        current_phase: "Spidering endpoints".to_string(),
        alerts_found_so_far: 3,
    });
    let progress_json = serde_json::to_string(&progress_event).unwrap();
    let v_prog: serde_json::Value = serde_json::from_str(&progress_json).unwrap();
    assert_eq!(v_prog["event"], "scan_progress");
    assert_eq!(v_prog["data"]["status"], "spidering");
    assert_eq!(v_prog["data"]["progress_percent"], 25);
    let parsed_prog: WsServerEvent = serde_json::from_str(&progress_json).unwrap();
    assert_eq!(parsed_prog, progress_event);

    // 2. ScanCompleted
    let completed_event = WsServerEvent::ScanCompleted(ScanCompletedEvent {
        scan_id,
        application_id: app_id,
        severity_counts: SeverityCounts::new(0, 1, 2, 3, 0),
        overall_risk_score: 15.5,
    });
    let completed_json = serde_json::to_string(&completed_event).unwrap();
    let v_comp: serde_json::Value = serde_json::from_str(&completed_json).unwrap();
    assert_eq!(v_comp["event"], "scan_completed");
    assert_eq!(v_comp["data"]["overall_risk_score"], 15.5);
    let parsed_comp: WsServerEvent = serde_json::from_str(&completed_json).unwrap();
    assert_eq!(parsed_comp, completed_event);

    // 3. ScanFailed
    let failed_event = WsServerEvent::ScanFailed(ScanFailedEvent {
        scan_id,
        application_id: app_id,
        reason: "Connection reset by peer".to_string(),
    });
    let failed_json = serde_json::to_string(&failed_event).unwrap();
    let v_fail: serde_json::Value = serde_json::from_str(&failed_json).unwrap();
    assert_eq!(v_fail["event"], "scan_failed");
    assert_eq!(v_fail["data"]["reason"], "Connection reset by peer");
    let parsed_fail: WsServerEvent = serde_json::from_str(&failed_json).unwrap();
    assert_eq!(parsed_fail, failed_event);
}

#[test]
fn test_platform_common_types_integration() {
    let err = ErrorEnvelope::new("TARGET_UNREACHABLE", "Cannot resolve host", "req_9988");
    let err_json = serde_json::to_string(&err).unwrap();
    let parsed_err: ErrorEnvelope = serde_json::from_str(&err_json).unwrap();
    assert_eq!(parsed_err.error.code, "TARGET_UNREACHABLE");

    let page = PaginatedResponse::new(vec![1, 2, 3], 15, 2, 5);
    assert_eq!(page.total_pages, 3);
    assert_eq!(page.items.len(), 3);
    let page_json = serde_json::to_string(&page).unwrap();
    let parsed_page: PaginatedResponse<i32> = serde_json::from_str(&page_json).unwrap();
    assert_eq!(parsed_page.items, vec![1, 2, 3]);
}
