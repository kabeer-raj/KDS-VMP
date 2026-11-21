use std::sync::Arc;
use infra::memory::{InMemoryAppRepo, InMemoryScanRepo, InMemoryVulnRepo};
use infra::traits::{AppRepository, ScanRepository, VulnRepository, ZapAlert};
use scan_worker::pipeline::FindingPipeline;
use shared_types::app::CreateApplicationRequest;
use shared_types::enums::{AppCriticality, AppEnvironment, RemediationStatus};
use shared_types::scan::TriggerScanRequest;

#[tokio::test]
async fn test_pipeline_ingestion_deduplication_and_diffing_across_3_scans() {
    let app_repo: Arc<dyn AppRepository> = Arc::new(InMemoryAppRepo::new());
    let scan_repo: Arc<dyn ScanRepository> = Arc::new(InMemoryScanRepo::new());
    let vuln_repo: Arc<dyn VulnRepository> = Arc::new(InMemoryVulnRepo::new());

    let app = app_repo
        .create(
            &CreateApplicationRequest {
                name: "Pipeline App".to_string(),
                description: None,
                base_url: "https://app.local".to_string(),
                environment: AppEnvironment::Production,
                criticality: AppCriticality::Critical,
                team_name: None,
                include_regexes: vec![],
                exclude_regexes: vec![],
                cron_schedule: None,
                is_authorized: true,
            },
            None,
        )
        .await
        .unwrap();

    // Scan 1: Two vulnerabilities discovered (SQLi and XSS)
    let scan1 = scan_repo
        .create(app.id, None, &TriggerScanRequest { scan_type: shared_types::enums::ScanType::FullActive, max_duration_minutes: None, custom_headers: None }, None)
        .await
        .unwrap();

    let alert_sqli = ZapAlert {
        id: "1".to_string(),
        plugin_id: "40018".to_string(),
        alert: "SQL Injection".to_string(),
        name: Some("SQL Injection in Users".to_string()),
        risk: "High".to_string(),
        confidence: "High".to_string(),
        url: "https://app.local/api/users".to_string(),
        param: Some("id".to_string()),
        attack: Some("' OR 1=1".to_string()),
        evidence: Some("syntax error".to_string()),
        description: "SQLi".to_string(),
        solution: "Use prepared statements".to_string(),
        reference: None,
        cweid: Some("89".to_string()),
        wascid: Some("19".to_string()),
        method: Some("GET".to_string()),
        request_header: None,
        response_header: None,
    };

    let alert_xss = ZapAlert {
        id: "2".to_string(),
        plugin_id: "40012".to_string(),
        alert: "Reflected XSS".to_string(),
        name: Some("XSS in Search".to_string()),
        risk: "Medium".to_string(),
        confidence: "Medium".to_string(),
        url: "https://app.local/search".to_string(),
        param: Some("q".to_string()),
        attack: Some("<script>alert(1)</script>".to_string()),
        evidence: None,
        description: "XSS".to_string(),
        solution: "HTML encode output".to_string(),
        reference: None,
        cweid: Some("79".to_string()),
        wascid: Some("8".to_string()),
        method: Some("GET".to_string()),
        request_header: None,
        response_header: None,
    };

    let res1 = FindingPipeline::process(
        scan1.id,
        &app,
        &[alert_sqli.clone(), alert_xss.clone()],
        None,
        Some(60),
        &vuln_repo,
        &scan_repo,
        &app_repo,
    )
    .await
    .unwrap();

    assert_eq!(res1.diff_summary.new_count, 2);
    assert_eq!(res1.severity_counts.high, 1);
    assert_eq!(res1.severity_counts.medium, 1);
    assert!(res1.overall_risk_score > 0.0);

    // Verify application latest risk was updated
    let updated_app = app_repo.get_by_id(app.id).await.unwrap().unwrap();
    assert_eq!(updated_app.latest_risk_score, res1.overall_risk_score);

    // Triage SQLi: developer marks SQLi as Resolved
    let vulns = vuln_repo.list_with_filters(&infra::traits::VulnFilter { app_id: Some(app.id), ..Default::default() }, 1, 10).await.unwrap();
    let sqli_vuln = vulns.items.iter().find(|v| v.cwe_id == Some(89)).unwrap();
    vuln_repo.update_triage(sqli_vuln.id, &shared_types::vuln::UpdateVulnerabilityRequest {
        status: Some(RemediationStatus::Resolved),
        comment: Some("Patched in main".to_string()),
        ..Default::default()
    }, None).await.unwrap();

    // Scan 2: SQLi is re-detected despite being marked Resolved -> Regression!
    let scan2 = scan_repo
        .create(app.id, None, &TriggerScanRequest { scan_type: shared_types::enums::ScanType::FullActive, max_duration_minutes: None, custom_headers: None }, Some(scan1.id))
        .await
        .unwrap();

    let res2 = FindingPipeline::process(
        scan2.id,
        &app,
        &[alert_sqli.clone(), alert_xss.clone()],
        Some(scan1.id),
        Some(50),
        &vuln_repo,
        &scan_repo,
        &app_repo,
    )
    .await
    .unwrap();

    assert_eq!(res2.diff_summary.regressed_count, 1);  // SQLi regressed
    assert_eq!(res2.diff_summary.persistent_count, 1); // XSS is persistent
    assert_eq!(res2.diff_summary.new_count, 0);

    // Verify SQLi is now Regressed in vuln_repo
    let sqli_detail = vuln_repo.get_by_id(sqli_vuln.id).await.unwrap().unwrap();
    assert_eq!(sqli_detail.summary.status, RemediationStatus::Regressed);

    // Scan 3: SQLi is finally fixed (absent), XSS is still present
    let scan3 = scan_repo
        .create(app.id, None, &TriggerScanRequest { scan_type: shared_types::enums::ScanType::FullActive, max_duration_minutes: None, custom_headers: None }, Some(scan2.id))
        .await
        .unwrap();

    let res3 = FindingPipeline::process(
        scan3.id,
        &app,
        &[alert_xss.clone()],
        Some(scan2.id),
        Some(55),
        &vuln_repo,
        &scan_repo,
        &app_repo,
    )
    .await
    .unwrap();

    assert_eq!(res3.diff_summary.fixed_count, 1);      // SQLi is auto-verified fixed
    assert_eq!(res3.diff_summary.persistent_count, 1); // XSS persistent
    assert_eq!(res3.diff_summary.new_count, 0);

    let sqli_fixed = vuln_repo.get_by_id(sqli_vuln.id).await.unwrap().unwrap();
    assert_eq!(sqli_fixed.summary.status, RemediationStatus::VerifiedFixed);
}

#[tokio::test]
async fn test_pipeline_deduplication_of_duplicate_alerts() {
    let app_repo: Arc<dyn AppRepository> = Arc::new(InMemoryAppRepo::new());
    let scan_repo: Arc<dyn ScanRepository> = Arc::new(InMemoryScanRepo::new());
    let vuln_repo: Arc<dyn VulnRepository> = Arc::new(InMemoryVulnRepo::new());

    let app = app_repo
        .create(
            &CreateApplicationRequest {
                name: "Dedup App".to_string(),
                description: None,
                base_url: "https://dedup.local".to_string(),
                environment: AppEnvironment::Staging,
                criticality: AppCriticality::Medium,
                team_name: None,
                include_regexes: vec![],
                exclude_regexes: vec![],
                cron_schedule: None,
                is_authorized: true,
            },
            None,
        )
        .await
        .unwrap();

    let scan = scan_repo
        .create(app.id, None, &TriggerScanRequest { scan_type: shared_types::enums::ScanType::FullActive, max_duration_minutes: None, custom_headers: None }, None)
        .await
        .unwrap();

    // Two identical alerts with URL differences that both normalize to /users
    let alert1 = ZapAlert {
        id: "1".to_string(),
        plugin_id: "40018".to_string(),
        alert: "SQL Injection".to_string(),
        name: Some("SQLi".to_string()),
        risk: "High".to_string(),
        confidence: "High".to_string(),
        url: "https://dedup.local/users?page=1".to_string(),
        param: Some("id".to_string()),
        attack: Some("'".to_string()),
        evidence: None,
        description: "".to_string(),
        solution: "".to_string(),
        reference: None,
        cweid: Some("89".to_string()),
        wascid: None,
        method: Some("GET".to_string()),
        request_header: None,
        response_header: None,
    };

    let alert2 = ZapAlert {
        id: "2".to_string(),
        plugin_id: "40018".to_string(),
        alert: "SQL Injection".to_string(),
        name: Some("SQLi".to_string()),
        risk: "High".to_string(),
        confidence: "High".to_string(),
        url: "https://dedup.local/users#top".to_string(),
        param: Some("id".to_string()),
        attack: Some("'".to_string()),
        evidence: None,
        description: "".to_string(),
        solution: "".to_string(),
        reference: None,
        cweid: Some("89".to_string()),
        wascid: None,
        method: Some("get".to_string()),
        request_header: None,
        response_header: None,
    };

    let res = FindingPipeline::process(
        scan.id,
        &app,
        &[alert1, alert2],
        None,
        Some(30),
        &vuln_repo,
        &scan_repo,
        &app_repo,
    )
    .await
    .unwrap();

    // Must be deduplicated into 1 unique finding
    assert_eq!(res.severity_counts.total(), 1);
    assert_eq!(res.diff_summary.new_count, 1);
}
