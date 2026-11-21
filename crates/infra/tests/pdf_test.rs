use chrono::Utc;
use infra::pdf::SimplePdfGenerator;
use infra::traits::PdfGenerator;
use shared_types::{
    AppCriticality, AppEnvironment, ApplicationResponse, RemediationStatus, ScanDiffSummary,
    ScanResponse, ScanStatus, ScanType, SeverityCounts, SeverityLevel, VulnerabilityDetail,
    VulnerabilitySummary,
};
use uuid::Uuid;

#[tokio::test]
async fn test_scan_pdf_report_generation() {
    let generator = SimplePdfGenerator::new();

    let app_id = Uuid::new_v4();
    let scan_id = Uuid::new_v4();

    let app = ApplicationResponse {
        id: app_id,
        name: "Enterprise Core API".to_string(),
        description: Some("Production banking API".to_string()),
        base_url: "https://api.bank.com".to_string(),
        environment: AppEnvironment::Production,
        criticality: AppCriticality::Critical,
        owner_id: None,
        team_name: Some("FinTech Core".to_string()),
        include_regexes: vec!["https://api.bank.com/.*".to_string()],
        exclude_regexes: vec![],
        has_auth_configured: false,
        cron_schedule: None,
        is_authorized: true,
        latest_risk_score: 8.5,
        last_scanned_at: Some(Utc::now()),
        open_counts: SeverityCounts::new(1, 0, 0, 0, 0),
        created_at: Utc::now(),
    };

    let scan = ScanResponse {
        id: scan_id,
        application_id: app_id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::new(1, 0, 0, 0, 0),
        diff_summary: ScanDiffSummary {
            previous_scan_id: None,
            new_count: 1,
            persistent_count: 0,
            fixed_count: 0,
            regressed_count: 0,
            risk_score_delta: 0.0,
        },
        overall_risk_score: 9.0,
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        duration_seconds: Some(180),
        error_message: None,
    };

    let finding = VulnerabilityDetail {
        summary: VulnerabilitySummary {
            id: Uuid::new_v4(),
            application_id: app_id,
            fingerprint: "a".repeat(64),
            title: "Remote Code Execution".to_string(),
            owasp_category: "A03:2021-Injection".to_string(),
            cwe_id: Some(94),
            severity: SeverityLevel::Critical,
            cvss_score: 9.8,
            status: RemediationStatus::Open,
            http_method: "POST".to_string(),
            normalized_path: "/exec".to_string(),
            affected_param: Some("cmd".to_string()),
            assigned_to: None,
            seen_count: 1,
            last_seen_at: Utc::now(),
        },
        zap_plugin_id: "40018".to_string(),
        wasc_id: None,
        cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
        confidence: "High".to_string(),
        affected_url: "https://api.bank.com/exec".to_string(),
        description: "Arbitrary command execution flaw.".to_string(),
        solution: "Sanitize inputs and restrict shell execution.".to_string(),
        reference_urls: vec!["https://owasp.org/rce".to_string()],
        due_date: None,
        latest_evidence: None,
        first_seen_at: Utc::now(),
        resolved_at: None,
    };

    let pdf_bytes = generator
        .generate_scan_report(&scan, &app, &[finding])
        .await
        .expect("pdf generation failed");

    // Standard PDF validation
    assert!(pdf_bytes.starts_with(b"%PDF-"), "Must start with %PDF- header");
    let pdf_str = String::from_utf8_lossy(&pdf_bytes);
    assert!(pdf_str.contains("%%EOF"), "Must contain %%EOF trailer");
    assert!(pdf_str.contains("Enterprise Core API"));
    assert!(pdf_str.contains("Remote Code Execution"));
}

#[tokio::test]
async fn test_app_pdf_report_generation() {
    let generator = SimplePdfGenerator::new();
    let app_id = Uuid::new_v4();

    let app = ApplicationResponse {
        id: app_id,
        name: "Payments Portal".to_string(),
        description: None,
        base_url: "https://payments.bank.com".to_string(),
        environment: AppEnvironment::Staging,
        criticality: AppCriticality::High,
        owner_id: None,
        team_name: None,
        include_regexes: vec![],
        exclude_regexes: vec![],
        has_auth_configured: false,
        cron_schedule: None,
        is_authorized: true,
        latest_risk_score: 5.5,
        last_scanned_at: Some(Utc::now()),
        open_counts: SeverityCounts::default(),
        created_at: Utc::now(),
    };

    let pdf_bytes = generator
        .generate_app_report(&app, &[], &[])
        .await
        .expect("pdf generation failed");

    assert!(pdf_bytes.starts_with(b"%PDF-"));
    let pdf_str = String::from_utf8_lossy(&pdf_bytes);
    assert!(pdf_str.contains("%%EOF"));
    assert!(pdf_str.contains("Payments Portal"));
}
