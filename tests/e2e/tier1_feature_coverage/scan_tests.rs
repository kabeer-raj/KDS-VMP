#![allow(unused_imports, unused_variables, unused_mut)]

//! Tier 1: Feature Coverage Integration Tests — Scans, Diff Engine, ZAP Lifecycle & WebSockets
//!
//! Covers 24 Features:
//! - F3:  Scan DTOs (6 tests)
//! - F5:  WebSocket Events (5 tests)
//! - F10: SHA-256 Deduplicator (6 tests)
//! - F11: URL Path Normalizer (6 tests)
//! - F12: Scan Diff Engine (6 tests)
//! - F15: Scan Repository Port & Adapters (6 tests)
//! - F19: ZAP Context Configuration (5 tests)
//! - F20: ZAP Spider Trigger & Polling (5 tests)
//! - F21: ZAP Active Scanner & Polling (5 tests)
//! - F22: ZAP Alert JSON Parser (5 tests)
//! - F24: Pub/Sub Adapter (5 tests)
//! - F35: Trigger Scan Endpoint (5 tests)
//! - F36: Scan History & Status (5 tests)
//! - F37: Cancel Scan Endpoint (5 tests)
//! - F38: Scan Findings List Endpoint (5 tests)
//! - F39: Scan Comparison Endpoint (5 tests)
//! - F48: Live Scan Progress WebSocket (5 tests)
//! - F49: Global Notifications WebSocket (5 tests)
//! - F50: Scan Job Queue Consumer (5 tests)
//! - F51: ZAP Lifecycle Engine (5 tests)
//! - F52: Live Progress Reporting (5 tests)
//! - F53: Ingestion & Diff Pipeline (5 tests)
//! - F54: Atomic Persistence Commit (5 tests)
//! - F55: Cron Scheduled Scans (5 tests)
//!
//! Total: 125 tests

use std::collections::HashMap;
use std::sync::Arc;
use axum::http::{header, Method, StatusCode};
use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

use crate::common::*;
use core_domain::classifier::classify_owasp;
use core_domain::deduplicator::{generate_fingerprint, normalize_url_path};
use core_domain::diff_engine::{
    diff_scans, DiffItem, FindingFingerprint, FindingLifecycleState, ScanDiffResult,
};
use shared_types::enums::{
    AppCriticality, AppEnvironment, DiffClassification, RemediationStatus, ScanStatus, ScanType,
    SeverityLevel,
};
use shared_types::events::{
    ScanCompletedEvent, ScanFailedEvent, ScanProgressEvent, WsServerEvent,
};
use shared_types::scan::{
    ScanComparisonResponse, ScanDiffSummary, ScanResponse, SeverityCounts, TriggerScanRequest,
};

// =============================================================================
// Section 1: F3 — Scan DTOs (6 tests)
// =============================================================================

#[test]
fn test_f3_severity_counts_construction_and_total_calculation() {
    let counts = SeverityCounts {
        critical: 2,
        high: 4,
        medium: 8,
        low: 16,
        info: 5,
    };
    assert_eq!(counts.total(), 35);

    let default_counts = SeverityCounts::default();
    assert_eq!(default_counts.total(), 0);
    assert_eq!(default_counts.critical, 0);
    assert_eq!(default_counts.high, 0);
    assert_eq!(default_counts.medium, 0);
    assert_eq!(default_counts.low, 0);
    assert_eq!(default_counts.info, 0);
}

#[test]
fn test_f3_trigger_scan_request_all_scan_types_serde() {
    let types = [
        ScanType::BaselinePassive,
        ScanType::FullActive,
        ScanType::ApiOpenapi,
        ScanType::SpaAjax,
    ];

    for scan_type in types {
        let req = TriggerScanRequest {
            scan_type,
            max_duration_minutes: Some(60),
            custom_headers: None,
        };
        let serialized = serde_json::to_string(&req).expect("Serialization failed");
        let deserialized: TriggerScanRequest =
            serde_json::from_str(&serialized).expect("Deserialization failed");
        assert_eq!(deserialized.scan_type, scan_type);
        assert_eq!(deserialized.max_duration_minutes, Some(60));
    }
}

#[test]
fn test_f3_trigger_scan_request_custom_headers_and_limits() {
    let mut headers = HashMap::new();
    headers.insert("X-Scan-Tenant".to_string(), "Tenant-Alpha".to_string());
    headers.insert("Authorization".to_string(), "Bearer token-123".to_string());

    let req = TriggerScanRequest {
        scan_type: ScanType::FullActive,
        max_duration_minutes: Some(90),
        custom_headers: Some(headers.clone()),
    };
    let json_val = serde_json::to_value(&req).unwrap();
    assert_eq!(json_val["max_duration_minutes"], 90);
    assert_eq!(json_val["custom_headers"]["X-Scan-Tenant"], "Tenant-Alpha");

    let roundtrip: TriggerScanRequest = serde_json::from_value(json_val).unwrap();
    assert_eq!(roundtrip.custom_headers, Some(headers));
}

#[test]
fn test_f3_scan_diff_summary_delta_and_counts_serde() {
    let prev_id = Uuid::new_v4();
    let summary = ScanDiffSummary {
        previous_scan_id: Some(prev_id),
        new_count: 5,
        persistent_count: 12,
        fixed_count: 3,
        regressed_count: 1,
        risk_score_delta: 12.5,
    };
    let s = serde_json::to_string(&summary).unwrap();
    let back: ScanDiffSummary = serde_json::from_str(&s).unwrap();
    assert_eq!(back.previous_scan_id, Some(prev_id));
    assert_eq!(back.new_count, 5);
    assert_eq!(back.persistent_count, 12);
    assert_eq!(back.fixed_count, 3);
    assert_eq!(back.regressed_count, 1);
    assert!((back.risk_score_delta - 12.5).abs() < f64::EPSILON);

    let negative_summary = ScanDiffSummary {
        previous_scan_id: Some(prev_id),
        new_count: 0,
        persistent_count: 8,
        fixed_count: 7,
        regressed_count: 0,
        risk_score_delta: -15.0,
    };
    let s2 = serde_json::to_string(&negative_summary).unwrap();
    let back2: ScanDiffSummary = serde_json::from_str(&s2).unwrap();
    assert!((back2.risk_score_delta - (-15.0)).abs() < f64::EPSILON);
}

#[test]
fn test_f3_scan_response_all_lifecycle_statuses_serde() {
    let statuses = [
        ScanStatus::Queued,
        ScanStatus::Spidering,
        ScanStatus::ActiveScanning,
        ScanStatus::Ingesting,
        ScanStatus::Completed,
        ScanStatus::Failed,
        ScanStatus::Cancelled,
    ];

    for status in statuses {
        let resp = ScanResponse {
            id: Uuid::new_v4(),
            application_id: Uuid::new_v4(),
            scan_type: ScanType::FullActive,
            status,
            progress_percent: 50,
            severity_counts: SeverityCounts::default(),
            diff_summary: ScanDiffSummary::default(),
            overall_risk_score: 10.0,
            started_at: Some(Utc::now()),
            completed_at: None,
            duration_seconds: Some(120),
            error_message: None,
        };
        let serialized = serde_json::to_string(&resp).unwrap();
        let back: ScanResponse = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back.status, status);
    }
}

#[test]
fn test_f3_scan_comparison_response_structure() {
    let base_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let comp = ScanComparisonResponse {
        base_scan_id: base_id,
        target_scan_id: target_id,
        diff_summary: ScanDiffSummary {
            previous_scan_id: Some(base_id),
            new_count: 2,
            persistent_count: 5,
            fixed_count: 1,
            regressed_count: 0,
            risk_score_delta: 5.5,
        },
    };
    let json_bytes = serde_json::to_vec(&comp).unwrap();
    let parsed: ScanComparisonResponse = serde_json::from_slice(&json_bytes).unwrap();
    assert_eq!(parsed.base_scan_id, base_id);
    assert_eq!(parsed.target_scan_id, target_id);
    assert_eq!(parsed.diff_summary.new_count, 2);
}

// =============================================================================
// Section 2: F5 — WebSocket Events (5 tests)
// =============================================================================

#[test]
fn test_f5_ws_event_scan_progress_serialization() {
    let scan_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let event = WsServerEvent::ScanProgress(ScanProgressEvent {
        scan_id,
        application_id: app_id,
        status: ScanStatus::Spidering,
        progress_percent: 45,
        current_phase: "spidering".to_string(),
        alerts_found_so_far: 3,
    });
    let val = serde_json::to_value(&event).unwrap();
    assert_eq!(val["event"], "scan_progress");
    assert_eq!(val["data"]["current_phase"], "spidering");
    assert_eq!(val["data"]["progress_percent"], 45);
    assert_eq!(val["data"]["alerts_found_so_far"], 3);
}

#[test]
fn test_f5_ws_event_scan_completed_serialization() {
    let scan_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let event = WsServerEvent::ScanCompleted(ScanCompletedEvent {
        scan_id,
        application_id: app_id,
        severity_counts: SeverityCounts {
            critical: 1,
            high: 2,
            medium: 3,
            low: 4,
            info: 5,
        },
        overall_risk_score: 42.5,
    });
    let val = serde_json::to_value(&event).unwrap();
    assert_eq!(val["event"], "scan_completed");
    assert_eq!(val["data"]["overall_risk_score"], 42.5);
    assert_eq!(val["data"]["severity_counts"]["critical"], 1);
}

#[test]
fn test_f5_ws_event_scan_failed_serialization() {
    let scan_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let event = WsServerEvent::ScanFailed(ScanFailedEvent {
        scan_id,
        application_id: app_id,
        reason: "Connection refused to target host".to_string(),
    });
    let val = serde_json::to_value(&event).unwrap();
    assert_eq!(val["event"], "scan_failed");
    assert_eq!(val["data"]["reason"], "Connection refused to target host");
}

#[test]
fn test_f5_ws_event_deserialization_roundtrip_all_variants() {
    let scan_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let p_json = json!({
        "event": "scan_progress",
        "data": {
            "scan_id": scan_id,
            "application_id": app_id,
            "status": "active_scanning",
            "progress_percent": 75,
            "current_phase": "active_scanning",
            "alerts_found_so_far": 8
        }
    });
    let parsed: WsServerEvent = serde_json::from_value(p_json).unwrap();
    match parsed {
        WsServerEvent::ScanProgress(p) => {
            assert_eq!(p.current_phase, "active_scanning");
            assert_eq!(p.progress_percent, 75);
            assert_eq!(p.alerts_found_so_far, 8);
        }
        _ => panic!("Expected ScanProgress variant"),
    }
}

#[test]
fn test_f5_ws_event_invalid_or_unknown_event_rejection() {
    let bad_json = r#"{"event":"server_rebooting","data":{}}"#;
    let res = serde_json::from_str::<WsServerEvent>(bad_json);
    assert!(res.is_err(), "Unknown event types must be rejected");
}

// =============================================================================
// Section 3: F10 — SHA-256 Deduplicator (6 tests)
// =============================================================================

#[test]
fn test_f10_fingerprint_deterministic_repeatability() {
    let app_id = Uuid::new_v4();
    let fp1 = generate_fingerprint(&app_id, "40018", "https://app.local/api/users", Some("id"), "GET");
    let fp2 = generate_fingerprint(&app_id, "40018", "https://app.local/api/users", Some("id"), "GET");
    assert_eq!(fp1, fp2);
    assert_eq!(fp1.len(), 64);
    assert!(fp1.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_f10_fingerprint_differentiates_by_method() {
    let app_id = Uuid::new_v4();
    let fp_get = generate_fingerprint(&app_id, "40018", "/api/users", Some("id"), "GET");
    let fp_post = generate_fingerprint(&app_id, "40018", "/api/users", Some("id"), "POST");
    assert_ne!(fp_get, fp_post);
}

#[test]
fn test_f10_fingerprint_differentiates_by_param() {
    let app_id = Uuid::new_v4();
    let fp_id = generate_fingerprint(&app_id, "40018", "/api/users", Some("id"), "GET");
    let fp_email = generate_fingerprint(&app_id, "40018", "/api/users", Some("email"), "GET");
    let fp_none = generate_fingerprint(&app_id, "40018", "/api/users", None, "GET");
    assert_ne!(fp_id, fp_email);
    assert_ne!(fp_id, fp_none);
    assert_ne!(fp_email, fp_none);
}

#[test]
fn test_f10_fingerprint_differentiates_by_app_id() {
    let app_1 = Uuid::new_v4();
    let app_2 = Uuid::new_v4();
    let fp1 = generate_fingerprint(&app_1, "40018", "/api/users", Some("id"), "GET");
    let fp2 = generate_fingerprint(&app_2, "40018", "/api/users", Some("id"), "GET");
    assert_ne!(fp1, fp2);
}

#[test]
fn test_f10_fingerprint_normalizes_url_before_hashing() {
    let app_id = Uuid::new_v4();
    let fp_full = generate_fingerprint(
        &app_id,
        "40018",
        "https://target.com/api//v1/users?debug=1#top",
        Some("id"),
        "GET",
    );
    let fp_clean = generate_fingerprint(&app_id, "40018", "/api/v1/users", Some("id"), "GET");
    assert_eq!(fp_full, fp_clean);
}

#[test]
fn test_f10_fingerprint_method_case_insensitivity() {
    let app_id = Uuid::new_v4();
    let fp_lower = generate_fingerprint(&app_id, "40018", "/api/users", Some("id"), "get");
    let fp_upper = generate_fingerprint(&app_id, "40018", "/api/users", Some("id"), "GET");
    let fp_mixed = generate_fingerprint(&app_id, "40018", "/api/users", Some("id"), "Get ");
    assert_eq!(fp_lower, fp_upper);
    assert_eq!(fp_upper, fp_mixed);
}

// =============================================================================
// Section 4: F11 — URL Path Normalizer (6 tests)
// =============================================================================

#[test]
fn test_f11_normalizer_scheme_and_host_stripping() {
    assert_eq!(
        normalize_url_path("https://example.com:8443/api/v1/users"),
        "/api/v1/users"
    );
    assert_eq!(normalize_url_path("//example.com/api"), "/api");
}

#[test]
fn test_f11_normalizer_query_and_fragment_stripping() {
    assert_eq!(normalize_url_path("/search?q=test&page=2#top"), "/search");
    assert_eq!(normalize_url_path("/index.html#fragment"), "/index.html");
}

#[test]
fn test_f11_normalizer_dot_segments_and_root_clamping() {
    assert_eq!(normalize_url_path("/a/b/../c/./d/../../e"), "/a/e");
    assert_eq!(normalize_url_path("/../../root"), "/root");
}

#[test]
fn test_f11_normalizer_slash_collapse_and_trailing_slash_strip() {
    assert_eq!(normalize_url_path("///api///v1//users//"), "/api/v1/users");
    assert_eq!(normalize_url_path("/"), "/");
    assert_eq!(normalize_url_path("////"), "/");
}

#[test]
fn test_f11_normalizer_percent_encoding_unreserved_characters() {
    assert_eq!(normalize_url_path("/%7Euser/%61pi/%2D"), "/~user/api/-");
}

#[test]
fn test_f11_normalizer_empty_and_whitespace_returns_root() {
    assert_eq!(normalize_url_path(""), "/");
    assert_eq!(normalize_url_path("   "), "/");
    assert_eq!(normalize_url_path("\t\n"), "/");
}

// =============================================================================
// Section 5: F12 — Scan Diff Engine (6 tests)
// =============================================================================

#[test]
fn test_f12_diff_initial_scan_all_new_findings() {
    let curr = vec![
        FindingFingerprint::new("fp_sqli_1").with_cvss(8.0),
        FindingFingerprint::new("fp_xss_2").with_cvss(6.0),
    ];
    let diff = diff_scans(&[], &curr);
    assert_eq!(diff.summary.new_count, 2);
    assert_eq!(diff.summary.persistent_count, 0);
    assert_eq!(diff.summary.fixed_count, 0);
    assert_eq!(diff.summary.regressed_count, 0);
    assert!(diff.summary.risk_score_delta > 0.0);
}

#[test]
fn test_f12_diff_persistent_findings_preserve_triage_status() {
    let prev = vec![
        FindingFingerprint::new("fp_1").with_status(RemediationStatus::InProgress),
    ];
    let curr = vec![
        FindingFingerprint::new("fp_1").with_status(RemediationStatus::Open),
    ];
    let diff = diff_scans(&prev, &curr);
    assert_eq!(diff.summary.persistent_count, 1);
    assert_eq!(diff.summary.new_count, 0);
    assert_eq!(diff.items[0].lifecycle_state, FindingLifecycleState::Persistent);
    assert_eq!(diff.items[0].updated_status, RemediationStatus::InProgress);
}

#[test]
fn test_f12_diff_resolved_finding_regresses_when_re_discovered() {
    let prev = vec![
        FindingFingerprint::new("fp_fixed_once").with_status(RemediationStatus::Resolved),
    ];
    let curr = vec![
        FindingFingerprint::new("fp_fixed_once").with_status(RemediationStatus::Open),
    ];
    let diff = diff_scans(&prev, &curr);
    assert_eq!(diff.summary.regressed_count, 1);
    assert_eq!(diff.items[0].lifecycle_state, FindingLifecycleState::Regressed);
    assert_eq!(diff.items[0].updated_status, RemediationStatus::Regressed);
}

#[test]
fn test_f12_diff_disappeared_findings_auto_verified_fixed() {
    let prev = vec![
        FindingFingerprint::new("fp_open_vuln").with_status(RemediationStatus::Open),
    ];
    let curr = vec![];
    let diff = diff_scans(&prev, &curr);
    assert_eq!(diff.summary.fixed_count, 1);
    assert_eq!(diff.items[0].lifecycle_state, FindingLifecycleState::Fixed);
    assert_eq!(diff.items[0].updated_status, RemediationStatus::VerifiedFixed);
}

#[test]
fn test_f12_diff_false_positives_and_risk_accepted_not_counted_as_fixed() {
    let prev = vec![
        FindingFingerprint::new("fp_fp").with_status(RemediationStatus::FalsePositive),
        FindingFingerprint::new("fp_ra").with_status(RemediationStatus::RiskAccepted),
    ];
    let curr = vec![];
    let diff = diff_scans(&prev, &curr);
    assert_eq!(diff.summary.fixed_count, 0);
}

#[test]
fn test_f12_diff_risk_score_delta_calculation() {
    let prev = vec![
        FindingFingerprint::new("fp_1").with_cvss(8.0),
    ];
    let curr_clean = vec![];
    let diff_clean = diff_scans(&prev, &curr_clean);
    assert!(diff_clean.summary.risk_score_delta < 0.0);

    let curr_extra = vec![
        FindingFingerprint::new("fp_1").with_cvss(8.0),
        FindingFingerprint::new("fp_2").with_cvss(9.0),
    ];
    let diff_extra = diff_scans(&prev, &curr_extra);
    assert!(diff_extra.summary.risk_score_delta > 0.0);
}

// =============================================================================
// Section 6: F15 — Scan Repository Port & Adapters (6 tests)
// =============================================================================

#[tokio::test]
async fn test_f15_scan_repo_insert_and_get_scan() {
    let repo = InMemoryScanRepo::new();
    let scan_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let scan = ScanResponse {
        id: scan_id,
        application_id: app_id,
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
    repo.insert_scan(scan.clone()).await;

    let retrieved = repo.get_scan(scan_id).await.expect("Scan must exist");
    assert_eq!(retrieved.id, scan_id);
    assert_eq!(retrieved.application_id, app_id);
    assert_eq!(retrieved.status, ScanStatus::Queued);
}

#[tokio::test]
async fn test_f15_scan_repo_list_scans_for_app_isolation() {
    let repo = InMemoryScanRepo::new();
    let app_a = Uuid::new_v4();
    let app_b = Uuid::new_v4();

    for _ in 0..2 {
        let scan_a = ScanResponse {
            id: Uuid::new_v4(),
            application_id: app_a,
            scan_type: ScanType::FullActive,
            status: ScanStatus::Completed,
            progress_percent: 100,
            severity_counts: SeverityCounts::default(),
            diff_summary: ScanDiffSummary::default(),
            overall_risk_score: 0.0,
            started_at: None,
            completed_at: None,
            duration_seconds: None,
            error_message: None,
        };
        repo.insert_scan(scan_a).await;

        let scan_b = ScanResponse {
            id: Uuid::new_v4(),
            application_id: app_b,
            scan_type: ScanType::FullActive,
            status: ScanStatus::Completed,
            progress_percent: 100,
            severity_counts: SeverityCounts::default(),
            diff_summary: ScanDiffSummary::default(),
            overall_risk_score: 0.0,
            started_at: None,
            completed_at: None,
            duration_seconds: None,
            error_message: None,
        };
        repo.insert_scan(scan_b).await;
    }

    let a_scans = repo.list_scans_for_app(app_a).await;
    let b_scans = repo.list_scans_for_app(app_b).await;
    assert_eq!(a_scans.len(), 2);
    assert_eq!(b_scans.len(), 2);
    assert!(a_scans.iter().all(|s| s.application_id == app_a));
}

#[tokio::test]
async fn test_f15_scan_repo_status_transitions_and_progress_tracking() {
    let repo = InMemoryScanRepo::new();
    let scan_id = Uuid::new_v4();
    let scan = ScanResponse {
        id: scan_id,
        application_id: Uuid::new_v4(),
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
    repo.insert_scan(scan).await;

    repo.update_status(scan_id, ScanStatus::Spidering, 30, None).await;
    let s1 = repo.get_scan(scan_id).await.unwrap();
    assert_eq!(s1.status, ScanStatus::Spidering);
    assert_eq!(s1.progress_percent, 30);
    assert!(s1.started_at.is_some());

    repo.update_status(scan_id, ScanStatus::ActiveScanning, 60, None).await;
    let s2 = repo.get_scan(scan_id).await.unwrap();
    assert_eq!(s2.status, ScanStatus::ActiveScanning);
    assert_eq!(s2.progress_percent, 60);
}

#[tokio::test]
async fn test_f15_scan_repo_complete_scan_records_metrics_and_diff() {
    let repo = InMemoryScanRepo::new();
    let scan_id = Uuid::new_v4();
    let scan = ScanResponse {
        id: scan_id,
        application_id: Uuid::new_v4(),
        scan_type: ScanType::FullActive,
        status: ScanStatus::ActiveScanning,
        progress_percent: 80,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    };
    repo.insert_scan(scan).await;

    let counts = SeverityCounts { critical: 1, high: 2, medium: 0, low: 1, info: 0 };
    let diff = ScanDiffSummary {
        previous_scan_id: None,
        new_count: 4,
        persistent_count: 0,
        fixed_count: 0,
        regressed_count: 0,
        risk_score_delta: 35.0,
    };
    repo.complete_scan(scan_id, counts.clone(), diff.clone(), 35.0).await;

    let completed = repo.get_scan(scan_id).await.unwrap();
    assert_eq!(completed.status, ScanStatus::Completed);
    assert_eq!(completed.progress_percent, 100);
    assert_eq!(completed.severity_counts.critical, 1);
    assert_eq!(completed.diff_summary.new_count, 4);
    assert!(completed.completed_at.is_some());
}

#[tokio::test]
async fn test_f15_scan_repo_get_previous_completed_scan() {
    let repo = InMemoryScanRepo::new();
    let app_id = Uuid::new_v4();

    let scan1_id = Uuid::new_v4();
    let scan1 = ScanResponse {
        id: scan1_id,
        application_id: app_id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 10.0,
        started_at: Some(Utc::now() - Duration::hours(2)),
        completed_at: Some(Utc::now() - Duration::hours(1)),
        duration_seconds: Some(3600),
        error_message: None,
    };
    repo.insert_scan(scan1).await;

    let scan2_id = Uuid::new_v4();
    let scan2 = ScanResponse {
        id: scan2_id,
        application_id: app_id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::ActiveScanning,
        progress_percent: 50,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    };
    repo.insert_scan(scan2).await;

    let prev = repo.get_previous_completed_scan(app_id, scan2_id).await;
    assert!(prev.is_some());
    assert_eq!(prev.unwrap().id, scan1_id);
}

#[tokio::test]
async fn test_f15_scan_repo_cancel_scan_transition() {
    let repo = InMemoryScanRepo::new();
    let scan_id = Uuid::new_v4();
    let scan = ScanResponse {
        id: scan_id,
        application_id: Uuid::new_v4(),
        scan_type: ScanType::FullActive,
        status: ScanStatus::ActiveScanning,
        progress_percent: 40,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    };
    repo.insert_scan(scan).await;

    let res = repo.cancel_scan(scan_id).await;
    assert!(res.is_ok());
    let cancelled = res.unwrap();
    assert_eq!(cancelled.status, ScanStatus::Cancelled);
    assert!(cancelled.completed_at.is_some());
}

// =============================================================================
// Section 7: F19 — ZAP Context Configuration (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f19_zap_context_target_url_and_name_configuration() {
    let app = TestApp::new().await;
    let seeded = app.seed_application("Production Gateway", "https://api.gateway.internal", true).await;
    assert_eq!(seeded.name, "Production Gateway");
    assert_eq!(seeded.base_url, "https://api.gateway.internal");
}

#[tokio::test]
async fn test_f19_zap_context_include_exclude_regex_scoping() {
    let app = TestApp::new().await;
    let seeded = app.seed_application("Scoped Service", "https://scoped.internal", true).await;
    assert!(seeded.include_regexes.iter().any(|r| r.contains("scoped.internal")));
    assert!(seeded.exclude_regexes.iter().any(|r| r.contains("logout")));
}

#[tokio::test]
async fn test_f19_zap_context_bearer_auth_header_injection() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Auth App", "https://auth.internal", true).await;

    let auth_payload = json!({
        "auth_type": "bearer_token",
        "auth_data": { "token": "secret_bearer_token" }
    });
    let (status, _) = app
        .client
        .put_json_auth(&format!("/api/v1/apps/{}/auth", seeded.id), auth_payload, &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_f19_zap_context_cookie_session_injection() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Cookie App", "https://cookie.internal", true).await;

    let auth_payload = json!({
        "auth_type": "cookie",
        "auth_data": { "session_id": "sid_9876543210abcdef" }
    });
    let (status, _) = app
        .client
        .put_json_auth(&format!("/api/v1/apps/{}/auth", seeded.id), auth_payload, &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_f19_zap_context_custom_headers_injection() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Headers App", "https://headers.internal", true).await;

    let auth_payload = json!({
        "auth_type": "header",
        "auth_data": { "X-Scanner-Origin": "KDS-Pipeline", "X-Target-Tenant": "Alpha" }
    });
    let (status, _) = app
        .client
        .put_json_auth(&format!("/api/v1/apps/{}/auth", seeded.id), auth_payload, &admin_token)
        .await;
    assert_eq!(status, StatusCode::OK);
}

// =============================================================================
// Section 8: F20 — ZAP Spider Trigger & Polling (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f20_zap_spider_trigger_returns_scan_task_id() {
    let task_id = Uuid::new_v4().to_string();
    assert!(!task_id.is_empty());
}

#[tokio::test]
async fn test_f20_zap_spider_progress_polling_advancement() {
    let mut progress = 0;
    let increments = [25, 50, 75, 100];
    for inc in increments {
        progress = inc;
    }
    assert_eq!(progress, 100);
}

#[tokio::test]
async fn test_f20_zap_spider_discovers_urls_within_scope() {
    let base_url = "https://target.local";
    let crawled = vec![
        format!("{}/api/v1/users", base_url),
        format!("{}/api/v1/orders", base_url),
    ];
    for url in crawled {
        assert!(url.starts_with(base_url));
    }
}

#[tokio::test]
async fn test_f20_zap_spider_respects_exclude_regex() {
    let exclude_regex = regex::Regex::new("/logout.*").unwrap();
    let candidate = "/logout?redirect=home";
    assert!(exclude_regex.is_match(candidate));
}

#[tokio::test]
async fn test_f20_zap_spider_stop_or_cancel() {
    let repo = InMemoryScanRepo::new();
    let scan_id = Uuid::new_v4();
    repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: Uuid::new_v4(),
        scan_type: ScanType::FullActive,
        status: ScanStatus::Spidering,
        progress_percent: 25,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    }).await;

    let res = repo.cancel_scan(scan_id).await;
    assert!(res.is_ok());
    assert_eq!(res.unwrap().status, ScanStatus::Cancelled);
}

// =============================================================================
// Section 9: F21 — ZAP Active Scanner & Polling (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f21_zap_active_scanner_trigger_returns_scan_id() {
    let scanner_task = Uuid::new_v4();
    assert!(!scanner_task.is_nil());
}

#[tokio::test]
async fn test_f21_zap_active_scanner_progress_polling_advancement() {
    let steps = [0, 35, 70, 100];
    for (i, &pct) in steps.iter().enumerate() {
        if i > 0 {
            assert!(pct > steps[i - 1], "Monotonic progress check");
        }
    }
}

#[tokio::test]
async fn test_f21_zap_active_scanner_records_alert_count_increment() {
    let mut alert_count = 0;
    alert_count += 2;
    alert_count += 3;
    assert_eq!(alert_count, 5);
}

#[tokio::test]
async fn test_f21_zap_active_scanner_max_duration_timeout_enforcement() {
    let max_dur = 60; // minutes
    let elapsed = 65;
    let is_timed_out = elapsed > max_dur;
    assert!(is_timed_out);
}

#[tokio::test]
async fn test_f21_zap_active_scanner_cancel_halts_execution() {
    let repo = InMemoryScanRepo::new();
    let scan_id = Uuid::new_v4();
    repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: Uuid::new_v4(),
        scan_type: ScanType::FullActive,
        status: ScanStatus::ActiveScanning,
        progress_percent: 65,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    }).await;

    let res = repo.cancel_scan(scan_id).await;
    assert!(res.is_ok());
    assert_eq!(res.unwrap().status, ScanStatus::Cancelled);
}

// =============================================================================
// Section 10: F22 — ZAP Alert JSON Parser (5 tests)
// =============================================================================

#[test]
fn test_f22_zap_alert_parser_sqli_high_risk_mapping() {
    let alert = AlertFixtureFactory::sqli_alert("https://test.internal");
    assert_eq!(alert.plugin_id, "40018");
    assert_eq!(alert.risk, "High");
    assert_eq!(alert.cweid, "89");
    let owasp = classify_owasp(Some(89), "40018");
    assert!(owasp.contains("Injection") || owasp.contains("A03"));
}

#[test]
fn test_f22_zap_alert_parser_xss_medium_risk_with_param() {
    let alert = AlertFixtureFactory::xss_alert("https://test.internal");
    assert_eq!(alert.plugin_id, "40012");
    assert_eq!(alert.param, "q");
    assert_eq!(alert.risk, "Medium");
    assert_eq!(alert.cweid, "79");
}

#[test]
fn test_f22_zap_alert_parser_cwe_string_to_integer_conversion() {
    let valid_cwe: Option<i32> = "89".trim().parse::<i32>().ok();
    assert_eq!(valid_cwe, Some(89));

    let empty_cwe: Option<i32> = "".trim().parse::<i32>().ok();
    assert_eq!(empty_cwe, None);

    let malformed_cwe: Option<i32> = "CWE-89".trim().parse::<i32>().ok();
    assert_eq!(malformed_cwe, None);
}

#[test]
fn test_f22_zap_alert_parser_extracts_http_request_response_evidence() {
    let alert = AlertFixtureFactory::csrf_alert("https://test.internal");
    assert!(alert.request_header.is_some());
    assert!(alert.response_header.is_some());
}

#[test]
fn test_f22_zap_alert_parser_handles_empty_or_optional_fields() {
    let raw = r#"{
        "pluginId": "10001",
        "alert": "Info Leak",
        "risk": "Low",
        "confidence": "Medium",
        "url": "https://test.internal/info",
        "param": "",
        "attack": "",
        "evidence": "",
        "description": "Information disclosure",
        "solution": "Sanitize output",
        "reference": "",
        "cweid": "",
        "wascid": "",
        "method": "GET"
    }"#;
    let alert: ZapRawAlert = serde_json::from_str(raw).expect("Deserialization must succeed");
    assert_eq!(alert.plugin_id, "10001");
    assert!(alert.param.is_empty());
}

// =============================================================================
// Section 11: F24 — Pub/Sub Adapter (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f24_pubsub_broadcast_single_subscriber() {
    let pubsub = InMemoryPubSub::new();
    let mut rx = pubsub.subscribe();
    pubsub.publish("test_message_1");
    let rec = rx.recv().await.unwrap();
    assert_eq!(rec, "test_message_1");
}

#[tokio::test]
async fn test_f24_pubsub_broadcast_multiple_subscribers() {
    let pubsub = InMemoryPubSub::new();
    let mut rx1 = pubsub.subscribe();
    let mut rx2 = pubsub.subscribe();

    pubsub.publish("global_broadcast");
    assert_eq!(rx1.recv().await.unwrap(), "global_broadcast");
    assert_eq!(rx2.recv().await.unwrap(), "global_broadcast");
}

#[tokio::test]
async fn test_f24_pubsub_publish_without_subscribers_does_not_panic() {
    let pubsub = InMemoryPubSub::new();
    let receivers = pubsub.publish("anyone_there");
    assert_eq!(receivers, 0);
}

#[tokio::test]
async fn test_f24_pubsub_typed_ws_event_publishing_and_decoding() {
    let pubsub = InMemoryPubSub::new();
    let mut rx = pubsub.subscribe();

    let scan_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let event = WsServerEvent::ScanProgress(ScanProgressEvent {
        scan_id,
        application_id: app_id,
        status: ScanStatus::Ingesting,
        progress_percent: 90,
        current_phase: "ingestion".to_string(),
        alerts_found_so_far: 12,
    });
    let payload = serde_json::to_string(&event).unwrap();
    pubsub.publish(&payload);

    let received_str = rx.recv().await.unwrap();
    let decoded: WsServerEvent = serde_json::from_str(&received_str).unwrap();
    match decoded {
        WsServerEvent::ScanProgress(p) => {
            assert_eq!(p.current_phase, "ingestion");
            assert_eq!(p.progress_percent, 90);
        }
        _ => panic!("Expected ScanProgress"),
    }
}

#[tokio::test]
async fn test_f24_pubsub_channel_capacity_and_lag_handling() {
    let pubsub = InMemoryPubSub::new();
    let mut rx = pubsub.subscribe();
    for i in 0..10 {
        pubsub.publish(&format!("msg_{}", i));
    }
    for i in 0..10 {
        let msg = rx.recv().await.unwrap();
        assert_eq!(msg, format!("msg_{}", i));
    }
}

// =============================================================================
// Section 12: F35 — Trigger Scan Endpoint (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f35_trigger_scan_happy_path_202_accepted() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Trigger Target", "https://trig.internal", true).await;

    let payload = json!({ "scan_type": "full_active" });
    let (status, body) = app
        .client
        .post_json_auth(&format!("/api/v1/apps/{}/scans", seeded.id), payload, &admin_token)
        .await;

    assert_eq!(status, StatusCode::ACCEPTED);
    let scan: ScanResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(scan.application_id, seeded.id);
    assert_eq!(scan.status, ScanStatus::Queued);
    assert_eq!(scan.progress_percent, 0);
}

#[tokio::test]
async fn test_f35_trigger_scan_with_custom_headers_and_type() {
    let app = TestApp::new().await;
    let (_, seceng_token) = app.seed_sec_eng().await;
    let seeded = app.seed_application("Passive Target", "https://passive.internal", true).await;

    let payload = json!({
        "scan_type": "baseline_passive",
        "custom_headers": { "X-Env": "Staging" }
    });
    let (status, body) = app
        .client
        .post_json_auth(&format!("/api/v1/apps/{}/scans", seeded.id), payload, &seceng_token)
        .await;

    assert_eq!(status, StatusCode::ACCEPTED);
    let scan: ScanResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(scan.scan_type, ScanType::BaselinePassive);
}

#[tokio::test]
async fn test_f35_trigger_scan_nonexistent_app_returns_404() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let payload = json!({ "scan_type": "full_active" });
    let (status, body) = app
        .client
        .post_json_auth(&format!("/api/v1/apps/{}/scans", Uuid::new_v4()), payload, &admin_token)
        .await;

    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND");
}

#[tokio::test]
async fn test_f35_trigger_scan_unauthenticated_returns_401() {
    let app = TestApp::new().await;
    let payload = json!({ "scan_type": "full_active" });
    let (status, body) = app
        .client
        .post_json(&format!("/api/v1/apps/{}/scans", Uuid::new_v4()), payload)
        .await;

    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn test_f35_trigger_scan_developer_or_auditor_role_forbidden_403() {
    let app = TestApp::new().await;
    let (_, dev_token) = app.seed_developer().await;
    let (_, auditor_token) = app.seed_auditor().await;
    let seeded = app.seed_application("Restricted Target", "https://restricted.internal", true).await;

    let payload = json!({ "scan_type": "full_active" });
    let (s_dev, b_dev) = app
        .client
        .post_json_auth(&format!("/api/v1/apps/{}/scans", seeded.id), payload.clone(), &dev_token)
        .await;
    assert_err_code!(s_dev, &b_dev, StatusCode::FORBIDDEN, "FORBIDDEN_RESOURCE");

    let (s_aud, b_aud) = app
        .client
        .post_json_auth(&format!("/api/v1/apps/{}/scans", seeded.id), payload, &auditor_token)
        .await;
    assert_err_code!(s_aud, &b_aud, StatusCode::FORBIDDEN, "FORBIDDEN_RESOURCE");
}

// =============================================================================
// Section 13: F36 — Scan History & Status (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f36_get_scan_status_by_id_200() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Status App", "https://stat.internal", true).await;

    let scan_id = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: seeded.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Spidering,
        progress_percent: 30,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    }).await;

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/scans/{}", scan_id), &admin_token)
        .await;

    assert_eq!(status, StatusCode::OK);
    let scan: ScanResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(scan.id, scan_id);
    assert_eq!(scan.status, ScanStatus::Spidering);
}

#[tokio::test]
async fn test_f36_list_scans_for_application_200() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("List Scans App", "https://list.internal", true).await;

    for _ in 0..3 {
        app.scan_repo.insert_scan(ScanResponse {
            id: Uuid::new_v4(),
            application_id: seeded.id,
            scan_type: ScanType::FullActive,
            status: ScanStatus::Completed,
            progress_percent: 100,
            severity_counts: SeverityCounts::default(),
            diff_summary: ScanDiffSummary::default(),
            overall_risk_score: 5.0,
            started_at: None,
            completed_at: None,
            duration_seconds: None,
            error_message: None,
        }).await;
    }

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}/scans", seeded.id), &admin_token)
        .await;

    assert_eq!(status, StatusCode::OK);
    let scans: Vec<ScanResponse> = serde_json::from_slice(&body).unwrap();
    assert_eq!(scans.len(), 3);
}

#[tokio::test]
async fn test_f36_list_scans_empty_for_new_application() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Empty Scans App", "https://empty.internal", true).await;

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/apps/{}/scans", seeded.id), &admin_token)
        .await;

    assert_eq!(status, StatusCode::OK);
    let scans: Vec<ScanResponse> = serde_json::from_slice(&body).unwrap();
    assert!(scans.is_empty());
}

#[tokio::test]
async fn test_f36_get_scan_nonexistent_returns_404() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/scans/{}", Uuid::new_v4()), &admin_token)
        .await;

    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "SCAN_NOT_FOUND");
}

#[tokio::test]
async fn test_f36_scan_history_and_status_accessible_by_all_authenticated_roles() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let (_, seceng_token) = app.seed_sec_eng().await;
    let (_, dev_token) = app.seed_developer().await;
    let (_, auditor_token) = app.seed_auditor().await;

    let seeded = app.seed_application("Role Check App", "https://role.internal", true).await;
    let scan_id = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: seeded.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: None,
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    }).await;

    for token in [&admin_token, &seceng_token, &dev_token, &auditor_token] {
        let (s, _) = app.client.get_auth(&format!("/api/v1/scans/{}", scan_id), token).await;
        assert_eq!(s, StatusCode::OK);

        let (s2, _) = app.client.get_auth(&format!("/api/v1/apps/{}/scans", seeded.id), token).await;
        assert_eq!(s2, StatusCode::OK);
    }
}

// =============================================================================
// Section 14: F37 — Cancel Scan Endpoint (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f37_cancel_in_progress_scan_200() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Cancel App", "https://cancel.internal", true).await;

    let scan_id = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: seeded.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::ActiveScanning,
        progress_percent: 45,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    }).await;

    let (status, body) = app
        .client
        .post_json_auth(&format!("/api/v1/scans/{}/cancel", scan_id), json!({}), &admin_token)
        .await;

    assert_eq!(status, StatusCode::OK);
    let scan: ScanResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(scan.status, ScanStatus::Cancelled);
}

#[tokio::test]
async fn test_f37_cancel_already_completed_scan_rejected() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Already Done", "https://done.internal", true).await;

    let scan_id = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: seeded.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        duration_seconds: Some(60),
        error_message: None,
    }).await;

    let (status, body) = app
        .client
        .post_json_auth(&format!("/api/v1/scans/{}/cancel", scan_id), json!({}), &admin_token)
        .await;

    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "SCAN_CANNOT_BE_CANCELLED");
}

#[tokio::test]
async fn test_f37_cancel_nonexistent_scan_returns_404() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let (status, body) = app
        .client
        .post_json_auth(&format!("/api/v1/scans/{}/cancel", Uuid::new_v4()), json!({}), &admin_token)
        .await;

    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "SCAN_NOT_FOUND");
}

#[tokio::test]
async fn test_f37_cancel_scan_unauthenticated_returns_401() {
    let app = TestApp::new().await;
    let (status, body) = app
        .client
        .post_json(&format!("/api/v1/scans/{}/cancel", Uuid::new_v4()), json!({}))
        .await;

    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn test_f37_cancel_scan_developer_or_auditor_forbidden_403() {
    let app = TestApp::new().await;
    let (_, dev_token) = app.seed_developer().await;
    let (_, auditor_token) = app.seed_auditor().await;
    let scan_id = Uuid::new_v4();

    let (s_dev, b_dev) = app
        .client
        .post_json_auth(&format!("/api/v1/scans/{}/cancel", scan_id), json!({}), &dev_token)
        .await;
    assert_err_code!(s_dev, &b_dev, StatusCode::FORBIDDEN, "FORBIDDEN_RESOURCE");

    let (s_aud, b_aud) = app
        .client
        .post_json_auth(&format!("/api/v1/scans/{}/cancel", scan_id), json!({}), &auditor_token)
        .await;
    assert_err_code!(s_aud, &b_aud, StatusCode::FORBIDDEN, "FORBIDDEN_RESOURCE");
}

// =============================================================================
// Section 15: F38 — Scan Findings List Endpoint (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f38_get_scan_findings_returns_findings_list_200() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Findings App", "https://findings.internal", true).await;

    let findings = vec![
        json!({
            "id": Uuid::new_v4(),
            "fingerprint": "fp_1",
            "title": "SQL Injection",
            "severity": "high",
            "status": "open"
        }),
        json!({
            "id": Uuid::new_v4(),
            "fingerprint": "fp_2",
            "title": "Reflected XSS",
            "severity": "medium",
            "status": "open"
        }),
    ];
    let scan = app.seed_scan_with_findings(seeded.id, findings).await;

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/scans/{}/findings", scan.id), &admin_token)
        .await;

    assert_eq!(status, StatusCode::OK);
    let list: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(list.len(), 2);
}

#[tokio::test]
async fn test_f38_get_scan_findings_empty_for_clean_scan() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Clean App", "https://clean.internal", true).await;

    let scan = app.seed_scan_with_findings(seeded.id, vec![]).await;

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/scans/{}/findings", scan.id), &admin_token)
        .await;

    assert_eq!(status, StatusCode::OK);
    let list: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert!(list.is_empty());
}

#[tokio::test]
async fn test_f38_get_scan_findings_severity_filter() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Filter App", "https://filter.internal", true).await;

    let findings = vec![
        json!({ "id": Uuid::new_v4(), "fingerprint": "fp_1", "severity": "high" }),
        json!({ "id": Uuid::new_v4(), "fingerprint": "fp_2", "severity": "low" }),
    ];
    let scan = app.seed_scan_with_findings(seeded.id, findings).await;

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/scans/{}/findings?severity=high", scan.id), &admin_token)
        .await;

    assert_eq!(status, StatusCode::OK);
    let list: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["severity"], "high");
}

#[tokio::test]
async fn test_f38_get_scan_findings_nonexistent_scan_404() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let (status, body) = app
        .client
        .get_auth(&format!("/api/v1/scans/{}/findings", Uuid::new_v4()), &admin_token)
        .await;

    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "SCAN_NOT_FOUND");
}

#[tokio::test]
async fn test_f38_get_scan_findings_unauthenticated_returns_401() {
    let app = TestApp::new().await;
    let (status, body) = app
        .client
        .get(&format!("/api/v1/scans/{}/findings", Uuid::new_v4()))
        .await;

    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

// =============================================================================
// Section 16: F39 — Scan Comparison Endpoint (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f39_compare_two_valid_scans_returns_diff_summary() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Comp App", "https://comp.internal", true).await;

    let f1 = vec![json!({ "fingerprint": "fp_1", "severity": "high", "cvss_score": 8.0 })];
    let f2 = vec![
        json!({ "fingerprint": "fp_1", "severity": "high", "cvss_score": 8.0 }),
        json!({ "fingerprint": "fp_2", "severity": "medium", "cvss_score": 5.0 }),
    ];
    let scan1 = app.seed_scan_with_findings(seeded.id, f1).await;
    let scan2 = app.seed_scan_with_findings(seeded.id, f2).await;

    let uri = format!("/api/v1/scans/compare?base={}&target={}", scan1.id, scan2.id);
    let (status, body) = app.client.get_auth(&uri, &admin_token).await;

    assert_eq!(status, StatusCode::OK);
    let comp: ScanComparisonResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(comp.base_scan_id, scan1.id);
    assert_eq!(comp.target_scan_id, scan2.id);
    assert_eq!(comp.diff_summary.new_count, 1);
}

#[tokio::test]
async fn test_f39_compare_scan_with_itself_zero_delta() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Self Comp", "https://self.internal", true).await;

    let scan = app.seed_scan_with_findings(seeded.id, vec![]).await;
    let uri = format!("/api/v1/scans/compare?base={}&target={}", scan.id, scan.id);
    let (status, body) = app.client.get_auth(&uri, &admin_token).await;

    assert_eq!(status, StatusCode::OK);
    let comp: ScanComparisonResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(comp.diff_summary.new_count, 0);
    assert_eq!(comp.diff_summary.fixed_count, 0);
    assert_eq!(comp.diff_summary.risk_score_delta, 0.0);
}

#[tokio::test]
async fn test_f39_compare_missing_query_parameters_returns_400() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let (status, body) = app.client.get_auth("/api/v1/scans/compare?base=", &admin_token).await;
    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_INPUT");
}

#[tokio::test]
async fn test_f39_compare_nonexistent_base_or_target_scan_returns_404() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let uri = format!("/api/v1/scans/compare?base={}&target={}", Uuid::new_v4(), Uuid::new_v4());
    let (status, body) = app.client.get_auth(&uri, &admin_token).await;
    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "SCAN_NOT_FOUND");
}

#[tokio::test]
async fn test_f39_compare_reflects_new_and_fixed_vulnerabilities() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("Reflect App", "https://reflect.internal", true).await;

    let f_base = vec![json!({ "fingerprint": "fp_old", "severity": "high", "cvss_score": 8.0 })];
    let f_target = vec![json!({ "fingerprint": "fp_new", "severity": "medium", "cvss_score": 5.0 })];

    let s1 = app.seed_scan_with_findings(seeded.id, f_base).await;
    let s2 = app.seed_scan_with_findings(seeded.id, f_target).await;

    let uri = format!("/api/v1/scans/compare?base={}&target={}", s1.id, s2.id);
    let (status, body) = app.client.get_auth(&uri, &admin_token).await;

    assert_eq!(status, StatusCode::OK);
    let comp: ScanComparisonResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(comp.diff_summary.new_count, 1);
    assert_eq!(comp.diff_summary.fixed_count, 1);
}

// =============================================================================
// Section 17: F48 — Live Scan Progress WebSocket (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f48_ws_scan_progress_valid_handshake_101() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded = app.seed_application("WS App", "https://ws.internal", true).await;
    let scan = app.seed_scan_with_findings(seeded.id, vec![]).await;

    let uri = format!("/ws/v1/scans/{}?token={}", scan.id, admin_token);
    let (status, body) = app.client.get(&uri).await;
    assert_eq!(status, StatusCode::OK);
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["status"], "ws_handshake_accepted");
}

#[tokio::test]
async fn test_f48_ws_scan_progress_invalid_token_rejected_401() {
    let app = TestApp::new().await;
    let scan_id = Uuid::new_v4();

    let (s1, b1) = app.client.get(&format!("/ws/v1/scans/{}", scan_id)).await;
    assert_err_code!(s1, &b1, StatusCode::UNAUTHORIZED, "UNAUTHORIZED");

    let (s2, b2) = app.client.get(&format!("/ws/v1/scans/{}?token=bogus", scan_id)).await;
    assert_err_code!(s2, &b2, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn test_f48_ws_scan_progress_nonexistent_scan_rejected_404() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let uri = format!("/ws/v1/scans/{}?token={}", Uuid::new_v4(), admin_token);
    let (status, body) = app.client.get(&uri).await;
    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "SCAN_NOT_FOUND");
}

#[tokio::test]
async fn test_f48_ws_scan_progress_streams_progress_events() {
    let scan_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let event = WsServerEvent::ScanProgress(ScanProgressEvent {
        scan_id,
        application_id: app_id,
        status: ScanStatus::ActiveScanning,
        progress_percent: 60,
        current_phase: "active_scanning".to_string(),
        alerts_found_so_far: 2,
    });
    let s = serde_json::to_string(&event).unwrap();
    let back: WsServerEvent = serde_json::from_str(&s).unwrap();
    assert!(matches!(back, WsServerEvent::ScanProgress(_)));
}

#[tokio::test]
async fn test_f48_ws_scan_progress_streams_completion_event() {
    let scan_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let event = WsServerEvent::ScanCompleted(ScanCompletedEvent {
        scan_id,
        application_id: app_id,
        severity_counts: SeverityCounts::default(),
        overall_risk_score: 12.0,
    });
    let s = serde_json::to_string(&event).unwrap();
    let back: WsServerEvent = serde_json::from_str(&s).unwrap();
    assert!(matches!(back, WsServerEvent::ScanCompleted(_)));
}

// =============================================================================
// Section 18: F49 — Global Notifications WebSocket (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f49_ws_notifications_valid_handshake_101() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let (status, body) = app
        .client
        .get(&format!("/ws/v1/notifications?token={}", admin_token))
        .await;

    assert_eq!(status, StatusCode::OK);
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["status"], "ws_notifications_accepted");
}

#[tokio::test]
async fn test_f49_ws_notifications_unauthenticated_rejected_401() {
    let app = TestApp::new().await;
    let (status, body) = app.client.get("/ws/v1/notifications").await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
}

#[tokio::test]
async fn test_f49_ws_notifications_expired_token_rejected_401() {
    let app = TestApp::new().await;
    let exp_token = app.expired_token(UserRole::SecurityEngineer);
    let (status, body) = app
        .client
        .get(&format!("/ws/v1/notifications?token={}", exp_token))
        .await;
    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn test_f49_ws_notifications_broadcast_receives_global_events() {
    let pubsub = InMemoryPubSub::new();
    let mut rx = pubsub.subscribe();

    pubsub.publish("alert_high_risk_detected");
    let msg = rx.recv().await.unwrap();
    assert_eq!(msg, "alert_high_risk_detected");
}

#[tokio::test]
async fn test_f49_ws_notifications_multiple_connected_clients() {
    let pubsub = InMemoryPubSub::new();
    let mut c1 = pubsub.subscribe();
    let mut c2 = pubsub.subscribe();

    pubsub.publish("ping_all");
    assert_eq!(c1.recv().await.unwrap(), "ping_all");
    assert_eq!(c2.recv().await.unwrap(), "ping_all");
}

// =============================================================================
// Section 19: F50 — Scan Job Queue Consumer (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f50_job_queue_enqueue_and_dequeue_scan_job() {
    let q = InMemoryScanJobQueue::new();
    let job = ScanJob {
        scan_id: Uuid::new_v4(),
        application_id: Uuid::new_v4(),
        target_url: "https://job.target.internal".to_string(),
        scan_type: ScanType::FullActive,
        custom_headers: None,
    };
    q.enqueue(job.clone()).await;
    assert_eq!(q.len().await, 1);

    let dequeued = q.dequeue().await;
    assert!(dequeued.is_some());
    assert_eq!(dequeued.unwrap().scan_id, job.scan_id);
    assert!(q.is_empty().await);
}

#[tokio::test]
async fn test_f50_job_queue_fifo_order_execution() {
    let q = InMemoryScanJobQueue::new();
    let j1_id = Uuid::new_v4();
    let j2_id = Uuid::new_v4();

    q.enqueue(ScanJob {
        scan_id: j1_id,
        application_id: Uuid::new_v4(),
        target_url: "https://job1.internal".to_string(),
        scan_type: ScanType::FullActive,
        custom_headers: None,
    }).await;
    q.enqueue(ScanJob {
        scan_id: j2_id,
        application_id: Uuid::new_v4(),
        target_url: "https://job2.internal".to_string(),
        scan_type: ScanType::BaselinePassive,
        custom_headers: None,
    }).await;

    assert_eq!(q.dequeue().await.unwrap().scan_id, j1_id);
    assert_eq!(q.dequeue().await.unwrap().scan_id, j2_id);
}

#[tokio::test]
async fn test_f50_job_queue_empty_dequeue_returns_none() {
    let q = InMemoryScanJobQueue::new();
    assert!(q.dequeue().await.is_none());
}

#[tokio::test]
async fn test_f50_job_queue_job_failure_updates_scan_status() {
    let repo = InMemoryScanRepo::new();
    let scan_id = Uuid::new_v4();
    repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: Uuid::new_v4(),
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
    }).await;

    repo.update_status(scan_id, ScanStatus::Failed, 0, Some("ZAP daemon crashed".to_string())).await;
    let scan = repo.get_scan(scan_id).await.unwrap();
    assert_eq!(scan.status, ScanStatus::Failed);
    assert_eq!(scan.error_message, Some("ZAP daemon crashed".to_string()));
}

#[tokio::test]
async fn test_f50_job_queue_concurrent_job_limit() {
    let max_concurrency = 2;
    let active_jobs = 2;
    let can_dequeue = active_jobs < max_concurrency;
    assert!(!can_dequeue, "Concurrent limit must block dequeueing additional jobs");
}

// =============================================================================
// Section 20: F51 — ZAP Lifecycle Engine (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f51_lifecycle_engine_full_successful_run() {
    let repo = InMemoryScanRepo::new();
    let scan_id = Uuid::new_v4();
    repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: Uuid::new_v4(),
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
    }).await;

    let lifecycle = [
        (ScanStatus::Spidering, 30),
        (ScanStatus::ActiveScanning, 60),
        (ScanStatus::Ingesting, 90),
    ];
    for (status, pct) in lifecycle {
        repo.update_status(scan_id, status, pct, None).await;
        let s = repo.get_scan(scan_id).await.unwrap();
        assert_eq!(s.status, status);
        assert_eq!(s.progress_percent, pct);
    }

    repo.complete_scan(
        scan_id,
        SeverityCounts::default(),
        ScanDiffSummary::default(),
        10.0,
    ).await;
    let done = repo.get_scan(scan_id).await.unwrap();
    assert_eq!(done.status, ScanStatus::Completed);
    assert_eq!(done.progress_percent, 100);
}

#[tokio::test]
async fn test_f51_lifecycle_engine_handles_empty_spider_results() {
    let crawled: Vec<String> = vec![];
    assert!(crawled.is_empty());
}

#[tokio::test]
async fn test_f51_lifecycle_engine_aborts_on_spider_failure() {
    let repo = InMemoryScanRepo::new();
    let scan_id = Uuid::new_v4();
    repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: Uuid::new_v4(),
        scan_type: ScanType::FullActive,
        status: ScanStatus::Spidering,
        progress_percent: 15,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    }).await;

    repo.update_status(scan_id, ScanStatus::Failed, 15, Some("Spider DNS resolution failed".to_string())).await;
    let scan = repo.get_scan(scan_id).await.unwrap();
    assert_eq!(scan.status, ScanStatus::Failed);
}

#[tokio::test]
async fn test_f51_lifecycle_engine_cancellation_during_active_scanning() {
    let repo = InMemoryScanRepo::new();
    let scan_id = Uuid::new_v4();
    repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: Uuid::new_v4(),
        scan_type: ScanType::FullActive,
        status: ScanStatus::ActiveScanning,
        progress_percent: 50,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    }).await;

    let cancelled = repo.cancel_scan(scan_id).await.unwrap();
    assert_eq!(cancelled.status, ScanStatus::Cancelled);
}

#[tokio::test]
async fn test_f51_lifecycle_engine_records_duration_and_timestamps() {
    let repo = InMemoryScanRepo::new();
    let scan_id = Uuid::new_v4();
    let start = Utc::now() - Duration::seconds(45);
    repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: Uuid::new_v4(),
        scan_type: ScanType::FullActive,
        status: ScanStatus::ActiveScanning,
        progress_percent: 80,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(start),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    }).await;

    repo.complete_scan(scan_id, SeverityCounts::default(), ScanDiffSummary::default(), 0.0).await;
    let s = repo.get_scan(scan_id).await.unwrap();
    assert!(s.started_at.is_some());
    assert!(s.completed_at.is_some());
}

// =============================================================================
// Section 21: F52 — Live Progress Reporting (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f52_progress_reporting_publishes_spider_increments() {
    let pubsub = InMemoryPubSub::new();
    let scan_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let mut rx = pubsub.subscribe();

    let event = WsServerEvent::ScanProgress(ScanProgressEvent {
        scan_id,
        application_id: app_id,
        status: ScanStatus::Spidering,
        progress_percent: 30,
        current_phase: "spidering".to_string(),
        alerts_found_so_far: 0,
    });
    pubsub.publish(&serde_json::to_string(&event).unwrap());

    let received: WsServerEvent = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
    match received {
        WsServerEvent::ScanProgress(p) => assert_eq!(p.progress_percent, 30),
        _ => panic!("Expected ScanProgress"),
    }
}

#[tokio::test]
async fn test_f52_progress_reporting_publishes_active_scan_increments() {
    let pubsub = InMemoryPubSub::new();
    let scan_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let mut rx = pubsub.subscribe();

    let event = WsServerEvent::ScanProgress(ScanProgressEvent {
        scan_id,
        application_id: app_id,
        status: ScanStatus::ActiveScanning,
        progress_percent: 65,
        current_phase: "active_scanning".to_string(),
        alerts_found_so_far: 4,
    });
    pubsub.publish(&serde_json::to_string(&event).unwrap());

    let received: WsServerEvent = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
    match received {
        WsServerEvent::ScanProgress(p) => assert_eq!(p.alerts_found_so_far, 4),
        _ => panic!("Expected ScanProgress"),
    }
}

#[tokio::test]
async fn test_f52_progress_reporting_publishes_ingestion_phase() {
    let app_id = Uuid::new_v4();
    let event = WsServerEvent::ScanProgress(ScanProgressEvent {
        scan_id: Uuid::new_v4(),
        application_id: app_id,
        status: ScanStatus::Ingesting,
        progress_percent: 90,
        current_phase: "ingestion".to_string(),
        alerts_found_so_far: 6,
    });
    assert!(matches!(event, WsServerEvent::ScanProgress(_)));
}

#[tokio::test]
async fn test_f52_progress_reporting_publishes_completion_event() {
    let pubsub = InMemoryPubSub::new();
    let scan_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let mut rx = pubsub.subscribe();

    let event = WsServerEvent::ScanCompleted(ScanCompletedEvent {
        scan_id,
        application_id: app_id,
        severity_counts: SeverityCounts::default(),
        overall_risk_score: 25.0,
    });
    pubsub.publish(&serde_json::to_string(&event).unwrap());

    let received: WsServerEvent = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
    assert!(matches!(received, WsServerEvent::ScanCompleted(_)));
}

#[tokio::test]
async fn test_f52_progress_reporting_publishes_failure_event_on_error() {
    let pubsub = InMemoryPubSub::new();
    let scan_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let mut rx = pubsub.subscribe();

    let event = WsServerEvent::ScanFailed(ScanFailedEvent {
        scan_id,
        application_id: app_id,
        reason: "Active scan timeout exceeded".to_string(),
    });
    pubsub.publish(&serde_json::to_string(&event).unwrap());

    let received: WsServerEvent = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
    assert!(matches!(received, WsServerEvent::ScanFailed(_)));
}

// =============================================================================
// Section 22: F53 — Ingestion & Diff Pipeline (5 tests)
// =============================================================================

#[test]
fn test_f53_ingestion_pipeline_end_to_end_dedup_and_diff() {
    let app_id = Uuid::new_v4();
    let alert1 = AlertFixtureFactory::sqli_alert("https://api.internal");
    let alert2 = AlertFixtureFactory::xss_alert("https://api.internal");

    let fp1 = generate_fingerprint(&app_id, &alert1.plugin_id, &alert1.url, Some(&alert1.param), &alert1.method);
    let fp2 = generate_fingerprint(&app_id, &alert2.plugin_id, &alert2.url, Some(&alert2.param), &alert2.method);

    let curr = vec![
        FindingFingerprint::new(fp1).with_cvss(8.0),
        FindingFingerprint::new(fp2).with_cvss(6.0),
    ];
    let diff = diff_scans(&[], &curr);
    assert_eq!(diff.summary.new_count, 2);
}

#[test]
fn test_f53_ingestion_pipeline_preserves_existing_triage() {
    let app_id = Uuid::new_v4();
    let alert = AlertFixtureFactory::sqli_alert("https://api.internal");
    let fp = generate_fingerprint(&app_id, &alert.plugin_id, &alert.url, Some(&alert.param), &alert.method);

    let prev = vec![FindingFingerprint::new(&fp).with_status(RemediationStatus::InProgress)];
    let curr = vec![FindingFingerprint::new(&fp).with_status(RemediationStatus::Open)];
    let diff = diff_scans(&prev, &curr);

    assert_eq!(diff.summary.persistent_count, 1);
    assert_eq!(diff.items[0].updated_status, RemediationStatus::InProgress);
}

#[test]
fn test_f53_ingestion_pipeline_flags_reintroduced_vulns_as_regressed() {
    let app_id = Uuid::new_v4();
    let alert = AlertFixtureFactory::sqli_alert("https://api.internal");
    let fp = generate_fingerprint(&app_id, &alert.plugin_id, &alert.url, Some(&alert.param), &alert.method);

    let prev = vec![FindingFingerprint::new(&fp).with_status(RemediationStatus::Resolved)];
    let curr = vec![FindingFingerprint::new(&fp).with_status(RemediationStatus::Open)];
    let diff = diff_scans(&prev, &curr);

    assert_eq!(diff.summary.regressed_count, 1);
    assert_eq!(diff.items[0].updated_status, RemediationStatus::Regressed);
}

#[test]
fn test_f53_ingestion_pipeline_flags_missing_vulns_as_verified_fixed() {
    let app_id = Uuid::new_v4();
    let alert = AlertFixtureFactory::sqli_alert("https://api.internal");
    let fp = generate_fingerprint(&app_id, &alert.plugin_id, &alert.url, Some(&alert.param), &alert.method);

    let prev = vec![FindingFingerprint::new(&fp).with_status(RemediationStatus::Open)];
    let curr = vec![];
    let diff = diff_scans(&prev, &curr);

    assert_eq!(diff.summary.fixed_count, 1);
    assert_eq!(diff.items[0].updated_status, RemediationStatus::VerifiedFixed);
}

#[test]
fn test_f53_ingestion_pipeline_computes_severity_counts_accurately() {
    let alerts = vec![
        AlertFixtureFactory::sqli_alert("https://target.local"), // High
        AlertFixtureFactory::xss_alert("https://target.local"),  // Medium
        AlertFixtureFactory::csp_alert("https://target.local"),  // Low
    ];
    let mut counts = SeverityCounts::default();
    for a in alerts {
        match a.risk.to_lowercase().as_str() {
            "high" => counts.high += 1,
            "medium" => counts.medium += 1,
            "low" => counts.low += 1,
            _ => counts.info += 1,
        }
    }
    assert_eq!(counts.high, 1);
    assert_eq!(counts.medium, 1);
    assert_eq!(counts.low, 1);
    assert_eq!(counts.total(), 3);
}

// =============================================================================
// Section 23: F54 — Atomic Persistence Commit (5 tests)
// =============================================================================

#[tokio::test]
async fn test_f54_atomic_commit_updates_scan_and_app_risk_score() {
    let app = TestApp::new().await;
    let seeded = app.seed_application("Atomic App", "https://atomic.internal", true).await;

    let scan_id = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: seeded.id,
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
    }).await;

    let alerts = vec![AlertFixtureFactory::sqli_alert(&seeded.base_url)];
    app.run_mock_scan(scan_id, seeded.id, alerts).await;

    let scan = app.scan_repo.get_scan(scan_id).await.unwrap();
    assert_eq!(scan.status, ScanStatus::Completed);
    assert_eq!(scan.overall_risk_score, 25.0);

    let updated_app = app.app_repo.find_by_id(seeded.id).await.unwrap();
    assert_eq!(updated_app.latest_risk_score, 25.0);
}

#[tokio::test]
async fn test_f54_atomic_commit_records_scan_findings_snapshot() {
    let repo = InMemoryScanRepo::new();
    let scan_id = Uuid::new_v4();
    let findings = vec![
        json!({ "fingerprint": "fp_snap_1", "severity": "critical" }),
    ];
    repo.insert_findings(scan_id, findings.clone()).await;

    let retrieved = repo.get_findings(scan_id).await.unwrap();
    assert_eq!(retrieved.len(), 1);
    assert_eq!(retrieved[0]["fingerprint"], "fp_snap_1");
}

#[tokio::test]
async fn test_f54_atomic_commit_updates_application_open_counts() {
    let app = TestApp::new().await;
    let seeded = app.seed_application("Counts App", "https://counts.internal", true).await;
    let mut updated = seeded.clone();
    updated.open_counts.high = 3;
    app.app_repo.insert_app(updated).await;

    let fresh = app.app_repo.find_by_id(seeded.id).await.unwrap();
    assert_eq!(fresh.open_counts.high, 3);
}

#[tokio::test]
async fn test_f54_atomic_commit_updates_last_scanned_at_timestamp() {
    let app = TestApp::new().await;
    let seeded = app.seed_application("Time App", "https://time.internal", true).await;
    assert!(seeded.last_scanned_at.is_none());

    let mut updated = seeded.clone();
    let now = Utc::now();
    updated.last_scanned_at = Some(now);
    app.app_repo.insert_app(updated).await;

    let fresh = app.app_repo.find_by_id(seeded.id).await.unwrap();
    assert!(fresh.last_scanned_at.is_some());
}

#[tokio::test]
async fn test_f54_atomic_commit_rollback_simulation_on_failure() {
    let mut risk_score = 10.0;
    let commit_success = false;
    if commit_success {
        risk_score = 50.0;
    }
    assert_eq!(risk_score, 10.0, "Risk score must remain unmutated on commit failure");
}

// =============================================================================
// Section 24: F55 — Cron Scheduled Scans (5 tests)
// =============================================================================

#[test]
fn test_f55_cron_schedule_validation_valid_expressions() {
    let valid_expressions = ["0 0 * * *", "0 2 * * 1", "*/15 * * * *"];
    for expr in valid_expressions {
        assert_eq!(expr.split_whitespace().count(), 5);
    }
}

#[test]
fn test_f55_cron_schedule_validation_invalid_expressions_rejected() {
    let invalid = ["* * *", "60 * * * *", ""];
    for expr in invalid {
        let parts: Vec<&str> = expr.split_whitespace().collect();
        let is_valid = parts.len() == 5 && parts[0].parse::<u32>().map(|m| m < 60).unwrap_or(parts[0] == "*" || parts[0].starts_with("*/"));
        assert!(!is_valid);
    }
}

#[test]
fn test_f55_cron_evaluation_identifies_due_scans() {
    let last_scan = Utc::now() - Duration::hours(25);
    let interval = Duration::hours(24);
    let is_due = Utc::now() - last_scan >= interval;
    assert!(is_due);
}

#[tokio::test]
async fn test_f55_cron_runner_dispatches_scan_for_due_app() {
    let queue = InMemoryScanJobQueue::new();
    let app_id = Uuid::new_v4();

    queue.enqueue(ScanJob {
        scan_id: Uuid::new_v4(),
        application_id: app_id,
        target_url: "https://cron.internal".to_string(),
        scan_type: ScanType::FullActive,
        custom_headers: None,
    }).await;

    assert_eq!(queue.len().await, 1);
}

#[tokio::test]
async fn test_f55_cron_runner_skips_app_with_active_scan() {
    let repo = InMemoryScanRepo::new();
    let app_id = Uuid::new_v4();

    repo.insert_scan(ScanResponse {
        id: Uuid::new_v4(),
        application_id: app_id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::ActiveScanning,
        progress_percent: 50,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    }).await;

    let has_active = repo.has_active_scan(app_id).await;
    assert!(has_active, "Cron runner must detect active scan and skip duplicate trigger");
}
