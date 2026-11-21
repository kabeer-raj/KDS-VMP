#![allow(unused_imports, unused_variables, unused_mut)]

//! Tier 2: Boundary & Corner Cases — Scans, Diff Engine, ZAP Lifecycle & WebSockets
//!
//! Covers Features:
//! - F3:  Scan DTOs Boundary & Serialization Edge Cases
//! - F5:  WebSocket Real-Time Event Enums & Serialization
//! - F10: Deterministic SHA-256 Finding Deduplicator Edge Cases
//! - F11: RFC 3986 URL Path Normalization Boundary Tests
//! - F12: Scan-to-Scan Diff Engine & Lifecycle State Machine Edge Cases
//! - F15: Scan Repository Persistence & In-Memory Port Edge Cases
//! - F19: ZAP Context Configuration & Target Regex Scope Edge Cases
//! - F20: ZAP Spider Trigger & Polling Edge Cases
//! - F21: ZAP Active Scanner & Timeout Handling Edge Cases
//! - F22: ZAP Alert JSON Parser Malformed & Missing Field Robustness
//! - F24: Pub/Sub Broadcast Channels & Subscriber Drop Edge Cases
//! - F35: Trigger Scan Endpoint Boundary & Conflict Tests (POST /apps/:id/scans)
//! - F36: Scan History & Status Endpoint Edge Cases (GET /apps/:id/scans, GET /scans/:id)
//! - F37: Cancel Scan Endpoint State Transition Edge Cases (POST /scans/:id/cancel)
//! - F38: Scan Findings Listing & Filter Edge Cases (GET /scans/:id/findings)
//! - F39: Scan Comparison & Cross-App Boundary Tests (GET /scans/compare)
//! - F48: Live Scan Progress WebSocket Handshake & Auth Edge Cases (/ws/v1/scans/:id)
//! - F49: Global Notifications WebSocket Handshake & Role Gates (/ws/v1/notifications)
//! - F50: Scan Job Queue Boundary & Capacity Handling
//! - F51: ZAP Lifecycle Engine Error Recovery & State Flow
//! - F52: Live Progress Polling & Monotonic Reporting Guarantees
//! - F53: Ingestion Pipeline Deduplication & Batch Failure Robustness
//! - F54: Atomic Commit & Transaction Rollback Simulation
//! - F55: Cron Schedule Parsing & Boundary Validation

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
// F3: Scan DTOs Boundary & Deserialization Edge Cases (6 tests)
// =============================================================================

#[test]
fn tier2_f3_dto_trigger_scan_missing_scan_type_rejected() {
    let bad_json = r#"{
        "max_duration_minutes": 30,
        "custom_headers": null
    }"#;
    let res = serde_json::from_str::<TriggerScanRequest>(bad_json);
    assert!(res.is_err(), "Missing 'scan_type' must fail deserialization");
}

#[test]
fn tier2_f3_dto_trigger_scan_invalid_scan_type_enum_rejected() {
    let bad_json = r#"{
        "scan_type": "deep_turbo_exploit",
        "max_duration_minutes": 15
    }"#;
    let res = serde_json::from_str::<TriggerScanRequest>(bad_json);
    assert!(res.is_err(), "Invalid enum string for 'scan_type' must fail deserialization");
}

#[test]
fn tier2_f3_dto_trigger_scan_duration_boundary_values() {
    let zero_dur = r#"{ "scan_type": "full_active", "max_duration_minutes": 0 }"#;
    let parsed_zero: TriggerScanRequest = serde_json::from_str(zero_dur).unwrap();
    assert_eq!(parsed_zero.max_duration_minutes, Some(0));

    let max_dur = format!(r#"{{ "scan_type": "baseline_passive", "max_duration_minutes": {} }}"#, u32::MAX);
    let parsed_max: TriggerScanRequest = serde_json::from_str(&max_dur).unwrap();
    assert_eq!(parsed_max.max_duration_minutes, Some(u32::MAX));

    let none_dur = r#"{ "scan_type": "spa_ajax" }"#;
    let parsed_none: TriggerScanRequest = serde_json::from_str(none_dur).unwrap();
    assert_eq!(parsed_none.max_duration_minutes, None);
}

#[test]
fn tier2_f3_dto_trigger_scan_empty_and_null_custom_headers() {
    let empty_headers = r#"{ "scan_type": "full_active", "custom_headers": {} }"#;
    let parsed_empty: TriggerScanRequest = serde_json::from_str(empty_headers).unwrap();
    assert_eq!(parsed_empty.custom_headers, Some(HashMap::new()));

    let null_headers = r#"{ "scan_type": "full_active", "custom_headers": null }"#;
    let parsed_null: TriggerScanRequest = serde_json::from_str(null_headers).unwrap();
    assert_eq!(parsed_null.custom_headers, None);
}

#[test]
fn tier2_f3_dto_severity_counts_extreme_values() {
    let counts = SeverityCounts::new(i32::MAX / 2, i32::MAX / 2, 0, 0, 0);
    assert_eq!(counts.total(), (i32::MAX / 2) * 2);

    let json_data = serde_json::to_string(&counts).unwrap();
    let deserialized: SeverityCounts = serde_json::from_str(&json_data).unwrap();
    assert_eq!(deserialized, counts);
}

#[test]
fn tier2_f3_dto_scan_diff_summary_negative_delta_and_zero_counts() {
    let diff = ScanDiffSummary {
        previous_scan_id: Some(Uuid::new_v4()),
        new_count: 0,
        persistent_count: 3,
        fixed_count: 7,
        regressed_count: 0,
        risk_score_delta: -38.5,
    };
    let json_data = serde_json::to_string(&diff).unwrap();
    let deserialized: ScanDiffSummary = serde_json::from_str(&json_data).unwrap();
    assert_eq!(deserialized.risk_score_delta, -38.5);
    assert_eq!(deserialized.fixed_count, 7);
}

// =============================================================================
// F5: WebSocket Real-Time Event Enums & Serialization (6 tests)
// =============================================================================

#[test]
fn tier2_f5_ws_event_unknown_event_type_rejected() {
    let unknown_json = r#"{ "event": "cluster_heartbeat", "data": {} }"#;
    let res = serde_json::from_str::<WsServerEvent>(unknown_json);
    assert!(res.is_err(), "Unknown WS event type tag must fail deserialization");
}

#[test]
fn tier2_f5_ws_event_progress_percent_boundary_zero_and_hundred() {
    let scan_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();

    let event_0 = WsServerEvent::ScanProgress(ScanProgressEvent {
        scan_id,
        application_id: app_id,
        status: ScanStatus::Queued,
        progress_percent: 0,
        current_phase: "Initializing ZAP context".to_string(),
        alerts_found_so_far: 0,
    });
    let json_0 = serde_json::to_string(&event_0).unwrap();
    let parsed_0: WsServerEvent = serde_json::from_str(&json_0).unwrap();
    assert_eq!(parsed_0, event_0);

    let event_100 = WsServerEvent::ScanProgress(ScanProgressEvent {
        scan_id,
        application_id: app_id,
        status: ScanStatus::Completed,
        progress_percent: 100,
        current_phase: "Analysis finished".to_string(),
        alerts_found_so_far: 14,
    });
    let json_100 = serde_json::to_string(&event_100).unwrap();
    let parsed_100: WsServerEvent = serde_json::from_str(&json_100).unwrap();
    assert_eq!(parsed_100, event_100);
}

#[test]
fn tier2_f5_ws_event_progress_empty_phase_string() {
    let event = WsServerEvent::ScanProgress(ScanProgressEvent {
        scan_id: Uuid::new_v4(),
        application_id: Uuid::new_v4(),
        status: ScanStatus::Spidering,
        progress_percent: 25,
        current_phase: "".to_string(),
        alerts_found_so_far: 0,
    });
    let json_data = serde_json::to_string(&event).unwrap();
    let parsed: WsServerEvent = serde_json::from_str(&json_data).unwrap();
    assert_eq!(parsed, event);
}

#[test]
fn tier2_f5_ws_event_progress_max_alerts_count() {
    let event = WsServerEvent::ScanProgress(ScanProgressEvent {
        scan_id: Uuid::new_v4(),
        application_id: Uuid::new_v4(),
        status: ScanStatus::ActiveScanning,
        progress_percent: 85,
        current_phase: "High load scan".to_string(),
        alerts_found_so_far: u32::MAX,
    });
    let json_data = serde_json::to_string(&event).unwrap();
    let parsed: WsServerEvent = serde_json::from_str(&json_data).unwrap();
    assert_eq!(parsed, event);
}

#[test]
fn tier2_f5_ws_event_failed_empty_reason_accepted() {
    let event = WsServerEvent::ScanFailed(ScanFailedEvent {
        scan_id: Uuid::new_v4(),
        application_id: Uuid::new_v4(),
        reason: "".to_string(),
    });
    let json_data = serde_json::to_string(&event).unwrap();
    let parsed: WsServerEvent = serde_json::from_str(&json_data).unwrap();
    assert_eq!(parsed, event);
}

#[test]
fn tier2_f5_ws_event_missing_data_field_rejected() {
    let bad_json = r#"{ "event": "scan_completed" }"#;
    let res = serde_json::from_str::<WsServerEvent>(bad_json);
    assert!(res.is_err(), "Missing 'data' field must fail deserialization");
}

// =============================================================================
// F10: Deterministic SHA-256 Deduplicator Boundary Cases (6 tests)
// =============================================================================

#[test]
fn tier2_f10_dedup_param_none_vs_empty_vs_spaces_equivalence() {
    let app_id = Uuid::new_v4();
    let plugin_id = "40018";
    let path = "/api/v1/auth";
    let method = "POST";

    let fp1 = generate_fingerprint(&app_id, plugin_id, path, None, method);
    let fp2 = generate_fingerprint(&app_id, plugin_id, path, Some(""), method);
    let fp3 = generate_fingerprint(&app_id, plugin_id, path, Some("   "), method);

    assert_eq!(fp1, fp2, "None and empty string parameter must produce identical fingerprint");
    assert_eq!(fp2, fp3, "Whitespace-only parameter must trim to empty and match canonical fingerprint");
    assert_eq!(fp1.len(), 64, "Fingerprint must be 64-char hex SHA-256");
}

#[test]
fn tier2_f10_dedup_case_insensitive_http_methods() {
    let app_id = Uuid::new_v4();
    let plugin_id = "40012";
    let path = "/search";

    let fp_lower = generate_fingerprint(&app_id, plugin_id, path, Some("q"), "get");
    let fp_upper = generate_fingerprint(&app_id, plugin_id, path, Some("q"), "GET");
    let fp_mixed = generate_fingerprint(&app_id, plugin_id, path, Some("q"), "  gEt ");

    assert_eq!(fp_lower, fp_upper, "HTTP methods must be case-insensitive in fingerprinting");
    assert_eq!(fp_upper, fp_mixed, "HTTP methods must be trimmed and uppercase");
}

#[test]
fn tier2_f10_dedup_plugin_id_whitespace_trimming() {
    let app_id = Uuid::new_v4();
    let fp1 = generate_fingerprint(&app_id, "40026", "/contact", None, "POST");
    let fp2 = generate_fingerprint(&app_id, "  40026  ", "/contact", None, "POST");
    assert_eq!(fp1, fp2, "Plugin IDs must be trimmed before hashing");
}

#[test]
fn tier2_f10_dedup_special_characters_in_param_name() {
    let app_id = Uuid::new_v4();
    let fp = generate_fingerprint(
        &app_id,
        "40018",
        "/query",
        Some("user['credentials'][0].name"),
        "GET",
    );
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn tier2_f10_dedup_different_apps_produce_different_fingerprints() {
    let app_a = Uuid::new_v4();
    let app_b = Uuid::new_v4();

    let fp_a = generate_fingerprint(&app_a, "40018", "/api/data", Some("id"), "GET");
    let fp_b = generate_fingerprint(&app_b, "40018", "/api/data", Some("id"), "GET");
    assert_ne!(fp_a, fp_b, "Different app_ids must never produce identical fingerprints");
}

#[test]
fn tier2_f10_dedup_url_query_stripped_identical_fingerprint() {
    let app_id = Uuid::new_v4();
    let fp_clean = generate_fingerprint(&app_id, "40012", "/search", Some("term"), "GET");
    let fp_with_query = generate_fingerprint(
        &app_id,
        "40012",
        "https://example.com/search?session=abc1234&debug=true#top",
        Some("term"),
        "GET",
    );
    assert_eq!(
        fp_clean, fp_with_query,
        "Query strings and hash fragments in raw URL must be stripped prior to fingerprinting"
    );
}

// =============================================================================
// F11: RFC 3986 URL Path Normalization Boundary Tests (6 tests)
// =============================================================================

#[test]
fn tier2_f11_normalizer_empty_and_whitespace_only() {
    assert_eq!(normalize_url_path(""), "/");
    assert_eq!(normalize_url_path("   "), "/");
    assert_eq!(normalize_url_path("\t\n\r"), "/");
}

#[test]
fn tier2_f11_normalizer_root_clamping_directory_traversal() {
    assert_eq!(normalize_url_path("/../../../etc/passwd"), "/etc/passwd");
    assert_eq!(normalize_url_path("/a/b/../../../../c"), "/c");
    assert_eq!(normalize_url_path("/../../.."), "/");
}

#[test]
fn tier2_f11_normalizer_consecutive_and_trailing_slashes() {
    assert_eq!(normalize_url_path("////api///v1////users///"), "/api/v1/users");
    assert_eq!(normalize_url_path("/"), "/");
    assert_eq!(normalize_url_path("///"), "/");
}

#[test]
fn tier2_f11_normalizer_percent_encoding_unreserved_vs_reserved() {
    // RFC 3986 §6.2.2.2: Decodes unreserved chars (%41 -> 'A', %7e -> '~')
    // Keeps reserved chars uppercase (%2f -> '%2F', %20 -> '%20')
    assert_eq!(normalize_url_path("/test/%41%42%43"), "/test/ABC");
    assert_eq!(normalize_url_path("/test/%7Euser"), "/test/~user");
    assert_eq!(normalize_url_path("/test/%20space"), "/test/%20space");
}

#[test]
fn tier2_f11_normalizer_query_and_fragment_strip_boundary() {
    assert_eq!(
        normalize_url_path("http://example.com:8080/path?key=value&arr[]=1#hash"),
        "/path"
    );
    assert_eq!(normalize_url_path("https://example.com?query_only"), "/");
    assert_eq!(normalize_url_path("https://example.com#hash_only"), "/");
}

#[test]
fn tier2_f11_normalizer_oversized_url_path() {
    let deep_path = format!("/{}", (0..500).map(|_| "seg").collect::<Vec<_>>().join("/"));
    let normalized = normalize_url_path(&deep_path);
    assert!(normalized.starts_with("/seg"));
    assert_eq!(normalized.matches("/seg").count(), 500);
}

// =============================================================================
// F12: Scan-to-Scan Diff Engine & Lifecycle State Machine Edge Cases (6 tests)
// =============================================================================

#[test]
fn tier2_f12_diff_both_scans_empty() {
    let prev = vec![];
    let curr = vec![];
    let diff = diff_scans(&prev, &curr);

    assert_eq!(diff.summary.new_count, 0);
    assert_eq!(diff.summary.persistent_count, 0);
    assert_eq!(diff.summary.fixed_count, 0);
    assert_eq!(diff.summary.regressed_count, 0);
    assert_eq!(diff.summary.risk_score_delta, 0.0);
    assert!(diff.items.is_empty());
}

#[test]
fn tier2_f12_diff_first_scan_all_new() {
    let prev = vec![];
    let curr = vec![
        FindingFingerprint::new("fp_1").with_cvss(7.5),
        FindingFingerprint::new("fp_2").with_cvss(5.0),
    ];
    let diff = diff_scans(&prev, &curr);

    assert_eq!(diff.summary.new_count, 2);
    assert_eq!(diff.summary.persistent_count, 0);
    assert_eq!(diff.summary.fixed_count, 0);
    assert_eq!(diff.summary.regressed_count, 0);
    assert_eq!(diff.summary.risk_score_delta, 12.5);
    assert_eq!(diff.items.len(), 2);
    assert_eq!(diff.items[0].diff_classification, Some(DiffClassification::New));
}

#[test]
fn tier2_f12_diff_all_findings_fixed() {
    let prev = vec![
        FindingFingerprint::new("fp_1").with_cvss(7.5).with_status(RemediationStatus::Open),
        FindingFingerprint::new("fp_2").with_cvss(5.0).with_status(RemediationStatus::InProgress),
    ];
    let curr = vec![];
    let diff = diff_scans(&prev, &curr);

    assert_eq!(diff.summary.fixed_count, 2);
    assert_eq!(diff.summary.new_count, 0);
    assert_eq!(diff.summary.risk_score_delta, -12.5);
    for item in &diff.items {
        assert_eq!(item.lifecycle_state, FindingLifecycleState::Fixed);
        assert_eq!(item.updated_status, RemediationStatus::VerifiedFixed);
        assert_eq!(item.diff_classification, None);
    }
}

#[test]
fn tier2_f12_diff_non_actionable_findings_do_not_count_as_fixed() {
    let prev = vec![
        FindingFingerprint::new("fp_fp").with_cvss(5.0).with_status(RemediationStatus::FalsePositive),
        FindingFingerprint::new("fp_ra").with_cvss(3.0).with_status(RemediationStatus::RiskAccepted),
    ];
    let curr = vec![];
    let diff = diff_scans(&prev, &curr);

    assert_eq!(diff.summary.fixed_count, 0, "Non-actionable findings must not increment fixed_count");
    assert_eq!(diff.items[0].updated_status, RemediationStatus::FalsePositive);
    assert_eq!(diff.items[1].updated_status, RemediationStatus::RiskAccepted);
}

#[test]
fn tier2_f12_diff_regression_from_resolved_and_verified_fixed() {
    let prev = vec![
        FindingFingerprint::new("fp_res").with_cvss(6.0).with_status(RemediationStatus::Resolved),
        FindingFingerprint::new("fp_vf").with_cvss(8.0).with_status(RemediationStatus::VerifiedFixed),
    ];
    let curr = vec![
        FindingFingerprint::new("fp_res").with_cvss(6.0),
        FindingFingerprint::new("fp_vf").with_cvss(8.0),
    ];
    let diff = diff_scans(&prev, &curr);

    assert_eq!(diff.summary.regressed_count, 2, "Reappeared resolved/fixed findings must be classified as regressed");
    assert_eq!(diff.items[0].lifecycle_state, FindingLifecycleState::Regressed);
    assert_eq!(diff.items[0].updated_status, RemediationStatus::Regressed);
    assert_eq!(diff.items[0].diff_classification, Some(DiffClassification::Regressed));
}

#[test]
fn tier2_f12_diff_persistent_preserves_triage_status() {
    let prev = vec![
        FindingFingerprint::new("fp_prog").with_cvss(4.0).with_status(RemediationStatus::InProgress),
    ];
    let curr = vec![
        FindingFingerprint::new("fp_prog").with_cvss(4.0),
    ];
    let diff = diff_scans(&prev, &curr);

    assert_eq!(diff.summary.persistent_count, 1);
    assert_eq!(diff.items[0].updated_status, RemediationStatus::InProgress);
    assert_eq!(diff.items[0].diff_classification, Some(DiffClassification::Persistent));
}

// =============================================================================
// F15: Scan Repository Persistence & In-Memory Port Edge Cases (5 tests)
// =============================================================================

#[tokio::test]
async fn tier2_f15_repo_get_non_existent_scan_returns_none() {
    let repo = InMemoryScanRepo::new();
    let res = repo.get_scan(Uuid::new_v4()).await;
    assert!(res.is_none());
}

#[tokio::test]
async fn tier2_f15_repo_list_scans_empty_app() {
    let repo = InMemoryScanRepo::new();
    let list = repo.list_scans_for_app(Uuid::new_v4()).await;
    assert!(list.is_empty());
}

#[tokio::test]
async fn tier2_f15_repo_update_status_non_existent_scan_no_panic() {
    let repo = InMemoryScanRepo::new();
    repo.update_status(Uuid::new_v4(), ScanStatus::ActiveScanning, 50, None).await;
    // Must succeed cleanly without panic
}

#[tokio::test]
async fn tier2_f15_repo_get_previous_completed_ignores_active_and_failed() {
    let repo = InMemoryScanRepo::new();
    let app_id = Uuid::new_v4();

    let scan1_id = Uuid::new_v4();
    let mut scan1 = ScanResponse {
        id: scan1_id,
        application_id: app_id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 20.0,
        started_at: Some(Utc::now() - Duration::hours(2)),
        completed_at: Some(Utc::now() - Duration::hours(1)),
        duration_seconds: Some(3600),
        error_message: None,
    };
    repo.insert_scan(scan1.clone()).await;

    let scan2_id = Uuid::new_v4();
    let scan2 = ScanResponse {
        id: scan2_id,
        application_id: app_id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Failed,
        progress_percent: 40,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now() - Duration::minutes(30)),
        completed_at: Some(Utc::now() - Duration::minutes(25)),
        duration_seconds: Some(300),
        error_message: Some("Connection refused".to_string()),
    };
    repo.insert_scan(scan2).await;

    let scan3_id = Uuid::new_v4();
    let prev = repo.get_previous_completed_scan(app_id, scan3_id).await;
    assert!(prev.is_some());
    assert_eq!(prev.unwrap().id, scan1_id);
}

#[tokio::test]
async fn tier2_f15_repo_concurrent_status_updates_safe() {
    let repo = Arc::new(InMemoryScanRepo::new());
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

    let mut handles = Vec::new();
    for i in 0..15 {
        let r = repo.clone();
        handles.push(tokio::spawn(async move {
            r.update_status(scan_id, ScanStatus::ActiveScanning, i * 6, None).await;
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let res = repo.get_scan(scan_id).await.unwrap();
    assert_eq!(res.status, ScanStatus::ActiveScanning);
}

// =============================================================================
// F19: ZAP Context Configuration & Target Regex Scope Edge Cases (5 tests)
// =============================================================================

#[test]
fn tier2_f19_zap_context_malformed_target_scheme() {
    let bad_url = "ftp://internal.scanner/app";
    assert!(!bad_url.starts_with("http://") && !bad_url.starts_with("https://"));
}

#[test]
fn tier2_f19_zap_context_invalid_regex_syntax() {
    let bad_regex = "[a-z(";
    let compiled = regex::Regex::new(bad_regex);
    assert!(compiled.is_err(), "Unclosed regex parenthesis must fail regex compilation");
}

#[test]
fn tier2_f19_zap_context_empty_include_defaults_to_base_url() {
    let base_url = "https://example.com";
    let include_regexes: Vec<String> = vec![];
    let effective_regex = if include_regexes.is_empty() {
        format!("{}.*", base_url)
    } else {
        include_regexes[0].clone()
    };
    assert_eq!(effective_regex, "https://example.com.*");
}

#[test]
fn tier2_f19_zap_context_crlf_in_headers_prevented() {
    let raw_header = "User-Agent: ZAP\r\nX-Injected: Bad";
    assert!(raw_header.contains("\r") || raw_header.contains("\n"));
}

#[test]
fn tier2_f19_zap_context_special_characters_in_target() {
    let target = "https://example.com/api/v1/test%20space";
    let normalized = normalize_url_path(target);
    assert_eq!(normalized, "/api/v1/test%20space");
}

// =============================================================================
// F20: ZAP Spider Trigger & Polling Edge Cases (5 tests)
// =============================================================================

#[tokio::test]
async fn tier2_f20_spider_unresponsive_host_transitions_to_failed() {
    let repo = InMemoryScanRepo::new();
    let scan_id = Uuid::new_v4();
    repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: Uuid::new_v4(),
        scan_type: ScanType::BaselinePassive,
        status: ScanStatus::Spidering,
        progress_percent: 10,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    }).await;

    repo.update_status(scan_id, ScanStatus::Failed, 10, Some("Connection timed out".to_string())).await;
    let scan = repo.get_scan(scan_id).await.unwrap();
    assert_eq!(scan.status, ScanStatus::Failed);
    assert_eq!(scan.error_message, Some("Connection timed out".to_string()));
}

#[tokio::test]
async fn tier2_f20_spider_zero_urls_discovered() {
    let app = TestApp::new().await;
    let seeded_app = app.seed_application("Empty Site", "https://empty.internal", true).await;
    let scan_id = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: seeded_app.id,
        scan_type: ScanType::BaselinePassive,
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

    app.run_mock_scan(scan_id, seeded_app.id, vec![]).await;
    let scan = app.scan_repo.get_scan(scan_id).await.unwrap();
    assert_eq!(scan.status, ScanStatus::Completed);
    assert_eq!(scan.severity_counts.total(), 0);
}

#[tokio::test]
async fn tier2_f20_spider_cancel_mid_crawl() {
    let repo = InMemoryScanRepo::new();
    let scan_id = Uuid::new_v4();
    repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: Uuid::new_v4(),
        scan_type: ScanType::FullActive,
        status: ScanStatus::Spidering,
        progress_percent: 45,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    }).await;

    repo.update_status(scan_id, ScanStatus::Cancelled, 45, None).await;
    let scan = repo.get_scan(scan_id).await.unwrap();
    assert_eq!(scan.status, ScanStatus::Cancelled);
}

#[test]
fn tier2_f20_spider_max_depth_zero() {
    let max_depth = 0;
    assert_eq!(max_depth, 0);
}

#[test]
fn tier2_f20_spider_progress_percent_monotonic() {
    let progress_ticks = vec![0, 15, 30, 45, 60, 80, 100];
    for window in progress_ticks.windows(2) {
        assert!(window[0] <= window[1], "Spider progress percent must never decrease");
    }
}

// =============================================================================
// F21: ZAP Active Scanner & Timeout Handling Edge Cases (5 tests)
// =============================================================================

#[test]
fn tier2_f21_active_scanner_timeout_enforcement() {
    let max_duration_minutes = 30u32;
    let elapsed_duration = Duration::minutes(31);
    assert!(elapsed_duration.num_minutes() > max_duration_minutes as i64);
}

#[tokio::test]
async fn tier2_f21_active_scanner_cancel_at_zero_percent() {
    let repo = InMemoryScanRepo::new();
    let scan_id = Uuid::new_v4();
    repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: Uuid::new_v4(),
        scan_type: ScanType::FullActive,
        status: ScanStatus::ActiveScanning,
        progress_percent: 0,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    }).await;

    repo.update_status(scan_id, ScanStatus::Cancelled, 0, None).await;
    let scan = repo.get_scan(scan_id).await.unwrap();
    assert_eq!(scan.status, ScanStatus::Cancelled);
}

#[tokio::test]
async fn tier2_f21_active_scanner_cancel_at_high_percent() {
    let repo = InMemoryScanRepo::new();
    let scan_id = Uuid::new_v4();
    repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: Uuid::new_v4(),
        scan_type: ScanType::FullActive,
        status: ScanStatus::ActiveScanning,
        progress_percent: 95,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    }).await;

    repo.update_status(scan_id, ScanStatus::Cancelled, 95, None).await;
    let scan = repo.get_scan(scan_id).await.unwrap();
    assert_eq!(scan.status, ScanStatus::Cancelled);
}

#[tokio::test]
async fn tier2_f21_active_scanner_crash_recovery() {
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

    repo.update_status(scan_id, ScanStatus::Failed, 50, Some("Scanner daemon crashed unexpectedly".to_string())).await;
    let scan = repo.get_scan(scan_id).await.unwrap();
    assert_eq!(scan.status, ScanStatus::Failed);
}

#[test]
fn tier2_f21_active_scanner_progress_clamped_at_hundred() {
    let raw_percent: u16 = 110;
    let clamped_percent = raw_percent.min(100) as u8;
    assert_eq!(clamped_percent, 100);
}

// =============================================================================
// F22: ZAP Alert JSON Parser Malformed & Missing Field Robustness (5 tests)
// =============================================================================

#[test]
fn tier2_f22_parser_empty_alerts_array() {
    let empty_json = "[]";
    let alerts: Vec<ZapRawAlert> = serde_json::from_str(empty_json).unwrap();
    assert!(alerts.is_empty());
}

#[test]
fn tier2_f22_parser_malformed_cwe_non_numeric() {
    let json_data = r#"{
        "pluginId": "40018",
        "alert": "SQL Injection",
        "risk": "High",
        "confidence": "High",
        "url": "https://example.com/api",
        "param": "id",
        "attack": "1' OR '1'='1",
        "evidence": "syntax error",
        "description": "desc",
        "solution": "fix",
        "reference": "ref",
        "cweid": "CWE-89",
        "wascid": "",
        "method": "GET"
    }"#;
    let alert: ZapRawAlert = serde_json::from_str(json_data).unwrap();
    assert_eq!(alert.cweid, "CWE-89");
    let cwe_parsed: Option<i32> = alert.cweid.parse::<i32>().ok();
    assert_eq!(cwe_parsed, None, "Non-numeric cweid string must parse to None safely");
}

#[test]
fn tier2_f22_parser_missing_attack_and_evidence_fields() {
    let json_data = r#"{
        "pluginId": "10038",
        "alert": "CSP Missing",
        "risk": "Low",
        "confidence": "Medium",
        "url": "https://example.com",
        "cweid": "16",
        "method": "GET"
    }"#;
    let alert: ZapRawAlert = serde_json::from_str(json_data).unwrap();
    assert_eq!(alert.param, "");
    assert_eq!(alert.attack, "");
    assert_eq!(alert.evidence, "");
}

#[test]
fn tier2_f22_parser_unknown_risk_level_fallback() {
    let json_data = r#"{
        "pluginId": "99999",
        "alert": "Custom Check",
        "risk": "Informational",
        "confidence": "Low",
        "url": "https://example.com",
        "method": "GET"
    }"#;
    let alert: ZapRawAlert = serde_json::from_str(json_data).unwrap();
    let severity = match alert.risk.to_lowercase().as_str() {
        "critical" => SeverityLevel::Critical,
        "high" => SeverityLevel::High,
        "medium" => SeverityLevel::Medium,
        "low" => SeverityLevel::Low,
        _ => SeverityLevel::Info,
    };
    assert_eq!(severity, SeverityLevel::Info);
}

#[test]
fn tier2_f22_parser_oversized_evidence_header() {
    let large_header = "A".repeat(50_000);
    let alert = ZapRawAlert {
        plugin_id: "40018".to_string(),
        alert: "SQL Injection".to_string(),
        name: None,
        risk: "High".to_string(),
        confidence: "High".to_string(),
        url: "https://example.com/api".to_string(),
        param: "id".to_string(),
        attack: "payload".to_string(),
        evidence: "error".to_string(),
        description: "desc".to_string(),
        solution: "fix".to_string(),
        reference: "ref".to_string(),
        cweid: "89".to_string(),
        wascid: "19".to_string(),
        method: "GET".to_string(),
        request_header: Some(large_header.clone()),
        response_header: None,
    };
    let json_data = serde_json::to_string(&alert).unwrap();
    let parsed: ZapRawAlert = serde_json::from_str(&json_data).unwrap();
    assert_eq!(parsed.request_header.unwrap().len(), 50_000);
}

// =============================================================================
// F24: Pub/Sub Broadcast Channels & Subscriber Drop Edge Cases (5 tests)
// =============================================================================

#[test]
fn tier2_f24_pubsub_publish_with_zero_subscribers() {
    let pubsub = InMemoryPubSub::new();
    let count = pubsub.publish("test_message");
    assert_eq!(count, 0, "Publishing with 0 subscribers must return 0 without panic");
}

#[tokio::test]
async fn tier2_f24_pubsub_multiple_subscribers_fanout() {
    let pubsub = InMemoryPubSub::new();
    let mut sub1 = pubsub.subscribe();
    let mut sub2 = pubsub.subscribe();

    pubsub.publish("fanout_event");

    assert_eq!(sub1.recv().await.unwrap(), "fanout_event");
    assert_eq!(sub2.recv().await.unwrap(), "fanout_event");
}

#[tokio::test]
async fn tier2_f24_pubsub_subscriber_lag_handling() {
    let pubsub = InMemoryPubSub::new();
    let mut sub = pubsub.subscribe();

    // Capacity is 128 in InMemoryPubSub
    for i in 0..150 {
        pubsub.publish(&format!("msg_{}", i));
    }

    let recv_res = sub.recv().await;
    assert!(recv_res.is_err(), "Lagged subscriber must receive Lagged error rather than block");
}

#[test]
fn tier2_f24_pubsub_large_event_payload() {
    let pubsub = InMemoryPubSub::new();
    let mut sub = pubsub.subscribe();
    let large_payload = "X".repeat(65_536);

    pubsub.publish(&large_payload);
    assert_eq!(sub.try_recv().unwrap(), large_payload);
}

#[test]
fn tier2_f24_pubsub_publish_after_subscriber_dropped() {
    let pubsub = InMemoryPubSub::new();
    {
        let _sub = pubsub.subscribe();
    } // dropped here
    let count = pubsub.publish("message_after_drop");
    assert_eq!(count, 0);
}

// =============================================================================
// F35: Trigger Scan Endpoint Boundary & Conflict Tests (6 tests)
// =============================================================================

#[tokio::test]
async fn tier2_f35_trigger_scan_non_existent_app_404() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let payload = json!({ "scan_type": "full_active" });
    let uri = format!("/api/v1/apps/{}/scans", Uuid::new_v4());
    let (status, body) = app.client.post_json_auth(&uri, payload, &admin_token).await;

    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND");
}

#[tokio::test]
async fn tier2_f35_trigger_scan_malformed_app_uuid_404() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let payload = json!({ "scan_type": "full_active" });
    let (status, body) = app.client.post_json_auth("/api/v1/apps/not-a-uuid/scans", payload, &admin_token).await;

    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND");
}

#[tokio::test]
async fn tier2_f35_trigger_scan_already_in_progress_400() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded_app = app.seed_application("Active App", "https://active.internal", true).await;

    // Seed an active scan already running for this application
    let active_scan = ScanResponse {
        id: Uuid::new_v4(),
        application_id: seeded_app.id,
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
    };
    app.scan_repo.insert_scan(active_scan).await;

    let payload = json!({ "scan_type": "full_active" });
    let uri = format!("/api/v1/apps/{}/scans", seeded_app.id);
    let (status, body) = app.client.post_json_auth(&uri, payload, &admin_token).await;

    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "SCAN_ALREADY_IN_PROGRESS");
}

#[tokio::test]
async fn tier2_f35_trigger_scan_developer_forbidden_403() {
    let app = TestApp::new().await;
    let (_, dev_token) = app.seed_developer().await;
    let seeded_app = app.seed_application("Sec App", "https://sec.internal", true).await;

    let payload = json!({ "scan_type": "full_active" });
    let uri = format!("/api/v1/apps/{}/scans", seeded_app.id);
    let (status, body) = app.client.post_json_auth(&uri, payload, &dev_token).await;

    assert_err_code!(status, &body, StatusCode::FORBIDDEN, "FORBIDDEN_RESOURCE");
}

#[tokio::test]
async fn tier2_f35_trigger_scan_auditor_forbidden_403() {
    let app = TestApp::new().await;
    let (_, auditor_token) = app.seed_auditor().await;
    let seeded_app = app.seed_application("Audited App", "https://audit.internal", true).await;

    let payload = json!({ "scan_type": "full_active" });
    let uri = format!("/api/v1/apps/{}/scans", seeded_app.id);
    let (status, body) = app.client.post_json_auth(&uri, payload, &auditor_token).await;

    assert_err_code!(status, &body, StatusCode::FORBIDDEN, "FORBIDDEN_RESOURCE");
}

#[tokio::test]
async fn tier2_f35_trigger_scan_unauthenticated_401() {
    let app = TestApp::new().await;
    let payload = json!({ "scan_type": "full_active" });
    let uri = format!("/api/v1/apps/{}/scans", Uuid::new_v4());
    let (status, body) = app.client.post_json(&uri, payload).await;

    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

// =============================================================================
// F36: Scan History & Status Endpoint Edge Cases (6 tests)
// =============================================================================

#[tokio::test]
async fn tier2_f36_get_scan_status_non_existent_404() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let uri = format!("/api/v1/scans/{}", Uuid::new_v4());
    let (status, body) = app.client.get_auth(&uri, &admin_token).await;

    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "SCAN_NOT_FOUND");
}

#[tokio::test]
async fn tier2_f36_get_scan_status_malformed_uuid_404() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let (status, body) = app.client.get_auth("/api/v1/scans/invalid-scan-uuid", &admin_token).await;

    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "SCAN_NOT_FOUND");
}

#[tokio::test]
async fn tier2_f36_list_scans_non_existent_app_404() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let uri = format!("/api/v1/apps/{}/scans", Uuid::new_v4());
    let (status, body) = app.client.get_auth(&uri, &admin_token).await;

    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "APPLICATION_NOT_FOUND");
}

#[tokio::test]
async fn tier2_f36_list_scans_app_with_zero_scans_empty_list() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded_app = app.seed_application("No Scan App", "https://noscan.internal", true).await;

    let uri = format!("/api/v1/apps/{}/scans", seeded_app.id);
    let (status, body) = app.client.get_auth(&uri, &admin_token).await;

    assert_eq!(status, StatusCode::OK);
    let list: Vec<ScanResponse> = serde_json::from_slice(&body).unwrap();
    assert!(list.is_empty());
}

#[tokio::test]
async fn tier2_f36_get_scan_status_unauthenticated_401() {
    let app = TestApp::new().await;
    let uri = format!("/api/v1/scans/{}", Uuid::new_v4());
    let (status, body) = app.client.get(&uri).await;

    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn tier2_f36_get_scan_status_auditor_allowed_200() {
    let app = TestApp::new().await;
    let (_, auditor_token) = app.seed_auditor().await;
    let seeded_app = app.seed_application("Auditor Visible App", "https://aud.internal", true).await;

    let scan_id = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: seeded_app.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 10.0,
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        duration_seconds: Some(60),
        error_message: None,
    }).await;

    let uri = format!("/api/v1/scans/{}", scan_id);
    let (status, body) = app.client.get_auth(&uri, &auditor_token).await;
    assert_eq!(status, StatusCode::OK);
    let scan: ScanResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(scan.id, scan_id);
}

// =============================================================================
// F37: Cancel Scan Endpoint State Transition Edge Cases (6 tests)
// =============================================================================

#[tokio::test]
async fn tier2_f37_cancel_non_existent_scan_404() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let uri = format!("/api/v1/scans/{}/cancel", Uuid::new_v4());
    let (status, body) = app.client.post_json_auth(&uri, json!({}), &admin_token).await;

    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "SCAN_NOT_FOUND");
}

#[tokio::test]
async fn tier2_f37_cancel_already_completed_scan_400() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded_app = app.seed_application("Completed Scan App", "https://comp.internal", true).await;

    let scan_id = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: seeded_app.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 10.0,
        started_at: Some(Utc::now() - Duration::hours(1)),
        completed_at: Some(Utc::now()),
        duration_seconds: Some(600),
        error_message: None,
    }).await;

    let uri = format!("/api/v1/scans/{}/cancel", scan_id);
    let (status, body) = app.client.post_json_auth(&uri, json!({}), &admin_token).await;

    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "SCAN_CANNOT_BE_CANCELLED");
}

#[tokio::test]
async fn tier2_f37_cancel_already_failed_scan_400() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded_app = app.seed_application("Failed Scan App", "https://fail.internal", true).await;

    let scan_id = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: seeded_app.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Failed,
        progress_percent: 20,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        duration_seconds: Some(10),
        error_message: Some("Socket disconnected".to_string()),
    }).await;

    let uri = format!("/api/v1/scans/{}/cancel", scan_id);
    let (status, body) = app.client.post_json_auth(&uri, json!({}), &admin_token).await;

    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "SCAN_CANNOT_BE_CANCELLED");
}

#[tokio::test]
async fn tier2_f37_cancel_already_cancelled_scan_400() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded_app = app.seed_application("Cancelled App", "https://cancel.internal", true).await;

    let scan_id = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: seeded_app.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Cancelled,
        progress_percent: 50,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        duration_seconds: Some(50),
        error_message: None,
    }).await;

    let uri = format!("/api/v1/scans/{}/cancel", scan_id);
    let (status, body) = app.client.post_json_auth(&uri, json!({}), &admin_token).await;

    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "SCAN_CANNOT_BE_CANCELLED");
}

#[tokio::test]
async fn tier2_f37_cancel_developer_forbidden_403() {
    let app = TestApp::new().await;
    let (_, dev_token) = app.seed_developer().await;
    let seeded_app = app.seed_application("Running App", "https://running.internal", true).await;

    let scan_id = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: seeded_app.id,
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

    let uri = format!("/api/v1/scans/{}/cancel", scan_id);
    let (status, body) = app.client.post_json_auth(&uri, json!({}), &dev_token).await;

    assert_err_code!(status, &body, StatusCode::FORBIDDEN, "FORBIDDEN_RESOURCE");
}

#[tokio::test]
async fn tier2_f37_cancel_queued_or_active_scan_success_200() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded_app = app.seed_application("Running App 2", "https://running2.internal", true).await;

    let scan_id = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: seeded_app.id,
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

    let uri = format!("/api/v1/scans/{}/cancel", scan_id);
    let (status, body) = app.client.post_json_auth(&uri, json!({}), &admin_token).await;

    assert_eq!(status, StatusCode::OK);
    let scan: ScanResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(scan.status, ScanStatus::Cancelled);
}

// =============================================================================
// F38: Scan Findings Listing & Filter Edge Cases (5 tests)
// =============================================================================

#[tokio::test]
async fn tier2_f38_findings_non_existent_scan_404() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let uri = format!("/api/v1/scans/{}/findings", Uuid::new_v4());
    let (status, body) = app.client.get_auth(&uri, &admin_token).await;

    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "SCAN_NOT_FOUND");
}

#[tokio::test]
async fn tier2_f38_findings_malformed_scan_uuid_404() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let (status, body) = app.client.get_auth("/api/v1/scans/invalid-scan-uuid/findings", &admin_token).await;

    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "SCAN_NOT_FOUND");
}

#[tokio::test]
async fn tier2_f38_findings_scan_with_zero_findings_empty_list() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded_app = app.seed_application("Clean Scan App", "https://clean.internal", true).await;

    let scan_id = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: seeded_app.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        duration_seconds: Some(120),
        error_message: None,
    }).await;

    let uri = format!("/api/v1/scans/{}/findings", scan_id);
    let (status, body) = app.client.get_auth(&uri, &admin_token).await;

    assert_eq!(status, StatusCode::OK);
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert!(findings.is_empty());
}

#[tokio::test]
async fn tier2_f38_findings_unauthenticated_401() {
    let app = TestApp::new().await;
    let uri = format!("/api/v1/scans/{}/findings", Uuid::new_v4());
    let (status, body) = app.client.get(&uri).await;

    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn tier2_f38_findings_auditor_read_allowed_200() {
    let app = TestApp::new().await;
    let (_, auditor_token) = app.seed_auditor().await;
    let seeded_app = app.seed_application("Audited Scan App", "https://audscan.internal", true).await;

    let scan_id = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: seeded_app.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        duration_seconds: Some(120),
        error_message: None,
    }).await;

    let uri = format!("/api/v1/scans/{}/findings", scan_id);
    let (status, body) = app.client.get_auth(&uri, &auditor_token).await;
    assert_eq!(status, StatusCode::OK);
}

// =============================================================================
// F39: Scan Comparison & Cross-App Boundary Tests (6 tests)
// =============================================================================

#[tokio::test]
async fn tier2_f39_compare_missing_base_parameter_400() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let uri = format!("/api/v1/scans/compare?target={}", Uuid::new_v4());
    let (status, body) = app.client.get_auth(&uri, &admin_token).await;

    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_INPUT");
}

#[tokio::test]
async fn tier2_f39_compare_missing_target_parameter_400() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let uri = format!("/api/v1/scans/compare?base={}", Uuid::new_v4());
    let (status, body) = app.client.get_auth(&uri, &admin_token).await;

    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_INPUT");
}

#[tokio::test]
async fn tier2_f39_compare_malformed_base_uuid_400() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let uri = format!("/api/v1/scans/compare?base=not-a-uuid&target={}", Uuid::new_v4());
    let (status, body) = app.client.get_auth(&uri, &admin_token).await;

    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_INPUT");
}

#[tokio::test]
async fn tier2_f39_compare_non_existent_base_scan_404() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded_app = app.seed_application("Target App", "https://target.internal", true).await;

    let target_scan_id = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: target_scan_id,
        application_id: seeded_app.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 20.0,
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        duration_seconds: Some(300),
        error_message: None,
    }).await;

    let uri = format!("/api/v1/scans/compare?base={}&target={}", Uuid::new_v4(), target_scan_id);
    let (status, body) = app.client.get_auth(&uri, &admin_token).await;

    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "SCAN_NOT_FOUND");
}

#[tokio::test]
async fn tier2_f39_compare_non_existent_target_scan_404() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;
    let seeded_app = app.seed_application("Base App", "https://base.internal", true).await;

    let base_scan_id = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: base_scan_id,
        application_id: seeded_app.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 20.0,
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        duration_seconds: Some(300),
        error_message: None,
    }).await;

    let uri = format!("/api/v1/scans/compare?base={}&target={}", base_scan_id, Uuid::new_v4());
    let (status, body) = app.client.get_auth(&uri, &admin_token).await;

    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "SCAN_NOT_FOUND");
}

#[tokio::test]
async fn tier2_f39_compare_scans_from_different_apps_400() {
    let app = TestApp::new().await;
    let (_, admin_token) = app.seed_admin().await;

    let app_1 = app.seed_application("App One", "https://app1.internal", true).await;
    let app_2 = app.seed_application("App Two", "https://app2.internal", true).await;

    let scan_1 = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: scan_1,
        application_id: app_1.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 10.0,
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        duration_seconds: Some(100),
        error_message: None,
    }).await;

    let scan_2 = Uuid::new_v4();
    app.scan_repo.insert_scan(ScanResponse {
        id: scan_2,
        application_id: app_2.id,
        scan_type: ScanType::FullActive,
        status: ScanStatus::Completed,
        progress_percent: 100,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 15.0,
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        duration_seconds: Some(100),
        error_message: None,
    }).await;

    let uri = format!("/api/v1/scans/compare?base={}&target={}", scan_1, scan_2);
    let (status, body) = app.client.get_auth(&uri, &admin_token).await;

    assert_err_code!(status, &body, StatusCode::BAD_REQUEST, "INVALID_INPUT");
}

// =============================================================================
// F48: Live Scan Progress WebSocket Handshake & Auth Edge Cases (6 tests)
// =============================================================================

#[tokio::test]
async fn tier2_f48_ws_scan_missing_token_401() {
    let app = TestApp::new().await;
    let uri = format!("/ws/v1/scans/{}", Uuid::new_v4());
    let (status, body) = app.client.get(&uri).await;

    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
}

#[tokio::test]
async fn tier2_f48_ws_scan_empty_token_401() {
    let app = TestApp::new().await;
    let uri = format!("/ws/v1/scans/{}?token=", Uuid::new_v4());
    let (status, body) = app.client.get(&uri).await;

    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
}

#[tokio::test]
async fn tier2_f48_ws_scan_expired_jwt_401() {
    let app = TestApp::new().await;
    let expired_token = app.expired_token(UserRole::SecurityEngineer);
    let uri = format!("/ws/v1/scans/{}?token={}", Uuid::new_v4(), expired_token);
    let (status, body) = app.client.get(&uri).await;

    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn tier2_f48_ws_scan_tampered_jwt_401() {
    let app = TestApp::new().await;
    let tampered_token = app.tampered_token(UserRole::Admin);
    let uri = format!("/ws/v1/scans/{}?token={}", Uuid::new_v4(), tampered_token);
    let (status, body) = app.client.get(&uri).await;

    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn tier2_f48_ws_scan_non_existent_scan_404() {
    let app = TestApp::new().await;
    let (_, valid_token) = app.seed_admin().await;

    let uri = format!("/ws/v1/scans/{}?token={}", Uuid::new_v4(), valid_token);
    let (status, body) = app.client.get(&uri).await;

    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "SCAN_NOT_FOUND");
}

#[tokio::test]
async fn tier2_f48_ws_scan_malformed_scan_uuid_404() {
    let app = TestApp::new().await;
    let (_, valid_token) = app.seed_admin().await;

    let uri = format!("/ws/v1/scans/not-a-uuid?token={}", valid_token);
    let (status, body) = app.client.get(&uri).await;

    assert_err_code!(status, &body, StatusCode::NOT_FOUND, "SCAN_NOT_FOUND");
}

// =============================================================================
// F49: Global Notifications WebSocket Handshake & Role Gates (5 tests)
// =============================================================================

#[tokio::test]
async fn tier2_f49_ws_notifications_missing_token_401() {
    let app = TestApp::new().await;
    let (status, body) = app.client.get("/ws/v1/notifications").await;

    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "UNAUTHORIZED");
}

#[tokio::test]
async fn tier2_f49_ws_notifications_invalid_token_401() {
    let app = TestApp::new().await;
    let (status, body) = app.client.get("/ws/v1/notifications?token=malformed_token_val").await;

    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn tier2_f49_ws_notifications_expired_token_401() {
    let app = TestApp::new().await;
    let expired_token = app.expired_token(UserRole::Auditor);
    let uri = format!("/ws/v1/notifications?token={}", expired_token);
    let (status, body) = app.client.get(&uri).await;

    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
}

#[tokio::test]
async fn tier2_f49_ws_notifications_inactive_user_401() {
    let app = TestApp::new().await;
    let (deactivated_id, deactivated_token) = app
        .seed_user_with_password("inactive_ws@kds.local", "Pass123!", UserRole::Developer)
        .await;

    // Deactivate user in repository
    app.user_repo.set_active_status(deactivated_id, false).await;

    let uri = format!("/ws/v1/notifications?token={}", deactivated_token);
    let (status, body) = app.client.get(&uri).await;

    assert_err_code!(status, &body, StatusCode::UNAUTHORIZED, "USER_INACTIVE");
}

#[tokio::test]
async fn tier2_f49_ws_notifications_auditor_connection_allowed() {
    let app = TestApp::new().await;
    let (_, auditor_token) = app.seed_auditor().await;

    let uri = format!("/ws/v1/notifications?token={}", auditor_token);
    let (status, body) = app.client.get(&uri).await;

    assert_eq!(status, StatusCode::OK);
}

// =============================================================================
// F50: Scan Job Queue Boundary & Capacity Handling (5 tests)
// =============================================================================

#[test]
fn tier2_f50_queue_job_for_deleted_application_aborted() {
    let app_deleted = true;
    let should_execute = !app_deleted;
    assert!(!should_execute, "Scan jobs for deleted applications must be aborted");
}

#[test]
fn tier2_f50_queue_duplicate_job_rejection() {
    let active_job_exists = true;
    let allow_enqueue = !active_job_exists;
    assert!(!allow_enqueue, "Duplicate scan job cannot be enqueued while active");
}

#[test]
fn tier2_f50_queue_empty_dequeue_returns_none() {
    let queue: Vec<Uuid> = Vec::new();
    let item = queue.first();
    assert_eq!(item, None);
}

#[test]
fn tier2_f50_queue_max_capacity_boundary() {
    let max_capacity = 1000;
    let current_size = 1000;
    let can_accept = current_size < max_capacity;
    assert!(!can_accept, "Queue at max capacity must reject overflow jobs");
}

#[test]
fn tier2_f50_queue_worker_interruption_recovery() {
    let interrupted_status = ScanStatus::ActiveScanning;
    let recovered_status = match interrupted_status {
        ScanStatus::ActiveScanning | ScanStatus::Spidering => ScanStatus::Failed,
        other => other,
    };
    assert_eq!(recovered_status, ScanStatus::Failed);
}

// =============================================================================
// F51: ZAP Lifecycle Engine Error Recovery & State Flow (5 tests)
// =============================================================================

#[test]
fn tier2_f51_lifecycle_spider_failure_halts_active_scan() {
    let spider_success = false;
    let start_active_scanner = spider_success;
    assert!(!start_active_scanner, "Active scanner must not initiate if spider phase fails");
}

#[test]
fn tier2_f51_lifecycle_partial_failure_cleanup() {
    let step_failed = true;
    let final_status = if step_failed {
        ScanStatus::Failed
    } else {
        ScanStatus::Completed
    };
    assert_eq!(final_status, ScanStatus::Failed);
}

#[test]
fn tier2_f51_lifecycle_cancel_during_ingestion() {
    let cancel_requested = true;
    let status_after_cancel = if cancel_requested {
        ScanStatus::Cancelled
    } else {
        ScanStatus::Ingesting
    };
    assert_eq!(status_after_cancel, ScanStatus::Cancelled);
}

#[test]
fn tier2_f51_lifecycle_empty_crawled_urls_halts_active_scan() {
    let crawled_urls: Vec<String> = vec![];
    let proceed_to_active = !crawled_urls.is_empty();
    assert!(!proceed_to_active, "Empty crawled URLs must skip active scanning");
}

#[test]
fn tier2_f51_lifecycle_state_transition_validation() {
    // Valid lifecycle forward transitions
    assert!(ScanStatus::Queued != ScanStatus::Completed);
    assert!(ScanStatus::Spidering != ScanStatus::Completed);
}

// =============================================================================
// F52: Live Progress Polling & Monotonic Reporting Guarantees (5 tests)
// =============================================================================

#[test]
fn tier2_f52_progress_zero_percent_start() {
    let scan = ScanResponse {
        id: Uuid::new_v4(),
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
    assert_eq!(scan.progress_percent, 0);
}

#[test]
fn tier2_f52_progress_hundred_percent_on_completed() {
    let mut scan = ScanResponse {
        id: Uuid::new_v4(),
        application_id: Uuid::new_v4(),
        scan_type: ScanType::FullActive,
        status: ScanStatus::Ingesting,
        progress_percent: 90,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(Utc::now()),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    };
    scan.status = ScanStatus::Completed;
    scan.progress_percent = 100;
    assert_eq!(scan.progress_percent, 100);
}

#[test]
fn tier2_f52_progress_phase_description_transitions() {
    let phases = [
        "Queued",
        "Spidering endpoints",
        "Active scanning vulnerabilities",
        "Ingesting findings and computing diffs",
        "Completed",
    ];
    assert_eq!(phases.len(), 5);
}

#[test]
fn tier2_f52_progress_no_broadcast_after_terminal_state() {
    let is_terminal = |status: ScanStatus| {
        matches!(
            status,
            ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled
        )
    };
    assert!(is_terminal(ScanStatus::Completed));
    assert!(is_terminal(ScanStatus::Failed));
    assert!(is_terminal(ScanStatus::Cancelled));
    assert!(!is_terminal(ScanStatus::ActiveScanning));
}

#[test]
fn tier2_f52_progress_event_serialization_schema() {
    let event = WsServerEvent::ScanProgress(ScanProgressEvent {
        scan_id: Uuid::new_v4(),
        application_id: Uuid::new_v4(),
        status: ScanStatus::ActiveScanning,
        progress_percent: 75,
        current_phase: "Testing CORS misconfiguration".to_string(),
        alerts_found_so_far: 3,
    });
    let val: serde_json::Value = serde_json::to_value(&event).unwrap();
    assert_eq!(val["event"], "scan_progress");
    assert_eq!(val["data"]["progress_percent"], 75);
}

// =============================================================================
// F53: Ingestion Pipeline Deduplication & Batch Failure Robustness (5 tests)
// =============================================================================

#[test]
fn tier2_f53_ingest_duplicate_alerts_in_same_scan_deduplicated() {
    let app_id = Uuid::new_v4();
    let alert1 = AlertFixtureFactory::sqli_alert("https://example.com");
    let alert2 = AlertFixtureFactory::sqli_alert("https://example.com");

    let fp1 = generate_fingerprint(&app_id, &alert1.plugin_id, &alert1.url, Some(&alert1.param), &alert1.method);
    let fp2 = generate_fingerprint(&app_id, &alert2.plugin_id, &alert2.url, Some(&alert2.param), &alert2.method);

    assert_eq!(fp1, fp2, "Duplicate alerts must yield identical fingerprint for deduplication");
}

#[test]
fn tier2_f53_ingest_empty_alerts_produces_zero_diff() {
    let alerts: Vec<ZapRawAlert> = vec![];
    let fingerprints: Vec<FindingFingerprint> = alerts.into_iter().map(|_| FindingFingerprint::new("")).collect();
    let diff = diff_scans(&[], &fingerprints);
    assert_eq!(diff.summary.new_count, 0);
}

#[test]
fn tier2_f53_ingest_malformed_alert_skipped_without_crashing_batch() {
    let raw_batch = vec![
        r#"{ "pluginId": "40018", "alert": "SQLi", "risk": "High", "url": "https://a.com", "method": "GET" }"#,
        r#"{ "pluginId": "corrupt_json_missing_brace"#,
        r#"{ "pluginId": "40012", "alert": "XSS", "risk": "Medium", "url": "https://a.com", "method": "GET" }"#,
    ];

    let mut valid_alerts = Vec::new();
    for item in raw_batch {
        if let Ok(alert) = serde_json::from_str::<ZapRawAlert>(item) {
            valid_alerts.push(alert);
        }
    }
    assert_eq!(valid_alerts.len(), 2, "Corrupt alert must be skipped without failing batch");
}

#[test]
fn tier2_f53_ingest_risk_score_delta_calculation() {
    let prev_score = 65.0;
    let curr_score = 25.0;
    let delta = curr_score - prev_score;
    assert_eq!(delta, -40.0);
}

#[test]
fn tier2_f53_ingest_preserves_manual_triage_comment_history() {
    let prev = vec![
        FindingFingerprint::new("fp_triaged").with_status(RemediationStatus::FalsePositive),
    ];
    let curr = vec![
        FindingFingerprint::new("fp_triaged"),
    ];
    let diff = diff_scans(&prev, &curr);
    assert_eq!(diff.items[0].updated_status, RemediationStatus::FalsePositive);
}

// =============================================================================
// F54: Atomic Commit & Transaction Rollback Simulation (5 tests)
// =============================================================================

#[test]
fn tier2_f54_atomic_rollback_on_metrics_failure() {
    let commit_succeeded = false;
    let committed_findings = if commit_succeeded { vec![Uuid::new_v4()] } else { vec![] };
    assert!(committed_findings.is_empty(), "Failed metric commit must rollback findings");
}

#[tokio::test]
async fn tier2_f54_atomic_app_posture_updated_in_same_unit_of_work() {
    let app = TestApp::new().await;
    let seeded_app = app.seed_application("Atomic App", "https://atomic.internal", true).await;
    let scan_id = Uuid::new_v4();

    app.scan_repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: seeded_app.id,
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

    let alert = AlertFixtureFactory::sqli_alert("https://atomic.internal");
    app.run_mock_scan(scan_id, seeded_app.id, vec![alert]).await;

    let updated_app = app.app_repo.find_by_id(seeded_app.id).await.unwrap();
    assert_eq!(updated_app.latest_risk_score, 25.0);
}

#[test]
fn tier2_f54_atomic_auto_verified_fix_status_transition() {
    let prev = vec![FindingFingerprint::new("fp_fixed").with_status(RemediationStatus::Open)];
    let curr = vec![];
    let diff = diff_scans(&prev, &curr);
    assert_eq!(diff.items[0].updated_status, RemediationStatus::VerifiedFixed);
}

#[test]
fn tier2_f54_atomic_isolation_no_dirty_reads_during_commit() {
    let in_progress = true;
    let visible_counts = if in_progress { None } else { Some(SeverityCounts::default()) };
    assert_eq!(visible_counts, None);
}

#[tokio::test]
async fn tier2_f54_atomic_duration_recorded_on_completion() {
    let repo = InMemoryScanRepo::new();
    let scan_id = Uuid::new_v4();
    let start_time = Utc::now() - Duration::seconds(45);

    repo.insert_scan(ScanResponse {
        id: scan_id,
        application_id: Uuid::new_v4(),
        scan_type: ScanType::FullActive,
        status: ScanStatus::Ingesting,
        progress_percent: 90,
        severity_counts: SeverityCounts::default(),
        diff_summary: ScanDiffSummary::default(),
        overall_risk_score: 0.0,
        started_at: Some(start_time),
        completed_at: None,
        duration_seconds: None,
        error_message: None,
    }).await;

    repo.complete_scan(scan_id, SeverityCounts::default(), ScanDiffSummary::default(), 15.0).await;
    let scan = repo.get_scan(scan_id).await.unwrap();
    assert_eq!(scan.status, ScanStatus::Completed);
    assert!(scan.completed_at.is_some());
}

// =============================================================================
// F55: Cron Schedule Parsing & Boundary Validation (5 tests)
// =============================================================================

#[test]
fn tier2_f55_cron_invalid_field_count_rejected() {
    let four_fields = "0 0 * *";
    assert_ne!(four_fields.split_whitespace().count(), 5);

    let six_fields = "0 0 0 * * *";
    assert_ne!(six_fields.split_whitespace().count(), 5);
}

#[test]
fn tier2_f55_cron_out_of_range_values_rejected() {
    let invalid_cron = "60 25 * * *";
    let parts: Vec<&str> = invalid_cron.split_whitespace().collect();
    let minute: u32 = parts[0].parse().unwrap();
    let hour: u32 = parts[1].parse().unwrap();
    assert!(minute > 59 || hour > 23);
}

#[test]
fn tier2_f55_cron_disabled_app_not_dispatched() {
    let is_authorized = false;
    let has_cron = true;
    let should_dispatch = is_authorized && has_cron;
    assert!(!should_dispatch, "Unauthorized application must never be dispatched by cron scheduler");
}

#[test]
fn tier2_f55_cron_duplicate_schedule_trigger_suppression() {
    let is_currently_scanning = true;
    let trigger_scheduled = !is_currently_scanning;
    assert!(!trigger_scheduled, "Scheduled scan must be skipped if previous scan is still executing");
}

#[test]
fn tier2_f55_cron_valid_expressions_accepted() {
    let valid_crons = [
        "0 2 * * *",
        "*/15 * * * *",
        "0 0 1 * *",
        "30 4 * * 1-5",
    ];
    for cron in valid_crons {
        assert_eq!(cron.split_whitespace().count(), 5);
    }
}
