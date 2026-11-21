//! Integration Test Suite for crates/core-domain
//!
//! Exercises the full domain flow combining:
//! - RFC 3986 URL path normalization
//! - Deterministic SHA-256 finding deduplication
//! - OWASP Top 10 (2021) classification
//! - CVSS v3.1 scoring formulas & asset context risk weighting
//! - Multi-scan lifecycle diffing and triage state preservation

use core_domain::{
    calculate_asset_risk, calculate_cvss_v31, classify_owasp, diff_scans, generate_fingerprint,
    normalize_url_path, DiffItem, FindingFingerprint, FindingLifecycleState,
    A01_BROKEN_ACCESS_CONTROL, A03_INJECTION, A05_SECURITY_MISCONFIGURATION,
};
use shared_types::{
    AppCriticality, AppEnvironment, CvssVector, DiffClassification, RemediationStatus,
    SeverityLevel,
};
use uuid::Uuid;

#[test]
fn test_end_to_end_domain_pipeline_flow() {
    let app_id = Uuid::new_v4();
    let env = AppEnvironment::Production;
    let crit = AppCriticality::Critical;

    // --- SCAN 1: Initial Discovery ---
    // Raw alert 1: SQL Injection
    let alert1_url = "https://shop.example.com/api/v1/products/../../../api/v1/users?id=1#details";
    let alert1_method = "get";
    let alert1_cwe = Some(89);
    let alert1_plugin = "40018";
    let alert1_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

    let norm_path1 = normalize_url_path(alert1_url);
    assert_eq!(norm_path1, "/api/v1/users");
    let owasp_cat1 = classify_owasp(alert1_cwe, alert1_plugin);
    assert_eq!(owasp_cat1, A03_INJECTION);
    let fp1 = generate_fingerprint(&app_id, alert1_plugin, alert1_url, Some("id"), alert1_method);
    let metrics1 = CvssVector::new(alert1_vector).parse_metrics().unwrap();
    let (score1, severity1) = calculate_cvss_v31(&metrics1);
    assert_eq!(score1, 9.8);
    assert_eq!(severity1, SeverityLevel::Critical);
    let asset_risk1 = calculate_asset_risk(score1, env, crit);
    assert_eq!(asset_risk1, 98.0);

    // Raw alert 2: Content Security Policy missing
    let alert2_url = "https://shop.example.com/dashboard/";
    let alert2_method = "GET";
    let alert2_cwe = None;
    let alert2_plugin = "10038";
    let alert2_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";

    let norm_path2 = normalize_url_path(alert2_url);
    assert_eq!(norm_path2, "/dashboard");
    let owasp_cat2 = classify_owasp(alert2_cwe, alert2_plugin);
    assert_eq!(owasp_cat2, A05_SECURITY_MISCONFIGURATION);
    let fp2 = generate_fingerprint(&app_id, alert2_plugin, alert2_url, None, alert2_method);
    let metrics2 = CvssVector::new(alert2_vector).parse_metrics().unwrap();
    let (score2, severity2) = calculate_cvss_v31(&metrics2);
    assert_eq!(score2, 6.1);
    assert_eq!(severity2, SeverityLevel::Medium);
    let asset_risk2 = calculate_asset_risk(score2, env, crit);
    assert_eq!(asset_risk2, 61.0);

    // Raw alert 3: Path Traversal
    let alert3_url = "https://shop.example.com:8443/static/../etc/passwd";
    let alert3_method = "POST";
    let alert3_cwe = Some(22);
    let alert3_plugin = "40011";
    let alert3_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H";

    let norm_path3 = normalize_url_path(alert3_url);
    assert_eq!(norm_path3, "/etc/passwd");
    let owasp_cat3 = classify_owasp(alert3_cwe, alert3_plugin);
    assert_eq!(owasp_cat3, A01_BROKEN_ACCESS_CONTROL);
    let fp3 = generate_fingerprint(&app_id, alert3_plugin, alert3_url, Some("file"), alert3_method);
    let metrics3 = CvssVector::new(alert3_vector).parse_metrics().unwrap();
    let (score3, severity3) = calculate_cvss_v31(&metrics3);
    assert_eq!(score3, 9.9);
    assert_eq!(severity3, SeverityLevel::Critical);
    let asset_risk3 = calculate_asset_risk(score3, env, crit);
    assert_eq!(asset_risk3, 99.0);

    // Initial Scan 1 Diff against empty baseline
    let scan1_findings = vec![
        FindingFingerprint::new(&fp1).with_cvss(score1),
        FindingFingerprint::new(&fp2).with_cvss(score2),
        FindingFingerprint::new(&fp3).with_cvss(score3),
    ];
    let diff_result1 = diff_scans(&[], &scan1_findings);
    assert_eq!(diff_result1.summary.new_count, 3);
    assert_eq!(diff_result1.summary.persistent_count, 0);
    assert_eq!(diff_result1.summary.fixed_count, 0);
    assert_eq!(diff_result1.summary.regressed_count, 0);
    assert_eq!(diff_result1.summary.risk_score_delta, 25.8); // 9.8 + 6.1 + 9.9 = 25.8

    // --- SCAN 2: Triage and Remediation ---
    // Developers fixed SQLi (fp1).
    // Security engineer triaged CSP (fp2) as FalsePositive.
    // Path traversal (fp3) is still Open.
    let scan2_prev = vec![
        FindingFingerprint::new(&fp1).with_status(RemediationStatus::Resolved).with_cvss(score1),
        FindingFingerprint::new(&fp2).with_status(RemediationStatus::FalsePositive).with_cvss(score2),
        FindingFingerprint::new(&fp3).with_status(RemediationStatus::Open).with_cvss(score3),
    ];

    // Current Scan 2 detects fp2 and fp3; fp1 is absent (fixed)
    let scan2_curr = vec![
        FindingFingerprint::new(&fp2).with_cvss(score2),
        FindingFingerprint::new(&fp3).with_cvss(score3),
    ];

    let diff_result2 = diff_scans(&scan2_prev, &scan2_curr);
    assert_eq!(diff_result2.summary.new_count, 0);
    assert_eq!(diff_result2.summary.persistent_count, 2);
    assert_eq!(diff_result2.summary.fixed_count, 1); // fp1 auto-verified fixed
    assert_eq!(diff_result2.summary.regressed_count, 0);
    assert_eq!(diff_result2.summary.risk_score_delta, -9.8); // fp1 eliminated

    let fixed_fp1: &DiffItem = diff_result2.items.iter().find(|i| i.fingerprint == fp1).unwrap();
    assert_eq!(fixed_fp1.lifecycle_state, FindingLifecycleState::Fixed);
    assert_eq!(fixed_fp1.diff_classification, None);
    assert_eq!(fixed_fp1.updated_status, RemediationStatus::VerifiedFixed);

    let persistent_fp2 = diff_result2.items.iter().find(|i| i.fingerprint == fp2).unwrap();
    assert_eq!(persistent_fp2.lifecycle_state, FindingLifecycleState::Persistent);
    assert_eq!(persistent_fp2.diff_classification, Some(DiffClassification::Persistent));
    assert_eq!(persistent_fp2.updated_status, RemediationStatus::FalsePositive); // Triage preserved!

    // --- SCAN 3: Regression ---
    // A faulty code deploy accidentally re-introduced SQLi (fp1)!
    let scan3_prev = vec![
        FindingFingerprint::new(&fp1).with_status(RemediationStatus::VerifiedFixed).with_cvss(0.0),
        FindingFingerprint::new(&fp2).with_status(RemediationStatus::FalsePositive).with_cvss(score2),
        FindingFingerprint::new(&fp3).with_status(RemediationStatus::Open).with_cvss(score3),
    ];

    let scan3_curr = vec![
        FindingFingerprint::new(&fp1).with_cvss(score1), // Reappeared!
        FindingFingerprint::new(&fp2).with_cvss(score2),
        FindingFingerprint::new(&fp3).with_cvss(score3),
    ];

    let diff_result3 = diff_scans(&scan3_prev, &scan3_curr);
    assert_eq!(diff_result3.summary.new_count, 0);
    assert_eq!(diff_result3.summary.persistent_count, 2);
    assert_eq!(diff_result3.summary.fixed_count, 0);
    assert_eq!(diff_result3.summary.regressed_count, 1); // fp1 regressed!
    assert_eq!(diff_result3.summary.risk_score_delta, 9.8);

    let regressed_fp1 = diff_result3.items.iter().find(|i| i.fingerprint == fp1).unwrap();
    assert_eq!(regressed_fp1.lifecycle_state, FindingLifecycleState::Regressed);
    assert_eq!(regressed_fp1.diff_classification, Some(DiffClassification::Regressed));
    assert_eq!(regressed_fp1.updated_status, RemediationStatus::Regressed);
}

#[test]
fn test_url_normalization_and_fingerprint_variants_equivalence() {
    let app_id = Uuid::new_v4();
    let plugin = "40018";
    let param = Some("search");
    let method = "post";

    let urls = [
        "https://example.com/api/v1/search",
        "http://example.com:8080/api/v1/search",
        "https://example.com/api/v1/search/",
        "//example.com/api/v1/search",
        "/api/v1/search",
        "/api/v1/search?query=test#top",
        "/api/v0/../v1/./search",
        "https://example.com////api///v1////search//",
    ];

    let baseline_fp = generate_fingerprint(&app_id, plugin, urls[0], param, method);
    assert_eq!(baseline_fp.len(), 64);

    for (idx, &url) in urls.iter().enumerate() {
        let fp = generate_fingerprint(&app_id, plugin, url, param, method);
        assert_eq!(
            fp, baseline_fp,
            "Variant {} failed to produce baseline fingerprint: {}",
            idx, url
        );
    }
}

#[test]
fn test_cvss_asset_risk_matrix() {
    let base_score = 9.8;

    // Test matrix of environments and criticalities
    let prod_crit = calculate_asset_risk(base_score, AppEnvironment::Production, AppCriticality::Critical);
    let prod_high = calculate_asset_risk(base_score, AppEnvironment::Production, AppCriticality::High);
    let stag_med = calculate_asset_risk(base_score, AppEnvironment::Staging, AppCriticality::Medium);
    let dev_low = calculate_asset_risk(base_score, AppEnvironment::Development, AppCriticality::Low);

    // 9.8 * 10 * 1.0 * 1.0 = 98.0
    assert_eq!(prod_crit, 98.0);
    // 9.8 * 10 * 1.0 * 0.8 = 78.4
    assert_eq!(prod_high, 78.4);
    // 9.8 * 10 * 0.8 * 0.6 = 47.04
    assert_eq!(stag_med, 47.04);
    // 9.8 * 10 * 0.4 * 0.4 = 15.68
    assert_eq!(dev_low, 15.68);
}
