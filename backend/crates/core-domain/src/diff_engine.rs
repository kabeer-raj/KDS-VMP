//! Scan-to-Scan Diff Engine & Lifecycle State Machine
//!
//! Compares sequential scan snapshots (Scan N vs. Scan N-1), tracking lifecycle
//! transitions (NEW, PERSISTENT, FIXED, REGRESSED), preserving triage decisions,
//! and computing summary metrics.

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use shared_types::{DiffClassification, RemediationStatus, ScanDiffSummary};

/// Lifecycle classification of a finding between two scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingLifecycleState {
    New,
    Persistent,
    Fixed,
    Regressed,
}

/// Representation of a finding fingerprint and its associated triage/remediation metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingFingerprint {
    pub fingerprint: String,
    pub status: RemediationStatus,
    pub cvss_score: f64,
}

impl FindingFingerprint {
    pub fn new(fingerprint: impl Into<String>) -> Self {
        Self {
            fingerprint: fingerprint.into(),
            status: RemediationStatus::Open,
            cvss_score: 0.0,
        }
    }

    pub fn with_status(mut self, status: RemediationStatus) -> Self {
        self.status = status;
        self
    }

    pub fn with_cvss(mut self, cvss_score: f64) -> Self {
        self.cvss_score = cvss_score;
        self
    }
}

/// Itemized diff result for a specific finding fingerprint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiffItem {
    pub fingerprint: String,
    pub lifecycle_state: FindingLifecycleState,
    pub diff_classification: Option<DiffClassification>, // None for findings absent in current scan
    pub previous_status: Option<RemediationStatus>,
    pub updated_status: RemediationStatus,
    pub cvss_score: f64,
}

/// Aggregated scan comparison result including summary metrics and itemized transitions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanDiffResult {
    pub summary: ScanDiffSummary,
    pub items: Vec<DiffItem>,
}

/// Compare findings from previous scan (`prev`) against current scan (`curr`).
///
/// Lifecycle Rules:
/// - Present in `curr`, absent in `prev`: `NEW` (`DiffClassification::New`, `Open`, `new_count++`).
/// - Present in `curr`, present in `prev` with status `Resolved` or `VerifiedFixed`: `REGRESSED` (`DiffClassification::Regressed`, `Regressed`, `regressed_count++`).
/// - Present in both: `PERSISTENT` (`DiffClassification::Persistent`, preserves triage status, `persistent_count++`).
/// - Present in `prev`, absent in `curr`:
///   - If actionable (`Open`, `InProgress`, `Resolved`, `Regressed`): `FIXED` (`VerifiedFixed`, `fixed_count++`).
///   - If non-actionable triage (`FalsePositive`, `RiskAccepted`): Preserves triage status, does NOT increment `fixed_count`.
pub fn diff_scans(prev: &[FindingFingerprint], curr: &[FindingFingerprint]) -> ScanDiffResult {
    let mut prev_map: HashMap<&str, &FindingFingerprint> = HashMap::with_capacity(prev.len());
    let mut prev_total_score = 0.0;
    for item in prev {
        prev_map.insert(&item.fingerprint, item);
        prev_total_score += item.cvss_score;
    }

    let mut matched_prev: HashSet<&str> = HashSet::with_capacity(curr.len());
    let mut items: Vec<DiffItem> = Vec::with_capacity(curr.len() + prev.len());

    let mut new_count = 0;
    let mut persistent_count = 0;
    let mut fixed_count = 0;
    let mut regressed_count = 0;
    let mut curr_total_score = 0.0;

    // 1. Evaluate findings in current scan
    for curr_item in curr {
        curr_total_score += curr_item.cvss_score;
        let fp_str = curr_item.fingerprint.as_str();

        if let Some(prev_item) = prev_map.get(fp_str) {
            matched_prev.insert(fp_str);

            if prev_item.status == RemediationStatus::Resolved
                || prev_item.status == RemediationStatus::VerifiedFixed
            {
                // Regressed finding
                regressed_count += 1;
                items.push(DiffItem {
                    fingerprint: curr_item.fingerprint.clone(),
                    lifecycle_state: FindingLifecycleState::Regressed,
                    diff_classification: Some(DiffClassification::Regressed),
                    previous_status: Some(prev_item.status),
                    updated_status: RemediationStatus::Regressed,
                    cvss_score: curr_item.cvss_score,
                });
            } else {
                // Persistent finding - preserves developer triage status
                persistent_count += 1;
                items.push(DiffItem {
                    fingerprint: curr_item.fingerprint.clone(),
                    lifecycle_state: FindingLifecycleState::Persistent,
                    diff_classification: Some(DiffClassification::Persistent),
                    previous_status: Some(prev_item.status),
                    updated_status: prev_item.status,
                    cvss_score: curr_item.cvss_score,
                });
            }
        } else {
            // New finding
            new_count += 1;
            items.push(DiffItem {
                fingerprint: curr_item.fingerprint.clone(),
                lifecycle_state: FindingLifecycleState::New,
                diff_classification: Some(DiffClassification::New),
                previous_status: None,
                updated_status: RemediationStatus::Open,
                cvss_score: curr_item.cvss_score,
            });
        }
    }

    // 2. Evaluate findings in previous scan that are absent in current scan
    for prev_item in prev {
        let fp_str = prev_item.fingerprint.as_str();
        if !matched_prev.contains(fp_str) {
            match prev_item.status {
                RemediationStatus::FalsePositive | RemediationStatus::RiskAccepted => {
                    // Non-actionable triage preserved, does not increment fixed_count
                    items.push(DiffItem {
                        fingerprint: prev_item.fingerprint.clone(),
                        lifecycle_state: FindingLifecycleState::Fixed,
                        diff_classification: None,
                        previous_status: Some(prev_item.status),
                        updated_status: prev_item.status,
                        cvss_score: prev_item.cvss_score,
                    });
                }
                _ => {
                    // Actionable finding resolved/disappeared -> Auto-verified fixed
                    fixed_count += 1;
                    items.push(DiffItem {
                        fingerprint: prev_item.fingerprint.clone(),
                        lifecycle_state: FindingLifecycleState::Fixed,
                        diff_classification: None,
                        previous_status: Some(prev_item.status),
                        updated_status: RemediationStatus::VerifiedFixed,
                        cvss_score: prev_item.cvss_score,
                    });
                }
            }
        }
    }

    let delta = ((curr_total_score - prev_total_score) * 100.0).round() / 100.0;

    ScanDiffResult {
        summary: ScanDiffSummary {
            previous_scan_id: None,
            new_count,
            persistent_count,
            fixed_count,
            regressed_count,
            risk_score_delta: delta,
        },
        items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_first_scan() {
        let prev: Vec<FindingFingerprint> = vec![];
        let curr = vec![
            FindingFingerprint::new("fp-1").with_cvss(5.0),
            FindingFingerprint::new("fp-2").with_cvss(7.5),
        ];

        let result = diff_scans(&prev, &curr);
        assert_eq!(result.summary.new_count, 2);
        assert_eq!(result.summary.persistent_count, 0);
        assert_eq!(result.summary.fixed_count, 0);
        assert_eq!(result.summary.regressed_count, 0);
        assert_eq!(result.summary.risk_score_delta, 12.5);

        assert_eq!(result.items.len(), 2);
        assert_eq!(result.items[0].lifecycle_state, FindingLifecycleState::New);
        assert_eq!(result.items[0].diff_classification, Some(DiffClassification::New));
        assert_eq!(result.items[0].updated_status, RemediationStatus::Open);
    }

    #[test]
    fn test_diff_identical_consecutive_scans() {
        let prev = vec![
            FindingFingerprint::new("fp-1").with_cvss(5.0),
            FindingFingerprint::new("fp-2").with_cvss(7.5),
        ];
        let curr = vec![
            FindingFingerprint::new("fp-1").with_cvss(5.0),
            FindingFingerprint::new("fp-2").with_cvss(7.5),
        ];

        let result = diff_scans(&prev, &curr);
        assert_eq!(result.summary.new_count, 0);
        assert_eq!(result.summary.persistent_count, 2);
        assert_eq!(result.summary.fixed_count, 0);
        assert_eq!(result.summary.regressed_count, 0);
        assert_eq!(result.summary.risk_score_delta, 0.0);

        for item in &result.items {
            assert_eq!(item.lifecycle_state, FindingLifecycleState::Persistent);
            assert_eq!(item.diff_classification, Some(DiffClassification::Persistent));
        }
    }

    #[test]
    fn test_diff_auto_verified_fixed() {
        let prev = vec![
            FindingFingerprint::new("fp-1").with_cvss(5.0),
            FindingFingerprint::new("fp-2").with_cvss(7.5),
        ];
        // fp-2 disappeared in curr
        let curr = vec![FindingFingerprint::new("fp-1").with_cvss(5.0)];

        let result = diff_scans(&prev, &curr);
        assert_eq!(result.summary.new_count, 0);
        assert_eq!(result.summary.persistent_count, 1);
        assert_eq!(result.summary.fixed_count, 1);
        assert_eq!(result.summary.regressed_count, 0);
        assert_eq!(result.summary.risk_score_delta, -7.5);

        let fixed_item = result.items.iter().find(|i| i.fingerprint == "fp-2").unwrap();
        assert_eq!(fixed_item.lifecycle_state, FindingLifecycleState::Fixed);
        assert_eq!(fixed_item.diff_classification, None);
        assert_eq!(fixed_item.updated_status, RemediationStatus::VerifiedFixed);
    }

    #[test]
    fn test_diff_regression_from_resolved_and_verified_fixed() {
        let prev = vec![
            FindingFingerprint::new("fp-1")
                .with_status(RemediationStatus::Resolved)
                .with_cvss(6.0),
            FindingFingerprint::new("fp-2")
                .with_status(RemediationStatus::VerifiedFixed)
                .with_cvss(8.0),
        ];
        let curr = vec![
            FindingFingerprint::new("fp-1").with_cvss(6.0),
            FindingFingerprint::new("fp-2").with_cvss(8.0),
        ];

        let result = diff_scans(&prev, &curr);
        assert_eq!(result.summary.new_count, 0);
        assert_eq!(result.summary.persistent_count, 0);
        assert_eq!(result.summary.regressed_count, 2);
        assert_eq!(result.summary.fixed_count, 0);

        for item in &result.items {
            assert_eq!(item.lifecycle_state, FindingLifecycleState::Regressed);
            assert_eq!(item.diff_classification, Some(DiffClassification::Regressed));
            assert_eq!(item.updated_status, RemediationStatus::Regressed);
        }
    }

    #[test]
    fn test_diff_triage_preservation_when_present() {
        let prev = vec![
            FindingFingerprint::new("fp-fp")
                .with_status(RemediationStatus::FalsePositive)
                .with_cvss(5.0),
            FindingFingerprint::new("fp-ra")
                .with_status(RemediationStatus::RiskAccepted)
                .with_cvss(4.0),
            FindingFingerprint::new("fp-ip")
                .with_status(RemediationStatus::InProgress)
                .with_cvss(7.0),
        ];
        let curr = vec![
            FindingFingerprint::new("fp-fp").with_cvss(5.0),
            FindingFingerprint::new("fp-ra").with_cvss(4.0),
            FindingFingerprint::new("fp-ip").with_cvss(7.0),
        ];

        let result = diff_scans(&prev, &curr);
        assert_eq!(result.summary.persistent_count, 3);

        let item_fp = result.items.iter().find(|i| i.fingerprint == "fp-fp").unwrap();
        assert_eq!(item_fp.updated_status, RemediationStatus::FalsePositive);

        let item_ra = result.items.iter().find(|i| i.fingerprint == "fp-ra").unwrap();
        assert_eq!(item_ra.updated_status, RemediationStatus::RiskAccepted);

        let item_ip = result.items.iter().find(|i| i.fingerprint == "fp-ip").unwrap();
        assert_eq!(item_ip.updated_status, RemediationStatus::InProgress);
    }

    #[test]
    fn test_diff_triage_preservation_when_absent() {
        let prev = vec![
            FindingFingerprint::new("fp-fp")
                .with_status(RemediationStatus::FalsePositive)
                .with_cvss(5.0),
            FindingFingerprint::new("fp-ra")
                .with_status(RemediationStatus::RiskAccepted)
                .with_cvss(4.0),
        ];
        // Both absent in curr
        let curr: Vec<FindingFingerprint> = vec![];

        let result = diff_scans(&prev, &curr);
        // Fixed count must NOT be incremented for non-actionable triaged findings
        assert_eq!(result.summary.fixed_count, 0);

        let item_fp = result.items.iter().find(|i| i.fingerprint == "fp-fp").unwrap();
        assert_eq!(item_fp.updated_status, RemediationStatus::FalsePositive);

        let item_ra = result.items.iter().find(|i| i.fingerprint == "fp-ra").unwrap();
        assert_eq!(item_ra.updated_status, RemediationStatus::RiskAccepted);
    }

    #[test]
    fn test_diff_scan_1_to_2_to_3_lifecycle() {
        // Scan 1: initial discovery
        let scan1_findings = vec![
            FindingFingerprint::new("vuln-sqli").with_cvss(9.0),
            FindingFingerprint::new("vuln-xss").with_cvss(6.1),
        ];
        let diff_1 = diff_scans(&[], &scan1_findings);
        assert_eq!(diff_1.summary.new_count, 2);
        assert_eq!(diff_1.summary.fixed_count, 0);

        // Scan 2: developer resolved vuln-sqli, vuln-xss triaged InProgress, new vuln-csrf found
        let scan2_prev = vec![
            FindingFingerprint::new("vuln-sqli").with_status(RemediationStatus::Resolved).with_cvss(9.0),
            FindingFingerprint::new("vuln-xss").with_status(RemediationStatus::InProgress).with_cvss(6.1),
        ];
        let scan2_curr = vec![
            // vuln-sqli is absent (verified fixed in scan 2)
            FindingFingerprint::new("vuln-xss").with_cvss(6.1),
            FindingFingerprint::new("vuln-csrf").with_cvss(4.3),
        ];
        let diff_2 = diff_scans(&scan2_prev, &scan2_curr);
        assert_eq!(diff_2.summary.new_count, 1); // vuln-csrf
        assert_eq!(diff_2.summary.persistent_count, 1); // vuln-xss
        assert_eq!(diff_2.summary.fixed_count, 1); // vuln-sqli
        assert_eq!(diff_2.summary.regressed_count, 0);

        // Scan 3: vuln-sqli reappears! (Regression)
        let scan3_prev = vec![
            FindingFingerprint::new("vuln-sqli").with_status(RemediationStatus::VerifiedFixed).with_cvss(9.0),
            FindingFingerprint::new("vuln-xss").with_status(RemediationStatus::InProgress).with_cvss(6.1),
            FindingFingerprint::new("vuln-csrf").with_status(RemediationStatus::Open).with_cvss(4.3),
        ];
        let scan3_curr = vec![
            FindingFingerprint::new("vuln-sqli").with_cvss(9.0), // Regressed!
            FindingFingerprint::new("vuln-xss").with_cvss(6.1),
            FindingFingerprint::new("vuln-csrf").with_cvss(4.3),
        ];
        let diff_3 = diff_scans(&scan3_prev, &scan3_curr);
        assert_eq!(diff_3.summary.new_count, 0);
        assert_eq!(diff_3.summary.persistent_count, 2);
        assert_eq!(diff_3.summary.fixed_count, 0);
        assert_eq!(diff_3.summary.regressed_count, 1); // vuln-sqli regressed
    }
}
