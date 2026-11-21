use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::enums::{ScanStatus, ScanType};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TriggerScanRequest {
    pub scan_type: ScanType,
    pub max_duration_minutes: Option<u32>,
    pub custom_headers: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SeverityCounts {
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
    pub info: i32,
}

impl SeverityCounts {
    pub fn new(critical: i32, high: i32, medium: i32, low: i32, info: i32) -> Self {
        Self {
            critical,
            high,
            medium,
            low,
            info,
        }
    }

    pub fn total(&self) -> i32 {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanDiffSummary {
    pub previous_scan_id: Option<Uuid>,
    pub new_count: i32,
    pub persistent_count: i32,
    pub fixed_count: i32,
    pub regressed_count: i32,
    pub risk_score_delta: f64,
}

impl Default for ScanDiffSummary {
    fn default() -> Self {
        Self {
            previous_scan_id: None,
            new_count: 0,
            persistent_count: 0,
            fixed_count: 0,
            regressed_count: 0,
            risk_score_delta: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanResponse {
    pub id: Uuid,
    pub application_id: Uuid,
    pub scan_type: ScanType,
    pub status: ScanStatus,
    pub progress_percent: u8,
    pub severity_counts: SeverityCounts,
    pub diff_summary: ScanDiffSummary,
    pub overall_risk_score: f64,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_seconds: Option<i32>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanComparisonResponse {
    pub base_scan_id: Uuid,
    pub target_scan_id: Uuid,
    pub diff_summary: ScanDiffSummary,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_counts_default_and_total() {
        let counts = SeverityCounts::default();
        assert_eq!(counts.critical, 0);
        assert_eq!(counts.high, 0);
        assert_eq!(counts.medium, 0);
        assert_eq!(counts.low, 0);
        assert_eq!(counts.info, 0);
        assert_eq!(counts.total(), 0);

        let populated = SeverityCounts::new(2, 5, 10, 15, 3);
        assert_eq!(populated.total(), 35);
    }

    #[test]
    fn test_severity_counts_serde_roundtrip() {
        let counts = SeverityCounts::new(1, 2, 3, 4, 5);
        let json = serde_json::to_string(&counts).unwrap();
        let parsed: SeverityCounts = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, counts);
    }

    #[test]
    fn test_trigger_scan_request_serde() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer secret123".to_string());
        headers.insert("X-Custom-Scan".to_string(), "true".to_string());

        let req = TriggerScanRequest {
            scan_type: ScanType::FullActive,
            max_duration_minutes: Some(60),
            custom_headers: Some(headers),
        };

        let json = serde_json::to_string(&req).unwrap();
        let parsed: TriggerScanRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, req);

        // Without optional fields
        let minimal_json = r#"{"scan_type":"baseline_passive","max_duration_minutes":null,"custom_headers":null}"#;
        let minimal: TriggerScanRequest = serde_json::from_str(minimal_json).unwrap();
        assert_eq!(minimal.scan_type, ScanType::BaselinePassive);
        assert_eq!(minimal.max_duration_minutes, None);
        assert_eq!(minimal.custom_headers, None);
    }

    #[test]
    fn test_scan_diff_summary_default_and_serde() {
        let default_summary = ScanDiffSummary::default();
        assert_eq!(default_summary.previous_scan_id, None);
        assert_eq!(default_summary.new_count, 0);
        assert_eq!(default_summary.persistent_count, 0);
        assert_eq!(default_summary.fixed_count, 0);
        assert_eq!(default_summary.regressed_count, 0);
        assert_eq!(default_summary.risk_score_delta, 0.0);

        let prev_id = Uuid::new_v4();
        let populated = ScanDiffSummary {
            previous_scan_id: Some(prev_id),
            new_count: 3,
            persistent_count: 10,
            fixed_count: 2,
            regressed_count: 1,
            risk_score_delta: -5.2,
        };

        let json = serde_json::to_string(&populated).unwrap();
        let parsed: ScanDiffSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, populated);
    }

    #[test]
    fn test_scan_response_serde() {
        let scan_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let now = Utc::now();

        let resp = ScanResponse {
            id: scan_id,
            application_id: app_id,
            scan_type: ScanType::FullActive,
            status: ScanStatus::Completed,
            progress_percent: 100,
            severity_counts: SeverityCounts::new(1, 2, 4, 8, 16),
            diff_summary: ScanDiffSummary::default(),
            overall_risk_score: 42.5,
            started_at: Some(now),
            completed_at: Some(now),
            duration_seconds: Some(180),
            error_message: None,
        };

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ScanResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, resp.id);
        assert_eq!(parsed.application_id, resp.application_id);
        assert_eq!(parsed.scan_type, resp.scan_type);
        assert_eq!(parsed.status, resp.status);
        assert_eq!(parsed.progress_percent, 100);
        assert_eq!(parsed.duration_seconds, Some(180));
        assert_eq!(parsed.error_message, None);
    }

    #[test]
    fn test_scan_comparison_response_serde() {
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
                risk_score_delta: -1.5,
            },
        };

        let json = serde_json::to_string(&comp).unwrap();
        let parsed: ScanComparisonResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, comp);
    }
}
