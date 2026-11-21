use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::enums::ScanStatus;
use crate::scan::SeverityCounts;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanProgressEvent {
    pub scan_id: Uuid,
    pub application_id: Uuid,
    pub status: ScanStatus,
    pub progress_percent: u8,
    pub current_phase: String,
    pub alerts_found_so_far: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanCompletedEvent {
    pub scan_id: Uuid,
    pub application_id: Uuid,
    pub severity_counts: SeverityCounts,
    pub overall_risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanFailedEvent {
    pub scan_id: Uuid,
    pub application_id: Uuid,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum WsServerEvent {
    ScanProgress(ScanProgressEvent),
    ScanCompleted(ScanCompletedEvent),
    ScanFailed(ScanFailedEvent),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_server_event_scan_progress_serde() {
        let scan_id = Uuid::parse_str("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d").unwrap();
        let app_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

        let progress = ScanProgressEvent {
            scan_id,
            application_id: app_id,
            status: ScanStatus::ActiveScanning,
            progress_percent: 64,
            current_phase: "Testing SQL Injection & XSS vectors on /api/login".to_string(),
            alerts_found_so_far: 7,
        };

        let event = WsServerEvent::ScanProgress(progress);
        let json = serde_json::to_string(&event).unwrap();

        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["event"], "scan_progress");
        assert_eq!(v["data"]["scan_id"], "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d");
        assert_eq!(v["data"]["application_id"], "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(v["data"]["status"], "active_scanning");
        assert_eq!(v["data"]["progress_percent"], 64);
        assert_eq!(v["data"]["current_phase"], "Testing SQL Injection & XSS vectors on /api/login");
        assert_eq!(v["data"]["alerts_found_so_far"], 7);

        let parsed: WsServerEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_ws_server_event_scan_completed_serde() {
        let scan_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();

        let completed = ScanCompletedEvent {
            scan_id,
            application_id: app_id,
            severity_counts: SeverityCounts::new(1, 2, 3, 4, 5),
            overall_risk_score: 45.2,
        };

        let event = WsServerEvent::ScanCompleted(completed);
        let json = serde_json::to_string(&event).unwrap();

        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["event"], "scan_completed");
        assert_eq!(v["data"]["overall_risk_score"], 45.2);
        assert_eq!(v["data"]["severity_counts"]["critical"], 1);

        let parsed: WsServerEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_ws_server_event_scan_failed_serde() {
        let scan_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();

        let failed = ScanFailedEvent {
            scan_id,
            application_id: app_id,
            reason: "Target host unreachable: connection timed out after 30s".to_string(),
        };

        let event = WsServerEvent::ScanFailed(failed);
        let json = serde_json::to_string(&event).unwrap();

        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["event"], "scan_failed");
        assert_eq!(v["data"]["reason"], "Target host unreachable: connection timed out after 30s");

        let parsed: WsServerEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn test_ws_server_event_unknown_event_rejection() {
        let bad_json = r#"{"event":"unknown_event","data":{"foo":"bar"}}"#;
        assert!(serde_json::from_str::<WsServerEvent>(bad_json).is_err());
    }
}
