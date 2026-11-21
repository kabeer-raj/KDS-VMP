use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::enums::{DiffClassification, RemediationStatus, SeverityLevel};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VulnerabilitySummary {
    pub id: Uuid,
    pub application_id: Uuid,
    pub fingerprint: String,
    pub title: String,
    pub owasp_category: String,
    pub cwe_id: Option<i32>,
    pub severity: SeverityLevel,
    pub cvss_score: f64,
    pub status: RemediationStatus,
    pub http_method: String,
    pub normalized_path: String,
    pub affected_param: Option<String>,
    pub assigned_to: Option<Uuid>,
    pub seen_count: i32,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HttpEvidence {
    pub scan_id: Uuid,
    pub diff_state: DiffClassification,
    pub attack_payload: Option<String>,
    pub evidence_snippet: Option<String>,
    pub raw_request_header: Option<String>,
    pub raw_response_header: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VulnerabilityDetail {
    #[serde(flatten)]
    pub summary: VulnerabilitySummary,
    pub zap_plugin_id: String,
    pub wasc_id: Option<i32>,
    pub cvss_vector: Option<String>,
    pub confidence: String,
    pub affected_url: String,
    pub description: String,
    pub solution: String,
    #[serde(default)]
    pub reference_urls: Vec<String>,
    pub due_date: Option<DateTime<Utc>>,
    pub latest_evidence: Option<HttpEvidence>,
    pub first_seen_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct UpdateVulnerabilityRequest {
    pub status: Option<RemediationStatus>,
    pub severity: Option<SeverityLevel>,
    pub assigned_to: Option<Uuid>,
    pub due_date: Option<DateTime<Utc>>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BulkUpdateVulnsRequest {
    pub vuln_ids: Vec<Uuid>,
    pub status: Option<RemediationStatus>,
    pub severity: Option<SeverityLevel>,
    pub assigned_to: Option<Uuid>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BulkUpdateResponse {
    pub updated_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddCommentRequest {
    pub comment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemediationAuditLogResponse {
    pub id: Uuid,
    pub vulnerability_id: Uuid,
    pub actor_id: Option<Uuid>,
    pub scan_id: Option<Uuid>,
    pub action_type: String,
    pub old_status: Option<RemediationStatus>,
    pub new_status: Option<RemediationStatus>,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerability_summary_serde() {
        let vuln_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let now = Utc::now();

        let summary = VulnerabilitySummary {
            id: vuln_id,
            application_id: app_id,
            fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            title: "SQL Injection in User Search".to_string(),
            owasp_category: "A03:2021-Injection".to_string(),
            cwe_id: Some(89),
            severity: SeverityLevel::High,
            cvss_score: 8.5,
            status: RemediationStatus::Open,
            http_method: "GET".to_string(),
            normalized_path: "/api/users".to_string(),
            affected_param: Some("q".to_string()),
            assigned_to: None,
            seen_count: 3,
            last_seen_at: now,
        };

        let json = serde_json::to_string(&summary).unwrap();
        let parsed: VulnerabilitySummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, summary.id);
        assert_eq!(parsed.fingerprint, summary.fingerprint);
        assert_eq!(parsed.severity, SeverityLevel::High);
        assert_eq!(parsed.status, RemediationStatus::Open);
    }

    #[test]
    fn test_vulnerability_detail_flattened_serde() {
        let vuln_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let scan_id = Uuid::new_v4();
        let now = Utc::now();

        let detail = VulnerabilityDetail {
            summary: VulnerabilitySummary {
                id: vuln_id,
                application_id: app_id,
                fingerprint: "abcdef1234567890".to_string(),
                title: "Cross-Site Scripting (Reflected)".to_string(),
                owasp_category: "A03:2021-Injection".to_string(),
                cwe_id: Some(79),
                severity: SeverityLevel::Medium,
                cvss_score: 6.1,
                status: RemediationStatus::InProgress,
                http_method: "POST".to_string(),
                normalized_path: "/contact".to_string(),
                affected_param: Some("message".to_string()),
                assigned_to: None,
                seen_count: 1,
                last_seen_at: now,
            },
            zap_plugin_id: "40012".to_string(),
            wasc_id: Some(8),
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N".to_string()),
            confidence: "High".to_string(),
            affected_url: "https://example.com/contact".to_string(),
            description: "The parameter message is vulnerable to XSS".to_string(),
            solution: "Apply context-aware HTML entity encoding".to_string(),
            reference_urls: vec!["https://owasp.org/www-community/attacks/xss/".to_string()],
            due_date: None,
            latest_evidence: Some(HttpEvidence {
                scan_id,
                diff_state: DiffClassification::New,
                attack_payload: Some("<script>alert(1)</script>".to_string()),
                evidence_snippet: Some("value=\"<script>alert(1)</script>\"".to_string()),
                raw_request_header: Some("POST /contact HTTP/1.1".to_string()),
                raw_response_header: Some("HTTP/1.1 200 OK".to_string()),
            }),
            first_seen_at: now,
            resolved_at: None,
        };

        let json = serde_json::to_string(&detail).unwrap();

        // Verify summary fields are flattened to the root JSON object
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("summary").is_none(), "summary key should not exist because of #[serde(flatten)]");
        assert_eq!(v["fingerprint"], "abcdef1234567890");
        assert_eq!(v["zap_plugin_id"], "40012");
        assert_eq!(v["severity"], "medium");
        assert_eq!(v["latest_evidence"]["diff_state"], "new");

        // Verify roundtrip deserialization
        let parsed: VulnerabilityDetail = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.summary.id, detail.summary.id);
        assert_eq!(parsed.summary.fingerprint, detail.summary.fingerprint);
        assert_eq!(parsed.zap_plugin_id, detail.zap_plugin_id);
        assert_eq!(parsed.reference_urls.len(), 1);
        assert!(parsed.latest_evidence.is_some());
    }

    #[test]
    fn test_vulnerability_detail_default_reference_urls() {
        // Without reference_urls in JSON, it should deserialize to empty Vec
        let vuln_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let json_input = serde_json::json!({
            "id": vuln_id,
            "application_id": app_id,
            "fingerprint": "fp123",
            "title": "Missing Security Header",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "severity": "low",
            "cvss_score": 3.5,
            "status": "open",
            "http_method": "GET",
            "normalized_path": "/robots.txt",
            "seen_count": 1,
            "last_seen_at": "2026-11-21T12:00:00Z",
            "first_seen_at": "2026-11-21T12:00:00Z",
            "zap_plugin_id": "10038",
            "confidence": "Medium",
            "affected_url": "https://example.com/robots.txt",
            "description": "CSP header missing",
            "solution": "Configure CSP header"
        });

        let detail: VulnerabilityDetail = serde_json::from_value(json_input).unwrap();
        assert!(detail.reference_urls.is_empty());
        assert_eq!(detail.latest_evidence, None);
        assert_eq!(detail.wasc_id, None);
    }

    #[test]
    fn test_update_and_bulk_update_requests_serde() {
        let user_id = Uuid::new_v4();
        let update_req = UpdateVulnerabilityRequest {
            status: Some(RemediationStatus::RiskAccepted),
            severity: Some(SeverityLevel::Low),
            assigned_to: Some(user_id),
            due_date: None,
            comment: Some("Accepted risk for internal network only".to_string()),
        };

        let json = serde_json::to_string(&update_req).unwrap();
        let parsed: UpdateVulnerabilityRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, update_req);

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let bulk_req = BulkUpdateVulnsRequest {
            vuln_ids: vec![id1, id2],
            status: Some(RemediationStatus::FalsePositive),
            severity: None,
            assigned_to: None,
            comment: Some("Bulk marked as false positive".to_string()),
        };

        let bulk_json = serde_json::to_string(&bulk_req).unwrap();
        let parsed_bulk: BulkUpdateVulnsRequest = serde_json::from_str(&bulk_json).unwrap();
        assert_eq!(parsed_bulk.vuln_ids.len(), 2);
        assert_eq!(parsed_bulk.status, Some(RemediationStatus::FalsePositive));

        let bulk_resp = BulkUpdateResponse { updated_count: 2 };
        let bulk_resp_json = serde_json::to_string(&bulk_resp).unwrap();
        let parsed_resp: BulkUpdateResponse = serde_json::from_str(&bulk_resp_json).unwrap();
        assert_eq!(parsed_resp.updated_count, 2);
    }

    #[test]
    fn test_add_comment_and_audit_log_response_serde() {
        let comment_req = AddCommentRequest {
            comment: "Verified with security team; patch is scheduled for sprint 4.".to_string(),
        };
        let c_json = serde_json::to_string(&comment_req).unwrap();
        let parsed_c: AddCommentRequest = serde_json::from_str(&c_json).unwrap();
        assert_eq!(parsed_c, comment_req);

        let log_id = Uuid::new_v4();
        let vuln_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let now = Utc::now();

        let audit = RemediationAuditLogResponse {
            id: log_id,
            vulnerability_id: vuln_id,
            actor_id: Some(actor_id),
            scan_id: None,
            action_type: "STATUS_CHANGE".to_string(),
            old_status: Some(RemediationStatus::Open),
            new_status: Some(RemediationStatus::InProgress),
            comment: Some("Assigned to developer".to_string()),
            created_at: now,
        };

        let a_json = serde_json::to_string(&audit).unwrap();
        let parsed_a: RemediationAuditLogResponse = serde_json::from_str(&a_json).unwrap();
        assert_eq!(parsed_a.id, audit.id);
        assert_eq!(parsed_a.old_status, Some(RemediationStatus::Open));
        assert_eq!(parsed_a.new_status, Some(RemediationStatus::InProgress));
    }
}
