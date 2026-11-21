use shared_types::SeverityLevel;
use uuid::Uuid;

use crate::traits::{FindingIngestionInput, ZapAlert};

pub struct ZapAlertParser;

impl ZapAlertParser {
    pub fn parse_alerts(alerts: &[ZapAlert], _app_id: &Uuid) -> Vec<FindingIngestionInput> {
        alerts.iter().map(Self::parse_alert).collect()
    }

    pub fn parse_alert(alert: &ZapAlert) -> FindingIngestionInput {
        let cwe_id = alert
            .cweid
            .as_deref()
            .and_then(|s| s.trim().parse::<i32>().ok());
        let wasc_id = alert
            .wascid
            .as_deref()
            .and_then(|s| s.trim().parse::<i32>().ok());

        let severity = match alert.risk.to_lowercase().as_str() {
            "critical" => SeverityLevel::Critical,
            "high" => SeverityLevel::High,
            "medium" => SeverityLevel::Medium,
            "low" => SeverityLevel::Low,
            _ => SeverityLevel::Info,
        };

        let cvss_score = match severity {
            SeverityLevel::Critical => 9.5,
            SeverityLevel::High => 8.0,
            SeverityLevel::Medium => 5.5,
            SeverityLevel::Low => 3.0,
            SeverityLevel::Info => 0.0,
        };

        let reference_urls = alert
            .reference
            .as_deref()
            .map(|r| {
                r.lines()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();

        let param = alert.param.as_deref().and_then(|p| {
            let trimmed = p.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });

        let attack = alert.attack.as_deref().and_then(|a| {
            let trimmed = a.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });

        let evidence = alert.evidence.as_deref().and_then(|e| {
            let trimmed = e.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });

        let title = alert
            .name
            .as_deref()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or(&alert.alert)
            .to_string();

        let http_method = alert
            .method
            .as_deref()
            .filter(|m| !m.trim().is_empty())
            .unwrap_or("GET")
            .to_uppercase();

        FindingIngestionInput {
            zap_plugin_id: alert.plugin_id.clone(),
            title,
            cwe_id,
            wasc_id,
            confidence: alert.confidence.clone(),
            http_method,
            affected_url: alert.url.clone(),
            affected_param: param,
            attack_payload: attack,
            evidence_snippet: evidence,
            description: alert.description.clone(),
            solution: alert.solution.clone(),
            reference_urls,
            raw_request_header: alert.request_header.clone(),
            raw_response_header: alert.response_header.clone(),
            cvss_score: Some(cvss_score),
            severity: Some(severity),
        }
    }
}
