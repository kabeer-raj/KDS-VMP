use std::collections::HashMap;
use std::sync::Arc;
use chrono::Utc;
use uuid::Uuid;

use core_domain::classifier::classify_owasp;
use core_domain::cvss_engine::calculate_asset_risk;
use core_domain::deduplicator::{generate_fingerprint, normalize_url_path};
use core_domain::diff_engine::ScanDiffResult;
use infra::traits::{
    AppRepository, FindingIngestionInput, ScanRepository, VulnRepository, ZapAlert,
};
use infra::zap::parser::ZapAlertParser;
use shared_types::app::ApplicationResponse;
use shared_types::enums::SeverityLevel;
use shared_types::scan::{ScanDiffSummary, SeverityCounts};

use crate::error::ScanWorkerError;

/// Result summary of the finding processing pipeline execution.
#[derive(Debug, Clone)]
pub struct PipelineResult {
    pub severity_counts: SeverityCounts,
    pub diff_summary: ScanDiffSummary,
    pub diff_result: ScanDiffResult,
    pub overall_risk_score: f64,
}

/// Finding processing pipeline:
/// Ingests ZAP alerts, deduplicates them deterministically, classifies OWASP categories,
/// computes CVSS scores, diffs against previous scan, and persists results.
pub struct FindingPipeline;

impl FindingPipeline {
    /// Executes the full finding ingestion, normalization, deduplication, scoring, diffing, and persistence pipeline.
    pub async fn process(
        scan_id: Uuid,
        app: &ApplicationResponse,
        raw_alerts: &[ZapAlert],
        prev_scan_id: Option<Uuid>,
        duration_seconds: Option<i32>,
        vuln_repo: &Arc<dyn VulnRepository>,
        scan_repo: &Arc<dyn ScanRepository>,
        app_repo: &Arc<dyn AppRepository>,
    ) -> Result<PipelineResult, ScanWorkerError> {
        let now = Utc::now();

        // 1. Ingest raw ZAP alerts using ZapAlertParser
        let parsed_inputs = ZapAlertParser::parse_alerts(raw_alerts, &app.id);

        // 2. Deduplicate findings using RFC 3986 path normalization + deterministic SHA-256 fingerprinting
        // Also enrich with OWASP classification and CVSS v3.1 scoring
        let mut deduped_map: HashMap<String, FindingIngestionInput> = HashMap::new();

        for mut input in parsed_inputs {
            let normalized_path = normalize_url_path(&input.affected_url);
            let fingerprint = generate_fingerprint(
                &app.id,
                &input.zap_plugin_id,
                &normalized_path,
                input.affected_param.as_deref(),
                &input.http_method,
            );

            // 3. Classify OWASP category
            let _owasp_cat = classify_owasp(input.cwe_id, &input.zap_plugin_id);

            // 4. Calculate CVSS v3.1 score and qualitative severity if missing
            let (score, severity) = match input.severity {
                Some(SeverityLevel::Critical) => (input.cvss_score.unwrap_or(9.5), SeverityLevel::Critical),
                Some(SeverityLevel::High) => (input.cvss_score.unwrap_or(8.0), SeverityLevel::High),
                Some(SeverityLevel::Medium) => (input.cvss_score.unwrap_or(5.5), SeverityLevel::Medium),
                Some(SeverityLevel::Low) => (input.cvss_score.unwrap_or(3.0), SeverityLevel::Low),
                Some(SeverityLevel::Info) | None => (input.cvss_score.unwrap_or(0.0), SeverityLevel::Info),
            };
            input.cvss_score = Some(score);
            input.severity = Some(severity);

            // Deduplicate: preserve the finding with higher severity if collision occurs
            if let Some(existing) = deduped_map.get_mut(&fingerprint) {
                if let (Some(new_sev), Some(old_sev)) = (input.severity, existing.severity) {
                    if new_sev > old_sev {
                        *existing = input;
                    }
                }
            } else {
                deduped_map.insert(fingerprint, input);
            }
        }

        let deduped_inputs: Vec<FindingIngestionInput> = deduped_map.into_values().collect();

        // 5. Diff findings against previous scan and persist into VulnRepository
        let diff_result = vuln_repo
            .upsert_findings(scan_id, app.id, &deduped_inputs, prev_scan_id)
            .await?;

        // 6. Calculate summary severity counts
        let mut counts = SeverityCounts::default();
        let mut max_cvss: f64 = 0.0;

        for item in &deduped_inputs {
            if let Some(cvss) = item.cvss_score {
                if cvss > max_cvss {
                    max_cvss = cvss;
                }
            }
            match item.severity {
                Some(SeverityLevel::Critical) => counts.critical += 1,
                Some(SeverityLevel::High) => counts.high += 1,
                Some(SeverityLevel::Medium) => counts.medium += 1,
                Some(SeverityLevel::Low) => counts.low += 1,
                Some(SeverityLevel::Info) | None => counts.info += 1,
            }
        }

        // 7. Calculate asset-weighted risk score
        let overall_risk_score = if counts.total() == 0 {
            0.0
        } else {
            calculate_asset_risk(max_cvss, app.environment, app.criticality)
        };

        // 8. Persist findings metrics and diff into ScanRepository
        scan_repo
            .update_metrics(
                scan_id,
                &counts,
                &diff_result.summary,
                overall_risk_score,
                duration_seconds,
            )
            .await?;

        // 9. Update application latest risk and last_scanned_at in AppRepository
        app_repo
            .update_latest_risk(app.id, overall_risk_score, now)
            .await?;

        Ok(PipelineResult {
            severity_counts: counts,
            diff_summary: diff_result.summary.clone(),
            diff_result,
            overall_risk_score,
        })
    }
}
