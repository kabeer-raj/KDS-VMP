use std::collections::HashMap;
use std::sync::Arc;
use chrono::Utc;
use uuid::Uuid;

use infra::traits::{
    AppRepository, PubSubPort, ScanRepository, VulnRepository, ZapClient, ZapContextConfig,
};
use shared_types::app::ApplicationResponse;
use shared_types::enums::{ScanStatus, ScanType};
use shared_types::events::{
    ScanCompletedEvent, ScanFailedEvent, ScanProgressEvent, WsServerEvent,
};
use shared_types::scan::ScanResponse;

use crate::error::ScanWorkerError;
use crate::pipeline::FindingPipeline;

/// Orchestrates OWASP ZAP execution:
/// 1. Configures isolated ZAP context with target scope and headers.
/// 2. Executes traditional spider and streams progress via pub/sub.
/// 3. Executes active scanner and streams progress via pub/sub.
/// 4. Collects alerts and invokes the finding processing pipeline.
/// 5. Handles live cancellation requests gracefully.
pub struct ZapOrchestrator;

impl ZapOrchestrator {
    async fn is_cancelled(scan_repo: &Arc<dyn ScanRepository>, scan_id: Uuid) -> bool {
        if let Ok(Some(s)) = scan_repo.get_by_id(scan_id).await {
            s.status == ScanStatus::Cancelled
        } else {
            false
        }
    }

    /// Resolves target URL for ZAP container: translates localhost / 127.0.0.1 to Docker container
    /// names or host.docker.internal when running under containerized environments.
    pub fn resolve_target_url_for_zap(target_url: &str) -> String {
        let in_docker = std::env::var("IN_DOCKER").map(|v| v == "true" || v == "1").unwrap_or(false)
            || std::env::var("ZAP_URL").map(|u| u.contains("zap:")).unwrap_or(false);

        if !in_docker {
            return target_url.to_string();
        }

        let trimmed = target_url.trim();
        if trimmed.starts_with("http://localhost:8000") {
            return trimmed.replacen("http://localhost:8000", "http://api-server:8000", 1);
        }
        if trimmed.starts_with("http://127.0.0.1:8000") {
            return trimmed.replacen("http://127.0.0.1:8000", "http://api-server:8000", 1);
        }
        if trimmed.starts_with("https://localhost:8000") {
            return trimmed.replacen("https://localhost:8000", "http://api-server:8000", 1);
        }
        if trimmed.starts_with("https://127.0.0.1:8000") {
            return trimmed.replacen("https://127.0.0.1:8000", "http://api-server:8000", 1);
        }

        if trimmed.starts_with("http://localhost:") {
            return trimmed.replacen("http://localhost:", "http://host.docker.internal:", 1);
        }
        if trimmed.starts_with("http://127.0.0.1:") {
            return trimmed.replacen("http://127.0.0.1:", "http://host.docker.internal:", 1);
        }
        if trimmed.starts_with("https://localhost:") {
            return trimmed.replacen("https://localhost:", "https://host.docker.internal:", 1);
        }
        if trimmed.starts_with("https://127.0.0.1:") {
            return trimmed.replacen("https://127.0.0.1:", "https://host.docker.internal:", 1);
        }

        if trimmed == "http://localhost" || trimmed == "http://localhost/" {
            return "http://api-server:8000/".to_string();
        }
        if trimmed == "http://127.0.0.1" || trimmed == "http://127.0.0.1/" {
            return "http://api-server:8000/".to_string();
        }

        trimmed.to_string()
    }

    pub async fn orchestrate_scan(
        scan_id: Uuid,
        app: &ApplicationResponse,
        scan_type: ScanType,
        custom_headers: Option<HashMap<String, String>>,
        zap_client: &Arc<dyn ZapClient>,
        scan_repo: &Arc<dyn ScanRepository>,
        vuln_repo: &Arc<dyn VulnRepository>,
        app_repo: &Arc<dyn AppRepository>,
        pubsub: &Arc<dyn PubSubPort>,
    ) -> Result<ScanResponse, ScanWorkerError> {
        let start_time = Utc::now();

        // Check if already cancelled
        if let Some(scan) = scan_repo.get_by_id(scan_id).await? {
            if scan.status == ScanStatus::Cancelled {
                return Ok(scan);
            }
        }

        let zap_target_url = Self::resolve_target_url_for_zap(&app.base_url);

        // 1. Initialize ZAP context
        let context_name = format!("ctx_{}_{}", app.name.replace(' ', "_"), scan_id);
        let mut context_config = ZapContextConfig {
            context_name: context_name.clone(),
            target_url: zap_target_url.clone(),
            include_regexes: app.include_regexes.clone(),
            exclude_regexes: app.exclude_regexes.clone(),
            auth_header: None,
            session_cookie: None,
        };

        if let Some(ref headers) = custom_headers {
            if let Some(auth_val) = headers.get("Authorization") {
                context_config.auth_header = Some(("Authorization".to_string(), auth_val.clone()));
            }
        }

        if let Err(e) = zap_client.configure_context(&context_config).await {
            let err_msg = format!("Failed to configure ZAP context: {e}");
            scan_repo.update_status(scan_id, ScanStatus::Failed, Some(err_msg.clone())).await?;
            let _ = pubsub.publish_scan_progress(&WsServerEvent::ScanFailed(ScanFailedEvent {
                scan_id,
                application_id: app.id,
                reason: err_msg,
            })).await;
            return Err(ScanWorkerError::Zap(format!("Failed to configure ZAP context: {e}")));
        }

        // 2. Spider Phase
        scan_repo.update_status(scan_id, ScanStatus::Spidering, None).await?;
        scan_repo.update_progress(scan_id, 0).await?;

        let _ = pubsub.publish_scan_progress(&WsServerEvent::ScanProgress(ScanProgressEvent {
            scan_id,
            application_id: app.id,
            status: ScanStatus::Spidering,
            progress_percent: 0,
            current_phase: "spidering".to_string(),
            alerts_found_so_far: 0,
        })).await;

        let spider_scan_id = match zap_client.start_spider(&zap_target_url, Some(&context_name)).await {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::warn!("Failed to initiate ZAP spider: {e}");
                None
            }
        };

        if let Some(ref spider_scan_id) = spider_scan_id {
            // Poll spider progress
            loop {
                if Self::is_cancelled(scan_repo, scan_id).await {
                    return scan_repo.get_by_id(scan_id).await?.ok_or_else(|| ScanWorkerError::ScanNotFound(scan_id));
                }

                let spider_pct = zap_client.get_spider_status(spider_scan_id).await.unwrap_or(100);
                let overall_pct = ((spider_pct as f64) * 0.35).min(35.0) as u8;

                scan_repo.update_progress(scan_id, overall_pct).await?;
                let _ = pubsub.publish_scan_progress(&WsServerEvent::ScanProgress(ScanProgressEvent {
                    scan_id,
                    application_id: app.id,
                    status: ScanStatus::Spidering,
                    progress_percent: overall_pct,
                    current_phase: "spidering".to_string(),
                    alerts_found_so_far: 0,
                })).await;

                if spider_pct >= 100 {
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
            }
        }

        // 3. Active Scan Phase (for FullActive, ApiOpenapi, SpaAjax)
        if matches!(scan_type, ScanType::FullActive | ScanType::ApiOpenapi | ScanType::SpaAjax) {
            scan_repo.update_status(scan_id, ScanStatus::ActiveScanning, None).await?;
            scan_repo.update_progress(scan_id, 35).await?;

            let _ = pubsub.publish_scan_progress(&WsServerEvent::ScanProgress(ScanProgressEvent {
                scan_id,
                application_id: app.id,
                status: ScanStatus::ActiveScanning,
                progress_percent: 35,
                current_phase: "active_scanning".to_string(),
                alerts_found_so_far: 0,
            })).await;

            let ascan_id = match zap_client.start_active_scan(&zap_target_url, Some(&context_name)).await {
                Ok(id) => Some(id),
                Err(e) => {
                    tracing::warn!("Failed to initiate ZAP active scan (proceeding with passive/spider findings): {e}");
                    let _ = pubsub.publish_scan_progress(&WsServerEvent::ScanProgress(ScanProgressEvent {
                        scan_id,
                        application_id: app.id,
                        status: ScanStatus::ActiveScanning,
                        progress_percent: 50,
                        current_phase: "active_scanning_skipped".to_string(),
                        alerts_found_so_far: 0,
                    })).await;
                    None
                }
            };

            if let Some(ref ascan_id) = ascan_id {
                // Poll active scanner progress
                loop {
                    if Self::is_cancelled(scan_repo, scan_id).await {
                        return scan_repo.get_by_id(scan_id).await?.ok_or_else(|| ScanWorkerError::ScanNotFound(scan_id));
                    }

                    let ascan_pct = zap_client.get_active_scan_status(ascan_id).await.unwrap_or(100);
                    let overall_pct = 35 + ((ascan_pct as f64) * 0.50).min(50.0) as u8;

                    scan_repo.update_progress(scan_id, overall_pct).await?;
                    let _ = pubsub.publish_scan_progress(&WsServerEvent::ScanProgress(ScanProgressEvent {
                        scan_id,
                        application_id: app.id,
                        status: ScanStatus::ActiveScanning,
                        progress_percent: overall_pct,
                        current_phase: "active_scanning".to_string(),
                        alerts_found_so_far: 0,
                    })).await;

                    if ascan_pct >= 100 {
                        break;
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                }
            }
        }

        // 4. Analyzing / Ingestion Phase
        scan_repo.update_status(scan_id, ScanStatus::Ingesting, None).await?;
        scan_repo.update_progress(scan_id, 90).await?;

        let _ = pubsub.publish_scan_progress(&WsServerEvent::ScanProgress(ScanProgressEvent {
            scan_id,
            application_id: app.id,
            status: ScanStatus::Ingesting,
            progress_percent: 90,
            current_phase: "analyzing".to_string(),
            alerts_found_so_far: 0,
        })).await;

        if Self::is_cancelled(scan_repo, scan_id).await {
            return scan_repo.get_by_id(scan_id).await?.ok_or_else(|| ScanWorkerError::ScanNotFound(scan_id));
        }

        // 5. Fetch alerts from ZAP (query resolved URL first, fall back to base_url)
        let mut alerts = match zap_client.get_alerts(&zap_target_url, None, None).await {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("Failed to fetch alerts from ZAP for {zap_target_url}: {e}");
                Vec::new()
            }
        };

        if alerts.is_empty() && zap_target_url != app.base_url {
            if let Ok(fallback_alerts) = zap_client.get_alerts(&app.base_url, None, None).await {
                alerts = fallback_alerts;
            }
        }

        // 6. Execute finding pipeline (deduplicate, classify OWASP, CVSS scoring, diffing, persistence)
        let prev_scan_id = scan_repo.get_latest_completed_scan_id(app.id).await?;
        let duration_seconds = Some((Utc::now() - start_time).num_seconds().max(0) as i32);

        let pipeline_res = match FindingPipeline::process(
            scan_id,
            app,
            &alerts,
            prev_scan_id,
            duration_seconds,
            vuln_repo,
            scan_repo,
            app_repo,
        )
        .await
        {
            Ok(res) => res,
            Err(e) => {
                let err_msg = format!("Finding pipeline processing error: {e}");
                scan_repo.update_status(scan_id, ScanStatus::Failed, Some(err_msg.clone())).await?;
                let _ = pubsub.publish_scan_progress(&WsServerEvent::ScanFailed(ScanFailedEvent {
                    scan_id,
                    application_id: app.id,
                    reason: err_msg,
                })).await;
                return Err(e);
            }
        };

        // 7. Mark scan as Completed
        scan_repo.update_status(scan_id, ScanStatus::Completed, None).await?;
        scan_repo.update_progress(scan_id, 100).await?;

        let completed_scan = scan_repo
            .get_by_id(scan_id)
            .await?
            .ok_or_else(|| ScanWorkerError::ScanNotFound(scan_id))?;

        // 8. Publish ScanCompleted event
        let _ = pubsub.publish_scan_progress(&WsServerEvent::ScanCompleted(ScanCompletedEvent {
            scan_id,
            application_id: app.id,
            severity_counts: pipeline_res.severity_counts,
            overall_risk_score: pipeline_res.overall_risk_score,
        })).await;

        Ok(completed_scan)
    }
}
