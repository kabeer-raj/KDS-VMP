use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use infra::memory::{InMemoryAppRepo, InMemoryPubSub, InMemoryScanRepo, InMemoryVulnRepo};
use infra::zap::client::MockZapClient;
use scan_worker::engine::ScanWorkerEngine;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    tracing::info!("Initializing scan-worker binary");

    let app_repo = Arc::new(InMemoryAppRepo::new());
    let scan_repo = Arc::new(InMemoryScanRepo::new());
    let vuln_repo = Arc::new(InMemoryVulnRepo::new());
    let zap_client = Arc::new(MockZapClient::new());
    let pubsub = Arc::new(InMemoryPubSub::new());

    let engine = Arc::new(ScanWorkerEngine::new(
        app_repo,
        scan_repo,
        vuln_repo,
        zap_client,
        pubsub,
    ));

    let (stop_tx, stop_rx) = watch::channel(false);

    let worker_handle = engine.clone().start_background_worker(Duration::from_millis(500), stop_rx.clone());
    let scheduler_handle = engine.clone().start_cron_scheduler(Duration::from_secs(60), stop_rx);

    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutdown signal received, stopping background tasks");

    let _ = stop_tx.send(true);
    let _ = tokio::join!(worker_handle, scheduler_handle);

    tracing::info!("scan-worker shutdown gracefully");
    Ok(())
}
