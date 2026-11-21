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
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,scan_worker=debug".into()))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    tracing::info!("Initializing scan-worker binary");

    let database_url = std::env::var("DATABASE_URL").ok();
    let redis_url = std::env::var("REDIS_URL").ok();
    let zap_url = std::env::var("ZAP_URL").unwrap_or_else(|_| "http://zap:8080".into());
    let zap_api_key = std::env::var("ZAP_API_KEY").ok();

    let (app_repo, scan_repo, vuln_repo, zap_client, pubsub): (
        Arc<dyn infra::traits::AppRepository>,
        Arc<dyn infra::traits::ScanRepository>,
        Arc<dyn infra::traits::VulnRepository>,
        Arc<dyn infra::traits::ZapClient>,
        Arc<dyn infra::traits::PubSubPort>,
    ) = if let Some(ref db_url) = database_url {
        tracing::info!("Connecting to PostgreSQL at {}", db_url);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(10)
            .connect(db_url)
            .await?;
        (
            Arc::new(infra::db::PgAppRepo::new(pool.clone())),
            Arc::new(infra::db::PgScanRepo::new(pool.clone())),
            Arc::new(infra::db::PgVulnRepo::new(pool.clone())),
            Arc::new(infra::zap::HttpZapClient::new(zap_url, zap_api_key)),
            Arc::new(infra::pubsub::RedisPubSub::new(redis_url.as_deref())),
        )
    } else {
        tracing::info!("DATABASE_URL not set; running with self-contained in-memory fixtures");
        (
            Arc::new(InMemoryAppRepo::new()),
            Arc::new(InMemoryScanRepo::new()),
            Arc::new(InMemoryVulnRepo::new()),
            Arc::new(MockZapClient::new()),
            Arc::new(InMemoryPubSub::new()),
        )
    };

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
