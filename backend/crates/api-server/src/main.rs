use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use api_server::{create_router, AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "api_server=debug,tower_http=debug,info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = std::env::var("DATABASE_URL").ok();
    let redis_url = std::env::var("REDIS_URL").ok();
    let zap_url = std::env::var("ZAP_URL").unwrap_or_else(|_| "http://zap:8080".into());
    let zap_api_key = std::env::var("ZAP_API_KEY").ok();
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "test_jwt_secret_key_appsec_platform_2026_super_secure".into());

    let state = if let Some(ref db_url) = database_url {
        tracing::info!("Connecting to PostgreSQL database at {}", db_url);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(20)
            .connect(db_url)
            .await?;

        tracing::info!("Applying database migrations");
        infra::db::run_migrations(&pool).await?;

        let app_repo = Arc::new(infra::db::PgAppRepo::new(pool.clone()));
        let scan_repo = Arc::new(infra::db::PgScanRepo::new(pool.clone()));
        let vuln_repo = Arc::new(infra::db::PgVulnRepo::new(pool.clone()));
        let user_repo = Arc::new(infra::db::PgUserRepo::new(pool.clone()));
        let audit_repo = Arc::new(infra::db::PgAuditLogRepo::new(pool.clone()));
        let pubsub_adapter = Arc::new(infra::pubsub::RedisPubSub::new(redis_url.as_deref()));
        let pdf_generator = Arc::new(infra::pdf::SimplePdfGenerator::new());
        let zap_client: Arc<dyn infra::traits::ZapClient> =
            Arc::new(infra::zap::HttpZapClient::new(zap_url, zap_api_key));

        let app_state = AppState::new(
            app_repo,
            scan_repo,
            vuln_repo,
            user_repo,
            audit_repo,
            pubsub_adapter,
            pdf_generator,
            zap_client,
            jwt_secret,
        );
        app_state.seed_default_users().await;
        app_state
    } else {
        tracing::info!("DATABASE_URL not set; initializing with self-contained in-memory store");
        let app_state = AppState::new_in_memory();
        app_state.seed_default_users().await;
        app_state
    };

    let app = create_router(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8000);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("api-server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
