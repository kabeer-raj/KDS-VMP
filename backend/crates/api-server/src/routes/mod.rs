pub mod apps;
pub mod auth;
pub mod reports;
pub mod scans;
pub mod vulns;
pub mod ws;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde_json::json;
use tower_http::cors::CorsLayer;

use crate::state::AppState;

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::permissive();

    Router::new()
        // Health check
        .route("/healthz", get(healthz_handler))
        .route("/api/v1/healthz", get(healthz_handler))
        // Auth routes
        .route("/api/v1/auth/login", post(auth::login_handler))
        .route("/api/v1/auth/refresh", post(auth::refresh_handler))
        .route("/api/v1/auth/logout", post(auth::logout_handler))
        .route("/api/v1/auth/me", get(auth::me_handler))
        .route(
            "/api/v1/auth/keys",
            get(auth::list_api_keys_handler).post(auth::create_api_key_handler),
        )
        .route(
            "/api/v1/auth/keys/:id",
            delete(auth::delete_api_key_handler),
        )
        .route(
            "/api/v1/auth/api-keys",
            get(auth::list_api_keys_handler).post(auth::create_api_key_handler),
        )
        .route(
            "/api/v1/auth/api-keys/:id",
            delete(auth::delete_api_key_handler),
        )
        // Apps routes
        .route(
            "/api/v1/apps",
            get(apps::list_apps_handler).post(apps::create_app_handler),
        )
        .route(
            "/api/v1/apps/:id",
            get(apps::get_app_handler)
                .put(apps::patch_app_handler)
                .patch(apps::patch_app_handler)
                .delete(apps::delete_app_handler),
        )
        .route(
            "/api/v1/apps/:id/auth",
            put(apps::configure_app_auth_handler),
        )
        .route(
            "/api/v1/apps/:id/trends",
            get(apps::get_app_trends_handler),
        )
        // Scans routes
        .route(
            "/api/v1/apps/:app_id/scans",
            get(scans::list_scans_for_app_handler).post(scans::trigger_scan_by_app_handler),
        )
        .route(
            "/api/v1/scans",
            get(scans::list_scans_global_handler).post(scans::trigger_scan_global_handler),
        )
        .route("/api/v1/scans/diff", get(scans::compare_scans_handler))
        .route(
            "/api/v1/scans/compare",
            get(scans::compare_scans_handler),
        )
        .route("/api/v1/scans/:id", get(scans::get_scan_handler))
        .route(
            "/api/v1/scans/:id/cancel",
            post(scans::cancel_scan_handler),
        )
        .route(
            "/api/v1/scans/:id/report",
            get(scans::get_scan_findings_handler),
        )
        .route(
            "/api/v1/scans/:id/findings",
            get(scans::get_scan_findings_handler),
        )
        // Vulnerabilities routes (both /vulnerabilities and /vulns)
        .route(
            "/api/v1/vulnerabilities",
            get(vulns::list_vulns_handler),
        )
        .route(
            "/api/v1/vulnerabilities/bulk-update",
            post(vulns::bulk_update_vulns_handler),
        )
        .route(
            "/api/v1/vulnerabilities/:id",
            get(vulns::get_vuln_handler).patch(vulns::patch_vuln_handler),
        )
        .route(
            "/api/v1/vulnerabilities/:id/history",
            get(vulns::get_vuln_history_handler),
        )
        .route(
            "/api/v1/vulnerabilities/:id/comments",
            post(vulns::add_vuln_comment_handler),
        )
        .route("/api/v1/vulns", get(vulns::list_vulns_handler))
        .route(
            "/api/v1/vulns/bulk-update",
            post(vulns::bulk_update_vulns_handler),
        )
        .route(
            "/api/v1/vulns/:id",
            get(vulns::get_vuln_handler).patch(vulns::patch_vuln_handler),
        )
        .route(
            "/api/v1/vulns/:id/history",
            get(vulns::get_vuln_history_handler),
        )
        .route(
            "/api/v1/vulns/:id/comments",
            post(vulns::add_vuln_comment_handler),
        )
        // Reports & Dashboard routes
        .route(
            "/api/v1/dashboard/summary",
            get(reports::get_dashboard_summary_handler),
        )
        .route(
            "/dashboard/summary",
            get(reports::get_dashboard_summary_handler),
        )
        .route(
            "/api/v1/reports/:id/pdf",
            get(reports::get_scan_report_pdf_handler),
        )
        .route(
            "/api/v1/reports/scans/:id/pdf",
            get(reports::get_scan_report_pdf_handler),
        )
        .route(
            "/api/v1/reports/:id/json",
            get(reports::get_scan_report_json_handler),
        )
        .route(
            "/api/v1/reports/apps/:id/pdf",
            get(reports::get_app_report_pdf_handler),
        )
        // WebSocket routes
        .route(
            "/ws/scans/:id/progress",
            get(ws::ws_scan_progress_handler),
        )
        .route("/ws/scans/:id", get(ws::ws_scan_progress_handler))
        .route(
            "/ws/v1/scans/:id",
            get(ws::ws_scan_progress_handler),
        )
        .route(
            "/ws/v1/notifications",
            get(ws::ws_notifications_handler),
        )
        .layer(cors)
        .with_state(state)
}

async fn healthz_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status": "ok"})))
}
