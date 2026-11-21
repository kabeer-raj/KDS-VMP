use axum::extract::{Path as AxumPath, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use uuid::Uuid;

use infra::traits::VulnFilter;
use shared_types::RemediationStatus;

use crate::error::AppError;
use crate::middleware::AuthenticatedUser;
use crate::state::AppState;

pub async fn get_scan_report_pdf_handler(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    AxumPath(scan_id_str): AxumPath<String>,
) -> Result<Response, AppError> {
    let scan_id = Uuid::parse_str(&scan_id_str)
        .map_err(|_| AppError::not_found("SCAN_NOT_FOUND", "Scan not found"))?;

    let scan = state
        .scan_repo
        .get_by_id(scan_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("SCAN_NOT_FOUND", "Scan not found"))?;

    let app = state
        .app_repo
        .get_by_id(scan.application_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("APPLICATION_NOT_FOUND", "Application not found"))?;

    let findings_res = state
        .scan_repo
        .list_findings(scan.id, 1, 1000)
        .await
        .map_err(AppError::from)?;

    let mut detailed_findings = Vec::new();
    for f in &findings_res.items {
        if let Ok(Some(d)) = state.vuln_repo.get_by_id(f.id).await {
            detailed_findings.push(d);
        }
    }

    let pdf_bytes = state
        .pdf_generator
        .generate_scan_report(&scan, &app, &detailed_findings)
        .await
        .map_err(AppError::from)?;

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/pdf"));
    let filename = format!("attachment; filename=\"AppSec_Report_{}.pdf\"", scan.id);
    if let Ok(val) = HeaderValue::from_str(&filename) {
        headers.insert(CONTENT_DISPOSITION, val);
    }

    Ok((StatusCode::OK, headers, pdf_bytes).into_response())
}

pub async fn get_scan_report_json_handler(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    AxumPath(scan_id_str): AxumPath<String>,
) -> Result<Response, AppError> {
    let scan_id = Uuid::parse_str(&scan_id_str)
        .map_err(|_| AppError::not_found("SCAN_NOT_FOUND", "Scan not found"))?;

    let scan = state
        .scan_repo
        .get_by_id(scan_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("SCAN_NOT_FOUND", "Scan not found"))?;

    let app = state
        .app_repo
        .get_by_id(scan.application_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("APPLICATION_NOT_FOUND", "Application not found"))?;

    let findings_res = state
        .scan_repo
        .list_findings(scan.id, 1, 1000)
        .await
        .map_err(AppError::from)?;

    let body = json!({
        "scan": scan,
        "application": app,
        "findings": findings_res.items,
    });

    Ok((StatusCode::OK, Json(body)).into_response())
}

pub async fn get_app_report_pdf_handler(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    AxumPath(app_id_str): AxumPath<String>,
) -> Result<Response, AppError> {
    let app_id = Uuid::parse_str(&app_id_str)
        .map_err(|_| AppError::not_found("APPLICATION_NOT_FOUND", "Application not found"))?;

    let app = state
        .app_repo
        .get_by_id(app_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("APPLICATION_NOT_FOUND", "Application not found"))?;

    let scans_res = state
        .scan_repo
        .list_by_app(app_id, 1, 100)
        .await
        .map_err(AppError::from)?;

    let open_filter = VulnFilter {
        app_id: Some(app_id),
        status: Some(RemediationStatus::Open),
        ..Default::default()
    };

    let open_res = state
        .vuln_repo
        .list_with_filters(&open_filter, 1, 100)
        .await
        .map_err(AppError::from)?;

    let mut detailed_findings = Vec::new();
    for f in &open_res.items {
        if let Ok(Some(d)) = state.vuln_repo.get_by_id(f.id).await {
            detailed_findings.push(d);
        }
    }

    let pdf_bytes = state
        .pdf_generator
        .generate_app_report(&app, &scans_res.items, &detailed_findings)
        .await
        .map_err(AppError::from)?;

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/pdf"));
    let filename = format!("attachment; filename=\"App_Posture_{}.pdf\"", app.id);
    if let Ok(val) = HeaderValue::from_str(&filename) {
        headers.insert(CONTENT_DISPOSITION, val);
    }

    Ok((StatusCode::OK, headers, pdf_bytes).into_response())
}

pub async fn get_dashboard_summary_handler(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> Result<Response, AppError> {
    let apps = state.app_repo.list(None, None).await.map_err(AppError::from)?;
    let total_apps = apps.len();
    let mut total_risk = 0.0;
    for a in &apps {
        total_risk += a.latest_risk_score;
    }
    let avg_risk = if total_apps > 0 { total_risk / total_apps as f64 } else { 0.0 };

    let vulns = state.vuln_repo.list_with_filters(&VulnFilter::default(), 1, 1000).await.map_err(AppError::from)?;
    let body = json!({
        "total_applications": total_apps,
        "average_risk_score": avg_risk,
        "total_vulnerabilities": vulns.total,
        "vulnerabilities": vulns.items,
    });
    Ok((StatusCode::OK, Json(body)).into_response())
}
