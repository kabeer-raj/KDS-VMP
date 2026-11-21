use std::collections::HashMap;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use uuid::Uuid;

use shared_types::{
    ScanComparisonResponse, ScanDiffSummary, ScanResponse, ScanStatus, TriggerScanRequest,
};

use crate::error::AppError;
use crate::middleware::AuthenticatedUser;
use crate::state::AppState;

pub async fn trigger_scan_by_app_handler(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    AxumPath(app_id_str): AxumPath<String>,
    Json(payload): Json<TriggerScanRequest>,
) -> Result<Response, AppError> {
    auth.require_analyst()?;

    let app_id = Uuid::parse_str(&app_id_str)
        .map_err(|_| AppError::not_found("APPLICATION_NOT_FOUND", "Application not found"))?;

    trigger_scan_internal(&state, &auth, app_id, payload).await
}

#[derive(serde::Deserialize)]
pub struct TriggerScanWithAppPayload {
    pub application_id: Option<Uuid>,
    pub app_id: Option<Uuid>,
    #[serde(flatten)]
    pub req: TriggerScanRequest,
}

pub async fn trigger_scan_global_handler(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Query(params): Query<HashMap<String, String>>,
    Json(payload): Json<TriggerScanWithAppPayload>,
) -> Result<Response, AppError> {
    auth.require_analyst()?;

    let app_id = payload
        .application_id
        .or(payload.app_id)
        .or_else(|| {
            params
                .get("app_id")
                .or_else(|| params.get("application_id"))
                .and_then(|s| Uuid::parse_str(s).ok())
        })
        .ok_or_else(|| {
            AppError::bad_request("INVALID_INPUT", "Missing application_id for scan")
        })?;

    trigger_scan_internal(&state, &auth, app_id, payload.req).await
}

async fn trigger_scan_internal(
    state: &AppState,
    auth: &AuthenticatedUser,
    app_id: Uuid,
    req: TriggerScanRequest,
) -> Result<Response, AppError> {
    let app = state
        .app_repo
        .get_by_id(app_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| {
            AppError::not_found("APPLICATION_NOT_FOUND", "Application not found")
        })?;

    if !app.is_authorized {
        return Err(AppError::bad_request(
            "UNAUTHORIZED_TARGET",
            "Target application is not authorized for scanning",
        ));
    }

    let existing_scans = state
        .scan_repo
        .list_by_app(app_id, 1, 100)
        .await
        .map_err(AppError::from)?;

    let has_active = existing_scans.items.iter().any(|s| {
        matches!(
            s.status,
            ScanStatus::Queued
                | ScanStatus::Spidering
                | ScanStatus::ActiveScanning
                | ScanStatus::Ingesting
        )
    });

    if has_active {
        return Err(AppError::bad_request(
            "SCAN_ALREADY_IN_PROGRESS",
            "A scan is already in progress for this application",
        ));
    }

    let prev_scan_id = state
        .scan_repo
        .get_latest_completed_scan_id(app_id)
        .await
        .map_err(AppError::from)?;

    let scan = state
        .scan_repo
        .create(app_id, Some(auth.id), &req, prev_scan_id)
        .await
        .map_err(AppError::from)?;

    Ok((StatusCode::ACCEPTED, Json(scan)).into_response())
}

pub async fn list_scans_for_app_handler(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    AxumPath(app_id_str): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let app_id = Uuid::parse_str(&app_id_str)
        .map_err(|_| AppError::not_found("APPLICATION_NOT_FOUND", "Application not found"))?;

    if state
        .app_repo
        .get_by_id(app_id)
        .await
        .map_err(AppError::from)?
        .is_none()
    {
        return Err(AppError::not_found(
            "APPLICATION_NOT_FOUND",
            "Application not found",
        ));
    }

    let page = params
        .get("page")
        .and_then(|p| p.parse::<u64>().ok())
        .unwrap_or(1);
    let per_page = params
        .get("per_page")
        .and_then(|p| p.parse::<u64>().ok())
        .unwrap_or(20);

    let scans = state
        .scan_repo
        .list_by_app(app_id, page, per_page)
        .await
        .map_err(AppError::from)?;

    Ok((StatusCode::OK, Json(scans.items)).into_response())
}

pub async fn list_scans_global_handler(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    if let Some(app_id_str) = params.get("app_id").or_else(|| params.get("application_id")) {
        let app_id = Uuid::parse_str(app_id_str)
            .map_err(|_| AppError::not_found("APPLICATION_NOT_FOUND", "Application not found"))?;

        let page = params
            .get("page")
            .and_then(|p| p.parse::<u64>().ok())
            .unwrap_or(1);
        let per_page = params
            .get("per_page")
            .and_then(|p| p.parse::<u64>().ok())
            .unwrap_or(20);

        let scans = state
            .scan_repo
            .list_by_app(app_id, page, per_page)
            .await
            .map_err(AppError::from)?;

        Ok((StatusCode::OK, Json(scans.items)).into_response())
    } else {
        Ok((StatusCode::OK, Json(Vec::<ScanResponse>::new())).into_response())
    }
}

pub async fn get_scan_handler(
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

    Ok((StatusCode::OK, Json(scan)).into_response())
}

pub async fn cancel_scan_handler(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    AxumPath(scan_id_str): AxumPath<String>,
) -> Result<Response, AppError> {
    auth.require_analyst()?;

    let scan_id = Uuid::parse_str(&scan_id_str)
        .map_err(|_| AppError::not_found("SCAN_NOT_FOUND", "Scan not found"))?;

    let scan = state
        .scan_repo
        .get_by_id(scan_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("SCAN_NOT_FOUND", "Scan not found"))?;

    if matches!(
        scan.status,
        ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled
    ) {
        return Err(AppError::bad_request(
            "SCAN_CANNOT_BE_CANCELLED",
            "Scan cannot be cancelled in its current state",
        ));
    }

    state
        .scan_repo
        .cancel(scan_id)
        .await
        .map_err(AppError::from)?;

    let updated = state
        .scan_repo
        .get_by_id(scan_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("SCAN_NOT_FOUND", "Scan not found"))?;

    Ok((StatusCode::OK, Json(updated)).into_response())
}

pub async fn compare_scans_handler(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let base_str = params
        .get("base")
        .or_else(|| params.get("base_id"))
        .or_else(|| params.get("base_scan_id"))
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            AppError::bad_request("INVALID_INPUT", "Missing base scan ID parameter")
        })?;

    let target_str = params
        .get("target")
        .or_else(|| params.get("target_id"))
        .or_else(|| params.get("target_scan_id"))
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            AppError::bad_request("INVALID_INPUT", "Missing target scan ID parameter")
        })?;

    let base_id = Uuid::parse_str(base_str)
        .map_err(|_| AppError::bad_request("INVALID_INPUT", "Malformed base scan UUID"))?;

    let target_id = Uuid::parse_str(target_str)
        .map_err(|_| AppError::bad_request("INVALID_INPUT", "Malformed target scan UUID"))?;

    let base_scan = state
        .scan_repo
        .get_by_id(base_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("SCAN_NOT_FOUND", "Base scan not found"))?;

    let target_scan = state
        .scan_repo
        .get_by_id(target_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("SCAN_NOT_FOUND", "Target scan not found"))?;

    if base_scan.application_id != target_scan.application_id {
        return Err(AppError::bad_request(
            "INVALID_INPUT",
            "Cannot compare scans belonging to different applications",
        ));
    }

    let diff_summary = if base_id == target_id {
        ScanDiffSummary::default()
    } else {
        target_scan.diff_summary
    };

    let comparison = ScanComparisonResponse {
        base_scan_id: base_id,
        target_scan_id: target_id,
        diff_summary,
    };

    Ok((StatusCode::OK, Json(comparison)).into_response())
}

#[derive(serde::Deserialize, Default)]
pub struct FindingsQuery {
    pub severity: Option<String>,
    pub page: Option<u64>,
    pub per_page: Option<u64>,
}

pub async fn get_scan_findings_handler(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    AxumPath(scan_id_str): AxumPath<String>,
    Query(params): Query<FindingsQuery>,
) -> Result<Response, AppError> {
    let scan_id = Uuid::parse_str(&scan_id_str)
        .map_err(|_| AppError::not_found("SCAN_NOT_FOUND", "Scan not found"))?;

    if state
        .scan_repo
        .get_by_id(scan_id)
        .await
        .map_err(AppError::from)?
        .is_none()
    {
        return Err(AppError::not_found("SCAN_NOT_FOUND", "Scan not found"));
    }

    let page = params.page.unwrap_or(1);
    let per_page = params.per_page.unwrap_or(100);

    let findings_res = state
        .scan_repo
        .list_findings(scan_id, page, per_page)
        .await
        .map_err(AppError::from)?;

    let mut items = findings_res.items;
    if let Some(sev) = params.severity {
        let sev_clean = sev.to_lowercase();
        items.retain(|f| f.severity.as_str() == sev_clean);
    }

    Ok((StatusCode::OK, Json(items)).into_response())
}
