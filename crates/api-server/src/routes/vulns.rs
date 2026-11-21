use std::collections::HashMap;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use uuid::Uuid;

use infra::traits::VulnFilter;
use shared_types::{
    AddCommentRequest, BulkUpdateResponse, BulkUpdateVulnsRequest, RemediationStatus,
    SeverityLevel, UpdateVulnerabilityRequest,
};

use crate::error::AppError;
use crate::middleware::AuthenticatedUser;
use crate::state::AppState;

pub async fn list_vulns_handler(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let app_id = params
        .get("app_id")
        .or_else(|| params.get("application_id"))
        .and_then(|s| Uuid::parse_str(s).ok());

    let severity = params
        .get("severity")
        .and_then(|s| s.parse::<SeverityLevel>().ok());

    let status = params
        .get("status")
        .and_then(|s| s.parse::<RemediationStatus>().ok());

    let owasp_category = params.get("owasp_category").cloned();

    let assigned_to = params
        .get("assigned_to")
        .and_then(|s| Uuid::parse_str(s).ok());

    let search = params.get("search").cloned();
    let sort_by = params.get("sort_by").cloned();
    let order = params.get("order").cloned();

    let page = params
        .get("page")
        .and_then(|p| p.parse::<u64>().ok())
        .unwrap_or(1);
    let per_page = params
        .get("per_page")
        .and_then(|p| p.parse::<u64>().ok())
        .unwrap_or(20);

    let filter = VulnFilter {
        app_id,
        severity,
        status,
        owasp_category,
        assigned_to,
        search,
        sort_by,
        order,
    };

    let result = state
        .vuln_repo
        .list_with_filters(&filter, page, per_page)
        .await
        .map_err(AppError::from)?;

    Ok((StatusCode::OK, Json(result)).into_response())
}

pub async fn get_vuln_handler(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    AxumPath(vuln_id_str): AxumPath<String>,
) -> Result<Response, AppError> {
    let vuln_id = Uuid::parse_str(&vuln_id_str)
        .map_err(|_| AppError::not_found("VULNERABILITY_NOT_FOUND", "Vulnerability not found"))?;

    let vuln = state
        .vuln_repo
        .get_by_id(vuln_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| {
            AppError::not_found("VULNERABILITY_NOT_FOUND", "Vulnerability not found")
        })?;

    Ok((StatusCode::OK, Json(vuln)).into_response())
}

pub async fn patch_vuln_handler(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    AxumPath(vuln_id_str): AxumPath<String>,
    Json(payload): Json<UpdateVulnerabilityRequest>,
) -> Result<Response, AppError> {
    auth.require_developer()?;

    let vuln_id = Uuid::parse_str(&vuln_id_str)
        .map_err(|_| AppError::not_found("VULNERABILITY_NOT_FOUND", "Vulnerability not found"))?;

    let updated = state
        .vuln_repo
        .update_triage(vuln_id, &payload, Some(auth.id))
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| {
            AppError::not_found("VULNERABILITY_NOT_FOUND", "Vulnerability not found")
        })?;

    Ok((StatusCode::OK, Json(updated)).into_response())
}

pub async fn bulk_update_vulns_handler(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Json(payload): Json<BulkUpdateVulnsRequest>,
) -> Result<Response, AppError> {
    auth.require_developer()?;

    let updated_count = state
        .vuln_repo
        .bulk_update(&payload, Some(auth.id))
        .await
        .map_err(AppError::from)?;

    let resp = BulkUpdateResponse { updated_count };
    Ok((StatusCode::OK, Json(resp)).into_response())
}

pub async fn get_vuln_history_handler(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    AxumPath(vuln_id_str): AxumPath<String>,
) -> Result<Response, AppError> {
    let vuln_id = Uuid::parse_str(&vuln_id_str)
        .map_err(|_| AppError::not_found("VULNERABILITY_NOT_FOUND", "Vulnerability not found"))?;

    if state
        .vuln_repo
        .get_by_id(vuln_id)
        .await
        .map_err(AppError::from)?
        .is_none()
    {
        return Err(AppError::not_found(
            "VULNERABILITY_NOT_FOUND",
            "Vulnerability not found",
        ));
    }

    let history = state
        .vuln_repo
        .get_history(vuln_id)
        .await
        .map_err(AppError::from)?;

    Ok((StatusCode::OK, Json(history)).into_response())
}

pub async fn add_vuln_comment_handler(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    AxumPath(vuln_id_str): AxumPath<String>,
    Json(payload): Json<AddCommentRequest>,
) -> Result<Response, AppError> {
    auth.require_developer()?;

    let vuln_id = Uuid::parse_str(&vuln_id_str)
        .map_err(|_| AppError::not_found("VULNERABILITY_NOT_FOUND", "Vulnerability not found"))?;

    if payload.comment.trim().is_empty() {
        return Err(AppError::bad_request(
            "VALIDATION_ERROR",
            "Comment must not be empty",
        ));
    }

    let log = state
        .vuln_repo
        .add_comment(vuln_id, &payload.comment, Some(auth.id))
        .await
        .map_err(AppError::from)?;

    Ok((StatusCode::CREATED, Json(log)).into_response())
}
