use std::collections::HashMap;
use axum::body::Bytes;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use uuid::Uuid;

use shared_types::{
    AppEnvironment, ConfigureAuthRequest, CreateApplicationRequest,
    UpdateApplicationRequest,
};

use crate::error::AppError;
use crate::middleware::AuthenticatedUser;
use crate::state::AppState;

pub async fn list_apps_handler(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let env_filter = params.get("environment").and_then(|e| {
        let clean = e.trim().to_lowercase();
        clean.parse::<AppEnvironment>().ok()
    });

    let apps = state
        .app_repo
        .list(None, env_filter)
        .await
        .map_err(AppError::from)?;

    Ok((StatusCode::OK, Json(apps)).into_response())
}

pub async fn create_app_handler(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    body: Bytes,
) -> Result<Response, AppError> {
    auth.require_analyst()?;

    let payload_val: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| AppError::bad_request("INVALID_PAYLOAD", "Malformed JSON body"))?;

    let is_auth = payload_val
        .get("is_authorized")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !is_auth {
        return Err(AppError::bad_request(
            "UNAUTHORIZED_TARGET",
            "Explicit authorization flag must be verified before scanning",
        ));
    }

    let name = payload_val
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();

    if name.is_empty() || name.len() > 150 {
        return Err(AppError::bad_request(
            "INVALID_APPLICATION_NAME",
            "Application name must be between 1 and 150 characters",
        ));
    }

    let base_url = payload_val
        .get("base_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();

    if (!base_url.starts_with("http://") && !base_url.starts_with("https://"))
        || base_url.starts_with("ftp://")
    {
        return Err(AppError::bad_request(
            "INVALID_APPLICATION_URL",
            "Application URL must start with http:// or https://",
        ));
    }

    // Check port if specified
    if let Some(pos) = base_url.rfind(':') {
        let remainder = &base_url[pos + 1..];
        let port_str: String = remainder.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !port_str.is_empty() {
            if let Ok(port) = port_str.parse::<u64>() {
                if port == 0 || port > 65535 {
                    return Err(AppError::bad_request(
                        "INVALID_APPLICATION_URL",
                        "Port out of valid range (1-65535)",
                    ));
                }
            }
        }
    }

    if let Some(desc) = payload_val.get("description").and_then(|v| v.as_str()) {
        if desc.len() > 4096 {
            return Err(AppError::bad_request(
                "INVALID_PAYLOAD",
                "Description exceeds maximum 4096 characters",
            ));
        }
    }

    let cron_schedule = payload_val.get("cron_schedule").and_then(|v| v.as_str());
    if let Some(cron) = cron_schedule {
        if cron.split_whitespace().count() != 5 {
            return Err(AppError::bad_request(
                "INVALID_CRON_SCHEDULE",
                "Cron schedule must follow standard 5-part format",
            ));
        }
    }

    let req: CreateApplicationRequest = serde_json::from_value(payload_val)
        .map_err(|_| AppError::bad_request("INVALID_PAYLOAD", "Deserialization failed"))?;

    // Check duplicate name and env
    let existing_apps = state
        .app_repo
        .list(None, Some(req.environment))
        .await
        .map_err(AppError::from)?;

    if existing_apps
        .iter()
        .any(|a| a.name.eq_ignore_ascii_case(&req.name) && a.environment == req.environment)
    {
        return Err(AppError::conflict(
            "DUPLICATE_APPLICATION",
            "An application with this name already exists in this environment",
        ));
    }

    let app = state
        .app_repo
        .create(&req, Some(auth.id))
        .await
        .map_err(AppError::from)?;

    Ok((StatusCode::CREATED, Json(app)).into_response())
}

pub async fn get_app_handler(
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
        .ok_or_else(|| {
            AppError::not_found("APPLICATION_NOT_FOUND", "Application not found")
        })?;

    Ok((StatusCode::OK, Json(app)).into_response())
}

pub async fn patch_app_handler(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    AxumPath(app_id_str): AxumPath<String>,
    body: Bytes,
) -> Result<Response, AppError> {
    auth.require_analyst()?;

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

    let req: UpdateApplicationRequest = serde_json::from_slice(&body)
        .map_err(|_| AppError::bad_request("INVALID_PAYLOAD", "Malformed update payload"))?;

    let updated = state
        .app_repo
        .update(app_id, &req)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| {
            AppError::not_found("APPLICATION_NOT_FOUND", "Application not found")
        })?;

    Ok((StatusCode::OK, Json(updated)).into_response())
}

pub async fn delete_app_handler(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    AxumPath(app_id_str): AxumPath<String>,
) -> Result<Response, AppError> {
    auth.require_admin()?;

    let app_id = Uuid::parse_str(&app_id_str)
        .map_err(|_| AppError::not_found("APPLICATION_NOT_FOUND", "Application not found"))?;

    let deleted = state
        .app_repo
        .delete(app_id)
        .await
        .map_err(AppError::from)?;

    if deleted {
        Ok((
            StatusCode::OK,
            Json(json!({"status": "deleted", "id": app_id})),
        )
            .into_response())
    } else {
        Err(AppError::not_found(
            "APPLICATION_NOT_FOUND",
            "Application not found",
        ))
    }
}

pub async fn configure_app_auth_handler(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    AxumPath(app_id_str): AxumPath<String>,
    body: Bytes,
) -> Result<Response, AppError> {
    auth.require_analyst()?;

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

    let payload: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| AppError::bad_request("INVALID_PAYLOAD", "Malformed JSON payload"))?;

    let auth_type = payload
        .get("auth_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let valid_types = ["bearer_token", "cookie", "header", "basic", "bearer"];
    if !valid_types.contains(&auth_type) {
        return Err(AppError::bad_request(
            "INVALID_AUTH_TYPE",
            "Unsupported application auth configuration type",
        ));
    }

    let auth_data = match payload.get("auth_data") {
        Some(v) if v.is_object() && !v.as_object().unwrap().is_empty() => v.clone(),
        _ => {
            return Err(AppError::bad_request(
                "INVALID_AUTH_DATA",
                "Auth data cannot be empty",
            ))
        }
    };

    let req = ConfigureAuthRequest {
        auth_type: auth_type.to_string(),
        auth_data,
    };

    state
        .app_repo
        .update_auth_config(app_id, &req)
        .await
        .map_err(AppError::from)?;

    Ok((
        StatusCode::OK,
        Json(json!({"status": "configured", "has_auth_configured": true})),
    )
        .into_response())
}

pub async fn get_app_trends_handler(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    AxumPath(app_id_str): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let app_id = Uuid::parse_str(&app_id_str).map_err(|_| {
        AppError::bad_request("INVALID_UUID", "Malformed application UUID in path")
    })?;

    if let Some(days_str) = params.get("days") {
        match days_str.parse::<i64>() {
            Ok(d) if d >= 0 => {}
            _ => {
                return Err(AppError::bad_request(
                    "INVALID_QUERY_PARAMETER",
                    "The days parameter must be a non-negative integer",
                ))
            }
        }
    }

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

    let trends = state
        .app_repo
        .get_trends(app_id)
        .await
        .map_err(AppError::from)?;

    Ok((StatusCode::OK, Json(trends)).into_response())
}
