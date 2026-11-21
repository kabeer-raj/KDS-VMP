use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use shared_types::{
    CreateApiKeyRequest, CreateApiKeyResponse, TokenResponse,
};

use crate::error::AppError;
use crate::middleware::{
    create_jwt_token, hash_api_key, verify_password_hash, AuthenticatedUser,
};
use crate::state::AppState;

pub async fn login_handler(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Response, AppError> {
    let payload: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| AppError::bad_request("VALIDATION_ERROR", "Invalid JSON payload"))?;

    let email = payload
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let password = payload
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if email.is_empty() || password.is_empty() {
        return Err(AppError::bad_request(
            "VALIDATION_ERROR",
            "Email and password must not be empty",
        ));
    }

    let user_info = state
        .user_repo
        .get_password_hash(email)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| {
            AppError::unauthorized("INVALID_CREDENTIALS", "Invalid email or password")
        })?;

    let (mut user, stored_hash) = user_info;

    if !verify_password_hash(password, &stored_hash) {
        return Err(AppError::unauthorized(
            "INVALID_CREDENTIALS",
            "Invalid email or password",
        ));
    }

    if !user.is_active {
        return Err(AppError::unauthorized(
            "USER_INACTIVE",
            "User account is deactivated",
        ));
    }

    let _ = state.user_repo.update_last_login(user.id).await;
    user.last_login_at = Some(Utc::now());

    let access_token = create_jwt_token(
        user.id,
        &user.email,
        user.role,
        &state.jwt_secret,
        15,
    );

    let refresh_token = format!(
        "refresh_{}_{}",
        user.id.simple(),
        Uuid::new_v4().simple()
    );

    state.store_refresh_token(user.id, &refresh_token, 7).await;

    let resp = TokenResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: 900,
        user,
    };

    Ok((StatusCode::OK, Json(resp)).into_response())
}

pub async fn refresh_handler(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Response, AppError> {
    let payload: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| AppError::bad_request("VALIDATION_ERROR", "Invalid JSON payload"))?;

    let rt = payload
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();

    if rt.is_empty() || !rt.starts_with("refresh_") {
        return Err(AppError::unauthorized(
            "INVALID_REFRESH_TOKEN",
            "Invalid refresh token signature or format",
        ));
    }

    let new_rt = format!(
        "refresh_{}_{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );

    let user_id = state.rotate_refresh_token(rt, &new_rt, 7).await?;

    let user = state
        .user_repo
        .find_by_id(user_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::unauthorized("INVALID_TOKEN", "User not found"))?;

    if !user.is_active {
        return Err(AppError::unauthorized(
            "USER_INACTIVE",
            "User account is deactivated",
        ));
    }

    let access_token = create_jwt_token(
        user.id,
        &user.email,
        user.role,
        &state.jwt_secret,
        15,
    );

    let resp = TokenResponse {
        access_token,
        refresh_token: new_rt,
        token_type: "Bearer".to_string(),
        expires_in: 900,
        user,
    };

    Ok((StatusCode::OK, Json(resp)).into_response())
}

pub async fn logout_handler(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    body: Bytes,
) -> Result<Response, AppError> {
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&body) {
        if let Some(rt) = val.get("refresh_token").and_then(|v| v.as_str()) {
            state.revoke_refresh_token(rt).await;
        } else {
            state.revoke_all_refresh_tokens_for_user(auth.id).await;
        }
    } else {
        state.revoke_all_refresh_tokens_for_user(auth.id).await;
    }

    Ok((StatusCode::OK, Json(json!({"status": "logged_out"}))).into_response())
}

pub async fn me_handler(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Response, AppError> {
    let user = state
        .user_repo
        .find_by_id(auth.id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::unauthorized("INVALID_TOKEN", "User not found"))?;

    Ok((StatusCode::OK, Json(user)).into_response())
}

pub async fn list_api_keys_handler(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Response, AppError> {
    auth.require_analyst()?;

    let keys = state
        .user_repo
        .list_api_keys(auth.id)
        .await
        .map_err(AppError::from)?;

    Ok((StatusCode::OK, Json(keys)).into_response())
}

pub async fn create_api_key_handler(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    body: Bytes,
) -> Result<Response, AppError> {
    auth.require_analyst()?;

    let payload: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| AppError::bad_request("INVALID_PAYLOAD", "Malformed JSON body"))?;

    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();

    if name.is_empty() || name.len() > 100 {
        return Err(AppError::bad_request(
            "INVALID_API_KEY_NAME",
            "API key name must be between 1 and 100 characters",
        ));
    }

    let expires_at = if let Some(exp_val) = payload.get("expires_at") {
        if !exp_val.is_null() {
            match serde_json::from_value::<chrono::DateTime<Utc>>(exp_val.clone()) {
                Ok(exp) => {
                    if exp <= Utc::now() {
                        return Err(AppError::bad_request(
                            "INVALID_EXPIRATION",
                            "API key expiration must be in the future",
                        ));
                    }
                    Some(exp)
                }
                Err(_) => {
                    return Err(AppError::bad_request(
                        "INVALID_EXPIRATION",
                        "Invalid expiration timestamp format",
                    ))
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    let raw_secret = format!(
        "appsec_live_{}_{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    let prefix = raw_secret[..12].to_string();
    let hash = hash_api_key(&raw_secret);

    let create_req = CreateApiKeyRequest {
        name: name.to_string(),
        expires_at,
    };

    let key_resp = state
        .user_repo
        .create_api_key(auth.id, &create_req, &prefix, &hash)
        .await
        .map_err(AppError::from)?;

    let resp = CreateApiKeyResponse {
        id: key_resp.id,
        name: key_resp.name,
        key_prefix: key_resp.key_prefix,
        secret_key: raw_secret,
        expires_at: key_resp.expires_at,
        created_at: key_resp.created_at,
    };

    Ok((StatusCode::CREATED, Json(resp)).into_response())
}

pub async fn delete_api_key_handler(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    AxumPath(key_id_str): AxumPath<String>,
) -> Result<Response, AppError> {
    auth.require_analyst()?;

    let key_id = Uuid::parse_str(&key_id_str)
        .map_err(|_| AppError::not_found("API_KEY_NOT_FOUND", "API key not found"))?;

    let revoked = state
        .user_repo
        .revoke_api_key(key_id, auth.id)
        .await
        .map_err(AppError::from)?;

    if revoked {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(AppError::not_found(
            "API_KEY_NOT_FOUND",
            "API key not found",
        ))
    }
}
