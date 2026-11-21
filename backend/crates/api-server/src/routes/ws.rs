use std::collections::HashMap;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use uuid::Uuid;

use shared_types::WsServerEvent;

use crate::error::AppError;
use crate::middleware::decode_jwt_token;
use crate::state::AppState;

pub async fn ws_scan_progress_handler(
    State(state): State<AppState>,
    AxumPath(scan_id_str): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
    ws: Option<WebSocketUpgrade>,
) -> Result<Response, AppError> {
    let token = params
        .get("token")
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| AppError::unauthorized("UNAUTHORIZED", "Missing authentication token"))?;

    let claims = decode_jwt_token(token, &state.jwt_secret)
        .map_err(|_| AppError::unauthorized("INVALID_TOKEN", "Token validation failed"))?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::unauthorized("INVALID_TOKEN", "Invalid subject"))?;

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

    if let Some(upgrade) = ws {
        let pubsub = state.pubsub_adapter.clone();
        Ok(upgrade.on_upgrade(move |socket| handle_scan_socket(socket, scan_id, pubsub)))
    } else {
        Ok((
            StatusCode::OK,
            Json(json!({
                "status": "ws_handshake_accepted",
                "scan_id": scan_id
            })),
        )
            .into_response())
    }
}

pub async fn ws_notifications_handler(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    ws: Option<WebSocketUpgrade>,
) -> Result<Response, AppError> {
    let token = params
        .get("token")
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| AppError::unauthorized("UNAUTHORIZED", "Missing authentication token"))?;

    let claims = decode_jwt_token(token, &state.jwt_secret)
        .map_err(|_| AppError::unauthorized("INVALID_TOKEN", "Token validation failed"))?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::unauthorized("INVALID_TOKEN", "Invalid subject"))?;

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

    if let Some(upgrade) = ws {
        Ok(upgrade.on_upgrade(|mut socket| async move {
            let _ = socket.send(Message::Ping(vec![])).await;
        }))
    } else {
        Ok((
            StatusCode::OK,
            Json(json!({
                "status": "ws_notifications_accepted"
            })),
        )
            .into_response())
    }
}

async fn handle_scan_socket(
    socket: WebSocket,
    scan_id: Uuid,
    pubsub: std::sync::Arc<dyn infra::traits::PubSubPort>,
) {
    let (mut sender, mut receiver) = socket.split();

    let mut rx = match pubsub.subscribe_scan_progress(scan_id).await {
        Ok(rx) => rx,
        Err(_) => return,
    };

    let mut send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            let event_matches = match &event {
                WsServerEvent::ScanProgress(p) => p.scan_id == scan_id,
                WsServerEvent::ScanCompleted(c) => c.scan_id == scan_id,
                WsServerEvent::ScanFailed(f) => f.scan_id == scan_id,
            };

            if event_matches {
                if let Ok(json_str) = serde_json::to_string(&event) {
                    if sender.send(Message::Text(json_str)).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Close(_) = msg {
                break;
            }
        }
    });

    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };
}
