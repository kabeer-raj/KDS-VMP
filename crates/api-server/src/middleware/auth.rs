use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::header;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use shared_types::UserRole;

use crate::error::AppError;
use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub role: UserRole,
    pub exp: usize,
    pub iat: usize,
}

pub fn create_jwt_token(
    user_id: Uuid,
    email: &str,
    role: UserRole,
    secret: &str,
    ttl_minutes: i64,
) -> String {
    let now = Utc::now();
    let exp = (now + Duration::minutes(ttl_minutes)).timestamp() as usize;
    let iat = now.timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role,
        exp,
        iat,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("Failed to encode JWT token")
}

pub fn decode_jwt_token(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?;
    Ok(data.claims)
}

pub fn hash_password(plain: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plain.as_bytes());
    format!("$sha256${:x}", hasher.finalize())
}

pub fn verify_password_hash(plain: &str, stored_hash: &str) -> bool {
    if stored_hash.starts_with("$sha256$") {
        let computed = hash_password(plain);
        computed == stored_hash
    } else {
        stored_hash == plain
    }
}

pub fn hash_api_key(raw_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_key.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub id: Uuid,
    pub email: String,
    pub full_name: String,
    pub role: UserRole,
    pub is_api_key: bool,
    pub api_key_id: Option<Uuid>,
}

impl AuthenticatedUser {
    pub fn require_role(&self, allowed_roles: &[UserRole]) -> Result<(), AppError> {
        if !allowed_roles.contains(&self.role) {
            return Err(AppError::forbidden(
                "FORBIDDEN_RESOURCE",
                "Insufficient role privileges",
            ));
        }
        Ok(())
    }

    pub fn require_admin(&self) -> Result<(), AppError> {
        self.require_role(&[UserRole::Admin])
    }

    pub fn require_analyst(&self) -> Result<(), AppError> {
        self.require_role(&[UserRole::Admin, UserRole::SecurityEngineer])
    }

    pub fn require_developer(&self) -> Result<(), AppError> {
        self.require_role(&[
            UserRole::Admin,
            UserRole::SecurityEngineer,
            UserRole::Developer,
        ])
    }

    pub fn require_viewer(&self) -> Result<(), AppError> {
        self.require_role(&[
            UserRole::Admin,
            UserRole::SecurityEngineer,
            UserRole::Developer,
            UserRole::Auditor,
        ])
    }
}

#[async_trait]
impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // 1. Check Authorization Bearer header
        if let Some(auth_val) = parts.headers.get(header::AUTHORIZATION) {
            let auth_str = auth_val
                .to_str()
                .map_err(|_| AppError::unauthorized("INVALID_TOKEN", "Malformed Authorization header"))?;

            let token = auth_str
                .strip_prefix("Bearer ")
                .ok_or_else(|| AppError::unauthorized("INVALID_TOKEN", "Missing Bearer prefix"))?;

            if token.trim().is_empty() {
                return Err(AppError::unauthorized("INVALID_TOKEN", "Empty Bearer token"));
            }

            let claims = decode_jwt_token(token, &state.jwt_secret)
                .map_err(|_| AppError::unauthorized("INVALID_TOKEN", "Token validation failed"))?;

            let user_id = Uuid::parse_str(&claims.sub)
                .map_err(|_| AppError::unauthorized("INVALID_TOKEN", "Invalid subject in claims"))?;

            let user = state
                .user_repo
                .find_by_id(user_id)
                .await
                .map_err(|e| AppError::from(e))?
                .ok_or_else(|| AppError::unauthorized("INVALID_TOKEN", "User not found"))?;

            if !user.is_active {
                return Err(AppError::unauthorized(
                    "USER_INACTIVE",
                    "User account is deactivated",
                ));
            }

            return Ok(AuthenticatedUser {
                id: user.id,
                email: user.email,
                full_name: user.full_name,
                role: user.role,
                is_api_key: false,
                api_key_id: None,
            });
        }

        // 2. Check X-API-Key header (case-insensitive)
        if let Some(api_val) = parts.headers.get("x-api-key") {
            let key_str = api_val
                .to_str()
                .map_err(|_| AppError::unauthorized("INVALID_API_KEY", "Malformed API key header"))?;

            if key_str.is_empty() || !key_str.starts_with("appsec_live_") {
                return Err(AppError::unauthorized(
                    "INVALID_API_KEY",
                    "Invalid API key format",
                ));
            }

            let key_hash = hash_api_key(key_str);
            let lookup = state
                .user_repo
                .api_key_lookup(&key_hash)
                .await
                .map_err(|e| AppError::from(e))?;

            let (user, key_id) = lookup.ok_or_else(|| {
                AppError::unauthorized("INVALID_API_KEY", "API key not found or revoked")
            })?;

            if !user.is_active {
                return Err(AppError::unauthorized(
                    "USER_INACTIVE",
                    "User account is deactivated",
                ));
            }

            return Ok(AuthenticatedUser {
                id: user.id,
                email: user.email,
                full_name: user.full_name,
                role: user.role,
                is_api_key: true,
                api_key_id: Some(key_id),
            });
        }

        Err(AppError::unauthorized(
            "INVALID_TOKEN",
            "Missing Authorization or X-API-Key header",
        ))
    }
}
