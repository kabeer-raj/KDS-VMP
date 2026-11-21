use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::enums::UserRole;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserProfile {
    pub id: Uuid,
    pub email: String,
    pub full_name: String,
    pub role: UserRole,
    pub is_active: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String, // "Bearer"
    pub expires_in: i64,    // e.g. 900
    pub user: UserProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiKeyResponse {
    pub id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateApiKeyResponse {
    pub id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub secret_key: String, // Exposed only once upon creation
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_request_serde() {
        let req = LoginRequest {
            email: "admin@kds.local".to_string(),
            password: "super_secret_password".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: LoginRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn test_user_profile_serde() {
        let user_id = Uuid::new_v4();
        let now = Utc::now();
        let profile = UserProfile {
            id: user_id,
            email: "dev@kds.local".to_string(),
            full_name: "Alice Engineer".to_string(),
            role: UserRole::Developer,
            is_active: true,
            last_login_at: Some(now),
            created_at: now,
        };

        let json = serde_json::to_string(&profile).unwrap();
        let parsed: UserProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, profile);
        assert_eq!(parsed.role, UserRole::Developer);
    }

    #[test]
    fn test_token_response_serde() {
        let user_id = Uuid::new_v4();
        let now = Utc::now();
        let resp = TokenResponse {
            access_token: "jwt.access.token".to_string(),
            refresh_token: "jwt.refresh.token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 900,
            user: UserProfile {
                id: user_id,
                email: "seceng@kds.local".to_string(),
                full_name: "Bob Security".to_string(),
                role: UserRole::SecurityEngineer,
                is_active: true,
                last_login_at: None,
                created_at: now,
            },
        };

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: TokenResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
        assert_eq!(parsed.token_type, "Bearer");
        assert_eq!(parsed.expires_in, 900);
    }

    #[test]
    fn test_refresh_token_request_serde() {
        let req = RefreshTokenRequest {
            refresh_token: "valid_refresh_token_xyz".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: RefreshTokenRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn test_api_key_response_and_create_serde() {
        let key_id = Uuid::new_v4();
        let now = Utc::now();

        // Listing response: secret_key is NOT present
        let resp = ApiKeyResponse {
            id: key_id,
            name: "GitHub Actions CI".to_string(),
            key_prefix: "kds_live_a1b2".to_string(),
            expires_at: None,
            last_used_at: Some(now),
            created_at: now,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("secret_key").is_none());
        let parsed: ApiKeyResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);

        // Creation request & response
        let create_req = CreateApiKeyRequest {
            name: "Jenkins Pipeline".to_string(),
            expires_at: Some(now),
        };
        let create_json = serde_json::to_string(&create_req).unwrap();
        let parsed_req: CreateApiKeyRequest = serde_json::from_str(&create_json).unwrap();
        assert_eq!(parsed_req, create_req);

        let create_resp = CreateApiKeyResponse {
            id: key_id,
            name: "Jenkins Pipeline".to_string(),
            key_prefix: "kds_live_c3d4".to_string(),
            secret_key: "kds_live_c3d4_9876543210abcdef".to_string(),
            expires_at: Some(now),
            created_at: now,
        };
        let create_resp_json = serde_json::to_string(&create_resp).unwrap();
        let parsed_create_resp: CreateApiKeyResponse = serde_json::from_str(&create_resp_json).unwrap();
        assert_eq!(parsed_create_resp, create_resp);
        assert_eq!(parsed_create_resp.secret_key, "kds_live_c3d4_9876543210abcdef");
    }
}
