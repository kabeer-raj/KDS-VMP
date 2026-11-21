use std::fmt;
use std::str::FromStr;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Admin,
    SecurityEngineer,
    Developer,
    Auditor,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::SecurityEngineer => "security_engineer",
            Self::Developer => "developer",
            Self::Auditor => "auditor",
        }
    }
}

impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for UserRole {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Self::Admin),
            "security_engineer" => Ok(Self::SecurityEngineer),
            "developer" => Ok(Self::Developer),
            "auditor" => Ok(Self::Auditor),
            other => Err(format!("Unknown user role: {other}")),
        }
    }
}

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

pub fn create_expired_jwt_token(
    user_id: Uuid,
    email: &str,
    role: UserRole,
    secret: &str,
) -> String {
    let now = Utc::now();
    let exp = (now - Duration::hours(1)).timestamp() as usize;
    let iat = (now - Duration::hours(2)).timestamp() as usize;

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
    .expect("Failed to encode expired JWT token")
}

pub fn create_tampered_jwt_token(
    user_id: Uuid,
    email: &str,
    role: UserRole,
) -> String {
    create_jwt_token(user_id, email, role, "tampered_invalid_secret_key_12345", 15)
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

pub fn hash_api_key(raw_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_key.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_create_and_decode() {
        let secret = "super_secret_test_key_kds_appsec_platform";
        let user_id = Uuid::new_v4();
        let email = "admin@kds.local";
        let token = create_jwt_token(user_id, email, UserRole::Admin, secret, 15);

        let claims = decode_jwt_token(&token, secret).expect("Token should decode successfully");
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, email);
        assert_eq!(claims.role, UserRole::Admin);
    }

    #[test]
    fn test_jwt_expired() {
        let secret = "super_secret_test_key_kds_appsec_platform";
        let user_id = Uuid::new_v4();
        let token = create_expired_jwt_token(user_id, "expired@kds.local", UserRole::Developer, secret);

        let res = decode_jwt_token(&token, secret);
        assert!(res.is_err(), "Expired token must fail validation");
    }

    #[test]
    fn test_jwt_tampered() {
        let secret = "super_secret_test_key_kds_appsec_platform";
        let user_id = Uuid::new_v4();
        let token = create_tampered_jwt_token(user_id, "tampered@kds.local", UserRole::SecurityEngineer);

        let res = decode_jwt_token(&token, secret);
        assert!(res.is_err(), "Tampered token must fail signature check");
    }

    #[test]
    fn test_hashing() {
        let pass_hash1 = hash_password("Password123!");
        let pass_hash2 = hash_password("Password123!");
        assert_eq!(pass_hash1, pass_hash2);
        assert!(pass_hash1.starts_with("$sha256$"));

        let key_hash = hash_api_key("appsec_live_1234567890abcdef");
        assert_eq!(key_hash.len(), 64);
    }
}
