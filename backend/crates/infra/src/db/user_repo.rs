use async_trait::async_trait;
use chrono::Utc;
use sqlx::{PgPool, Row};
use std::str::FromStr;
use uuid::Uuid;

use crate::error::InfraError;
use crate::traits::UserRepository;
use shared_types::{ApiKeyResponse, CreateApiKeyRequest, UserProfile, UserRole};

pub struct PgUserRepo {
    pool: PgPool,
}

impl PgUserRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PgUserRepo {
    async fn find_by_email(&self, email: &str) -> Result<Option<UserProfile>, InfraError> {
        let row = sqlx::query(
            r#"
            SELECT id, email, full_name, role::text as role, is_active, last_login_at, created_at
            FROM users
            WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = row {
            let role_str: String = r.get("role");
            let role = UserRole::from_str(&role_str)
                .map_err(|e| InfraError::Database(sqlx::Error::Decode(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))))?;

            Ok(Some(UserProfile {
                id: r.get("id"),
                email: r.get("email"),
                full_name: r.get("full_name"),
                role,
                is_active: r.get("is_active"),
                last_login_at: r.get("last_login_at"),
                created_at: r.get("created_at"),
            }))
        } else {
            Ok(None)
        }
    }

    async fn find_by_id(&self, user_id: Uuid) -> Result<Option<UserProfile>, InfraError> {
        let row = sqlx::query(
            r#"
            SELECT id, email, full_name, role::text as role, is_active, last_login_at, created_at
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = row {
            let role_str: String = r.get("role");
            let role = UserRole::from_str(&role_str)
                .map_err(|e| InfraError::Database(sqlx::Error::Decode(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))))?;

            Ok(Some(UserProfile {
                id: r.get("id"),
                email: r.get("email"),
                full_name: r.get("full_name"),
                role,
                is_active: r.get("is_active"),
                last_login_at: r.get("last_login_at"),
                created_at: r.get("created_at"),
            }))
        } else {
            Ok(None)
        }
    }

    async fn get_password_hash(&self, email: &str) -> Result<Option<(UserProfile, String)>, InfraError> {
        let row = sqlx::query(
            r#"
            SELECT id, email, full_name, password_hash, role::text as role, is_active, last_login_at, created_at
            FROM users
            WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = row {
            let role_str: String = r.get("role");
            let role = UserRole::from_str(&role_str)
                .map_err(|e| InfraError::Database(sqlx::Error::Decode(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))))?;

            let profile = UserProfile {
                id: r.get("id"),
                email: r.get("email"),
                full_name: r.get("full_name"),
                role,
                is_active: r.get("is_active"),
                last_login_at: r.get("last_login_at"),
                created_at: r.get("created_at"),
            };
            let hash: String = r.get("password_hash");
            Ok(Some((profile, hash)))
        } else {
            Ok(None)
        }
    }

    async fn verify_password(&self, email: &str, password_hash: &str) -> Result<Option<UserProfile>, InfraError> {
        if let Some((profile, stored_hash)) = self.get_password_hash(email).await? {
            if stored_hash == password_hash {
                return Ok(Some(profile));
            }
        }
        Ok(None)
    }

    async fn create(&self, email: &str, full_name: &str, password_hash: &str, role: UserRole) -> Result<UserProfile, InfraError> {
        let row = sqlx::query(
            r#"
            INSERT INTO users (email, full_name, password_hash, role)
            VALUES ($1, $2, $3, $4::user_role)
            RETURNING id, email, full_name, role::text as role, is_active, last_login_at, created_at
            "#,
        )
        .bind(email)
        .bind(full_name)
        .bind(password_hash)
        .bind(role.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db_err) if db_err.is_unique_violation() => {
                InfraError::Conflict(format!("User with email {} already exists", email))
            }
            _ => InfraError::Database(e),
        })?;

        let role_str: String = row.get("role");
        let user_role = UserRole::from_str(&role_str)
            .map_err(|e| InfraError::Database(sqlx::Error::Decode(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))))?;

        Ok(UserProfile {
            id: row.get("id"),
            email: row.get("email"),
            full_name: row.get("full_name"),
            role: user_role,
            is_active: row.get("is_active"),
            last_login_at: row.get("last_login_at"),
            created_at: row.get("created_at"),
        })
    }

    async fn update_last_login(&self, user_id: Uuid) -> Result<(), InfraError> {
        let rows_affected = sqlx::query(
            r#"
            UPDATE users
            SET last_login_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?
        .rows_affected();

        if rows_affected == 0 {
            Err(InfraError::NotFound(format!("User {} not found", user_id)))
        } else {
            Ok(())
        }
    }

    async fn api_key_lookup(&self, key_hash: &str) -> Result<Option<(UserProfile, Uuid)>, InfraError> {
        let row = sqlx::query(
            r#"
            SELECT u.id, u.email, u.full_name, u.role::text as role, u.is_active, u.last_login_at, u.created_at,
                   k.id as key_id, k.expires_at
            FROM api_keys k
            JOIN users u ON k.user_id = u.id
            WHERE k.key_hash = $1
            "#,
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = row {
            let expires_at: Option<chrono::DateTime<Utc>> = r.get("expires_at");
            if let Some(exp) = expires_at {
                if exp < Utc::now() {
                    return Ok(None);
                }
            }

            let key_id: Uuid = r.get("key_id");
            let _ = sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1")
                .bind(key_id)
                .execute(&self.pool)
                .await;

            let role_str: String = r.get("role");
            let role = UserRole::from_str(&role_str)
                .map_err(|e| InfraError::Database(sqlx::Error::Decode(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))))?;

            let profile = UserProfile {
                id: r.get("id"),
                email: r.get("email"),
                full_name: r.get("full_name"),
                role,
                is_active: r.get("is_active"),
                last_login_at: r.get("last_login_at"),
                created_at: r.get("created_at"),
            };

            Ok(Some((profile, key_id)))
        } else {
            Ok(None)
        }
    }

    async fn create_api_key(&self, user_id: Uuid, req: &CreateApiKeyRequest, key_prefix: &str, key_hash: &str) -> Result<ApiKeyResponse, InfraError> {
        let expires_at = req.expires_at;

        let row = sqlx::query(
            r#"
            INSERT INTO api_keys (user_id, name, key_prefix, key_hash, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, name, key_prefix, created_at, expires_at, last_used_at
            "#,
        )
        .bind(user_id)
        .bind(&req.name)
        .bind(key_prefix)
        .bind(key_hash)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(ApiKeyResponse {
            id: row.get("id"),
            name: row.get("name"),
            key_prefix: row.get("key_prefix"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
            last_used_at: row.get("last_used_at"),
        })
    }

    async fn list_api_keys(&self, user_id: Uuid) -> Result<Vec<ApiKeyResponse>, InfraError> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, key_prefix, created_at, expires_at, last_used_at
            FROM api_keys
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let keys = rows
            .into_iter()
            .map(|r| ApiKeyResponse {
                id: r.get("id"),
                name: r.get("name"),
                key_prefix: r.get("key_prefix"),
                created_at: r.get("created_at"),
                expires_at: r.get("expires_at"),
                last_used_at: r.get("last_used_at"),
            })
            .collect();

        Ok(keys)
    }

    async fn revoke_api_key(&self, key_id: Uuid, user_id: Uuid) -> Result<bool, InfraError> {
        let rows_affected = sqlx::query(
            r#"
            DELETE FROM api_keys
            WHERE id = $1 AND user_id = $2
            "#,
        )
        .bind(key_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?
        .rows_affected();

        Ok(rows_affected > 0)
    }
}
