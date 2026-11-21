use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::InfraError;
use crate::traits::UserRepository;
use shared_types::{ApiKeyResponse, CreateApiKeyRequest, UserProfile, UserRole};

pub struct InMemoryUserRepo {
    users: RwLock<HashMap<Uuid, UserProfile>>,
    passwords: RwLock<HashMap<String, (Uuid, String)>>, // email_lower -> (user_id, password_hash)
    api_keys: RwLock<HashMap<Uuid, (ApiKeyResponse, Uuid)>>, // key_id -> (key_response, user_id)
    key_hashes: RwLock<HashMap<String, (Uuid, Uuid)>>,  // key_hash -> (key_id, user_id)
}

impl InMemoryUserRepo {
    pub fn new() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            passwords: RwLock::new(HashMap::new()),
            api_keys: RwLock::new(HashMap::new()),
            key_hashes: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryUserRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UserRepository for InMemoryUserRepo {
    async fn find_by_email(&self, email: &str) -> Result<Option<UserProfile>, InfraError> {
        let passwords = self.passwords.read().await;
        if let Some((user_id, _)) = passwords.get(&email.to_lowercase()) {
            let users = self.users.read().await;
            Ok(users.get(user_id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn find_by_id(&self, user_id: Uuid) -> Result<Option<UserProfile>, InfraError> {
        let users = self.users.read().await;
        Ok(users.get(&user_id).cloned())
    }

    async fn get_password_hash(&self, email: &str) -> Result<Option<(UserProfile, String)>, InfraError> {
        let passwords = self.passwords.read().await;
        if let Some((user_id, hash)) = passwords.get(&email.to_lowercase()) {
            let users = self.users.read().await;
            if let Some(user) = users.get(user_id) {
                return Ok(Some((user.clone(), hash.clone())));
            }
        }
        Ok(None)
    }

    async fn verify_password(&self, email: &str, password_hash: &str) -> Result<Option<UserProfile>, InfraError> {
        let passwords = self.passwords.read().await;
        if let Some((user_id, stored_hash)) = passwords.get(&email.to_lowercase()) {
            if stored_hash == password_hash {
                let users = self.users.read().await;
                return Ok(users.get(user_id).cloned());
            }
        }
        Ok(None)
    }

    async fn create(&self, email: &str, full_name: &str, password_hash: &str, role: UserRole) -> Result<UserProfile, InfraError> {
        let mut passwords = self.passwords.write().await;
        let email_lower = email.to_lowercase();
        if passwords.contains_key(&email_lower) {
            return Err(InfraError::Conflict(format!("User with email {} already exists", email)));
        }

        let user_id = Uuid::new_v4();
        let now = Utc::now();
        let profile = UserProfile {
            id: user_id,
            email: email.to_string(),
            full_name: full_name.to_string(),
            role,
            is_active: true,
            last_login_at: None,
            created_at: now,
        };

        let mut users = self.users.write().await;
        users.insert(user_id, profile.clone());
        passwords.insert(email_lower, (user_id, password_hash.to_string()));

        Ok(profile)
    }

    async fn update_last_login(&self, user_id: Uuid) -> Result<(), InfraError> {
        let mut users = self.users.write().await;
        if let Some(user) = users.get_mut(&user_id) {
            user.last_login_at = Some(Utc::now());
            Ok(())
        } else {
            Err(InfraError::NotFound(format!("User with id {} not found", user_id)))
        }
    }

    async fn api_key_lookup(&self, key_hash: &str) -> Result<Option<(UserProfile, Uuid)>, InfraError> {
        let key_hashes = self.key_hashes.read().await;
        if let Some(&(key_id, user_id)) = key_hashes.get(key_hash) {
            let mut api_keys = self.api_keys.write().await;
            if let Some((key_resp, _)) = api_keys.get_mut(&key_id) {
                if let Some(exp) = key_resp.expires_at {
                    if exp < Utc::now() {
                        return Ok(None);
                    }
                }
                key_resp.last_used_at = Some(Utc::now());
                let users = self.users.read().await;
                if let Some(user) = users.get(&user_id) {
                    return Ok(Some((user.clone(), key_id)));
                }
            }
        }
        Ok(None)
    }

    async fn create_api_key(&self, user_id: Uuid, req: &CreateApiKeyRequest, key_prefix: &str, key_hash: &str) -> Result<ApiKeyResponse, InfraError> {
        let key_id = Uuid::new_v4();
        let now = Utc::now();

        let api_key = ApiKeyResponse {
            id: key_id,
            name: req.name.clone(),
            key_prefix: key_prefix.to_string(),
            created_at: now,
            expires_at: req.expires_at,
            last_used_at: None,
        };

        let mut api_keys = self.api_keys.write().await;
        api_keys.insert(key_id, (api_key.clone(), user_id));

        let mut key_hashes = self.key_hashes.write().await;
        key_hashes.insert(key_hash.to_string(), (key_id, user_id));

        Ok(api_key)
    }

    async fn list_api_keys(&self, user_id: Uuid) -> Result<Vec<ApiKeyResponse>, InfraError> {
        let api_keys = self.api_keys.read().await;
        let mut keys: Vec<ApiKeyResponse> = api_keys
            .values()
            .filter(|(_, uid)| *uid == user_id)
            .map(|(key, _)| key.clone())
            .collect();
        keys.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(keys)
    }

    async fn revoke_api_key(&self, key_id: Uuid, user_id: Uuid) -> Result<bool, InfraError> {
        let mut api_keys = self.api_keys.write().await;
        if let Some((_, owner_id)) = api_keys.get(&key_id) {
            if *owner_id != user_id {
                return Ok(false);
            }
            api_keys.remove(&key_id);
            let mut key_hashes = self.key_hashes.write().await;
            key_hashes.retain(|_, (kid, _)| *kid != key_id);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
