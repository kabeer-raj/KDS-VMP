pub mod error;
pub mod middleware;
pub mod routes;
pub mod state;

pub use error::AppError;
pub use middleware::{
    create_jwt_token, decode_jwt_token, hash_api_key, hash_password, verify_password_hash,
    AuthenticatedUser, Claims,
};
pub use routes::create_router;
pub use state::{AppState, AuditRepository, PubSubAdapter, RefreshTokenRecord};

pub fn app(state: AppState) -> axum::Router {
    create_router(state)
}

pub async fn create_test_router() -> axum::Router {
    let state = AppState::new_in_memory();
    state.seed_default_users().await;
    create_router(state)
}

pub async fn create_test_app() -> (axum::Router, AppState) {
    let state = AppState::new_in_memory();
    state.seed_default_users().await;
    let router = create_router(state.clone());
    (router, state)
}
