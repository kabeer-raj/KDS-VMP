#![allow(dead_code, unused_imports, unused_variables)]

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

use api_server::{create_jwt_token, create_test_app, AppState};
use shared_types::UserRole;

pub struct TestHarness {
    pub app: axum::Router,
    pub state: AppState,
}

impl TestHarness {
    pub async fn new() -> Self {
        let (app, state) = create_test_app().await;
        Self { app, state }
    }

    pub async fn token_for_email(&self, email: &str) -> String {
        let user = self
            .state
            .user_repo
            .find_by_email(email)
            .await
            .unwrap()
            .expect("User not found");
        create_jwt_token(user.id, &user.email, user.role, &self.state.jwt_secret, 15)
    }

    pub async fn admin_token(&self) -> String {
        self.token_for_email("admin@kds.local").await
    }

    pub async fn seceng_token(&self) -> String {
        self.token_for_email("seceng@kds.local").await
    }

    pub async fn dev_token(&self) -> String {
        self.token_for_email("dev@kds.local").await
    }

    pub async fn auditor_token(&self) -> String {
        self.token_for_email("auditor@kds.local").await
    }

    pub async fn request(
        &self,
        method: Method,
        uri: &str,
        token: Option<&str>,
        api_key: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, HeaderMapRef, Vec<u8>) {
        let mut builder = Request::builder().method(method).uri(uri);

        if let Some(t) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", t));
        }
        if let Some(k) = api_key {
            builder = builder.header("X-API-Key", k);
        }

        let req_body = if let Some(b) = body {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&b).unwrap())
        } else {
            Body::empty()
        };

        let req = builder.body(req_body).unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();

        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();

        (status, HeaderMapRef(headers), bytes)
    }

    pub async fn get(&self, uri: &str) -> (StatusCode, Vec<u8>) {
        let (status, _, body) = self.request(Method::GET, uri, None, None, None).await;
        (status, body)
    }

    pub async fn get_auth(&self, uri: &str, token: &str) -> (StatusCode, Vec<u8>) {
        let (status, _, body) = self.request(Method::GET, uri, Some(token), None, None).await;
        (status, body)
    }

    pub async fn post_json(&self, uri: &str, payload: Value) -> (StatusCode, Vec<u8>) {
        let (status, _, body) = self.request(Method::POST, uri, None, None, Some(payload)).await;
        (status, body)
    }

    pub async fn post_json_auth(
        &self,
        uri: &str,
        payload: Value,
        token: &str,
    ) -> (StatusCode, Vec<u8>) {
        let (status, _, body) = self
            .request(Method::POST, uri, Some(token), None, Some(payload))
            .await;
        (status, body)
    }

    pub async fn patch_json_auth(
        &self,
        uri: &str,
        payload: Value,
        token: &str,
    ) -> (StatusCode, Vec<u8>) {
        let (status, _, body) = self
            .request(Method::PATCH, uri, Some(token), None, Some(payload))
            .await;
        (status, body)
    }

    pub async fn put_json_auth(
        &self,
        uri: &str,
        payload: Value,
        token: &str,
    ) -> (StatusCode, Vec<u8>) {
        let (status, _, body) = self
            .request(Method::PUT, uri, Some(token), None, Some(payload))
            .await;
        (status, body)
    }

    pub async fn delete_auth(&self, uri: &str, token: &str) -> (StatusCode, Vec<u8>) {
        let (status, _, body) = self.request(Method::DELETE, uri, Some(token), None, None).await;
        (status, body)
    }
}

pub struct HeaderMapRef(pub axum::http::HeaderMap);

impl HeaderMapRef {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }
}

pub fn parse_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
    serde_json::from_slice(bytes).expect("Failed to deserialize response JSON")
}
