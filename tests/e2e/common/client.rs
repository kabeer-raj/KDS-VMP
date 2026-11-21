use axum::body::Body;
use axum::Router;
use bytes::Bytes;
use http::{header, HeaderMap, Method, Request, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tower::ServiceExt;

use crate::common::assertions::ErrorEnvelope;

#[derive(Clone)]
pub struct TestClient {
    router: Router,
}

impl TestClient {
    pub fn new(router: Router) -> Self {
        Self { router }
    }

    pub fn router(&self) -> &Router {
        &self.router
    }

    pub async fn execute(&self, req: Request<Body>) -> (StatusCode, HeaderMap, Bytes) {
        let service = self.router.clone();
        let res = service
            .oneshot(req)
            .await
            .expect("tower::Service::oneshot failed");
        let status = res.status();
        let headers = res.headers().clone();
        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .expect("Failed to read response body bytes");
        (status, headers, body_bytes)
    }

    pub fn build_request(
        &self,
        method: Method,
        uri: &str,
        body: Option<Value>,
        token: Option<&str>,
        api_key: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);

        if let Some(t) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {}", t));
        } else if let Some(k) = api_key {
            builder = builder.header("X-API-Key", k);
        }

        let body_data = if let Some(b) = body {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&b).expect("Failed to serialize body to JSON"))
        } else {
            Body::empty()
        };

        builder.body(body_data).expect("Failed to build HTTP request")
    }

    pub async fn get(&self, uri: &str) -> (StatusCode, Bytes) {
        let req = self.build_request(Method::GET, uri, None, None, None);
        let (status, _, body) = self.execute(req).await;
        (status, body)
    }

    pub async fn get_auth(&self, uri: &str, token: &str) -> (StatusCode, Bytes) {
        let req = self.build_request(Method::GET, uri, None, Some(token), None);
        let (status, _, body) = self.execute(req).await;
        (status, body)
    }

    pub async fn get_api_key(&self, uri: &str, api_key: &str) -> (StatusCode, Bytes) {
        let req = self.build_request(Method::GET, uri, None, None, Some(api_key));
        let (status, _, body) = self.execute(req).await;
        (status, body)
    }

    pub async fn post_json(&self, uri: &str, body: Value) -> (StatusCode, Bytes) {
        let req = self.build_request(Method::POST, uri, Some(body), None, None);
        let (status, _, body) = self.execute(req).await;
        (status, body)
    }

    pub async fn post_json_auth(&self, uri: &str, body: Value, token: &str) -> (StatusCode, Bytes) {
        let req = self.build_request(Method::POST, uri, Some(body), Some(token), None);
        let (status, _, body) = self.execute(req).await;
        (status, body)
    }

    pub async fn post_json_api_key(&self, uri: &str, body: Value, api_key: &str) -> (StatusCode, Bytes) {
        let req = self.build_request(Method::POST, uri, Some(body), None, Some(api_key));
        let (status, _, body) = self.execute(req).await;
        (status, body)
    }

    pub async fn patch_json_auth(&self, uri: &str, body: Value, token: &str) -> (StatusCode, Bytes) {
        let req = self.build_request(Method::PATCH, uri, Some(body), Some(token), None);
        let (status, _, body) = self.execute(req).await;
        (status, body)
    }

    pub async fn put_json_auth(&self, uri: &str, body: Value, token: &str) -> (StatusCode, Bytes) {
        let req = self.build_request(Method::PUT, uri, Some(body), Some(token), None);
        let (status, _, body) = self.execute(req).await;
        (status, body)
    }

    pub async fn delete_auth(&self, uri: &str, token: &str) -> (StatusCode, Bytes) {
        let req = self.build_request(Method::DELETE, uri, None, Some(token), None);
        let (status, _, body) = self.execute(req).await;
        (status, body)
    }

    pub async fn json_request<T: DeserializeOwned>(
        &self,
        method: Method,
        uri: &str,
        body: Option<Value>,
        token: Option<&str>,
    ) -> (StatusCode, Result<T, ErrorEnvelope>) {
        let req = self.build_request(method, uri, body, token, None);
        let (status, _, body_bytes) = self.execute(req).await;

        if status.is_success() {
            match serde_json::from_slice::<T>(&body_bytes) {
                Ok(data) => (status, Ok(data)),
                Err(err) => panic!(
                    "Failed to deserialize response body to {}: {}. Raw body: {}",
                    std::any::type_name::<T>(),
                    err,
                    String::from_utf8_lossy(&body_bytes)
                ),
            }
        } else {
            let err_env: ErrorEnvelope = serde_json::from_slice(&body_bytes).unwrap_or_else(|e| {
                panic!(
                    "Expected ErrorEnvelope on HTTP {}, parse error: {}. Body: {}",
                    status,
                    e,
                    String::from_utf8_lossy(&body_bytes)
                )
            });
            (status, Err(err_env))
        }
    }

    pub async fn api_key_request<T: DeserializeOwned>(
        &self,
        method: Method,
        uri: &str,
        body: Option<Value>,
        api_key: &str,
    ) -> (StatusCode, Result<T, ErrorEnvelope>) {
        let req = self.build_request(method, uri, body, None, Some(api_key));
        let (status, _, body_bytes) = self.execute(req).await;

        if status.is_success() {
            match serde_json::from_slice::<T>(&body_bytes) {
                Ok(data) => (status, Ok(data)),
                Err(err) => panic!(
                    "Failed to deserialize response body to {}: {}. Raw body: {}",
                    std::any::type_name::<T>(),
                    err,
                    String::from_utf8_lossy(&body_bytes)
                ),
            }
        } else {
            let err_env: ErrorEnvelope = serde_json::from_slice(&body_bytes).unwrap_or_else(|e| {
                panic!(
                    "Expected ErrorEnvelope on HTTP {}, parse error: {}. Body: {}",
                    status,
                    e,
                    String::from_utf8_lossy(&body_bytes)
                )
            });
            (status, Err(err_env))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum::Json;
    use serde::{Deserialize, Serialize};

    async fn health_handler() -> &'static str {
        "OK"
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Resp {
        message: String,
    }

    async fn data_handler() -> Json<Resp> {
        Json(Resp {
            message: "hello".to_string(),
        })
    }

    #[tokio::test]
    async fn test_client_execute_health() {
        let app = Router::new().route("/health", get(health_handler));
        let client = TestClient::new(app);
        let (status, bytes) = client.get("/health").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&bytes[..], b"OK");
    }

    #[tokio::test]
    async fn test_client_json_request_success() {
        let app = Router::new().route("/data", get(data_handler));
        let client = TestClient::new(app);
        let (status, res) = client
            .json_request::<Resp>(Method::GET, "/data", None, None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(res.unwrap().message, "hello");
    }
}
