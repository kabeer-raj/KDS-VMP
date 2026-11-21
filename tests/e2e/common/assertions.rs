use http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorEnvelope {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    pub request_id: String,
}

pub fn assert_error_response(
    status: StatusCode,
    body_bytes: &[u8],
    expected_status: StatusCode,
    expected_code: &str,
) -> ErrorDetail {
    assert_eq!(
        status, expected_status,
        "Expected HTTP status {}, but got {}. Response body: {}",
        expected_status, status, String::from_utf8_lossy(body_bytes)
    );
    let envelope: ErrorEnvelope = serde_json::from_slice(body_bytes).unwrap_or_else(|e| {
        panic!(
            "Failed to parse error envelope from body: {}. Raw body: {}",
            e, String::from_utf8_lossy(body_bytes)
        )
    });
    assert_eq!(
        envelope.error.code, expected_code,
        "Expected error code '{}', but got '{}'. Message: {}",
        expected_code, envelope.error.code, envelope.error.message
    );
    assert!(!envelope.error.message.is_empty(), "Error message must not be empty");
    assert!(!envelope.error.request_id.is_empty(), "Error request_id must not be empty");
    envelope.error
}

#[macro_export]
macro_rules! assert_err_code {
    ($status:expr, $body:expr, $expected_status:expr, $expected_code:expr) => {
        $crate::common::assertions::assert_error_response(
            $status, $body, $expected_status, $expected_code,
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assert_error_response_valid() {
        let json_body = br#"{"error":{"code":"UNAUTHORIZED_TARGET","message":"Target not authorized","request_id":"req_12345"}}"#;
        let detail = assert_error_response(
            StatusCode::BAD_REQUEST,
            json_body,
            StatusCode::BAD_REQUEST,
            "UNAUTHORIZED_TARGET",
        );
        assert_eq!(detail.code, "UNAUTHORIZED_TARGET");
        assert_eq!(detail.message, "Target not authorized");
        assert_eq!(detail.request_id, "req_12345");
    }

    #[test]
    #[should_panic(expected = "Expected HTTP status")]
    fn test_assert_error_response_wrong_status() {
        let json_body = br#"{"error":{"code":"UNAUTHORIZED_TARGET","message":"Target not authorized","request_id":"req_12345"}}"#;
        assert_error_response(
            StatusCode::OK,
            json_body,
            StatusCode::BAD_REQUEST,
            "UNAUTHORIZED_TARGET",
        );
    }

    #[test]
    #[should_panic(expected = "Expected error code")]
    fn test_assert_error_response_wrong_code() {
        let json_body = br#"{"error":{"code":"OTHER_ERROR","message":"Some error","request_id":"req_12345"}}"#;
        assert_error_response(
            StatusCode::BAD_REQUEST,
            json_body,
            StatusCode::BAD_REQUEST,
            "UNAUTHORIZED_TARGET",
        );
    }
}
