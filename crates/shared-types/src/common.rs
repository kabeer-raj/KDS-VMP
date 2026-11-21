use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorEnvelope {
    pub error: ErrorDetail,
}

impl ErrorEnvelope {
    pub fn new(code: impl Into<String>, message: impl Into<String>, request_id: impl Into<String>) -> Self {
        Self {
            error: ErrorDetail {
                code: code.into(),
                message: message.into(),
                request_id: request_id.into(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
    pub total_pages: u64,
}

impl<T> PaginatedResponse<T> {
    pub fn new(items: Vec<T>, total: u64, page: u64, per_page: u64) -> Self {
        let total_pages = if per_page == 0 {
            0
        } else {
            (total + per_page - 1) / per_page
        };
        Self {
            items,
            total,
            page,
            per_page,
            total_pages,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_envelope_serde() {
        let env = ErrorEnvelope::new(
            "UNAUTHORIZED_TARGET",
            "Explicit authorization flag must be verified before scanning.",
            "req_01J9X8K2M4N6P8Q0R2S4T6",
        );

        let json = serde_json::to_string(&env).unwrap();
        let expected = r#"{"error":{"code":"UNAUTHORIZED_TARGET","message":"Explicit authorization flag must be verified before scanning.","request_id":"req_01J9X8K2M4N6P8Q0R2S4T6"}}"#;
        assert_eq!(json, expected);

        let parsed: ErrorEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn test_paginated_response_calculation_and_serde() {
        let items = vec!["vuln_1".to_string(), "vuln_2".to_string()];
        let resp = PaginatedResponse::new(items, 45, 1, 10);
        assert_eq!(resp.total_pages, 5);
        assert_eq!(resp.page, 1);
        assert_eq!(resp.per_page, 10);

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: PaginatedResponse<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, resp);
    }
}
