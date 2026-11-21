//! Tier 1: Feature Coverage Integration Tests

pub mod app_tests;
pub mod auth_tests;
pub mod report_dashboard_tests;
pub mod scan_tests;
pub mod vuln_tests;

#[cfg(test)]
mod tests {
    use crate::common::*;

    #[tokio::test]
    async fn tier1_feature_coverage_bootstrap_check() {
        let app = TestApp::new().await;
        let (admin_id, token) = app.seed_admin().await;
        assert!(!token.is_empty(), "Admin token must not be empty");
        assert!(!admin_id.is_nil(), "Admin ID must not be nil");
    }
}
