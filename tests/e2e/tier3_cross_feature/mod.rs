//! Tier 3: Cross-Feature Combinations Integration Tests

pub mod auth_app_scan_flow;
pub mod scan_diff_triage_flow;
pub mod vuln_dashboard_sync;

#[cfg(test)]
mod tests {
    use crate::common::*;

    #[tokio::test]
    async fn tier3_cross_feature_bootstrap_check() {
        let app = TestApp::new().await;
        let seeded = app.seed_application("Cross-Feature App", "https://app.test", true).await;
        assert_eq!(seeded.name, "Cross-Feature App");
        assert!(seeded.is_authorized);
    }
}
