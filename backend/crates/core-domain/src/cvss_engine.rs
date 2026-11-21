//! CVSS v3.1 Scoring Engine & Asset Risk Weighter
//!
//! Implements FIRST CVSS v3.1 base score computation, Appendix A integer roundup,
//! qualitative severity rating, and asset context risk weighting.

use shared_types::{
    AppCriticality, AppEnvironment, AttackComplexity, AttackVector, CiaImpact, CvssMetrics,
    PrivilegesRequired, Scope, SeverityLevel, UserInteraction,
};

/// FIRST CVSS v3.1 Appendix A integer-based roundup function.
///
/// Converts input to an integer scaled by 100,000, checks if the least significant
/// 4 decimal places are zero, and rounds up to 1 decimal place.
pub fn roundup(input: f64) -> f64 {
    let int_input = (input * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input / 10_000) + 1) as f64 / 10.0
    }
}

/// Calculate the CVSS v3.1 base numerical score (0.0 to 10.0) and qualitative severity level.
pub fn calculate_cvss_v31(metrics: &CvssMetrics) -> (f64, SeverityLevel) {
    // 1. Attack Vector numerical weight
    let av = match metrics.attack_vector {
        AttackVector::Network => 0.85,
        AttackVector::Adjacent => 0.62,
        AttackVector::Local => 0.55,
        AttackVector::Physical => 0.20,
    };

    // 2. Attack Complexity numerical weight
    let ac = match metrics.attack_complexity {
        AttackComplexity::Low => 0.77,
        AttackComplexity::High => 0.44,
    };

    // 3. Privileges Required numerical weight (depends on Scope)
    let pr = match metrics.scope {
        Scope::Unchanged => match metrics.privileges_required {
            PrivilegesRequired::None => 0.85,
            PrivilegesRequired::Low => 0.62,
            PrivilegesRequired::High => 0.27,
        },
        Scope::Changed => match metrics.privileges_required {
            PrivilegesRequired::None => 0.85,
            PrivilegesRequired::Low => 0.68,
            PrivilegesRequired::High => 0.50,
        },
    };

    // 4. User Interaction numerical weight
    let ui = match metrics.user_interaction {
        UserInteraction::None => 0.85,
        UserInteraction::Required => 0.62,
    };

    // 5. CIA Impact weights
    let c = match metrics.confidentiality {
        CiaImpact::None => 0.0,
        CiaImpact::Low => 0.22,
        CiaImpact::High => 0.56,
    };

    let i = match metrics.integrity {
        CiaImpact::None => 0.0,
        CiaImpact::Low => 0.22,
        CiaImpact::High => 0.56,
    };

    let a = match metrics.availability {
        CiaImpact::None => 0.0,
        CiaImpact::Low => 0.22,
        CiaImpact::High => 0.56,
    };

    // 6. Impact Sub-Score (ISS)
    let iss: f64 = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));

    // 7. Impact
    let impact: f64 = match metrics.scope {
        Scope::Unchanged => 6.42 * iss,
        Scope::Changed => 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02_f64).powi(15),
    };

    // 8. Exploitability Sub-Score
    let exploitability: f64 = 8.22 * av * ac * pr * ui;

    // 9. Base Score computation
    let base_score: f64 = if impact <= 0.0 {
        0.0
    } else {
        match metrics.scope {
            Scope::Unchanged => roundup(f64::min(impact + exploitability, 10.0)),
            Scope::Changed => roundup(f64::min(1.08 * (impact + exploitability), 10.0)),
        }
    };

    // 10. Qualitative Severity Level mapping
    let severity = if base_score == 0.0 {
        SeverityLevel::Info
    } else if base_score < 4.0 {
        SeverityLevel::Low
    } else if base_score < 7.0 {
        SeverityLevel::Medium
    } else if base_score < 9.0 {
        SeverityLevel::High
    } else {
        SeverityLevel::Critical
    };

    (base_score, severity)
}

/// Calculate the asset-weighted risk score (0.0 to 100.0) from the CVSS base score,
/// application environment, and criticality.
pub fn calculate_asset_risk(base_score: f64, env: AppEnvironment, crit: AppCriticality) -> f64 {
    if base_score <= 0.0 {
        return 0.0;
    }

    let env_mult = match env {
        AppEnvironment::Production => 1.0,
        AppEnvironment::Staging => 0.8,
        AppEnvironment::Qa => 0.6,
        AppEnvironment::Development => 0.4,
    };

    let crit_mult = match crit {
        AppCriticality::Critical => 1.0,
        AppCriticality::High => 0.8,
        AppCriticality::Medium => 0.6,
        AppCriticality::Low => 0.4,
    };

    let raw = base_score * 10.0 * env_mult * crit_mult;
    let clamped = raw.clamp(0.0, 100.0);
    (clamped * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared_types::CvssVector;

    #[test]
    fn test_cvss_roundup_edge_cases() {
        assert_eq!(roundup(4.000), 4.0);
        assert_eq!(roundup(4.001), 4.1);
        assert_eq!(roundup(4.020), 4.1);
        assert_eq!(roundup(9.88995), 9.9);
        assert_eq!(roundup(0.0), 0.0);
        assert_eq!(roundup(10.0), 10.0);
        assert_eq!(roundup(1.50001), 1.6);
        assert_eq!(roundup(1.50000), 1.5);
    }

    #[test]
    fn test_cvss_benchmark_vector_1_critical_9_8() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        let vector = CvssVector::new("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        let metrics = vector.parse_metrics().unwrap();
        let (score, severity) = calculate_cvss_v31(&metrics);
        assert_eq!(score, 9.8);
        assert_eq!(severity, SeverityLevel::Critical);
    }

    #[test]
    fn test_cvss_benchmark_vector_2_medium_6_1() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
        let vector = CvssVector::new("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
        let metrics = vector.parse_metrics().unwrap();
        let (score, severity) = calculate_cvss_v31(&metrics);
        assert_eq!(score, 6.1);
        assert_eq!(severity, SeverityLevel::Medium);
    }

    #[test]
    fn test_cvss_benchmark_vector_3_critical_9_9() {
        // CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
        let vector = CvssVector::new("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
        let metrics = vector.parse_metrics().unwrap();
        let (score, severity) = calculate_cvss_v31(&metrics);
        assert_eq!(score, 9.9);
        assert_eq!(severity, SeverityLevel::Critical);
    }

    #[test]
    fn test_cvss_benchmark_vector_4_low_1_6() {
        // CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N
        let vector = CvssVector::new("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N");
        let metrics = vector.parse_metrics().unwrap();
        let (score, severity) = calculate_cvss_v31(&metrics);
        assert_eq!(score, 1.6);
        assert_eq!(severity, SeverityLevel::Low);
    }

    #[test]
    fn test_cvss_benchmark_vector_5_zero_info() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N
        let vector = CvssVector::new("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
        let metrics = vector.parse_metrics().unwrap();
        let (score, severity) = calculate_cvss_v31(&metrics);
        assert_eq!(score, 0.0);
        assert_eq!(severity, SeverityLevel::Info);
    }

    #[test]
    fn test_cvss_benchmark_vector_6_high_7_8() {
        // CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
        let vector = CvssVector::new("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
        let metrics = vector.parse_metrics().unwrap();
        let (score, severity) = calculate_cvss_v31(&metrics);
        assert_eq!(score, 7.8);
        assert_eq!(severity, SeverityLevel::High);
    }

    #[test]
    fn test_cvss_benchmark_vector_7_low_3_7() {
        // CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N
        let vector = CvssVector::new("CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N");
        let metrics = vector.parse_metrics().unwrap();
        let (score, severity) = calculate_cvss_v31(&metrics);
        assert_eq!(score, 3.7);
        assert_eq!(severity, SeverityLevel::Low);
    }

    #[test]
    fn test_cvss_benchmark_vector_network_medium_4_2() {
        // CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N
        let vector = CvssVector::new("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N");
        let metrics = vector.parse_metrics().unwrap();
        let (score, severity) = calculate_cvss_v31(&metrics);
        assert_eq!(score, 4.2);
        assert_eq!(severity, SeverityLevel::Medium);
    }

    #[test]
    fn test_asset_risk_calculation() {
        // 10.0, Production, Critical -> 100.0
        assert_eq!(calculate_asset_risk(10.0, AppEnvironment::Production, AppCriticality::Critical), 100.0);
        // 10.0, Staging, High -> 64.0
        assert_eq!(calculate_asset_risk(10.0, AppEnvironment::Staging, AppCriticality::High), 64.0);
        // 10.0, Qa, Medium -> 36.0
        assert_eq!(calculate_asset_risk(10.0, AppEnvironment::Qa, AppCriticality::Medium), 36.0);
        // 10.0, Development, Low -> 16.0
        assert_eq!(calculate_asset_risk(10.0, AppEnvironment::Development, AppCriticality::Low), 16.0);
        // 0.0, Production, Critical -> 0.0
        assert_eq!(calculate_asset_risk(0.0, AppEnvironment::Production, AppCriticality::Critical), 0.0);
        // 6.1, Staging, High -> 39.04
        assert_eq!(calculate_asset_risk(6.1, AppEnvironment::Staging, AppCriticality::High), 39.04);
        // Negative score clamp
        assert_eq!(calculate_asset_risk(-5.0, AppEnvironment::Production, AppCriticality::Critical), 0.0);
    }
}
