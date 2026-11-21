use std::fmt;
use std::str::FromStr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Admin,
    SecurityEngineer,
    Developer,
    Auditor,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::SecurityEngineer => "security_engineer",
            Self::Developer => "developer",
            Self::Auditor => "auditor",
        }
    }
}

impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for UserRole {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Self::Admin),
            "security_engineer" => Ok(Self::SecurityEngineer),
            "developer" => Ok(Self::Developer),
            "auditor" => Ok(Self::Auditor),
            other => Err(format!("Unknown user role: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AppEnvironment {
    Production,
    Staging,
    Development,
    Qa,
}

impl AppEnvironment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Staging => "staging",
            Self::Development => "development",
            Self::Qa => "qa",
        }
    }
}

impl fmt::Display for AppEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for AppEnvironment {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "production" => Ok(Self::Production),
            "staging" => Ok(Self::Staging),
            "development" => Ok(Self::Development),
            "qa" => Ok(Self::Qa),
            other => Err(format!("Unknown app environment: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AppCriticality {
    Critical,
    High,
    Medium,
    Low,
}

impl AppCriticality {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

impl fmt::Display for AppCriticality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for AppCriticality {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            other => Err(format!("Unknown app criticality: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    BaselinePassive,
    FullActive,
    ApiOpenapi,
    SpaAjax,
}

impl ScanType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BaselinePassive => "baseline_passive",
            Self::FullActive => "full_active",
            Self::ApiOpenapi => "api_openapi",
            Self::SpaAjax => "spa_ajax",
        }
    }
}

impl fmt::Display for ScanType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ScanType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "baseline_passive" => Ok(Self::BaselinePassive),
            "full_active" => Ok(Self::FullActive),
            "api_openapi" => Ok(Self::ApiOpenapi),
            "spa_ajax" => Ok(Self::SpaAjax),
            other => Err(format!("Unknown scan type: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Queued,
    Spidering,
    ActiveScanning,
    Ingesting,
    Completed,
    Failed,
    Cancelled,
}

impl ScanStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Spidering => "spidering",
            Self::ActiveScanning => "active_scanning",
            Self::Ingesting => "ingesting",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

impl fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ScanStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "queued" => Ok(Self::Queued),
            "spidering" => Ok(Self::Spidering),
            "active_scanning" => Ok(Self::ActiveScanning),
            "ingesting" => Ok(Self::Ingesting),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            other => Err(format!("Unknown scan status: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SeverityLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for SeverityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for SeverityLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(format!("Unknown severity level: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RemediationStatus {
    Open,
    InProgress,
    FalsePositive,
    RiskAccepted,
    Resolved,
    VerifiedFixed,
    Regressed,
}

impl RemediationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::InProgress => "in_progress",
            Self::FalsePositive => "false_positive",
            Self::RiskAccepted => "risk_accepted",
            Self::Resolved => "resolved",
            Self::VerifiedFixed => "verified_fixed",
            Self::Regressed => "regressed",
        }
    }
}

impl fmt::Display for RemediationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for RemediationStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(Self::Open),
            "in_progress" => Ok(Self::InProgress),
            "false_positive" => Ok(Self::FalsePositive),
            "risk_accepted" => Ok(Self::RiskAccepted),
            "resolved" => Ok(Self::Resolved),
            "verified_fixed" => Ok(Self::VerifiedFixed),
            "regressed" => Ok(Self::Regressed),
            other => Err(format!("Unknown remediation status: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DiffClassification {
    New,
    Persistent,
    Regressed,
}

impl DiffClassification {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Persistent => "persistent",
            Self::Regressed => "regressed",
        }
    }
}

impl fmt::Display for DiffClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for DiffClassification {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "new" => Ok(Self::New),
            "persistent" => Ok(Self::Persistent),
            "regressed" => Ok(Self::Regressed),
            other => Err(format!("Unknown diff classification: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_role_serde_and_display() {
        let roles = [
            (UserRole::Admin, "\"admin\"", "admin"),
            (UserRole::SecurityEngineer, "\"security_engineer\"", "security_engineer"),
            (UserRole::Developer, "\"developer\"", "developer"),
            (UserRole::Auditor, "\"auditor\"", "auditor"),
        ];

        for (role, expected_json, expected_str) in roles {
            assert_eq!(serde_json::to_string(&role).unwrap(), expected_json);
            assert_eq!(role.to_string(), expected_str);
            assert_eq!(role.as_str(), expected_str);
            let parsed_json: UserRole = serde_json::from_str(expected_json).unwrap();
            assert_eq!(parsed_json, role);
            let parsed_str: UserRole = expected_str.parse().unwrap();
            assert_eq!(parsed_str, role);
        }

        assert!(UserRole::from_str("superuser").is_err());
        assert!(serde_json::from_str::<UserRole>("\"superuser\"").is_err());
    }

    #[test]
    fn test_app_environment_serde_and_display() {
        let envs = [
            (AppEnvironment::Production, "\"production\"", "production"),
            (AppEnvironment::Staging, "\"staging\"", "staging"),
            (AppEnvironment::Development, "\"development\"", "development"),
            (AppEnvironment::Qa, "\"qa\"", "qa"),
        ];

        for (env, expected_json, expected_str) in envs {
            assert_eq!(serde_json::to_string(&env).unwrap(), expected_json);
            assert_eq!(env.to_string(), expected_str);
            assert_eq!(env.as_str(), expected_str);
            let parsed: AppEnvironment = serde_json::from_str(expected_json).unwrap();
            assert_eq!(parsed, env);
            let parsed_str: AppEnvironment = expected_str.parse().unwrap();
            assert_eq!(parsed_str, env);
        }

        assert!(AppEnvironment::from_str("prod").is_err());
        assert!(serde_json::from_str::<AppEnvironment>("\"local\"").is_err());
    }

    #[test]
    fn test_app_criticality_serde_and_display() {
        let criticalities = [
            (AppCriticality::Critical, "\"critical\"", "critical"),
            (AppCriticality::High, "\"high\"", "high"),
            (AppCriticality::Medium, "\"medium\"", "medium"),
            (AppCriticality::Low, "\"low\"", "low"),
        ];

        for (crit, expected_json, expected_str) in criticalities {
            assert_eq!(serde_json::to_string(&crit).unwrap(), expected_json);
            assert_eq!(crit.to_string(), expected_str);
            assert_eq!(crit.as_str(), expected_str);
            let parsed: AppCriticality = serde_json::from_str(expected_json).unwrap();
            assert_eq!(parsed, crit);
            let parsed_str: AppCriticality = expected_str.parse().unwrap();
            assert_eq!(parsed_str, crit);
        }

        assert!(AppCriticality::from_str("none").is_err());
        assert!(serde_json::from_str::<AppCriticality>("\"urgent\"").is_err());
    }

    #[test]
    fn test_scan_type_serde_and_display() {
        let scan_types = [
            (ScanType::BaselinePassive, "\"baseline_passive\"", "baseline_passive"),
            (ScanType::FullActive, "\"full_active\"", "full_active"),
            (ScanType::ApiOpenapi, "\"api_openapi\"", "api_openapi"),
            (ScanType::SpaAjax, "\"spa_ajax\"", "spa_ajax"),
        ];

        for (st, expected_json, expected_str) in scan_types {
            assert_eq!(serde_json::to_string(&st).unwrap(), expected_json);
            assert_eq!(st.to_string(), expected_str);
            assert_eq!(st.as_str(), expected_str);
            let parsed: ScanType = serde_json::from_str(expected_json).unwrap();
            assert_eq!(parsed, st);
            let parsed_str: ScanType = expected_str.parse().unwrap();
            assert_eq!(parsed_str, st);
        }

        assert!(ScanType::from_str("quick_scan").is_err());
        assert!(serde_json::from_str::<ScanType>("\"deep_scan\"").is_err());
    }

    #[test]
    fn test_scan_status_serde_and_display() {
        let statuses = [
            (ScanStatus::Queued, "\"queued\"", "queued"),
            (ScanStatus::Spidering, "\"spidering\"", "spidering"),
            (ScanStatus::ActiveScanning, "\"active_scanning\"", "active_scanning"),
            (ScanStatus::Ingesting, "\"ingesting\"", "ingesting"),
            (ScanStatus::Completed, "\"completed\"", "completed"),
            (ScanStatus::Failed, "\"failed\"", "failed"),
            (ScanStatus::Cancelled, "\"cancelled\"", "cancelled"),
        ];

        for (status, expected_json, expected_str) in statuses {
            assert_eq!(serde_json::to_string(&status).unwrap(), expected_json);
            assert_eq!(status.to_string(), expected_str);
            assert_eq!(status.as_str(), expected_str);
            let parsed: ScanStatus = serde_json::from_str(expected_json).unwrap();
            assert_eq!(parsed, status);
            let parsed_str: ScanStatus = expected_str.parse().unwrap();
            assert_eq!(parsed_str, status);
        }

        assert!(ScanStatus::from_str("aborted").is_err());
        assert!(serde_json::from_str::<ScanStatus>("\"pending\"").is_err());
    }

    #[test]
    fn test_severity_level_ordering_and_serde() {
        let severities = [
            (SeverityLevel::Info, "\"info\"", "info"),
            (SeverityLevel::Low, "\"low\"", "low"),
            (SeverityLevel::Medium, "\"medium\"", "medium"),
            (SeverityLevel::High, "\"high\"", "high"),
            (SeverityLevel::Critical, "\"critical\"", "critical"),
        ];

        for (sev, expected_json, expected_str) in severities {
            assert_eq!(serde_json::to_string(&sev).unwrap(), expected_json);
            assert_eq!(sev.to_string(), expected_str);
            assert_eq!(sev.as_str(), expected_str);
            let parsed: SeverityLevel = serde_json::from_str(expected_json).unwrap();
            assert_eq!(parsed, sev);
            let parsed_str: SeverityLevel = expected_str.parse().unwrap();
            assert_eq!(parsed_str, sev);
        }

        // Strict ordering check
        assert!(SeverityLevel::Info < SeverityLevel::Low);
        assert!(SeverityLevel::Low < SeverityLevel::Medium);
        assert!(SeverityLevel::Medium < SeverityLevel::High);
        assert!(SeverityLevel::High < SeverityLevel::Critical);

        let mut list = vec![
            SeverityLevel::Critical,
            SeverityLevel::Info,
            SeverityLevel::High,
            SeverityLevel::Low,
            SeverityLevel::Medium,
        ];
        list.sort();
        assert_eq!(
            list,
            vec![
                SeverityLevel::Info,
                SeverityLevel::Low,
                SeverityLevel::Medium,
                SeverityLevel::High,
                SeverityLevel::Critical,
            ]
        );

        assert!(SeverityLevel::from_str("moderate").is_err());
        assert!(serde_json::from_str::<SeverityLevel>("\"extreme\"").is_err());
    }

    #[test]
    fn test_remediation_status_serde_and_display() {
        let statuses = [
            (RemediationStatus::Open, "\"open\"", "open"),
            (RemediationStatus::InProgress, "\"in_progress\"", "in_progress"),
            (RemediationStatus::FalsePositive, "\"false_positive\"", "false_positive"),
            (RemediationStatus::RiskAccepted, "\"risk_accepted\"", "risk_accepted"),
            (RemediationStatus::Resolved, "\"resolved\"", "resolved"),
            (RemediationStatus::VerifiedFixed, "\"verified_fixed\"", "verified_fixed"),
            (RemediationStatus::Regressed, "\"regressed\"", "regressed"),
        ];

        for (status, expected_json, expected_str) in statuses {
            assert_eq!(serde_json::to_string(&status).unwrap(), expected_json);
            assert_eq!(status.to_string(), expected_str);
            assert_eq!(status.as_str(), expected_str);
            let parsed: RemediationStatus = serde_json::from_str(expected_json).unwrap();
            assert_eq!(parsed, status);
            let parsed_str: RemediationStatus = expected_str.parse().unwrap();
            assert_eq!(parsed_str, status);
        }

        assert!(RemediationStatus::from_str("closed").is_err());
        assert!(serde_json::from_str::<RemediationStatus>("\"ignored\"").is_err());
    }

    #[test]
    fn test_diff_classification_serde_and_display() {
        let diffs = [
            (DiffClassification::New, "\"new\"", "new"),
            (DiffClassification::Persistent, "\"persistent\"", "persistent"),
            (DiffClassification::Regressed, "\"regressed\"", "regressed"),
        ];

        for (diff, expected_json, expected_str) in diffs {
            assert_eq!(serde_json::to_string(&diff).unwrap(), expected_json);
            assert_eq!(diff.to_string(), expected_str);
            assert_eq!(diff.as_str(), expected_str);
            let parsed: DiffClassification = serde_json::from_str(expected_json).unwrap();
            assert_eq!(parsed, diff);
            let parsed_str: DiffClassification = expected_str.parse().unwrap();
            assert_eq!(parsed_str, diff);
        }

        // 'fixed' is deliberately NOT a row-level DiffClassification variant
        assert!(DiffClassification::from_str("fixed").is_err());
        assert!(serde_json::from_str::<DiffClassification>("\"fixed\"").is_err());
        assert!(DiffClassification::from_str("unknown").is_err());
    }
}
