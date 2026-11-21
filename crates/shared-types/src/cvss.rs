use std::fmt;
use std::str::FromStr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

impl AttackVector {
    pub fn as_code(&self) -> &'static str {
        match self {
            Self::Network => "N",
            Self::Adjacent => "A",
            Self::Local => "L",
            Self::Physical => "P",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AttackComplexity {
    Low,
    High,
}

impl AttackComplexity {
    pub fn as_code(&self) -> &'static str {
        match self {
            Self::Low => "L",
            Self::High => "H",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

impl PrivilegesRequired {
    pub fn as_code(&self) -> &'static str {
        match self {
            Self::None => "N",
            Self::Low => "L",
            Self::High => "H",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum UserInteraction {
    None,
    Required,
}

impl UserInteraction {
    pub fn as_code(&self) -> &'static str {
        match self {
            Self::None => "N",
            Self::Required => "R",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Unchanged,
    Changed,
}

impl Scope {
    pub fn as_code(&self) -> &'static str {
        match self {
            Self::Unchanged => "U",
            Self::Changed => "C",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CiaImpact {
    None,
    Low,
    High,
}

impl CiaImpact {
    pub fn as_code(&self) -> &'static str {
        match self {
            Self::None => "N",
            Self::Low => "L",
            Self::High => "H",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CvssMetrics {
    pub attack_vector: AttackVector,
    pub attack_complexity: AttackComplexity,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: UserInteraction,
    pub scope: Scope,
    pub confidentiality: CiaImpact,
    pub integrity: CiaImpact,
    pub availability: CiaImpact,
}

impl CvssMetrics {
    pub fn to_vector_string(&self) -> String {
        format!(
            "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
            self.attack_vector.as_code(),
            self.attack_complexity.as_code(),
            self.privileges_required.as_code(),
            self.user_interaction.as_code(),
            self.scope.as_code(),
            self.confidentiality.as_code(),
            self.integrity.as_code(),
            self.availability.as_code(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CvssParseError {
    InvalidPrefix(String),
    MissingMetric(&'static str),
    InvalidMetricValue { metric: String, value: String },
    UnrecognizedMetricKey(String),
    MalformedMetric(String),
}

impl fmt::Display for CvssParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix(msg) => write!(f, "Invalid CVSS prefix: {msg}"),
            Self::MissingMetric(m) => write!(f, "Missing mandatory CVSS metric: {m}"),
            Self::InvalidMetricValue { metric, value } => {
                write!(f, "Invalid value '{value}' for CVSS metric '{metric}'")
            }
            Self::UnrecognizedMetricKey(k) => write!(f, "Unrecognized CVSS metric key: {k}"),
            Self::MalformedMetric(pair) => write!(f, "Malformed CVSS metric pair: {pair}"),
        }
    }
}

impl std::error::Error for CvssParseError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct CvssVector(pub String);

impl CvssVector {
    pub fn new(vector: impl Into<String>) -> Self {
        Self(vector.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse_metrics(&self) -> Result<CvssMetrics, CvssParseError> {
        let s = self.0.trim();
        let prefix = "CVSS:3.1/";
        if !s.starts_with(prefix) {
            return Err(CvssParseError::InvalidPrefix(format!(
                "CVSS vector must start with '{prefix}', got '{s}'"
            )));
        }

        let metric_part = &s[prefix.len()..];
        let mut av = None;
        let mut ac = None;
        let mut pr = None;
        let mut ui = None;
        let mut sc = None;
        let mut c = None;
        let mut i = None;
        let mut a = None;

        for pair in metric_part.split('/') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            let mut parts = pair.split(':');
            let key = parts.next().unwrap_or("");
            let val = parts.next().ok_or_else(|| CvssParseError::MalformedMetric(pair.to_string()))?;
            if parts.next().is_some() {
                return Err(CvssParseError::MalformedMetric(pair.to_string()));
            }

            match key {
                "AV" => av = Some(match val {
                    "N" => AttackVector::Network,
                    "A" => AttackVector::Adjacent,
                    "L" => AttackVector::Local,
                    "P" => AttackVector::Physical,
                    _ => return Err(CvssParseError::InvalidMetricValue {
                        metric: "AV".to_string(),
                        value: val.to_string(),
                    }),
                }),
                "AC" => ac = Some(match val {
                    "L" => AttackComplexity::Low,
                    "H" => AttackComplexity::High,
                    _ => return Err(CvssParseError::InvalidMetricValue {
                        metric: "AC".to_string(),
                        value: val.to_string(),
                    }),
                }),
                "PR" => pr = Some(match val {
                    "N" => PrivilegesRequired::None,
                    "L" => PrivilegesRequired::Low,
                    "H" => PrivilegesRequired::High,
                    _ => return Err(CvssParseError::InvalidMetricValue {
                        metric: "PR".to_string(),
                        value: val.to_string(),
                    }),
                }),
                "UI" => ui = Some(match val {
                    "N" => UserInteraction::None,
                    "R" => UserInteraction::Required,
                    _ => return Err(CvssParseError::InvalidMetricValue {
                        metric: "UI".to_string(),
                        value: val.to_string(),
                    }),
                }),
                "S" => sc = Some(match val {
                    "U" => Scope::Unchanged,
                    "C" => Scope::Changed,
                    _ => return Err(CvssParseError::InvalidMetricValue {
                        metric: "S".to_string(),
                        value: val.to_string(),
                    }),
                }),
                "C" => c = Some(match val {
                    "N" => CiaImpact::None,
                    "L" => CiaImpact::Low,
                    "H" => CiaImpact::High,
                    _ => return Err(CvssParseError::InvalidMetricValue {
                        metric: "C".to_string(),
                        value: val.to_string(),
                    }),
                }),
                "I" => i = Some(match val {
                    "N" => CiaImpact::None,
                    "L" => CiaImpact::Low,
                    "H" => CiaImpact::High,
                    _ => return Err(CvssParseError::InvalidMetricValue {
                        metric: "I".to_string(),
                        value: val.to_string(),
                    }),
                }),
                "A" => a = Some(match val {
                    "N" => CiaImpact::None,
                    "L" => CiaImpact::Low,
                    "H" => CiaImpact::High,
                    _ => return Err(CvssParseError::InvalidMetricValue {
                        metric: "A".to_string(),
                        value: val.to_string(),
                    }),
                }),
                _ => return Err(CvssParseError::UnrecognizedMetricKey(key.to_string())),
            }
        }

        Ok(CvssMetrics {
            attack_vector: av.ok_or(CvssParseError::MissingMetric("AttackVector (AV)"))?,
            attack_complexity: ac.ok_or(CvssParseError::MissingMetric("AttackComplexity (AC)"))?,
            privileges_required: pr.ok_or(CvssParseError::MissingMetric("PrivilegesRequired (PR)"))?,
            user_interaction: ui.ok_or(CvssParseError::MissingMetric("UserInteraction (UI)"))?,
            scope: sc.ok_or(CvssParseError::MissingMetric("Scope (S)"))?,
            confidentiality: c.ok_or(CvssParseError::MissingMetric("Confidentiality (C)"))?,
            integrity: i.ok_or(CvssParseError::MissingMetric("Integrity (I)"))?,
            availability: a.ok_or(CvssParseError::MissingMetric("Availability (A)"))?,
        })
    }
}

impl fmt::Display for CvssVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for CvssVector {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

impl From<CvssMetrics> for CvssVector {
    fn from(metrics: CvssMetrics) -> Self {
        Self(metrics.to_vector_string())
    }
}

impl TryFrom<&str> for CvssMetrics {
    type Error = CvssParseError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        CvssVector::new(s).parse_metrics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cvss_vector_valid_roundtrip() {
        let vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        let vector = CvssVector::new(vector_str);
        assert_eq!(vector.to_string(), vector_str);
        assert_eq!(vector.as_str(), vector_str);

        let metrics = vector.parse_metrics().unwrap();
        assert_eq!(metrics.attack_vector, AttackVector::Network);
        assert_eq!(metrics.attack_complexity, AttackComplexity::Low);
        assert_eq!(metrics.privileges_required, PrivilegesRequired::None);
        assert_eq!(metrics.user_interaction, UserInteraction::None);
        assert_eq!(metrics.scope, Scope::Unchanged);
        assert_eq!(metrics.confidentiality, CiaImpact::High);
        assert_eq!(metrics.integrity, CiaImpact::High);
        assert_eq!(metrics.availability, CiaImpact::High);

        assert_eq!(metrics.to_vector_string(), vector_str);

        let roundtrip_vector: CvssVector = metrics.into();
        assert_eq!(roundtrip_vector.as_str(), vector_str);
    }

    #[test]
    fn test_cvss_vector_complex_permutation() {
        let vector_str = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:L";
        let metrics: CvssMetrics = vector_str.try_into().unwrap();
        assert_eq!(metrics.attack_vector, AttackVector::Local);
        assert_eq!(metrics.attack_complexity, AttackComplexity::High);
        assert_eq!(metrics.privileges_required, PrivilegesRequired::High);
        assert_eq!(metrics.user_interaction, UserInteraction::Required);
        assert_eq!(metrics.scope, Scope::Changed);
        assert_eq!(metrics.confidentiality, CiaImpact::Low);
        assert_eq!(metrics.integrity, CiaImpact::None);
        assert_eq!(metrics.availability, CiaImpact::Low);

        assert_eq!(metrics.to_vector_string(), vector_str);
    }

    #[test]
    fn test_cvss_vector_invalid_prefix() {
        let v1 = CvssVector::new("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert!(matches!(v1.parse_metrics(), Err(CvssParseError::InvalidPrefix(_))));

        let v2 = CvssVector::new("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        assert!(matches!(v2.parse_metrics(), Err(CvssParseError::InvalidPrefix(_))));
    }

    #[test]
    fn test_cvss_vector_missing_metric() {
        // Missing S (Scope)
        let v = CvssVector::new("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H");
        let res = v.parse_metrics();
        assert!(matches!(res, Err(CvssParseError::MissingMetric("Scope (S)"))));
    }

    #[test]
    fn test_cvss_vector_invalid_metric_value() {
        // AV:X is invalid
        let v = CvssVector::new("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        let res = v.parse_metrics();
        match res {
            Err(CvssParseError::InvalidMetricValue { metric, value }) => {
                assert_eq!(metric, "AV");
                assert_eq!(value, "X");
            }
            other => panic!("Expected InvalidMetricValue, got {:?}", other),
        }
    }

    #[test]
    fn test_cvss_vector_unrecognized_key() {
        let v = CvssVector::new("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/UNKNOWN:VAL");
        assert!(matches!(v.parse_metrics(), Err(CvssParseError::UnrecognizedMetricKey(_))));
    }

    #[test]
    fn test_cvss_sub_enums_serde() {
        assert_eq!(serde_json::to_string(&AttackVector::Adjacent).unwrap(), "\"adjacent\"");
        assert_eq!(serde_json::to_string(&AttackComplexity::High).unwrap(), "\"high\"");
        assert_eq!(serde_json::to_string(&PrivilegesRequired::Low).unwrap(), "\"low\"");
        assert_eq!(serde_json::to_string(&UserInteraction::Required).unwrap(), "\"required\"");
        assert_eq!(serde_json::to_string(&Scope::Changed).unwrap(), "\"changed\"");
        assert_eq!(serde_json::to_string(&CiaImpact::Low).unwrap(), "\"low\"");
    }
}
