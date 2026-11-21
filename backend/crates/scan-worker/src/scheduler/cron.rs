use chrono::{DateTime, Datelike, Timelike, Utc};
use std::collections::HashSet;

/// Parsed schedule specification for a single cron field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldMatcher {
    Any,
    Step { step: u32, min: u32, max: u32 },
    Values(HashSet<u32>),
}

impl FieldMatcher {
    pub fn matches(&self, value: u32) -> bool {
        match self {
            Self::Any => true,
            Self::Step { step, min, max } => {
                if *step == 0 {
                    return false;
                }
                value >= *min && value <= *max && (value - *min) % *step == 0
            }
            Self::Values(set) => set.contains(&value),
        }
    }

    fn parse_field(s: &str, min: u32, max: u32) -> Result<Self, String> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err("Empty cron field".to_string());
        }

        if trimmed == "*" {
            return Ok(Self::Any);
        }

        if let Some(step_str) = trimmed.strip_prefix("*/") {
            let step: u32 = step_str
                .parse()
                .map_err(|_| format!("Invalid step in cron field: {step_str}"))?;
            if step == 0 || step > (max - min) {
                return Err(format!("Step out of range: {step}"));
            }
            return Ok(Self::Step { step, min, max });
        }

        let mut values = HashSet::new();
        for part in trimmed.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err("Empty sub-field in comma-separated list".to_string());
            }

            if let Some((start_s, end_s)) = part.split_once('-') {
                let start: u32 = start_s
                    .parse()
                    .map_err(|_| format!("Invalid range start: {start_s}"))?;
                let end: u32 = end_s
                    .parse()
                    .map_err(|_| format!("Invalid range end: {end_s}"))?;
                if start > end || start < min || end > max {
                    return Err(format!("Invalid range: {start}-{end} for limits {min}-{max}"));
                }
                for v in start..=end {
                    values.insert(v);
                }
            } else {
                let val: u32 = part
                    .parse()
                    .map_err(|_| format!("Invalid number: {part}"))?;
                if val < min || val > max {
                    return Err(format!("Value {val} out of bounds [{min}, {max}]"));
                }
                values.insert(val);
            }
        }

        Ok(Self::Values(values))
    }
}

/// Standard 5-field cron expression representation.
/// Fields: `minute` (0-59), `hour` (0-23), `day_of_month` (1-31), `month` (1-12), `day_of_week` (0-7, where 0 and 7 are Sunday).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronExpression {
    original: String,
    minute: FieldMatcher,
    hour: FieldMatcher,
    day_of_month: FieldMatcher,
    month: FieldMatcher,
    day_of_week: FieldMatcher,
}

impl CronExpression {
    /// Validates and parses a standard 5-field cron expression string.
    pub fn parse(expr: &str) -> Result<Self, String> {
        let parts: Vec<&str> = expr.split_whitespace().collect();
        if parts.len() != 5 {
            return Err(format!(
                "Cron expression must contain exactly 5 fields, got {}: '{}'",
                parts.len(),
                expr
            ));
        }

        let minute = FieldMatcher::parse_field(parts[0], 0, 59)?;
        let hour = FieldMatcher::parse_field(parts[1], 0, 23)?;
        let day_of_month = FieldMatcher::parse_field(parts[2], 1, 31)?;
        let month = FieldMatcher::parse_field(parts[3], 1, 12)?;
        let day_of_week = FieldMatcher::parse_field(parts[4], 0, 7)?;

        Ok(Self {
            original: expr.to_string(),
            minute,
            hour,
            day_of_month,
            month,
            day_of_week,
        })
    }

    /// Helper that returns true if the string is a valid 5-field cron expression.
    pub fn is_valid(expr: &str) -> bool {
        Self::parse(expr).is_ok()
    }

    pub fn original(&self) -> &str {
        &self.original
    }

    /// Evaluates whether the given DateTime matches all cron criteria.
    pub fn matches(&self, dt: &DateTime<Utc>) -> bool {
        if !self.minute.matches(dt.minute()) {
            return false;
        }
        if !self.hour.matches(dt.hour()) {
            return false;
        }
        if !self.day_of_month.matches(dt.day()) {
            return false;
        }
        if !self.month.matches(dt.month()) {
            return false;
        }

        // Chrono weekday: Sunday is 0 from Sunday (0..=6).
        // Standard cron accepts 0 and 7 for Sunday.
        let dow = dt.weekday().num_days_from_sunday();
        let dow_match = self.day_of_week.matches(dow) || (dow == 0 && self.day_of_week.matches(7));
        if !dow_match {
            return false;
        }

        true
    }

    /// Determines whether a recurring scan is due, given the last scanned timestamp and the current time.
    pub fn is_due(&self, last_run: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
        match last_run {
            None => true,
            Some(last) => {
                if now <= last {
                    return false;
                }
                // Check if any minute boundary between last and now matches the cron schedule
                // Clamp search window to 1440 minutes (24h) to prevent long iterations
                let diff_secs = (now - last).num_seconds();
                if diff_secs <= 0 {
                    return false;
                }

                // If more than 24 hours have elapsed and schedule is daily or more frequent, it's due
                if diff_secs >= 86400 {
                    return true;
                }

                // Check minute by minute backward from now up to last
                let mut cursor = now;
                let step = chrono::Duration::minutes(1);
                let mut checks = 0;
                while cursor > last && checks < 1440 {
                    if self.matches(&cursor) {
                        return true;
                    }
                    cursor = cursor - step;
                    checks += 1;
                }

                false
            }
        }
    }
}
