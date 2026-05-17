//! Port and port-range matching.
//!
//! A `PortMatcher` represents one entry in `include.ports` or
//! `exclude.ports`. Two forms are supported in YAML:
//!
//! ```yaml
//! ports: [80, 443]                # single ports
//! ports: ["8000-9000"]            # inclusive range
//! ```

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ScopeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortMatcher {
    pub low: u16,
    pub high: u16,
}

impl PortMatcher {
    pub fn single(port: u16) -> Self {
        Self {
            low: port,
            high: port,
        }
    }

    pub fn range(low: u16, high: u16) -> Result<Self, ScopeError> {
        if low > high {
            return Err(ScopeError::PortRange(
                format!("{low}-{high}"),
                "low must be <= high".into(),
            ));
        }
        Ok(Self { low, high })
    }

    pub fn matches(&self, port: u16) -> bool {
        port >= self.low && port <= self.high
    }
}

impl fmt::Display for PortMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.low == self.high {
            write!(f, "{}", self.low)
        } else {
            write!(f, "{}-{}", self.low, self.high)
        }
    }
}

impl Serialize for PortMatcher {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.low == self.high {
            s.serialize_u16(self.low)
        } else {
            s.serialize_str(&self.to_string())
        }
    }
}

impl<'de> Deserialize<'de> for PortMatcher {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Single(u16),
            Range(String),
        }
        match Repr::deserialize(d)? {
            Repr::Single(p) => Ok(Self::single(p)),
            Repr::Range(s) => parse_range(&s).map_err(serde::de::Error::custom),
        }
    }
}

fn parse_range(s: &str) -> Result<PortMatcher, ScopeError> {
    if let Ok(single) = s.parse::<u16>() {
        return Ok(PortMatcher::single(single));
    }
    let Some((low, high)) = s.split_once('-') else {
        return Err(ScopeError::PortRange(
            s.to_owned(),
            "expected '<low>-<high>' or single port".into(),
        ));
    };
    let low: u16 = low
        .trim()
        .parse()
        .map_err(|e: std::num::ParseIntError| ScopeError::PortRange(s.to_owned(), e.to_string()))?;
    let high: u16 = high
        .trim()
        .parse()
        .map_err(|e: std::num::ParseIntError| ScopeError::PortRange(s.to_owned(), e.to_string()))?;
    PortMatcher::range(low, high)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_matches() {
        let m = PortMatcher::single(80);
        assert!(m.matches(80));
        assert!(!m.matches(81));
    }

    #[test]
    fn range_matches_bounds_inclusive() {
        let m = PortMatcher::range(80, 90).unwrap();
        assert!(m.matches(80));
        assert!(m.matches(85));
        assert!(m.matches(90));
        assert!(!m.matches(79));
        assert!(!m.matches(91));
    }

    #[test]
    fn invalid_range_low_greater_than_high() {
        assert!(PortMatcher::range(100, 50).is_err());
    }

    #[test]
    fn parse_single() {
        let m: PortMatcher = serde_json::from_str("443").unwrap();
        assert_eq!(m, PortMatcher::single(443));
    }

    #[test]
    fn parse_range_string() {
        let m: PortMatcher = serde_json::from_str("\"8000-9000\"").unwrap();
        assert_eq!(m, PortMatcher::range(8000, 9000).unwrap());
    }

    #[test]
    fn parse_malformed_returns_err() {
        let r: Result<PortMatcher, _> = serde_json::from_str("\"abc\"");
        assert!(r.is_err());
    }
}
