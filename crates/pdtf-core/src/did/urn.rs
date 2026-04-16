//! PDTF URN validation and parsing.
//!
//! Supported URN types (`urn:pdtf` namespace):
//! - `urn:pdtf:uprn:{uprn}`
//! - `urn:pdtf:titleNumber:{number}`
//! - `urn:pdtf:unregisteredTitle:{uuid}`
//! - `urn:pdtf:capacity:{uuid}`
//! - `urn:pdtf:representation:{uuid}`
//! - `urn:pdtf:consent:{uuid}`
//! - `urn:pdtf:offer:{uuid}`

use crate::error::{PdtfError, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

static UUID_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap()
});
static UPRN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\d{1,12}$").unwrap());
static TITLE_NUMBER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Z]{1,3}\d{1,6}$").unwrap());

/// PDTF URN types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PdtfUrnType {
    Uprn,
    TitleNumber,
    UnregisteredTitle,
    Ownership,
    Representation,
    Consent,
    Offer,
}

impl PdtfUrnType {
    fn as_str(&self) -> &str {
        match self {
            Self::Uprn => "uprn",
            Self::TitleNumber => "titleNumber",
            Self::UnregisteredTitle => "unregisteredTitle",
            Self::Ownership => "ownership",
            Self::Representation => "representation",
            Self::Consent => "consent",
            Self::Offer => "offer",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "uprn" => Some(Self::Uprn),
            "titleNumber" => Some(Self::TitleNumber),
            "unregisteredTitle" => Some(Self::UnregisteredTitle),
            "ownership" => Some(Self::Ownership),
            "representation" => Some(Self::Representation),
            "consent" => Some(Self::Consent),
            "offer" => Some(Self::Offer),
            _ => None,
        }
    }

    fn validator(&self) -> &Lazy<Regex> {
        match self {
            Self::Uprn => &UPRN_RE,
            Self::TitleNumber => &TITLE_NUMBER_RE,
            _ => &UUID_RE,
        }
    }
}

/// Parsed PDTF URN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedUrn {
    pub urn_type: PdtfUrnType,
    pub value: String,
    pub raw: String,
}

/// Parse a PDTF URN into its components.
pub fn parse_pdtf_urn(urn: &str) -> Result<ParsedUrn> {
    if !urn.starts_with("urn:pdtf:") {
        return Err(PdtfError::InvalidUrn(format!("Not a PDTF URN: {urn}")));
    }

    let rest = &urn["urn:pdtf:".len()..];
    let colon_idx = rest
        .find(':')
        .ok_or_else(|| PdtfError::InvalidUrn(format!("Invalid PDTF URN format: {urn}")))?;

    let type_str = &rest[..colon_idx];
    let value = &rest[colon_idx + 1..];

    let urn_type = PdtfUrnType::from_str(type_str)
        .ok_or_else(|| PdtfError::InvalidUrn(format!("Unknown PDTF URN type: {type_str}")))?;

    if !urn_type.validator().is_match(value) {
        return Err(PdtfError::InvalidUrn(format!(
            "Invalid value for urn:pdtf:{}: \"{value}\"",
            urn_type.as_str()
        )));
    }

    Ok(ParsedUrn {
        urn_type,
        value: value.to_string(),
        raw: urn.to_string(),
    })
}

/// Validate a PDTF URN string.
pub fn validate_pdtf_urn(urn: &str) -> bool {
    parse_pdtf_urn(urn).is_ok()
}

/// Create a PDTF URN from type and value.
pub fn create_pdtf_urn(urn_type: &PdtfUrnType, value: &str) -> Result<String> {
    let urn = format!("urn:pdtf:{}:{value}", urn_type.as_str());
    parse_pdtf_urn(&urn)?; // validates
    Ok(urn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uprn() {
        let parsed = parse_pdtf_urn("urn:pdtf:uprn:123456789").unwrap();
        assert_eq!(parsed.urn_type, PdtfUrnType::Uprn);
        assert_eq!(parsed.value, "123456789");
    }

    #[test]
    fn test_parse_title_number() {
        let parsed = parse_pdtf_urn("urn:pdtf:titleNumber:AGL123456").unwrap();
        assert_eq!(parsed.urn_type, PdtfUrnType::TitleNumber);
        assert_eq!(parsed.value, "AGL123456");
    }

    #[test]
    fn test_parse_ownership_uuid() {
        let parsed =
            parse_pdtf_urn("urn:pdtf:capacity:550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(parsed.urn_type, PdtfUrnType::Ownership);
    }

    #[test]
    fn test_invalid_urn_prefix() {
        assert!(parse_pdtf_urn("urn:other:uprn:123").is_err());
    }

    #[test]
    fn test_invalid_uprn_value() {
        assert!(parse_pdtf_urn("urn:pdtf:uprn:abc").is_err());
    }

    #[test]
    fn test_invalid_title_number() {
        assert!(parse_pdtf_urn("urn:pdtf:titleNumber:123").is_err());
    }

    #[test]
    fn test_unknown_type() {
        assert!(parse_pdtf_urn("urn:pdtf:unknown:value").is_err());
    }

    #[test]
    fn test_create_pdtf_urn() {
        let urn = create_pdtf_urn(&PdtfUrnType::Uprn, "123456789").unwrap();
        assert_eq!(urn, "urn:pdtf:uprn:123456789");
    }

    #[test]
    fn test_validate() {
        assert!(validate_pdtf_urn("urn:pdtf:uprn:123456789"));
        assert!(!validate_pdtf_urn("not:a:urn"));
    }
}
