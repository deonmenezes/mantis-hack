//! Inbound message parsing (operator → daemon).

use serde::{Deserialize, Serialize};

use crate::platform::PlatformId;

/// Raw inbound message from a platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundMessage {
    pub platform: PlatformId,
    pub remote_id: String,
    pub body: String,
    pub received_at_unix: u64,
}

/// Operator command, parsed from an inbound message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    Status {
        engagement_id: Option<String>,
    },
    Halt {
        engagement_id: String,
    },
    Focus {
        engagement_id: String,
        hint: String,
    },
    ApproveLiveVerification {
        engagement_id: String,
        primitive_id: String,
    },
    DenyLiveVerification {
        engagement_id: String,
        primitive_id: String,
    },
    Help,
    Unknown(String),
}

impl Command {
    pub fn parse(body: &str) -> Self {
        let body = body.trim();
        let mut parts = body.split_whitespace();
        let head = parts.next().unwrap_or("");
        let lower = head.to_ascii_lowercase();
        match lower.as_str() {
            "/status" | "status" => Command::Status {
                engagement_id: parts.next().map(str::to_owned),
            },
            "/halt" | "halt" => match parts.next() {
                Some(id) => Command::Halt {
                    engagement_id: id.to_owned(),
                },
                None => Command::Unknown(body.to_owned()),
            },
            "/focus" | "focus" => match (parts.next(), parts.collect::<Vec<_>>().join(" ")) {
                (Some(id), hint) if !hint.is_empty() => Command::Focus {
                    engagement_id: id.to_owned(),
                    hint,
                },
                _ => Command::Unknown(body.to_owned()),
            },
            "/approve" | "approve" => {
                let id = parts.next().unwrap_or("").to_owned();
                let prim = parts.next().unwrap_or("").to_owned();
                if id.is_empty() || prim.is_empty() {
                    Command::Unknown(body.to_owned())
                } else {
                    Command::ApproveLiveVerification {
                        engagement_id: id,
                        primitive_id: prim,
                    }
                }
            }
            "/deny" | "deny" => {
                let id = parts.next().unwrap_or("").to_owned();
                let prim = parts.next().unwrap_or("").to_owned();
                if id.is_empty() || prim.is_empty() {
                    Command::Unknown(body.to_owned())
                } else {
                    Command::DenyLiveVerification {
                        engagement_id: id,
                        primitive_id: prim,
                    }
                }
            }
            "/help" | "help" | "?" => Command::Help,
            _ => Command::Unknown(body.to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_with_optional_engagement() {
        assert_eq!(
            Command::parse("/status"),
            Command::Status {
                engagement_id: None
            }
        );
        assert_eq!(
            Command::parse("/status 01HXX"),
            Command::Status {
                engagement_id: Some("01HXX".into())
            }
        );
    }

    #[test]
    fn parse_halt_requires_id() {
        assert_eq!(Command::parse("/halt"), Command::Unknown("/halt".into()));
        assert_eq!(
            Command::parse("halt 01HXX"),
            Command::Halt {
                engagement_id: "01HXX".into()
            }
        );
    }

    #[test]
    fn parse_focus_with_hint() {
        assert_eq!(
            Command::parse("/focus 01HXX try open redirect"),
            Command::Focus {
                engagement_id: "01HXX".into(),
                hint: "try open redirect".into(),
            }
        );
    }

    #[test]
    fn parse_approve_and_deny() {
        assert_eq!(
            Command::parse("/approve 01HXX sqli.error-based"),
            Command::ApproveLiveVerification {
                engagement_id: "01HXX".into(),
                primitive_id: "sqli.error-based".into(),
            }
        );
        assert_eq!(
            Command::parse("/deny 01HXX sqli.error-based"),
            Command::DenyLiveVerification {
                engagement_id: "01HXX".into(),
                primitive_id: "sqli.error-based".into(),
            }
        );
    }

    #[test]
    fn parse_help_variants() {
        assert_eq!(Command::parse("/help"), Command::Help);
        assert_eq!(Command::parse("help"), Command::Help);
        assert_eq!(Command::parse("?"), Command::Help);
    }

    #[test]
    fn unknown_message_returned_verbatim() {
        assert_eq!(
            Command::parse("hi everyone"),
            Command::Unknown("hi everyone".into())
        );
    }
}
