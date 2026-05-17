//! Scope-enforcing egress proxy. The single network boundary in Mantis.
//!
//! Phase 0 milestone M0.3 delivers:
//!
//! - A TCP listener on localhost (or any operator-provided address).
//! - HTTP/1.1 CONNECT semantics for HTTPS tunneling.
//! - Scope evaluation on the *requested hostname* (not the resolved
//!   IP) per ADR-0003.
//! - Per-request budget decrement via `BudgetTracker::try_acquire_request`.
//! - Every allow/deny decision is appended to the engagement event
//!   log as a `ScopeDecisionLogged` event.
//! - Resolve-once-pin-IP for DNS-rebinding resistance.
//!
//! Plain HTTP forwarding (non-CONNECT methods) is deferred to a later
//! milestone. The scanner used in M0.5 talks HTTPS via CONNECT, which
//! is sufficient for the Phase 0 demo target set.
//!
//! See ADR-0004 for the full threat model.

pub mod error;
pub mod proxy;
pub mod request;

pub use crate::error::EgressError;
pub use crate::proxy::{EgressConfig, EgressProxy};
pub use crate::request::{parse_connect, ConnectRequest};
