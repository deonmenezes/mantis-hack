//! Daemon-served Web UI (PRD §9.3, M4.3).
//!
//! Self-contained tokio HTTP/1.1 server. Three endpoints:
//! - `GET /` — embedded SvelteKit-style HTML shell that polls
//!   `/api/state` and subscribes to `/api/events` (SSE).
//! - `GET /api/state` — current `WebState` snapshot as JSON.
//! - `GET /api/events` — Server-Sent Events stream of [`Event`]s
//!   broadcast by the daemon.
//!
//! Why not axum/hyper directly? Keeping the deps small. The full
//! routing surface here is three paths, so a hand-rolled HTTP/1.1
//! parser via `httparse` is cheaper than pulling in tower + axum
//! and just as testable. A future M4.3b can swap in axum without
//! changing the public API.

pub mod server;
pub mod state;

pub use server::{serve, ServeHandle, ServerError};
pub use state::{ClaimView, EngagementView, Event, EventChannel, WebState};
