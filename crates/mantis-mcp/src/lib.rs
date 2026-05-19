//! MCP stdio server that fronts the Mantis daemon.
//!
//! This crate ships a single binary, `mantis-mcp`, that speaks the
//! Model Context Protocol over stdio. It is registered by the Claude
//! Code plugin as an MCP server, which lets the host LLM drive a
//! Mantis engagement by calling tools (`mantis_create_engagement`,
//! `mantis_authorize_scope`, `mantis_run_recon`, ...) instead of
//! shelling out to `mantis pentest` and polling the daemon for
//! `state=complete`. The shift from a rigid sequencer to an
//! LLM-orchestrated tool loop fixes the budget-hang and
//! redirect-dead-end bugs in the existing pentest pipeline.
//!
//! # Attribution
//!
//! The MCP-tool-orchestrated workflow exposed here was inspired by
//! the Hacker Bob project (<https://github.com/vmihalis/hacker-bob>),
//! Apache License 2.0, Copyright 2026 Michail Vasileiadis and
//! contributors. Hacker Bob is implemented in Node.js; this crate is
//! an independent Rust implementation built on `rmcp`. No Hacker Bob
//! source code was copied or ported — only the architectural pattern
//! of letting the host LLM drive engagement state through MCP tools.
//! See `/NOTICE` at the repository root for the full attribution.
//!
//! Architecturally, `mantis-mcp` is a thin adapter:
//! - `server` exposes the `MantisMcpServer` type and its tool router.
//! - `daemon` wraps the generated tonic client from `mantis-proto`.
//! - `scope` constructs the signed scope manifest authorized clients
//!   must send to the daemon's `Authorize` RPC.

pub mod daemon;
pub mod scope;
pub mod server;
pub mod utility_tools;
pub mod wave;
