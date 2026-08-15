//! Shared HTTP-over-reqwest core for mcpg's network backend plugins.
//!
//! The `http`, `grpc`, and `graphql` backend plugins all dispatch tool
//! calls as outbound HTTP/1.1+2 requests with the same security and
//! lifecycle requirements: a DNS-rebinding / SSRF guard, per-credential
//! `reqwest::Client` caching, body-limit truncation, and a structured
//! downstream-error envelope the gateway projects onto `tools/call`.
//!
//! Rather than triplicate that security-sensitive machinery, it lives
//! here once and each network plugin links this rlib:
//!
//! - [`client_registry`] — bounded per-credential `reqwest::Client`
//!   cache (LRU + idle eviction + revocation/rotation hooks).
//! - [`client`] — build a DNS-pinned `reqwest::Client` for one resolved
//!   bundle; the rebinding guard rejects private/loopback resolutions
//!   unless the binding opted in (`allow_private_backends`).
//! - [`exec`] — per-call request formatting + response reading (buffered
//!   and streaming), header filtering, query-string building.
//! - [`types`] — the request profile + method/call-mode/response shapes
//!   shared across the consuming plugins.
//! - [`retry`] — downstream-error classification + retry-guidance shaping
//!   (the `downstreamError` envelope slot the gateway reads to set
//!   `is_error`).
//!
//! This crate is a plain library, NOT a loadable plugin: it carries no
//! `plugin.yaml` and emits no `mcpg_plugin_register` symbol.

pub mod client;
pub mod client_registry;
pub mod exec;
pub mod retry;
pub mod runtime;
pub mod safe_dns;
pub mod types;
