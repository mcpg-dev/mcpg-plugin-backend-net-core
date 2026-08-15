//! Request profile + method / call-mode / response shapes shared by the
//! network backend plugins (http, grpc, graphql).
//!
//! The http crate re-exports them so its own `types::` paths keep
//! resolving, and grpc/graphql build a [`HttpRequestProfile`] directly
//! from their own specs.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;

/// HTTP method discriminator shared by every net-backed binding and
/// the HTTP completion endpoint. Only `Post` and `Get` are supported
/// today — other methods can be added when an operator surfaces a
/// requirement.
///
/// Accepts any common casing — `get` / `GET` / `Get` (and likewise for
/// `post`) all deserialize — so the operator-facing `method:` field has
/// ONE vocabulary regardless of which net binding or the completion
/// endpoint it sits on.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HttpBackendMethod {
    #[serde(alias = "POST", alias = "Post")]
    Post,
    #[serde(alias = "GET", alias = "Get")]
    Get,
}

/// Per-profile runtime state. Stable across calls; replaced on
/// hot-reload — in-flight calls hold their own clone so the swap is
/// safe.
#[derive(Debug, Clone)]
pub struct HttpRequestProfile {
    pub url: String,
    pub method: HttpBackendMethod,
    pub headers: BTreeMap<String, String>,
    pub expected_status_codes: Vec<u16>,
    pub require_json_response: bool,
    pub max_response_bytes: usize,
    pub timeout: Duration,
    pub allow_private_backends: bool,
}

/// Call mode resolved from the binding's `method`. JSON-body for
/// POST, query-string for GET. Drives idempotency semantics for
/// the retry-guidance shaping in the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpCallMode {
    JsonBody,
    QueryString,
}

impl HttpCallMode {
    pub fn for_method(method: HttpBackendMethod) -> Self {
        match method {
            HttpBackendMethod::Post => Self::JsonBody,
            HttpBackendMethod::Get => Self::QueryString,
        }
    }

    pub fn request_kind(self) -> &'static str {
        match self {
            Self::JsonBody => "json_body",
            Self::QueryString => "query_string",
        }
    }

    pub fn retry_safety_context(self) -> RetrySafetyContext {
        match self {
            Self::JsonBody => RetrySafetyContext::PotentiallyNonIdempotentJsonCall,
            Self::QueryString => RetrySafetyContext::ReadOnlyProbe,
        }
    }
}

/// Retry-safety class — fed into the downstream-error shaping. GET-style
/// read-only probes are flagged safe-for-automatic-retry; POST-style
/// JSON calls require operator idempotency review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetrySafetyContext {
    ReadOnlyProbe,
    PotentiallyNonIdempotentJsonCall,
}

/// Outcome of a single HTTP call. Carries enough state for the envelope
/// builder to render the structured-content response without further IO.
#[derive(Debug, Clone)]
pub struct HttpResponseSummary {
    pub status_code: u16,
    pub content_type: Option<String>,
    pub retry_after_ms: Option<u64>,
    pub body: String,
    pub body_truncated: bool,
    pub duration_ms: u128,
}
