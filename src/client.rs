//! Build a fresh `reqwest::Client` for one resolved-credential
//! bundle.
//!
//! Called from `lib.rs::resolve_client_for_call` on registry cache
//! miss. Performs DNS rebinding validation: walks the address list
//! returned by `tokio::net::lookup_host` and picks the first
//! non-private one (or fails if all are private and
//! `allow_private_backends == false`). The chosen `SocketAddr` is
//! pinned via `ClientBuilder::resolve` so subsequent calls against
//! the same client reuse the validated resolution. Pinning closes
//! the DNS-rebinding TOCTOU window: without it, reqwest would
//! re-resolve the host per call, letting an attacker-controlled DNS
//! record flip to a private/loopback address after the initial
//! validation and reach internal services (SSRF).

use std::sync::Arc;

use anyhow::{Context, Result};
use mcpg_plugin_protocol::security::is_private_address;
use url::Url;

use crate::exec::build_default_headers;
use crate::types::{HttpBackendMethod, HttpRequestProfile};

/// Build a `reqwest::Client` for the given resolved URL + headers
/// bundle. The client bakes in DNS pinning + default headers +
/// timeout + redirect=none.
///
/// Errors when DNS resolution fails or the rebinding guard rejects
/// every resolved address.
pub async fn build_http_client(
    profile: &HttpRequestProfile,
    resolved_url: &str,
    resolved_headers: &std::collections::BTreeMap<String, String>,
) -> Result<Arc<reqwest::Client>> {
    // The resolved URL may carry credentials in its userinfo, so a parse
    // failure must not echo it back into the error.
    let url =
        Url::parse(resolved_url).map_err(|_| anyhow::anyhow!("resolved URL failed to parse"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL has no host"))?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("URL has no port and no default for the scheme"))?;

    let pairs: Vec<_> = tokio::net::lookup_host(format!("{host}:{port}"))
        .await
        .with_context(|| format!("DNS resolution failed for {host}:{port}"))?
        .collect();
    if pairs.is_empty() {
        anyhow::bail!("DNS resolution returned no addresses for {host}");
    }
    let resolved = if profile.allow_private_backends {
        pairs[0]
    } else {
        pairs
            .iter()
            .find(|a| !is_private_address(&a.ip()))
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "DNS rebinding guard: host '{}' resolved only to private addresses ({})",
                    host,
                    pairs
                        .iter()
                        .map(|a| a.ip().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?
    };

    let is_json_call = matches!(profile.method, HttpBackendMethod::Post);
    let default_headers =
        build_default_headers(resolved_headers, is_json_call).map_err(anyhow::Error::msg)?;

    let client = reqwest::Client::builder()
        .timeout(profile.timeout)
        .resolve(&host, resolved)
        .default_headers(default_headers)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .with_context(|| "reqwest client build failed")?;

    Ok(Arc::new(client))
}
