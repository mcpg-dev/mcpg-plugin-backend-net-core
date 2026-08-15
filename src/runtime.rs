//! Shared per-profile network runtime + per-call resolution for the
//! network backend plugins (http, grpc, graphql).
//!
//! [`NetworkProfileRuntime`] owns everything a binding profile needs
//! across calls — the per-credential `reqwest::Client` cache, the
//! credential-revocation / secret-rotation / idle-eviction
//! subscriptions, and the compiled CEL templates for the URL + headers
//! — and resolves a client per call: evaluate the operator's CEL
//! templates against this call's args + identity, substitute `cred://`
//! references through the host, digest the resulting bundle, and pull
//! (or build, behind the DNS-rebinding guard) a `reqwest::Client` from
//! the registry.
//!
//! This is the single home for the security-sensitive resolution flow;
//! each plugin builds a `NetworkProfileRuntime` at `register_profile`
//! time and assembles its own family-specific request/envelope around
//! [`NetworkProfileRuntime::resolve_client`].

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use mcpg_expr::{DynamicValue, ExprContext, ExprRequestContext};
use mcpg_plugin_protocol::{
    BackendHost, BackendHostError, BackendInvocationContext, BackendRequest,
    CredentialRevocationSubscription, SecretRotationSubscription,
};

use crate::client::build_http_client;
use crate::client_registry::{
    self, ClientRegistry, ClientRegistryConfig, CredDigest, IdleSweeper, collect_cred_refs,
    digest_credential_bundle,
};
use crate::types::HttpRequestProfile;

/// Resolved per-call values produced by
/// [`NetworkProfileRuntime::resolve_client`] — the post-CEL +
/// post-cred URL and header map plus the `reqwest::Client` from the
/// registry that's bound to that bundle.
pub struct ResolvedCall {
    pub client: Arc<reqwest::Client>,
    pub resolved_url: String,
    pub resolved_headers: BTreeMap<String, String>,
}

/// Per-profile network runtime shared across the network backend
/// plugins. Cheap to clone (every field is `Arc`-backed or a small
/// owned value); the dispatch path clones it out of the profile map
/// so the read lock isn't held across the upstream call.
#[derive(Clone)]
pub struct NetworkProfileRuntime {
    profile: HttpRequestProfile,
    /// Operator-supplied (un-evaluated) URL + headers. Retained for
    /// `cred://` scanning (revocation routing keys) and for callers
    /// that need to inspect the static config (e.g. an operator-pinned
    /// `Idempotency-Key`).
    raw_url: String,
    raw_headers: BTreeMap<String, String>,
    has_cred_refs: bool,
    compiled_url: Arc<DynamicValue<String>>,
    compiled_headers: Arc<BTreeMap<String, DynamicValue<String>>>,
    host: Arc<dyn BackendHost>,
    client_registry: Arc<ClientRegistry>,
    /// Held for the profile lifetime so the host callbacks stay
    /// subscribed + the sweeper keeps running. Drop = unsubscribe /
    /// cancel.
    _revocation_sub: Arc<CredentialRevocationSubscription>,
    _rotation_sub: Arc<SecretRotationSubscription>,
    _idle_sweeper: Arc<IdleSweeper>,
}

impl std::fmt::Debug for NetworkProfileRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkProfileRuntime")
            .field("url", &self.raw_url)
            .field("has_cred_refs", &self.has_cred_refs)
            .finish()
    }
}

impl NetworkProfileRuntime {
    /// Compile the CEL templates + wire the revocation / rotation /
    /// idle subscriptions for one binding profile.
    ///
    /// `raw_url` / `raw_headers` are the operator-supplied (pre-CEL)
    /// values; `profile` carries the timeout / SSRF / body-limit knobs.
    /// `secret_refs` is the gateway's post-resolution
    /// `__mcpg_secret_refs` hint — the rotation subscription only
    /// evicts when a rotating `secret_ref` is in this set. Returns
    /// `Err` on a CEL parse failure; the caller maps it onto its own
    /// `InvalidSpec`.
    pub fn register(
        backend_name: &str,
        raw_url: String,
        raw_headers: BTreeMap<String, String>,
        profile: HttpRequestProfile,
        host: Arc<dyn BackendHost>,
        secret_refs: Vec<String>,
    ) -> Result<Self, String> {
        let has_cred_refs =
            raw_url.contains("cred://") || raw_headers.values().any(|v| v.contains("cred://"));

        // Compile CEL expressions at register time. Plain literals
        // (no `${`) compile to `DynamicValue::Literal` and skip the
        // CEL engine entirely; `$env.X` is already substituted by the
        // gateway's config pre-pass, so only `$arguments` / `$context`
        // resolve per call inside `resolve_client`.
        let compiled_url =
            DynamicValue::<String>::parse(&raw_url).map_err(|e| format!("url expression: {e}"))?;
        let mut compiled_headers: BTreeMap<String, DynamicValue<String>> = BTreeMap::new();
        for (name, value) in &raw_headers {
            let dv = DynamicValue::<String>::parse(value)
                .map_err(|e| format!("header '{name}' expression: {e}"))?;
            compiled_headers.insert(name.clone(), dv);
        }

        let client_registry = Arc::new(ClientRegistry::new(ClientRegistryConfig::default()));

        // Credential revocation → evict matching cached clients. Held
        // in the runtime so unsubscribe happens at profile teardown.
        let registry_for_cb = Arc::clone(&client_registry);
        let revocation_sub =
            host.subscribe_credential_revoked(Arc::new(move |plugin_id: &str, target: &str| {
                let registry = Arc::clone(&registry_for_cb);
                let plugin_id = plugin_id.to_owned();
                let target = target.to_owned();
                tokio::spawn(async move {
                    let evicted = registry.evict_for(&plugin_id, &target).await;
                    if evicted > 0 {
                        tracing::info!(
                            target: "mcpg::net_core::client_registry",
                            plugin_id = %plugin_id,
                            target = %target,
                            evicted = evicted,
                            "evicted clients on credential revocation"
                        );
                    }
                });
            }));

        // Secret rotation (URI-scoped) → evict every client whose
        // resolved bundle derived from a rotating `vault://...` URI.
        // Filtered to the URIs the gateway flagged as touching this
        // profile.
        let registry_for_rotation = Arc::clone(&client_registry);
        let secret_refs_for_cb: Arc<Vec<String>> = Arc::new(secret_refs);
        let rotation_sub =
            host.subscribe_secret_rotation(Arc::new(move |secret_ref: &str, version: u64| {
                if !secret_refs_for_cb.iter().any(|r| r == secret_ref) {
                    return;
                }
                let registry = Arc::clone(&registry_for_rotation);
                let secret_ref = secret_ref.to_owned();
                tokio::spawn(async move {
                    let evicted = registry.evict_for_secret(&secret_ref).await;
                    if evicted > 0 {
                        tracing::info!(
                            target: "mcpg::net_core::client_registry",
                            secret_ref = %secret_ref,
                            version = version,
                            evicted = evicted,
                            "evicted clients on secret rotation"
                        );
                    }
                });
            }));

        let idle_sweeper = client_registry::spawn_idle_sweeper(
            backend_name.to_owned(),
            Arc::clone(&client_registry),
            Duration::from_secs(60),
        );

        Ok(Self {
            profile,
            raw_url,
            raw_headers,
            has_cred_refs,
            compiled_url: Arc::new(compiled_url),
            compiled_headers: Arc::new(compiled_headers),
            host,
            client_registry,
            _revocation_sub: Arc::new(revocation_sub),
            _rotation_sub: Arc::new(rotation_sub),
            _idle_sweeper: idle_sweeper,
        })
    }

    /// The timeout / SSRF / body-limit knobs for this profile.
    pub fn profile(&self) -> &HttpRequestProfile {
        &self.profile
    }

    /// Whether the operator's URL or any header carries a `cred://`
    /// reference (drives per-call credential resolution).
    pub fn has_cred_refs(&self) -> bool {
        self.has_cred_refs
    }

    /// True when the operator's static config binds `name`
    /// (case-insensitive HTTP/1.1 header match).
    pub fn operator_has_header(&self, name: &str) -> bool {
        self.raw_headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case(name))
    }

    /// Acquire a `reqwest::Client` for this profile's base URL with no
    /// per-call CEL templating or `cred://` resolution — the path the
    /// HTTP completion endpoint uses (read-shaped, keystroke-driven, no
    /// caller args). Keyed on the base URL only, so it shares cache
    /// entries with static-cred tool calls against the same host and
    /// inherits the DNS-rebinding guard inside `build_http_client`.
    pub async fn resolve_static_client(&self) -> Result<Arc<reqwest::Client>, String> {
        let digest_pairs = vec![("url".to_owned(), self.profile.url.clone())];
        let digest = digest_credential_bundle(&digest_pairs);
        let profile = self.profile.clone();
        let url = self.profile.url.clone();
        let headers: BTreeMap<String, String> = BTreeMap::new();
        self.client_registry
            .get_or_build(digest, Vec::new(), || async move {
                build_http_client(&profile, &url, &headers).await
            })
            .await
            .map_err(|e| format!("building HTTP client: {e}"))
    }

    /// Single per-call resolution path. Evaluates the
    /// operator's compiled CEL templates against this call's args +
    /// identity, runs `cred://` substitution through the host when any
    /// header / url carries a credential reference, digests the
    /// resulting bundle, and pulls (or builds) a per-bundle
    /// `reqwest::Client` from the registry.
    pub async fn resolve_client(
        &self,
        expr_ctx: &ExprContext,
        request: &BackendRequest,
        backend_name: &str,
    ) -> Result<ResolvedCall, String> {
        // 1. Collect the `${cred://issuer/target}` references the operator
        // baked into the url / header templates. These come from the PARSED
        // template structure (`cred_refs()`), so they are config-origin BY
        // CONSTRUCTION: a request argument interpolated into a `${…}` CEL
        // segment is only a value and can never introduce a credential
        // reference. Bare `cred://…` *outside* `${}` is NOT a credential
        // reference — it travels to the upstream verbatim.
        let mut cred_uris: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for uri in self.compiled_url.cred_refs() {
            cred_uris.insert(uri.to_owned());
        }
        for dv in self.compiled_headers.values() {
            for uri in dv.cred_refs() {
                cred_uris.insert(uri.to_owned());
            }
        }

        // 2. Resolve those references through the host, per caller identity,
        // in one call → `uri → resolved value`.
        let cred_map: std::collections::HashMap<String, String> = if cred_uris.is_empty() {
            std::collections::HashMap::new()
        } else {
            let mut snapshot = serde_json::Map::new();
            for uri in &cred_uris {
                snapshot.insert(uri.clone(), serde_json::Value::String(uri.clone()));
            }
            let mut snapshot = serde_json::Value::Object(snapshot);

            let mut host_ctx = BackendInvocationContext::root(
                request.request_id.clone(),
                request.session_id.clone(),
                backend_name.to_owned(),
            );
            host_ctx.identity = request.identity.clone();
            self.host
                .resolve_credentials(&host_ctx, &mut snapshot)
                .await
                .map_err(|e| match e {
                    BackendHostError::Backend { cause, .. } => cause.to_string(),
                    other => format!("credential resolution: {other}"),
                })?;

            snapshot
                .as_object()
                .map(|o| {
                    o.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                        .collect()
                })
                .unwrap_or_default()
        };

        // 3. Evaluate compiled URL + per-header templates, filling any
        // `${cred://…}` segment from the resolved map.
        let resolve_cred = |uri: &str| cred_map.get(uri).cloned();
        let resolved_url = self
            .compiled_url
            .resolve_with_credentials(expr_ctx, resolve_cred)
            .map_err(|e| format!("evaluating URL expression: {e}"))?;
        let mut resolved_headers: BTreeMap<String, String> = BTreeMap::new();
        for (name, expr) in self.compiled_headers.iter() {
            let value = expr
                .resolve_with_credentials(expr_ctx, resolve_cred)
                .map_err(|e| format!("evaluating header '{name}' expression: {e}"))?;
            mcpg_expr::validate_header_value(name, &value)
                .map_err(|e| format!("header '{name}': {e}"))?;
            resolved_headers.insert(name.clone(), value);
        }

        // 3. Digest pairs: url + per-header (hdr:<name>) entries.
        // Order-independent across header iteration.
        let mut digest_pairs: Vec<(String, String)> =
            Vec::with_capacity(1 + resolved_headers.len());
        digest_pairs.push(("url".into(), resolved_url.clone()));
        for (k, v) in &resolved_headers {
            digest_pairs.push((format!("hdr:{}", k.to_ascii_lowercase()), v.clone()));
        }
        let digest: CredDigest = digest_credential_bundle(&digest_pairs);

        // 4. Pre-resolution `cred://` refs route revocation events.
        // Walk the operator-supplied (un-evaluated) values so the keys
        // are stable across calls regardless of the args used.
        let mut cred_keys: Vec<(String, String)> = Vec::new();
        if let Some(refs) = collect_cred_refs(&self.raw_url) {
            cred_keys.extend(refs);
        }
        for v in self.raw_headers.values() {
            if let Some(refs) = collect_cred_refs(v) {
                cred_keys.extend(refs);
            }
        }
        cred_keys.sort();
        cred_keys.dedup();

        // 5. Look up / build the client.
        let profile = self.profile.clone();
        let resolved_url_for_build = resolved_url.clone();
        let resolved_headers_for_build = resolved_headers.clone();
        let client = self
            .client_registry
            .get_or_build(digest, cred_keys, || async move {
                build_http_client(
                    &profile,
                    &resolved_url_for_build,
                    &resolved_headers_for_build,
                )
                .await
            })
            .await
            .map_err(|e| format!("building HTTP client: {e}"))?;

        Ok(ResolvedCall {
            client,
            resolved_url,
            resolved_headers,
        })
    }
}

/// Build an [`ExprContext`] for one call. Identity claims propagate to
/// `$context.principal_id` / `$context.trust_level` /
/// `$context.auth_provider` / `$context.session_id` /
/// `$context.transport` / `$context.roles` / `$context.groups` /
/// `$context.scopes` / `$context.attributes`. `$env.*` is empty because
/// the gateway resolves env vars at config-load time before the plugin
/// sees the spec.
pub fn build_expr_context(
    arguments: &serde_json::Value,
    tool_name: &str,
    request: &BackendRequest,
) -> ExprContext {
    let mut ctx = ExprRequestContext {
        session_id: request.session_id.clone(),
        ..ExprRequestContext::default()
    };
    if let Some(identity) = request.identity.as_ref() {
        ctx.principal_id = identity.subject_id.clone();
        ctx.trust_level = identity.trust_level.clone();
        ctx.auth_provider = identity.auth_provider.clone();
        ctx.transport = identity.kind.clone();
        ctx.roles = identity.roles.clone();
        ctx.groups = identity.groups.clone();
        ctx.scopes = identity.scopes.clone();
        ctx.attributes = identity.attributes.clone();
    }
    ExprContext {
        arguments: arguments.clone(),
        tool_name: tool_name.to_owned(),
        context: ctx,
        steps: None,
        env: Arc::new(HashMap::new()),
    }
}
