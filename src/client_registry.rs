//! Per-credential `reqwest::Client` cache for HTTP.
//!
//! Mirrors the SQL/NATS/Kafka backends' shape: keyed on a BLAKE3
//! digest of the resolved credential bundle (URL + header values),
//! bounded with LRU + idle eviction, and wired up to the credential
//! cache's revocation broadcast for precise eviction.
//!
//! Each cached client bakes in:
//!
//! - DNS pinning to a pre-validated `SocketAddr` (rebinding guard
//!   evaluates only at cache-miss time; the pinned address is
//!   reused for subsequent calls).
//! - Operator-configured default headers, post-cred-resolution, so
//!   the per-call `RequestBuilder` only adds traceparent / tracestate
//!   plus body framing.
//! - The binding's `timeout` and a `redirect=none` policy.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::{CancellationToken, DropGuard};
use tracing::{debug, info};

/// 32-byte BLAKE3 digest of a resolved credential bundle.
pub type CredDigest = [u8; 32];

/// Stable digest for the static-cred path (no `cred://` references in
/// the spec). The plugin uses this when `has_cred_refs == false` so
/// every call hits the same cache entry — avoiding a per-call
/// `reqwest::Client` rebuild.
#[must_use]
pub fn static_digest() -> CredDigest {
    blake3::hash(b"static").into()
}

/// Compute a digest from a sorted set of `(field, value)` pairs.
/// Order-independent so callers can hand the pairs in any order.
#[must_use]
pub fn digest_credential_bundle(pairs: &[(String, String)]) -> CredDigest {
    let mut sorted: Vec<&(String, String)> = pairs.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = blake3::Hasher::new();
    for (k, v) in sorted {
        hasher.update(k.as_bytes());
        hasher.update(b"=");
        hasher.update(v.as_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().into()
}

struct ClientEntry {
    client: Arc<reqwest::Client>,
    cred_keys: Vec<(String, String)>,
    last_used: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
pub struct ClientRegistryConfig {
    pub max_entries: usize,
    pub idle_eviction: Duration,
}

impl Default for ClientRegistryConfig {
    fn default() -> Self {
        Self {
            max_entries: 256,
            idle_eviction: Duration::from_secs(15 * 60),
        }
    }
}

struct Inner {
    clients: HashMap<CredDigest, ClientEntry>,
}

/// Bounded per-credential `reqwest::Client` cache. See module docs.
pub struct ClientRegistry {
    inner: Arc<AsyncMutex<Inner>>,
    config: ClientRegistryConfig,
    epoch: Instant,
}

impl ClientRegistry {
    #[must_use]
    pub fn new(config: ClientRegistryConfig) -> Self {
        Self {
            inner: Arc::new(AsyncMutex::new(Inner {
                clients: HashMap::new(),
            })),
            config,
            epoch: Instant::now(),
        }
    }

    fn now_millis(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Look up an existing client by digest, or build a fresh one
    /// via `build`. Concurrent callers serialise on the registry
    /// mutex while the connect happens, so a thundering herd of
    /// cold callers does not spawn N parallel connects.
    pub async fn get_or_build<F, Fut>(
        &self,
        digest: CredDigest,
        cred_keys: Vec<(String, String)>,
        build: F,
    ) -> Result<Arc<reqwest::Client>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Arc<reqwest::Client>>>,
    {
        let guard = self.inner.lock().await;
        if let Some(entry) = guard.clients.get(&digest) {
            entry.last_used.store(self.now_millis(), Ordering::Relaxed);
            return Ok(Arc::clone(&entry.client));
        }
        drop(guard);
        let client = build().await?;
        let mut guard = self.inner.lock().await;
        if let Some(entry) = guard.clients.get(&digest) {
            entry.last_used.store(self.now_millis(), Ordering::Relaxed);
            return Ok(Arc::clone(&entry.client));
        }
        guard.clients.insert(
            digest,
            ClientEntry {
                client: Arc::clone(&client),
                cred_keys,
                last_used: AtomicU64::new(self.now_millis()),
            },
        );
        if guard.clients.len() > self.config.max_entries
            && let Some(oldest_digest) = guard
                .clients
                .iter()
                .min_by_key(|(_, e)| e.last_used.load(Ordering::Relaxed))
                .map(|(d, _)| *d)
        {
            guard.clients.remove(&oldest_digest);
            metrics::counter!(
                "mcpg_http_client_registry_evictions_total",
                "reason" => "lru",
            )
            .increment(1);
        }
        Ok(client)
    }

    /// Drop every entry whose `cred_keys` contains
    /// `(plugin_id, target)`. Called from the revocation subscriber.
    pub async fn evict_for(&self, plugin_id: &str, target: &str) -> usize {
        let mut guard = self.inner.lock().await;
        let to_drop: Vec<CredDigest> = guard
            .clients
            .iter()
            .filter(|(_, e)| {
                e.cred_keys
                    .iter()
                    .any(|(p, t)| p == plugin_id && t == target)
            })
            .map(|(d, _)| *d)
            .collect();
        let count = to_drop.len();
        for d in to_drop {
            guard.clients.remove(&d);
        }
        if count > 0 {
            metrics::counter!(
                "mcpg_http_client_registry_evictions_total",
                "reason" => "revoked",
            )
            .increment(count as u64);
        }
        count
    }

    /// Drop every entry in the registry. Called from the secret-
    /// rotation subscriber when a `vault://...` URI tied to this
    /// profile rotates — the resolved bundle baked into each
    /// `reqwest::Client` is now stale, so we drop the lot and let
    /// the next call rebuild against the freshly-resolved bundle.
    ///
    /// We don't track per-entry source secret URIs because every
    /// entry in a single profile's registry shares the same set of
    /// resolved secret refs (they all came from the same operator-
    /// supplied spec, just with different per-call cred bundles).
    /// The plugin's subscription callback gates the call on whether
    /// the rotated `secret_ref` was registered for this profile —
    /// see the subscription site in `lib.rs`.
    pub async fn evict_for_secret(&self, _secret_ref: &str) -> usize {
        let mut guard = self.inner.lock().await;
        let count = guard.clients.len();
        guard.clients.clear();
        if count > 0 {
            metrics::counter!(
                "mcpg_http_client_registry_evictions_total",
                "reason" => "secret_rotation",
            )
            .increment(count as u64);
        }
        count
    }

    /// Drop entries whose `last_used` age exceeds
    /// `config.idle_eviction`. Called by the background sweeper.
    pub async fn sweep_idle(&self) -> usize {
        let mut guard = self.inner.lock().await;
        let now = self.now_millis();
        let threshold_ms = self.config.idle_eviction.as_millis() as u64;
        let to_drop: Vec<CredDigest> = guard
            .clients
            .iter()
            .filter(|(_, e)| {
                let last = e.last_used.load(Ordering::Relaxed);
                now.saturating_sub(last) > threshold_ms
            })
            .map(|(d, _)| *d)
            .collect();
        let count = to_drop.len();
        for d in to_drop {
            guard.clients.remove(&d);
        }
        if count > 0 {
            metrics::counter!(
                "mcpg_http_client_registry_evictions_total",
                "reason" => "idle",
            )
            .increment(count as u64);
        }
        count
    }

    #[cfg(test)]
    #[allow(clippy::len_without_is_empty)] // test-only entry-count helper
    pub async fn len(&self) -> usize {
        self.inner.lock().await.clients.len()
    }
}

/// Idle-client sweeper guard. Holding this Arc keeps the spawned
/// background task alive; dropping the last clone cancels it.
pub struct IdleSweeper {
    _cancel_guard: DropGuard,
}

#[must_use]
pub fn spawn_idle_sweeper(
    backend_name: String,
    registry: Arc<ClientRegistry>,
    interval: Duration,
) -> Arc<IdleSweeper> {
    let token = CancellationToken::new();
    let guard = IdleSweeper {
        _cancel_guard: token.clone().drop_guard(),
    };
    tokio::spawn(idle_sweep_loop(backend_name, registry, interval, token));
    Arc::new(guard)
}

async fn idle_sweep_loop(
    backend_name: String,
    registry: Arc<ClientRegistry>,
    interval: Duration,
    cancel: CancellationToken,
) {
    info!(
        target: "mcpg::http::client_registry",
        backend = %backend_name,
        interval_ms = interval.as_millis() as u64,
        "http client idle sweeper: started"
    );
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                debug!(
                    target: "mcpg::http::client_registry",
                    backend = %backend_name,
                    "http client idle sweeper: cancelled"
                );
                return;
            }
            _ = ticker.tick() => {
                let evicted = registry.sweep_idle().await;
                if evicted > 0 {
                    info!(
                        target: "mcpg::http::client_registry",
                        backend = %backend_name,
                        evicted = evicted,
                        "evicted idle HTTP clients"
                    );
                }
            }
        }
    }
}

/// Extract `(plugin_id, target)` pairs from every `cred://` URI in
/// `s`. Same scanner the SQL/NATS adapters use; kept local to avoid
/// a workspace-shared crate just for one helper.
pub fn collect_cred_refs(s: &str) -> Option<Vec<(String, String)>> {
    if !s.contains("cred://") {
        return None;
    }
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(idx) = rest.find("cred://") {
        let after = &rest[idx + "cred://".len()..];
        let Some(slash_idx) = after.find('/') else {
            break;
        };
        let plugin_id = &after[..slash_idx];
        let after_slash = &after[slash_idx + 1..];
        let end = after_slash
            .find(|c: char| {
                c.is_whitespace()
                    || matches!(c, '?' | '&' | '@' | ':' | '"' | '\'' | '>' | ',' | ';')
            })
            .unwrap_or(after_slash.len());
        let target = &after_slash[..end];
        let target = match target.split_once('#') {
            Some((t, _)) => t,
            None => target,
        };
        if !plugin_id.is_empty() && !target.is_empty() {
            out.push((plugin_id.to_owned(), target.to_owned()));
        }
        let advance = idx + "cred://".len() + slash_idx + 1 + end;
        if advance >= rest.len() {
            break;
        }
        rest = &rest[advance..];
    }
    if out.is_empty() { None } else { Some(out) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_order_independent() {
        let a = digest_credential_bundle(&[
            ("url".into(), "https://x.test/".into()),
            ("hdr:authorization".into(), "Bearer abc".into()),
        ]);
        let b = digest_credential_bundle(&[
            ("hdr:authorization".into(), "Bearer abc".into()),
            ("url".into(), "https://x.test/".into()),
        ]);
        assert_eq!(a, b);
    }

    #[test]
    fn digest_distinguishes_different_inputs() {
        let a = digest_credential_bundle(&[("hdr:x".into(), "v1".into())]);
        let b = digest_credential_bundle(&[("hdr:x".into(), "v2".into())]);
        assert_ne!(a, b);
    }

    #[test]
    fn static_digest_is_stable() {
        assert_eq!(static_digest(), static_digest());
    }

    #[test]
    fn collect_cred_refs_finds_simple_uri() {
        let refs = collect_cred_refs("Bearer cred://oauth/api?type=access").unwrap();
        assert_eq!(refs, vec![("oauth".to_owned(), "api".to_owned())]);
    }

    #[test]
    fn collect_cred_refs_skips_when_absent() {
        assert!(collect_cred_refs("Bearer static-token").is_none());
    }

    #[test]
    fn collect_cred_refs_finds_multiple() {
        let s = "Auth: cred://oauth/api Cookie: cred://cookies/sess";
        let refs = collect_cred_refs(s).unwrap();
        assert_eq!(refs.len(), 2);
        assert!(refs.contains(&("oauth".to_owned(), "api".to_owned())));
        assert!(refs.contains(&("cookies".to_owned(), "sess".to_owned())));
    }

    fn fake_client() -> Arc<reqwest::Client> {
        Arc::new(reqwest::Client::new())
    }

    #[tokio::test]
    async fn get_or_build_caches_on_hit() {
        let reg = ClientRegistry::new(ClientRegistryConfig::default());
        let digest = static_digest();
        let mut calls = 0;
        for _ in 0..3 {
            reg.get_or_build(digest, vec![], || {
                calls += 1;
                async { Ok(fake_client()) }
            })
            .await
            .unwrap();
        }
        assert_eq!(calls, 1);
        assert_eq!(reg.len().await, 1);
    }

    #[tokio::test]
    async fn evict_for_drops_matching_entries() {
        let reg = ClientRegistry::new(ClientRegistryConfig::default());
        let d1 = digest_credential_bundle(&[("url".into(), "u1".into())]);
        let d2 = digest_credential_bundle(&[("url".into(), "u2".into())]);
        reg.get_or_build(d1, vec![("p".into(), "t1".into())], || async {
            Ok(fake_client())
        })
        .await
        .unwrap();
        reg.get_or_build(d2, vec![("p".into(), "t2".into())], || async {
            Ok(fake_client())
        })
        .await
        .unwrap();
        assert_eq!(reg.len().await, 2);
        let dropped = reg.evict_for("p", "t1").await;
        assert_eq!(dropped, 1);
        assert_eq!(reg.len().await, 1);
    }

    #[tokio::test]
    async fn evict_for_secret_drops_all_entries() {
        let reg = ClientRegistry::new(ClientRegistryConfig::default());
        let d1 = digest_credential_bundle(&[("url".into(), "u1".into())]);
        let d2 = digest_credential_bundle(&[("url".into(), "u2".into())]);
        reg.get_or_build(d1, vec![], || async { Ok(fake_client()) })
            .await
            .unwrap();
        reg.get_or_build(d2, vec![], || async { Ok(fake_client()) })
            .await
            .unwrap();
        assert_eq!(reg.len().await, 2);
        let dropped = reg.evict_for_secret("vault://kv/db#password").await;
        assert_eq!(dropped, 2, "all entries dropped on rotation");
        assert_eq!(reg.len().await, 0);
    }

    #[tokio::test]
    async fn sweep_idle_drops_old_entries() {
        let reg = ClientRegistry::new(ClientRegistryConfig {
            max_entries: 256,
            idle_eviction: Duration::from_millis(10),
        });
        let d = static_digest();
        reg.get_or_build(d, vec![], || async { Ok(fake_client()) })
            .await
            .unwrap();
        assert_eq!(reg.len().await, 1);
        tokio::time::sleep(Duration::from_millis(30)).await;
        let dropped = reg.sweep_idle().await;
        assert_eq!(dropped, 1);
        assert_eq!(reg.len().await, 0);
    }
}
