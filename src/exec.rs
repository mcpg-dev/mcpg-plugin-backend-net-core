//! Async HTTP execution path for the HTTP backend plugin.
//!
//! Client construction (DNS pre-resolve, rebinding validation, default
//! headers) lives in `client_factory.rs`; the built clients are cached
//! in `client_registry.rs` keyed by resolved-credential digest. This
//! module only formats per-call requests and reads the response.
//!
//! DNS rebinding is enforced at *cache-miss* time inside
//! `client_factory::build_http_client`. The pinned `SocketAddr` is
//! reused for every subsequent call against the same client, so the
//! guard window matches the entry's TTL (idle eviction or revocation).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use reqwest::Method;
use serde_json::Value;
use url::Url;

use crate::types::{HttpBackendMethod, HttpCallMode, HttpRequestProfile, HttpResponseSummary};

/// Hop-by-hop and gateway-injected request headers the plugin must
/// not let an operator set. Either reqwest computes them itself
/// (`host`, `content-length`, `connection`) or they belong to the
/// downstream proxy topology that should not leak to the upstream.
pub fn is_protected_request_header(name: &str, is_json_call: bool) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    matches!(lower.as_str(), "host" | "connection" | "content-length")
        || (is_json_call && matches!(lower.as_str(), "accept" | "content-type"))
        || lower.starts_with("x-forwarded-")
        || matches!(
            lower.as_str(),
            "forwarded" | "via" | "x-real-ip" | "x-request-id"
        )
}

/// Build the GET-style query string from a JSON object. Keys sort
/// stably so cache keys stay deterministic; arrays repeat the key.
pub fn build_query_string(arguments: &Value) -> Result<String, String> {
    let Value::Object(object) = arguments else {
        return Err("HTTP query call arguments must be a JSON object".to_owned());
    };
    let mut keys: Vec<&String> = object.keys().collect();
    keys.sort();
    let mut pairs = Vec::new();
    for key in keys {
        let value = object.get(key).expect("key from sorted set");
        match value {
            Value::Array(items) => {
                for item in items {
                    pairs.push(format!(
                        "{}={}",
                        percent_encode(key),
                        percent_encode(&query_value_string(item)?),
                    ));
                }
            }
            _ => {
                pairs.push(format!(
                    "{}={}",
                    percent_encode(key),
                    percent_encode(&query_value_string(value)?),
                ));
            }
        }
    }
    Ok(pairs.join("&"))
}

fn query_value_string(value: &Value) -> Result<String, String> {
    match value {
        Value::Null => Ok("null".to_owned()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        Value::String(s) => Ok(s.clone()),
        Value::Array(_) | Value::Object(_) => {
            serde_json::to_string(value).map_err(|e| e.to_string())
        }
    }
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{:02X}", byte));
        }
    }
    encoded
}

fn with_query_string(url: &mut Url, query: &str) -> Result<(), String> {
    if query.is_empty() {
        return Ok(());
    }
    let merged = match url.query() {
        Some(existing) if !existing.is_empty() => format!("{existing}&{query}"),
        _ => query.to_owned(),
    };
    url.set_query(Some(&merged));
    Ok(())
}

/// Per-call headers attached to every outbound request. Filters the
/// caller-supplied `request_headers` to the W3C trace context names
/// the gateway forwards (`traceparent`, `tracestate`), and — when
/// the gateway threaded an idempotency hint through
/// `BackendRequest.idempotency` and the operator did NOT statically
/// configure their own `Idempotency-Key` header — appends the
/// canonical `Idempotency-Key` per RFC
/// `draft-ietf-httpapi-idempotency-key-header-07`.
///
/// Operator headers are baked into the cached client's
/// `default_headers`, so per-call headers carry only what the
/// gateway derives at dispatch time.
///
/// Precedence rule: an operator-configured
/// `Idempotency-Key` (e.g. a static integration-test scaffold key —
/// Stripe ships one such pattern) wins over the gateway-injected
/// hint. The `operator_has_idempotency_key` flag, computed by the
/// caller from the operator's compiled header map, suppresses
/// injection when set so reqwest doesn't append a duplicate
/// `Idempotency-Key` value alongside the operator's static one.
fn build_per_call_headers(
    request_headers: &[(String, String)],
    idempotency_key: Option<&str>,
    operator_has_idempotency_key: bool,
) -> Result<reqwest::header::HeaderMap, String> {
    let mut map = reqwest::header::HeaderMap::new();
    for (name, value) in request_headers {
        let lower = name.trim().to_ascii_lowercase();
        if !matches!(lower.as_str(), "traceparent" | "tracestate") {
            continue;
        }
        let header_name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| format!("invalid trace header '{name}': {e}"))?;
        let header_value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|e| format!("invalid trace header value for '{name}': {e}"))?;
        map.insert(header_name, header_value);
    }
    // Propagate the gateway-supplied idempotency key UNLESS the
    // operator pinned their own. RFC canonical title-case
    // (`Idempotency-Key`) per `draft-ietf-httpapi-idempotency-key-header-07`.
    if let Some(key) = idempotency_key
        && !operator_has_idempotency_key
    {
        let header_value = reqwest::header::HeaderValue::from_str(key)
            .map_err(|e| format!("invalid Idempotency-Key value: {e}"))?;
        // `HeaderName::from_bytes` preserves the byte sequence as
        // supplied; HTTP/1.1 headers are case-insensitive but the
        // RFC + Stripe + Square + Chargebee idiom is title-case.
        let header_name = reqwest::header::HeaderName::from_bytes(b"Idempotency-Key")
            .expect("'Idempotency-Key' is a valid HTTP header name");
        map.insert(header_name, header_value);
    }
    Ok(map)
}

/// Execute one HTTP call. The `client` carries the per-bundle default
/// headers + DNS pinning + timeout; per-call work is just URL
/// composition + body serialization + response reading.
#[allow(clippy::too_many_arguments)] // per-call idempotency args.
pub async fn execute_http_call(
    client: &reqwest::Client,
    profile: &HttpRequestProfile,
    call_mode: HttpCallMode,
    request_arguments: &Value,
    request_query: Option<&str>,
    request_headers: &[(String, String)],
    idempotency_key: Option<&str>,
    operator_has_idempotency_key: bool,
    resolved_url: &str,
) -> Result<HttpResponseSummary, String> {
    let started_at = Instant::now();
    let mut url = Url::parse(resolved_url).map_err(|e| format!("invalid URL: {e}"))?;
    if let Some(query) = request_query {
        with_query_string(&mut url, query)?;
    }

    let trace_headers = build_per_call_headers(
        request_headers,
        idempotency_key,
        operator_has_idempotency_key,
    )?;

    let method = match profile.method {
        HttpBackendMethod::Post => Method::POST,
        HttpBackendMethod::Get => Method::GET,
    };

    let mut req = client.request(method, url).headers(trace_headers);
    let accept = if profile.require_json_response {
        "application/json"
    } else {
        "*/*"
    };
    req = req.header(reqwest::header::ACCEPT, accept);

    if matches!(call_mode, HttpCallMode::JsonBody) {
        req = req.json(request_arguments);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    let status = resp.status();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());
    let retry_after_ms = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_retry_after_ms);

    let (body, truncated) = read_body_with_limit(resp, profile.max_response_bytes).await?;

    Ok(HttpResponseSummary {
        status_code: status.as_u16(),
        content_type,
        retry_after_ms,
        body,
        body_truncated: truncated,
        duration_ms: started_at.elapsed().as_millis(),
    })
}

fn parse_retry_after_ms(value: &str) -> Option<u64> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .and_then(|secs| secs.checked_mul(1_000))
}

async fn read_body_with_limit(
    resp: reqwest::Response,
    limit: usize,
) -> Result<(String, bool), String> {
    let (bytes, truncated) = read_response_with_limit(resp, limit).await?;
    Ok((String::from_utf8_lossy(&bytes).to_string(), truncated))
}

/// Drain the response body up to `limit` bytes. Returns the raw
/// buffer plus a `truncated` flag (true if the upstream over-ran the
/// cap). Used by both the buffered tool-call path (via
/// `read_body_with_limit`'s lossy-utf8 step) and the completion path
/// (which needs raw bytes for `serde_json::from_slice`).
pub async fn read_response_with_limit(
    resp: reqwest::Response,
    limit: usize,
) -> Result<(Vec<u8>, bool), String> {
    use futures::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("HTTP body read failed: {e}"))?;
        if buf.len() >= limit {
            truncated = true;
            continue;
        }
        let remaining = limit - buf.len();
        if chunk.len() > remaining {
            buf.extend_from_slice(&chunk[..remaining]);
            truncated = true;
        } else {
            buf.extend_from_slice(&chunk);
        }
    }
    Ok((buf, truncated))
}

// ---------------------------------------------------------------------------
// Streaming variant — produces per-chunk progress events
// ---------------------------------------------------------------------------

/// Whether the upstream response is "streaming" in the sense the
/// progress wire wants — body arrives in pieces over time, so the
/// gateway should forward one `BackendChunk::Progress` per piece.
///
/// Trigger conditions (any one):
/// - `Transfer-Encoding: chunked` (true streaming HTTP/1.1)
/// - `Content-Type: text/event-stream` (Server-Sent Events)
/// - No `Content-Length` header at all (server didn't precompute size)
///
/// A response with `Content-Length: <small>` returns `false` so the
/// caller emits a single `Done` instead of fake per-chunk Progress.
pub fn response_is_streaming(headers: &reqwest::header::HeaderMap) -> bool {
    let transfer_encoding = headers
        .get(reqwest::header::TRANSFER_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if transfer_encoding
        .split(',')
        .any(|tok| tok.trim().eq_ignore_ascii_case("chunked"))
    {
        return true;
    }
    let content_type = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if content_type
        .split(';')
        .next()
        .map(|tok| tok.trim().eq_ignore_ascii_case("text/event-stream"))
        .unwrap_or(false)
    {
        return true;
    }
    !headers.contains_key(reqwest::header::CONTENT_LENGTH)
}

/// One body-read step from the streaming reader. Either an
/// intermediate progress tick (cumulative byte count after appending
/// this chunk) or the terminal summary (full body, truncation flag).
pub enum BodyReadStep {
    /// A body chunk was appended; `cumulative_bytes` is the total
    /// received so far (post-append, post-truncation cap).
    Progress { cumulative_bytes: usize },
    /// Stream end. `body` is the buffered body (UTF-8-lossy) up to
    /// `max_response_bytes`; `truncated` is true if the upstream
    /// over-ran.
    Done { body: String, truncated: bool },
}

/// Stream the response body and yield `BodyReadStep::Progress` per
/// upstream chunk, ending with `BodyReadStep::Done`. Errors flow as
/// `Err(String)` and terminate the stream.
///
/// Cumulative byte count is post-truncation: once `limit` is hit,
/// `cumulative_bytes` stops at `limit` and subsequent chunks still
/// produce a Progress step (so clients can see "still receiving") but
/// the buffer is no longer growing. This matches the buffered path's
/// behaviour where over-limit chunks are dropped.
pub fn read_body_streaming(
    resp: reqwest::Response,
    limit: usize,
) -> impl futures::Stream<Item = Result<BodyReadStep, String>> {
    async_stream_body(resp, limit)
}

/// Internal: drive the upstream body stream and emit BodyReadStep
/// values to a channel. Implemented as a manual `Stream` via
/// `unfold` so we don't pull in the `async-stream` macro crate.
fn async_stream_body(
    resp: reqwest::Response,
    limit: usize,
) -> impl futures::Stream<Item = Result<BodyReadStep, String>> {
    use futures::StreamExt;

    enum State {
        Reading {
            inner: futures::stream::BoxStream<'static, reqwest::Result<bytes::Bytes>>,
            buf: Vec<u8>,
            truncated: bool,
            limit: usize,
            done_emitted: bool,
        },
        Finished,
    }

    let inner = Box::pin(resp.bytes_stream()) as futures::stream::BoxStream<'static, _>;
    let init = State::Reading {
        inner,
        buf: Vec::new(),
        truncated: false,
        limit,
        done_emitted: false,
    };

    futures::stream::unfold(init, |state| async move {
        match state {
            State::Finished => None,
            State::Reading {
                mut inner,
                mut buf,
                mut truncated,
                limit,
                done_emitted,
            } => {
                if done_emitted {
                    return None;
                }
                match inner.next().await {
                    Some(Ok(chunk)) => {
                        if buf.len() < limit {
                            let remaining = limit - buf.len();
                            if chunk.len() > remaining {
                                buf.extend_from_slice(&chunk[..remaining]);
                                truncated = true;
                            } else {
                                buf.extend_from_slice(&chunk);
                            }
                        } else {
                            truncated = true;
                        }
                        let step = BodyReadStep::Progress {
                            cumulative_bytes: buf.len(),
                        };
                        Some((
                            Ok(step),
                            State::Reading {
                                inner,
                                buf,
                                truncated,
                                limit,
                                done_emitted: false,
                            },
                        ))
                    }
                    Some(Err(e)) => {
                        Some((Err(format!("HTTP body read failed: {e}")), State::Finished))
                    }
                    None => {
                        let body = String::from_utf8_lossy(&buf).to_string();
                        let step = BodyReadStep::Done { body, truncated };
                        Some((
                            Ok(step),
                            State::Reading {
                                inner,
                                buf: Vec::new(),
                                truncated,
                                limit,
                                done_emitted: true,
                            },
                        ))
                    }
                }
            }
        }
    })
}

/// Pre-body part of an HTTP call: send the request, await headers,
/// and surface enough of the response for the streaming path to
/// decide whether to emit per-chunk Progress.
///
/// This is the streaming counterpart of [`execute_http_call`]. It
/// returns the `reqwest::Response` (so the caller can drive the body
/// stream) plus the metadata fields the buffered path captures up
/// front (status, content-type, retry-after).
pub struct HttpStreamHandle {
    pub response: reqwest::Response,
    pub status_code: u16,
    pub content_type: Option<String>,
    pub retry_after_ms: Option<u64>,
    pub started_at: Instant,
    pub is_streaming: bool,
}

#[allow(clippy::too_many_arguments)] // per-call idempotency args.
pub async fn start_http_call_streaming(
    client: &reqwest::Client,
    profile: &HttpRequestProfile,
    call_mode: HttpCallMode,
    request_arguments: &Value,
    request_query: Option<&str>,
    request_headers: &[(String, String)],
    idempotency_key: Option<&str>,
    operator_has_idempotency_key: bool,
    resolved_url: &str,
) -> Result<HttpStreamHandle, String> {
    let started_at = Instant::now();
    let mut url = Url::parse(resolved_url).map_err(|e| format!("invalid URL: {e}"))?;
    if let Some(query) = request_query {
        with_query_string(&mut url, query)?;
    }

    let trace_headers = build_per_call_headers(
        request_headers,
        idempotency_key,
        operator_has_idempotency_key,
    )?;

    let method = match profile.method {
        HttpBackendMethod::Post => Method::POST,
        HttpBackendMethod::Get => Method::GET,
    };

    let mut req = client.request(method, url).headers(trace_headers);
    let accept = if profile.require_json_response {
        "application/json"
    } else {
        "*/*"
    };
    req = req.header(reqwest::header::ACCEPT, accept);

    if matches!(call_mode, HttpCallMode::JsonBody) {
        req = req.json(request_arguments);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    let status = resp.status();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());
    let retry_after_ms = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_retry_after_ms);
    let is_streaming = response_is_streaming(resp.headers());

    Ok(HttpStreamHandle {
        response: resp,
        status_code: status.as_u16(),
        content_type,
        retry_after_ms,
        started_at,
        is_streaming,
    })
}

/// Build a final [`HttpResponseSummary`] from a started handle plus
/// the buffered body collected by draining `read_body_streaming`. The
/// shape matches what [`execute_http_call`] would have returned for
/// the same upstream response, so the envelope-shaping logic in
/// `lib.rs` doesn't need a streaming-specific code path.
pub fn finalize_http_summary(
    handle_status: u16,
    handle_content_type: Option<String>,
    handle_retry_after_ms: Option<u64>,
    handle_started_at: Instant,
    body: String,
    body_truncated: bool,
) -> HttpResponseSummary {
    HttpResponseSummary {
        status_code: handle_status,
        content_type: handle_content_type,
        retry_after_ms: handle_retry_after_ms,
        body,
        body_truncated,
        duration_ms: handle_started_at.elapsed().as_millis(),
    }
}

/// Convert the operator-configured headers into a reqwest `HeaderMap`
/// that becomes the cached client's `default_headers`. Strips
/// protected names and warns on credential-shaped header *names*
/// (not values — operator-configured `Authorization: <secret>` is
/// the entire point of the cred-resolution recipe). Individual values
/// are not inspected for credential shape: the operator's
/// post-cred-resolution values are trusted by definition.
pub fn build_default_headers(
    profile_headers: &BTreeMap<String, String>,
    is_json_call: bool,
) -> Result<reqwest::header::HeaderMap, String> {
    let mut map = reqwest::header::HeaderMap::new();
    for (name, value) in profile_headers {
        if is_protected_request_header(name, is_json_call) {
            continue;
        }
        let header_name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| format!("invalid header name '{name}': {e}"))?;
        let header_value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|e| format!("invalid header value for '{name}': {e}"))?;
        map.insert(header_name, header_value);
    }
    Ok(map)
}

/// Wrapper for the `Arc<reqwest::Client>` returned by the registry —
/// so the rest of the plugin doesn't import `reqwest` directly when
/// it just needs a handle.
pub type SharedClient = Arc<reqwest::Client>;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_query_sorts_keys() {
        let q = build_query_string(&json!({"b": 1, "a": "x"})).unwrap();
        assert_eq!(q, "a=x&b=1");
    }

    #[test]
    fn build_query_array_repeats_key() {
        let q = build_query_string(&json!({"x": ["a", "b"]})).unwrap();
        assert_eq!(q, "x=a&x=b");
    }

    #[test]
    fn build_query_percent_encodes_special() {
        let q = build_query_string(&json!({"k": "a b/c"})).unwrap();
        assert_eq!(q, "k=a%20b%2Fc");
    }

    #[test]
    fn build_query_rejects_non_object() {
        assert!(build_query_string(&json!([1, 2, 3])).is_err());
    }

    #[test]
    fn protected_headers_filter() {
        assert!(is_protected_request_header("Host", false));
        assert!(is_protected_request_header("Connection", false));
        assert!(is_protected_request_header("Accept", true));
        assert!(!is_protected_request_header("Accept", false));
        assert!(is_protected_request_header("X-Forwarded-For", false));
        assert!(!is_protected_request_header("X-Custom", false));
    }

    #[test]
    fn default_headers_drop_protected_names() {
        let mut headers = BTreeMap::new();
        headers.insert("Host".into(), "evil.test".into());
        headers.insert("X-Custom".into(), "ok".into());
        let map = build_default_headers(&headers, false).unwrap();
        assert!(!map.contains_key("host"));
        assert_eq!(map.get("x-custom").unwrap(), "ok");
    }
}
