# mcpg-plugin-backend-net-core

> Shared HTTP-over-reqwest core for MCPG's network backend plugins: SSRF guard, per-credential client cache, call execution, and downstream-error shaping.

Every MCPG backend plugin that dispatches a tool call as an outbound HTTP
request carries the same security and lifecycle obligations — refuse a hostname
that resolves into private address space, pin the validated address so DNS
cannot be rebound underneath the connection, cache one client per resolved
credential bundle and evict it when that credential is revoked or rotated, cap
the response body, and shape a failure into the structured envelope the gateway
reads. This crate is the single implementation of all of that, so the
security-sensitive code exists once rather than once per protocol. It is a plain
library, **not** a loadable plugin: it carries no `plugin.yaml`, exports no
`mcpg_plugin_register` symbol, and cannot be named in a gateway's `plugins:`
list.

## What's here

- `client::build_http_client` — resolves the URL's host, walks the address list,
  picks the first non-private address (or fails when every resolution is private
  and the profile did not set `allow_private_backends`), and pins it via
  `ClientBuilder::resolve`. Redirects are disabled and the profile timeout is
  baked in.
- `safe_dns` — the connect-time policy check `validate_resolved_address`, which
  increments `mcpg_dns_rebinding_blocked_total` and returns an operator-facing
  reason on a block. Re-exports `is_private_address`, `validate_resolved_addr`,
  and `PRIVATE_RANGES_DOC` from `mcpg-plugin-protocol`.
- `client_registry` — `ClientRegistry`, a bounded per-credential
  `reqwest::Client` cache keyed by `CredDigest` (a BLAKE3 digest built with
  `digest_credential_bundle`), with LRU plus idle eviction
  (`ClientRegistryConfig`, defaulting to 256 entries and a 15-minute idle
  window), the `spawn_idle_sweeper` / `IdleSweeper` background sweeper, and
  `collect_cred_refs` for routing revocation events to the right entries.
- `runtime::NetworkProfileRuntime` — the per-profile object a plugin builds at
  registration. It compiles the operator's CEL templates for the URL and
  headers, holds the credential-revocation, secret-rotation, and idle
  subscriptions, and exposes `resolve_client` (full per-call resolution, into a
  `ResolvedCall`) and `resolve_static_client` (base URL only). `build_expr_context`
  assembles the CEL evaluation context from the call arguments, tool name, and
  caller identity.
- `exec` — per-call request formatting and response reading:
  `execute_http_call`, `start_http_call_streaming` / `HttpStreamHandle`,
  `read_response_with_limit`, `read_body_streaming` / `BodyReadStep`,
  `response_is_streaming`, `finalize_http_summary`, `build_query_string`,
  `build_default_headers`, and `is_protected_request_header` (the hop-by-hop and
  proxy-topology header names an operator must not be able to set).
- `types` — `HttpRequestProfile`, `HttpBackendMethod` (`post` / `get`, accepted
  in any common casing), `HttpCallMode`, `RetrySafetyContext`, and
  `HttpResponseSummary`.
- `retry` — `DownstreamHttpError` plus `validate_expected_status_codes`,
  `parse_and_validate_json_response`, and `transport_downstream_error`. A
  non-null `downstreamError` slot in a plugin's response envelope is what tells
  the gateway to mark the `tools/call` result as an error, and these functions
  build that slot identically across protocols.

## Used by

- The network backend plugins that link it at build time:
  `libs/plugins/backend/{http,grpc,graphql,openapi,soap}`.
- The gateway itself, which re-exports the `safe_dns` policy check so
  gateway-side outbound requests are guarded by the same code as plugin-side
  ones.
- Out-of-tree plugin authors writing an HTTP-shaped backend who want the SSRF
  guard and the credential-keyed client cache without reimplementing them.

## Usage

```toml
[dependencies]
mcpg-plugin-backend-net-core = "<version>"
```

```rust
use mcpg_plugin_backend_net_core::exec::build_query_string;
use serde_json::json;

// GET-style calls turn the tool arguments into a stable, percent-encoded
// query string: keys sort, and an array repeats its key.
let query = build_query_string(&json!({ "b": 2, "a": "x y", "tag": ["red", "blue"] }))
    .expect("arguments are a JSON object");
assert_eq!(query, "a=x%20y&b=2&tag=red&tag=blue");
```

## Build / test

```bash
cargo build -p mcpg-plugin-backend-net-core
cargo test  -p mcpg-plugin-backend-net-core
```

## Licence
Apache-2.0.

## See also

- Backend binding reference, including the shared HTTP knobs: <https://mcpg.dev/docs/reference/backends>
- Plugin classes and the plugin ABI: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- The plugins that link this crate: `libs/plugins/backend/http`,
  `libs/plugins/backend/grpc`, `libs/plugins/backend/graphql`,
  `libs/plugins/backend/openapi`
