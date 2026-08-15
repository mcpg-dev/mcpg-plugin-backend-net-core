//! DNS rebinding protection for outbound HTTP connections.
//!
//! Prevents an attacker-controlled DNS server from re-pointing an
//! operator-configured hostname to a private IP at dispatch time,
//! tricking a network backend (or the gateway) into connecting to
//! internal infrastructure. The address-classification primitives live in
//! `mcpg-plugin-protocol`; this module adds the connect-time policy check
//! that emits the block metric and the operator-facing error, so the SSRF
//! resolution guard lives in exactly one place.

pub use mcpg_plugin_protocol::security::{
    PRIVATE_RANGES_DOC, is_private_address, validate_resolved_addr,
};

/// Validate a resolved `SocketAddr` before connecting.
///
/// When `allow_private` is false and the IP falls in a private range,
/// increments the `mcpg_dns_rebinding_blocked_total` counter and
/// returns `Err(reason)`.
pub fn validate_resolved_address(
    addr: &std::net::SocketAddr,
    host: &str,
    allow_private: bool,
) -> Result<(), String> {
    if allow_private {
        return Ok(());
    }
    if is_private_address(&addr.ip()) {
        metrics::counter!(
            "mcpg_dns_rebinding_blocked_total",
            "host" => host.to_owned(),
        )
        .increment(1);
        tracing::warn!(
            host = %host,
            resolved_ip = %addr.ip(),
            "DNS rebinding blocked: resolved to private/loopback/link-local address"
        );
        return Err(format!(
            "DNS rebinding guard: host '{}' resolved to private address {} \
             (set server.allow_private_backends=true for container-network deployments). \
             {}",
            host,
            addr.ip(),
            PRIVATE_RANGES_DOC,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn blocks_loopback() {
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        assert!(validate_resolved_address(&addr, "evil.test", false).is_err());
    }

    #[test]
    fn allows_loopback_when_private_ok() {
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        assert!(validate_resolved_address(&addr, "evil.test", true).is_ok());
    }

    #[test]
    fn allows_public() {
        let addr: SocketAddr = "93.184.216.34:443".parse().unwrap();
        assert!(validate_resolved_address(&addr, "example.com", false).is_ok());
    }

    #[test]
    fn blocks_rfc1918() {
        for ip in ["10.0.0.1:80", "172.16.0.1:80", "192.168.1.1:80"] {
            let addr: SocketAddr = ip.parse().unwrap();
            assert!(
                validate_resolved_address(&addr, "evil.test", false).is_err(),
                "{ip} should be blocked"
            );
        }
    }

    #[test]
    fn blocks_cgnat() {
        let addr: SocketAddr = "100.64.0.1:80".parse().unwrap();
        assert!(validate_resolved_address(&addr, "evil.test", false).is_err());
    }
}
