use std::net::IpAddr;
use anyhow::{bail, Result};
use url::Url;

/// Returns true if an IP address should never be reachable from this server:
/// loopback, RFC1918 private ranges, link-local (including the 169.254.169.254
/// cloud metadata address), multicast, unspecified, and IPv6 unique-local/link-local.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local() // covers 169.254.0.0/16, including the metadata IP
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || (seg0 & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (seg0 & 0xffc0) == 0xfe80 // fe80::/10 link local
        }
    }
}

/// Validates a URL's scheme and confirms every IP its host resolves to is
/// publicly routable. Call this again after every redirect hop, not just once.
pub async fn validate_url(url: &Url) -> Result<()> {
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        bail!("scheme '{scheme}' is not allowed, only http/https");
    }

    let host = match url.host_str() {
        Some(h) => h,
        None => bail!("URL has no host"),
    };
    let port = url.port_or_known_default().unwrap_or(443);

    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| anyhow::anyhow!("DNS resolution failed for {host}: {e}"))?;

    let mut resolved_any = false;
    for addr in addrs {
        resolved_any = true;
        if is_blocked_ip(addr.ip()) {
            bail!("host '{host}' resolves to a disallowed address ({}); refusing to fetch", addr.ip());
        }
    }

    if !resolved_any {
        bail!("host '{host}' did not resolve to any address");
    }

    Ok(())
}
