//! SSRF blocklist: classify dangerous IPs and provide a "safe dial" helper
//! that resolves a hostname once and refuses to connect to any blocked
//! address. Ported from the Go original's `isBlockedIP` + `safeDial` logic.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use ipnet::IpNet;
use thiserror::Error;
use tokio::net::TcpStream;

/// Extra CIDR ranges that Rust's std IP classifiers do not catch but the
/// proxy still refuses to forward to. Mirrors `extraBlockedCIDRs` in the
/// Go original.
fn extra_blocked_cidrs() -> &'static [IpNet] {
    use std::sync::OnceLock;
    static CIDRS: OnceLock<Vec<IpNet>> = OnceLock::new();
    CIDRS.get_or_init(|| {
        [
            "0.0.0.0/8",
            "100.64.0.0/10",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "255.255.255.255/32",
            "64:ff9b::/96",
            "2001:db8::/32",
        ]
        .iter()
        .map(|s| s.parse::<IpNet>().expect("built-in CIDR must parse"))
        .collect()
    })
}

/// Returns true if `ip` is loopback, private, link-local, multicast,
/// unspecified, etc. IPv4-mapped IPv6 addresses are unwrapped before
/// classification.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    let v4 = match ip {
        IpAddr::V4(v) => Some(v),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    };
    if let Some(v4) = v4 {
        if is_blocked_v4(v4) {
            return true;
        }
        return false;
    }
    if let IpAddr::V6(v6) = ip {
        if is_blocked_v6(v6) {
            return true;
        }
        for net in extra_blocked_cidrs() {
            if let IpNet::V6(n) = net {
                if n.contains(&v6) {
                    return true;
                }
            }
        }
    }
    false
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    if ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
    {
        return true;
    }
    let o = ip.octets();
    // 100.64.0.0/10 CGNAT.
    if o[0] == 100 && (o[1] & 0xC0) == 64 {
        return true;
    }
    // 0.0.0.0/8 "this host on this network".
    if o[0] == 0 {
        return true;
    }
    // 192.0.0.0/24 protocol assignments.
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return true;
    }
    // 198.18.0.0/15 benchmark.
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return true;
    }
    false
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        return true;
    }
    let seg = ip.segments();
    // Link-local unicast: fe80::/10.
    if (seg[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // Unique local (ULA): fc00::/7.
    if (seg[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    false
}

#[derive(Error, Debug)]
pub enum SafeDialError {
    #[error("target resolves to a blocked address")]
    Blocked,
    #[error("no addresses found for {0}")]
    NoAddresses(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Resolve `host` to an IP, returning the first non-blocked address.
pub async fn resolve_safe_ip(host: &str) -> Result<IpAddr, SafeDialError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_blocked_ip(ip) {
            return Err(SafeDialError::Blocked);
        }
        return Ok(ip);
    }
    let key = format!("{host}:0");
    let mut had_any = false;
    let mut blocked_any = false;
    for addr in tokio::net::lookup_host(&key).await? {
        had_any = true;
        let ip = addr.ip();
        if !is_blocked_ip(ip) {
            return Ok(ip);
        }
        blocked_any = true;
    }
    if !had_any {
        return Err(SafeDialError::NoAddresses(host.to_string()));
    }
    if blocked_any {
        return Err(SafeDialError::Blocked);
    }
    Err(SafeDialError::NoAddresses(host.to_string()))
}

/// Dial `host:port` after resolving via [`resolve_safe_ip`].
pub async fn safe_dial(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream, SafeDialError> {
    let ip = resolve_safe_ip(host).await?;
    let sa = SocketAddr::new(ip, port);
    let stream = tokio::time::timeout(timeout, TcpStream::connect(sa))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))??;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_well_known_unsafe_ranges() {
        let cases = [
            ("127.0.0.1", true),
            ("::1", true),
            ("10.0.0.5", true),
            ("172.16.5.5", true),
            ("192.168.1.1", true),
            ("169.254.169.254", true),
            ("fe80::1", true),
            ("0.0.0.0", true),
            ("::", true),
            ("224.0.0.1", true),
            ("ff02::1", true),
            ("fc00::1", true),
            ("8.8.8.8", false),
            ("1.1.1.1", false),
            ("2606:4700:4700::1111", false),
        ];
        for (s, want) in cases {
            let ip: IpAddr = s.parse().unwrap();
            assert_eq!(is_blocked_ip(ip), want, "ip={s}");
        }
    }

    #[test]
    fn blocks_extra_ranges() {
        let cases = [
            ("0.1.2.3", true),
            ("0.255.255.255", true),
            ("100.64.0.1", true),
            ("100.127.255.254", true),
            ("192.0.0.170", true),
            ("192.0.2.5", true),
            ("198.18.0.1", true),
            ("198.51.100.7", true),
            ("203.0.113.5", true),
            ("255.255.255.255", true),
            ("2001:db8::5", true),
            ("::ffff:127.0.0.1", true),
            ("::ffff:10.0.0.1", true),
            ("::ffff:169.254.169.254", true),
            ("64:ff9b::7f00:1", true),
            ("64:ff9b::808:808", true),
            ("100.63.255.254", false),
            ("100.128.0.1", false),
            ("1.0.0.1", false),
            ("64:ff9c::1", false),
        ];
        for (s, want) in cases {
            let ip: IpAddr = s.parse().unwrap();
            assert_eq!(is_blocked_ip(ip), want, "ip={s}");
        }
    }

    #[tokio::test]
    async fn resolve_safe_ip_blocks_literals() {
        for host in ["127.0.0.1", "169.254.169.254", "10.1.2.3", "::1", "fe80::1"] {
            let err = resolve_safe_ip(host).await.unwrap_err();
            assert!(matches!(err, SafeDialError::Blocked), "host={host}");
        }
    }

    #[tokio::test]
    async fn resolve_safe_ip_allows_literal() {
        let ip = resolve_safe_ip("8.8.8.8").await.unwrap();
        assert_eq!(ip.to_string(), "8.8.8.8");
    }

    #[tokio::test]
    async fn safe_dial_blocks_private_literal() {
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let err = safe_dial(&addr.ip().to_string(), addr.port(), Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(matches!(err, SafeDialError::Blocked));
    }
}
