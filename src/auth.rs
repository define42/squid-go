//! Proxy-Authorization parsing, constant-time digest compare, and client-IP
//! exemption logic. Ported from the Go original.

use std::net::IpAddr;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ipnet::IpNet;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const PROXY_AUTH_ENV: &str = "PROXY_AUTH_SHA256";
pub const PROXY_AUTH_DELIMITER: char = ',';

/// Returns the lowercased sha256(user:password) hex digests configured via
/// `PROXY_AUTH_SHA256`. Empty entries and surrounding whitespace are ignored.
pub fn allowed_auth_hashes() -> Vec<String> {
    let raw = std::env::var(PROXY_AUTH_ENV).unwrap_or_default();
    if raw.is_empty() {
        return Vec::new();
    }
    raw.split(PROXY_AUTH_DELIMITER)
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .collect()
}

/// Checks the `Proxy-Authorization` header against `allowed`.
pub fn authorized(header: Option<&str>, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return false;
    }
    let Some(auth) = header else { return false };
    let Some(b64) = auth.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(raw) = B64.decode(b64.as_bytes()) else {
        return false;
    };
    let Some(colon) = raw.iter().position(|&b| b == b':') else {
        return false;
    };
    if colon == 0 || colon == raw.len() - 1 {
        return false;
    }
    let sum = Sha256::digest(&raw);
    let got = hex::encode(sum);
    let got_bytes = got.as_bytes();
    let mut hit = false;
    for want in allowed {
        if want.len() != got_bytes.len() {
            continue;
        }
        if want.as_bytes().ct_eq(got_bytes).into() {
            hit = true;
        }
    }
    hit
}

pub fn client_ip_exempt(client_ip: Option<IpAddr>, nets: &[IpNet]) -> bool {
    if nets.is_empty() {
        return false;
    }
    let Some(ip) = client_ip else { return false };
    nets.iter().any(|n| n.contains(&ip))
}

/// Parse a `host:port` style `RemoteAddr` into an `IpAddr`. Accepts
/// bracketed IPv6, bare IPv6 (with no port), bare host:port, and bare IPs;
/// strips IPv6 zone-ids.
#[allow(dead_code)]
pub fn parse_remote_ip(remote: &str) -> Option<IpAddr> {
    let host = if let Some(rest) = remote.strip_prefix('[') {
        let end = rest.find(']')?;
        &rest[..end]
    } else if remote.matches(':').count() > 1 {
        // Unbracketed IPv6: try whole string.
        remote
    } else if let Some((h, _)) = remote.rsplit_once(':') {
        h
    } else {
        remote
    };
    let host = match host.find('%') {
        Some(i) => &host[..i],
        None => host,
    };
    host.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(user: &str, pass: &str) -> String {
        let mut h = Sha256::new();
        h.update(user.as_bytes());
        h.update(b":");
        h.update(pass.as_bytes());
        hex::encode(h.finalize())
    }

    fn basic(user: &str, pass: &str) -> String {
        format!("Basic {}", B64.encode(format!("{user}:{pass}").as_bytes()))
    }

    #[test]
    fn authorized_table() {
        let h1 = sha256_hex("user", "pass");
        let h2 = sha256_hex("alice", "s3cret");
        let allowed = vec![h1, h2];

        assert!(!authorized(None, &allowed));
        assert!(!authorized(Some("Bearer token"), &allowed));
        assert!(!authorized(Some("Basic !!!notbase64!!!"), &allowed));
        assert!(!authorized(Some(&basic("wrong", "creds")), &allowed));
        assert!(authorized(Some(&basic("user", "pass")), &allowed));
        assert!(authorized(Some(&basic("alice", "s3cret")), &allowed));
        assert!(!authorized(Some(&basic("", "")), &allowed));
        let nocolon = format!("Basic {}", B64.encode(b"nocolon"));
        assert!(!authorized(Some(&nocolon), &allowed));
        assert!(!authorized(Some(&basic("user", "pass")), &[]));
    }

    #[test]
    fn client_ip_exempt_table() {
        let nets = vec![
            "10.0.0.0/8".parse::<IpNet>().unwrap(),
            "2001:db8::/32".parse::<IpNet>().unwrap(),
        ];
        let cases = [
            ("10.1.2.3:54321", true),
            ("192.0.2.1:54321", false),
            ("[2001:db8::1]:54321", true),
            ("[fe80::1%eth0]:54321", false),
            ("[2001:db9::1]:54321", false),
            ("10.2.3.4", true),
            ("not-an-addr", false),
        ];
        for (remote, want) in cases {
            let ip = parse_remote_ip(remote);
            assert_eq!(client_ip_exempt(ip, &nets), want, "remote={remote}");
        }
        assert!(!client_ip_exempt(parse_remote_ip("10.1.2.3:54321"), &[]));
    }
}
