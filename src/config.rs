//! Environment-variable configuration. Ports the `configured*` helpers from
//! the Go original.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

pub const ACME_EMAIL_ENV: &str = "ACME_EMAIL";
pub const ACME_DOMAIN_ENV: &str = "ACME_DOMAIN";
pub const ACME_PROFILE_ENV: &str = "ACME_PROFILE";
pub const ACME_PROFILE_SHORTLIVED: &str = "shortlived";

pub const LISTEN_ADDR_ENV: &str = "LISTEN_ADDR";
pub const LISTEN_ADDR_DEFAULT: &str = ":443";

pub const HTTP_LISTEN_ADDR_ENV: &str = "HTTP_LISTEN_ADDR";

pub const CERT_STORAGE_PATH_ENV: &str = "CERT_STORAGE_PATH";
pub const CERT_STORAGE_PATH_DEFAULT: &str = "./certmagic-storage";

pub const CONNECT_PORTS_ENV: &str = "CONNECT_ALLOWED_PORTS";
pub const CONNECT_PORTS_DEFAULT: &str = "443";
pub const CONNECT_PORTS_ALL: &str = "all";

pub const NO_AUTH_CIDRS_ENV: &str = "NO_AUTH_CIDRS";

pub const PROXY_PAC_PATH: &str = "/proxy.pac";

/// The set of ports allowed as CONNECT targets. The "all" sentinel allows
/// any port.
#[derive(Debug, Clone)]
pub struct AllowedPorts {
    all: bool,
    ports: BTreeSet<u16>,
}

impl AllowedPorts {
    pub fn allows(&self, port: u16) -> bool {
        self.all || self.ports.contains(&port)
    }
    #[allow(dead_code)]
    pub fn all(&self) -> bool {
        self.all
    }
    #[allow(dead_code)]
    pub fn ports(&self) -> &BTreeSet<u16> {
        &self.ports
    }
    pub fn all_sentinel() -> Self {
        Self {
            all: true,
            ports: BTreeSet::new(),
        }
    }
}

pub fn configured_acme_domains() -> Vec<String> {
    let raw = std::env::var(ACME_DOMAIN_ENV).unwrap_or_default();
    let raw = raw.trim();
    if raw.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for part in raw.split(',') {
        let p = part.trim().trim_start_matches('[').trim_end_matches(']');
        if p.is_empty() {
            continue;
        }
        if seen.insert(p.to_string()) {
            out.push(p.to_string());
        }
    }
    out
}

pub fn configured_acme_profile(acme_domains: &[String]) -> String {
    if let Ok(v) = std::env::var(ACME_PROFILE_ENV) {
        let t = v.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    if acme_domains.iter().any(|d| d.parse::<IpAddr>().is_ok()) {
        return ACME_PROFILE_SHORTLIVED.to_string();
    }
    String::new()
}

pub fn configured_listen_addr() -> String {
    let v = std::env::var(LISTEN_ADDR_ENV).unwrap_or_default();
    let t = v.trim();
    if t.is_empty() {
        LISTEN_ADDR_DEFAULT.to_string()
    } else {
        t.to_string()
    }
}

pub fn configured_http_listen_addr() -> String {
    std::env::var(HTTP_LISTEN_ADDR_ENV)
        .unwrap_or_default()
        .trim()
        .to_string()
}

pub fn configured_cert_storage_path() -> Result<PathBuf> {
    let v = std::env::var(CERT_STORAGE_PATH_ENV).unwrap_or_default();
    let p = v.trim();
    let p = if p.is_empty() {
        CERT_STORAGE_PATH_DEFAULT
    } else {
        p
    };
    let abs = std::path::absolute(p)
        .with_context(|| format!("resolving {CERT_STORAGE_PATH_ENV}={p:?}"))?;
    Ok(abs)
}

pub fn configured_connect_ports() -> Result<AllowedPorts> {
    let v = std::env::var(CONNECT_PORTS_ENV).unwrap_or_default();
    let raw = v.trim();
    let raw = if raw.is_empty() {
        CONNECT_PORTS_DEFAULT
    } else {
        raw
    };
    if raw.eq_ignore_ascii_case(CONNECT_PORTS_ALL) {
        return Ok(AllowedPorts::all_sentinel());
    }
    let mut ports: BTreeSet<u16> = BTreeSet::new();
    for part in raw.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let n = parse_port(p)?;
        ports.insert(n);
    }
    if ports.is_empty() {
        bail!("no ports configured");
    }
    Ok(AllowedPorts { all: false, ports })
}

fn parse_port(s: &str) -> Result<u16> {
    if s.is_empty() {
        bail!("empty port");
    }
    let mut n: u32 = 0;
    for c in s.chars() {
        if !c.is_ascii_digit() {
            bail!("invalid port {s:?}");
        }
        n = n * 10 + (c as u32 - '0' as u32);
        if n > 65535 {
            bail!("invalid port {s:?}");
        }
    }
    if n < 1 {
        bail!("invalid port {s:?}");
    }
    Ok(n as u16)
}

pub fn configured_acme_email() -> Result<String> {
    let v = std::env::var(ACME_EMAIL_ENV).unwrap_or_default();
    let email = v.trim();
    if email.is_empty() {
        bail!(
            "{ACME_EMAIL_ENV} must be set to a contact email when {ACME_DOMAIN_ENV} is configured"
        );
    }
    if !email.contains('@') {
        bail!("{ACME_EMAIL_ENV}={email:?} is not a valid email address");
    }
    let lower = email.to_ascii_lowercase();
    for bad in ["@example.com", "@example.org", "@example.net"] {
        if lower.ends_with(bad) {
            bail!(
                "{ACME_EMAIL_ENV}={email:?} uses a reserved example domain; mail is undeliverable"
            );
        }
    }
    Ok(email.to_string())
}

pub fn configured_no_auth_nets() -> Result<Vec<IpNet>> {
    let v = std::env::var(NO_AUTH_CIDRS_ENV).unwrap_or_default();
    let raw = v.trim();
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let mut nets: Vec<IpNet> = Vec::new();
    for part in raw.split(',') {
        let mut p = part.trim();
        if p.is_empty() {
            continue;
        }
        if p.starts_with('[') && p.ends_with(']') {
            p = &p[1..p.len() - 1];
        }
        if p.contains('/') {
            let n: IpNet = p.parse().map_err(|e| anyhow!("invalid CIDR {p:?}: {e}"))?;
            nets.push(n.trunc());
            continue;
        }
        let ip: IpAddr = p.parse().map_err(|_| anyhow!("invalid IP {p:?}"))?;
        let net = match ip {
            IpAddr::V4(v4) => IpNet::V4(Ipv4Net::new(v4, 32).unwrap()),
            IpAddr::V6(v6) => IpNet::V6(Ipv6Net::new(v6, 128).unwrap()),
        };
        nets.push(net);
    }
    Ok(nets)
}

/// Return host:port to embed in the PAC file. Empty when no ACME domain is
/// configured.
pub fn pac_proxy_endpoint(acme_domains: &[String], listen_addr: &str) -> String {
    if acme_domains.is_empty() {
        return String::new();
    }
    let port = listen_addr_port(listen_addr);
    let host = &acme_domains[0];
    let host_fmt = if let Ok(ip) = host.parse::<IpAddr>() {
        if matches!(ip, IpAddr::V6(_)) {
            format!("[{host}]")
        } else {
            host.clone()
        }
    } else {
        host.clone()
    };
    let port = if port.is_empty() {
        "443".to_string()
    } else {
        port
    };
    format!("{host_fmt}:{port}")
}

/// Extract the port component from a listen address like ":443",
/// "0.0.0.0:8443" or "[::]:8443". Empty if none.
pub fn listen_addr_port(addr: &str) -> String {
    if addr.is_empty() {
        return String::new();
    }
    if let Some(rest) = addr.strip_prefix(':') {
        if !rest.contains(':') {
            return rest.to_string();
        }
    }
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let tail = &rest[end + 1..];
            return tail.strip_prefix(':').unwrap_or("").to_string();
        }
    }
    if let Some((_, port)) = addr.rsplit_once(':') {
        if !port.contains(':') {
            return port.to_string();
        }
    }
    String::new()
}

/// Format `host:port` for display, bracketing IPv6 literals.
pub fn listener_host_port(host: &str, addr: &str) -> String {
    let port = addr.strip_prefix(':').unwrap_or(addr);
    let port = if port.contains(':') {
        listen_addr_port(addr)
    } else {
        port.to_string()
    };
    if port.is_empty() {
        return host.to_string();
    }
    if let Ok(IpAddr::V6(_)) = host.parse::<IpAddr>() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize env mutations across this module's tests.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn with_env<F: FnOnce()>(key: &str, val: Option<&str>, f: F) {
        let _g = env_lock();
        let prev = std::env::var(key).ok();
        unsafe {
            match val {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        f();
        unsafe {
            match prev {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }

    #[test]
    fn listen_addr_defaults() {
        with_env(LISTEN_ADDR_ENV, Some(""), || {
            assert_eq!(configured_listen_addr(), LISTEN_ADDR_DEFAULT);
        });
        with_env(LISTEN_ADDR_ENV, Some(":8443"), || {
            assert_eq!(configured_listen_addr(), ":8443");
        });
        with_env(LISTEN_ADDR_ENV, Some("  :9443  "), || {
            assert_eq!(configured_listen_addr(), ":9443");
        });
    }

    #[test]
    fn http_listen_addr_default_empty() {
        with_env(HTTP_LISTEN_ADDR_ENV, Some(""), || {
            assert_eq!(configured_http_listen_addr(), "");
        });
        with_env(HTTP_LISTEN_ADDR_ENV, Some(":80"), || {
            assert_eq!(configured_http_listen_addr(), ":80");
        });
        with_env(HTTP_LISTEN_ADDR_ENV, Some("  :8080  "), || {
            assert_eq!(configured_http_listen_addr(), ":8080");
        });
    }

    #[test]
    fn acme_domains_parsing() {
        with_env(ACME_DOMAIN_ENV, Some(""), || {
            assert!(configured_acme_domains().is_empty());
        });
        with_env(ACME_DOMAIN_ENV, Some("proxy.internal.example"), || {
            assert_eq!(configured_acme_domains(), vec!["proxy.internal.example"]);
        });
        with_env(ACME_DOMAIN_ENV, Some("203.0.113.8"), || {
            assert_eq!(configured_acme_domains(), vec!["203.0.113.8"]);
        });
        with_env(ACME_DOMAIN_ENV, Some("[2001:db8::1]"), || {
            assert_eq!(configured_acme_domains(), vec!["2001:db8::1"]);
        });
        with_env(
            ACME_DOMAIN_ENV,
            Some("proxy.example.com, www.proxy.example.com ,[2001:db8::1]"),
            || {
                assert_eq!(
                    configured_acme_domains(),
                    vec!["proxy.example.com", "www.proxy.example.com", "2001:db8::1"]
                );
            },
        );
        with_env(ACME_DOMAIN_ENV, Some(",,proxy.example.com,,"), || {
            assert_eq!(configured_acme_domains(), vec!["proxy.example.com"]);
        });
        with_env(
            ACME_DOMAIN_ENV,
            Some("proxy.example.com,proxy.example.com,www.proxy.example.com"),
            || {
                assert_eq!(
                    configured_acme_domains(),
                    vec!["proxy.example.com", "www.proxy.example.com"]
                );
            },
        );
    }

    #[test]
    fn acme_profile_rules() {
        with_env(ACME_PROFILE_ENV, None, || {
            assert_eq!(configured_acme_profile(&["proxy.example.com".into()]), "");
            assert_eq!(
                configured_acme_profile(&["203.0.113.8".into()]),
                ACME_PROFILE_SHORTLIVED
            );
            assert_eq!(
                configured_acme_profile(&["2001:db8::1".into()]),
                ACME_PROFILE_SHORTLIVED
            );
            assert_eq!(
                configured_acme_profile(&["proxy.example.com".into(), "203.0.113.8".into()]),
                ACME_PROFILE_SHORTLIVED
            );
        });
        with_env(ACME_PROFILE_ENV, Some("classic"), || {
            assert_eq!(configured_acme_profile(&["203.0.113.8".into()]), "classic");
        });
        with_env(ACME_PROFILE_ENV, Some("   "), || {
            assert_eq!(
                configured_acme_profile(&["203.0.113.8".into()]),
                ACME_PROFILE_SHORTLIVED
            );
            assert_eq!(configured_acme_profile(&["proxy.example.com".into()]), "");
        });
    }

    #[test]
    fn connect_ports_parsing() {
        with_env(CONNECT_PORTS_ENV, Some(""), || {
            let p = configured_connect_ports().unwrap();
            assert!(!p.all());
            assert_eq!(p.ports().iter().copied().collect::<Vec<_>>(), vec![443]);
        });
        with_env(CONNECT_PORTS_ENV, Some(" 443 ,8443, 9443 "), || {
            let p = configured_connect_ports().unwrap();
            for q in [443u16, 8443, 9443] {
                assert!(p.allows(q));
            }
        });
        with_env(CONNECT_PORTS_ENV, Some("abc"), || {
            assert!(configured_connect_ports().is_err());
        });
        with_env(CONNECT_PORTS_ENV, Some("70000"), || {
            assert!(configured_connect_ports().is_err());
        });
        with_env(CONNECT_PORTS_ENV, Some("0"), || {
            assert!(configured_connect_ports().is_err());
        });
        with_env(CONNECT_PORTS_ENV, Some(" ALL "), || {
            let p = configured_connect_ports().unwrap();
            assert!(p.all());
            assert!(p.allows(12345));
        });
    }

    #[test]
    fn no_auth_nets_parsing() {
        with_env(NO_AUTH_CIDRS_ENV, Some(""), || {
            assert!(configured_no_auth_nets().unwrap().is_empty());
        });
        with_env(NO_AUTH_CIDRS_ENV, Some("   ,  ,"), || {
            assert!(configured_no_auth_nets().unwrap().is_empty());
        });
        with_env(
            NO_AUTH_CIDRS_ENV,
            Some(" 10.0.0.0/8 , 192.0.2.5, 2001:db8::/32 ,[::1]"),
            || {
                let nets = configured_no_auth_nets().unwrap();
                assert_eq!(nets.len(), 4);
                assert!(nets[0].contains(&"10.1.2.3".parse::<IpAddr>().unwrap()));
                assert!(nets[1].contains(&"192.0.2.5".parse::<IpAddr>().unwrap()));
                assert!(!nets[1].contains(&"192.0.2.6".parse::<IpAddr>().unwrap()));
                assert!(nets[2].contains(&"2001:db8::1".parse::<IpAddr>().unwrap()));
                assert!(nets[3].contains(&"::1".parse::<IpAddr>().unwrap()));
            },
        );
        with_env(NO_AUTH_CIDRS_ENV, Some("not-an-ip"), || {
            assert!(configured_no_auth_nets().is_err());
        });
        with_env(NO_AUTH_CIDRS_ENV, Some("10.0.0.0/40"), || {
            assert!(configured_no_auth_nets().is_err());
        });
    }

    #[test]
    fn cert_storage_path_is_absolute() {
        with_env(CERT_STORAGE_PATH_ENV, Some(""), || {
            let p = configured_cert_storage_path().unwrap();
            assert!(p.is_absolute(), "path {p:?} should be absolute");
        });
    }

    #[test]
    fn acme_email_rules() {
        with_env(ACME_EMAIL_ENV, Some(""), || {
            assert!(configured_acme_email().is_err());
        });
        with_env(ACME_EMAIL_ENV, Some("admin@example.com"), || {
            assert!(configured_acme_email().is_err());
        });
        with_env(ACME_EMAIL_ENV, Some("not-an-email"), || {
            assert!(configured_acme_email().is_err());
        });
        with_env(ACME_EMAIL_ENV, Some("  ops@proxy.test  "), || {
            assert_eq!(configured_acme_email().unwrap(), "ops@proxy.test");
        });
    }

    #[test]
    fn pac_endpoint_table() {
        let cases: Vec<(Vec<&str>, &str, &str)> = vec![
            (vec![], ":443", ""),
            (vec!["proxy.example.com"], ":443", "proxy.example.com:443"),
            (vec!["proxy.example.com"], ":8443", "proxy.example.com:8443"),
            (vec!["203.0.113.5"], ":443", "203.0.113.5:443"),
            (vec!["2001:db8::1"], ":8443", "[2001:db8::1]:8443"),
            (
                vec!["proxy.example.com"],
                "0.0.0.0:8443",
                "proxy.example.com:8443",
            ),
            (vec!["proxy.example.com"], "", "proxy.example.com:443"),
            (
                vec!["a.example.com", "b.example.com"],
                ":443",
                "a.example.com:443",
            ),
        ];
        for (doms, addr, want) in cases {
            let d: Vec<String> = doms.iter().map(|s| s.to_string()).collect();
            assert_eq!(
                pac_proxy_endpoint(&d, addr),
                want,
                "doms={doms:?} addr={addr}"
            );
        }
    }

    #[test]
    fn listener_host_port_table() {
        let cases = [
            ("proxy.example.com", ":443", "proxy.example.com:443"),
            ("203.0.113.8", ":443", "203.0.113.8:443"),
            ("2001:db8::1", ":443", "[2001:db8::1]:443"),
            ("proxy.example.com", "", "proxy.example.com"),
        ];
        for (h, a, want) in cases {
            assert_eq!(listener_host_port(h, a), want, "h={h} a={a}");
        }
    }
}
