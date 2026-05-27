//! Authenticated HTTPS forward proxy. Rust port of the squid-go Go original.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio_rustls::TlsAcceptor;
use tracing::info;

mod auth;
mod blocklist;
mod config;
mod http_client;
mod proxy;
mod server;
mod tls_config;

use crate::config::{
    configured_acme_domains, configured_acme_email, configured_acme_profile,
    configured_cert_storage_path, configured_connect_ports, configured_http_listen_addr,
    configured_listen_addr, configured_no_auth_nets, listener_host_port, pac_proxy_endpoint,
};

fn main() -> Result<()> {
    init_tracing();

    // Install rustls' default crypto provider once, ahead of any TLS use.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    rt.block_on(run())
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).try_init();
}

async fn run() -> Result<()> {
    let acme_domains = configured_acme_domains();
    let listen_addr_str = configured_listen_addr();
    let listen_addr = parse_listen_addr(&listen_addr_str)
        .with_context(|| format!("invalid LISTEN_ADDR={listen_addr_str:?}"))?;

    let allowed_ports = configured_connect_ports().context("invalid CONNECT_ALLOWED_PORTS")?;
    let no_auth_nets = configured_no_auth_nets().context("invalid NO_AUTH_CIDRS")?;

    let (tls_cfg, acme_driver) = if acme_domains.is_empty() {
        info!("ACME_DOMAIN not set; using auto-generated self-signed certificate");
        (tls_config::self_signed_tls_config()?, None)
    } else {
        let email = configured_acme_email().context("invalid ACME configuration")?;
        let profile = configured_acme_profile(&acme_domains);
        let storage = configured_cert_storage_path()?;
        let (cfg, driver) =
            tls_config::managed_tls_config(&acme_domains, &email, &profile, storage)?;
        info!(
            url = %format!("https://{}", listener_host_port(&acme_domains[0], &listen_addr_str)),
            domains = ?acme_domains,
            acme_profile = %profile,
            "HTTPS proxy listening"
        );
        (cfg, Some(driver))
    };

    let acceptor = TlsAcceptor::from(tls_cfg);

    let http_listen_addr = {
        let s = configured_http_listen_addr();
        if s.is_empty() {
            None
        } else {
            Some(parse_listen_addr(&s).with_context(|| format!("invalid HTTP_LISTEN_ADDR={s:?}"))?)
        }
    };

    if !no_auth_nets.is_empty() {
        let nets: Vec<String> = no_auth_nets.iter().map(|n| n.to_string()).collect();
        info!(cidrs = ?nets, "proxy authentication bypass enabled for client networks");
    }

    let state = proxy::ProxyState {
        allowed_ports: Arc::new(allowed_ports),
        allowed_hashes: Arc::new(auth::allowed_auth_hashes()),
        no_auth_nets: Arc::new(no_auth_nets),
        pac_endpoint: Arc::new(pac_proxy_endpoint(&acme_domains, &listen_addr_str)),
        remote_addr: None,
        http_client: Arc::new(http_client::Client::new()),
    };

    if let Some(driver) = acme_driver {
        tokio::spawn(driver.run());
    }

    server::run(listen_addr, acceptor, http_listen_addr, state).await
}

/// Parse `LISTEN_ADDR`-style values like `":443"`, `"0.0.0.0:8443"`, or
/// `"[::]:8443"` into a `SocketAddr`. A leading `":"` binds all interfaces.
fn parse_listen_addr(s: &str) -> Result<SocketAddr> {
    if let Some(rest) = s.strip_prefix(':') {
        if !rest.contains(':') {
            let port: u16 = rest.parse().context("port")?;
            return Ok(SocketAddr::new(IpAddr::from([0u8, 0, 0, 0]), port));
        }
    }
    let addr: SocketAddr = s.parse().with_context(|| format!("parse {s:?}"))?;
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listen_addr_table() {
        let cases = [
            (":443", "0.0.0.0:443"),
            (":8443", "0.0.0.0:8443"),
            ("0.0.0.0:8443", "0.0.0.0:8443"),
            ("127.0.0.1:9443", "127.0.0.1:9443"),
            ("[::]:443", "[::]:443"),
        ];
        for (input, want) in cases {
            let got = parse_listen_addr(input).unwrap();
            assert_eq!(got.to_string(), want, "input={input}");
        }
    }
}
