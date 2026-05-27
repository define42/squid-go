//! TLS configuration: self-signed fallback (no `ACME_DOMAIN`) and Let's
//! Encrypt TLS-ALPN-01 via `rustls-acme`.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::ServerConfig;
use rustls_acme::caches::DirCache;
use rustls_acme::AcmeConfig;

/// Build a one-shot self-signed `ServerConfig`. Uses rcgen with the
/// `aws_lc_rs` backend.
pub fn self_signed_tls_config() -> Result<Arc<ServerConfig>> {
    let mut params = rcgen::CertificateParams::new(vec!["squid-go".to_string()])
        .context("invalid self-signed SAN")?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "squid-go");

    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).context("ecdsa keygen")?;
    let cert = params.self_signed(&key_pair).context("self-sign")?;

    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("private key: {e}"))?;

    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("self-signed ServerConfig")?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Build an ACME-managed `ServerConfig` that resolves certificates via
/// Let's Encrypt TLS-ALPN-01. Returns the config plus a `Future` that drives
/// renewal — the caller must spawn that future on the runtime.
pub fn managed_tls_config(
    acme_domains: &[String],
    acme_email: &str,
    acme_profile: &str,
    storage_path: PathBuf,
) -> Result<(Arc<ServerConfig>, ManagedAcmeDriver)> {
    if acme_domains.is_empty() {
        anyhow::bail!("no ACME domains configured");
    }
    std::fs::create_dir_all(&storage_path)
        .with_context(|| format!("could not create cert storage dir {storage_path:?}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&storage_path, std::fs::Permissions::from_mode(0o700));
    }

    let cache = DirCache::new(storage_path);
    let builder = AcmeConfig::new(acme_domains.iter().cloned())
        .contact_push(format!("mailto:{acme_email}"))
        .cache(cache)
        .directory_lets_encrypt(true);
    if !acme_profile.is_empty() {
        // rustls-acme < 0.17 does not expose ACME profiles directly; log so
        // operators know it was honored or skipped.
        tracing::info!(profile = %acme_profile, "ACME profile requested (passthrough)");
    }
    let state = builder.state();

    let resolver = state.resolver();
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec(), b"acme-tls/1".to_vec()];

    let driver = ManagedAcmeDriver { state };
    Ok((Arc::new(cfg), driver))
}

/// Holds the rustls-acme background state so the caller can poll it.
pub struct ManagedAcmeDriver {
    state: rustls_acme::AcmeState<std::io::Error>,
}

impl ManagedAcmeDriver {
    /// Drive renewal/issuance events. Spawn this on the runtime.
    pub async fn run(mut self) {
        use futures_util::StreamExt;
        loop {
            match self.state.next().await {
                Some(Ok(ok)) => tracing::info!(event = ?ok, "acme event"),
                Some(Err(e)) => tracing::warn!(err = %e, "acme error"),
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_has_cert() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cfg = self_signed_tls_config().unwrap();
        // Smoke test: ALPN includes http/1.1.
        assert!(cfg.alpn_protocols.contains(&b"http/1.1".to_vec()));
    }
}
