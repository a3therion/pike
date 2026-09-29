//! Validate and install key material without exposing private keys to callers.
use anyhow::{ensure, Context, Result};
use rustls::{
    client::{danger::ServerCertVerifier, WebPkiServerVerifier},
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    server::{danger::ClientCertVerifier, ParsedCertificate},
    RootCertStore,
};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) struct Material {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    pub not_before: u64,
    pub expires: u64,
}
impl Material {
    pub fn parse(
        hostname: &str,
        chain: &[u8],
        key: &[u8],
        roots: Option<&Arc<RootCertStore>>,
    ) -> Result<Self> {
        ensure!(
            chain.len() <= 65536 && key.len() <= 16384,
            "endpoint TLS material exceeds limit"
        );
        let chain = CertificateDer::pem_slice_iter(chain).collect::<Result<Vec<_>, _>>()?;
        ensure!(
            !chain.is_empty() && chain.len() <= 8,
            "endpoint certificate chain is empty or too long"
        );
        let name = ServerName::try_from(hostname.to_owned())?;
        let leaf = ParsedCertificate::try_from(&chain[0])?;
        rustls::client::verify_server_name(&leaf, &name)?;
        let (remaining, parsed) = x509_parser::parse_x509_certificate(chain[0].as_ref())
            .context("invalid server certificate")?;
        ensure!(
            remaining.is_empty() && !parsed.is_ca(),
            "invalid server leaf certificate"
        );
        let not_before = u64::try_from(parsed.validity().not_before.timestamp())?;
        let expires = u64::try_from(parsed.validity().not_after.timestamp())?;
        ensure!(
            not_before <= now() && now() < expires,
            "server certificate is not currently valid"
        );
        if let Some(roots) = roots {
            WebPkiServerVerifier::builder_with_provider(
                roots.clone(),
                Arc::new(rustls::crypto::ring::default_provider()),
            )
            .build()?
            .verify_server_cert(&chain[0], &chain[1..], &name, &[], UnixTime::now())?;
        }
        let key = PrivateKeyDer::from_pem_slice(key).context("endpoint private key missing")?;
        let material = Self {
            chain,
            key,
            not_before,
            expires,
        };
        // Rustls checks that the private key matches the leaf public key.
        material.server_config(None, false)?;
        Ok(material)
    }
    pub fn server_config(
        &self,
        verifier: Option<Arc<dyn ClientCertVerifier>>,
        http: bool,
    ) -> Result<Arc<rustls::ServerConfig>> {
        ensure!(
            self.not_before <= now() && now() < self.expires,
            "server certificate expired or not yet valid"
        );
        let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?;
        let mut config = match verifier {
            Some(verifier) => builder.with_client_cert_verifier(verifier),
            None => builder.with_no_client_auth(),
        }
        .with_single_cert(self.chain.clone(), self.key.clone_key())?;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        config.max_early_data_size = 0;
        if http {
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        }
        Ok(Arc::new(config))
    }
    pub fn same_certificate(&self, other: &Self) -> bool {
        self.chain == other.chain
    }
    pub fn renew_at(&self, lead: u64) -> u64 {
        self.expires
            .saturating_sub(lead.min((self.expires - self.not_before) / 3))
    }
}
pub(super) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
