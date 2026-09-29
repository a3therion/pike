//! Client trust and certificate restrictions. TLS owns proof of private-key
//! possession; this module never accepts certificate claims from HTTP headers.
use anyhow::{ensure, Context, Result};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, UnixTime},
    server::{danger::ClientCertVerifier, WebPkiClientVerifier},
    RootCertStore,
};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MtlsPolicy {
    pub ca_pem: String,
    pub allowed_fingerprints: Option<Vec<String>>,
    #[serde(default)]
    pub revoked_fingerprints: Vec<String>,
}
impl std::fmt::Debug for MtlsPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtlsPolicy")
            .field("ca_bytes", &self.ca_pem.len())
            .field("allowed_fingerprints", &self.allowed_fingerprints)
            .field("revoked_fingerprints", &self.revoked_fingerprints)
            .finish()
    }
}
pub struct Mtls {
    verifier: Arc<dyn ClientCertVerifier>,
    policy: MtlsPolicy,
}
#[derive(Clone, Debug)]
pub struct CertificateIdentity {
    pub fingerprint: String,
    pub expires: Instant,
}
impl Mtls {
    pub fn new(policy: MtlsPolicy) -> Result<Self> {
        ensure!(
            policy.ca_pem.len() <= 16384,
            "mTLS CA bundle exceeds 16 KiB"
        );
        let certificates = certificates(&policy.ca_pem)?;
        ensure!(
            !certificates.is_empty() && certificates.len() <= 8,
            "mTLS requires 1-8 CA certificates"
        );
        for list in [
            policy.allowed_fingerprints.as_deref().unwrap_or(&[]),
            policy.revoked_fingerprints.as_slice(),
        ] {
            ensure!(
                list.len() <= 64 && list.iter().all(|s| fingerprint_valid(s)),
                "invalid mTLS certificate fingerprints"
            );
        }
        let mut roots = RootCertStore::empty();
        for certificate in certificates {
            let (remaining, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref())
                .context("invalid mTLS CA certificate")?;
            ensure!(
                remaining.is_empty() && parsed.is_ca(),
                "mTLS trust material must contain CA certificates"
            );
            roots
                .add(certificate)
                .context("invalid mTLS trust anchor")?;
        }
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .context("invalid mTLS trust configuration")?;
        Ok(Self { verifier, policy })
    }
    pub fn verifier(&self) -> Arc<dyn ClientCertVerifier> {
        self.verifier.clone()
    }
    /// Call only for the peer chain returned by a successfully authenticated
    /// rustls connection. An uploaded PEM certificate is not an identity.
    pub fn identity(&self, chain: &[CertificateDer<'_>]) -> Result<CertificateIdentity> {
        ensure!(
            !chain.is_empty()
                && chain.len() <= 8
                && chain.iter().map(|c| c.len()).sum::<usize>() <= 65536,
            "mTLS client certificate chain required and bounded"
        );
        let now = UnixTime::now();
        self.verifier
            .verify_client_cert(&chain[0], &chain[1..], now)
            .context("mTLS client certificate rejected")?;
        let fingerprint = fingerprint(&chain[0]);
        ensure!(
            !self.policy.revoked_fingerprints.contains(&fingerprint),
            "mTLS client certificate revoked"
        );
        ensure!(
            self.policy
                .allowed_fingerprints
                .as_ref()
                .is_none_or(|allowed| allowed.contains(&fingerprint)),
            "mTLS client certificate not allowed"
        );
        // Conservatively expire with the earliest presented chain member. This
        // also bounds established HTTP/2 and raw TLS streams, not just admission.
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let mut remaining = Duration::MAX;
        for certificate in chain {
            let (rest, certificate) = x509_parser::parse_x509_certificate(certificate.as_ref())
                .context("invalid mTLS client certificate")?;
            ensure!(rest.is_empty(), "trailing mTLS certificate data");
            let expiry = u64::try_from(certificate.validity().not_after.timestamp())
                .context("expired mTLS client certificate")?;
            let duration = Duration::from_secs(expiry)
                .checked_sub(now)
                .context("expired mTLS client certificate")?;
            ensure!(!duration.is_zero(), "expired mTLS client certificate");
            remaining = remaining.min(duration);
        }
        let expires = Instant::now()
            .checked_add(remaining)
            .context("mTLS certificate lifetime overflow")?;
        Ok(CertificateIdentity {
            fingerprint,
            expires,
        })
    }
}
fn certificates(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    // Reject extra PEM objects and arbitrary text instead of silently ignoring
    // private keys or malformed neighboring blocks in an owner-supplied bundle.
    let mut rest = pem.trim();
    while !rest.is_empty() {
        ensure!(
            rest.starts_with("-----BEGIN CERTIFICATE-----"),
            "mTLS CA bundle must contain only certificates"
        );
        let end = rest
            .find("-----END CERTIFICATE-----")
            .context("incomplete mTLS CA certificate")?;
        rest = rest[end + "-----END CERTIFICATE-----".len()..].trim();
    }
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("invalid mTLS certificate PEM")
}
pub fn fingerprint(certificate: &CertificateDer<'_>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(64);
    for byte in ring::digest::digest(&ring::digest::SHA256, certificate.as_ref()).as_ref() {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 15)]));
    }
    result
}
fn fingerprint_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Constructed only by the native HTTPS listener after a completed handshake.
#[derive(Clone)]
pub(crate) struct TlsPeer {
    pub addr: std::net::SocketAddr,
    pub hostname: String,
    pub gate: Arc<super::VisitorGate>,
    pub certificate: Option<CertificateIdentity>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::visitor_policy::{Policy, Rejection, VisitorDecision, VisitorGate, VisitorPeer};
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;

    /// A throwaway CA generated per test process. No operator certificate or
    /// key file is read, so the test compiles and runs on a clean checkout.
    fn policy() -> MtlsPolicy {
        use std::sync::OnceLock;
        static CA_PEM: OnceLock<String> = OnceLock::new();
        let ca_pem = CA_PEM.get_or_init(|| {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
                .expect("empty subject alternative names");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
            ];
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "pike mtls test ca");
            let key = rcgen::KeyPair::generate().expect("test CA key");
            params.self_signed(&key).expect("test CA certificate").pem()
        });
        MtlsPolicy {
            ca_pem: ca_pem.clone(),
            allowed_fingerprints: None,
            revoked_fingerprints: vec![],
        }
    }

    #[test]
    fn trust_configuration_rejects_unbounded_or_malformed_material() {
        assert!(Mtls::new(policy()).is_ok());
        for pem in [
            String::new(),
            "x".repeat(16385),
            format!("{}\nprivate key", policy().ca_pem),
            policy().ca_pem.repeat(9),
        ] {
            assert!(Mtls::new(MtlsPolicy {
                ca_pem: pem,
                ..policy()
            })
            .is_err());
        }
        for list in [
            vec!["A".repeat(64)],
            vec!["0".repeat(63)],
            vec!["g".repeat(64)],
            vec!["0".repeat(64); 65],
        ] {
            assert!(Mtls::new(MtlsPolicy {
                allowed_fingerprints: Some(list),
                ..policy()
            })
            .is_err());
        }
        assert!(Mtls::new(policy()).unwrap().identity(&[]).is_err());
        assert_eq!(
            fingerprint(&CertificateDer::from(b"abc".as_slice())),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn only_protocols_with_native_certificate_proof_accept_mtls() {
        for kind in ["tcp", "udp", "tls", "tls-passthrough"] {
            let gate = VisitorGate::pending();
            assert!(gate
                .activate(
                    Policy {
                        mtls: Some(policy()),
                        ..Policy::default()
                    },
                    kind
                )
                .is_err());
            assert!(!gate.allows_ip("127.0.0.1".parse().unwrap()));
        }
        for kind in ["http", "tls-terminate"] {
            let gate = VisitorGate::pending();
            gate.activate(
                Policy {
                    mtls: Some(policy()),
                    ..Policy::default()
                },
                kind,
            )
            .unwrap();
            assert!(gate.tls_verifier().unwrap().is_some());
            assert!(matches!(
                gate.tls_admission(None),
                Err(Rejection::Certificate)
            ));
        }
    }

    #[tokio::test]
    async fn header_claims_and_another_routes_certificate_cannot_create_admission() {
        let gate = VisitorGate::pending();
        gate.activate(
            Policy {
                mtls: Some(policy()),
                ..Policy::default()
            },
            "http",
        )
        .unwrap();
        let visitor = VisitorPeer {
            addr: "127.0.0.1:5000".parse().unwrap(),
            secure: true,
            allow_plaintext: false,
        };
        let mut request = Request::builder()
            .header(
                "x-forwarded-client-cert",
                policy().ca_pem.replace('\n', " "),
            )
            .header("x-ssl-client-verify", "SUCCESS")
            .body(Body::empty())
            .unwrap();
        assert!(matches!(
            gate.handle_http(visitor, &mut request).await,
            Err(Rejection::Certificate)
        ));
        assert!(matches!(
            gate.authorize_http(visitor, request.headers_mut()).await,
            Err(Rejection::Certificate)
        ));
        request.extensions_mut().insert(TlsPeer {
            addr: visitor.addr,
            hostname: "a.test".into(),
            gate: VisitorGate::unrestricted(),
            certificate: Some(CertificateIdentity {
                fingerprint: "0".repeat(64),
                expires: Instant::now() + Duration::from_secs(60),
            }),
        });
        assert!(matches!(
            gate.handle_http(visitor, &mut request).await,
            Err(Rejection::Certificate)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn certificate_expiry_cancels_stalled_body_but_not_other_certificates() {
        let gate = VisitorGate::pending();
        gate.activate(
            Policy {
                mtls: Some(policy()),
                ..Policy::default()
            },
            "http",
        )
        .unwrap();
        let visitor = VisitorPeer {
            addr: "127.0.0.1:5000".parse().unwrap(),
            secure: true,
            allow_plaintext: false,
        };
        let identity = CertificateIdentity {
            fingerprint: "0".repeat(64),
            expires: Instant::now() + Duration::from_secs(2),
        };
        let longer = CertificateIdentity {
            expires: Instant::now() + Duration::from_secs(60),
            ..identity.clone()
        };
        let mut request = Request::new(Body::empty());
        request.extensions_mut().insert(TlsPeer {
            addr: visitor.addr,
            hostname: "a.test".into(),
            gate: gate.clone(),
            certificate: Some(identity.clone()),
        });
        let VisitorDecision::Admit(admission) =
            gate.handle_http(visitor, &mut request).await.unwrap()
        else {
            panic!("expected admission")
        };
        let mut body = admission.wrap_body(Body::from_stream(futures_util::stream::pending::<
            Result<axum::body::Bytes, std::io::Error>,
        >()));
        tokio::time::advance(Duration::from_secs(3)).await;
        assert!(body.frame().await.unwrap().is_err());
        assert!(matches!(
            gate.tls_admission(Some(&identity)),
            Err(Rejection::Certificate)
        ));
        assert!(gate.tls_admission(Some(&longer)).is_ok());
        assert!(gate.allows_ip(visitor.addr.ip()));
        assert!(matches!(
            gate.handle_http(visitor, &mut request).await,
            Err(Rejection::Certificate)
        ));
    }
}
