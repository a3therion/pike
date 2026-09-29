use super::*;
use axum::http::HeaderValue;
fn protected() -> Policy {
    let mut hash = [0; 32];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(100_000).unwrap(),
        &[7; 32],
        "visitor:pässword!".as_bytes(),
        &mut hash,
    );
    Policy {
        basic: vec![BasicUser {
            username: "reader".into(),
            password_hash: format!(
                "pbkdf2_sha256$100000${}${}",
                STANDARD.encode([7; 32]),
                STANDARD.encode(hash)
            ),
        }],
        ..Policy::default()
    }
}
fn peer(ip: &str, secure: bool) -> VisitorPeer {
    VisitorPeer {
        addr: SocketAddr::new(ip.parse().unwrap(), 443),
        secure,
        allow_plaintext: false,
    }
}
#[test]
fn ip_rules_cover_ipv4_ipv6_mapped_addresses_and_deny_precedence() {
    let gate = VisitorGate::pending();
    assert!(!gate.allows_ip("127.0.0.1".parse().unwrap()));
    gate.activate(
        Policy {
            allow_cidrs: Some(vec!["192.0.2.0/24".into(), "2001:db8::/32".into()]),
            deny_cidrs: vec!["192.0.2.3/32".into(), "2001:db8:ffff::/48".into()],
            basic: vec![],
            jwt: None,
            oidc: None,
            mtls: None,
        },
        "udp",
    )
    .unwrap();
    for ip in ["192.0.2.1", "::ffff:192.0.2.1", "2001:db8::1"] {
        assert!(gate.allows_ip(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "192.0.2.3",
        "::ffff:192.0.2.3",
        "198.51.100.1",
        "::1",
        "2001:db8:ffff::1",
    ] {
        assert!(!gate.allows_ip(ip.parse().unwrap()), "{ip}");
    }
    gate.close();
    assert!(!gate.allows_ip("192.0.2.1".parse().unwrap()));
    assert!(gate.activate(Policy::default(), "udp").is_err());
}
#[test]
fn empty_allow_list_denies_everyone_and_malformed_policy_never_opens() {
    let gate = VisitorGate::pending();
    assert!(gate
        .activate(
            Policy {
                deny_cidrs: vec!["invalid".into()],
                ..Policy::default()
            },
            "http"
        )
        .is_err());
    assert!(!gate.allows_ip("127.0.0.1".parse().unwrap()));
    gate.activate(
        Policy {
            allow_cidrs: Some(vec![]),
            ..Policy::default()
        },
        "tcp",
    )
    .unwrap();
    assert!(!gate.allows_ip("::1".parse().unwrap()));
    assert!(!gate.allows_ip("127.0.0.1".parse().unwrap()));
    let bad = VisitorGate::pending();
    assert!(bad.activate(protected(), "tls").is_err());
    assert!(!bad.allows_ip("127.0.0.1".parse().unwrap()));
}
#[tokio::test]
async fn basic_verification_handles_unicode_colons_duplicates_and_strips_only_consumed_auth() {
    let gate = VisitorGate::pending();
    gate.activate(protected(), "http").unwrap();
    let mut headers = HeaderMap::new();
    for value in [
        None,
        Some("Bearer connector-key".into()),
        Some("Basic %notbase64".into()),
        Some(format!("Basic {}", STANDARD.encode("reader:wrong"))),
        Some(format!(
            "Basic {}",
            STANDARD.encode("unknown:visitor:pässword!")
        )),
    ] {
        headers.clear();
        if let Some(value) = value {
            headers.insert("authorization", value.parse().unwrap());
        }
        assert!(matches!(
            gate.authorize_http(peer("127.0.0.1", true), &mut headers)
                .await,
            Err(Rejection::Unauthorized)
        ));
    }
    let value: HeaderValue = format!("bAsIc {}", STANDARD.encode("reader:visitor:pässword!"))
        .parse()
        .unwrap();
    headers.insert("authorization", value.clone());
    headers.append("authorization", value.clone());
    assert!(matches!(
        gate.authorize_http(peer("127.0.0.1", true), &mut headers)
            .await,
        Err(Rejection::Unauthorized)
    ));
    headers.insert("authorization", value.clone());
    assert!(matches!(
        gate.authorize_http(peer("192.0.2.1", false), &mut headers)
            .await,
        Err(Rejection::Insecure)
    ));
    gate.authorize_http(peer("192.0.2.1", true), &mut headers)
        .await
        .unwrap();
    assert!(!headers.contains_key("authorization"));
    headers.insert("authorization", value);
    VisitorGate::unrestricted()
        .authorize_http(peer("192.0.2.1", false), &mut headers)
        .await
        .unwrap();
    assert!(
        headers.contains_key("authorization"),
        "ordinary application auth preserved without Basic policy"
    );
    gate.close();
    assert!(matches!(
        gate.authorize_http(peer("127.0.0.1", true), &mut headers)
            .await,
        Err(Rejection::Unavailable)
    ));
}
#[test]
fn proxy_identity_requires_explicit_network_trust_and_single_overwritten_headers() {
    let proxies = TrustedProxies::new(&["127.0.0.1/32".into()], false).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", HeaderValue::from_static("192.0.2.1"));
    headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    let trusted = proxies
        .resolve("127.0.0.1:5000".parse().unwrap(), &headers)
        .unwrap();
    assert!(trusted.secure);
    assert_eq!(trusted.addr.ip().to_string(), "192.0.2.1");
    let direct = proxies
        .resolve("198.51.100.1:5000".parse().unwrap(), &headers)
        .unwrap();
    assert!(!direct.secure);
    assert_eq!(direct.addr.ip().to_string(), "198.51.100.1");
    headers.append("x-real-ip", HeaderValue::from_static("127.0.0.1"));
    assert!(proxies
        .resolve("127.0.0.1:5000".parse().unwrap(), &headers)
        .is_err());
    for ip in ["127.0.0.1, 192.0.2.1", "unknown", "127.0.0.1:1234"] {
        headers.insert("x-real-ip", ip.parse().unwrap());
        assert!(proxies
            .resolve("127.0.0.1:5000".parse().unwrap(), &headers)
            .is_err());
    }
    headers.clear();
    assert!(proxies
        .resolve("127.0.0.1:5000".parse().unwrap(), &headers)
        .is_err());
}

#[test]
fn plaintext_loopback_requires_explicit_test_opt_in() {
    let local = "127.0.0.1:5000".parse().unwrap();
    assert!(
        !TrustedProxies::default()
            .resolve(local, &HeaderMap::new())
            .unwrap()
            .allow_plaintext
    );
    assert!(
        TrustedProxies::new(&[], true)
            .unwrap()
            .resolve(local, &HeaderMap::new())
            .unwrap()
            .allow_plaintext
    );
    assert!(
        !TrustedProxies::new(&[], true)
            .unwrap()
            .resolve("192.0.2.1:5000".parse().unwrap(), &HeaderMap::new())
            .unwrap()
            .allow_plaintext
    );
}

#[tokio::test]
async fn revocation_interrupts_a_stalled_body_without_waiting_for_session_cleanup() {
    use http_body_util::BodyExt;
    let gate = VisitorGate::unrestricted();
    let mut body = gate.wrap_body(Body::from_stream(futures_util::stream::pending::<
        Result<axum::body::Bytes, std::io::Error>,
    >()));
    let read = tokio::spawn(async move { body.frame().await });
    tokio::task::yield_now().await;
    assert!(!read.is_finished());
    gate.close();
    let frame = tokio::time::timeout(std::time::Duration::from_millis(100), read)
        .await
        .unwrap()
        .unwrap();
    assert!(frame.unwrap().is_err());
    // Revocation is sticky even when subscribed after the change.
    tokio::time::timeout(std::time::Duration::from_millis(100), gate.cancelled())
        .await
        .unwrap();
}
#[tokio::test]
async fn visitor_body_wrapper_preserves_data_and_grpc_trailers() {
    use http_body_util::BodyExt;
    let gate = VisitorGate::unrestricted();
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("7"));
    let frames: Vec<Result<_, std::io::Error>> = vec![
        Ok(hyper::body::Frame::data(axum::body::Bytes::from_static(
            b"binary\0",
        ))),
        Ok(hyper::body::Frame::trailers(trailers.clone())),
    ];
    let mut body = gate.wrap_body(Body::new(http_body_util::StreamBody::new(
        futures_util::stream::iter(frames),
    )));
    assert_eq!(
        body.frame()
            .await
            .unwrap()
            .unwrap()
            .data_ref()
            .unwrap()
            .as_ref(),
        b"binary\0"
    );
    assert_eq!(
        body.frame().await.unwrap().unwrap().trailers_ref(),
        Some(&trailers)
    );
    assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn token_expiry_interrupts_stalled_body_without_revoking_other_visitors() {
    use http_body_util::BodyExt;
    let gate = VisitorGate::unrestricted();
    let admission = VisitorAdmission {
        gate: gate.clone(),
        expires: Some(tokio::time::Instant::now() + std::time::Duration::from_millis(30)),
        session: None,
        domain: None,
    };
    let mut body = admission.wrap_body(Body::from_stream(futures_util::stream::pending::<
        Result<axum::body::Bytes, std::io::Error>,
    >()));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), body.frame())
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(gate.allows_ip("127.0.0.1".parse().unwrap()));
}
