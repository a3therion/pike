use super::*;
use crate::visitor_policy::{Policy, VisitorDecision};
use http_body_util::BodyExt;
fn policy() -> OidcPolicy {
    OidcPolicy {
        issuer: "https://identity.example.com".into(),
        client_id: "pike".into(),
        redirect_uri: "https://app.example.com/.pike/auth/callback".into(),
        algorithm: SigningAlgorithm::RS256,
        token_endpoint_auth_method: TokenAuth::None,
        client_secret: None,
        session_ttl_secs: 3600,
        allowed_subjects: None,
        allowed_emails: None,
    }
}
fn oidc() -> Oidc {
    Oidc::new(
        policy(),
        "profile:1".into(),
        KeyStore::new(&[]).unwrap(),
        Sessions::new(),
    )
    .unwrap()
}
pub(super) fn pending(scope: &str, browser: &str) -> store::Pending {
    store::Pending {
        scope: scope.into(),
        browser_hash: store::digest(browser),
        verifier: "verifier".into(),
        nonce: "nonce".into(),
        return_to: "https://app.example.com/".into(),
        provider_binding: Provider::fixture().binding.clone(),
        expires: Instant::now() + Duration::from_secs(60),
    }
}
fn request(method: &str, path: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("host", "app.example.com")
        .body(Body::empty())
        .unwrap()
}
fn peer() -> VisitorPeer {
    VisitorPeer {
        addr: "127.0.0.1:443".parse().unwrap(),
        secure: true,
        allow_plaintext: false,
    }
}
#[tokio::test]
async fn state_is_bound_to_browser_profile_revision_and_one_use() {
    let store = Sessions::new();
    let state = store.begin(pending("profile:1", "browser")).await.unwrap();
    assert!(store.consume(&state, "wrong", "profile:1").await.is_err());
    assert!(store.consume(&state, "browser", "profile:2").await.is_err());
    assert!(store.consume(&state, "browser", "other:1").await.is_err());
    assert_eq!(
        store
            .consume(&state, "browser", "profile:1")
            .await
            .unwrap()
            .nonce,
        "nonce"
    );
    assert!(store.consume(&state, "browser", "profile:1").await.is_err());
    let mut flow = pending("profile:1", "browser");
    flow.expires = Instant::now();
    let state = store.begin(flow).await.unwrap();
    assert!(store.consume(&state, "browser", "profile:1").await.is_err());
}
#[tokio::test]
async fn pending_flows_and_exchange_concurrency_are_bounded() {
    let store = Sessions::new();
    let permits: Vec<_> = (0..32)
        .map(|_| store.authentication_slot().unwrap())
        .collect();
    assert!(matches!(
        store.authentication_slot(),
        Err(Rejection::Unavailable)
    ));
    drop(permits);
    assert!(store.authentication_slot().is_ok());
    let provider = Provider::fixture();
    for scope in 0..16 {
        for _ in 0..64 {
            let mut flow = pending(&scope.to_string(), "browser");
            flow.provider_binding = provider.binding.clone();
            store.begin(flow).await.unwrap();
        }
        if scope == 0 {
            assert!(store.begin(pending("0", "browser")).await.is_err());
        }
    }
    assert!(store.begin(pending("extra", "browser")).await.is_err());
}
#[tokio::test]
async fn session_logout_closes_stalled_body_and_isolated_sessions_survive() {
    let store = Sessions::new();
    let expires = Instant::now() + Duration::from_secs(60);
    let (token, session) = store.create("profile:1", expires).await.unwrap();
    let (other, _) = store.create("profile:1", expires).await.unwrap();
    assert!(store.get(&token, "profile:2").await.unwrap().is_none());
    store.revoke(&token, "profile:2").await.unwrap();
    assert!(store.get(&token, "profile:1").await.unwrap().is_some());
    let gate = VisitorGate::unrestricted();
    let admission = VisitorAdmission {
        gate: gate.clone(),
        expires: Some(expires),
        session: Some(session.clone()),
        domain: None,
    };
    let mut body = admission.wrap_body(Body::from_stream(futures_util::stream::pending::<
        Result<axum::body::Bytes, std::io::Error>,
    >()));
    store.revoke(&token, "profile:1").await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), body.frame())
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    tokio::time::timeout(Duration::from_millis(100), session.cancelled())
        .await
        .unwrap();
    assert!(store.get(&token, "profile:1").await.unwrap().is_none());
    assert!(store.get(&other, "profile:1").await.unwrap().is_some());
    assert!(gate.allows_ip("127.0.0.1".parse().unwrap()));
}
#[tokio::test]
async fn session_capacity_expiry_and_scope_fail_closed() {
    let store = Sessions::new();
    let expires = Instant::now() + Duration::from_secs(60);
    for _ in 0..8192 {
        store.create("profile:1", expires).await.unwrap();
    }
    assert!(store.create("profile:1", expires).await.is_err());
    let store = Sessions::new();
    let (token, _) = store.create("profile:1", Instant::now()).await.unwrap();
    assert!(store.get(&token, "profile:1").await.unwrap().is_none());
    assert!(Sessions::new()
        .get(&token, "profile:1")
        .await
        .unwrap()
        .is_none());
}
#[test]
fn cookies_reject_ambiguity_and_strip_only_pike_credentials() {
    let mut headers = HeaderMap::new();
    let a = store::random().unwrap();
    let b = store::random().unwrap();
    headers.append(
        "cookie",
        format!("app=keep; {SESSION}={a}").parse().unwrap(),
    );
    headers.append(
        "cookie",
        format!("{BROWSER}={b}; other=a=b").parse().unwrap(),
    );
    let cookies = Cookies::parse(&headers).unwrap();
    assert_eq!(cookies.session.as_deref(), Some(a.as_str()));
    cookies.strip(&mut headers).unwrap();
    assert_eq!(headers["cookie"], "app=keep; other=a=b");
    for value in [
        format!("{SESSION}={a}; {SESSION}={a}"),
        format!("{BROWSER}=invalid"),
        "app=long".repeat(2049),
    ] {
        headers.insert("cookie", value.parse().unwrap());
        assert!(Cookies::parse(&headers).is_err());
    }
}
#[test]
fn return_urls_and_callback_parameters_cannot_redirect_or_override() {
    for value in [
        "//evil.test/",
        "https://evil.test",
        "/\\evil.test",
        "/.pike/auth/callback",
        "/a/../.pike/auth/logout",
        "/%2e/.pike/auth/login",
        "/bad\n",
    ] {
        assert!(
            return_target("https://app.example.com", value).is_err(),
            "{value}"
        );
    }
    assert_eq!(
        return_target("https://app.example.com", "/hello?tab=2").unwrap(),
        "https://app.example.com/hello?tab=2"
    );
    assert!(parameters(Some("state=one&state=two")).is_err());
    assert!(parameters(Some(&"x".repeat(8193))).is_err());
}
#[test]
fn unsafe_requests_and_websockets_require_exact_origin() {
    let oidc = oidc();
    for method in ["POST", "PUT", "DELETE"] {
        let mut req = request(method, "/");
        assert!(!oidc.same_origin_request(&req));
        req.headers_mut()
            .insert("origin", "https://app.example.com".parse().unwrap());
        assert!(oidc.same_origin_request(&req));
        req.headers_mut()
            .insert("origin", "https://evil.test".parse().unwrap());
        assert!(!oidc.same_origin_request(&req));
    }
    let mut req = request("GET", "/socket");
    req.headers_mut()
        .insert("upgrade", "websocket".parse().unwrap());
    assert!(!oidc.same_origin_request(&req));
    req.headers_mut()
        .insert("origin", "https://app.example.com".parse().unwrap());
    assert!(oidc.same_origin_request(&req));
    req.headers_mut()
        .append("origin", "https://evil.test".parse().unwrap());
    assert!(!oidc.same_origin_request(&req));
    let mut req = request("GET", "/");
    req.headers_mut()
        .insert("sec-fetch-site", "same-site".parse().unwrap());
    assert!(!oidc.same_origin_request(&req));
    req.headers_mut()
        .insert("sec-fetch-mode", "navigate".parse().unwrap());
    assert!(oidc.same_origin_request(&req));
}
#[tokio::test]
async fn oidc_requires_https_exact_host_and_routes_before_origin() {
    let oidc = oidc();
    let gate = VisitorGate::unrestricted();
    let mut req = request("GET", "/private");
    let mut insecure = peer();
    insecure.secure = false;
    insecure.allow_plaintext = true;
    assert!(matches!(
        oidc.handle(&gate, insecure, &mut req).await,
        Err(Rejection::Insecure)
    ));
    req.headers_mut()
        .insert("host", "other.example.com".parse().unwrap());
    assert!(matches!(
        oidc.handle(&gate, peer(), &mut req).await,
        Err(Rejection::InvalidSignIn)
    ));
    let mut req = request("GET", "/private");
    let VisitorDecision::Response(response) = oidc.handle(&gate, peer(), &mut req).await.unwrap()
    else {
        panic!("unauthenticated")
    };
    assert_eq!(response.status(), 401);
    let mut req = request("GET", "/.pike/auth/unknown");
    let VisitorDecision::Response(response) = oidc.handle(&gate, peer(), &mut req).await.unwrap()
    else {
        panic!("auth route forwarded")
    };
    assert_eq!(response.status(), 404);
}
#[tokio::test]
async fn authenticated_requests_strip_cookies_and_logout_requires_same_origin() {
    let oidc = oidc();
    let gate = VisitorGate::unrestricted();
    let (token, _) = oidc
        .sessions
        .create(&oidc.scope, Instant::now() + Duration::from_secs(60))
        .await
        .unwrap();
    let mut req = request("GET", "/private");
    req.headers_mut().insert(
        "cookie",
        format!("{SESSION}={token}; app=value").parse().unwrap(),
    );
    assert!(matches!(
        oidc.handle(&gate, peer(), &mut req).await.unwrap(),
        VisitorDecision::Admit(_)
    ));
    assert_eq!(req.headers()["cookie"], "app=value");
    let mut req = request("POST", LOGOUT);
    req.headers_mut()
        .insert("cookie", format!("{SESSION}={token}").parse().unwrap());
    assert!(matches!(
        oidc.handle(&gate, peer(), &mut req).await,
        Err(Rejection::CrossOrigin)
    ));
    assert!(oidc
        .sessions
        .get(&token, &oidc.scope)
        .await
        .unwrap()
        .is_some());
    req.headers_mut()
        .insert("origin", oidc.origin.parse().unwrap());
    let VisitorDecision::Response(response) = oidc.handle(&gate, peer(), &mut req).await.unwrap()
    else {
        panic!("logout forwarded")
    };
    assert_eq!(response.status(), 200);
    assert!(oidc
        .sessions
        .get(&token, &oidc.scope)
        .await
        .unwrap()
        .is_none());
    for cookie in response.headers().get_all("set-cookie") {
        let value = cookie.to_str().unwrap();
        for attribute in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/", "Max-Age=0"] {
            assert!(value.contains(attribute));
        }
        assert!(!value.contains("Domain="));
    }
}
#[test]
fn invalid_policy_fails_closed_and_debug_does_not_expose_secret() {
    let mut policy = policy();
    policy.client_secret = Some("private-secret".into());
    assert!(Oidc::new(
        policy.clone(),
        "scope".into(),
        KeyStore::new(&[]).unwrap(),
        Sessions::new()
    )
    .is_err());
    policy.token_endpoint_auth_method = TokenAuth::SecretBasic;
    let policy = Policy {
        oidc: Some(policy),
        ..Policy::default()
    };
    assert!(!format!("{policy:?}").contains("private-secret"));
    for kind in ["tcp", "tls", "udp"] {
        let gate = VisitorGate::pending();
        assert!(gate.activate(policy.clone(), kind).is_err());
        assert!(!gate.allows_ip("127.0.0.1".parse().unwrap()));
    }
}

#[test]
fn shared_session_configuration_is_explicit_and_redacts_credentials() {
    for namespace in ["", "bad:namespace", "{bad}", &"a".repeat(65)] {
        assert!(Sessions::configured(Some(&SessionStoreConfig {
            redis_url: "redis://127.0.0.1/0".into(),
            namespace: namespace.into(),
        }))
        .is_err());
    }
    for url in [
        "https://redis.invalid",
        "rediss://redis.invalid/#insecure",
        "not a url",
    ] {
        assert!(Sessions::configured(Some(&SessionStoreConfig {
            redis_url: url.into(),
            namespace: "test".into()
        }))
        .is_err());
    }
    let config = SessionStoreConfig {
        redis_url: "rediss://user:private-secret@redis.example.com:6379/0".into(),
        namespace: "production".into(),
    };
    let store = Sessions::configured(Some(&config)).unwrap();
    assert!(!format!("{config:?} {store:?}").contains("private-secret"));
    assert!(format!("{store:?}").contains("shared: true"));
    assert!(format!("{:?}", Sessions::configured(None).unwrap()).contains("shared: false"));
}

#[tokio::test]
async fn callback_rejects_changed_discovery_before_sending_credentials() {
    let oidc = oidc();
    let browser = store::random().unwrap();
    let mut flow = pending(&oidc.scope, &browser);
    flow.provider_binding = "different-provider-endpoints".into();
    let state = oidc.sessions.begin(flow).await.unwrap();
    oidc.discovery.lock().await.cached = Some(CachedProvider {
        provider: Provider::fixture(),
        expires: Instant::now() + Duration::from_secs(60),
    });
    let cookies = Cookies {
        browser: Some(browser),
        session: None,
        remaining: vec![],
    };
    assert!(matches!(
        oidc.callback(Some(&format!("state={state}&code=secret-code")), &cookies)
            .await,
        Err(Rejection::InvalidSignIn)
    ));
}
