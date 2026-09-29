use super::*;
use crate::domain_grants::{DomainSet, VerifiedDomain};
use crate::visitor_policy::Policy;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use tower::ServiceExt;

const NONCE: &str = "0123456789abcdef0123456789abcdef";

fn gate(revision: u64) -> Arc<VisitorGate> {
    let visitor = VisitorGate::pending();
    visitor
        .activate_with_revision(Policy::default(), "http", Some(revision))
        .unwrap();
    visitor
}

fn claim(settings: &serde_json::Value) -> Claim<'_> {
    Claim {
        owner: "account",
        profile: "profile",
        hostname: "example.pike.test",
        kind: "http",
        port: None,
        settings,
        https: true,
        public_port: true,
    }
}

#[test]
fn verify_binds_only_the_current_matching_registration_and_its_gate() {
    let directory = Arc::<Directory>::default();
    let settings = serde_json::json!({"local_port": 3000});
    let visitor = gate(1);
    let (sender, receiver) = mpsc::channel(1);
    let first = directory
        .register(
            claim(&settings),
            visitor.clone(),
            None,
            sender.clone(),
            None,
        )
        .unwrap();
    let target = Target::hostname(Protocol::Http, "example.pike.test");
    let authority = directory.snapshot(NONCE).unwrap().routes[0]
        .authority
        .clone();
    assert!(directory.verify(&target, "0".repeat(64).as_str()).is_err());
    assert!(directory
        .verify(
            &Target::hostname(Protocol::Tls, "example.pike.test"),
            &authority
        )
        .is_err());
    let (hostname, bound) = directory.verify(&target, &authority).unwrap();
    assert_eq!(hostname, "example.pike.test");
    assert!(Arc::ptr_eq(&bound, &visitor));
    // A second member of the same endpoint shares the gate and the digest.
    let second = directory
        .register(
            claim(&settings),
            visitor.clone(),
            None,
            sender.clone(),
            None,
        )
        .unwrap();
    assert!(directory.verify(&target, &authority).is_ok());
    // A conflicting registration for the same target fails closed even though a
    // matching member still exists.
    let conflict = directory
        .register(claim(&settings), gate(2), None, sender.clone(), None)
        .unwrap();
    assert!(directory.verify(&target, &authority).is_err());
    drop(conflict);
    assert!(directory.verify(&target, &authority).is_ok());
    drop(first);
    drop(second);
    assert!(directory.verify(&target, &authority).is_err());
    // A same-relay replacement gets a fresh gate; the old digest cannot select it.
    let replacement = directory
        .register(claim(&settings), gate(1), None, sender, None)
        .unwrap();
    let (_, fresh) = directory.verify(&target, &authority).unwrap();
    assert!(!Arc::ptr_eq(&fresh, &visitor));
    drop(receiver);
    assert!(directory.verify(&target, &authority).is_err());
    drop(replacement);
    for bad in [
        Target {
            protocol: Protocol::Http,
            hostname: Some("Example.pike.test".into()),
            port: None,
        },
        Target {
            protocol: Protocol::Http,
            hostname: Some("example.pike.test".into()),
            port: Some(30000),
        },
        Target {
            protocol: Protocol::Tcp,
            hostname: None,
            port: Some(80),
        },
        Target {
            protocol: Protocol::Udp,
            hostname: Some("a".into()),
            port: Some(30000),
        },
    ] {
        assert!(bad.validate().is_err());
    }
}

#[test]
fn relay_local_ports_are_not_advertised_but_public_ports_are() {
    let directory = Arc::<Directory>::default();
    let settings = serde_json::json!({});
    let (sender, _receiver) = mpsc::channel(1);
    let mut local = claim(&settings);
    local.kind = "tcp";
    local.https = false;
    local.port = Some(30000);
    local.public_port = false;
    let visitor = VisitorGate::pending();
    visitor.activate(Policy::default(), "tcp").unwrap();
    let _local = directory
        .register(local, visitor.clone(), None, sender.clone(), None)
        .unwrap();
    assert!(directory.snapshot(NONCE).unwrap().routes.is_empty());
    let target = Target::port(Protocol::Tcp, 30000);
    let mut public = claim(&settings);
    public.kind = "tcp";
    public.https = false;
    public.port = Some(30000);
    let expected = Directory::authority(&public, &visitor, None, &target).unwrap();
    let _public = directory
        .register(public, visitor, None, sender, None)
        .unwrap();
    let snapshot = directory.snapshot(NONCE).unwrap();
    assert_eq!(snapshot.routes.len(), 1);
    assert_eq!(snapshot.routes[0].authority, expected);
    assert!(directory.verify(&target, &expected).is_ok());
}

#[test]
fn membership_and_revocation_follow_real_registration_lifetime() {
    let directory = Arc::<Directory>::default();
    let settings = serde_json::json!({"local_port": 3000});
    let visitor = gate(1);
    let (sender, receiver) = mpsc::channel(1);
    let first = directory
        .register(
            claim(&settings),
            visitor.clone(),
            None,
            sender.clone(),
            None,
        )
        .unwrap();
    let second = directory
        .register(claim(&settings), visitor.clone(), None, sender, None)
        .unwrap();
    let snapshot = directory.snapshot(NONCE).unwrap();
    assert_eq!(snapshot.routes.len(), 2);
    assert!(snapshot
        .routes
        .iter()
        .all(|route| route.members == 2 && route.origin_health == "unknown"));
    drop(first);
    assert!(directory
        .snapshot(NONCE)
        .unwrap()
        .routes
        .iter()
        .all(|route| route.members == 1));
    drop(receiver);
    assert!(directory.snapshot(NONCE).unwrap().routes.is_empty());
    drop(second);
    assert!(directory.0.lock().unwrap().is_empty());
    let (sender, _receiver) = mpsc::channel(1);
    let replacement = directory
        .register(claim(&settings), visitor.clone(), None, sender, None)
        .unwrap();
    visitor.close();
    assert!(directory.snapshot(NONCE).unwrap().routes.is_empty());
    drop(replacement);
}

#[test]
fn separate_relays_agree_only_on_the_same_owner_profile_policy_and_settings() {
    let a = Arc::<Directory>::default();
    let b = Arc::<Directory>::default();
    let settings = serde_json::json!({"local_port": 3000, "headers": {"x-b":"2", "x-a":"1"}});
    let (sender, _receiver) = mpsc::channel(1);
    let _a = a
        .register(claim(&settings), gate(1), None, sender.clone(), None)
        .unwrap();
    let first = b
        .register(claim(&settings), gate(1), None, sender.clone(), None)
        .unwrap();
    let expected = a.snapshot(NONCE).unwrap().routes[0].authority.clone();
    assert_eq!(expected, b.snapshot(NONCE).unwrap().routes[0].authority);
    drop(first);
    for variant in ["owner", "profile", "settings", "policy"] {
        let changed = serde_json::json!({"local_port": 3001});
        let mut next = claim(if variant == "settings" {
            &changed
        } else {
            &settings
        });
        if variant == "owner" {
            next.owner = "other";
        }
        if variant == "profile" {
            next.profile = "other";
        }
        let registration = b
            .register(
                next,
                gate(if variant == "policy" { 2 } else { 1 }),
                None,
                sender.clone(),
                None,
            )
            .unwrap();
        assert_ne!(
            expected,
            b.snapshot(NONCE).unwrap().routes[0].authority,
            "{variant}"
        );
        drop(registration);
    }
    let text = serde_json::to_string(&a.snapshot(NONCE).unwrap()).unwrap();
    assert!(!text.contains("account") && !text.contains("local_port") && !text.contains("x-a"));
}

#[tokio::test(start_paused = true)]
async fn expired_aliases_disappear_without_revoking_the_primary() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let domains = DomainGrants::bind(
        DomainSet {
            revision: 7,
            domains: vec![VerifiedDomain {
                hostname: "alias.example.test".into(),
                verified_until: now + 60_000,
            }],
        },
        "pike.test",
    )
    .unwrap();
    let directory = Arc::<Directory>::default();
    let (sender, _receiver) = mpsc::channel(1);
    let settings = serde_json::json!({});
    let _registration = directory
        .register(claim(&settings), gate(1), Some(&domains), sender, None)
        .unwrap();
    assert_eq!(directory.snapshot(NONCE).unwrap().routes.len(), 4);
    tokio::time::advance(std::time::Duration::from_secs(61)).await;
    let snapshot = directory.snapshot(NONCE).unwrap();
    assert_eq!(snapshot.routes.len(), 2);
    assert!(snapshot
        .routes
        .iter()
        .all(|r| r.target.hostname.as_deref() == Some("example.pike.test")));
}

#[test]
fn conflicting_routes_and_capacity_fail_closed_instead_of_truncating() {
    let directory = Arc::<Directory>::default();
    let settings = serde_json::json!({});
    let (sender, _receiver) = mpsc::channel(1);
    let first = directory
        .register(claim(&settings), gate(1), None, sender.clone(), None)
        .unwrap();
    let conflict = directory
        .register(claim(&settings), gate(2), None, sender.clone(), None)
        .unwrap();
    assert!(directory.snapshot(NONCE).is_err());
    drop(conflict);
    assert_eq!(directory.snapshot(NONCE).unwrap().routes.len(), 2);
    // Exercise the guard without pretending these are 16k production sessions.
    {
        let mut entries = directory.0.lock().unwrap();
        let entry = entries.get(&first.id).unwrap().clone();
        while entries.len() < MAX_MEMBERS {
            entries.insert(Uuid::new_v4(), entry.clone());
        }
    }
    assert!(directory
        .register(claim(&settings), gate(1), None, sender, None)
        .is_err());
    assert!(directory.snapshot(NONCE).is_err());
}

#[test]
fn all_public_protocol_targets_have_unambiguous_shapes() {
    let settings = serde_json::json!({});
    for (kind, expected) in [
        ("http", Protocol::Http),
        ("tls", Protocol::Tls),
        ("tcp", Protocol::Tcp),
        ("udp", Protocol::Udp),
    ] {
        let directory = Arc::<Directory>::default();
        let (sender, _receiver) = mpsc::channel(1);
        let visitor = VisitorGate::pending();
        visitor.activate(Policy::default(), kind).unwrap();
        let mut spec = claim(&settings);
        spec.kind = kind;
        spec.https = false;
        spec.port = Some(30000);
        let _registration = directory
            .register(spec, visitor, None, sender, None)
            .unwrap();
        let snapshot = directory.snapshot(NONCE).unwrap();
        let route = &snapshot.routes[0];
        assert_eq!(route.target.protocol, expected);
        assert_eq!(
            route.target.port,
            matches!(kind, "tcp" | "udp").then_some(30000)
        );
        assert_eq!(
            route.target.hostname.is_some(),
            matches!(kind, "http" | "tls")
        );
    }
}

#[tokio::test]
async fn management_requires_auth_and_fresh_nonce_and_never_caches_snapshots() {
    let registry = Arc::new(crate::registry::ClientRegistry::new());
    let app = crate::management::management_router(registry, "internal-secret");
    for (auth, query, status) in [
        (None, NONCE, StatusCode::UNAUTHORIZED),
        (Some("wrong"), NONCE, StatusCode::UNAUTHORIZED),
        (Some("internal-secret"), "bad", StatusCode::BAD_REQUEST),
        (Some("internal-secret"), NONCE, StatusCode::OK),
    ] {
        let mut req = Request::builder().uri(format!("/api/ingress/routes?nonce={query}"));
        if let Some(token) = auth {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        let response = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        if status == StatusCode::OK {
            assert_eq!(response.headers()["cache-control"], "no-store");
            let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
                .await
                .unwrap();
            let snapshot: Snapshot = serde_json::from_slice(&body).unwrap();
            assert_eq!(snapshot.nonce, NONCE);
            assert_eq!(snapshot.version, VERSION);
            assert_eq!(snapshot.max_age_ms, 2000);
            assert!(snapshot.routes.is_empty());
        }
    }
}
