use std::sync::{Arc, Barrier};

use pike_core::types::TunnelId;
use pike_server::{
    config::AbuseConfig,
    connection::{ClientConnection, ConnectionState, ValidatedUser},
    metrics::ACTIVE_TUNNELS,
    registry::ClientRegistry,
};

fn client(registry: &ClientRegistry) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    let mut connection = ClientConnection::new(id, None);
    connection.state = ConnectionState::Authenticated;
    connection.set_validated_user(ValidatedUser {
        tunnel_limit: None,
        user_id: "reconnecting-owner".into(),
        email: "owner@example.test".into(),
        plan: "free".into(),
        plan_expires_at: None,
        status: pike_server::connection::UserStatus::Active,
        limits: pike_server::connection::UserLimits::default(),
    });
    registry.register_client(connection).unwrap();
    id
}

#[test]
// Keep the ordered lifecycle and its boundary assertions together in this scenario.
#[allow(clippy::too_many_lines)]
fn replacement_preserves_quota_usage_listener_identity_and_gauge_after_old_disconnect() {
    let gauge_before = ACTIVE_TUNNELS.get();
    let registry = Arc::new(ClientRegistry::new_with_abuse_config(AbuseConfig {
        tunnel_creations_per_user_per_hour: 1000,
        tunnel_creations_per_ip_per_hour: 1000,
        ..AbuseConfig::default()
    }));
    let old = client(&registry);
    let current = client(&registry);
    let runtime = TunnelId::new();
    let public_id = uuid::Uuid::new_v4().to_string();
    registry
        .register_tunnel(old, "reconnect.test".into(), runtime)
        .unwrap();
    registry
        .remember_tunnel_identity(runtime, public_id.clone())
        .unwrap();
    registry
        .remember_usage_tunnel(runtime, "reconnecting-owner".into(), public_id.clone())
        .unwrap();
    registry
        .register_tcp_listener(old, runtime, "127.0.0.1:12345".parse().unwrap())
        .unwrap();
    registry
        .clients
        .get_mut(&old)
        .unwrap()
        .tcp_remote_ports
        .insert(runtime, 12345);
    // A free plan allows one tunnel. Reconnection must transfer that slot.
    registry
        .register_tunnel(current, "reconnect.test".into(), runtime)
        .unwrap();
    assert!(registry.clients.get(&old).unwrap().tunnels.is_empty());
    assert!(registry
        .clients
        .get(&old)
        .unwrap()
        .tcp_remote_ports
        .is_empty());
    registry
        .register_tcp_listener(current, runtime, "127.0.0.1:12345".parse().unwrap())
        .unwrap();
    assert!(registry
        .register_tcp_listener(old, runtime, "127.0.0.1:12346".parse().unwrap())
        .is_err());
    registry.remove_client(&old);
    registry.finalize_usage_tunnel(runtime);
    assert_eq!(
        registry
            .lookup_tunnel("reconnect.test")
            .unwrap()
            .connection_id,
        current
    );
    assert_eq!(
        registry.lookup_tcp_listener(runtime).unwrap().connection_id,
        current
    );
    assert!(!registry.unregister_tcp_listener_if_owner(runtime, &old));
    assert!(registry.usage_tunnels()[0].finished_at.is_none());
    assert_eq!(ACTIVE_TUNNELS.get(), gauge_before + 1);
    assert!(registry
        .register_tunnel(current, "extra.test".into(), TunnelId::new())
        .is_err());
    // Same-owner duplicate registration is idempotent even at the plan limit.
    registry
        .register_tunnel(current, "reconnect.test".into(), runtime)
        .unwrap();
    assert_eq!(
        registry.clients.get(&current).unwrap().tunnels,
        vec![runtime]
    );

    registry.unregister_tunnel_if_owner("reconnect.test", &current);
    let first_finish = registry.usage_tunnels()[0].finished_at.unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1));
    registry
        .register_tunnel(current, "reconnect.test".into(), runtime)
        .unwrap();
    registry.unregister_tunnel_if_owner("reconnect.test", &current);
    let next_finish = registry.usage_tunnels()[0].finished_at.unwrap();
    assert!(next_finish > first_finish);
    registry.forget_finished_usage_tunnel(runtime, first_finish);
    assert_eq!(
        registry.usage_tunnels().len(),
        1,
        "old reporter ACK must not retire a newer generation"
    );
    registry.forget_finished_usage_tunnel(runtime, next_finish);
    assert!(registry.usage_tunnels().is_empty());
    assert_eq!(registry.public_tunnel_id(runtime), public_id);
    assert_eq!(registry.runtime_tunnel_id(&public_id), runtime.to_string());
    assert!(registry
        .remember_tunnel_identity(runtime, "different-public-id".into())
        .is_err());

    // A fresh runtime replacing the same hostname must also transfer the slot.
    registry
        .register_tunnel(current, "reconnect.test".into(), runtime)
        .unwrap();
    let replacement_owner = client(&registry);
    let replacement = TunnelId::new();
    registry
        .register_tunnel(replacement_owner, "reconnect.test".into(), replacement)
        .unwrap();
    registry
        .remember_tunnel_identity(replacement, public_id.clone())
        .unwrap();
    registry.remove_client(&current);
    assert_eq!(
        registry.runtime_tunnel_id(&public_id),
        replacement.to_string()
    );
    assert_eq!(
        registry.public_tunnel_id(runtime),
        public_id,
        "old metric identity must remain stable"
    );
    assert_eq!(ACTIVE_TUNNELS.get(), gauge_before + 1);
    assert!(registry
        .register_tunnel(replacement_owner, "alias.test".into(), replacement)
        .is_err());
    registry.remove_client(&replacement_owner);
    assert_eq!(ACTIVE_TUNNELS.get(), gauge_before);

    // A failed quota transfer must restore the previous owner's live slot.
    let preserved_owner = client(&registry);
    let preserved_runtime = TunnelId::new();
    registry
        .register_tunnel(preserved_owner, "preserved.test".into(), preserved_runtime)
        .unwrap();
    let busy_owner = client(&registry);
    registry
        .clients
        .get_mut(&busy_owner)
        .unwrap()
        .info
        .validated_user
        .as_mut()
        .unwrap()
        .user_id = "busy-owner".into();
    registry
        .register_tunnel(busy_owner, "busy.test".into(), TunnelId::new())
        .unwrap();
    assert!(registry
        .register_tunnel(busy_owner, "preserved.test".into(), TunnelId::new())
        .is_err());
    assert_eq!(
        registry.lookup_tunnel("preserved.test").unwrap().tunnel_id,
        preserved_runtime
    );
    assert!(registry
        .register_tunnel(preserved_owner, "extra.test".into(), TunnelId::new())
        .is_err());
    registry.remove_client(&preserved_owner);
    registry.remove_client(&busy_owner);
    assert_eq!(ACTIVE_TUNNELS.get(), gauge_before);

    // Both lock orderings of a real registration/disconnect race are valid.
    for _ in 0..20 {
        let old = client(&registry);
        let new = client(&registry);
        let runtime = TunnelId::new();
        registry
            .register_tunnel(old, "race.test".into(), runtime)
            .unwrap();
        let gate = Arc::new(Barrier::new(2));
        let retiring_registry = registry.clone();
        let retiring_gate = gate.clone();
        let retiring = std::thread::spawn(move || {
            retiring_gate.wait();
            retiring_registry.remove_client(&old);
        });
        gate.wait();
        registry
            .register_tunnel(new, "race.test".into(), runtime)
            .unwrap();
        retiring.join().unwrap();
        assert_eq!(
            registry.lookup_tunnel("race.test").unwrap().connection_id,
            new
        );
        registry.remove_client(&new);
    }
    assert_eq!(ACTIVE_TUNNELS.get(), gauge_before);
}
