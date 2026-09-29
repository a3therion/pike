use pike_core::types::TunnelId;
use pike_server::{
    connection::{ClientConnection, ConnectionState, ValidatedUser},
    registry::ClientRegistry,
};
use std::sync::Arc;
fn registry_with_tunnel() -> (Arc<ClientRegistry>, TunnelId, String, uuid::Uuid) {
    let registry = Arc::new(ClientRegistry::new());
    let conn_id = uuid::Uuid::new_v4();
    let mut client = ClientConnection::new(conn_id, None);
    client.transition_to(ConnectionState::Handshaking).unwrap();
    client.authenticate("pk_test_key_1234", true).unwrap();
    client.set_validated_user(ValidatedUser {
        tunnel_limit: None,
        user_id: "owner".to_string(),
        email: "test@example.test".to_string(),
        plan: "pro".to_string(),
        plan_expires_at: None,
        status: pike_server::connection::UserStatus::Active,
        limits: pike_server::connection::UserLimits::default(),
    });
    registry.register_client(client).unwrap();
    let runtime = TunnelId::new();
    let canonical = uuid::Uuid::new_v4().to_string();
    registry
        .register_tunnel(conn_id, "fixture".to_string(), runtime)
        .unwrap();
    registry
        .remember_usage_tunnel(runtime, "owner".to_string(), canonical.clone())
        .unwrap();
    (registry, runtime, canonical, conn_id)
}

#[test]
fn canonical_attribution_cannot_be_reassigned_to_another_owner() {
    let (registry, runtime, canonical, _) = registry_with_tunnel();
    assert!(registry
        .remember_usage_tunnel(runtime, "owner".to_string(), canonical.clone())
        .is_ok());
    assert!(registry
        .remember_usage_tunnel(runtime, "other".to_string(), canonical)
        .is_err());
    assert!(registry
        .remember_usage_tunnel(
            runtime,
            "owner".to_string(),
            uuid::Uuid::new_v4().to_string()
        )
        .is_err());
}

#[test]
fn owner_cleanup_removes_client_metadata_but_preserves_replacement() {
    let (registry, runtime, _, connection) = registry_with_tunnel();
    registry
        .clients
        .get_mut(&connection)
        .unwrap()
        .tcp_remote_ports
        .insert(runtime, 12345);
    assert!(!registry.unregister_tunnel_if_owner("fixture", &uuid::Uuid::new_v4()));
    assert!(registry.lookup_tunnel("fixture").is_some());
    assert!(registry.unregister_tunnel_if_owner("fixture", &connection));
    let client = registry.clients.get(&connection).unwrap();
    assert!(!client.tunnels.contains(&runtime));
    assert!(!client.tcp_remote_ports.contains_key(&runtime));
    assert!(registry.usage_tunnels()[0].finished_at.is_some());
    assert!(!registry.unregister_tunnel_if_owner("fixture", &connection));
}

#[test]
fn late_old_connection_cleanup_cannot_remove_new_hostname_owner() {
    let (registry, _, _, old_connection) = registry_with_tunnel();
    let new_connection = uuid::Uuid::new_v4();
    registry
        .register_client(ClientConnection::new(new_connection, None))
        .unwrap();
    let replacement = TunnelId::new();
    registry
        .register_tunnel(new_connection, "fixture".to_string(), replacement)
        .unwrap();
    assert!(!registry.unregister_tunnel_if_owner("fixture", &old_connection));
    registry.remove_client(&old_connection);
    assert_eq!(
        registry.lookup_tunnel("fixture").unwrap().tunnel_id,
        replacement
    );
    assert_eq!(
        registry.clients.get(&new_connection).unwrap().tunnels,
        vec![replacement]
    );
}
