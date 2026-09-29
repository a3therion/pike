use pike_core::{byte_stream::Direction, types::TunnelId};
use pike_server::{
    registry::ClientRegistry, traffic_meter::TrafficMeter, usage_journal::UsageJournal,
};
use std::sync::{atomic::Ordering, Arc};

#[tokio::test]
async fn canonical_directional_deltas_survive_teardown_and_do_not_count_buffers_as_requests() {
    let registry = Arc::new(ClientRegistry::new());
    let runtime = TunnelId::new();
    let owner = uuid::Uuid::new_v4().to_string();
    let canonical = uuid::Uuid::new_v4().to_string();
    registry
        .rate_limiter
        .register_tunnel(owner.clone(), runtime, Some("self-hosted"))
        .unwrap();
    let journal = Arc::new(UsageJournal::memory("https://test.invalid").unwrap());
    let meter = TrafficMeter::new(
        registry.clone(),
        runtime,
        owner.clone(),
        canonical.clone(),
        Some(journal.clone()),
    );
    meter.admit().unwrap();
    meter.opened().await.unwrap();
    for _ in 0..3 {
        meter.bytes(Direction::SocketToTunnel, 7).await.unwrap();
    }
    // Attribution was captured before retirement; late observations do not
    // depend on a live route or revert to the connector-generated UUID.
    registry.rate_limiter.unregister_tunnel(runtime);
    meter.bytes(Direction::TunnelToSocket, 11).await.unwrap();
    let first = journal.batch().await.unwrap();
    assert_eq!(first.iter().map(|row| row.request_count).sum::<u64>(), 1);
    assert_eq!(first.iter().map(|row| row.bytes_in).sum::<u64>(), 21);
    assert_eq!(first.iter().map(|row| row.bytes_out).sum::<u64>(), 11);
    assert!(first
        .iter()
        .all(|row| row.user_id == owner && row.tunnel_id == canonical));
    assert_eq!(registry.total_bytes_in.load(Ordering::Relaxed), 21);
    assert_eq!(registry.total_bytes_out.load(Ordering::Relaxed), 11);
    meter.packet(Direction::SocketToTunnel, 0).await.unwrap();
    meter.packet(Direction::SocketToTunnel, 3).await.unwrap();
    meter.packet(Direction::TunnelToSocket, 5).await.unwrap();
    assert_eq!(journal.batch().await.unwrap(), first);
    journal.acknowledge(&first).await.unwrap();
    let next = journal.batch().await.unwrap();
    assert_eq!(next.iter().map(|row| row.request_count).sum::<u64>(), 2);
    assert_eq!(next.iter().map(|row| row.bytes_in).sum::<u64>(), 3);
    assert_eq!(next.iter().map(|row| row.bytes_out).sum::<u64>(), 5);
}

#[tokio::test]
async fn storage_failure_rejects_observation_without_publishing_live_bytes() {
    let path = std::env::temp_dir().join(format!("pike-meter-{}.sqlite", uuid::Uuid::new_v4()));
    let registry = Arc::new(ClientRegistry::new());
    let journal = Arc::new(UsageJournal::open(&path, "https://test.invalid").unwrap());
    let meter = TrafficMeter::new(
        registry.clone(),
        TunnelId::new(),
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
        Some(journal.clone()),
    );
    meter.opened().await.unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("CREATE TRIGGER disk_failure BEFORE UPDATE ON counters BEGIN SELECT RAISE(ABORT,'fixture disk failure'); END;").unwrap();
    assert!(meter.bytes(Direction::SocketToTunnel, 13).await.is_err());
    assert_eq!(registry.total_bytes_in.load(Ordering::Relaxed), 0);
    assert!(!journal.is_healthy());
    let rows = journal.batch().await.unwrap();
    assert_eq!(rows[0].bytes_in, 0);
    assert_eq!(rows[0].request_count, 1);
    drop(connection);
    drop(meter);
    drop(journal);
    std::fs::remove_file(path).unwrap();
}
