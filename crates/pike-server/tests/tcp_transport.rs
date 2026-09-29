// Exercise the same transport bridges used by both binaries against real
// loopback TCP sockets; importing the CLI module keeps one production copy.
// Process-level fixtures cover CLI shutdown; this import exercises forwarding.
#[allow(dead_code)]
#[path = "../../pike/src/tunnel/tcp.rs"]
mod client_tcp;
#[path = "../src/relay_tcp.rs"]
mod relay_tcp;

use pike_core::{
    quic::{
        client::{ClientCommand, LocalData, PikeConnection, RegistrationResult, ServerData},
        server::{InboundData, PikeOutboundMessage},
        stream_manager::StreamManager,
    },
    types::{TunnelConfig, TunnelId, TunnelType},
};
use pike_server::tcp::TcpTunnelManager;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::timeout,
};

#[tokio::test]
async fn registered_tcp_tunnel_preserves_server_first_bytes_and_half_close() {
    timeout(Duration::from_secs(5), async {
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_port = local.local_addr().unwrap().port();
        let service = tokio::spawn(async move {
            let (mut socket, _) = local.accept().await.unwrap();
            socket.write_all(b"banner").await.unwrap();
            let mut request = Vec::new();
            socket.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request");
            socket.write_all(b"response after request FIN").await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let tunnel_id = TunnelId::new();
        let manager = TcpTunnelManager::new(Arc::new(StreamManager::new()));
        let (accepted_tx, accepted_rx) = mpsc::channel(4);
        let handle = manager.create_listener_with_dispatcher(tunnel_id, None, accepted_tx).await.unwrap();
        let remote_port = handle.local_addr.port();
        let (control_tx, mut control_rx) = mpsc::channel(4);
        let (local_tx, mut local_rx) = mpsc::channel::<LocalData>(4);
        let (server_tx, server_rx) = mpsc::channel(4);
        let (outbound_tx, mut outbound_rx) = mpsc::channel(4);
        let routes: relay_tcp::TcpRelays = Arc::default();
        let registry = Arc::new(pike_server::registry::ClientRegistry::new());
        registry.rate_limiter.register_tunnel("fixture".into(), tunnel_id, Some("self-hosted")).unwrap();
        let relay_task = tokio::spawn(relay_tcp::run_listener(tunnel_id, accepted_rx, outbound_tx, routes.clone(), pike_server::traffic_meter::TrafficMeter::new(registry.clone(), tunnel_id, "fixture".into(), tunnel_id.to_string(), None), pike_server::visitor_policy::VisitorGate::unrestricted()));
        let adapter_routes = routes.clone();
        let adapter = tokio::spawn(async move {
            loop {
                tokio::select! {
                    command = control_rx.recv() => match command {
                        Some(ClientCommand::RegisterTunnel { result_tx, .. }) => {
                            let _ = result_tx.send(RegistrationResult { public_url: format!("tcp://localhost:{remote_port}"), remote_port: Some(remote_port) });
                        }
                        _ => break,
                    },
                    Some(PikeOutboundMessage::Data(data)) = outbound_rx.recv() => {
                        if server_tx.send(ServerData { stream_id: 1, tunnel_id: data.tunnel_id, connection_id: data.connection_id, source_addr: data.source_addr, payload: data.payload, fin: data.fin, streaming: data.streaming, mode: data.mode }).await.is_err() { break; }
                    },
                    Some(data) = local_rx.recv() => {
                        relay_tcp::route_data(&adapter_routes, InboundData { stream_id: data.stream_id.unwrap(), tunnel_id: data.tunnel_id, connection_id: data.connection_id, source_addr: data.source_addr, payload: data.payload, fin: data.fin, streaming: data.streaming, mode: data.mode }).await.unwrap();
                    },
                }
            }
        });
        let config = TunnelConfig { cloud: None, id: tunnel_id, tunnel_type: TunnelType::Tcp { local_port, remote_port: Some(remote_port) }, local_addr: (std::net::Ipv4Addr::LOCALHOST, local_port).into() };
        let connection = PikeConnection::from_channels(control_tx, local_tx, server_rx);
        let mut tunnel = client_tcp::TcpTunnel::new(config, local_port, "127.0.0.1".into(), Some(remote_port), connection);
        assert_eq!(tunnel.register().await.unwrap(), remote_port);
        let client_task = tokio::spawn(async move { tunnel.run().await });
        let mut external = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, remote_port)).await.unwrap();
        let mut banner = [0; 6];
        external.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"banner");
        external.write_all(b"request").await.unwrap();
        external.shutdown().await.unwrap();
        let mut response = Vec::new();
        external.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response after request FIN");
        service.await.unwrap();
        manager.close_listener(tunnel_id).await;
        relay_task.await.unwrap();
        assert!(routes.lock().await.is_empty());
        assert_eq!(registry.total_bytes_in.load(std::sync::atomic::Ordering::Relaxed), b"request".len() as u64);
        assert_eq!(registry.total_bytes_out.load(std::sync::atomic::Ordering::Relaxed), (b"banner".len() + b"response after request FIN".len()) as u64);
        adapter.abort();
        let _ = adapter.await;
        client_task.await.unwrap().unwrap();
    }).await.expect("TCP tunnel must complete and release its routes");
}
