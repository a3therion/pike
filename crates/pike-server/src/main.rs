#![allow(
    clippy::too_many_lines,
    clippy::unnecessary_option_map_or_else,
    clippy::uninlined_format_args,
    clippy::needless_pass_by_value,
    clippy::ignored_unit_patterns,
    clippy::match_same_arms
)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::body::{to_bytes, Body};
use axum::http::header::{CONNECTION, CONTENT_LENGTH, HOST};
use axum::http::{Request, Response};
use clap::Parser;
use pike_core::proto::{ControlMessage, ALPN_PROTOCOL, MIN_SUPPORTED_VERSION, PROTOCOL_VERSION};
use pike_core::quic::server::{OutboundData, PikeMessage, PikeOutboundMessage, PikeTunnelApp};
use pike_core::types::{RelayInfo, SubdomainSpec, TunnelType};
use pike_server::admin::run_admin_command;
use pike_server::config::{CliArgs, ServerConfig};
use pike_server::connection::{ClientConnection, ConnectionState, ValidatedUser};
use pike_server::control_plane::{AuthCache, ControlPlaneClient};
use pike_server::dashboard_ws::{DashboardBroadcaster, DashboardEvent};
use pike_server::http::run_http_server;
use pike_server::ingest::RequestBuffer;
use pike_server::management::run_management_server;
use pike_server::proxy::{HttpRequest, ProxyError, TunnelRequest, WebSocketRequest};
use pike_server::registry::ClientRegistry;
use pike_server::request_log::RequestLogStore;
use pike_server::router::{TunnelEntry, VhostRouter};
use pike_server::state_store::{
    FallbackStateStore, InMemoryStateStore, RedisStateStore, StateStore,
};
use pike_server::tunnel_metrics::TunnelMetricsStore;
use pike_server::usage_reporter::UsageReporter;
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
use tokio_quiche::ConnectionParams;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    let args = CliArgs::parse();
    let config = ServerConfig::from_file(&args.config, args.dev_mode)?;
    let state_store =
        build_rate_limit_store(config.redis_url.as_deref(), config.require_redis).await?;

    if let Some(command) = args.command {
        let registry = Arc::new(ClientRegistry::with_limits_and_store(
            config.abuse.clone(),
            config.max_connections,
            config.max_tunnels_per_connection,
            state_store.clone(),
        ));
        run_admin_command(command, registry).await?;
        return Ok(());
    }

    if config.dev_mode {
        warn!("Running in DEV MODE - no control plane");
    }

    info!(
        bind_addr = %config.bind_addr,
        deployment_topology = config.deployment_topology.as_str(),
        "starting pike-server"
    );

    let registry = Arc::new(ClientRegistry::with_limits_and_store(
        config.abuse.clone(),
        config.max_connections,
        config.max_tunnels_per_connection,
        state_store.clone(),
    ));
    let vhost_router = Arc::new(VhostRouter::new());
    let broadcaster = Arc::new(DashboardBroadcaster::new());
    let ingest_buffer = Arc::new(RequestBuffer::new(
        config.workers_api_url.clone().unwrap_or_default(),
        config.server_token.clone().unwrap_or_default(),
    ));
    let request_log_store = Arc::new(RequestLogStore::with_state_store(state_store.clone()));
    let tunnel_metrics_store = Arc::new(TunnelMetricsStore::with_state_store(state_store));

    let server_token_configured = config
        .server_token
        .as_ref()
        .is_some_and(|token| !token.trim().is_empty());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    if config.workers_api_url.is_some() && server_token_configured {
        ingest_buffer.spawn_flush_loop();
        let usage_reporter = Arc::new(UsageReporter::new(
            config.workers_api_url.clone().unwrap_or_default(),
            config.server_token.clone().unwrap_or_default(),
            tunnel_metrics_store.clone(),
            registry.clone(),
        ));
        usage_reporter.spawn_flush_loop(shutdown_rx.clone());
    }

    let accept_loop = spawn_accept_loop(
        registry.clone(),
        vhost_router.clone(),
        broadcaster.clone(),
        tunnel_metrics_store.clone(),
        config.clone(),
        shutdown_rx.clone(),
    )
    .await?;
    let heartbeat_loop = spawn_half_open_monitor(
        registry.clone(),
        vhost_router.clone(),
        config.clone(),
        shutdown_rx.clone(),
    );
    let http_loop = spawn_http_loop(
        vhost_router.clone(),
        registry.clone(),
        broadcaster.clone(),
        ingest_buffer.clone(),
        request_log_store,
        tunnel_metrics_store,
        config.clone(),
        shutdown_rx.clone(),
    );
    let management_loop =
        spawn_management_loop(registry.clone(), config.clone(), shutdown_rx.clone());
    let signal_loop = spawn_signal_handler(shutdown_tx.clone());

    wait_for_shutdown(shutdown_rx.clone()).await;
    info!("shutdown signal received; draining connections");

    registry.begin_shutdown_drain();
    tokio::time::timeout(
        Duration::from_secs(config.shutdown_timeout_secs),
        wait_for_all_connections_closed(registry.clone()),
    )
    .await
    .ok();

    registry.clients.clear();
    registry.tunnels.clear();
    registry.tcp_listeners.clear();

    let _ = signal_loop.await;
    let _ = heartbeat_loop.await;
    let _ = http_loop.await;
    let _ = management_loop.await;
    let _ = accept_loop.await;

    info!("shutdown complete");
    Ok(())
}

async fn build_rate_limit_store(
    redis_url: Option<&str>,
    require_redis: bool,
) -> Result<Option<Arc<dyn StateStore>>> {
    let fallback = Arc::new(InMemoryStateStore::new());
    let Some(redis_url) = redis_url else {
        if require_redis {
            anyhow::bail!("require_redis is enabled but redis_url is not configured");
        }
        return Ok(None);
    };

    match RedisStateStore::new(redis_url) {
        Ok(redis_store) => match redis_store.ping().await {
            Ok(()) if require_redis => {
                info!("connected to required Redis state store");
                Ok(Some(Arc::new(redis_store) as Arc<dyn StateStore>))
            }
            Ok(()) => Ok(Some(Arc::new(FallbackStateStore::new(
                Arc::new(redis_store) as Arc<dyn StateStore>,
                fallback,
            )) as Arc<dyn StateStore>)),
            Err(err) if require_redis => {
                Err(err.context("failed to connect to required Redis state store"))
            }
            Err(err) => {
                warn!(error = %err, "failed to initialize Redis state store, using in-memory state store");
                Ok(Some(fallback as Arc<dyn StateStore>))
            }
        },
        Err(err) => {
            if require_redis {
                Err(err.context("failed to initialize required Redis state store"))
            } else {
                warn!(error = %err, "failed to initialize Redis state store, using in-memory state store");
                Ok(Some(fallback as Arc<dyn StateStore>))
            }
        }
    }
}

fn check_protocol_version(protocol_version: Option<u32>) -> std::result::Result<(), String> {
    let Some(version) = protocol_version else {
        return Ok(());
    };

    if version > PROTOCOL_VERSION {
        return Err(format!(
            "protocol version {version} not supported, server max {PROTOCOL_VERSION}"
        ));
    }

    if version < MIN_SUPPORTED_VERSION {
        return Err(format!(
            "protocol version {version} not supported, minimum supported {MIN_SUPPORTED_VERSION}"
        ));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn spawn_http_loop(
    router: Arc<VhostRouter>,
    registry: Arc<ClientRegistry>,
    broadcaster: Arc<DashboardBroadcaster>,
    ingest_buffer: Arc<RequestBuffer>,
    request_log_store: Arc<RequestLogStore>,
    tunnel_metrics_store: Arc<TunnelMetricsStore>,
    config: ServerConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(error) = run_http_server(
            config.http_bind_addr,
            router,
            registry,
            broadcaster,
            ingest_buffer,
            request_log_store,
            tunnel_metrics_store,
            config.control_plane_url.clone(),
            config.local_api_keys.clone(),
            config.dev_mode,
            config.traffic_inspection.clone(),
            config.domain.clone(),
            shutdown_rx,
        )
        .await
        {
            warn!(error = %error, "HTTP listener exited with error");
        }
        info!("HTTP loop stopped");
    })
}

fn spawn_management_loop(
    registry: Arc<ClientRegistry>,
    config: ServerConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let server = tokio::spawn(async move {
            if let Err(error) =
                run_management_server(config.management_bind_addr, registry, config.internal_token)
                    .await
            {
                warn!(error = %error, "Management API listener exited with error");
            }
        });

        let _ = shutdown_rx.changed().await;
        server.abort();
        let _ = server.await;
        info!("Management API loop stopped");
    })
}

async fn spawn_accept_loop(
    registry: Arc<ClientRegistry>,
    vhost_router: Arc<VhostRouter>,
    broadcaster: Arc<DashboardBroadcaster>,
    tunnel_metrics_store: Arc<TunnelMetricsStore>,
    config: ServerConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<tokio::task::JoinHandle<()>> {
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let control_plane = Arc::new(ControlPlaneClient::new(
        http_client,
        config.control_plane_url.clone().unwrap_or_default(),
        config
            .workers_api_url
            .clone()
            .or_else(|| config.control_plane_url.clone())
            .unwrap_or_default(),
        config.dev_mode,
        config.local_api_keys.clone(),
    ));
    let auth_cache = AuthCache::new(Duration::from_secs(300));

    let socket = tokio::net::UdpSocket::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind QUIC socket on {}", config.bind_addr))?;
    let local_addr = socket
        .local_addr()
        .context("failed to get QUIC socket local address")?;
    info!(configured = %config.bind_addr, actual = %local_addr, "QUIC socket bound");

    let mut settings = QuicSettings::default();
    settings.alpn = vec![ALPN_PROTOCOL.to_vec()];
    settings.max_idle_timeout = Some(Duration::from_millis(config.quic_config.idle_timeout_ms));

    let cert_path = config
        .quic_config
        .cert_path
        .as_ref()
        .context("quic.cert_path must be set in config")?
        .to_string_lossy()
        .to_string();
    let key_path = config
        .quic_config
        .key_path
        .as_ref()
        .context("quic.key_path must be set in config")?
        .to_string_lossy()
        .to_string();

    let params = ConnectionParams::new_server(
        settings,
        TlsCertificatePaths {
            cert: &cert_path,
            private_key: &key_path,
            kind: CertificateKind::X509,
        },
        Hooks::default(),
    );

    let mut listeners = listen(
        [socket],
        params,
        SimpleConnectionIdGenerator,
        DefaultMetrics,
    )
    .context("failed to create tokio-quiche listener")?;

    let listener = listeners.remove(0);
    let mut accept_rx = listener.into_inner();
    info!("QUIC listener ready");

    Ok(tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_ok() && *shutdown_rx.borrow() {
                        break;
                    }
                }
                incoming = accept_rx.recv() => {
                    let Some(conn_result) = incoming else {
                        break;
                    };

                    match conn_result {
                        Ok(conn) => {
                            let connection_id = uuid::Uuid::new_v4();
                            let mut client = ClientConnection::new(connection_id, None);
                            if client.transition_to(ConnectionState::Handshaking).is_err() {
                                continue;
                            }

                            registry.register_client(client).ok();

                            let registry_for_conn = registry.clone();
                            let vhost_router_for_conn = vhost_router.clone();
                            let broadcaster_for_conn = broadcaster.clone();
                            let tunnel_metrics_store_for_conn = tunnel_metrics_store.clone();
                            let control_plane_for_conn = control_plane.clone();
                            let auth_cache_for_conn = auth_cache.clone();
                            let mut conn_shutdown_rx = shutdown_rx.clone();
                            let server_config = config.clone();
                            tokio::spawn(async move {
                                let (data_tx, mut data_rx) = mpsc::channel(256);
                                let (outbound_tx, outbound_rx) = mpsc::channel(256);
                                let app = PikeTunnelApp::new(data_tx, outbound_rx);
                                conn.start(app);
                                let pending_http = Arc::new(Mutex::new(HashMap::<
                                    u64,
                                    oneshot::Sender<Result<Response<Body>, ProxyError>>,
                                >::new()));
                                let ws_relays: Arc<Mutex<HashMap<u64, mpsc::Sender<Vec<u8>>>>> =
                                    Arc::new(Mutex::new(HashMap::new()));
                                let mut http_forwarders = Vec::new();
                                let mut registered_hosts = Vec::new();

                                loop {
                                    tokio::select! {
                                        changed = conn_shutdown_rx.changed() => {
                                            if changed.is_ok() && *conn_shutdown_rx.borrow() {
                                                break;
                                            }
                                        }
                                        inbound = data_rx.recv() => {
                                            let Some(inbound) = inbound else {
                                                warn!(connection_id = %connection_id, "QUIC connection lost: tunnel app channel closed (likely QUIC idle timeout or peer disconnect)");
                                                break;
                                            };

                                            match inbound {
                                                PikeMessage::Control(control_msg) => {
                                                    match control_msg {
                                                        ControlMessage::RegisterTunnel { config } => {
                                                            let tunnel_id = config.id;
                                                            info!(tunnel_id = %tunnel_id, "RegisterTunnel message received");
                                                            let api_key = registry_for_conn
                                                                .clients
                                                                .get(&connection_id)
                                                                .and_then(|client| client.info.api_key.clone())
                                                                .unwrap_or_default();
                                                            let (subdomain, remote_port) = match &config.tunnel_type {
                                                                TunnelType::Http { subdomain, .. } => {
                                                                    let host = match subdomain {
                                                                        Some(candidate) => {
                                                                            match SubdomainSpec::new(candidate.to_lowercase()) {
                                                                                Ok(spec) => spec.0,
                                                                                Err(e) => {
                                                                                    warn!(tunnel_id = %tunnel_id, error = %e, "Subdomain validation failed");
                                                                                    let reason = format!("Invalid subdomain: {}", e);
                                                                                    let _ = outbound_tx
                                                                                        .send(PikeOutboundMessage::Control(ControlMessage::TunnelError {
                                                                                            tunnel_id,
                                                                                            reason,
                                                                                        }))
                                                                                        .await;
                                                                                    continue;
                                                                                }
                                                                            }
                                                                        }
                                                                        None => tunnel_id.to_string(),
                                                                    };
                                                                    (format!("{host}.{}", server_config.domain), None)
                                                                }
                                                                TunnelType::Tcp { remote_port, .. } => {
                                                                    (format!("{}.{}", tunnel_id, server_config.domain), *remote_port)
                                                                }
                                                            };
                                                            info!(subdomain = %subdomain, "Registering tunnel with subdomain");

                                                            if matches!(&config.tunnel_type, TunnelType::Http { .. }) {
                                                                let requested_subdomain =
                                                                    subdomain.trim_end_matches(&format!(".{}", server_config.domain));
                                                                if let Err(error) = control_plane_for_conn
                                                                    .register_tunnel(
                                                                        &api_key,
                                                                        requested_subdomain,
                                                                        "http",
                                                                    )
                                                                    .await
                                                                {
                                                                    let workers_reason = error.to_string();
                                                                    warn!(tunnel_id = %tunnel_id, subdomain = %subdomain, error = %workers_reason, "Workers API rejected tunnel registration");
                                                                    let reason = if workers_reason
                                                                        == "subdomain already in use by another user"
                                                                    {
                                                                        format!(
                                                                            "Subdomain '{}' is owned by another user",
                                                                            requested_subdomain
                                                                        )
                                                                    } else if workers_reason.contains("tunnel limit reached") {
                                                                        format!("Tunnel limit reached for your plan. Upgrade at {}", server_config.domain)
                                                                    } else {
                                                                        workers_reason
                                                                    };
                                                                    let _ = outbound_tx
                                                                        .send(PikeOutboundMessage::Control(ControlMessage::TunnelError {
                                                                            tunnel_id,
                                                                            reason,
                                                                        }))
                                                                        .await;
                                                                    continue;
                                                                }
                                                            }

                                                            if let Err(error) = registry_for_conn.register_tunnel(
                                                                connection_id,
                                                                subdomain.clone(),
                                                                tunnel_id,
                                                            ) {
                                                                warn!(error = %error, "failed to register tunnel");
                                                                let _ = outbound_tx
                                                                    .send(PikeOutboundMessage::Control(ControlMessage::TunnelError {
                                                                        tunnel_id,
                                                                        reason: error.to_string(),
                                                                    }))
                                                                    .await;
                                                                continue;
                                                            }
                                                            info!("Tunnel registered in registry");

                                                            if let Some(user_id) = registry_for_conn
                                                                .user_id_for_connection(&connection_id)
                                                            {
                                                                tunnel_metrics_store_for_conn
                                                                    .remember_tunnel(
                                                                        &tunnel_id.to_string(),
                                                                        &user_id,
                                                                    )
                                                                    .await;
                                                            }

                                                            if matches!(&config.tunnel_type, TunnelType::Http { .. }) {
                                                                info!("Registering HTTP tunnel in VhostRouter");
                                                                let (http_tx, mut http_rx) = mpsc::channel::<TunnelRequest>(256);
                                                                vhost_router_for_conn.register(
                                                                    &subdomain,
                                                                    TunnelEntry {
                                                                        tunnel_id,
                                                                        connection_id,
                                                                        stream_tx: http_tx,
                                                                        active: true,
                                                                    },
                                                                );
                                                                registered_hosts.push(subdomain.clone());

                                                                let outbound_tx = outbound_tx.clone();
                                                                let pending_http = pending_http.clone();
                                                                let ws_relays = ws_relays.clone();
                                                                http_forwarders.push(tokio::spawn(async move {
                                                                    while let Some(tunnel_req) = http_rx.recv().await {
                                                                        match tunnel_req {
                                                                            TunnelRequest::Http(http_request) => {
                                                                                let HttpRequest {
                                                                                    stream_header,
                                                                                    request,
                                                                                    response_tx,
                                                                                    ..
                                                                                } = *http_request;

                                                                                let encoded_request = match encode_http_request(request).await {
                                                                                    Ok(encoded) => encoded,
                                                                                    Err(error) => {
                                                                                        let _ = response_tx.send(Err(error));
                                                                                        continue;
                                                                                    }
                                                                                };

                                                                                let request_key = stream_header.connection_id;
                                                                                pending_http.lock().await.insert(request_key, response_tx);

                                                                                let send_result = outbound_tx
                                                                                    .send(PikeOutboundMessage::Data(OutboundData {
                                                                                        stream_id: None,
                                                                                        tunnel_id: stream_header.tunnel_id,
                                                                                        connection_id: stream_header.connection_id,
                                                                                        source_addr: stream_header.source_addr,
                                                                                        payload: encoded_request,
                                                                                        fin: true,
                                                                                        streaming: false,
                                                                                    }))
                                                                                    .await;

                                                                                if send_result.is_err() {
                                                                                    if let Some(tx) = pending_http.lock().await.remove(&request_key) {
                                                                                        let _ = tx.send(Err(ProxyError::DispatchFailed));
                                                                                    }
                                                                                }
                                                                            }
                                                                            TunnelRequest::WebSocket(ws_request) => {
                                                                                let WebSocketRequest {
                                                                                    stream_header,
                                                                                    request_id: _,
                                                                                    raw_upgrade_request,
                                                                                    mut ws_to_quic_rx,
                                                                                    quic_to_ws_tx,
                                                                                } = ws_request;

                                                                                let conn_id = stream_header.connection_id;

                                                                                // Store the WS relay channel for routing incoming QUIC data
                                                                                ws_relays.lock().await.insert(conn_id, quic_to_ws_tx);

                                                                                // Send the raw HTTP upgrade request through QUIC with streaming: true
                                                                                let _ = outbound_tx
                                                                                    .send(PikeOutboundMessage::Data(OutboundData {
                                                                                        stream_id: None,
                                                                                        tunnel_id: stream_header.tunnel_id,
                                                                                        connection_id: conn_id,
                                                                                        source_addr: stream_header.source_addr,
                                                                                        payload: raw_upgrade_request,
                                                                                        fin: false,
                                                                                        streaming: true,
                                                                                    }))
                                                                                    .await;

                                                                                // Spawn a task to relay WS frames -> QUIC
                                                                                let outbound_tx_ws = outbound_tx.clone();
                                                                                let ws_relays_cleanup = ws_relays.clone();
                                                                                tokio::spawn(async move {
                                                                                    while let Some(bytes) = ws_to_quic_rx.recv().await {
                                                                                        if bytes.is_empty() {
                                                                                            continue;
                                                                                        }
                                                                                        let _ = outbound_tx_ws
                                                                                            .send(PikeOutboundMessage::Data(OutboundData {
                                                                                                stream_id: None, // Will be routed by connection_id
                                                                                                tunnel_id: stream_header.tunnel_id,
                                                                                                connection_id: conn_id,
                                                                                                source_addr: stream_header.source_addr,
                                                                                                payload: bytes,
                                                                                                fin: false,
                                                                                                streaming: true,
                                                                                            }))
                                                                                            .await;
                                                                                    }
                                                                                    // WS closed, send fin
                                                                                    let _ = outbound_tx_ws
                                                                                        .send(PikeOutboundMessage::Data(OutboundData {
                                                                                            stream_id: None,
                                                                                            tunnel_id: stream_header.tunnel_id,
                                                                                            connection_id: conn_id,
                                                                                            source_addr: stream_header.source_addr,
                                                                                            payload: vec![],
                                                                                            fin: true,
                                                                                            streaming: true,
                                                                                        }))
                                                                                        .await;
                                                                                    ws_relays_cleanup.lock().await.remove(&conn_id);
                                                                                });
                                                                            }
                                                                        }
                                                                    }
                                                                }));
                                                            }

                                                            // Broadcast tunnel connected event
                                                            if let Some(uid) = registry_for_conn.user_id_for_connection(&connection_id) {
                                                                let event = DashboardEvent::TunnelStatus {
                                                                    tunnel_id: tunnel_id.to_string(),
                                                                    subdomain: subdomain.clone(),
                                                                    status: "connected".to_string(),
                                                                };
                                                                if let Ok(json) = serde_json::to_string(&event) {
                                                                    broadcaster_for_conn.broadcast(&uid, &json);
                                                                }
                                                            }

                                                            let response = ControlMessage::TunnelRegistered {
                                                                tunnel_id,
                                                                public_url: format!("https://{subdomain}"),
                                                                remote_port,
                                                            };
                                                            let _ = outbound_tx
                                                                .send(PikeOutboundMessage::Control(response))
                                                                .await;
                                                        }
                                                        ControlMessage::Heartbeat { seq, timestamp } => {
                                                            registry_for_conn.heartbeat(&connection_id);
                                                            let response = ControlMessage::HeartbeatAck {
                                                                seq,
                                                                timestamp,
                                                                server_time: std::time::SystemTime::now()
                                                                    .duration_since(std::time::UNIX_EPOCH)
                                                                    .unwrap_or_default()
                                                                    .as_secs(),
                                                            };
                                                            let _ = outbound_tx
                                                                .send(PikeOutboundMessage::Control(response))
                                                                .await;
                                                        }
                                                        ControlMessage::Login { api_key, client_version: _, protocol_version } => {
                                                            info!(connection_id = %connection_id, api_key_len = api_key.len(), "Login received, validating API key");

                                                            if let Err(reason) = check_protocol_version(protocol_version) {
                                                                warn!(connection_id = %connection_id, %reason, "client protocol version rejected");
                                                                let _ = outbound_tx
                                                                    .send(PikeOutboundMessage::Control(ControlMessage::LoginFailure {
                                                                        reason,
                                                                    }))
                                                                    .await;
                                                                continue;
                                                            }

                                                            if let Some(version) = protocol_version {
                                                                info!(connection_id = %connection_id, version, "client connected with protocol version");
                                                            } else {
                                                                warn!(connection_id = %connection_id, "client connected without protocol version (legacy client)");
                                                            }

                                                            let auth_result: Result<ValidatedUser> =
                                                                if let Some(cached_user) = auth_cache_for_conn.get(&api_key) {
                                                                    info!(connection_id = %connection_id, "auth cache hit");
                                                                    Ok(cached_user)
                                                                } else {
                                                                    control_plane_for_conn.validate_api_key(&api_key).await
                                                                };

                                                            match auth_result {
                                                                Ok(user) => {
                                                                    auth_cache_for_conn.insert(&api_key, user.clone());

                                                                    if let Some(mut client) =
                                                                        registry_for_conn.clients.get_mut(&connection_id)
                                                                    {
                                                                        client.info.api_key = Some(api_key.clone());
                                                                        client.set_validated_user(user);
                                                                        let _ = client.transition_to(ConnectionState::Authenticated);
                                                                    }

                                                                    let session_id =
                                                                        format!("session-{}", uuid::Uuid::new_v4().simple());
                                                                    let response = ControlMessage::LoginSuccess {
                                                                        session_id,
                                                                        relay_info: RelayInfo {
                                                                            addr: config.bind_addr,
                                                                            region: "global".to_string(),
                                                                            version: env!("CARGO_PKG_VERSION").to_string(),
                                                                        },
                                                                    };
                                                                    let _ = outbound_tx
                                                                        .send(PikeOutboundMessage::Control(response))
                                                                        .await;
                                                                }
                                                                Err(e) => {
                                                                    warn!(connection_id = %connection_id, error = %e, "API key validation failed");
                                                                    let response = ControlMessage::LoginFailure {
                                                                        reason: e.to_string(),
                                                                    };
                                                                    let _ = outbound_tx
                                                                        .send(PikeOutboundMessage::Control(response))
                                                                        .await;
                                                                }
                                                            }
                                                        }
                                                        ControlMessage::UnregisterTunnel { .. }
                                                        | ControlMessage::LoginSuccess { .. }
                                                        | ControlMessage::LoginFailure { .. }
                                                        | ControlMessage::TunnelRegistered { .. }
                                                        | ControlMessage::TunnelError { .. }
                                                        | ControlMessage::HeartbeatAck { .. } => {}
                                                    }
                                                }
                                                PikeMessage::Data(data) => {
                                                    if data.streaming {
                                                        // Route to WS relay
                                                        let relays = ws_relays.lock().await;
                                                        if let Some(relay_tx) = relays.get(&data.connection_id) {
                                                            let _ = relay_tx.send(data.payload).await;
                                                        }
                                                        drop(relays);
                                                        if data.fin {
                                                            ws_relays.lock().await.remove(&data.connection_id);
                                                        }
                                                    } else if let Some(response_tx) = pending_http.lock().await.remove(&data.connection_id) {
                                                        let _ = response_tx.send(parse_http_response(&data.payload));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                for forwarder in http_forwarders {
                                    forwarder.abort();
                                }

                                // Broadcast disconnected status for each tunnel
                                if let Some(uid) = registry_for_conn.user_id_for_connection(&connection_id) {
                                    for host in &registered_hosts {
                                        let event = DashboardEvent::TunnelStatus {
                                            tunnel_id: String::new(),
                                            subdomain: host.clone(),
                                            status: "disconnected".to_string(),
                                        };
                                        if let Ok(json) = serde_json::to_string(&event) {
                                            broadcaster_for_conn.broadcast(&uid, &json);
                                        }
                                    }
                                }

                                // Fire-and-forget: update tunnel status to inactive in Workers API
                                if let (Some(api_url), Some(token)) = (
                                    &server_config.workers_api_url,
                                    &server_config.server_token,
                                ) {
                                    if !token.trim().is_empty() {
                                        let url = format!("{}/api/v1/tunnels/internal/status-bulk", api_url);
                                        let subdomains: Vec<String> = registered_hosts
                                            .iter()
                                            .map(|h| h.trim_end_matches(".pike.life").to_string())
                                            .collect();
                                        let token = token.clone();
                                        tokio::spawn(async move {
                                            let client = reqwest::Client::new();
                                            match client
                                                .post(&url)
                                                .header("X-Server-Token", &token)
                                                .json(&serde_json::json!({
                                                    "subdomains": subdomains,
                                                    "status": "inactive"
                                                }))
                                                .send()
                                                .await
                                            {
                                                Ok(resp) => {
                                                    tracing::info!(
                                                        status = %resp.status(),
                                                        "tunnel status bulk update sent"
                                                    );
                                                }
                                                Err(e) => {
                                                    tracing::warn!(
                                                        error = %e,
                                                        "failed to update tunnel status in Workers API"
                                                    );
                                                }
                                            }
                                        });
                                    }
                                }

                                for host in registered_hosts {
                                    vhost_router_for_conn.unregister_if_owner(&host, &connection_id);
                                }

                                registry_for_conn.remove_client(&connection_id);
                            });
                        }
                        Err(error) => {
                            warn!(error = %error, "failed to accept QUIC connection");
                        }
                    }
                }
            }
        }

        info!("accept loop stopped");
    }))
}

fn spawn_half_open_monitor(
    registry: Arc<ClientRegistry>,
    vhost_router: Arc<VhostRouter>,
    config: ServerConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let workers_api_url = config.workers_api_url.clone();
    let server_token = config.server_token.clone();
    tokio::spawn(async move {
        let timeout = Duration::from_secs(config.heartbeat_timeout_secs);
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_ok() && *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    for conn_id in registry.mark_dead_connections(timeout) {
                        warn!(connection_id = %conn_id, "Client presumed dead, marking tunnels inactive");
                        let removed_hosts = vhost_router.unregister_by_connection_id(&conn_id);
                        if !removed_hosts.is_empty() {
                            if let (Some(api_url), Some(token)) = (&workers_api_url, &server_token) {
                                if !token.trim().is_empty() {
                                    let url = format!("{}/api/v1/tunnels/internal/status-bulk", api_url);
                                    let subdomains: Vec<String> = removed_hosts
                                        .iter()
                                        .map(|h| h.trim_end_matches(".pike.life").to_string())
                                        .collect();
                                    let token = token.clone();
                                    info!(subdomains = ?subdomains, "Updating tunnel status to inactive via Workers API");
                                    tokio::spawn(async move {
                                        let client = reqwest::Client::new();
                                        match client
                                            .post(&url)
                                            .header("X-Server-Token", &token)
                                            .json(&serde_json::json!({
                                                "subdomains": subdomains,
                                                "status": "inactive"
                                            }))
                                            .send()
                                            .await
                                        {
                                            Ok(resp) => info!(status = %resp.status(), "Workers API status-bulk response"),
                                            Err(e) => error!(error = %e, "Failed to update tunnel status via Workers API"),
                                        }
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    })
}

fn spawn_signal_handler(shutdown_tx: watch::Sender<bool>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        }

        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }

        let _ = shutdown_tx.send(true);
    })
}

async fn wait_for_shutdown(mut shutdown_rx: watch::Receiver<bool>) {
    while shutdown_rx.changed().await.is_ok() {
        if *shutdown_rx.borrow() {
            break;
        }
    }
}

async fn wait_for_all_connections_closed(registry: Arc<ClientRegistry>) {
    loop {
        if registry.clients.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn encode_http_request(request: Request<Body>) -> Result<Vec<u8>, ProxyError> {
    let (parts, body) = request.into_parts();
    let body_bytes = to_bytes(body, 10 * 1024 * 1024)
        .await
        .map_err(|error| ProxyError::Upstream(format!("failed to read request body: {error}")))?;

    let target = parts
        .uri
        .path_and_query()
        .map_or("/", |value| value.as_str());
    let mut encoded = format!("{} {} HTTP/1.1\r\n", parts.method.as_str(), target).into_bytes();
    let mut has_host = false;

    for (name, value) in &parts.headers {
        if is_hop_by_hop_header(name.as_str()) || name == CONTENT_LENGTH {
            continue;
        }
        if let Ok(header_value) = value.to_str() {
            if name == HOST {
                has_host = true;
            }
            encoded.extend_from_slice(name.as_str().as_bytes());
            encoded.extend_from_slice(b": ");
            encoded.extend_from_slice(header_value.as_bytes());
            encoded.extend_from_slice(b"\r\n");
        }
    }

    if !has_host {
        if let Some(authority) = parts.uri.authority() {
            encoded.extend_from_slice(b"Host: ");
            encoded.extend_from_slice(authority.as_str().as_bytes());
            encoded.extend_from_slice(b"\r\n");
        }
    }

    encoded.extend_from_slice(format!("Content-Length: {}\r\n", body_bytes.len()).as_bytes());
    encoded.extend_from_slice(CONNECTION.as_str().as_bytes());
    encoded.extend_from_slice(b": close\r\n\r\n");
    encoded.extend_from_slice(&body_bytes);
    Ok(encoded)
}

fn parse_http_response(payload: &[u8]) -> Result<Response<Body>, ProxyError> {
    let normalized = normalize_http_response(payload)?;
    let mut builder = Response::builder().status(normalized.status_code);
    let has_content_length = normalized
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()));

    for (name, value) in &normalized.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }

    if !has_content_length {
        builder = builder.header(CONTENT_LENGTH, normalized.body.len().to_string());
    }

    builder
        .body(Body::from(normalized.body))
        .map_err(|error| ProxyError::Upstream(format!("failed to build response: {error}")))
}

struct NormalizedHttpResponse {
    status_code: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn normalize_http_response(payload: &[u8]) -> Result<NormalizedHttpResponse, ProxyError> {
    let mut offset = 0;

    loop {
        let header_end = find_header_end(&payload[offset..]).ok_or_else(|| {
            ProxyError::Upstream("invalid upstream HTTP response framing".to_string())
        })?;
        let header_end_abs = offset + header_end;
        let header_bytes = &payload[offset..header_end_abs];
        let header_text = std::str::from_utf8(header_bytes).map_err(|error| {
            ProxyError::Upstream(format!("invalid upstream header encoding: {error}"))
        })?;
        let mut lines = header_text.split("\r\n");

        let status_line = lines
            .next()
            .ok_or_else(|| ProxyError::Upstream("missing upstream status line".to_string()))?;
        let mut status_parts = status_line.splitn(3, ' ');
        let _http_version = status_parts.next();
        let status_code = status_parts
            .next()
            .ok_or_else(|| ProxyError::Upstream("missing upstream status code".to_string()))?
            .parse::<u16>()
            .map_err(|error| {
                ProxyError::Upstream(format!("invalid upstream status code: {error}"))
            })?;

        let mut headers = Vec::new();
        let mut content_length = None;
        let mut chunked = false;
        let mut body_allowed =
            !matches!(status_code, 204 | 304) && !(100..200).contains(&status_code);

        for header_line in lines {
            if header_line.is_empty() {
                continue;
            }

            let Some((name, value)) = header_line.split_once(':') else {
                continue;
            };

            let name = name.trim();
            let value = value.trim();

            if name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()) {
                content_length = Some(value.parse::<usize>().map_err(|error| {
                    ProxyError::Upstream(format!("invalid upstream content-length: {error}"))
                })?);
                continue;
            }

            if name.eq_ignore_ascii_case("transfer-encoding") {
                chunked = value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("chunked"));
                continue;
            }

            if is_hop_by_hop_header(name) {
                continue;
            }

            headers.push((name.to_string(), value.to_string()));
        }

        if status_code == 101 {
            body_allowed = false;
        }

        let body_start = header_end_abs + 4;
        let (body, body_len) = if !body_allowed {
            (Vec::new(), 0)
        } else if chunked {
            decode_chunked_body(&payload[body_start..])?
        } else if let Some(length) = content_length {
            let end = body_start.checked_add(length).ok_or_else(|| {
                ProxyError::Upstream("upstream response body length overflow".to_string())
            })?;
            if end > payload.len() {
                return Err(ProxyError::Upstream(
                    "upstream response body shorter than declared content-length".to_string(),
                ));
            }
            (payload[body_start..end].to_vec(), length)
        } else {
            (
                payload[body_start..].to_vec(),
                payload.len().saturating_sub(body_start),
            )
        };

        let next_offset = body_start + body_len;
        if (100..200).contains(&status_code) && status_code != 101 {
            if next_offset >= payload.len() {
                return Err(ProxyError::Upstream(
                    "upstream returned only an interim response".to_string(),
                ));
            }
            offset = next_offset;
            continue;
        }

        return Ok(NormalizedHttpResponse {
            status_code,
            headers,
            body,
        });
    }
}

fn decode_chunked_body(payload: &[u8]) -> Result<(Vec<u8>, usize), ProxyError> {
    let mut decoded = Vec::new();
    let mut cursor = 0;

    loop {
        let line_end = find_crlf(&payload[cursor..])
            .ok_or_else(|| ProxyError::Upstream("invalid upstream chunk framing".to_string()))?;
        let line = std::str::from_utf8(&payload[cursor..cursor + line_end]).map_err(|error| {
            ProxyError::Upstream(format!("invalid chunk size encoding: {error}"))
        })?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|error| ProxyError::Upstream(format!("invalid chunk size: {error}")))?;
        cursor += line_end + 2;

        if size == 0 {
            loop {
                let trailer_end = find_crlf(&payload[cursor..]).ok_or_else(|| {
                    ProxyError::Upstream("invalid upstream trailer framing".to_string())
                })?;
                cursor += trailer_end + 2;
                if trailer_end == 0 {
                    return Ok((decoded, cursor));
                }
            }
        }

        let chunk_end = cursor
            .checked_add(size)
            .ok_or_else(|| ProxyError::Upstream("upstream chunk length overflow".to_string()))?;
        if chunk_end + 2 > payload.len() {
            return Err(ProxyError::Upstream(
                "upstream chunk shorter than declared size".to_string(),
            ));
        }

        decoded.extend_from_slice(&payload[cursor..chunk_end]);
        if &payload[chunk_end..chunk_end + 2] != b"\r\n" {
            return Err(ProxyError::Upstream(
                "invalid upstream chunk terminator".to_string(),
            ));
        }
        cursor = chunk_end + 2;
    }
}

fn find_header_end(payload: &[u8]) -> Option<usize> {
    payload.windows(4).position(|window| window == b"\r\n\r\n")
}

fn find_crlf(payload: &[u8]) -> Option<usize> {
    payload.windows(2).position(|window| window == b"\r\n")
}

fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "expect"
    )
}

#[cfg(test)]
mod tests {
    use axum::body::{to_bytes, Body};
    use axum::http::header::CONTENT_LENGTH;
    use axum::http::{Request, Version};

    use super::{
        build_rate_limit_store, check_protocol_version, encode_http_request, parse_http_response,
        PROTOCOL_VERSION,
    };

    #[test]
    fn test_legacy_client_accepted() {
        let result = check_protocol_version(None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_current_version_accepted() {
        let result = check_protocol_version(Some(PROTOCOL_VERSION));
        assert!(result.is_ok());
    }

    #[test]
    fn test_future_version_rejected() {
        let result = check_protocol_version(Some(999));
        assert!(result.is_err());
        let error = result.err().unwrap_or_default();
        assert!(error.contains("not supported"));
    }

    #[tokio::test]
    async fn optional_redis_without_url_returns_none() {
        let store = build_rate_limit_store(None, false)
            .await
            .expect("optional redis should not fail");
        assert!(store.is_none());
    }

    #[tokio::test]
    async fn required_redis_without_url_returns_error() {
        let err = match build_rate_limit_store(None, true).await {
            Ok(_) => panic!("required redis should fail without url"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("redis_url"));
    }

    #[tokio::test]
    async fn required_redis_connection_failure_returns_error() {
        let err = match build_rate_limit_store(Some("redis://127.0.0.1:1/"), true).await {
            Ok(_) => panic!("required redis should fail on connection error"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("required Redis state store"));
    }

    #[tokio::test]
    async fn encode_http_request_normalizes_localhop_framing() {
        let request = Request::builder()
            .method("POST")
            .uri("/login?next=%2Fdemo")
            .version(Version::HTTP_2)
            .header("Host", "chat.pike.life")
            .header("Transfer-Encoding", "chunked")
            .header("Expect", "100-continue")
            .body(Body::from("password=admin123"))
            .expect("request should build");

        let encoded = encode_http_request(request)
            .await
            .expect("request should encode");
        let encoded = String::from_utf8(encoded).expect("request bytes should be utf-8");
        let encoded_lower = encoded.to_ascii_lowercase();

        assert!(encoded.starts_with("POST /login?next=%2Fdemo HTTP/1.1\r\n"));
        assert!(encoded_lower.contains("host: chat.pike.life\r\n"));
        assert!(encoded_lower.contains("content-length: 17\r\n"));
        assert!(encoded_lower.contains("connection: close\r\n"));
        assert!(!encoded.contains("Transfer-Encoding:"));
        assert!(!encoded.contains("Expect:"));
        assert!(!encoded.contains("HTTP/2.0"));
    }

    #[tokio::test]
    async fn parse_http_response_skips_interim_responses() {
        let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 302 Found\r\nLocation: /demo\r\nContent-Length: 0\r\n\r\n";
        let response = parse_http_response(raw).expect("response should parse");

        assert_eq!(response.status(), 302);
        assert_eq!(
            response
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok()),
            Some("/demo")
        );
    }

    #[tokio::test]
    async fn parse_http_response_dechunks_and_preserves_repeated_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n5\r\nhello\r\n0\r\nTrailer-One: ignored\r\n\r\n";
        let response = parse_http_response(raw).expect("response should parse");
        let header_count = response.headers().get_all("set-cookie").iter().count();
        let content_length = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let has_transfer_encoding = response.headers().get("transfer-encoding").is_some();
        let has_connection = response.headers().get("connection").is_some();
        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("body should read");

        assert_eq!(&body[..], b"hello");
        assert_eq!(header_count, 2);
        assert!(!has_transfer_encoding);
        assert!(!has_connection);
        assert_eq!(content_length.as_deref(), Some("5"));
    }
}
