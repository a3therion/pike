#![allow(
    clippy::too_many_lines,
    clippy::unnecessary_option_map_or_else,
    clippy::uninlined_format_args,
    clippy::needless_pass_by_value,
    clippy::ignored_unit_patterns,
    clippy::match_same_arms
)]

mod public_tls;
mod relay_endpoints;
mod relay_http;
mod relay_ingress;
mod relay_session;
mod relay_streams;
mod relay_tcp;
mod relay_udp;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
#[cfg(test)]
use axum::body::Body;
#[cfg(test)]
use axum::http::header::CONTENT_LENGTH;
#[cfg(test)]
use axum::http::Response;
use clap::Parser;
use pike_core::proto::{ALPN_PROTOCOL, MIN_SUPPORTED_VERSION, PROTOCOL_VERSION};
use pike_core::quic::server::PikeTunnelApp;
use pike_server::admin::run_admin_command;
use pike_server::config::{CliArgs, ServerConfig};
use pike_server::connection::{ClientConnection, ConnectionState};
use pike_server::control_plane::ControlPlaneClient;
use pike_server::dashboard_ws::DashboardBroadcaster;
use pike_server::http::run_http_server;
use pike_server::ingest::RequestBuffer;
use pike_server::management::run_management_server;
#[cfg(test)]
use pike_server::proxy::ProxyError;
use pike_server::registry::ClientRegistry;
use pike_server::request_log::RequestLogStore;
use pike_server::router::VhostRouter;
use pike_server::state_store::{
    FallbackStateStore, InMemoryStateStore, RedisStateStore, StateStore,
};
use pike_server::tunnel_metrics::TunnelMetricsStore;
use pike_server::usage_reporter::UsageReporter;
use tokio::sync::{mpsc, watch};
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
use tokio_quiche::ConnectionParams;
use tracing::{info, warn};

/// Initialize Sentry when a non-empty DSN is provided. Returns `None` (a complete no-op)
/// when `dsn` is `None`, so the relay builds and runs identically without `SENTRY_DSN`.
///
/// The `panic` feature installs a panic hook that reports panics; error-level tracing events
/// are captured via the `sentry-tracing` layer wired in [`init_tracing`].
fn init_sentry(dsn: Option<&str>) -> Option<sentry::ClientInitGuard> {
    let dsn = dsn?;
    if dsn.trim().is_empty() {
        return None;
    }
    let guard = sentry::init((
        dsn.to_string(),
        sentry::ClientOptions {
            release: sentry::release_name!(),
            // Report panics and error events; no performance tracing by default (minimal).
            attach_stacktrace: true,
            ..Default::default()
        },
    ));
    Some(guard)
}

/// Build the tracing subscriber. When Sentry is enabled, an additional layer forwards
/// error-level events to Sentry (and lower levels as breadcrumbs) via `sentry-tracing`.
fn init_tracing(sentry_enabled: bool) {
    use tracing_subscriber::prelude::*;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .compact();
    let registry = tracing_subscriber::registry().with(filter).with(fmt_layer);

    if sentry_enabled {
        registry.with(sentry_tracing::layer()).init();
    } else {
        registry.init();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = CliArgs::parse();
    let config = ServerConfig::from_file(&args.config, args.dev_mode)?;

    // Fix #6: initialize Sentry error monitoring ONLY when a DSN is configured. When unset
    // this is a complete no-op — no network, no behavior change — and the guard is None. The
    // guard must outlive the program, so it is bound here and held for all of `main`.
    let sentry_guard = init_sentry(config.sentry_dsn.as_deref());
    init_tracing(sentry_guard.is_some());
    // Held for the lifetime of the process so buffered events flush on shutdown.
    let _sentry_guard = sentry_guard;

    let state_store =
        build_rate_limit_store(config.redis_url.as_deref(), config.require_redis).await?;

    if let Some(command) = args.command {
        let registry = Arc::new(ClientRegistry::with_limits_and_store(
            config.abuse.clone(),
            config.max_connections,
            config.max_tunnels_per_connection,
            state_store.clone(),
        ));
        run_admin_command(command, registry)?;
        return Ok(());
    }

    if config.dev_mode {
        warn!("Running in DEV MODE - no control plane");
    }

    if config.trust_cloudflare {
        // We honor CF-Connecting-IP for per-IP rate limiting / bans. That header is only
        // trustworthy if this relay's public port is firewalled to Cloudflare's edge IP
        // ranges — otherwise an attacker connecting directly can spoof any client IP and
        // defeat per-IP limiting and bans. This is enforced at the network layer (firewall),
        // not in code, so surface it loudly at startup.
        warn!(
            "trust_cloudflare is ENABLED: CF-Connecting-IP is trusted for per-IP limiting. \
             You MUST restrict the relay's inbound port to Cloudflare edge IP ranges at the \
             firewall, or clients can spoof their IP and bypass per-IP rate limits and bans."
        );
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
    let usage_journal = if config.workers_api_url.is_some()
        && config
            .server_token
            .as_ref()
            .is_some_and(|token| !token.trim().is_empty())
    {
        Some(Arc::new(pike_server::usage_journal::UsageJournal::open(
            &config.usage_journal_path,
            config.workers_api_url.as_deref().unwrap_or_default(),
        )?))
    } else {
        None
    };
    let quota = if config.dev_mode {
        None
    } else if let Some(journal) = &usage_journal {
        Some(Arc::new(
            pike_server::quota::QuotaManager::new(
                journal.clone(),
                config.workers_api_url.clone().unwrap_or_default(),
                config.server_token.clone().unwrap_or_default(),
            )
            .await?,
        ))
    } else {
        None
    };
    let tunnel_metrics_store = Arc::new(
        TunnelMetricsStore::with_state_store(state_store)
            .with_usage_journal(usage_journal.clone())
            .with_quota(quota.clone()),
    );

    let server_token_configured = config
        .server_token
        .as_ref()
        .is_some_and(|token| !token.trim().is_empty());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let quota_maintenance = quota
        .as_ref()
        .map(|quota| quota.spawn_maintenance(shutdown_rx.clone()));
    if config.workers_api_url.is_some() && server_token_configured {
        ingest_buffer.spawn_flush_loop();
        let usage_reporter = Arc::new(UsageReporter::new(
            config.workers_api_url.clone().unwrap_or_default(),
            config.server_token.clone().unwrap_or_default(),
            usage_journal.expect("configured cloud reporting has a journal"),
        ));
        usage_reporter.spawn_flush_loop(shutdown_rx.clone());
    }

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
    let manual_certificates = config
        .public_https
        .iter()
        .chain(config.public_tls.iter())
        .flat_map(|listener| listener.certificates.iter().cloned())
        .collect::<Vec<_>>();
    let certificates = pike_server::certificates::Certificates::new(
        manual_certificates,
        config.acme.clone(),
        shutdown_rx.clone(),
    )
    .await?;
    // Cross-relay ingress: hop trust is loaded before any public listener so a
    // misconfigured relay never starts half-way into the topology.
    let hop_tls = match &config.ingress {
        Some(ingress) => Some(pike_server::ingress::HopTls::load(ingress).await?),
        None => None,
    };
    let frontend = match (&config.ingress, &hop_tls) {
        (Some(ingress), Some(tls)) if !ingress.peers.is_empty() => {
            Some(pike_server::ingress::Frontend::spawn(
                ingress,
                config.public_bind_ip,
                tls.client.clone(),
                registry.ingress.clone(),
                shutdown_rx.clone(),
            )?)
        }
        _ => None,
    };
    let (hop_http_tx, hop_http_rx) = mpsc::channel(16);
    let (hop_https_tx, hop_https_rx) = mpsc::channel(16);
    let tls_endpoints = if let Some(tls) = &config.public_tls {
        Some(
            public_tls::TlsEndpoints::bind(
                tls,
                certificates.clone(),
                frontend.clone(),
                shutdown_rx.clone(),
            )
            .await?,
        )
    } else {
        None
    };
    let session_context = relay_session::SessionContext {
        certificates: certificates.clone(),
        tls_endpoints,
        registry: registry.clone(),
        vhost_router: vhost_router.clone(),
        broadcaster: broadcaster.clone(),
        tunnel_metrics_store: tunnel_metrics_store.clone(),
        control_plane,
        tcp_manager: Arc::new(
            pike_server::tcp::TcpTunnelManager::new(Arc::new(
                pike_core::quic::stream_manager::StreamManager::new(),
            ))
            .with_bind_ip(config.public_bind_ip),
        ),
        server_config: config.clone(),
        lifecycle_locks: Arc::default(),
        endpoints: Arc::default(),
        frontend: frontend.clone(),
    };
    let owner_loop = match (&config.ingress, &hop_tls) {
        (Some(ingress), Some(tls)) => ingress.hop_bind_addr.map(|bind| {
            let handles = relay_ingress::OwnerHandles {
                registry: registry.clone(),
                vhost_router: vhost_router.clone(),
                endpoints: session_context.endpoints.clone(),
                tls_endpoints: session_context.tls_endpoints.clone(),
                certificates: session_context.certificates.clone(),
                http: hop_http_tx,
                https: hop_https_tx,
            };
            let server = tls.server.clone();
            let shutdown = shutdown_rx.clone();
            tokio::spawn(async move {
                if let Err(error) = relay_ingress::run_owner(bind, server, handles, shutdown).await
                {
                    warn!(error = %error, "ingress hop listener exited with error");
                }
                info!("ingress hop loop stopped");
            })
        }),
        _ => None,
    };
    let http_ingress = if config.ingress.is_some() {
        Some(pike_server::ingress::HttpIngress {
            frontend: frontend.clone(),
            http: hop_http_rx,
            https: hop_https_rx,
        })
    } else {
        None
    };

    let accept_loop = spawn_accept_loop(session_context.clone(), shutdown_rx.clone()).await?;
    let (ws_accept_tx, ws_accept_rx) = mpsc::channel(16);
    let websocket_loop = spawn_websocket_loop(session_context, ws_accept_rx, shutdown_rx.clone());
    let heartbeat_loop = spawn_half_open_monitor(
        registry.clone(),
        vhost_router.clone(),
        config.clone(),
        shutdown_rx.clone(),
    );
    let http_loop = spawn_http_loop(
        certificates,
        vhost_router.clone(),
        registry.clone(),
        broadcaster.clone(),
        ingest_buffer.clone(),
        request_log_store,
        tunnel_metrics_store,
        config.clone(),
        shutdown_rx.clone(),
        ws_accept_tx,
        http_ingress,
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
    let _ = websocket_loop.await;
    if let Some(task) = owner_loop {
        let _ = task.await;
    }
    if let Some(task) = quota_maintenance {
        // If the control plane is down, durable seals/pending IDs remain for
        // startup recovery; shutdown must not wait indefinitely on the network.
        let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
    }

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
        return Err("protocol version required; upgrade Pike client to protocol 8".into());
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
    certificates: Arc<pike_server::certificates::Certificates>,
    router: Arc<VhostRouter>,
    registry: Arc<ClientRegistry>,
    broadcaster: Arc<DashboardBroadcaster>,
    ingest_buffer: Arc<RequestBuffer>,
    request_log_store: Arc<RequestLogStore>,
    tunnel_metrics_store: Arc<TunnelMetricsStore>,
    config: ServerConfig,
    shutdown_rx: watch::Receiver<bool>,
    ws_accept_tx: mpsc::Sender<pike_server::websocket::AcceptedWebSocket>,
    ingress: Option<pike_server::ingress::HttpIngress>,
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
            config.max_request_body_bytes,
            config.domain.clone(),
            config.trusted_http_proxies.clone(),
            config.trust_cloudflare,
            config.public_https.clone(),
            certificates,
            shutdown_rx,
            Some(ws_accept_tx),
            ingress,
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
    session_context: relay_session::SessionContext,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<tokio::task::JoinHandle<()>> {
    let registry = session_context.registry.clone();
    let config = session_context.server_config.clone();
    let socket = tokio::net::UdpSocket::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind QUIC socket on {}", config.bind_addr))?;
    let local_addr = socket
        .local_addr()
        .context("failed to get QUIC socket local address")?;
    info!(configured = %config.bind_addr, actual = %local_addr, "QUIC socket bound");

    let mut settings = QuicSettings::default();
    settings.alpn = vec![ALPN_PROTOCOL.to_vec()];
    settings.initial_max_data = config.quic_config.max_connection_data;
    settings.initial_max_stream_data_bidi_local = config.quic_config.max_stream_data;
    settings.initial_max_stream_data_bidi_remote = config.quic_config.max_stream_data;
    settings.initial_max_streams_bidi = config.quic_config.max_concurrent_streams;
    settings.initial_max_streams_uni = 0;
    settings.enable_dgram = false;
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

                            // Enforce the connection cap BEFORE spawning any per-connection
                            // tasks; a flood of QUIC connections must not spawn unbounded
                            // sessions. Dropping `conn` without registering closes it, so the
                            // session cleanup path never runs for an unregistered client.
                            if let Err(error) = registry.register_client(client) {
                                warn!(%connection_id, error = %error, "refusing QUIC connection: at max_connections");
                                pike_server::metrics::CONNECTION_LIMIT_REJECTIONS.inc();
                                drop(conn);
                                continue;
                            }

                            let session_context = session_context.clone();
                            let conn_shutdown_rx = shutdown_rx.clone();
                            tokio::spawn(async move {
                                let (data_tx, data_rx) = mpsc::channel(4);
                                let (outbound_tx, outbound_rx) = mpsc::channel(4);
                                let app = PikeTunnelApp::new(data_tx, outbound_rx);
                                conn.start(app);
                                relay_session::run_session(session_context, connection_id, data_rx, outbound_tx, conn_shutdown_rx, "quic").await;
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

fn spawn_websocket_loop(
    context: relay_session::SessionContext,
    mut sockets: mpsc::Receiver<pike_server::websocket::AcceptedWebSocket>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let socket = tokio::select! {
                _ = shutdown.changed() => break,
                socket = sockets.recv() => match socket { Some(socket) => socket, None => break },
            };
            let connection_id = uuid::Uuid::new_v4();
            let mut client = ClientConnection::new(connection_id, Some(socket.peer_addr));
            client.info.transport = "WebSocket";
            if client.transition_to(ConnectionState::Handshaking).is_err() {
                continue;
            }
            // The WebSocket transport shares the same registry and connection cap.
            if let Err(error) = context.registry.register_client(client) {
                warn!(%connection_id, error = %error, "refusing WebSocket connection: at max_connections");
                pike_server::metrics::CONNECTION_LIMIT_REJECTIONS.inc();
                continue;
            }
            let context = context.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                let (data_tx, data_rx) = mpsc::channel(4);
                let (outbound_tx, outbound_rx) = mpsc::channel(4);
                let transport = tokio::spawn(pike_server::websocket::run_transport(
                    socket.socket,
                    socket.login_permit,
                    data_tx,
                    outbound_rx,
                ));
                relay_session::run_session(
                    context,
                    connection_id,
                    data_rx,
                    outbound_tx,
                    shutdown,
                    "websocket",
                )
                .await;
                transport.abort();
                let _ = transport.await;
            });
        }
    })
}

fn spawn_half_open_monitor(
    registry: Arc<ClientRegistry>,
    _vhost_router: Arc<VhostRouter>,
    config: ServerConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let timeout = Duration::from_secs(config.heartbeat_timeout_secs);
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_ok() && *shutdown_rx.borrow() { break; }
                }
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    for attribution in registry.usage_tunnels() {
                        if let Some(finished) = attribution.finished_at {
                            if finished.elapsed() >= Duration::from_secs(60) {
                                registry.forget_finished_usage_tunnel(attribution.runtime_id, finished);
                            }
                        }
                    }
                    for conn_id in registry.mark_dead_connections(timeout) {
                        // The owning session serializes unregister/status updates with reconnects.
                        warn!(connection_id = %conn_id, "Client presumed dead; session will clean up tunnels");
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

#[cfg(test)]
fn parse_http_response(payload: &[u8]) -> Result<Response<Body>, ProxyError> {
    use pike_core::http_response::{Event, ResponseDecoder};
    let mut decoder = ResponseDecoder::new(false);
    let events = decoder
        .feed(payload, true)
        .map_err(|error| ProxyError::Upstream(error.to_string()))?;
    let mut response = Response::builder();
    let mut body = Vec::new();
    for event in events {
        match event {
            Event::Head(head) => {
                response = response.status(head.status);
                for (name, value) in head
                    .end_to_end_headers()
                    .filter(|(name, _)| !name.eq_ignore_ascii_case("content-length"))
                {
                    response = response.header(name, value);
                }
            }
            Event::Body(bytes) => body.extend(bytes),
            Event::End => {}
        }
    }
    response
        .header(CONTENT_LENGTH, body.len())
        .body(Body::from(body))
        .map_err(|error| ProxyError::Upstream(error.to_string()))
}
#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::http::header::CONTENT_LENGTH;

    use super::{
        build_rate_limit_store, check_protocol_version, parse_http_response, PROTOCOL_VERSION,
    };

    #[test]
    fn test_legacy_client_rejected() {
        let result = check_protocol_version(None);
        assert!(result.is_err());
        assert!(check_protocol_version(Some(1)).is_err());
        assert!(check_protocol_version(Some(2)).is_err());
        assert!(check_protocol_version(Some(3)).is_err());
        assert!(check_protocol_version(Some(4)).is_err());
        assert!(check_protocol_version(Some(5)).is_err());
        assert!(check_protocol_version(Some(6)).is_err());
        assert!(check_protocol_version(Some(7)).is_err());
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
        let Err(err) = build_rate_limit_store(None, true).await else {
            panic!("required redis should fail without url");
        };
        assert!(err.to_string().contains("redis_url"));
    }

    #[tokio::test]
    async fn required_redis_connection_failure_returns_error() {
        let Err(err) = build_rate_limit_store(Some("redis://127.0.0.1:1/"), true).await else {
            panic!("required redis should fail on connection error");
        };
        assert!(err.to_string().contains("required Redis state store"));
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

    // Malformed chunked framing from a tunnel client must decode to an error, never a
    // panic. The decoder lives in pike-core; this pins the relay-facing contract.
    #[test]
    fn malformed_chunked_upstream_responses_are_rejected_without_panicking() {
        for raw in [
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nX"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n64\r\nhi",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzzzz\r\ndata\r\n",
        ] {
            assert!(parse_http_response(raw).is_err());
        }
    }
}
