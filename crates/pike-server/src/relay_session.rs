//! Authentication, tunnel ownership and forwarding shared by QUIC and WebSocket.
use super::{check_protocol_version, relay_http, relay_tcp, relay_udp};
use anyhow::{anyhow, bail, Context, Result};
#[cfg(test)]
use axum::body::Body;
use http_body_util::BodyExt;
use pike_core::{
    byte_stream,
    http_wire::{HttpFrame, Writer, DATA_CHUNK_BYTES},
    proto::StreamMode,
};
use pike_core::{
    proto::ControlMessage,
    quic::server::{OutboundData, PikeMessage, PikeOutboundMessage},
    types::{RelayInfo, SubdomainSpec, TunnelConfig, TunnelId, TunnelType},
};
#[cfg(test)]
use pike_server::proxy::HttpRequest;
use pike_server::{
    config::ServerConfig,
    connection::{ConnectionState, ValidatedUser},
    control_plane::{ApiKeyValidation, ControlPlaneClient, EndpointLease},
    dashboard_ws::{DashboardBroadcaster, DashboardEvent},
    proxy::{ProxyError, TunnelRequest, WebSocketRequest},
    registry::ClientRegistry,
    router::{TunnelEntry, VhostRouter},
    tcp::TcpTunnelManager,
    tunnel_metrics::TunnelMetricsStore,
};
use relay_http::PendingHttp;
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
    time::Duration,
};
#[cfg(test)]
use tokio::sync::oneshot;
use tokio::{
    sync::{mpsc, watch, Mutex},
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use tracing::{info, warn};

#[derive(Clone)]
struct WsRelay {
    tunnel_id: TunnelId,
    input: Arc<Mutex<byte_stream::Ingress<PikeOutboundMessage>>>,
    cancel: watch::Sender<bool>,
}

type WsRelays = Arc<Mutex<HashMap<u64, WsRelay>>>;

#[derive(Clone)]
pub struct SessionContext {
    pub endpoints: Arc<super::relay_endpoints::Endpoints>,
    pub certificates: Arc<pike_server::certificates::Certificates>,
    pub registry: Arc<ClientRegistry>,
    pub vhost_router: Arc<VhostRouter>,
    pub broadcaster: Arc<DashboardBroadcaster>,
    pub tunnel_metrics_store: Arc<TunnelMetricsStore>,
    pub control_plane: Arc<ControlPlaneClient>,
    pub tcp_manager: Arc<TcpTunnelManager>,
    pub tls_endpoints: Option<Arc<super::public_tls::TlsEndpoints>>,
    pub server_config: ServerConfig,
    pub lifecycle_locks: Arc<Mutex<HashMap<String, Weak<Mutex<()>>>>>,
    /// Frontend role; local registration yields forwarded ports to it.
    pub frontend: Option<Arc<pike_server::ingress::Frontend>>,
}

impl SessionContext {
    async fn host_guard(&self, host: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.lifecycle_locks.lock().await;
            locks.retain(|_, lock| lock.strong_count() > 0);
            if let Some(lock) = locks.get(host).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(Mutex::new(()));
                locks.insert(host.to_owned(), Arc::downgrade(&lock));
                lock
            }
        };
        lock.lock_owned().await
    }
}

struct Session {
    endpoints: HashMap<TunnelId, Arc<super::relay_endpoints::Endpoint>>,
    context: SessionContext,
    id: uuid::Uuid,
    outbound: mpsc::Sender<PikeOutboundMessage>,
    api_key: Option<String>,
    tunnels: HashMap<TunnelId, String>,
    forwarders: HashMap<TunnelId, JoinHandle<()>>,
    pending_streams: HashMap<TunnelId, super::relay_streams::StreamEndpoint>,
    pending_datagrams: HashMap<TunnelId, relay_udp::Endpoint>,
    lease_reset: bool,
    visitor_gates: HashMap<TunnelId, Arc<pike_server::visitor_policy::VisitorGate>>,
    domain_grants: HashMap<TunnelId, Arc<pike_server::domain_grants::DomainGrants>>,
    certificate_leases: HashMap<TunnelId, Vec<pike_server::certificates::CertificateLease>>,
    health_reporters: HashMap<TunnelId, pike_server::origin_health::HealthReporter>,
    ingress_registrations: HashMap<TunnelId, pike_server::ingress_directory::Registration>,
    pending_http: PendingHttp,
    ws_relays: WsRelays,
    tcp_relays: relay_tcp::TcpRelays,
    udp_relays: relay_udp::Routes,
    udp_budget: Arc<tokio::sync::Semaphore>,
    transport: &'static str,
    cloud_endpoints: HashMap<TunnelId, String>,
    lease_tasks: JoinSet<TunnelId>,
    lease_abort: HashMap<TunnelId, tokio::task::AbortHandle>,
}

pub async fn run_session(
    context: SessionContext,
    connection_id: uuid::Uuid,
    mut inbound: mpsc::Receiver<PikeMessage>,
    outbound: mpsc::Sender<PikeOutboundMessage>,
    mut shutdown: watch::Receiver<bool>,
    transport: &'static str,
) {
    let mut session = Session {
        context,
        id: connection_id,
        outbound,
        api_key: None,
        tunnels: HashMap::new(),
        endpoints: HashMap::new(),
        forwarders: HashMap::new(),
        pending_streams: HashMap::new(),
        pending_datagrams: HashMap::new(),
        lease_reset: false,
        visitor_gates: HashMap::new(),
        domain_grants: HashMap::new(),
        certificate_leases: HashMap::new(),
        health_reporters: HashMap::new(),
        ingress_registrations: HashMap::new(),
        pending_http: Arc::default(),
        ws_relays: Arc::default(),
        tcp_relays: Arc::default(),
        udp_relays: Arc::default(),
        udp_budget: Arc::new(tokio::sync::Semaphore::new(64)),
        transport,
        cloud_endpoints: HashMap::new(),
        lease_tasks: JoinSet::new(),
        lease_abort: HashMap::new(),
    };
    let started = Instant::now();
    let mut last_auth = Instant::now();
    let mut maintenance = tokio::time::interval(Duration::from_secs(1));
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            lease = session.lease_tasks.join_next(), if !session.lease_tasks.is_empty() => {
                if matches!(lease, Some(Ok(_))) {
                    session.lease_reset = true;
                    session.context.registry.allow_lease_reconnect(&connection_id);
                    break;
                }
            },
            _ = maintenance.tick() => {
                session.pending_http.lock().await.retain(|_, (_, tx)| !tx.is_closed());
                if session.api_key.is_none() && started.elapsed() > Duration::from_secs(15) { break; }
                if session.context.registry.clients.get(&connection_id).is_none_or(|client| matches!(client.state, ConnectionState::Closed | ConnectionState::Draining)) { break; }
                if last_auth.elapsed() >= Duration::from_secs(30) {
                    if let Some(key) = session.api_key.clone() {
                        // Revocation/expiry must affect established tunnels as well as new logins.
                        if !session.revalidate(&key).await { break; }
                    }
                    last_auth = Instant::now();
                }
            }
            message = inbound.recv() => {
                let Some(message) = message else { break; };
                if let Err(error) = session.handle(message).await {
                    warn!(%connection_id, %error, "relay session ending");
                    break;
                }
            }
        }
    }
    let tunnels: Vec<_> = session.tunnels.keys().copied().collect();
    for id in tunnels {
        session.unregister(id).await;
    }
    session.pending_http.lock().await.clear();
    session.ws_relays.lock().await.clear();
    session.context.registry.remove_client(&connection_id);
}

impl Session {
    /// Bans, revoked keys and control-plane suspension apply at login, at every
    /// registration and on each revalidation tick.
    fn account_rejection(&self, key: &str, user: &ValidatedUser) -> Option<&'static str> {
        if !self.context.registry.is_api_key_allowed(key) {
            return Some("api key revoked");
        }
        if self
            .context
            .registry
            .abuse_detector
            .is_banned(&user.user_id)
        {
            return Some("user is banned");
        }
        if !user.status.is_active() {
            return Some("account suspended");
        }
        None
    }

    /// Live revocation check for an established connection. Only a definitive
    /// negative ends the session: a control-plane outage must never disconnect
    /// every connected user, so `Unavailable` keeps the session and is logged.
    /// A still-valid user has its plan, limits and status refreshed in place.
    async fn revalidate(&self, key: &str) -> bool {
        let outcome = self
            .context
            .control_plane
            .validate_relay_api_key_status(key, self.context.server_config.server_token.as_deref())
            .await;
        let reason = match outcome {
            ApiKeyValidation::Unavailable(error) => {
                warn!(connection_id = %self.id, %error, "revalidation unavailable; keeping session");
                return true;
            }
            ApiKeyValidation::Invalid(reason) => reason,
            ApiKeyValidation::Valid(user) => {
                if let Some(reason) = self.account_rejection(key, &user) {
                    reason.to_string()
                } else {
                    let _ = self.context.registry.rate_limiter.update_user_plan(
                        &user.user_id,
                        Some(&user.plan),
                        &user.limits,
                    );
                    if let Some(mut client) = self.context.registry.clients.get_mut(&self.id) {
                        client.set_validated_user(*user);
                    }
                    return true;
                }
            }
        };
        warn!(connection_id = %self.id, %reason, "revalidation ended session");
        pike_server::metrics::REVALIDATION_DISCONNECTS.inc();
        false
    }

    async fn control(&self, control: ControlMessage) -> Result<()> {
        tokio::time::timeout(
            Duration::from_secs(5),
            self.outbound.send(PikeOutboundMessage::Control(control)),
        )
        .await
        .map_err(|_| anyhow!("transport stopped reading control messages"))?
        .map_err(|_| anyhow!("transport closed"))
    }

    async fn handle(&mut self, message: PikeMessage) -> Result<()> {
        match message {
            PikeMessage::Control(ControlMessage::Login {
                api_key,
                protocol_version,
                ..
            }) => {
                if self.api_key.is_some() {
                    bail!("already authenticated");
                }
                let result = match check_protocol_version(protocol_version) {
                    Ok(()) => {
                        self.context
                            .control_plane
                            .validate_relay_api_key(
                                &api_key,
                                self.context.server_config.server_token.as_deref(),
                            )
                            .await
                    }
                    Err(reason) => Err(anyhow!(reason)),
                };
                match result {
                    Ok(user) => {
                        if let Some(reason) = self.account_rejection(&api_key, &user) {
                            warn!(connection_id = %self.id, user_id = %user.user_id, reason, "login rejected");
                            self.control(ControlMessage::LoginFailure {
                                reason: "account suspended or banned".into(),
                            })
                            .await?;
                            bail!("authentication failed");
                        }
                        let mut client = self
                            .context
                            .registry
                            .clients
                            .get_mut(&self.id)
                            .ok_or_else(|| anyhow!("connection no longer registered"))?;
                        client.info.api_key = Some(api_key.clone());
                        client.set_validated_user(user);
                        client.transition_to(ConnectionState::Authenticated)?;
                        drop(client);
                        self.api_key = Some(api_key);
                        self.control(ControlMessage::LoginSuccess {
                            session_id: uuid::Uuid::new_v4().to_string(),
                            relay_info: RelayInfo {
                                addr: self.context.server_config.bind_addr,
                                region: "global".into(),
                                version: env!("CARGO_PKG_VERSION").into(),
                            },
                        })
                        .await?;
                    }
                    Err(error) => {
                        self.control(ControlMessage::LoginFailure {
                            reason: error.to_string(),
                        })
                        .await?;
                        bail!("authentication failed");
                    }
                }
            }
            PikeMessage::Control(ControlMessage::RegisterTunnel { config }) => {
                let tunnel_id = config.id;
                match self.register(config).await {
                    Ok((public_url, remote_port)) => {
                        self.control(ControlMessage::TunnelRegistered {
                            tunnel_id,
                            public_url,
                            remote_port,
                        })
                        .await?;
                    }
                    Err(error) => {
                        self.control(ControlMessage::TunnelError {
                            tunnel_id,
                            reason: error.to_string(),
                        })
                        .await?;
                    }
                }
            }
            PikeMessage::Control(ControlMessage::UnregisterTunnel { tunnel_id }) => {
                if self.api_key.is_none() {
                    bail!("authentication required");
                }
                self.unregister(tunnel_id).await;
                self.control(ControlMessage::TunnelUnregistered { tunnel_id })
                    .await?;
            }
            PikeMessage::Control(ControlMessage::OriginHealthResponse {
                tunnel_id,
                nonce,
                report,
            }) => {
                if let Some(reporter) = self.health_reporters.get(&tunnel_id) {
                    reporter.accept(nonce, report)?;
                }
            }
            PikeMessage::Control(ControlMessage::Heartbeat { seq, timestamp }) => {
                if self.api_key.is_none() {
                    bail!("authentication required");
                }
                self.context.registry.heartbeat(&self.id);
                self.control(ControlMessage::HeartbeatAck {
                    seq,
                    timestamp,
                    server_time: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                })
                .await?;
            }
            PikeMessage::Data(data) => {
                if self.api_key.is_none() || !self.tunnels.contains_key(&data.tunnel_id) {
                    bail!("data for unauthorized tunnel");
                }
                if data.mode == pike_core::proto::StreamMode::Datagram {
                    return relay_udp::route(&self.udp_relays, data).await;
                }
                let data = match relay_tcp::route_data(&self.tcp_relays, data).await {
                    Ok(()) => return Ok(()),
                    Err(data) => data,
                };
                let relay = self
                    .ws_relays
                    .lock()
                    .await
                    .get(&data.connection_id)
                    .cloned();
                if let Some(relay) = relay {
                    if relay.tunnel_id != data.tunnel_id {
                        bail!("stream tunnel identity changed");
                    }
                    if !data.streaming
                        || data.mode != StreamMode::ByteStream
                        || relay
                            .input
                            .lock()
                            .await
                            .feed(&data.payload, data.fin)
                            .is_err()
                    {
                        let _ = relay.cancel.send(true);
                    }
                } else {
                    let route = self
                        .pending_http
                        .lock()
                        .await
                        .get(&data.connection_id)
                        .cloned();
                    if let Some((id, sender)) = route {
                        if id != data.tunnel_id {
                            bail!("response tunnel identity changed");
                        }
                        let key = data.connection_id;
                        let fin = data.fin;
                        // Saturation terminates only this response. The dispatcher
                        // never waits for a slow HTTP consumer.
                        if sender.try_send(data).is_err() || fin {
                            self.pending_http.lock().await.remove(&key);
                        }
                    }
                }
            }
            PikeMessage::Control(_) => bail!("unexpected client control message"),
        }
        Ok(())
    }

    async fn register(&mut self, config: TunnelConfig) -> Result<(String, Option<u16>)> {
        let key = self
            .api_key
            .as_deref()
            .ok_or_else(|| anyhow!("authentication required"))?;
        if self.tunnels.contains_key(&config.id) {
            bail!("tunnel already registered");
        }
        // Revalidate at the capability boundary, even on an existing connection.
        let user = self
            .context
            .control_plane
            .validate_relay_api_key(key, self.context.server_config.server_token.as_deref())
            .await?;
        if let Some(reason) = self.account_rejection(key, &user) {
            bail!("{reason}");
        }
        if let Some(mut client) = self.context.registry.clients.get_mut(&self.id) {
            client.set_validated_user(user.clone());
        }
        let (mut name, kind, requested_port) = match &config.tunnel_type {
            TunnelType::Http { subdomain, .. } => {
                let name = subdomain.clone().unwrap_or_else(|| config.id.to_string());
                (SubdomainSpec::new(name.to_lowercase())?.0, "http", None)
            }
            TunnelType::Tls { subdomain, .. } => {
                (SubdomainSpec::new(subdomain.to_lowercase())?.0, "tls", None)
            }
            TunnelType::Udp {
                remote_port,
                idle_timeout_secs,
                ..
            } => {
                anyhow::ensure!(
                    (1..=300).contains(idle_timeout_secs),
                    "UDP idle timeout must be between 1 and 300 seconds"
                );
                anyhow::ensure!(
                    !remote_port.is_some_and(|port| !(10_000..=65_000).contains(&port)),
                    "UDP port must be between 10000 and 65000"
                );
                (config.id.to_string(), "udp", *remote_port)
            }
            TunnelType::Tcp { remote_port, .. } => {
                if remote_port.is_some_and(|port| !(10_000..=65_000).contains(&port)) {
                    bail!("TCP port must be between 10000 and 65000");
                }
                (config.id.to_string(), "tcp", *remote_port)
            }
        };
        if let Some(requested) = config.cloud.as_ref().and_then(|cloud| cloud.name.as_ref()) {
            name = SubdomainSpec::new(requested.to_lowercase())?.0;
        }
        let settings = cloud_settings(&config)?;
        let remote = !self.context.server_config.dev_mode
            && self
                .context
                .server_config
                .workers_api_url
                .as_ref()
                .is_some_and(|url| !url.trim().is_empty());
        if remote {
            anyhow::ensure!(
                self.context
                    .server_config
                    .server_token
                    .as_ref()
                    .is_some_and(|token| !token.is_empty()),
                "Hosted endpoint registration requires server_token"
            );
        }
        let host = format!("{name}.{}", self.context.server_config.domain);
        if self.tunnels.values().any(|registered| registered == &host) {
            bail!("host already registered on this connection");
        }
        let _lifecycle = self.context.host_guard(&host).await;
        let shared = self.context.endpoints.get(&host).await;
        if shared.is_none()
            && (self.context.registry.lookup_tunnel(&host).is_some()
                || self.context.vhost_router.route(&host).is_some())
        {
            bail!("hostname is still registered; retry after its session disconnects");
        }
        // A public port number is a global identity only when the cloud profile
        // reserves it. Peer snapshots cannot prove ownership, so a standalone
        // relay in the cross-relay topology refuses port profiles outright
        // rather than binding a number another relay may also claim.
        let port_profile = matches!(kind, "tcp" | "udp");
        if port_profile && !remote && self.context.server_config.ingress.is_some() {
            bail!(
                "public TCP/UDP ports in the cross-relay topology require the cloud port reservation; a standalone relay cannot prove port ownership across relays"
            );
        }
        let cloud_tunnel = self
            .context
            .control_plane
            .register_tunnel(key, &name, kind, &settings)
            .await?;
        let real_cloud_identity = !self.context.server_config.dev_mode
            && self
                .context
                .server_config
                .workers_api_url
                .as_ref()
                .is_some_and(|url| !url.trim().is_empty());
        let public_id = if real_cloud_identity {
            cloud_tunnel.id.clone()
        } else {
            config.id.to_string()
        };
        if let Some(endpoint) = &shared {
            endpoint.validate(&user.user_id, &public_id, config.id, kind, &settings)?;
        }
        // Authoritative reservation before any local bind or forwarder
        // withdrawal: every relay and connector of the profile receives the same
        // number, and an explicit request must agree with it.
        let bind_port = if port_profile && remote && shared.is_none() {
            let token = self
                .context
                .server_config
                .server_token
                .as_deref()
                .expect("validated server token");
            Some(
                self.context
                    .control_plane
                    .reserve_public_port(key, token, &public_id, requested_port)
                    .await?,
            )
        } else {
            requested_port
        };
        let public_target = match (&config.tunnel_type, bind_port, remote, &shared) {
            (TunnelType::Tcp { .. }, Some(port), true, None) => {
                Some(pike_server::ingress_directory::Target::port(
                    pike_server::ingress_directory::Protocol::Tcp,
                    port,
                ))
            }
            (TunnelType::Udp { .. }, Some(port), true, None) => {
                Some(pike_server::ingress_directory::Target::port(
                    pike_server::ingress_directory::Protocol::Udp,
                    port,
                ))
            }
            _ => None,
        };
        // Ownership is proven; stop forwarding the port to a peer so this relay
        // can bind it. The hold releases with this registration attempt on every
        // exit path, so a failure cannot leave the peer's port withdrawn.
        let _port_hold = match (&self.context.frontend, &public_target) {
            (Some(frontend), Some(target)) => Some(frontend.hold_port(target).await),
            _ => None,
        };
        if let (TunnelType::Tcp { .. }, Some(port)) = (&config.tunnel_type, bind_port) {
            if shared.is_none() && self.context.tcp_manager.parked_port(config.id) != Some(port) {
                self.context.tcp_manager.check_requested_port(port)?;
            }
        }
        let endpoint_settings = settings.clone();
        let mut endpoint_policy_revision = None;
        let reports_usage = !self.context.server_config.dev_mode
            && self
                .context
                .server_config
                .workers_api_url
                .as_ref()
                .is_some_and(|url| !url.trim().is_empty())
            && self
                .context
                .server_config
                .server_token
                .as_ref()
                .is_some_and(|token| !token.trim().is_empty());
        let policy_kind = if matches!(
            config.tunnel_type,
            TunnelType::Tls {
                mode: pike_core::types::TlsMode::Terminate,
                ..
            }
        ) {
            "tls-terminate"
        } else {
            kind
        };
        let visitor = shared.as_ref().map_or_else(
            || {
                pike_server::visitor_policy::VisitorGate::with_identity(
                    self.context.server_config.visitor_keys.clone(),
                    self.context.server_config.visitor_sessions.clone(),
                    if real_cloud_identity {
                        format!("cloud:{public_id}")
                    } else {
                        format!("standalone:{host}")
                    },
                )
            },
            |endpoint| endpoint.visitor.clone(),
        );
        let operator_domains = if remote {
            None
        } else {
            self.context
                .server_config
                .custom_domains
                .get(&host)
                .map(|assignment| {
                    anyhow::ensure!(
                        assignment.owner_user_id == user.user_id,
                        "custom domains belong to another operator-configured account"
                    );
                    anyhow::ensure!(
                        matches!(kind, "http" | "tls"),
                        "custom domains require HTTP or TLS"
                    );
                    pike_server::domain_grants::DomainGrants::from_operator(
                        &assignment.hostnames,
                        &self.context.server_config.domain,
                    )
                })
                .transpose()?
        };
        if !remote && shared.is_none() {
            visitor.activate(
                self.context
                    .server_config
                    .visitor_policies
                    .get(&host)
                    .cloned()
                    .unwrap_or_default(),
                policy_kind,
            )?;
        }
        let register = ClientRegistry::register_connector;
        if shared.is_none() {
            register(
                &self.context.registry,
                self.id,
                host.clone(),
                config.id,
                public_id.clone(),
                reports_usage,
            )?;
        }
        if let Some(endpoint) = &shared {
            self.endpoints.insert(config.id, endpoint.clone());
        }
        self.context
            .tunnel_metrics_store
            .remember_tunnel(&config.id.to_string(), &user.user_id)
            .await;
        let meter = pike_server::traffic_meter::TrafficMeter::new(
            self.context.registry.clone(),
            config.id,
            user.user_id.clone(),
            public_id.clone(),
            self.context.tunnel_metrics_store.usage_journal().cloned(),
        )
        .with_quota(
            self.context.tunnel_metrics_store.quota().cloned(),
            self.id.to_string(),
        );
        let mut http_route = None;
        let mut stream_sender = None;
        let mut datagram_connector = None;
        let port = if let TunnelType::Udp {
            idle_timeout_secs, ..
        } = config.tunnel_type
        {
            let port = if let Some(endpoint) = &shared {
                endpoint
                    .datagram
                    .as_ref()
                    .context("shared UDP listener missing")?
                    .port
            } else {
                let endpoint = match relay_udp::Endpoint::bind(
                    config.id,
                    self.context.server_config.public_bind_ip,
                    bind_port,
                    Duration::from_secs(u64::from(idle_timeout_secs)),
                    visitor.clone(),
                )
                .await
                {
                    Ok(endpoint) => endpoint,
                    Err(error) => {
                        self.context
                            .registry
                            .unregister_tunnel_if_owner(&host, &self.id);
                        return Err(error);
                    }
                };
                let port = endpoint.port;
                self.pending_datagrams.insert(config.id, endpoint);
                port
            };
            datagram_connector = Some(relay_udp::Connector {
                id: self.id,
                outbound: self.outbound.clone(),
                routes: self.udp_relays.clone(),
                budget: self.udp_budget.clone(),
                meter: meter.clone(),
            });
            Some(port)
        } else if matches!(kind, "tcp" | "tls") {
            let port = if let Some(endpoint) = &shared {
                endpoint
                    .stream
                    .as_ref()
                    .context("shared stream listener missing")?
                    .port
            } else {
                let dispatcher = Arc::new(super::relay_streams::StreamDispatcher::default());
                let prepared = async {
                    if let TunnelType::Tls { mode, .. } = config.tunnel_type {
                        let endpoints = self
                            .context
                            .tls_endpoints
                            .as_ref()
                            .context("public TLS listener is not configured")?;
                        let accepted = endpoints
                            .register(&host, &user.user_id, config.id, mode, visitor.clone())
                            .await?;
                        Ok(super::relay_streams::StreamEndpoint {
                            port: endpoints.address.port(),
                            task: dispatcher.spawn(accepted),
                            dispatcher,
                        })
                    } else {
                        let (sender, accepted) = mpsc::channel(4);
                        let listener = self
                            .context
                            .tcp_manager
                            .create_listener_with_dispatcher(config.id, bind_port, sender)
                            .await?;
                        if let Err(error) = self.context.registry.register_tcp_listener(
                            self.id,
                            config.id,
                            listener.local_addr,
                        ) {
                            self.context.tcp_manager.close_listener(config.id).await;
                            return Err(error);
                        }
                        Ok::<_, anyhow::Error>(super::relay_streams::StreamEndpoint {
                            port: listener.local_addr.port(),
                            task: dispatcher.spawn(accepted),
                            dispatcher,
                        })
                    }
                }
                .await;
                let endpoint = match prepared {
                    Ok(endpoint) => endpoint,
                    Err(error) => {
                        self.context
                            .registry
                            .unregister_tunnel_if_owner(&host, &self.id);
                        return Err(error);
                    }
                };
                let port = endpoint.port;
                self.pending_streams.insert(config.id, endpoint);
                port
            };
            let (sender, accepted) = mpsc::channel(4);
            stream_sender = Some(sender);
            self.forwarders.insert(
                config.id,
                tokio::spawn(relay_tcp::run_listener(
                    config.id,
                    accepted,
                    self.outbound.clone(),
                    self.tcp_relays.clone(),
                    meter.clone(),
                    visitor.clone(),
                )),
            );
            Some(port)
        } else {
            let (tx, rx) = mpsc::channel(4);
            http_route = Some(TunnelEntry {
                tunnel_id: config.id,
                connection_id: self.id,
                stream_tx: tx,
                active: true,
                visitor: visitor.clone(),
                domain: None,
                origin_health: None,
            });
            self.forwarders.insert(
                config.id,
                tokio::spawn(forward_http(
                    rx,
                    self.outbound.clone(),
                    self.pending_http.clone(),
                    self.ws_relays.clone(),
                    self.context.tunnel_metrics_store.clone(),
                )),
            );
            None
        };
        let url = if kind == "tls" {
            format!("tls://{host}:{}", port.expect("TLS listener has a port"))
        } else {
            port.map_or_else(
                || format!("https://{host}"),
                |port| {
                    format!(
                        "{kind}://relay.{}:{port}",
                        self.context.server_config.domain
                    )
                },
            )
        };
        self.visitor_gates.insert(config.id, visitor.clone());
        if let Some(domains) = operator_domains {
            let domains = shared
                .as_ref()
                .and_then(|endpoint| endpoint.domains.clone())
                .unwrap_or(domains);
            self.domain_grants.insert(config.id, domains.clone());
            let registered = if kind == "http" || shared.is_some() {
                Ok(())
            } else {
                self.context
                    .tls_endpoints
                    .as_ref()
                    .expect("registered TLS listener")
                    .register_aliases(&host, &user.user_id, config.id, &domains)
                    .await
            };
            if let Err(error) = registered {
                self.stop_forwarding(config.id).await;
                self.context
                    .registry
                    .unregister_tunnel_if_owner(&host, &self.id);
                return Err(error);
            }
        }
        if remote {
            let token = self
                .context
                .server_config
                .server_token
                .as_deref()
                .expect("validated server token");
            let lease = EndpointLease {
                quota_protocol: pike_server::quota::QUOTA_PROTOCOL,
                policy_protocol: pike_server::visitor_policy::POLICY_PROTOCOL,
                domain_protocol: pike_server::domain_grants::DOMAIN_PROTOCOL,
                tunnel_id: public_id.clone(),
                lease_id: self.id.to_string(),
                endpoint_url: url.clone(),
                remote_port: port,
                transport: self.transport.into(),
                config: settings,
            };
            self.cloud_endpoints.insert(config.id, public_id.clone());
            let acknowledgement = self
                .context
                .control_plane
                .publish_endpoint(key, token, &lease)
                .await;
            let admitted = async {
                let acknowledgement = acknowledgement?;
                let domains = pike_server::domain_grants::DomainGrants::bind(
                    acknowledgement.domains,
                    &self.context.server_config.domain,
                )?;
                let record = acknowledgement.visitor;
                let domains = if let Some(endpoint) = &shared {
                    endpoint.validate_admission(record.revision, &domains)?;
                    endpoint
                        .domains
                        .clone()
                        .expect("validated domain authority")
                } else {
                    domains
                };
                self.domain_grants.insert(config.id, domains.clone());
                if kind == "tls" && shared.is_none() {
                    self.context
                        .tls_endpoints
                        .as_ref()
                        .context("TLS listener missing")?
                        .register_aliases(&host, &user.user_id, config.id, &domains)
                        .await?;
                } else if !matches!(kind, "http" | "tls") {
                    anyhow::ensure!(
                        domains.hosts().next().is_none(),
                        "custom domains require HTTP or TLS"
                    );
                }
                if shared.is_none() {
                    visitor.activate_with_revision(
                        record.policy,
                        policy_kind,
                        Some(record.revision),
                    )?;
                }
                Ok::<_, anyhow::Error>((record.revision, domains))
            }
            .await;
            let (policy_revision, domains) = match admitted {
                Ok(admission) => admission,
                Err(error) => {
                    self.stop_forwarding(config.id).await;
                    self.context
                        .registry
                        .unregister_tunnel_if_owner(&host, &self.id);
                    return Err(error);
                }
            };
            endpoint_policy_revision = Some(policy_revision);
            if kind == "http" {
                self.health_reporters.insert(
                    config.id,
                    pike_server::origin_health::HealthReporter::spawn(
                        pike_server::origin_health::ReportingLease {
                            tunnel_id: config.id,
                            public_id: public_id.clone(),
                            lease_id: lease.lease_id.clone(),
                            api_key: key.to_string(),
                            server_token: token.to_string(),
                            max_probe_age: Duration::from_millis(
                                lease
                                    .config
                                    .get("health_interval")
                                    .and_then(serde_json::Value::as_u64)
                                    .unwrap_or(5)
                                    .saturating_mul(2000)
                                    .saturating_add(
                                        lease
                                            .config
                                            .get("health_timeout_ms")
                                            .and_then(serde_json::Value::as_u64)
                                            .unwrap_or(2000),
                                    )
                                    .max(20_000),
                            ),
                            origin_count: lease
                                .config
                                .get("origins")
                                .and_then(serde_json::Value::as_array)
                                .map_or(1, |origins| origins.len().max(1)),
                        },
                        self.context.control_plane.clone(),
                        self.outbound.clone(),
                        visitor.clone(),
                    ),
                );
            }
            let control = self.context.control_plane.clone();
            let key = key.to_string();
            let token = token.to_string();
            let id = config.id;
            let certificates = self.context.certificates.clone();
            let certificate_host = host.clone();
            let lease_public_id = public_id.clone();
            let handle = self.lease_tasks.spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(25)).await;
                    let mut observations = Vec::new();
                    for hostname in std::iter::once(certificate_host.as_str())
                        .chain(domains.hosts().map(|(host, _)| host))
                    {
                        if let Some(status) = certificates.status(hostname).await {
                            observations.push(status);
                        }
                    }
                    let renewed = control
                        .renew_endpoint(
                            &key,
                            &token,
                            &lease_public_id,
                            &pike_server::control_plane::EndpointRenewal {
                                lease_id: &lease.lease_id,
                                quota_protocol: pike_server::quota::QUOTA_PROTOCOL,
                                policy_protocol: pike_server::visitor_policy::POLICY_PROTOCOL,
                                policy_revision,
                                domain_protocol: pike_server::domain_grants::DOMAIN_PROTOCOL,
                                domain_revision: domains.revision(),
                                certificates: observations,
                            },
                        )
                        .await
                        .and_then(|set| domains.reconcile(&set));
                    if let Err(error) = renewed {
                        warn!(tunnel_id = %id, %error, "endpoint lease renewal ended connector");
                        // One member losing its lease cannot revoke a surviving
                        // member's shared authority. Last-session teardown does.
                        return id;
                    }
                }
            });
            self.lease_abort.insert(config.id, handle);
        }
        if shared.is_some() {
            // A new policy may arrive while an older member is still draining.
            // Validate the authoritative admission before spending reconnect or
            // creation allowance on a join that cannot share that authority.
            if let Err(error) = self.context.registry.register_connector(
                self.id,
                host.clone(),
                config.id,
                public_id.clone(),
                reports_usage,
            ) {
                self.stop_forwarding(config.id).await;
                return Err(error);
            }
        }
        if shared.is_none()
            && ((kind == "http" && self.context.server_config.public_https.is_some())
                || policy_kind == "tls-terminate")
        {
            let admitted = (|| {
                let mut leases = vec![self.context.certificates.authorize(
                    &host,
                    &user.user_id,
                    visitor.clone(),
                    None,
                )?];
                if let Some(domains) = self.domain_grants.get(&config.id) {
                    for (alias, grant) in domains.hosts() {
                        leases.push(self.context.certificates.authorize(
                            alias,
                            &user.user_id,
                            visitor.clone(),
                            Some(grant.clone()),
                        )?);
                    }
                }
                Ok::<_, anyhow::Error>(leases)
            })();
            match admitted {
                Ok(leases) => {
                    self.certificate_leases.insert(config.id, leases);
                }
                Err(error) => {
                    self.stop_forwarding(config.id).await;
                    self.context
                        .registry
                        .unregister_tunnel_if_owner(&host, &self.id);
                    return Err(error);
                }
            }
        }
        if shared.is_none() {
            let endpoint = Arc::new(super::relay_endpoints::Endpoint {
                owner: user.user_id.clone(),
                public_id: public_id.clone(),
                tunnel_id: config.id,
                kind,
                settings: endpoint_settings,
                policy_revision: endpoint_policy_revision,
                visitor: visitor.clone(),
                domains: self.domain_grants.get(&config.id).cloned(),
                certificates: self
                    .certificate_leases
                    .remove(&config.id)
                    .unwrap_or_default(),
                stream: self.pending_streams.remove(&config.id),
                datagram: self.pending_datagrams.remove(&config.id),
            });
            self.context.endpoints.insert(host.clone(), &endpoint).await;
            self.endpoints.insert(config.id, endpoint);
        }
        if let Some(connector) = datagram_connector {
            let endpoint = self
                .endpoints
                .get(&config.id)
                .context("UDP endpoint authority missing")?;
            if let Err(error) = endpoint
                .datagram
                .as_ref()
                .context("UDP listener missing")?
                .add(connector)
            {
                self.stop_forwarding(config.id).await;
                self.context
                    .registry
                    .unregister_tunnel_if_owner(&host, &self.id);
                return Err(error);
            }
        }
        if let Some(sender) = stream_sender {
            let endpoint = self
                .endpoints
                .get(&config.id)
                .context("stream endpoint authority missing")?;
            if let Err(error) = endpoint
                .stream
                .as_ref()
                .context("stream endpoint listener missing")?
                .dispatcher
                .add(self.id, sender)
            {
                self.stop_forwarding(config.id).await;
                self.context
                    .registry
                    .unregister_tunnel_if_owner(&host, &self.id);
                return Err(error);
            }
        }
        if let Some(mut route) = http_route {
            route.origin_health = self
                .health_reporters
                .get(&config.id)
                .map(pike_server::origin_health::HealthReporter::routing);
            let routed = self
                .context
                .vhost_router
                .register_member(&host, route)
                .and_then(|()| {
                    if let Some(domains) = self.domain_grants.get(&config.id) {
                        self.context
                            .vhost_router
                            .register_aliases(&host, &self.id, domains)
                    } else {
                        Ok(())
                    }
                });
            if let Err(error) = routed {
                self.stop_forwarding(config.id).await;
                self.context
                    .registry
                    .unregister_tunnel_if_owner(&host, &self.id);
                return Err(error);
            }
        }
        let endpoint = self
            .endpoints
            .get(&config.id)
            .context("endpoint authority missing")?;
        let advertisement = self.context.registry.ingress.register(
            pike_server::ingress_directory::Claim {
                owner: &user.user_id,
                profile: if real_cloud_identity {
                    &public_id
                } else {
                    &host
                },
                hostname: &host,
                kind,
                port,
                settings: &endpoint.settings,
                https: self.context.server_config.public_https.is_some(),
                // Only a cloud-reserved number is a public identity peers may
                // forward; standalone ports stay relay-local.
                public_port: remote,
            },
            visitor,
            self.domain_grants.get(&config.id).map(Arc::as_ref),
            self.outbound.clone(),
            self.health_reporters
                .get(&config.id)
                .map(pike_server::origin_health::HealthReporter::routing),
        );
        match advertisement {
            Ok(registration) => {
                self.ingress_registrations.insert(config.id, registration);
            }
            Err(error) => {
                self.stop_forwarding(config.id).await;
                self.context
                    .registry
                    .unregister_tunnel_if_owner(&host, &self.id);
                return Err(error);
            }
        }
        // Reconcile a suspension persisted by a previous run or another instance once,
        // here, so the per-request `is_suspended` check stays an in-memory lookup.
        self.context
            .registry
            .abuse_detector
            .refresh_tunnel_suspension(config.id)
            .await;
        self.tunnels.insert(config.id, host.clone());
        self.broadcast(config.id, &host, "connected");
        info!(tunnel_id = %config.id, %url, "tunnel registered");
        Ok((url, port))
    }

    fn broadcast(&self, tunnel_id: TunnelId, host: &str, status: &str) {
        if let Some(user) = self.context.registry.user_id_for_connection(&self.id) {
            if let Ok(json) = serde_json::to_string(&DashboardEvent::TunnelStatus {
                tunnel_id: self.context.registry.public_tunnel_id(tunnel_id),
                subdomain: host.to_string(),
                status: status.to_string(),
            }) {
                self.context.broadcaster.broadcast(&user, &json);
            }
        }
    }

    async fn stop_forwarding(&mut self, id: TunnelId) {
        self.ingress_registrations.remove(&id);
        let shared = self.endpoints.remove(&id);
        let last_member = shared
            .as_ref()
            .is_none_or(|endpoint| Arc::strong_count(endpoint) == 1);
        if let Some(stream) = shared
            .as_ref()
            .and_then(|endpoint| endpoint.stream.as_ref())
        {
            stream.dispatcher.remove(self.id);
        }
        if let Some(datagram) = shared
            .as_ref()
            .and_then(|endpoint| endpoint.datagram.as_ref())
        {
            datagram.remove(self.id);
            if last_member {
                datagram.close().await;
            }
        }
        if let Some(datagram) = self.pending_datagrams.remove(&id) {
            datagram.close().await;
        }
        self.pending_streams.remove(&id);
        self.certificate_leases.remove(&id);
        self.health_reporters.remove(&id);
        self.context
            .vhost_router
            .unregister_tunnel_if_owner(id, &self.id);
        if let Some(domains) = self.domain_grants.remove(&id) {
            if shared.is_none() {
                domains.close();
            }
        }
        if let Some(gate) = self.visitor_gates.remove(&id) {
            if shared.is_none() {
                gate.close();
            }
        }
        if last_member {
            if let Some(tls) = &self.context.tls_endpoints {
                tls.unregister(id).await;
            }
        }
        if let Some(handle) = self.lease_abort.remove(&id) {
            handle.abort();
        }
        if last_member
            && (shared
                .as_ref()
                .is_some_and(|endpoint| endpoint.kind == "tcp")
                || self
                    .context
                    .registry
                    .lookup_tcp_listener(id)
                    .is_some_and(|listener| listener.connection_id == self.id))
        {
            if self.lease_reset {
                self.context.tcp_manager.park_listener(id).await;
            } else {
                self.context.tcp_manager.close_listener(id).await;
            }
            self.context.registry.unregister_tcp_listener(id);
        }
        drop(shared);
        if let Some(task) = self.forwarders.remove(&id) {
            task.abort();
            let _ = task.await;
        }
        relay_tcp::forget_tunnel(&self.tcp_relays, id).await;
        relay_udp::forget(&self.udp_relays, id).await;
        self.pending_http
            .lock()
            .await
            .retain(|_, (tunnel_id, _)| *tunnel_id != id);
        self.ws_relays.lock().await.retain(|_, relay| {
            if relay.tunnel_id == id {
                let _ = relay.cancel.send(true);
                false
            } else {
                true
            }
        });
        if let Some(public_id) = self.cloud_endpoints.remove(&id) {
            if let Some(token) = self.context.server_config.server_token.as_deref() {
                if let Err(error) = self
                    .context
                    .control_plane
                    .release_endpoint(token, &public_id, &self.id.to_string())
                    .await
                {
                    warn!(%error, "cloud lease release failed; it will expire");
                }
            }
        }
    }

    async fn unregister(&mut self, id: TunnelId) {
        let Some(host) = self.tunnels.remove(&id) else {
            return;
        };
        let _lifecycle = self.context.host_guard(&host).await;
        self.context
            .vhost_router
            .unregister_if_owner(&host, &self.id);
        self.stop_forwarding(id).await;
        let owned = self
            .context
            .registry
            .unregister_tunnel_if_owner(&host, &self.id);
        if owned {
            self.broadcast(id, &host, "disconnected");
            self.context.registry.finalize_usage_tunnel(id);
        }
    }
}

fn cloud_settings(config: &TunnelConfig) -> Result<serde_json::Value> {
    if let Some(json) = config
        .cloud
        .as_ref()
        .and_then(|cloud| cloud.settings_json.as_ref())
    {
        anyhow::ensure!(json.len() <= 16_384, "cloud settings exceed 16 KiB");
        let value: serde_json::Value = serde_json::from_str(json)?;
        anyhow::ensure!(value.is_object(), "cloud settings must be an object");
        return Ok(value);
    }
    let mut value = serde_json::json!({"local_host":config.local_addr.ip().to_string(), "local_port":config.local_addr.port()});
    match config.tunnel_type {
        TunnelType::Http { .. } => {}
        TunnelType::Tls { mode, .. } => {
            value["tls_mode"] = serde_json::to_value(mode)?;
        }
        TunnelType::Tcp { remote_port, .. } => {
            value["remote_port"] = serde_json::json!(remote_port);
        }
        TunnelType::Udp {
            remote_port,
            idle_timeout_secs,
            ..
        } => {
            value["remote_port"] = serde_json::json!(remote_port);
            value["idle_timeout_secs"] = serde_json::json!(idle_timeout_secs);
        }
    }
    Ok(value)
}

fn duration_micros_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

async fn forward_http(
    mut requests: mpsc::Receiver<TunnelRequest>,
    outbound: mpsc::Sender<PikeOutboundMessage>,
    pending: PendingHttp,
    relays: WsRelays,
    metrics: Arc<TunnelMetricsStore>,
) {
    let mut streams = JoinSet::new();
    loop {
        let request = tokio::select! {
            _ = streams.join_next(), if !streams.is_empty() => continue,
            request = requests.recv() => match request { Some(request) => request, None => break },
        };
        match request {
            TunnelRequest::Http(request) => {
                if streams.len() >= 32 {
                    let _ = request.response_tx.send(Err(ProxyError::Overloaded));
                    continue;
                }
                let outbound = outbound.clone();
                let pending = pending.clone();
                streams.spawn(async move {
                    relay_http::forward(*request, outbound, pending).await;
                });
            }
            TunnelRequest::WebSocket(request) => {
                if streams.len() >= 32 {
                    continue;
                }
                let WebSocketRequest {
                    stream_header,
                    raw_upgrade_request,
                    mut ws_to_quic_rx,
                    quic_to_ws_tx,
                    ..
                } = request;
                let key = stream_header.connection_id;
                let (cancel, mut cancelled) = watch::channel(false);
                let template = OutboundData {
                    stream_id: None,
                    tunnel_id: stream_header.tunnel_id,
                    connection_id: key,
                    source_addr: stream_header.source_addr,
                    payload: vec![],
                    fin: false,
                    streaming: true,
                    mode: StreamMode::ByteStream,
                };
                let writer = Writer::new(outbound.clone(), PikeOutboundMessage::Data(template));
                let (input, stream) = byte_stream::channel(writer);
                relays.lock().await.insert(
                    key,
                    WsRelay {
                        tunnel_id: stream_header.tunnel_id,
                        input: Arc::new(Mutex::new(input)),
                        cancel: cancel.clone(),
                    },
                );
                let relays = relays.clone();
                let metrics = metrics.clone();
                let tunnel = stream_header.tunnel_id.to_string();
                streams.spawn(async move {
                    let _keep_cancel_open = cancel;
                    let (writer, mut incoming) = stream.into_parts();
                    // WSS observability: raw WebSocket frames are only visible here, on
                    // the browser side of the relay; the tunnel side carries wire frames.
                    // The connection counts as open only once the upstream accepts the
                    // upgrade, and the guard decrements even if this task is aborted.
                    let mut upstream =
                        pike_server::ws_proxy::UpstreamObserver::new(&raw_upgrade_request);
                    let mut connection = None;
                    let send = async {
                        let mut next = Some(raw_upgrade_request);
                        let mut upgrade = true;
                        while let Some(bytes) = next {
                            let started = Instant::now();
                            let frames = pike_server::ws_proxy::websocket_frame_stats(&bytes)
                                .frames
                                .max(1);
                            for chunk in bytes.chunks(DATA_CHUNK_BYTES) {
                                if let Err(error) = tokio::time::timeout(
                                    Duration::from_secs(5),
                                    writer.send(HttpFrame::Data(chunk.to_vec()), false),
                                )
                                .await
                                .map_err(anyhow::Error::from)
                                .and_then(|sent| sent)
                                {
                                    metrics
                                        .record_wss_dropped_frames(
                                            &tunnel,
                                            frames,
                                            "browser_to_tunnel_dispatch_failed",
                                        )
                                        .await;
                                    return Err(error);
                                }
                            }
                            if !upgrade {
                                metrics
                                    .record_wss_inbound_frames(
                                        &tunnel,
                                        frames,
                                        bytes.len() as u64,
                                        duration_micros_u64(started.elapsed()),
                                    )
                                    .await;
                            }
                            upgrade = false;
                            next = ws_to_quic_rx.recv().await;
                        }
                        Ok::<(), anyhow::Error>(())
                    };
                    let receive = async {
                        while let Some(frame) = incoming.frame().await {
                            let bytes = frame?
                                .into_data()
                                .map_err(|_| anyhow!("unexpected WebSocket trailers"))?;
                            let started = Instant::now();
                            let observed = upstream.observe(&bytes);
                            if observed.accepted {
                                connection = Some(metrics.open_wss(&tunnel).await);
                            }
                            if let Err(error) = tokio::time::timeout(
                                Duration::from_secs(5),
                                quic_to_ws_tx.send(bytes.to_vec()),
                            )
                            .await
                            .map_err(anyhow::Error::from)
                            .and_then(|sent| sent.map_err(anyhow::Error::from))
                            {
                                if observed.frames > 0 {
                                    metrics
                                        .record_wss_dropped_frames(
                                            &tunnel,
                                            observed.frames,
                                            "tunnel_to_browser_dispatch_failed",
                                        )
                                        .await;
                                }
                                return Err(error);
                            }
                            if observed.frames > 0 {
                                metrics
                                    .record_wss_outbound_frames(
                                        &tunnel,
                                        observed.frames,
                                        observed.bytes,
                                        duration_micros_u64(started.elapsed()),
                                    )
                                    .await;
                            }
                        }
                        Ok::<(), anyhow::Error>(())
                    };
                    let close_reason = tokio::select! {
                        biased;
                        _ = cancelled.changed() => "cancelled",
                        result = send => if result.is_ok() { "client_closed" } else { "client_dispatch_failed" },
                        result = receive => if result.is_ok() { "tunnel_closed" } else { "tunnel_error" },
                    };
                    // One ordered terminal marker; a slow browser affects only
                    // this stream, never the connection-wide dispatcher.
                    let _ = tokio::time::timeout(
                        Duration::from_secs(5),
                        writer.send(HttpFrame::End, true),
                    )
                    .await;
                    if let Some(connection) = connection {
                        connection.close(close_reason).await;
                    }
                    relays.lock().await.remove(&key);
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pike_core::{
        proto::PROTOCOL_VERSION,
        quic::{config::PikeQuicConfig, stream_manager::StreamManager},
    };
    use pike_server::{
        config::{AbuseConfig, DeploymentTopology, TrafficInspectionConfig},
        connection::ClientConnection,
    };

    fn context() -> SessionContext {
        let config = ServerConfig {
            acme: None,
            custom_domains: HashMap::new(),
            trusted_http_proxies: pike_server::visitor_policy::TrustedProxies::default(),
            visitor_sessions: pike_server::visitor_policy::oidc::Sessions::new(),
            visitor_keys: pike_server::visitor_policy::jwks::KeyStore::new(&[]).unwrap(),
            visitor_policies: HashMap::default(),
            public_tls: None,
            public_https: None,
            ingress: None,
            public_bind_ip: std::net::Ipv4Addr::UNSPECIFIED,
            bind_addr: "127.0.0.1:4433".parse().unwrap(),
            http_bind_addr: "127.0.0.1:8080".parse().unwrap(),
            management_bind_addr: "127.0.0.1:9090".parse().unwrap(),
            internal_token: "fixture".into(),
            quic_config: PikeQuicConfig::default(),
            dev_mode: true,
            control_plane_url: None,
            local_api_keys: Some(vec!["fixture-key".into()]),
            workers_api_url: None,
            usage_journal_path: std::path::PathBuf::from("unused-test-journal.sqlite3"),
            server_token: None,
            redis_url: None,
            require_redis: false,
            heartbeat_timeout_secs: 60,
            shutdown_timeout_secs: 1,
            abuse: AbuseConfig::default(),
            traffic_inspection: TrafficInspectionConfig::default(),
            deployment_topology: DeploymentTopology::SingleNode,
            domain: "fixture.test".into(),
            max_request_body_bytes: pike_server::http::DEFAULT_MAX_BODY_SIZE,
            max_connections: 10,
            max_tunnels_per_connection: 10,
            trust_cloudflare: false,
            sentry_dsn: None,
        };
        SessionContext {
            certificates: pike_server::certificates::Certificates::disabled(),
            registry: Arc::new(ClientRegistry::new()),
            vhost_router: Arc::new(VhostRouter::new()),
            broadcaster: Arc::new(DashboardBroadcaster::new()),
            tunnel_metrics_store: Arc::new(TunnelMetricsStore::new()),
            control_plane: Arc::new(ControlPlaneClient::new(
                reqwest::Client::new(),
                String::new(),
                String::new(),
                true,
                config.local_api_keys.clone(),
            )),
            tls_endpoints: None,
            tcp_manager: Arc::new(TcpTunnelManager::new(Arc::new(StreamManager::new()))),
            server_config: config,
            lifecycle_locks: Arc::default(),
            endpoints: Arc::default(),
            frontend: None,
        }
    }

    fn session(context: SessionContext) -> (Session, mpsc::Receiver<PikeOutboundMessage>) {
        let id = uuid::Uuid::new_v4();
        let mut client = ClientConnection::new(id, Some("127.0.0.1:1234".parse().unwrap()));
        client.transition_to(ConnectionState::Handshaking).unwrap();
        context.registry.register_client(client).unwrap();
        let (outbound, incoming) = mpsc::channel(4);
        (
            Session {
                context,
                id,
                outbound,
                api_key: None,
                tunnels: HashMap::new(),
                endpoints: HashMap::new(),
                forwarders: HashMap::new(),
                pending_streams: HashMap::new(),
                pending_datagrams: HashMap::new(),
                lease_reset: false,
                visitor_gates: HashMap::new(),
                domain_grants: HashMap::new(),
                certificate_leases: HashMap::new(),
                health_reporters: HashMap::new(),
                ingress_registrations: HashMap::new(),
                pending_http: Arc::default(),
                ws_relays: Arc::default(),
                tcp_relays: Arc::default(),
                udp_relays: Arc::default(),
                udp_budget: Arc::new(tokio::sync::Semaphore::new(64)),
                transport: "quic",
                cloud_endpoints: HashMap::new(),
                lease_tasks: JoinSet::new(),
                lease_abort: HashMap::new(),
            },
            incoming,
        )
    }

    async fn login(session: &mut Session) {
        session
            .handle(PikeMessage::Control(ControlMessage::Login {
                api_key: "fixture-key".into(),
                client_version: "fixture".into(),
                protocol_version: Some(PROTOCOL_VERSION),
            }))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn http_members_share_authority_until_last_disconnect_and_reject_changed_settings() {
        let context = context();
        let (mut first, _first_output) = session(context.clone());
        let (mut second, _second_output) = session(context.clone());
        login(&mut first).await;
        login(&mut second).await;
        let config = http_config();
        first.register(config.clone()).await.unwrap();
        let authority = context
            .vhost_router
            .route("fixture.fixture.test")
            .unwrap()
            .visitor;
        let mut changed = config.clone();
        changed.local_addr.set_port(9999);
        assert!(second.register(changed).await.is_err());
        assert!(authority.is_active());
        second.register(config.clone()).await.unwrap();
        assert_eq!(context.registry.active_tunnels(), 1);
        let other = context
            .vhost_router
            .route_for_connection("fixture.fixture.test", &second.id)
            .unwrap();
        assert!(Arc::ptr_eq(&other.visitor, &authority));
        first.unregister(config.id).await;
        assert!(authority.is_active());
        assert_eq!(
            context
                .vhost_router
                .route("fixture.fixture.test")
                .unwrap()
                .connection_id,
            second.id
        );
        first.unregister(config.id).await;
        assert!(authority.is_active());
        second.unregister(config.id).await;
        assert!(!authority.is_active());
        assert!(context.vhost_router.route("fixture.fixture.test").is_none());
        assert_eq!(context.registry.active_tunnels(), 0);
    }

    fn http_config() -> TunnelConfig {
        TunnelConfig {
            cloud: None,
            id: TunnelId::new(),
            tunnel_type: TunnelType::Http {
                local_port: 8080,
                subdomain: Some("fixture".into()),
            },
            local_addr: "127.0.0.1:8080".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn tcp_members_share_the_requested_listener_and_only_the_last_member_closes_it() {
        let context = context();
        let (mut first, _first_output) = session(context.clone());
        let (mut second, mut second_output) = session(context.clone());
        login(&mut first).await;
        login(&mut second).await;
        let mut config = http_config();
        config.tunnel_type = TunnelType::Tcp {
            local_port: 8080,
            remote_port: None,
        };
        let (_, port) = first.register(config.clone()).await.unwrap();
        assert_eq!(second.register(config.clone()).await.unwrap().1, port);
        assert_eq!(context.tcp_manager.active_listeners().len(), 1);
        assert_eq!(context.registry.active_tunnels(), 1);
        let gate = first.endpoints[&config.id].visitor.clone();
        first.unregister(config.id).await;
        context.registry.remove_client(&first.id);
        assert!(gate.is_active());
        assert_eq!(
            context
                .registry
                .lookup_tcp_listener(config.id)
                .unwrap()
                .connection_id,
            second.id
        );
        let socket = tokio::net::TcpStream::connect(("127.0.0.1", port.unwrap()))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(PikeOutboundMessage::Data(open)) = second_output.recv().await {
                    assert_eq!(open.tunnel_id, config.id);
                    assert_eq!(open.mode, StreamMode::ByteStream);
                    break;
                }
            }
        })
        .await
        .unwrap();
        drop(socket);
        second.unregister(config.id).await;
        assert!(!gate.is_active());
        assert!(context.tcp_manager.active_listeners().is_empty());
        assert!(context.registry.lookup_tcp_listener(config.id).is_none());
        assert_eq!(context.registry.active_tunnels(), 0);
    }

    #[tokio::test]
    async fn udp_members_keep_one_listener_and_pinned_peers_until_the_last_member_leaves() {
        async fn opened(output: &mut mpsc::Receiver<PikeOutboundMessage>) -> u64 {
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if let Some(PikeOutboundMessage::Data(data)) = output.recv().await {
                        if data.mode == StreamMode::Datagram && !data.fin {
                            return data.connection_id;
                        }
                    }
                }
            })
            .await
            .unwrap()
        }
        let context = context();
        let (mut first, mut first_output) = session(context.clone());
        let (mut second, mut second_output) = session(context.clone());
        login(&mut first).await;
        login(&mut second).await;
        let config = TunnelConfig {
            cloud: None,
            id: TunnelId::new(),
            local_addr: "127.0.0.1:9000".parse().unwrap(),
            tunnel_type: TunnelType::Udp {
                local_port: 9000,
                remote_port: None,
                idle_timeout_secs: 30,
            },
        };
        let (_, port) = first.register(config.clone()).await.unwrap();
        let (_, same) = second.register(config.clone()).await.unwrap();
        assert_eq!(port, same);
        assert_eq!(context.registry.active_tunnels(), 1);
        let gate = first.endpoints[&config.id].visitor.clone();
        let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = ("127.0.0.1", port.unwrap());
        a.send_to(b"first", target).await.unwrap();
        let _ = opened(&mut first_output).await;
        b.send_to(b"second", target).await.unwrap();
        let pinned = opened(&mut second_output).await;
        assert_eq!(first.udp_relays.lock().await.len(), 1);
        assert_eq!(second.udp_relays.lock().await.len(), 1);
        first.unregister(config.id).await;
        assert!(gate.is_active());
        assert!(first.udp_relays.lock().await.is_empty());
        b.send_to(b"same association", target).await.unwrap();
        assert_eq!(opened(&mut second_output).await, pinned);
        a.send_to(b"new association", target).await.unwrap();
        assert_ne!(opened(&mut second_output).await, pinned);
        second.unregister(config.id).await;
        assert!(!gate.is_active());
        assert!(second.udp_relays.lock().await.is_empty());
        assert_eq!(context.registry.active_tunnels(), 0);
        let _rebound =
            tokio::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port.unwrap()))
                .await
                .unwrap();
        assert_eq!(first.udp_budget.available_permits(), 64);
        assert_eq!(second.udp_budget.available_permits(), 64);
    }

    #[tokio::test]
    async fn registration_requires_auth_and_duplicate_registration_does_not_add_resources() {
        let context = context();
        let (mut session, _incoming) = session(context.clone());
        let tunnel = http_config();
        assert!(session.register(tunnel.clone()).await.is_err());
        assert_eq!(context.registry.active_tunnels(), 0);
        login(&mut session).await;
        session.register(tunnel.clone()).await.unwrap();
        assert!(session.register(tunnel.clone()).await.is_err());
        assert_eq!(context.registry.active_tunnels(), 1);
        assert_eq!(session.forwarders.len(), 1);
        session.unregister(tunnel.id).await;
        assert_eq!(context.registry.active_tunnels(), 0);
        assert!(context.vhost_router.route("fixture.fixture.test").is_none());
        assert!(session.forwarders.is_empty());
    }

    #[tokio::test]
    async fn local_reconnect_with_same_runtime_id_does_not_conflict_with_synthetic_cloud_identity()
    {
        let context = context();
        let tunnel = http_config();
        let (mut old, _old_messages) = session(context.clone());
        login(&mut old).await;
        old.register(tunnel.clone()).await.unwrap();
        old.unregister(tunnel.id).await;
        context.registry.remove_client(&old.id);
        let (mut new, _new_messages) = session(context.clone());
        login(&mut new).await;
        new.register(tunnel.clone()).await.unwrap();
        assert!(context.registry.usage_tunnels().is_empty());
        new.unregister(tunnel.id).await;
    }

    #[tokio::test]
    async fn attribution_failure_rolls_back_runtime_before_listener_activation() {
        use wiremock::{
            matchers::{method, path},
            Mock, MockServer, ResponseTemplate,
        };
        let server = MockServer::start().await;
        let canonical = uuid::Uuid::new_v4().to_string();
        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels"))
            .respond_with(ResponseTemplate::new(201).set_body_json(
                serde_json::json!({"tunnel":{"id":canonical,"subdomain":"fixture"}}),
            ))
            .mount(&server)
            .await;
        let mut context = context();
        context.server_config.dev_mode = false;
        context.server_config.workers_api_url = Some(server.uri());
        context.server_config.server_token = Some("fixture".into());
        context.control_plane = Arc::new(ControlPlaneClient::new(
            reqwest::Client::new(),
            String::new(),
            server.uri(),
            false,
            context.server_config.local_api_keys.clone(),
        ));
        let tunnel = http_config();
        context
            .registry
            .remember_usage_tunnel(
                tunnel.id,
                "different-owner".into(),
                "different-canonical".into(),
            )
            .unwrap();
        let (mut session, _incoming) = session(context.clone());
        login(&mut session).await;
        assert!(session.register(tunnel).await.is_err());
        assert_eq!(context.registry.active_tunnels(), 0);
        assert!(session.forwarders.is_empty());
        assert!(session.tunnels.is_empty());
        assert!(context.vhost_router.route("fixture.fixture.test").is_none());
    }

    #[tokio::test]
    async fn cross_relay_standalone_refuses_port_profiles_before_binding_anything() {
        let mut context = context();
        context.server_config.ingress = Some(pike_server::config::IngressConfig {
            ca_path: "unused".into(),
            cert_path: "unused".into(),
            key_path: "unused".into(),
            hop_bind_addr: Some("127.0.0.1:1".parse().unwrap()),
            peers: vec![],
        });
        let (mut session, _output) = session(context.clone());
        login(&mut session).await;
        for tunnel_type in [
            TunnelType::Tcp {
                local_port: 8080,
                remote_port: None,
            },
            TunnelType::Tcp {
                local_port: 8080,
                remote_port: Some(30000),
            },
            TunnelType::Udp {
                local_port: 9000,
                remote_port: Some(30000),
                idle_timeout_secs: 30,
            },
        ] {
            let mut config = http_config();
            config.tunnel_type = tunnel_type;
            let error = session.register(config).await.unwrap_err();
            assert!(
                error.to_string().contains("cloud port reservation"),
                "{error}"
            );
        }
        assert!(context.tcp_manager.active_listeners().is_empty());
        assert_eq!(context.registry.active_tunnels(), 0);
        assert!(session.tunnels.is_empty());
        // Hostname profiles are unaffected by the port constraint.
        session.register(http_config()).await.unwrap();
        assert_eq!(context.registry.active_tunnels(), 1);
    }

    #[tokio::test]
    async fn hosted_port_profiles_bind_the_reserved_number_and_a_refusal_binds_nothing() {
        use wiremock::{
            matchers::{body_partial_json, method, path},
            Mock, MockServer, ResponseTemplate,
        };
        let reserved = loop {
            let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = probe.local_addr().unwrap().port();
            if (10_000..=65_000).contains(&port) {
                drop(probe);
                break port;
            }
        };
        let server = MockServer::start().await;
        let granted = uuid::Uuid::new_v4().to_string();
        let refused = uuid::Uuid::new_v4().to_string();
        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels"))
            .and(body_partial_json(
                serde_json::json!({"subdomain": "granted"}),
            ))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(
                    serde_json::json!({"tunnel":{"id":granted,"subdomain":"granted"}}),
                ),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels"))
            .and(body_partial_json(
                serde_json::json!({"subdomain": "refused"}),
            ))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(
                    serde_json::json!({"tunnel":{"id":refused,"subdomain":"refused"}}),
                ),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/api/v1/tunnels/{granted}/reserve-port")))
            .and(body_partial_json(
                serde_json::json!({"port_protocol": 1, "requested_port": null}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"port_protocol": 1, "port": reserved})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/api/v1/tunnels/{refused}/reserve-port")))
            .respond_with(ResponseTemplate::new(409).set_body_json(
                serde_json::json!({"error": "Public port is reserved by another tunnel"}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        // The lease carries exactly the reserved number.
        Mock::given(method("POST"))
            .and(path(format!("/api/v1/tunnels/{granted}/connect")))
            .and(body_partial_json(
                serde_json::json!({"remote_port": reserved}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "quota_protocol": 1, "policy_protocol": 4, "domain_protocol": 1,
                "visitor": {"revision": 0, "policy": {}},
                "domains": {"revision": 0, "domains": []}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels/internal/release"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let mut context = context();
        context.server_config.dev_mode = false;
        context.server_config.workers_api_url = Some(server.uri());
        context.server_config.server_token = Some("fixture".into());
        context.control_plane = Arc::new(ControlPlaneClient::new(
            reqwest::Client::new(),
            String::new(),
            server.uri(),
            false,
            context.server_config.local_api_keys.clone(),
        ));
        let (mut session, _output) = session(context.clone());
        login(&mut session).await;
        let mut auto = http_config();
        auto.tunnel_type = TunnelType::Tcp {
            local_port: 8080,
            remote_port: None,
        };
        auto.cloud = Some(pike_core::types::CloudTunnelConfig {
            name: Some("granted".into()),
            settings_json: None,
        });
        let (url, port) = session.register(auto.clone()).await.unwrap();
        assert_eq!(port, Some(reserved));
        assert!(url.ends_with(&format!(":{reserved}")), "{url}");
        assert_eq!(
            context
                .registry
                .lookup_tcp_listener(auto.id)
                .unwrap()
                .local_addr
                .port(),
            reserved
        );
        let mut blocked = http_config();
        blocked.tunnel_type = TunnelType::Tcp {
            local_port: 8080,
            remote_port: None,
        };
        blocked.cloud = Some(pike_core::types::CloudTunnelConfig {
            name: Some("refused".into()),
            settings_json: None,
        });
        let error = session.register(blocked.clone()).await.unwrap_err();
        assert!(
            error.to_string().contains("reserved by another tunnel"),
            "{error}"
        );
        assert_eq!(context.tcp_manager.active_listeners().len(), 1);
        assert!(context.registry.lookup_tcp_listener(blocked.id).is_none());
        session.unregister(auto.id).await;
        assert!(context.tcp_manager.active_listeners().is_empty());
    }

    #[tokio::test]
    async fn occupied_port_retries_do_not_exhaust_creation_allowance() {
        let owner = loop {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            if listener.local_addr().unwrap().port() <= 65_000 {
                break listener;
            }
        };
        let port = owner.local_addr().unwrap().port();
        let context = context();
        let (mut session, _output) = session(context.clone());
        login(&mut session).await;
        let mut config = http_config();
        config.tunnel_type = TunnelType::Tcp {
            local_port: 8080,
            remote_port: Some(port),
        };
        for _ in 0..10 {
            let error = session.register(config.clone()).await.unwrap_err();
            assert!(
                error.to_string().contains("failed to bind TCP listener"),
                "{error}"
            );
            assert_eq!(context.registry.active_tunnels(), 0);
        }
        drop(owner);
        let (_, registered_port) = session.register(config.clone()).await.unwrap();
        assert_eq!(registered_port, Some(port));
        assert_eq!(context.registry.active_tunnels(), 1);
        session.unregister(config.id).await;
        assert_eq!(context.registry.active_tunnels(), 0);
    }

    async fn failed_browser_stream_keeps_other_tunnel_usable(stalled: bool) {
        use pike_core::{proto::StreamHeader, quic::server::InboundData};

        let context = context();
        let (mut session, mut output) = session(context.clone());
        login(&mut session).await;
        assert!(matches!(
            output.recv().await,
            Some(PikeOutboundMessage::Control(
                ControlMessage::LoginSuccess { .. }
            ))
        ));
        let websocket_tunnel = http_config();
        let mut healthy_tunnel = http_config();
        healthy_tunnel.tunnel_type = TunnelType::Http {
            local_port: 8081,
            subdomain: Some("healthy".into()),
        };
        session.register(websocket_tunnel.clone()).await.unwrap();
        session.register(healthy_tunnel.clone()).await.unwrap();
        let (browser_tx, browser_rx) = mpsc::channel(1);
        let (to_browser, mut browser_output) = mpsc::channel(1);
        if stalled {
            to_browser.send(vec![0]).await.unwrap();
        } else {
            browser_output.close();
        }
        let header = StreamHeader {
            tunnel_id: websocket_tunnel.id,
            connection_id: 700,
            source_addr: "127.0.0.1:1234".parse().unwrap(),
            streaming: true,
            mode: StreamMode::ByteStream,
        };
        context
            .vhost_router
            .route("fixture.fixture.test")
            .unwrap()
            .stream_tx
            .send(TunnelRequest::WebSocket(WebSocketRequest {
                stream_header: header.clone(),
                request_id: "websocket".into(),
                raw_upgrade_request: b"GET /socket HTTP/1.1\r\n\r\n".to_vec(),
                ws_to_quic_rx: browser_rx,
                quic_to_ws_tx: to_browser,
            }))
            .await
            .unwrap();
        assert!(
            matches!(output.recv().await, Some(PikeOutboundMessage::Data(data)) if data.connection_id == 700 && !data.fin)
        );

        session
            .handle(PikeMessage::Data(InboundData {
                stream_id: 4,
                tunnel_id: header.tunnel_id,
                connection_id: header.connection_id,
                source_addr: header.source_addr,
                payload: pike_core::http_wire::encode(&HttpFrame::Data(b"browser frame".to_vec()))
                    .unwrap(),
                fin: false,
                streaming: true,
                mode: StreamMode::ByteStream,
            }))
            .await
            .expect("closed or stalled browser must not fail the relay session");
        loop {
            let Some(PikeOutboundMessage::Data(data)) = output.recv().await else {
                panic!("missing terminal frame")
            };
            assert_eq!(data.connection_id, 700);
            if data.fin {
                assert_eq!(
                    data.payload,
                    pike_core::http_wire::encode(&HttpFrame::End).unwrap()
                );
                break;
            }
        }
        browser_tx.closed().await;
        assert!(!session.ws_relays.lock().await.contains_key(&700));

        let (response_tx, response_rx) = oneshot::channel();
        context
            .vhost_router
            .route("healthy.fixture.test")
            .unwrap()
            .stream_tx
            .send(TunnelRequest::Http(Box::new(HttpRequest {
                stream_header: StreamHeader {
                    tunnel_id: healthy_tunnel.id,
                    connection_id: 701,
                    streaming: false,
                    mode: pike_core::proto::StreamMode::Raw,
                    ..header.clone()
                },
                request_id: "healthy".into(),
                websocket: false,
                request: axum::http::Request::builder()
                    .uri("/healthy")
                    .body(Body::empty())
                    .unwrap(),
                response_tx,
            })))
            .await
            .unwrap();
        assert!(
            matches!(output.recv().await, Some(PikeOutboundMessage::Data(data)) if data.connection_id == 701 && data.mode == pike_core::proto::StreamMode::Http)
        );
        session
            .handle(PikeMessage::Data(InboundData {
                stream_id: 8,
                tunnel_id: healthy_tunnel.id,
                connection_id: 701,
                source_addr: header.source_addr,
                payload: [
                    pike_core::http_wire::HttpFrame::Response {
                        status: 200,
                        headers: vec![],
                    },
                    pike_core::http_wire::HttpFrame::Data(b"ok".to_vec()),
                    pike_core::http_wire::HttpFrame::End,
                ]
                .iter()
                .flat_map(|frame| pike_core::http_wire::encode(frame).unwrap())
                .collect(),
                fin: true,
                streaming: true,
                mode: pike_core::proto::StreamMode::Http,
            }))
            .await
            .unwrap();
        assert_eq!(
            response_rx.await.unwrap().unwrap().status(),
            axum::http::StatusCode::OK
        );
        while let Ok(message) = output.try_recv() {
            assert!(
                matches!(message, PikeOutboundMessage::Data(data) if data.connection_id == 701),
                "failed WebSocket must emit only one FIN"
            );
        }
        assert_eq!(context.registry.active_tunnels(), 2);
        session.unregister(websocket_tunnel.id).await;
        session.unregister(healthy_tunnel.id).await;
    }

    #[tokio::test]
    async fn closed_websocket_sender_preserves_session_and_other_http_route() {
        failed_browser_stream_keeps_other_tunnel_usable(false).await;
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_websocket_sender_preserves_session_and_other_http_route() {
        failed_browser_stream_keeps_other_tunnel_usable(true).await;
    }
}
