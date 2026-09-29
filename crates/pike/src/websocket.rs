//! Transport adapter for relays reached over HTTPS/WebSocket when UDP is blocked.
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use futures::{Sink, SinkExt, StreamExt};
use pike_core::{
    proto::{ControlMessage, StreamHeader, PROTOCOL_VERSION},
    quic::client::{ClientCommand, LocalData, PikeConnection, RegistrationResult, ServerData},
    types::TunnelId,
    websocket::{decode, encode, WsMessage, MAX_MESSAGE_SIZE},
};
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio::time::Instant;
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{protocol::WebSocketConfig, Message},
};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(20);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

async fn send_message<S>(sink: &mut S, message: Message) -> Result<()>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    tokio::time::timeout(WRITE_TIMEOUT, sink.send(message))
        .await
        .context("WebSocket write timed out")??;
    Ok(())
}

async fn monitor_heartbeat(mut acknowledgements: watch::Receiver<Instant>) -> Result<()> {
    loop {
        let deadline = *acknowledgements.borrow_and_update() + HEARTBEAT_TIMEOUT;
        tokio::select! {
            biased;
            changed = acknowledgements.changed() => changed.context("heartbeat channel closed")?,
            _ = tokio::time::sleep_until(deadline) => bail!("WebSocket heartbeat acknowledgement timed out"),
        }
    }
}

pub async fn connect(url: &str, api_key: &str) -> Result<PikeConnection> {
    let config = WebSocketConfig {
        max_message_size: Some(MAX_MESSAGE_SIZE),
        max_frame_size: Some(MAX_MESSAGE_SIZE),
        ..WebSocketConfig::default()
    };
    let (mut socket, _) = tokio::time::timeout(
        Duration::from_secs(10),
        connect_async_with_config(url, Some(config), false),
    )
    .await
    .context("WebSocket connection timed out")??;
    send_message(
        &mut socket,
        Message::Binary(encode(&WsMessage::Control(ControlMessage::Login {
            api_key: api_key.to_string(),
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: Some(PROTOCOL_VERSION),
        }))?),
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let message = socket
                .next()
                .await
                .ok_or_else(|| anyhow!("WebSocket closed during login"))??;
            match message {
                Message::Binary(bytes) => match decode(&bytes)? {
                    WsMessage::Control(ControlMessage::LoginSuccess { .. }) => {
                        return Ok::<(), anyhow::Error>(())
                    }
                    WsMessage::Control(ControlMessage::LoginFailure { reason }) => {
                        bail!("{reason}")
                    }
                    _ => bail!("unexpected WebSocket login response"),
                },
                Message::Ping(data) => send_message(&mut socket, Message::Pong(data)).await?,
                Message::Close(_) => bail!("WebSocket login rejected"),
                _ => {}
            }
        }
    })
    .await
    .context("WebSocket login timed out")??;

    let (control_tx, mut control_rx) = mpsc::channel(4);
    let (data_tx, mut data_rx) = mpsc::channel::<LocalData>(4);
    let (server_tx, server_rx) = mpsc::channel(4);
    let registrations = Arc::new(Mutex::new(HashMap::<
        TunnelId,
        oneshot::Sender<RegistrationResult>,
    >::new()));
    let unregistrations = Arc::new(Mutex::new(HashMap::<TunnelId, oneshot::Sender<()>>::new()));
    let health_sources =
        std::sync::Mutex::new(pike_core::proto::origin_health::OriginHealthSources::default());
    let (health_tx, mut health_rx) = mpsc::channel(4);
    let (acknowledged_tx, acknowledged_rx) = watch::channel(Instant::now());
    let last_sent = AtomicU64::new(0);
    tokio::spawn(async move {
        let (mut writer, mut reader) = socket.split();
        let registrations_read = registrations.clone();
        let read = async {
            let mut last_acknowledged = 0;
            while let Some(message) = reader.next().await {
                match message? {
                    Message::Binary(bytes) => match decode(&bytes)? {
                        WsMessage::Control(ControlMessage::TunnelRegistered {
                            tunnel_id,
                            public_url,
                            remote_port,
                        }) => {
                            if let Some(tx) = registrations_read.lock().await.remove(&tunnel_id) {
                                let _ = tx.send(RegistrationResult {
                                    public_url,
                                    remote_port,
                                });
                            }
                        }
                        WsMessage::Control(ControlMessage::TunnelUnregistered { tunnel_id }) => {
                            health_sources.lock().unwrap().remove(tunnel_id);
                            if let Some(completed) = unregistrations.lock().await.remove(&tunnel_id)
                            {
                                let _ = completed.send(());
                            }
                        }
                        WsMessage::Control(ControlMessage::TunnelError { tunnel_id, reason }) => {
                            tracing::warn!(%tunnel_id, %reason, "tunnel registration rejected");
                            registrations_read.lock().await.remove(&tunnel_id);
                        }
                        WsMessage::Control(ControlMessage::LoginFailure { reason }) => {
                            bail!("{reason}")
                        }
                        WsMessage::Control(ControlMessage::HeartbeatAck { seq, .. }) => {
                            if seq > last_acknowledged && seq <= last_sent.load(Ordering::Acquire) {
                                last_acknowledged = seq;
                                acknowledged_tx.send_replace(Instant::now());
                            }
                        }
                        WsMessage::Control(ControlMessage::OriginHealthRequest {
                            tunnel_id,
                            nonce,
                        }) => {
                            if let Some(report) = health_sources.lock().unwrap().snapshot(tunnel_id)
                            {
                                let _ = health_tx.try_send(ControlMessage::OriginHealthResponse {
                                    tunnel_id,
                                    nonce,
                                    report,
                                });
                            }
                        }
                        WsMessage::Control(_) => {}
                        WsMessage::Data {
                            stream_id,
                            header,
                            payload,
                            fin,
                        } => {
                            server_tx
                                .send(ServerData {
                                    stream_id,
                                    tunnel_id: header.tunnel_id,
                                    connection_id: header.connection_id,
                                    source_addr: header.source_addr,
                                    payload,
                                    fin,
                                    streaming: header.streaming,
                                    mode: header.mode,
                                })
                                .await
                                .map_err(|_| anyhow!("tunnel closed"))?;
                        }
                    },
                    Message::Close(_) => break,
                    Message::Text(_) => bail!("binary tunnel envelopes required"),
                    _ => {}
                }
            }
            Ok::<(), anyhow::Error>(())
        };
        let write = async {
            let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut seq = 0_u64;
            loop {
                let message = tokio::select! {
                    command = control_rx.recv() => match command {
                        Some(ClientCommand::RegisterTunnel { tunnel, result_tx }) => {
                            let mut pending = registrations.lock().await;
                            if pending.len() >= 64 || pending.contains_key(&tunnel.id) { bail!("too many pending registrations"); }
                            pending.insert(tunnel.id, result_tx);
                            WsMessage::Control(ControlMessage::RegisterTunnel { config: tunnel })
                        }
                        Some(ClientCommand::UnregisterTunnel { tunnel_id, completed }) => {
                            let mut pending = unregistrations.lock().await;
                            if pending.len() >= 64 || pending.contains_key(&tunnel_id) { bail!("too many pending unregistrations"); }
                            pending.insert(tunnel_id, completed);
                            WsMessage::Control(ControlMessage::UnregisterTunnel { tunnel_id })
                        }
                        Some(ClientCommand::OriginHealthSource { tunnel_id, source }) => {
                            health_sources.lock().unwrap().insert(tunnel_id, source)?;
                            continue;
                        }
                        Some(ClientCommand::Close) | None => break,
                    },
                    Some(message) = health_rx.recv() => WsMessage::Control(message),
                    data = data_rx.recv() => {
                        let Some(data) = data else { break; };
                        WsMessage::Data { stream_id: data.stream_id.ok_or_else(|| anyhow!("missing relay stream ID"))?, header: StreamHeader { tunnel_id: data.tunnel_id, connection_id: data.connection_id, source_addr: data.source_addr, streaming: data.streaming, mode: data.mode }, payload: data.payload, fin: data.fin }
                    }
                    _ = heartbeat.tick() => {
                        seq = seq.checked_add(1).ok_or_else(|| anyhow!("heartbeat sequence exhausted"))?;
                        last_sent.store(seq, Ordering::Release);
                        WsMessage::Control(ControlMessage::Heartbeat { seq, timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() })
                    }
                };
                send_message(&mut writer, Message::Binary(encode(&message)?)).await?;
            }
            Ok::<(), anyhow::Error>(())
        };
        let result = tokio::select! { result = read => result, result = write => result, result = monitor_heartbeat(acknowledged_rx) => result };
        if let Err(error) = result {
            tracing::warn!(%error, "WebSocket relay connection closed");
        }
    });
    Ok(PikeConnection::from_channels(
        control_tx, data_tx, server_rx,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn missing_heartbeat_ack_closes_even_when_socket_does_not() {
        let (_tx, rx) = watch::channel(Instant::now());
        let error = monitor_heartbeat(rx).await.unwrap_err();
        assert!(error.to_string().contains("acknowledgement timed out"));
    }

    #[tokio::test(start_paused = true)]
    async fn fresh_ack_extends_heartbeat_deadline() {
        let (tx, rx) = watch::channel(Instant::now());
        let task = tokio::spawn(monitor_heartbeat(rx));
        tokio::task::yield_now().await;
        tokio::time::advance(
            HEARTBEAT_TIMEOUT
                .checked_sub(Duration::from_secs(1))
                .unwrap(),
        )
        .await;
        assert!(!task.is_finished());
        tx.send_replace(Instant::now());
        tokio::task::yield_now().await;
        tokio::time::advance(
            HEARTBEAT_TIMEOUT
                .checked_sub(Duration::from_secs(1))
                .unwrap(),
        )
        .await;
        assert!(!task.is_finished());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn blocked_websocket_write_has_a_deadline() {
        let sink = futures::sink::unfold((), |(), _: Message| async {
            std::future::pending::<std::result::Result<(), tokio_tungstenite::tungstenite::Error>>()
                .await
        });
        let error = send_message(&mut Box::pin(sink), Message::Ping(Vec::new()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("write timed out"));
    }
}
