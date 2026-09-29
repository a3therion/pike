use super::pool::{OriginPool, PoolUnavailable};
use http_body_util::BodyExt;
use pike_core::http_response::ResponseDecoder;
use pike_core::{
    byte_stream,
    http_wire::{HttpFrame, IncomingBody, Writer, DATA_CHUNK_BYTES},
    proto::StreamMode,
};
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use pike_core::quic::client::{LocalData, PikeConnection, ServerData};
use pike_core::types::{TunnelConfig, TunnelId};
use pike_core::websocket::MAX_PAYLOAD_SIZE;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

use crate::inspector::storage::RequestStore;

const LOCAL_UPSTREAM_IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_INFLIGHT_HTTP_REQUESTS: usize = 32;
const MAX_UPGRADE_HEADER_SIZE: usize = 16 * 1024;
const STREAM_ENQUEUE_TIMEOUT: Duration = Duration::from_secs(5);

struct WebSocketRelay {
    input: RelayInput,
    cancel: watch::Sender<bool>,
}

enum RelayInput {
    Http(mpsc::Sender<ServerData>),
    WebSocket {
        first: ServerData,
        input: Box<byte_stream::Ingress<LocalData>>,
    },
}

pub struct HttpTunnel {
    config: TunnelConfig,
    origin: OriginPool,
    subdomain: Option<String>,
    connection: PikeConnection,
    tunnel_id: Option<TunnelId>,
    request_store: Option<Arc<RequestStore>>,
    ws_relays: HashMap<u64, WebSocketRelay>,
}

impl HttpTunnel {
    pub fn new(
        config: TunnelConfig,
        origin: impl Into<OriginPool>,
        subdomain: Option<String>,
        connection: PikeConnection,
        request_store: Option<Arc<RequestStore>>,
    ) -> Self {
        Self {
            config,
            origin: origin.into(),
            subdomain,
            connection,
            tunnel_id: None,
            request_store,
            ws_relays: HashMap::new(),
        }
    }

    pub async fn register(&mut self) -> Result<String> {
        let (tunnel_id, registration_rx) = self
            .connection
            .request_tunnel_registration(self.config.clone())
            .await?;
        self.tunnel_id = Some(tunnel_id);

        info!(
            tunnel_id = %tunnel_id,
            local_addr = %self.origin.display(),
            "HTTP tunnel registration requested (waiting for server confirmation)"
        );

        let registration = match timeout(Duration::from_secs(10), registration_rx).await {
            Ok(Ok(registration)) => registration,
            Ok(Err(_)) => bail!("registration confirmation channel closed"),
            Err(_) => bail!("registration timed out after 10s"),
        };

        let health_pool = self.origin.clone();
        self.connection
            .set_origin_health_source(
                tunnel_id,
                pike_core::proto::origin_health::OriginHealthSource::new(move || {
                    health_pool.health_report()
                }),
            )
            .await?;
        Ok(registration.public_url)
    }

    /// Own the upgrade and both directions; every exit seals one terminal frame.
    async fn relay_websocket(
        origin: impl Into<OriginPool>,
        stream_id: u64,
        stream: byte_stream::Stream<LocalData>,
        mut cancelled: watch::Receiver<bool>,
    ) {
        let origin = origin.into();
        let (writer, mut incoming) = stream.into_parts();
        let result = tokio::select! {
            biased;
            _ = cancelled.changed() => Err(anyhow!("WebSocket relay cancelled")),
            result = Self::forward_websocket(&origin, &mut incoming, &writer) => result,
        };
        if let Err(error) = result {
            warn!(stream_id, %error, "WebSocket relay ended");
        }
        let _ = timeout(STREAM_ENQUEUE_TIMEOUT, writer.send(HttpFrame::End, true)).await;
    }

    async fn forward_websocket(
        origin: &OriginPool,
        incoming: &mut IncomingBody,
        writer: &Writer<LocalData>,
    ) -> Result<()> {
        let (tcp, client_frames, server_frames) = timeout(LOCAL_UPSTREAM_IO_TIMEOUT, async {
            let mut request = Vec::new();
            let header_end = loop {
                let bytes = next_ws_bytes(incoming).await?
                    .ok_or_else(|| anyhow!("peer closed before WebSocket upgrade"))?;
                request.extend_from_slice(&bytes);
                if let Some(end) = find_header_end(&request) {
                    if end + 4 > MAX_UPGRADE_HEADER_SIZE { bail!("WebSocket upgrade request headers too large"); }
                    break end + 4;
                }
                if request.len() > MAX_UPGRADE_HEADER_SIZE { bail!("WebSocket upgrade request headers too large"); }
            };
            let mut client_frames = request.split_off(header_end);
            let (_, mut tcp, _) = match origin.connect(true).await {
                Ok(connection) => connection,
                Err(error) if error.is::<PoolUnavailable>() => {
                    send_ws_bytes(writer, b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nRetry-After: 1\r\n\r\n").await?;
                    return Err(error);
                },
                Err(error) => return Err(error),
            };
            tcp.write_all(&request).await?;
            let mut response = Vec::new();
            let mut buffer = [0_u8; 4096];
            let response_end = loop {
                tokio::select! {
                    read = tcp.read(&mut buffer) => {
                        let read = read?;
                        if read == 0 { bail!("upstream closed during WebSocket upgrade"); }
                        response.extend_from_slice(&buffer[..read]);
                        if let Some(end) = find_header_end(&response) {
                            if end + 4 > MAX_UPGRADE_HEADER_SIZE { bail!("WebSocket upgrade response headers too large"); }
                            break end + 4;
                        }
                        if response.len() > MAX_UPGRADE_HEADER_SIZE { bail!("WebSocket upgrade response headers too large"); }
                    }
                    next = next_ws_bytes(incoming) => {
                        let next = next?.ok_or_else(|| anyhow!("peer closed during WebSocket upgrade"))?;
                        if client_frames.len().saturating_add(next.len()) > MAX_PAYLOAD_SIZE {
                            bail!("early WebSocket frames exceed payload limit");
                        }
                        client_frames.extend_from_slice(&next);
                    }
                }
            };
            // Preserve the origin's rejection, subprotocols and extensions.
            send_ws_bytes(writer, &response[..response_end]).await?;
            let head = pike_core::http_response::parse_head(&response[..response_end - 4])?;
            if head.status != 101 {
                let mut decoder = ResponseDecoder::new(false);
                decoder.feed(&response, false)?;
                send_ws_bytes(writer, &response[response_end..]).await?;
                let mut chunk = vec![0; DATA_CHUNK_BYTES];
                while !decoder.is_done() {
                    let count = tcp.read(&mut chunk).await?;
                    decoder.feed(&chunk[..count], count == 0)?;
                    send_ws_bytes(writer, &chunk[..count]).await?;
                }
                bail!("local upstream rejected WebSocket upgrade with {}", head.status);
            }
            let server_frames = response.split_off(response_end);
            Ok::<_, anyhow::Error>((tcp, client_frames, server_frames))
        }).await.map_err(|_| anyhow!("WebSocket upgrade timed out"))??;

        let (mut read, mut write) = tokio::io::split(tcp);
        let send = async {
            send_ws_bytes(writer, &server_frames).await?;
            let mut buffer = vec![0_u8; DATA_CHUNK_BYTES];
            loop {
                let count = read.read(&mut buffer).await?;
                if count == 0 {
                    return Ok::<(), anyhow::Error>(());
                }
                send_ws_bytes(writer, &buffer[..count]).await?;
            }
        };
        let receive = async {
            timeout(LOCAL_UPSTREAM_IO_TIMEOUT, write.write_all(&client_frames)).await??;
            while let Some(bytes) = next_ws_bytes(incoming).await? {
                timeout(LOCAL_UPSTREAM_IO_TIMEOUT, write.write_all(&bytes)).await??;
            }
            Ok::<(), anyhow::Error>(())
        };
        tokio::select! { result = send => result, result = receive => result }
    }

    pub async fn run(&mut self) -> Result<()> {
        let tunnel_id = self.tunnel_id.unwrap_or(self.config.id);
        let request_limit = Arc::new(Semaphore::new(MAX_INFLIGHT_HTTP_REQUESTS));
        info!(
            local_addr = %self.origin.display(),
            tunnel_id = %tunnel_id,
            "HTTP tunnel running"
        );

        self.origin.refresh().await;
        let mut tasks = JoinSet::new();
        let pool = self.origin.clone();
        tasks.spawn(async move {
            pool.monitor().await;
        });
        loop {
            let msg = tokio::select! {
                _ = tasks.join_next(), if !tasks.is_empty() => continue,
                message = self.connection.data_rx.recv() => match message { Some(message) => message, None => break },
            };
            if msg.tunnel_id != tunnel_id {
                continue;
            }

            // Keep failed relay senders until peer FIN. Late bytes must not
            // reopen a second local connection with the same stream identity.
            if let Some(relay) = self.ws_relays.get_mut(&msg.stream_id) {
                let stream_id = msg.stream_id;
                let fin = msg.fin;
                let accepted = match &mut relay.input {
                    RelayInput::Http(sender) => sender.try_send(msg).is_ok(),
                    RelayInput::WebSocket { first, input } => {
                        validate_ws_message(first, &msg).is_ok()
                            && input.feed(&msg.payload, msg.fin).is_ok()
                    }
                };
                if !accepted {
                    let _ = relay.cancel.send(true);
                }
                if fin {
                    self.ws_relays.remove(&stream_id);
                }
                continue;
            }
            if msg.mode == pike_core::proto::StreamMode::Http {
                let Ok(permit) = request_limit.clone().try_acquire_owned() else {
                    let mut reply = ws_response(
                        &msg,
                        [
                            pike_core::http_wire::HttpFrame::Response {
                                status: 503,
                                headers: vec![],
                            },
                            pike_core::http_wire::HttpFrame::End,
                        ]
                        .iter()
                        .map(pike_core::http_wire::encode)
                        .collect::<Result<Vec<_>>>()?
                        .concat(),
                        true,
                    );
                    reply.mode = pike_core::proto::StreamMode::Http;
                    let _ = self.connection.data_tx.try_send(reply);
                    // Retain a closed route until peer FIN so late body chunks
                    // cannot open another origin or produce a second final reply.
                    if !msg.fin {
                        let (sender, receiver) = mpsc::channel(1);
                        drop(receiver);
                        let (cancel, _) = watch::channel(false);
                        self.ws_relays.insert(
                            msg.stream_id,
                            WebSocketRelay {
                                input: RelayInput::Http(sender),
                                cancel,
                            },
                        );
                    }
                    continue;
                };
                let (sender, receiver) = mpsc::channel(128);
                let (cancel, cancelled) = watch::channel(false);
                self.ws_relays.insert(
                    msg.stream_id,
                    WebSocketRelay {
                        input: RelayInput::Http(sender),
                        cancel: cancel.clone(),
                    },
                );
                let origin = self.origin.clone();
                let output = self.connection.data_tx.clone();
                let store = self.request_store.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _keep_cancel_open = cancel;
                    super::http_stream::relay(origin, store, msg, receiver, output, cancelled)
                        .await;
                });
                continue;
            }
            if msg.streaming && msg.mode == StreamMode::ByteStream {
                let (cancel, cancelled) = watch::channel(false);
                let writer = Writer::new(
                    self.connection.data_tx.clone(),
                    ws_response(&msg, vec![], false),
                );
                let (mut input, stream) = byte_stream::channel(writer);
                let permit = request_limit.clone().try_acquire_owned();
                if input.feed(&msg.payload, msg.fin).is_err() || permit.is_err() {
                    let _ = cancel.send(true);
                }
                if !msg.fin {
                    self.ws_relays.insert(
                        msg.stream_id,
                        WebSocketRelay {
                            input: RelayInput::WebSocket {
                                first: msg.clone(),
                                input: Box::new(input),
                            },
                            cancel: cancel.clone(),
                        },
                    );
                }
                let origin = self.origin.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _keep_cancel_open = cancel;
                    Self::relay_websocket(origin, msg.stream_id, stream, cancelled).await;
                });
                continue;
            }

            // HTTP exchanges and WebSocket upgrades both require bounded framing.
            // Never fall back to buffering an unframed legacy request.
            warn!(
                stream_id = msg.stream_id,
                "unsupported non-streaming HTTP message"
            );
            let _ = self
                .connection
                .data_tx
                .try_send(ws_response(&msg, vec![], true));
        }

        self.ws_relays.clear();
        tasks.shutdown().await;
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.connection.unregister_tunnel(self.config.id).await?;
        self.connection.close().await
    }
}

fn ws_response(first: &ServerData, payload: Vec<u8>, fin: bool) -> LocalData {
    LocalData {
        stream_id: Some(first.stream_id),
        tunnel_id: first.tunnel_id,
        connection_id: first.connection_id,
        source_addr: first.source_addr,
        payload,
        fin,
        streaming: true,
        mode: first.mode,
    }
}

fn validate_ws_message(first: &ServerData, message: &ServerData) -> Result<()> {
    if !message.streaming
        || message.mode != StreamMode::ByteStream
        || message.stream_id != first.stream_id
        || message.tunnel_id != first.tunnel_id
        || message.connection_id != first.connection_id
        || message.source_addr != first.source_addr
    {
        bail!("WebSocket stream identity changed");
    }
    if message.payload.len() > MAX_PAYLOAD_SIZE {
        bail!("WebSocket payload too large");
    }
    Ok(())
}

async fn next_ws_bytes(incoming: &mut IncomingBody) -> Result<Option<axum::body::Bytes>> {
    match incoming.frame().await {
        Some(frame) => Ok(Some(
            frame?
                .into_data()
                .map_err(|_| anyhow!("unexpected WebSocket trailers"))?,
        )),
        None => Ok(None),
    }
}

async fn send_ws_bytes(writer: &Writer<LocalData>, bytes: &[u8]) -> Result<()> {
    for chunk in bytes.chunks(DATA_CHUNK_BYTES) {
        timeout(
            STREAM_ENQUEUE_TIMEOUT,
            writer.send(HttpFrame::Data(chunk.to_vec()), false),
        )
        .await??;
    }
    Ok(())
}

fn find_header_end(payload: &[u8]) -> Option<usize> {
    payload.windows(4).position(|window| window == b"\r\n\r\n")
}

fn is_hop_by_hop_header(name: &str) -> bool {
    pike_core::http_response::is_hop_by_hop(name)
}

#[cfg(test)]
mod tests {
    use super::{HttpTunnel, MAX_UPGRADE_HEADER_SIZE};
    use crate::tunnel::origin::{Origin, OriginOptions};
    use futures::{SinkExt, StreamExt};
    use pike_core::quic::client::{LocalData, PikeConnection, ServerData};
    use pike_core::types::{TunnelConfig, TunnelId, TunnelType};
    use pike_core::websocket::MAX_PAYLOAD_SIZE;
    use pike_core::{
        http_wire::{encode, Decoder, HttpFrame, DATA_CHUNK_BYTES},
        proto::StreamMode,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration};

    async fn read_request_headers(socket: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let read = socket.read(&mut buf).await.expect("read request");
            assert!(read > 0, "client closed before request completed");
            request.extend_from_slice(&buf[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                return request;
            }
        }
    }

    #[tokio::test]
    async fn handle_payload_keeps_write_half_open_until_response_arrives() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let port = listener.local_addr().expect("listener addr").port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept connection");
            let _request = read_request_headers(&mut socket).await;

            let mut probe = [0u8; 1];
            match timeout(Duration::from_millis(100), socket.read(&mut probe)).await {
                Ok(Ok(0)) => {
                    // Simulate frameworks like Next.js dev that treat early EOF as an aborted request.
                    return;
                }
                Ok(Ok(_)) => panic!("unexpected extra request bytes"),
                Ok(Err(error)) => panic!("probe read failed: {error}"),
                Err(_) => {}
            }

            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .expect("write response");
        });

        let (response, _) = typed_http_exchange(port).await;
        server.await.expect("server task");
        assert_eq!(response, b"ok");
    }
    const UPGRADE: &[u8] = b"GET /socket HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";

    fn opening() -> ServerData {
        ServerData {
            stream_id: 4,
            connection_id: 17,
            tunnel_id: TunnelId::new(),
            source_addr: "127.0.0.1:1234".parse().unwrap(),
            payload: vec![],
            fin: false,
            streaming: true,
            mode: StreamMode::ByteStream,
        }
    }

    // Exercise the real dispatcher and wire framing; assertions below inspect
    // application bytes while this peer handles transport credits and End.
    struct PeerInput(mpsc::Sender<ServerData>);
    impl PeerInput {
        async fn send(&self, mut data: ServerData) -> anyhow::Result<()> {
            if data.mode == StreamMode::ByteStream {
                let mut framed = vec![];
                for bytes in data.payload.chunks(DATA_CHUNK_BYTES) {
                    framed.extend(encode(&HttpFrame::Data(bytes.to_vec()))?);
                }
                if data.fin {
                    framed.extend(encode(&HttpFrame::End)?);
                }
                data.payload = framed;
            }
            self.0.send(data).await?;
            Ok(())
        }
    }
    struct PeerOutput {
        rx: mpsc::Receiver<LocalData>,
        input: mpsc::WeakSender<ServerData>,
        first: ServerData,
        decoder: Decoder,
    }
    impl PeerOutput {
        fn decode(&mut self, mut data: LocalData) -> Option<LocalData> {
            if data.mode != StreamMode::ByteStream {
                return Some(data);
            }
            let frames = self.decoder.feed(&data.payload, data.fin).unwrap();
            data.payload.clear();
            let mut visible = false;
            for frame in frames {
                match frame {
                    HttpFrame::Data(bytes) => {
                        if let Some(input) = self.input.upgrade() {
                            input
                                .try_send(ServerData {
                                    payload: encode(&HttpFrame::Credit(
                                        bytes.len().max(1024) as u32
                                    ))
                                    .unwrap(),
                                    ..self.first.clone()
                                })
                                .unwrap();
                        }
                        data.payload.extend(bytes);
                        visible = true;
                    }
                    HttpFrame::End => visible = true,
                    HttpFrame::Credit(_) => {}
                    other => panic!("unexpected WebSocket frame {other:?}"),
                }
            }
            visible.then_some(data)
        }
        async fn recv(&mut self) -> Option<LocalData> {
            while let Some(data) = self.rx.recv().await {
                if let Some(data) = self.decode(data) {
                    return Some(data);
                }
            }
            None
        }
        fn try_recv(&mut self) -> Result<LocalData, mpsc::error::TryRecvError> {
            loop {
                let data = self.rx.try_recv()?;
                if let Some(data) = self.decode(data) {
                    return Ok(data);
                }
            }
        }
    }

    fn running_tunnel(
        port: u16,
        first: &ServerData,
    ) -> (tokio::task::JoinHandle<()>, PeerInput, PeerOutput) {
        let (control, _commands) = mpsc::channel(4);
        let (outgoing, output) = mpsc::channel(4);
        let (input, incoming) = mpsc::channel(4);
        let connection = PikeConnection::from_channels(control, outgoing, incoming);
        let config = TunnelConfig {
            cloud: None,
            id: first.tunnel_id,
            tunnel_type: TunnelType::Http {
                local_port: port,
                subdomain: None,
            },
            local_addr: format!("127.0.0.1:{port}").parse().unwrap(),
        };
        let mut tunnel = HttpTunnel::new(
            config,
            Origin::from_options(Some(port), "127.0.0.1", OriginOptions::default()).unwrap(),
            None,
            connection,
            None,
        );
        let task = tokio::spawn(async move {
            tunnel.run().await.unwrap();
        });
        let output = PeerOutput {
            rx: output,
            input: input.downgrade(),
            first: first.clone(),
            decoder: Decoder::default(),
        };
        (task, PeerInput(input), output)
    }

    async fn typed_http_exchange(port: u16) -> (Vec<u8>, usize) {
        use pike_core::http_wire::{encode, Decoder, HttpFrame};
        let first = ServerData {
            payload: [
                encode(&HttpFrame::Request {
                    method: "GET".into(),
                    target: "/".into(),
                    headers: vec![("host".into(), b"local".to_vec())],
                })
                .unwrap(),
                encode(&HttpFrame::End).unwrap(),
            ]
            .concat(),
            mode: pike_core::proto::StreamMode::Http,
            ..opening()
        };
        let (task, input, mut output) = running_tunnel(port, &first);
        input.send(first.clone()).await.unwrap();
        let mut decoder = Decoder::default();
        let mut body = vec![];
        let mut largest = 0;
        let mut status = None;
        loop {
            let response = timeout(Duration::from_secs(10), output.recv())
                .await
                .unwrap()
                .unwrap();
            largest = largest.max(response.payload.len());
            for frame in decoder.feed(&response.payload, response.fin).unwrap() {
                match frame {
                    HttpFrame::Response { status: value, .. } => status = Some(value),
                    HttpFrame::Data(bytes) => {
                        let credit = u32::try_from(bytes.len().max(1024)).unwrap();
                        body.extend(bytes);
                        input
                            .send(ServerData {
                                payload: encode(&HttpFrame::Credit(credit)).unwrap(),
                                ..first.clone()
                            })
                            .await
                            .unwrap();
                    }
                    HttpFrame::End => {}
                    other => panic!("unexpected HTTP frame: {other:?}"),
                }
            }
            if response.fin {
                break;
            }
        }
        assert_eq!(status, Some(200));
        drop(input);
        task.await.unwrap();
        (body, largest)
    }

    #[tokio::test]
    async fn empty_open_and_fragmented_upgrade_reach_real_local_websocket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(tcp).await.unwrap();
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    "ready".into(),
                ))
                .await
                .unwrap();
            let text = socket.next().await.unwrap().unwrap();
            assert_eq!(text.to_text().unwrap(), "hello");
            socket.send(text).await.unwrap();
            let closed = timeout(Duration::from_secs(5), socket.next())
                .await
                .unwrap();
            assert!(
                closed.is_none()
                    || closed
                        .is_some_and(|message| message.is_err() || message.unwrap().is_close())
            );
        });
        let first = opening();
        let (task, input, mut output) = running_tunnel(addr.port(), &first);
        input.send(first.clone()).await.unwrap();
        input
            .send(ServerData {
                payload: UPGRADE[..27].to_vec(),
                ..first.clone()
            })
            .await
            .unwrap();
        let mut remainder = UPGRADE[27..].to_vec();
        // Masked RFC6455 text frame coalesced with the final HTTP header bytes.
        remainder.extend_from_slice(&[
            0x81,
            0x85,
            1,
            2,
            3,
            4,
            b'h' ^ 1,
            b'e' ^ 2,
            b'l' ^ 3,
            b'l' ^ 4,
            b'o' ^ 1,
        ]);
        input
            .send(ServerData {
                payload: remainder,
                ..first.clone()
            })
            .await
            .unwrap();
        let handshake = output.recv().await.unwrap();
        assert!(handshake.payload.starts_with(b"HTTP/1.1 101"));
        assert!(!handshake.fin);
        let mut received = Vec::new();
        while received.len() < 14 {
            let message = timeout(Duration::from_secs(3), output.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(!message.fin);
            received.extend(message.payload);
        }
        assert_eq!(received, b"\x81\x05ready\x81\x05hello");
        input.send(ServerData { fin: true, ..first }).await.unwrap();
        assert!(
            timeout(Duration::from_secs(3), output.recv())
                .await
                .unwrap()
                .unwrap()
                .fin
        );
        drop(input);
        task.await.unwrap();
        assert!(output.recv().await.is_none());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connect_and_header_failures_each_send_exactly_one_fin() {
        for payload in [UPGRADE.to_vec(), vec![b'x'; MAX_UPGRADE_HEADER_SIZE + 1]] {
            let first = ServerData {
                payload,
                ..opening()
            };
            let (task, input, mut output) = running_tunnel(1, &first);
            input.send(first).await.unwrap();
            let final_message = output.recv().await.unwrap();
            assert!(final_message.fin && final_message.payload.is_empty());
            drop(input);
            task.await.unwrap();
            assert!(output.recv().await.is_none());
        }
    }

    #[tokio::test]
    async fn rejected_upgrade_does_not_reopen_on_late_stream_chunks() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first = ServerData {
            payload: UPGRADE.to_vec(),
            ..opening()
        };
        let (task, input, mut output) =
            running_tunnel(listener.local_addr().unwrap().port(), &first);
        input.send(first.clone()).await.unwrap();
        let (mut local, _) = listener.accept().await.unwrap();
        let mut request = vec![0; UPGRADE.len()];
        local.read_exact(&mut request).await.unwrap();
        local
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let handshake = output.recv().await.unwrap();
        assert!(handshake.payload.starts_with(b"HTTP/1.1 403"));
        assert!(!handshake.fin);
        assert!(
            timeout(Duration::from_secs(3), output.recv())
                .await
                .unwrap()
                .unwrap()
                .fin
        );
        input.send(first.clone()).await.unwrap();
        assert!(timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err());
        assert!(
            output.try_recv().is_err(),
            "late chunk must not cause another FIN/relay"
        );
        input
            .send(ServerData {
                fin: true,
                payload: vec![],
                ..first
            })
            .await
            .unwrap();
        drop(input);
        timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn peer_fin_cancels_stalled_upgrade_and_closes_local_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first = ServerData {
            payload: UPGRADE.to_vec(),
            ..opening()
        };
        let (task, input, mut output) =
            running_tunnel(listener.local_addr().unwrap().port(), &first);
        input.send(first.clone()).await.unwrap();
        let (mut local, _) = listener.accept().await.unwrap();
        let mut request = vec![0; UPGRADE.len()];
        local.read_exact(&mut request).await.unwrap();
        input
            .send(ServerData {
                payload: vec![],
                fin: true,
                ..first
            })
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_secs(3), output.recv())
                .await
                .unwrap()
                .unwrap()
                .fin
        );
        assert_eq!(
            timeout(Duration::from_secs(3), local.read(&mut [0]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        drop(input);
        timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn closing_tunnel_run_cancels_owned_websocket_tasks() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first = ServerData {
            payload: UPGRADE.to_vec(),
            ..opening()
        };
        let (task, input, mut output) =
            running_tunnel(listener.local_addr().unwrap().port(), &first);
        input.send(first).await.unwrap();
        let (mut local, _) = listener.accept().await.unwrap();
        let mut request = vec![0; UPGRADE.len()];
        local.read_exact(&mut request).await.unwrap();
        local
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\nready")
            .await
            .unwrap();
        assert!(output
            .recv()
            .await
            .unwrap()
            .payload
            .starts_with(b"HTTP/1.1 101"));
        assert_eq!(
            timeout(Duration::from_secs(3), output.recv())
                .await
                .unwrap()
                .unwrap()
                .payload,
            b"ready"
        );
        drop(input);
        timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(3), local.read(&mut [0]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn response_larger_than_envelope_limit_streams_in_bounded_chunks() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut local, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(local.read(&mut request).await.unwrap() > 0);
            local
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut body = tokio::io::repeat(b'x').take((MAX_PAYLOAD_SIZE + 1) as u64);
            let _ = tokio::io::copy(&mut body, &mut local).await;
        });
        let (body, largest) = typed_http_exchange(port).await;
        assert_eq!(body, vec![b'x'; MAX_PAYLOAD_SIZE + 1]);
        assert!(largest <= 64 * 1024);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn typed_exchange_completes_content_length_response_before_upstream_eof() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let port = listener.local_addr().expect("listener addr").port();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept connection");
            let _request = read_request_headers(&mut socket).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .expect("write response");
            // Keep the connection open: completion must come from framing, not EOF.
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let (body, _) = timeout(Duration::from_secs(3), typed_http_exchange(port))
            .await
            .expect("response should not wait for upstream EOF");
        server.abort();
        let _ = server.await;
        assert_eq!(body, b"ok");
    }
}
