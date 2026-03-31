use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use pike_core::quic::client::{LocalData, PikeClient, PikeConnection, ServerData};
use pike_core::types::{TunnelConfig, TunnelId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::{timeout, Duration};
use tracing::{error, info, warn};

use crate::inspector::storage::{CapturedHeader, CapturedRequest, RequestStore};

const LOCAL_UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const LOCAL_UPSTREAM_IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_INFLIGHT_HTTP_REQUESTS: usize = 32;

pub struct HttpTunnel {
    config: TunnelConfig,
    local_port: u16,
    local_host: String,
    subdomain: Option<String>,
    connection: PikeConnection,
    _client: PikeClient, // Keep client alive to maintain QUIC connection
    tunnel_id: Option<TunnelId>,
    request_store: Option<Arc<RequestStore>>,
    ws_relays: HashMap<u64, mpsc::Sender<Vec<u8>>>,
}

impl HttpTunnel {
    pub fn new(
        config: TunnelConfig,
        port: u16,
        host: String,
        subdomain: Option<String>,
        connection: PikeConnection,
        client: PikeClient,
        request_store: Option<Arc<RequestStore>>,
    ) -> Self {
        Self {
            config,
            local_port: port,
            local_host: host,
            subdomain,
            connection,
            _client: client,
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
            local_addr = %format!("{}:{}", self.local_host, self.local_port),
            "HTTP tunnel registration requested (waiting for server confirmation)"
        );

        let registration = match timeout(Duration::from_secs(10), registration_rx).await {
            Ok(Ok(registration)) => registration,
            Ok(Err(_)) => bail!("registration confirmation channel closed"),
            Err(_) => bail!("registration timed out after 10s"),
        };

        Ok(registration.public_url)
    }

    async fn handle_payload(
        local_host: String,
        local_port: u16,
        request_store: Option<Arc<RequestStore>>,
        request_data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let start = std::time::Instant::now();

        let header_end = request_data
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or_else(|| anyhow!("invalid HTTP request framing"))?;
        let body = &request_data[header_end + 4..];
        let headers_str = std::str::from_utf8(&request_data[..header_end])?;
        let mut lines = headers_str.split("\r\n");
        let request_line_str = lines.next().ok_or_else(|| anyhow!("empty HTTP request"))?;
        let request_line_parts: Vec<&str> = request_line_str.split_whitespace().collect();
        if request_line_parts.len() < 3 {
            return Err(anyhow!("invalid HTTP request line"));
        }

        let method = request_line_parts[0];
        let path = request_line_parts[1];

        // Rebuild the request as normalized HTTP/1.1 bytes for the localhost TCP hop.
        let mut modified_request = Vec::with_capacity(request_data.len() + 256);
        modified_request.extend_from_slice(format!("{method} {path} HTTP/1.1").as_bytes());
        modified_request.extend_from_slice(b"\r\n");

        let mut req_headers = Vec::new();
        let mut forwarded_host: Option<String> = None;
        let mut forwarded_proto: Option<String> = None;
        let mut has_null_origin = false;
        let mut has_host = false;

        for line in lines {
            if line.is_empty() {
                continue;
            }
            let Some((name, value)) = line.split_once(':') else {
                modified_request.extend_from_slice(line.as_bytes());
                modified_request.extend_from_slice(b"\r\n");
                continue;
            };

            let name_trimmed = name.trim();
            let value_trimmed = value.trim();

            // Capture forwarded headers for Origin reconstruction
            if name.eq_ignore_ascii_case("x-forwarded-host") {
                forwarded_host = Some(value_trimmed.to_string());
            }
            if name.eq_ignore_ascii_case("x-forwarded-proto") {
                forwarded_proto = Some(value_trimmed.to_string());
            }

            // Fix Origin: null (Firefox sends this with strict referrer policies)
            if name.eq_ignore_ascii_case("origin") && value_trimmed == "null" {
                has_null_origin = true;
                continue; // Will be replaced below
            }

            if is_hop_by_hop_header(name_trimmed) || name.eq_ignore_ascii_case("content-length") {
                continue;
            }

            if name.eq_ignore_ascii_case("host") {
                has_host = true;
            }

            req_headers.push(CapturedHeader {
                name: name_trimmed.to_string(),
                value: value_trimmed.to_string(),
            });
            modified_request.extend_from_slice(line.as_bytes());
            modified_request.extend_from_slice(b"\r\n");
        }

        if !has_host {
            if let Some(host) = &forwarded_host {
                req_headers.push(CapturedHeader {
                    name: "Host".to_string(),
                    value: host.clone(),
                });
                modified_request.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
            }
        }

        // Add fixed Origin if it was null
        if has_null_origin {
            let origin = if let Some(host) = &forwarded_host {
                let proto = forwarded_proto.as_deref().unwrap_or("https");
                format!("{proto}://{host}")
            } else {
                "null".to_string()
            };
            req_headers.push(CapturedHeader {
                name: "Origin".to_string(),
                value: origin.clone(),
            });
            modified_request.extend_from_slice(format!("Origin: {origin}\r\n").as_bytes());
        }

        req_headers.push(CapturedHeader {
            name: "Content-Length".to_string(),
            value: body.len().to_string(),
        });
        req_headers.push(CapturedHeader {
            name: "Connection".to_string(),
            value: "close".to_string(),
        });
        modified_request
            .extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        modified_request.extend_from_slice(b"Connection: close\r\n\r\n");
        modified_request.extend_from_slice(body);

        let req_body = if !body.is_empty() {
            String::from_utf8(body.to_vec()).ok()
        } else {
            None
        };

        let local_addr = format!("{}:{}", local_host, local_port);
        let mut tcp = timeout(
            LOCAL_UPSTREAM_CONNECT_TIMEOUT,
            TcpStream::connect(&local_addr),
        )
        .await
        .map_err(|_| anyhow!("timed out connecting to local upstream at {local_addr}"))??;

        timeout(LOCAL_UPSTREAM_IO_TIMEOUT, tcp.write_all(&modified_request))
            .await
            .map_err(|_| anyhow!("timed out writing request to local upstream"))??;
        timeout(LOCAL_UPSTREAM_IO_TIMEOUT, tcp.shutdown())
            .await
            .map_err(|_| anyhow!("timed out closing local upstream write half"))??;

        let mut raw_response = Vec::with_capacity(64 * 1024);
        timeout(LOCAL_UPSTREAM_IO_TIMEOUT, async {
            tcp.read_to_end(&mut raw_response).await
        })
        .await
        .map_err(|_| anyhow!("timed out reading response from local upstream"))??;

        let parsed_response = Self::normalize_upstream_response(&raw_response)?;

        let duration_ms = start.elapsed().as_millis() as u64;
        let status_code = parsed_response.status_code;

        info!(method = %method, path = %path, status = status_code, duration_ms, "HTTP request forwarded");

        // Capture request for inspector
        if let Some(store) = &request_store {
            store.add(CapturedRequest {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                method: method.to_string(),
                path: path.to_string(),
                headers: req_headers,
                body: req_body,
                response_status: status_code,
                response_headers: parsed_response.headers,
                response_body: String::from_utf8(parsed_response.body).ok(),
                duration_ms,
            });
        }

        Ok(raw_response)
    }

    fn normalize_upstream_response(payload: &[u8]) -> Result<ParsedUpstreamResponse> {
        let mut offset = 0;

        loop {
            let header_end = find_header_end(&payload[offset..])
                .ok_or_else(|| anyhow!("invalid upstream HTTP response framing"))?;
            let header_end_abs = offset + header_end;
            let header_text = std::str::from_utf8(&payload[offset..header_end_abs])?;
            let mut lines = header_text.split("\r\n");

            let status_line = lines
                .next()
                .ok_or_else(|| anyhow!("missing upstream status line"))?;
            let status_code = status_line
                .split_whitespace()
                .nth(1)
                .ok_or_else(|| anyhow!("missing upstream status code"))?
                .parse::<u16>()?;

            let mut headers = Vec::new();
            let mut content_length = None;
            let mut chunked = false;
            let mut body_allowed =
                !matches!(status_code, 204 | 304) && !(100..200).contains(&status_code);

            for line in lines {
                if line.is_empty() {
                    continue;
                }
                let Some((name, value)) = line.split_once(':') else {
                    continue;
                };

                let name = name.trim();
                let value = value.trim();

                if name.eq_ignore_ascii_case("content-length") {
                    content_length = Some(value.parse::<usize>()?);
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

                headers.push(CapturedHeader {
                    name: name.to_string(),
                    value: value.to_string(),
                });
            }

            if status_code == 101 {
                body_allowed = false;
            }

            let body_start = header_end_abs + 4;
            let (body, body_len) = if !body_allowed {
                (Vec::new(), 0)
            } else if chunked {
                Self::decode_chunked_body(&payload[body_start..])?
            } else if let Some(length) = content_length {
                let end = body_start
                    .checked_add(length)
                    .ok_or_else(|| anyhow!("upstream body length overflow"))?;
                if end > payload.len() {
                    bail!("upstream body shorter than declared content-length");
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
                    bail!("upstream returned only an interim response");
                }
                offset = next_offset;
                continue;
            }

            return Ok(ParsedUpstreamResponse {
                status_code,
                headers,
                body,
            });
        }
    }

    fn decode_chunked_body(payload: &[u8]) -> Result<(Vec<u8>, usize)> {
        let mut decoded = Vec::new();
        let mut cursor = 0;

        loop {
            let line_end = find_crlf(&payload[cursor..])
                .ok_or_else(|| anyhow!("invalid upstream chunk framing"))?;
            let line = std::str::from_utf8(&payload[cursor..cursor + line_end])?;
            let size_text = line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_text, 16)?;
            cursor += line_end + 2;

            if size == 0 {
                loop {
                    let trailer_end = find_crlf(&payload[cursor..])
                        .ok_or_else(|| anyhow!("invalid upstream trailer framing"))?;
                    cursor += trailer_end + 2;
                    if trailer_end == 0 {
                        return Ok((decoded, cursor));
                    }
                }
            }

            let chunk_end = cursor
                .checked_add(size)
                .ok_or_else(|| anyhow!("upstream chunk length overflow"))?;
            if chunk_end + 2 > payload.len() {
                bail!("upstream chunk shorter than declared size");
            }
            decoded.extend_from_slice(&payload[cursor..chunk_end]);
            if &payload[chunk_end..chunk_end + 2] != b"\r\n" {
                bail!("invalid upstream chunk terminator");
            }
            cursor = chunk_end + 2;
        }
    }

    /// Spawn a long-lived WebSocket relay for a streaming connection.
    /// Opens a raw TCP connection to the local server, sends the initial HTTP
    /// upgrade request, and relays bytes bidirectionally.
    fn spawn_ws_relay(&mut self, msg: ServerData, mut relay_rx: mpsc::Receiver<Vec<u8>>) {
        let local_addr = format!("{}:{}", self.local_host, self.local_port);
        let tunnel_id = msg.tunnel_id;
        let connection_id = msg.connection_id;
        let stream_id = msg.stream_id;
        let source_addr = msg.source_addr;
        let data_tx = self.connection.data_tx.clone();
        let initial_payload = msg.payload;

        tokio::spawn(async move {
            // 1. Open TCP connection to local server
            let tcp = match TcpStream::connect(&local_addr).await {
                Ok(tcp) => tcp,
                Err(e) => {
                    error!(error = %e, "failed to connect to local server for WebSocket relay");
                    return;
                }
            };

            info!(
                stream_id,
                connection_id,
                local_addr = %local_addr,
                "WebSocket relay started"
            );

            let (mut tcp_read, mut tcp_write) = tcp.into_split();

            // 2. Split initial payload: the HTTP upgrade request ends at \r\n\r\n.
            //    Any bytes after that are raw WS frames that arrived on the same
            //    QUIC stream (QUIC merges writes).
            let (upgrade_bytes, extra_bytes) =
                match initial_payload.windows(4).position(|w| w == b"\r\n\r\n") {
                    Some(pos) => {
                        let split = pos + 4;
                        (&initial_payload[..split], &initial_payload[split..])
                    }
                    None => (initial_payload.as_slice(), &[] as &[u8]),
                };

            if let Err(e) = tcp_write.write_all(upgrade_bytes).await {
                error!(error = %e, "failed to send upgrade request to local server");
                return;
            }

            // 3. Read and discard the local server's HTTP upgrade response.
            //    The browser already received a 101 from the pike-server.
            //    We just need to consume the local server's 101 response headers.
            {
                let mut response_buf = Vec::with_capacity(4096);
                let mut tmp = [0u8; 1];
                loop {
                    match tcp_read.read(&mut tmp).await {
                        Ok(0) => {
                            error!("local server closed connection during upgrade");
                            return;
                        }
                        Ok(_) => {
                            response_buf.push(tmp[0]);
                            if response_buf.len() >= 4
                                && response_buf[response_buf.len() - 4..] == *b"\r\n\r\n"
                            {
                                break;
                            }
                            if response_buf.len() > 8192 {
                                error!("upgrade response too large");
                                return;
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "failed to read upgrade response from local server");
                            return;
                        }
                    }
                }
                if let Ok(resp) = std::str::from_utf8(&response_buf) {
                    info!(
                        "local server upgrade response consumed: {}",
                        resp.lines().next().unwrap_or("")
                    );
                }
            }

            // 4. If extra bytes arrived with the initial payload (raw WS frames
            //    merged by QUIC), write them to local TCP now.
            if !extra_bytes.is_empty() {
                info!(
                    stream_id,
                    bytes = extra_bytes.len(),
                    "writing extra bytes from initial payload"
                );
                if let Err(e) = tcp_write.write_all(extra_bytes).await {
                    error!(error = %e, "failed to write extra initial bytes");
                    return;
                }
            }

            // 4. Bidirectional relay
            let data_tx_for_read = data_tx.clone();

            // TCP -> QUIC: read from local server, send to QUIC stream
            let tcp_to_quic = tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match tcp_read.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if data_tx_for_read
                                .send(LocalData {
                                    stream_id: Some(stream_id),
                                    tunnel_id,
                                    connection_id,
                                    source_addr,
                                    payload: buf[..n].to_vec(),
                                    fin: false,
                                    streaming: true,
                                })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "TCP read error in WebSocket relay");
                            break;
                        }
                    }
                }
                // Send fin when TCP closes
                let _ = data_tx_for_read
                    .send(LocalData {
                        stream_id: Some(stream_id),
                        tunnel_id,
                        connection_id,
                        source_addr,
                        payload: vec![],
                        fin: true,
                        streaming: true,
                    })
                    .await;
            });

            // QUIC -> TCP: receive from relay channel, write to local server
            let quic_to_tcp = tokio::spawn(async move {
                while let Some(data) = relay_rx.recv().await {
                    if data.is_empty() {
                        continue;
                    }
                    if tcp_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                let _ = tcp_write.shutdown().await;
            });

            // Wait for either direction to finish
            tokio::select! {
                _ = tcp_to_quic => {}
                _ = quic_to_tcp => {}
            }

            info!(stream_id, connection_id, "WebSocket relay ended");
        });
    }

    pub async fn run(&mut self) -> Result<()> {
        let tunnel_id = self.tunnel_id.unwrap_or(self.config.id);
        let request_limit = Arc::new(Semaphore::new(MAX_INFLIGHT_HTTP_REQUESTS));
        info!(
            local_addr = %format!("{}:{}", self.local_host, self.local_port),
            tunnel_id = %tunnel_id,
            "HTTP tunnel running"
        );

        while let Some(msg) = self.connection.data_rx.recv().await {
            if msg.tunnel_id != tunnel_id {
                continue;
            }

            // Check if this message belongs to an existing WS relay
            if let Some(relay_tx) = self.ws_relays.get(&msg.stream_id) {
                let _ = relay_tx.send(msg.payload).await;
                if msg.fin {
                    self.ws_relays.remove(&msg.stream_id);
                }
                continue;
            }

            // First chunk for a streaming connection — spawn new WS relay
            if msg.streaming {
                let (relay_tx, relay_rx) = mpsc::channel(256);
                self.ws_relays.insert(msg.stream_id, relay_tx);
                self.spawn_ws_relay(msg, relay_rx);
                continue;
            }

            // Normal HTTP request-response
            let permit = match request_limit.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => break,
            };
            let local_host = self.local_host.clone();
            let local_port = self.local_port;
            let request_store = self.request_store.clone();
            let data_tx = self.connection.data_tx.clone();
            let stream_id = msg.stream_id;
            let connection_id = msg.connection_id;
            let source_addr = msg.source_addr;
            let payload = msg.payload;

            tokio::spawn(async move {
                let _permit = permit;
                match Self::handle_payload(local_host, local_port, request_store, payload).await {
                    Ok(response_payload) => {
                        let _ = data_tx
                            .send(LocalData {
                                stream_id: Some(stream_id),
                                tunnel_id,
                                connection_id,
                                source_addr,
                                payload: response_payload,
                                fin: true,
                                streaming: false,
                            })
                            .await;
                    }
                    Err(e) => {
                        error!(stream_id, error = %e, "failed to process HTTP request");
                    }
                }
            });
        }

        Ok(())
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.connection.close().await
    }
}

struct ParsedUpstreamResponse {
    status_code: u16,
    headers: Vec<CapturedHeader>,
    body: Vec<u8>,
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
