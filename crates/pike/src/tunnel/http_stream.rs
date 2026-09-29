//! Stream one HTTP exchange without retaining either complete body.
use super::origin::OriginProtocol;
use super::pool::{OriginPool, PoolUnavailable};
use crate::inspector::{capture::Capture, storage::RequestStore};
use anyhow::{anyhow, bail, ensure, Result};
use axum::body::Body;
use http_body_util::BodyExt;
use hyper_util::rt::{TokioExecutor, TokioIo};
use pike_core::{
    http_wire::{self, Decoder, HttpFrame, Writer, DATA_CHUNK_BYTES},
    proto::StreamMode,
    quic::client::{LocalData, ServerData},
};
use std::sync::{Arc, Mutex};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
    time::{timeout, Duration},
};

const IDLE: Duration = Duration::from_secs(30);

pub async fn relay(
    origin: OriginPool,
    store: Option<Arc<RequestStore>>,
    first: ServerData,
    mut input: mpsc::Receiver<ServerData>,
    output: mpsc::Sender<LocalData>,
    mut cancelled: watch::Receiver<bool>,
) {
    let writer = Writer::new(
        output,
        LocalData {
            stream_id: Some(first.stream_id),
            tunnel_id: first.tunnel_id,
            connection_id: first.connection_id,
            source_addr: first.source_addr,
            payload: vec![],
            fin: false,
            streaming: true,
            mode: StreamMode::Http,
        },
    );
    let capture = store.as_ref().map(|_| Arc::new(Mutex::new(Capture::new())));
    let (body_tx, body) = http_wire::body_channel(writer.clone());
    let (head_tx, head_rx) = oneshot::channel();
    let mut head_tx = Some(head_tx);
    let mut decoder = Decoder::default();
    let mut initial = Some(first.clone());
    let receive = async {
        let mut request_ended = false;
        loop {
            let part = match initial.take() {
                Some(value) => value,
                None if request_ended => input
                    .recv()
                    .await
                    .ok_or_else(|| anyhow!("HTTP tunnel closed"))?,
                None => timeout(IDLE, input.recv())
                    .await?
                    .ok_or_else(|| anyhow!("HTTP tunnel closed"))?,
            };
            ensure!(
                part.mode == StreamMode::Http
                    && part.streaming
                    && part.tunnel_id == first.tunnel_id
                    && part.connection_id == first.connection_id
                    && part.stream_id == first.stream_id,
                "HTTP stream identity changed"
            );
            for frame in decoder.feed(&part.payload, part.fin)? {
                match frame {
                    HttpFrame::Credit(count) => writer.grant(count)?,
                    HttpFrame::Request {
                        method,
                        target,
                        headers,
                    } if head_tx.is_some() => {
                        let request = hyper::Request::builder()
                            .method(method.as_str())
                            .uri(target)
                            .body(())?;
                        ensure!(
                            request.uri().scheme().is_none() && request.uri().authority().is_none(),
                            "origin-form request required"
                        );
                        let (mut parts, ()) = request.into_parts();
                        parts.headers = http_wire::headers_from_wire(headers)?;
                        // Preserve the existing browser Origin:null normalization.
                        if parts
                            .headers
                            .get("origin")
                            .is_some_and(|value| value == "null")
                        {
                            if let Some(host) = parts
                                .headers
                                .get("x-forwarded-host")
                                .and_then(|v| v.to_str().ok())
                            {
                                let scheme = parts
                                    .headers
                                    .get("x-forwarded-proto")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("http");
                                let origin = format!("{scheme}://{host}").parse()?;
                                parts.headers.insert("origin", origin);
                            }
                        }
                        if let Some(capture) = &capture {
                            capture
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .request(
                                    parts.method.as_str(),
                                    &parts.uri.to_string(),
                                    &parts.headers,
                                );
                        }
                        head_tx
                            .take()
                            .unwrap()
                            .send(parts)
                            .map_err(|_| anyhow!("HTTP request cancelled"))?;
                    }
                    HttpFrame::Reset(reason) => bail!("relay cancelled HTTP request: {reason}"),
                    frame @ (HttpFrame::Data(_) | HttpFrame::Trailers(_) | HttpFrame::End)
                        if head_tx.is_none() =>
                    {
                        if let (Some(capture), HttpFrame::Data(data)) = (&capture, &frame) {
                            capture
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .data(false, data);
                        }
                        request_ended |= matches!(frame, HttpFrame::End);
                        // Early origin responses can drop their request body.
                        if !body_tx.is_closed() {
                            body_tx
                                .try_send(Ok(frame))
                                .map_err(|_| anyhow!("HTTP request body queue full"))?;
                        }
                    }
                    _ => bail!("invalid HTTP request sequence"),
                }
            }
            ensure!(!part.fin, "HTTP relay closed");
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let exchange = async {
        let mut parts = timeout(IDLE, head_rx).await??;
        let (origin, stream, protocol) = match origin.connect(false).await {
            Ok(connection) => connection,
            Err(error) if error.is::<PoolUnavailable>() => {
                let mut headers = hyper::HeaderMap::new();
                headers.insert("retry-after", "1".parse()?);
                headers.insert("content-length", "0".parse()?);
                if let Some(capture) = &capture {
                    capture
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .response(503, &headers);
                }
                timeout(
                    IDLE,
                    writer.send(
                        HttpFrame::Response {
                            status: 503,
                            headers: http_wire::headers_to_wire(&headers),
                        },
                        false,
                    ),
                )
                .await??;
                timeout(IDLE, writer.send(HttpFrame::End, true)).await??;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        origin.prepare_request(&mut parts, protocol)?;
        let request = hyper::Request::from_parts(parts, Body::new(body));
        // The connection driver belongs to this exchange; cancellation aborts it
        // and closes the origin socket, including a pending HTTP/2 request stream.
        let mut connections = JoinSet::new();
        let response = timeout(http_wire::RESPONSE_HEAD_TIMEOUT, async {
            if protocol == OriginProtocol::Http2 {
                let (mut sender, connection) = hyper::client::conn::http2::handshake(
                    TokioExecutor::new(),
                    TokioIo::new(stream),
                )
                .await?;
                connections.spawn(connection);
                sender.send_request(request).await
            } else {
                let (mut sender, connection) =
                    hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
                connections.spawn(connection);
                sender.send_request(request).await
            }
        })
        .await??;
        let (parts, mut body) = response.into_parts();
        if let Some(capture) = &capture {
            capture
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .response(parts.status.as_u16(), &parts.headers);
        }
        timeout(
            IDLE,
            writer.send(
                HttpFrame::Response {
                    status: parts.status.as_u16(),
                    headers: http_wire::headers_to_wire(&parts.headers),
                },
                false,
            ),
        )
        .await??;
        while let Some(frame) = timeout(IDLE, body.frame()).await? {
            let frame = frame?;
            match frame.into_data() {
                Ok(bytes) => {
                    for chunk in bytes.chunks(DATA_CHUNK_BYTES) {
                        if let Some(capture) = &capture {
                            capture
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .data(true, chunk);
                        }
                        timeout(IDLE, writer.send(HttpFrame::Data(chunk.to_vec()), false))
                            .await??;
                    }
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        timeout(
                            IDLE,
                            writer.send(
                                HttpFrame::Trailers(http_wire::headers_to_wire(&trailers)),
                                false,
                            ),
                        )
                        .await??;
                    }
                }
            }
        }
        timeout(IDLE, writer.send(HttpFrame::End, true)).await??;
        Ok::<(), anyhow::Error>(())
    };
    let result = tokio::select! {
        result = receive => result,
        result = exchange => result,
        _ = cancelled.changed() => Err(anyhow!("HTTP stream cancelled")),
    };
    if let (Some(store), Some(capture)) = (store, capture) {
        if let Ok(capture) = Arc::try_unwrap(capture) {
            store.add(
                capture
                    .into_inner()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .finish(),
            );
        }
    }
    if let Err(error) = result {
        tracing::debug!(%error, stream_id=first.stream_id, "HTTP exchange ended");
        let _ = timeout(
            Duration::from_secs(5),
            writer.send(HttpFrame::Reset("origin exchange failed".into()), true),
        )
        .await;
    }
}
