//! One bounded HTTP exchange. The shared dispatcher never awaits its body.
use axum::{body::Body, http::Response};
use http_body_util::BodyExt;
use pike_core::{
    http_wire::{
        self, Decoder, HttpFrame, RequestLimit, Writer, DATA_CHUNK_BYTES, DEFAULT_MAX_REQUEST_BYTES,
    },
    proto::StreamMode,
    quic::server::{InboundData, OutboundData, PikeOutboundMessage},
    types::TunnelId,
};
use pike_server::proxy::{HttpRequest, ProxyDeadline, ProxyError, DEFAULT_PROXY_TIMEOUT};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{
    sync::{mpsc, oneshot, Mutex},
    time::{timeout, timeout_at, Instant},
};

pub type PendingHttp = Arc<Mutex<HashMap<u64, (TunnelId, mpsc::Sender<InboundData>)>>>;
const IDLE: Duration = Duration::from_secs(30);

pub async fn forward(
    request: HttpRequest,
    outbound: mpsc::Sender<PikeOutboundMessage>,
    pending: PendingHttp,
) {
    let HttpRequest {
        stream_header,
        request,
        response_tx,
        ..
    } = request;
    let deadline = request
        .extensions()
        .get::<ProxyDeadline>()
        .map_or_else(|| Instant::now() + DEFAULT_PROXY_TIMEOUT, |value| value.0);
    let limit = request
        .extensions()
        .get::<RequestLimit>()
        .map_or(DEFAULT_MAX_REQUEST_BYTES, |value| value.0);
    if request
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|len| len > limit)
    {
        let _ = response_tx.send(Err(ProxyError::PayloadTooLarge));
        return;
    }
    let key = stream_header.connection_id;
    let writer = Writer::new(
        outbound,
        PikeOutboundMessage::Data(OutboundData {
            stream_id: None,
            tunnel_id: stream_header.tunnel_id,
            connection_id: key,
            source_addr: stream_header.source_addr,
            payload: vec![],
            fin: false,
            streaming: true,
            mode: StreamMode::Http,
        }),
    );
    let (tx, rx) = mpsc::channel(128);
    pending
        .lock()
        .await
        .insert(key, (stream_header.tunnel_id, tx));
    let (body_tx, body) = http_wire::body_channel(writer.clone());
    let mut response_tx = Some(response_tx);
    let result = {
        let upload = upload(request, writer.clone(), limit);
        let download = response(
            rx,
            &mut response_tx,
            writer.clone(),
            body_tx.clone(),
            Body::new(body),
            deadline,
        );
        tokio::pin!(upload, download);
        tokio::select! {
            result = &mut download => result,
            result = &mut upload => match result { Ok(()) => download.await, Err(error) => Err(error) },
        }
    };
    if let Err(error) = result {
        if let Some(tx) = response_tx.take() {
            let _ = tx.send(Err(error));
        } else {
            let _ = body_tx.try_send(Err(error.to_string()));
        }
    }
    let _ = timeout(
        Duration::from_secs(5),
        writer.send(
            HttpFrame::Reset("exchange complete or cancelled".into()),
            true,
        ),
    )
    .await;
    pending.lock().await.remove(&key);
}

async fn upload(
    request: axum::http::Request<Body>,
    writer: Writer<PikeOutboundMessage>,
    limit: u64,
) -> Result<(), ProxyError> {
    let (parts, mut body) = request.into_parts();
    send(
        &writer,
        HttpFrame::Request {
            method: parts.method.to_string(),
            target: parts
                .uri
                .path_and_query()
                .map_or("/", |value| value.as_str())
                .to_owned(),
            headers: http_wire::headers_to_wire(&parts.headers),
        },
    )
    .await?;
    let mut total = 0_u64;
    while let Some(frame) = timeout(IDLE, body.frame())
        .await
        .map_err(|_| ProxyError::Timeout)?
    {
        let frame = frame.map_err(|error| {
            use std::error::Error;
            let mut cause: &(dyn Error + 'static) = &error;
            loop {
                if cause.is::<http_body_util::LengthLimitError>() {
                    return ProxyError::PayloadTooLarge;
                }
                match cause.source() {
                    Some(next) => cause = next,
                    None => break,
                }
            }
            ProxyError::BadRequest("failed to read request body")
        })?;
        match frame.into_data() {
            Ok(bytes) => {
                total = total
                    .checked_add(bytes.len() as u64)
                    .ok_or(ProxyError::PayloadTooLarge)?;
                if total > limit {
                    return Err(ProxyError::PayloadTooLarge);
                }
                for chunk in bytes.chunks(DATA_CHUNK_BYTES) {
                    send(&writer, HttpFrame::Data(chunk.to_vec())).await?;
                }
            }
            Err(frame) => {
                if let Ok(headers) = frame.into_trailers() {
                    send(
                        &writer,
                        HttpFrame::Trailers(http_wire::headers_to_wire(&headers)),
                    )
                    .await?;
                }
            }
        }
    }
    send(&writer, HttpFrame::End).await
}

async fn send(writer: &Writer<PikeOutboundMessage>, frame: HttpFrame) -> Result<(), ProxyError> {
    timeout(IDLE, writer.send(frame, false))
        .await
        .map_err(|_| ProxyError::Timeout)?
        .map_err(|error| ProxyError::Upstream(error.to_string()))
}

async fn response(
    mut raw: mpsc::Receiver<InboundData>,
    response_tx: &mut Option<oneshot::Sender<Result<Response<Body>, ProxyError>>>,
    writer: Writer<PikeOutboundMessage>,
    body_tx: http_wire::BodySender,
    body: Body,
    deadline: Instant,
) -> Result<(), ProxyError> {
    let mut body = Some(body);
    let mut decoder = Decoder::default();
    loop {
        let next = if let Some(tx) = response_tx.as_mut() {
            tokio::select! { _ = tx.closed() => return Ok(()), next = timeout_at(deadline, raw.recv()) => next.map_err(|_| ProxyError::Timeout)? }
        } else {
            tokio::select! { _ = body_tx.closed() => return Ok(()), next = timeout(IDLE, raw.recv()) => next.map_err(|_| ProxyError::Timeout)? }
        }.ok_or_else(|| ProxyError::Upstream("HTTP tunnel disconnected".into()))?;
        if next.mode != StreamMode::Http {
            return Err(ProxyError::Upstream("HTTP stream mode changed".into()));
        }
        for frame in decoder
            .feed(&next.payload, next.fin)
            .map_err(|error| ProxyError::Upstream(error.to_string()))?
        {
            match frame {
                HttpFrame::Credit(count) => writer
                    .grant(count)
                    .map_err(|error| ProxyError::Upstream(error.to_string()))?,
                HttpFrame::Response { status, headers } if response_tx.is_some() => {
                    let mut response = Response::builder()
                        .status(status)
                        .body(body.take().unwrap())
                        .map_err(|error| ProxyError::Upstream(error.to_string()))?;
                    *response.headers_mut() = http_wire::headers_from_wire(headers)
                        .map_err(|error| ProxyError::Upstream(error.to_string()))?;
                    if response_tx.take().unwrap().send(Ok(response)).is_err() {
                        return Ok(());
                    }
                }
                HttpFrame::Reset(reason) => return Err(ProxyError::Upstream(reason)),
                frame @ (HttpFrame::Data(_) | HttpFrame::Trailers(_) | HttpFrame::End)
                    if response_tx.is_none() =>
                {
                    let ended = matches!(frame, HttpFrame::End);
                    body_tx.try_send(Ok(frame)).map_err(|_| {
                        ProxyError::Upstream("HTTP response consumer stalled".into())
                    })?;
                    if ended {
                        let _ = timeout(IDLE, body_tx.closed()).await;
                        return Ok(());
                    }
                }
                _ => {
                    return Err(ProxyError::Upstream(
                        "invalid HTTP response sequence".into(),
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use pike_core::proto::StreamHeader;

    fn request(
        body: Body,
        limit: u64,
    ) -> (
        HttpRequest,
        oneshot::Receiver<Result<Response<Body>, ProxyError>>,
    ) {
        let (tx, rx) = oneshot::channel();
        let mut request = Request::builder()
            .method("POST")
            .uri("/upload")
            .body(body)
            .unwrap();
        request.extensions_mut().insert(RequestLimit(limit));
        (
            HttpRequest {
                stream_header: StreamHeader {
                    tunnel_id: TunnelId::new(),
                    connection_id: pike_server::proxy::connection_id_from_uuid(),
                    source_addr: "127.0.0.1:1".parse().unwrap(),
                    streaming: true,
                    mode: StreamMode::Http,
                },
                request_id: "fixture".into(),
                websocket: false,
                request,
                response_tx: tx,
            },
            rx,
        )
    }

    #[tokio::test]
    async fn cancelled_upload_releases_route_without_blocking_another_request() {
        let pending = PendingHttp::default();
        let (outbound, mut output) = mpsc::channel(16);
        let (slow, slow_rx) = request(
            Body::from_stream(futures_util::stream::pending::<
                Result<Vec<u8>, std::io::Error>,
            >()),
            200_000_000,
        );
        let (fast, fast_rx) = request(Body::empty(), 200_000_000);
        let fast_header = fast.stream_header.clone();
        let slow_task = tokio::spawn(forward(slow, outbound.clone(), pending.clone()));
        let fast_task = tokio::spawn(forward(fast, outbound, pending.clone()));
        let mut heads = 0;
        while heads < 2 {
            let PikeOutboundMessage::Data(part) = timeout(Duration::from_secs(1), output.recv())
                .await
                .unwrap()
                .unwrap()
            else {
                panic!("data required");
            };
            let frames = Decoder::default().feed(&part.payload, false).unwrap();
            if matches!(frames.first(), Some(HttpFrame::Request { .. })) {
                heads += 1;
            }
        }
        let sender = pending
            .lock()
            .await
            .get(&fast_header.connection_id)
            .unwrap()
            .1
            .clone();
        sender
            .send(InboundData {
                stream_id: 1,
                tunnel_id: fast_header.tunnel_id,
                connection_id: fast_header.connection_id,
                source_addr: fast_header.source_addr,
                payload: [
                    HttpFrame::Response {
                        status: 200,
                        headers: vec![],
                    },
                    HttpFrame::Data(b"ok".to_vec()),
                    HttpFrame::End,
                ]
                .iter()
                .flat_map(|frame| http_wire::encode(frame).unwrap())
                .collect(),
                fin: true,
                streaming: true,
                mode: StreamMode::Http,
            })
            .await
            .unwrap();
        let response = timeout(Duration::from_secs(1), fast_rx)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "ok"
        );
        drop(slow_rx);
        timeout(Duration::from_secs(1), slow_task)
            .await
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(1), fast_task)
            .await
            .unwrap()
            .unwrap();
        assert!(pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn streamed_overflow_returns_413_and_sends_no_overlimit_chunk() {
        let pending = PendingHttp::default();
        let (outbound, mut output) = mpsc::channel(16);
        let body = Body::from_stream(futures_util::stream::iter([
            Ok::<_, std::io::Error>(vec![1; 8]),
            Ok(vec![2]),
        ]));
        let (request, response) = request(body, 8);
        forward(request, outbound, pending.clone()).await;
        assert!(matches!(
            response.await.unwrap(),
            Err(ProxyError::PayloadTooLarge)
        ));
        let mut data = vec![];
        let mut decoder = Decoder::default();
        while let Ok(PikeOutboundMessage::Data(part)) = output.try_recv() {
            for frame in decoder.feed(&part.payload, part.fin).unwrap() {
                if let HttpFrame::Data(bytes) = frame {
                    data.extend(bytes);
                }
            }
        }
        assert_eq!(data, vec![1; 8]);
        assert!(pending.lock().await.is_empty());
    }
}
