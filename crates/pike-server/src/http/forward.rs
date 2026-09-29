//! Public tunnel forwarding: admission, inspection and completion observation.
use super::capture::{
    content_type_str, is_previewable_content_type, maybe_capture_headers, preview_body,
    redact_path_query, should_capture_body_preview,
};
use super::platform::{dispatch_platform_request, is_platform_host, platform_health_response};
use super::HttpState;
use crate::{
    dashboard_ws::DashboardEvent,
    ingest::IngestEntry,
    proxy::{extract_host, is_websocket_upgrade, proxy_request, ProxyContext, ProxyError},
    rate_limit::{exceeded_headers, RateLimitError, RateLimitHeaders},
    ws_proxy,
};
use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, State},
    http::{
        header::{HeaderName, HeaderValue, CONTENT_LENGTH},
        Request, Response, StatusCode,
    },
};
use http_body_util::BodyExt;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};
pub(super) async fn handle_request(
    State(state): State<HttpState>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    mut req: Request<Body>,
) -> Response<Body> {
    let host = match crate::proxy::canonicalize_authority(&mut req) {
        Ok(host) => host,
        Err(error) => {
            return Response::builder()
                .status(error.status_code())
                .body(Body::from(error.to_string()))
                .unwrap()
        }
    };
    // Frontend role: a hostname routed on another relay leaves before any local
    // handling, including its ACME challenges. Hop-served requests carry an
    // expected gate and never forward again, so two frontends cannot loop.
    if let Some(frontend) = &state.frontend {
        if req
            .extensions()
            .get::<crate::ingress::ExpectedGate>()
            .is_none()
            && !is_platform_host(&host, &state.domain)
        {
            let name = crate::router::normalize_host(&host);
            let target = crate::ingress_directory::Target::hostname(
                crate::ingress_directory::Protocol::Http,
                &name,
            );
            if state.router.route(&name).is_none() && frontend.resolve(&target).is_some() {
                let visitor = match state.trusted_proxies.resolve(client_addr, req.headers()) {
                    Ok(visitor) => visitor,
                    Err(error) => return error.response(),
                };
                return frontend.forward_http(&name, visitor, req).await;
            }
        }
    }
    let request_path = req.uri().path().to_string();
    if let Some(token) = request_path.strip_prefix("/.well-known/acme-challenge/") {
        let name = crate::router::normalize_host(&host);
        let strict = req.method() == axum::http::Method::GET
            && req.uri().query().is_none()
            && crate::ingress::valid_challenge_token(token);
        let mut proof = if strict {
            state.certificates.challenge(&name, token).await
        } else {
            None
        };
        // Frontend role: a TLS-terminate profile owned elsewhere advertises no
        // HTTP target, so its HTTP-01 lookup travels as one bounded challenge
        // request over the hop. Hop-served requests never forward again.
        if proof.is_none() && strict {
            if let Some(frontend) = &state.frontend {
                if req
                    .extensions()
                    .get::<crate::ingress::ExpectedGate>()
                    .is_none()
                    && !is_platform_host(&host, &state.domain)
                    && state.router.route(&name).is_none()
                {
                    proof = frontend.forward_challenge(&name, token).await;
                }
            }
        }
        return Response::builder()
            .status(if proof.is_some() { 200 } else { 404 })
            .header("content-type", "text/plain")
            .header("cache-control", "no-store")
            .body(Body::from(proof.unwrap_or_default()))
            .unwrap();
    }

    if is_platform_host(&host, &state.domain) {
        if request_path == "/health" {
            return platform_health_response();
        }

        if request_path.starts_with("/ws/") || request_path.starts_with("/api/v1/") {
            return dispatch_platform_request(state.clone(), req).await;
        }
    }

    forward_tunnel_request(state, client_addr, req).await
}

pub(super) async fn forward_tunnel_request(
    state: HttpState,
    client_addr: SocketAddr,
    mut req: Request<Body>,
) -> Response<Body> {
    let visitor = match req
        .extensions()
        .get::<crate::visitor_policy::VisitorPeer>()
        .copied()
        .map(Ok)
        .unwrap_or_else(|| state.trusted_proxies.resolve(client_addr, req.headers()))
    {
        Ok(visitor) => visitor,
        Err(error) => return error.response(),
    };
    let client_addr = visitor.addr;
    let scheme = if visitor.secure { "https" } else { "http" }.to_owned();
    let request_content_length = request_content_length(&req);

    let tunnel_entry = crate::proxy::extract_host(req.headers())
        .map(|host| crate::router::normalize_host(&host))
        .and_then(|host| {
            if let Some(expected) = req.extensions().get::<super::replay::ExpectedTunnel>() {
                state.router.route_for_connection(&host, &expected.1)
            } else {
                state.router.route(&host)
            }
        });

    if let Some(expected) = req.extensions().get::<super::replay::ExpectedTunnel>() {
        if !tunnel_entry
            .as_ref()
            .is_some_and(|entry| entry.tunnel_id == expected.0 && entry.connection_id == expected.1)
        {
            return Response::builder()
                .status(409)
                .body(Body::from("tunnel changed; refresh before replay"))
                .unwrap();
        }
    }
    // A hop-served request must land on the endpoint whose gate the owning relay
    // bound before it accepted the hop. Rejected before the body is touched.
    if let Some(expected) = req.extensions().get::<crate::ingress::ExpectedGate>() {
        if !tunnel_entry
            .as_ref()
            .is_some_and(|entry| Arc::ptr_eq(&entry.visitor, &expected.0))
        {
            return crate::ingress::misdirected(
                "route authority changed since the ingress hop was accepted",
            );
        }
    }
    let admission = if let Some(entry) = &tunnel_entry {
        let admission = match entry.visitor.handle_http(visitor, &mut req).await {
            Ok(crate::visitor_policy::VisitorDecision::Admit(admission)) => admission,
            Ok(crate::visitor_policy::VisitorDecision::Response(response)) => return response,
            Err(error) => return error.response(),
        };
        let admission = match admission.with_domain(entry.domain.clone()) {
            Ok(admission) => admission,
            Err(error) => return error.response(),
        };
        // Admission, quota attribution and dispatch use one captured route.
        req.extensions_mut()
            .insert(crate::proxy::PinnedTunnel(entry.clone()));
        Some(admission)
    } else {
        None
    };

    // Forward only verified peer identity, including for raw WebSocket upgrades.
    let spoofed: Vec<_> = req
        .headers()
        .keys()
        .filter(|name| name.as_str().starts_with("x-pike-visitor-"))
        .cloned()
        .collect();
    for name in spoofed {
        req.headers_mut().remove(name);
    }
    req.headers_mut().remove("forwarded");
    for name in ["x-real-ip", "x-forwarded-for"] {
        req.headers_mut().insert(
            name,
            HeaderValue::from_str(&client_addr.ip().to_string()).expect("IP header"),
        );
    }
    req.headers_mut().insert(
        "x-forwarded-proto",
        HeaderValue::from_static(if visitor.secure { "https" } else { "http" }),
    );

    // Capture attribution before disconnect/delete can remove the live registry.
    let public_tunnel_id = tunnel_entry
        .as_ref()
        .map(|tunnel| state.registry.public_tunnel_id(tunnel.tunnel_id))
        .unwrap_or_default();
    let user_id = tunnel_entry
        .as_ref()
        .and_then(|tunnel| state.registry.user_id_for_connection(&tunnel.connection_id));

    let mut rate_limit_headers = None;
    if let Some(tunnel) = &tunnel_entry {
        if state
            .registry
            .abuse_detector
            .is_suspended(&tunnel.tunnel_id)
        {
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("tunnel suspended due to abuse"))
                .unwrap_or_else(|_| Response::new(Body::from("tunnel suspended")));
        }

        let user_id = state
            .registry
            .user_id_for_connection(&tunnel.connection_id)
            .unwrap_or_else(|| format!("conn:{}", tunnel.connection_id));
        let admission = if state.tunnel_metrics_store.quota().is_some() {
            // Hosted byte/day quotas are shared reservations owned by the quota manager.
            state.registry.rate_limiter.check_request_rate(user_id)
        } else {
            // Standalone: plan bandwidth plus the per-plan daily request ceiling (fix #18).
            state
                .registry
                .rate_limiter
                .check_limit(user_id.clone())
                .and_then(|()| state.registry.rate_limiter.check_daily_request(&user_id))
        };
        if let Err(error) = admission {
            let headers = exceeded_headers();
            return build_rate_limited_response(error, Some(&headers));
        }
        match state
            .registry
            .rate_limiter
            .check_tunnel_limit(tunnel.tunnel_id)
        {
            Ok(headers) => {
                rate_limit_headers = Some(headers);
            }
            Err(error) => {
                let headers = exceeded_headers();
                return build_rate_limited_response(error, Some(&headers));
            }
        }
    }

    // Extract host/subdomain before we pass the request through
    let subdomain = extract_host(req.headers())
        .map(|h| crate::router::normalize_host(&h))
        .unwrap_or_default();

    req.extensions_mut().insert(ProxyContext {
        client_addr: Some(client_addr),
        scheme,
    });

    // Intercept WebSocket upgrades and relay raw bytes through the tunnel.
    if is_websocket_upgrade(req.headers()) {
        if let Some(tunnel) = &tunnel_entry {
            let source_addr = client_addr;
            let stream_header = pike_core::proto::StreamHeader {
                tunnel_id: tunnel.tunnel_id,
                connection_id: crate::proxy::connection_id_from_uuid(),
                source_addr,
                streaming: true,
                mode: pike_core::proto::StreamMode::Raw,
            };

            let raw_upgrade = ws_proxy::build_raw_upgrade_request(&req);
            let request_id = uuid::Uuid::new_v4().to_string();
            let stream_tx = tunnel.stream_tx.clone();

            let upgrade = ws_proxy::handle_ws_upgrade(
                req,
                stream_tx,
                stream_header,
                raw_upgrade,
                request_id,
                crate::traffic_meter::TrafficMeter::new(
                    state.registry.clone(),
                    tunnel.tunnel_id,
                    user_id.clone().unwrap_or_default(),
                    public_tunnel_id.clone(),
                    state.tunnel_metrics_store.usage_journal().cloned(),
                )
                .with_quota(
                    state.tunnel_metrics_store.quota().cloned(),
                    tunnel.connection_id.to_string(),
                ),
                admission.clone().expect("routed visitor admission"),
            );
            return tokio::select! {
                biased;
                () = admission.as_ref().expect("routed visitor admission").cancelled() => crate::visitor_policy::Rejection::Unavailable.response(),
                response = upgrade => response,
            };
        }
    }

    let deadline = tokio::time::Instant::now() + crate::proxy::DEFAULT_PROXY_TIMEOUT;
    req.extensions_mut()
        .insert(crate::proxy::ProxyDeadline(deadline));
    // Capture method and path for live event broadcasting. Fix #17: keep the path but
    // redact the VALUES of sensitive query-string params (tokens, secrets, session ids)
    // so tunneled-request secrets are never persisted.
    let req_method = req.method().to_string();
    let req_path = redact_path_query(req.uri().path(), req.uri().query());

    // Capture request headers and body preview
    let req_content_type = content_type_str(req.headers());
    let req_headers_json = maybe_capture_headers(req.headers(), &state.traffic_inspection);

    let request_preview_limit = if should_capture_body_preview(
        &state.traffic_inspection,
        req_content_type.as_deref(),
        request_content_length,
    ) {
        state.traffic_inspection.max_body_preview_bytes
    } else {
        0
    };
    let request_preview = Arc::new(std::sync::Mutex::new(Vec::new()));
    let quota_meter = state.tunnel_metrics_store.quota().and_then(|quota| {
        tunnel_entry.as_ref().map(|tunnel| {
            crate::traffic_meter::TrafficMeter::new(
                state.registry.clone(),
                tunnel.tunnel_id,
                user_id.clone().unwrap_or_default(),
                public_tunnel_id.clone(),
                state.tunnel_metrics_store.usage_journal().cloned(),
            )
            .with_quota(Some(quota.clone()), tunnel.connection_id.to_string())
        })
    });

    if state
        .tunnel_metrics_store
        .usage_journal()
        .is_some_and(|journal| !journal.is_healthy())
    {
        return Response::builder()
            .status(503)
            .body(Body::from("usage storage unavailable"))
            .unwrap();
    }
    let proxy_start = Instant::now();

    if let Some(signature) = state
        .registry
        .abuse_detector
        .check_malware_signature(req.uri().path().as_bytes())
    {
        state
            .registry
            .abuse_detector
            .log_abuse(crate::abuse::AbuseLogEntry {
                timestamp: chrono::Utc::now(),
                source_ip: Some(client_addr.ip()),
                user_id: None,
                tunnel_id: tunnel_entry.as_ref().map(|entry| entry.tunnel_id),
                request_count_per_minute: None,
                bandwidth_bytes: Some(request_content_length),
                reason: format!("matched malware signature {signature}"),
            });
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("request blocked by malware signature"))
            .unwrap_or_else(|_| Response::new(Body::from("blocked")));
    }

    req.extensions_mut()
        .insert(pike_core::http_wire::RequestLimit(
            state.max_body_size as u64,
        ));

    if let Some(meter) = &quota_meter {
        if let Err(error) = meter.opened().await {
            return crate::quota::error_response(&error);
        }
    }

    let visitor_gate = admission;
    // Count bytes actually forwarded, including uploads without Content-Length.
    let request_bytes = Arc::new(AtomicU64::new(0));
    let observed_request_bytes = request_bytes.clone();
    let capture = request_preview.clone();
    let (parts, body) = req.into_parts();
    let body = if let Some(gate) = &visitor_gate {
        gate.wrap_body(body)
    } else {
        body
    };
    let body = if let Some(meter) = &quota_meter {
        meter.wrap_body(body, pike_core::byte_stream::Direction::SocketToTunnel)
    } else {
        body
    };
    let body = Body::new(body.map_frame(move |frame| {
        if let Some(bytes) = frame.data_ref() {
            observed_request_bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
            if request_preview_limit > 0 {
                let mut preview = capture
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let retain = bytes
                    .len()
                    .min((request_preview_limit + 1).saturating_sub(preview.len()));
                preview.extend_from_slice(&bytes[..retain]);
            }
        }
        frame
    }));
    let req = Request::from_parts(parts, body);

    let forwarded = if let Some(gate) = &visitor_gate {
        tokio::select! {
            biased;
            () = gate.cancelled() => return crate::visitor_policy::Rejection::Unavailable.response(),
            response = proxy_request(state.router.clone(), req) => response,
        }
    } else {
        proxy_request(state.router.clone(), req).await
    };
    let mut response = match forwarded {
        Ok(response) => response,
        Err(err) => {
            crate::metrics::ERROR_RATE
                .with_label_values(&["proxy_error"])
                .inc();
            build_error_response(err, &state.domain)
        }
    };

    if let Some(headers) = &rate_limit_headers {
        apply_rate_limit_headers(response.headers_mut(), headers);
    }

    let status_code = response.status().as_u16();
    let resp_content_type = content_type_str(response.headers());
    let resp_headers_json = maybe_capture_headers(response.headers(), &state.traffic_inspection);
    let preview_limit = if state.traffic_inspection.capture_bodies
        && resp_content_type
            .as_deref()
            .is_some_and(is_previewable_content_type)
    {
        state.traffic_inspection.max_body_preview_bytes
    } else {
        0
    };
    let (parts, body) = response.into_parts();
    let quota_accounted = quota_meter.is_some();
    let body = if let Some(meter) = quota_meter {
        meter.wrap_body(body, pike_core::byte_stream::Direction::TunnelToSocket)
    } else {
        body
    };
    let body = crate::observed_body::ObservedBody::wrap_async(
        body,
        preview_limit,
        move |response_content_length, preview| async move {
            let request_content_length = request_bytes.load(Ordering::Relaxed);
            if !quota_accounted {
                if let (Some(journal), Some(owner)) =
                    (state.tunnel_metrics_store.usage_journal(), user_id.as_ref())
                {
                    journal
                        .record(
                            public_tunnel_id.clone(),
                            owner.clone(),
                            request_content_length,
                            response_content_length,
                        )
                        .await
                        .map_err(|error| {
                            tracing::error!(%error, "usage observation could not be committed");
                            axum::Error::new(std::io::Error::other(error.to_string()))
                        })?;
                }
            }
            let req_body_preview = if request_preview_limit > 0 {
                let bytes = std::mem::take(
                    &mut *request_preview
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                );
                preview_body(
                    &Bytes::from(bytes),
                    request_preview_limit,
                    req_content_type.as_deref(),
                )
            } else {
                None
            };
            let response_time_ms = proxy_start.elapsed().as_millis() as u64;
            let resp_body_preview = if preview_limit > 0 {
                preview_body(
                    &Bytes::from(preview),
                    preview_limit,
                    resp_content_type.as_deref(),
                )
            } else {
                None
            };
            if let Some(tunnel) = tunnel_entry {
                state
                    .registry
                    .record_tunnel_request(tunnel.tunnel_id, status_code);
                let total_bytes = request_content_length.saturating_add(response_content_length);
                if !quota_accounted {
                    state
                        .registry
                        .track_bandwidth(tunnel.tunnel_id, total_bytes);
                }

                crate::metrics::BYTES_TRANSFERRED
                    .with_label_values(&["in"])
                    .inc_by(request_content_length as f64);
                crate::metrics::BYTES_TRANSFERRED
                    .with_label_values(&["out"])
                    .inc_by(response_content_length as f64);
                crate::metrics::REQUEST_LATENCY
                    .with_label_values(&["http"])
                    .observe(response_time_ms as f64 / 1000.0);

                // Log request for per-tunnel request log API
                {
                    let log_entry = crate::request_log::RequestLogEntry {
                        id: uuid::Uuid::new_v4().to_string(),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        method: req_method.clone(),
                        path: req_path.clone(),
                        status_code,
                        duration_ms: response_time_ms,
                        request_size: request_content_length,
                        response_size: response_content_length,
                        tunnel_id: public_tunnel_id.clone(),
                    };
                    let store = state.request_log_store.clone();
                    tokio::spawn(async move {
                        store.log(log_entry).await;
                    });
                }

                {
                    let store = state.tunnel_metrics_store.clone();
                    let tunnel_id = tunnel.tunnel_id.to_string();
                    tokio::spawn(async move {
                        store
                            .record(
                                &tunnel_id,
                                status_code,
                                response_time_ms,
                                request_content_length,
                                response_content_length,
                            )
                            .await;
                    });
                }

                // Broadcast live request to dashboard subscribers
                if let Some(user_id) = user_id {
                    let timestamp = chrono::Utc::now().to_rfc3339();
                    let event = DashboardEvent::LiveRequest {
                        tunnel_id: public_tunnel_id.clone(),
                        subdomain: subdomain.clone(),
                        method: req_method.clone(),
                        path: req_path.clone(),
                        status_code,
                        response_time_ms,
                        bytes: total_bytes,
                        client_ip: client_addr.ip().to_string(),
                        timestamp: timestamp.clone(),
                        request_headers: req_headers_json.clone(),
                        request_body: req_body_preview.clone(),
                        response_headers: resp_headers_json.clone(),
                        response_body: resp_body_preview.clone(),
                        request_content_type: req_content_type.clone(),
                        response_content_type: resp_content_type.clone(),
                    };
                    if let Ok(json) = serde_json::to_string(&event) {
                        state.broadcaster.broadcast(&user_id, &json);
                    }

                    // Push to ingest buffer for D1 persistence
                    let entry = IngestEntry {
                        user_id,
                        tunnel_id: public_tunnel_id.clone(),
                        subdomain: subdomain.clone(),
                        method: req_method,
                        path: req_path,
                        status_code,
                        response_time_ms,
                        bytes_transferred: total_bytes,
                        client_ip: client_addr.ip().to_string(),
                        timestamp,
                        request_headers: req_headers_json,
                        request_body: req_body_preview,
                        response_headers: resp_headers_json,
                        response_body: resp_body_preview,
                        request_content_type: req_content_type,
                        response_content_type: resp_content_type,
                    };
                    let buffer = state.ingest_buffer.clone();
                    tokio::spawn(async move {
                        buffer.push(entry).await;
                    });
                }
            }
            Ok(())
        },
    );
    let body = if let Some(gate) = visitor_gate {
        gate.wrap_body(body)
    } else {
        body
    };
    Response::from_parts(parts, body)
}

fn build_error_response(error: ProxyError, domain: &str) -> Response<Body> {
    if matches!(error, ProxyError::NotFound) {
        return Response::builder()
            .status(StatusCode::TEMPORARY_REDIRECT)
            .header("location", format!("https://app.{}", domain))
            .body(Body::empty())
            .unwrap_or_else(|_| Response::new(Body::from("redirecting...")));
    }
    Response::builder()
        .status(error.status_code())
        .body(Body::from(error.to_string()))
        .unwrap_or_else(|_| Response::new(Body::from("proxy error")))
}

fn build_rate_limited_response(
    error: RateLimitError,
    headers: Option<&RateLimitHeaders>,
) -> Response<Body> {
    let mut response = Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .body(Body::from(error.to_string()))
        .unwrap_or_else(|_| Response::new(Body::from("rate limit exceeded")));
    if let Some(headers) = headers {
        apply_rate_limit_headers(response.headers_mut(), headers);
        let retry_after = headers
            .reset_unix_seconds
            .saturating_sub(chrono::Utc::now().timestamp().max(0) as u64)
            .max(1);
        let _ = response.headers_mut().insert(
            HeaderName::from_static("retry-after"),
            HeaderValue::from_str(&retry_after.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("1")),
        );
    }
    response
}

fn apply_rate_limit_headers(headers: &mut axum::http::HeaderMap, rate: &RateLimitHeaders) {
    let _ = headers.insert(
        HeaderName::from_static("x-ratelimit-limit"),
        HeaderValue::from_str(&rate.limit.to_string()).unwrap_or(HeaderValue::from_static("0")),
    );
    let _ = headers.insert(
        HeaderName::from_static("x-ratelimit-remaining"),
        HeaderValue::from_str(&rate.remaining.to_string()).unwrap_or(HeaderValue::from_static("0")),
    );
    let _ = headers.insert(
        HeaderName::from_static("x-ratelimit-reset"),
        HeaderValue::from_str(&rate.reset_unix_seconds.to_string())
            .unwrap_or(HeaderValue::from_static("0")),
    );
}

fn request_content_length(request: &Request<Body>) -> u64 {
    request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}
