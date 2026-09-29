//! Real public HTTP/2 -> relay -> QUIC/WS -> CLI -> HTTP/2/HTTPS/Unix origin.
//! Run after `cargo build --workspace`; all sockets and certificates are local.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]
#[path = "support/grpc_origin.rs"]
mod grpc_origin;
#[path = "support/pool_origin.rs"]
mod pool_origin;
use axum::body::{Body, Bytes};
use futures::{SinkExt, StreamExt};
use grpc_origin::{Fixture, Message};
use http_body_util::BodyExt;
use hyper::{body::Frame, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{sleep, timeout},
};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn launch(bin: &Path, args: &[String], log: &Path) -> Process {
    let output = fs::File::create(log).unwrap();
    Process(
        Command::new(bin)
            .args(args)
            .env("NO_COLOR", "1")
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap(),
    )
}
fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn codec() -> tonic_prost::ProstCodec<Message, Message> {
    tonic_prost::ProstCodec::default()
}
fn msg(data: &[u8]) -> Message {
    Message {
        data: data.to_vec(),
    }
}
async fn wait_until(mut condition: impl FnMut() -> bool) {
    timeout(Duration::from_secs(5), async {
        while !condition() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

async fn origin_handler(
    mut request: Request<hyper::body::Incoming>,
    fixture: Fixture,
) -> Result<Response<Body>, std::convert::Infallible> {
    if request.uri().path().starts_with("/echo.Echo/") {
        return grpc_origin::serve(request, fixture).await;
    }
    let version = format!("{:?}", request.version());
    let authority = request
        .uri()
        .authority()
        .map(ToString::to_string)
        .or_else(|| {
            request
                .headers()
                .get("host")
                .map(|v| v.to_str().unwrap().to_owned())
        })
        .unwrap_or_default();
    if request.uri().path() == "/sse" {
        return Ok(Response::builder()
            .header("content-type", "text/event-stream")
            .body(Body::from_stream(async_stream::stream! {
                yield Ok::<_, std::io::Error>(Bytes::from_static(b"data: first\n\n"));
                sleep(Duration::from_millis(250)).await;
                yield Ok(Bytes::from_static(b"data: second\n\n"));
            }))
            .unwrap());
    }
    if request.uri().path() == "/trailers" {
        let mut collected = vec![];
        let mut trailer = None;
        while let Some(frame) = request.body_mut().frame().await {
            let frame = frame.unwrap();
            if let Some(data) = frame.data_ref() {
                collected.extend_from_slice(data);
            }
            if let Some(trailers) = frame.trailers_ref() {
                trailer = trailers.get("x-request-trailer").cloned();
            }
        }
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert(
            "x-response-trailer",
            trailer.unwrap_or_else(|| "missing".parse().unwrap()),
        );
        trailers.insert("grpc-status", "0".parse().unwrap());
        let frames = futures::stream::iter(vec![
            Ok::<_, std::io::Error>(Frame::data(Bytes::from(collected))),
            Ok(Frame::trailers(trailers)),
        ]);
        return Ok(Response::new(Body::new(http_body_util::StreamBody::new(
            frames,
        ))));
    }
    if request.uri().path() == "/ws" {
        let key = request.headers()["sec-websocket-key"].as_bytes();
        let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key);
        let upgrade = hyper::upgrade::on(&mut request);
        tokio::spawn(async move {
            let upgraded = upgrade.await.unwrap();
            let mut socket = tokio_tungstenite::WebSocketStream::from_raw_socket(
                TokioIo::new(upgraded),
                tokio_tungstenite::tungstenite::protocol::Role::Server,
                None,
            )
            .await;
            while let Some(Ok(frame)) = socket.next().await {
                if frame.is_close() {
                    break;
                }
                if socket.send(frame).await.is_err() {
                    break;
                }
            }
        });
        return Ok(Response::builder()
            .status(101)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-accept", accept)
            .body(Body::empty())
            .unwrap());
    }
    Ok(Response::builder()
        .header("x-origin-version", version)
        .header("x-origin-authority", authority)
        .body(Body::from("origin-ready"))
        .unwrap())
}
async fn serve_io<I>(io: I, h2: bool, fixture: Fixture)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service =
        hyper::service::service_fn(move |request| origin_handler(request, fixture.clone()));
    if h2 {
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(io), service)
            .await;
    } else {
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(io), service)
            .with_upgrades()
            .await;
    }
}
async fn spawn_origin(
    tasks: &mut JoinSet<()>,
    h2: bool,
    tls: Option<Arc<rustls::ServerConfig>>,
    fixture: Fixture,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tasks.spawn(async move {
        let mut connections = JoinSet::new();
        loop { tokio::select! {
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            next = listener.accept() => {
                let (io,_) = next.unwrap(); let tls=tls.clone(); let fixture=fixture.clone();
                connections.spawn(async move {
                    if let Some(config) = tls {
                        if let Ok(io) = tokio_rustls::TlsAcceptor::from(config).accept(io).await {
                            let h2 = io.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
                            serve_io(io,h2,fixture).await;
                        }
                    } else { serve_io(io,h2,fixture).await; }
                });
            }
        } }
    });
    port
}
async fn http_get(public: u16, host: &str, path: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(format!("http://127.0.0.1:{public}{path}"))
        .header("host", host)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap()
}
async fn wait_ready(public: u16, host: &str, cli: &mut Process, log: &Path) {
    let result = timeout(Duration::from_secs(15), async {
        loop {
            if let Some(status) = cli.0.try_wait().unwrap() {
                panic!("CLI exited {status}: {}", fs::read_to_string(log).unwrap());
            }
            if let Ok(response) = reqwest::Client::new()
                .get(format!(
                    "http://127.0.0.1:{public}/{}",
                    if host == "pike.test" { "health" } else { "" }
                ))
                .header("host", host)
                .timeout(Duration::from_millis(500))
                .send()
                .await
            {
                if response.status() == 200 || response.status() == 502 {
                    return;
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "tunnel failed: {}",
        fs::read_to_string(log).unwrap()
    );
}

async fn grpc_checks(public: u16, host: &str, fixture: &Fixture) {
    let channel = tonic::transport::Endpoint::from_shared(format!("http://127.0.0.1:{public}"))
        .unwrap()
        .origin(format!("http://{host}").parse().unwrap())
        .connect()
        .await
        .unwrap();
    let mut client = tonic::client::Grpc::new(channel);
    client.ready().await.unwrap();
    let response = client
        .unary(
            tonic::Request::new(msg(b"binary\x00\xff")),
            "/echo.Echo/Unary".parse().unwrap(),
            codec(),
        )
        .await
        .unwrap();
    assert_eq!(response.metadata().get("x-origin").unwrap(), "tonic");
    assert_eq!(response.into_inner().data, b"binary\x00\xff");
    client.ready().await.unwrap();
    let response = client
        .client_streaming(
            tonic::Request::new(tokio_stream::iter([
                msg(b"one"),
                msg(b"two"),
                msg(b"three"),
            ])),
            "/echo.Echo/Client".parse().unwrap(),
            codec(),
        )
        .await
        .unwrap();
    assert_eq!(response.into_inner().data, b"onetwothree");
    client.ready().await.unwrap();
    let mut response = client
        .server_streaming(
            tonic::Request::new(msg(b"stream")),
            "/echo.Echo/Server".parse().unwrap(),
            codec(),
        )
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        timeout(Duration::from_millis(150), response.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .data,
        b"stream"
    );
    assert_eq!(response.message().await.unwrap().unwrap().data, b"stream");
    assert!(response.message().await.unwrap().is_none());
    let (tx, rx) = tokio::sync::mpsc::channel(2);
    client.ready().await.unwrap();
    let mut response = client
        .streaming(
            tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(rx)),
            "/echo.Echo/Bidi".parse().unwrap(),
            codec(),
        )
        .await
        .unwrap()
        .into_inner();
    for value in [b"first".as_slice(), b"second".as_slice()] {
        tx.send(msg(value)).await.unwrap();
        let reply = timeout(Duration::from_secs(2), response.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(reply.data, value.iter().rev().copied().collect::<Vec<_>>());
    }
    drop(tx);
    assert!(response.message().await.unwrap().is_none());
    client.ready().await.unwrap();
    let error = client
        .unary(
            tonic::Request::new(msg(b"error")),
            "/echo.Echo/Unary".parse().unwrap(),
            codec(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert_eq!(error.metadata().get("x-error-detail").unwrap(), "preserved");
    let mut request = tonic::Request::new(msg(b"deadline"));
    request.set_timeout(Duration::from_millis(200));
    let started = std::time::Instant::now();
    client.ready().await.unwrap();
    let error = client
        .unary(request, "/echo.Echo/Unary".parse().unwrap(), codec())
        .await
        .unwrap_err();
    // tonic channel maps its own local TimeoutExpired to Cancelled.
    assert_eq!(error.code(), tonic::Code::Cancelled);
    assert!(started.elapsed() < Duration::from_secs(2));
    wait_until(|| fixture.active.load(Ordering::SeqCst) == 0).await;
    let before = fixture.cancelled.load(Ordering::SeqCst);
    client.ready().await.unwrap();
    let mut response = client
        .server_streaming(
            tonic::Request::new(msg(b"cancel")),
            "/echo.Echo/Server".parse().unwrap(),
            codec(),
        )
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.message().await.unwrap().unwrap().data, b"ready");
    assert_eq!(fixture.active.load(Ordering::SeqCst), 1);
    drop(response);
    wait_until(|| {
        fixture.active.load(Ordering::SeqCst) == 0
            && fixture.cancelled.load(Ordering::SeqCst) > before
    })
    .await;
}
async fn trailer_checks(public: u16, host: &str) {
    let (mut sender, connection) = hyper::client::conn::http2::handshake(
        TokioExecutor::new(),
        TokioIo::new(TcpStream::connect(("127.0.0.1", public)).await.unwrap()),
    )
    .await
    .unwrap();
    let driver = tokio::spawn(connection);
    let mut trailers = hyper::HeaderMap::new();
    trailers.insert("x-request-trailer", "from-client".parse().unwrap());
    let body = http_body_util::StreamBody::new(futures::stream::iter(vec![
        Ok::<_, std::io::Error>(Frame::data(Bytes::from_static(b"\x00\xffdata"))),
        Ok(Frame::trailers(trailers)),
    ]));
    let request = Request::builder()
        .method("POST")
        .uri(format!("http://{host}/trailers"))
        .body(Body::new(body))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    let collected = response.into_body().collect().await.unwrap();
    assert_eq!(
        collected.trailers().unwrap()["x-response-trailer"],
        "from-client"
    );
    assert_eq!(collected.to_bytes(), Bytes::from_static(b"\x00\xffdata"));
    // No SDK-local timer: observe the origin's deadline status on the wire.
    let protobuf = prost::Message::encode_to_vec(&msg(b"deadline"));
    let mut framed = vec![0];
    framed.extend_from_slice(&u32::try_from(protobuf.len()).unwrap().to_be_bytes());
    framed.extend(protobuf);
    let request = Request::builder()
        .method("POST")
        .uri(format!("http://{host}/echo.Echo/Unary"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("grpc-timeout", "200m")
        .body(Body::from(framed))
        .unwrap();
    let response = timeout(Duration::from_secs(2), sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 200);
    let status = response.headers().get("grpc-status").cloned();
    let collected = response.into_body().collect().await.unwrap();
    assert_eq!(
        status
            .or_else(|| collected
                .trailers()
                .and_then(|t| t.get("grpc-status").cloned()))
            .unwrap(),
        "4"
    );
    let request = Request::builder()
        .uri(format!("http://{host}/"))
        .header("host", "different.pike.test")
        .body(Body::empty())
        .unwrap();
    assert_eq!(sender.send_request(request).await.unwrap().status(), 400);
    driver.abort();
}
async fn streaming_checks(public: u16, host: &str) {
    let mut body = http_get(public, host, "/sse").await;
    assert_eq!(
        timeout(Duration::from_millis(150), body.chunk())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        Bytes::from_static(b"data: first\n\n")
    );
    assert_eq!(
        body.chunk().await.unwrap().unwrap(),
        Bytes::from_static(b"data: second\n\n")
    );
    let mut request = format!("ws://{host}/ws").into_client_request().unwrap();
    request.headers_mut().insert("host", host.parse().unwrap());
    let socket = TcpStream::connect(("127.0.0.1", public)).await.unwrap();
    let (mut socket, _) = tokio_tungstenite::client_async(request, socket)
        .await
        .unwrap();
    let frame = tokio_tungstenite::tungstenite::Message::Binary(vec![0, 255, 12, 65]);
    socket.send(frame.clone()).await.unwrap();
    assert_eq!(socket.next().await.unwrap().unwrap(), frame);
    socket.close(None).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_origins_and_grpc_over_both_transports() {
    timeout(Duration::from_secs(180), run())
        .await
        .expect("origin E2E deadline");
}
async fn run() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let cert = dir.join("origin.pem");
    let key = dir.join("origin.key");
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let certificates = CertificateDer::pem_slice_iter(&fs::read(&cert).unwrap())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certificates, PrivateKeyDer::from_pem_file(&key).unwrap())
    .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let fixture = Fixture::default();
    let mut tasks = JoinSet::new();
    let h1 = spawn_origin(&mut tasks, false, None, fixture.clone()).await;
    let h2 = spawn_origin(&mut tasks, true, None, fixture.clone()).await;
    let tls = Arc::new(tls);
    let https = spawn_origin(&mut tasks, false, Some(tls.clone()), fixture.clone()).await;
    let https_second = spawn_origin(&mut tasks, false, Some(tls), fixture.clone()).await;
    #[cfg(unix)]
    let unix_path = {
        let path = dir.join("origin.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let fixture = fixture.clone();
        tasks.spawn(async move { let mut connections=JoinSet::new(); loop { tokio::select! {
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            next=listener.accept()=>{let (io,_)=next.unwrap(); connections.spawn(serve_io(io,false,fixture.clone()));}
        } } });
        path
    };
    for transport in ["quic", "websocket"] {
        let public = port();
        let management = port();
        let relay = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_port = relay.local_addr().unwrap().port();
        drop(relay);
        let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_relay = if transport == "quic" {
            relay_port
        } else {
            blackhole.local_addr().unwrap().port()
        };
        let server_config = dir.join(format!("server-{transport}.toml"));
        fs::write(
            &server_config,
            format!(
                r#"bind_addr = "127.0.0.1:{relay_port}"
http_bind_addr = "127.0.0.1:{public}"
management_bind_addr = "127.0.0.1:{management}"
internal_token = "local-origin-test"
local_api_keys = ["pk_test_origin"]
domain = "pike.test"
[abuse]
tunnel_creations_per_user_per_hour = 20
[quic]
cert_path = "{}"
key_path = "{}"
"#,
                root.join("config/cert.pem").display(),
                root.join("config/key.pem").display()
            ),
        )
        .unwrap();
        let server_log = dir.join(format!("server-{transport}.log"));
        let mut server = launch(
            &root.join("target/debug/pike-server"),
            &[
                "--config".into(),
                server_config.display().to_string(),
                "--dev-mode".into(),
            ],
            &server_log,
        );
        wait_ready(public, "pike.test", &mut server, &server_log).await;
        let client_config = dir.join(format!("client-{transport}.toml"));
        fs::write(
            &client_config,
            format!(
                r#"[auth]
api_key = "pk_test_origin"
[relay]
addr = "127.0.0.1:{client_relay}"
ws_fallback = {}
ws_url = "ws://127.0.0.1:{public}/ws/tunnel"
connect_timeout_ms = {}
quic_timeout_ms = 60000
tls_server_name = "localhost"
api_url = "http://127.0.0.1:{public}"
insecure_skip_tls_verify = true
[tunnel]
subdomain_prefix = ""
bind_addr = "127.0.0.1"
[inspector]
enabled = false
port = 4040
max_requests = 100
[advanced]
log_level = "info"
zero_rtt = true
heartbeat_interval = 15
"#,
                transport == "websocket",
                // The blackhole only triggers the fallback fixture. A real
                // QUIC handshake needs the normal startup budget while other
                // local fixtures compete for CPU; this is not a latency test.
                if transport == "quic" { 5000 } else { 500 }
            ),
        )
        .unwrap();
        let mut cases = vec![
            ("http1", vec![h1.to_string()], "HTTP/1.1", 200),
            (
                "h2c",
                vec![h2.to_string(), "--upstream-protocol".into(), "http2".into()],
                "HTTP/2.0",
                200,
            ),
            (
                "https",
                vec![
                    "--upstream".into(),
                    format!("https://127.0.0.1:{https}"),
                    "--origin-ca".into(),
                    cert.display().to_string(),
                    "--origin-server-name".into(),
                    "localhost".into(),
                ],
                "HTTP/2.0",
                200,
            ),
            (
                "untrusted",
                vec!["--upstream".into(), format!("https://localhost:{https}")],
                "",
                502,
            ),
            (
                "wrongname",
                vec![
                    "--upstream".into(),
                    format!("https://127.0.0.1:{https}"),
                    "--origin-ca".into(),
                    cert.display().to_string(),
                ],
                "",
                502,
            ),
        ];
        #[cfg(unix)]
        cases.push((
            "unix",
            vec!["--unix-socket".into(), unix_path.display().to_string()],
            "HTTP/1.1",
            200,
        ));
        for (name, options, version, status) in cases {
            let host = format!("{name}.pike.test");
            let log = dir.join(format!("cli-{transport}-{name}.log"));
            let mut args = vec![
                "--config".into(),
                client_config.display().to_string(),
                "http".into(),
                "--subdomain".into(),
                name.into(),
                "--max-reconnects".into(),
                "0".into(),
            ];
            args.extend(options);
            let mut cli = launch(Path::new(env!("CARGO_BIN_EXE_pike")), &args, &log);
            wait_ready(public, &host, &mut cli, &log).await;
            let response = http_get(public, &host, "/").await;
            assert_eq!(
                response.status().as_u16(),
                status,
                "{transport}/{name}: {}",
                fs::read_to_string(&log).unwrap()
            );
            if status == 200 {
                assert_eq!(response.headers()["x-origin-version"], version);
                assert_eq!(response.headers()["x-origin-authority"], host);
                assert_eq!(response.text().await.unwrap(), "origin-ready");
                if version == "HTTP/2.0" {
                    grpc_checks(public, &host, &fixture).await;
                    trailer_checks(public, &host).await;
                }
                if name != "h2c" {
                    streaming_checks(public, &host).await;
                }
            }
            println!("PASS {transport}/{name}: status={status}, origin={version}");
        }
        // A fresh relay isolates this scenario from the public-IP request quota
        // consumed by the preceding interoperability matrix.
        drop(server);
        let mut server = launch(
            &root.join("target/debug/pike-server"),
            &[
                "--config".into(),
                server_config.display().to_string(),
                "--dev-mode".into(),
            ],
            &server_log,
        );
        wait_ready(public, "pike.test", &mut server, &server_log).await;
        pool_origin::verify(public, &client_config, dir, transport, &server).await;
        let pool_log = dir.join(format!("securepool-{transport}.log"));
        let args = vec![
            "--config".into(),
            client_config.display().to_string(),
            "http".into(),
            "--subdomain".into(),
            "securepool".into(),
            "--upstream".into(),
            format!("https://localhost:{https}"),
            "--upstream".into(),
            format!("https://localhost:{https_second}"),
            "--origin-ca".into(),
            cert.display().to_string(),
            "--upstream-protocol".into(),
            "http2".into(),
            "--health-path".into(),
            "/health".into(),
            "--health-interval".into(),
            "1".into(),
            "--max-reconnects".into(),
            "0".into(),
        ];
        let mut pool_cli = launch(Path::new(env!("CARGO_BIN_EXE_pike")), &args, &pool_log);
        wait_ready(public, "securepool.pike.test", &mut pool_cli, &pool_log).await;
        grpc_checks(public, "securepool.pike.test", &fixture).await;
        trailer_checks(public, "securepool.pike.test").await;
        streaming_checks(public, "securepool.pike.test").await;
        println!("POOL TLS PASS {transport}: verified HTTPS; gRPC=4/4; trailers; cancellation; SSE; WebSocket");
    }
    tasks.shutdown().await;
}
