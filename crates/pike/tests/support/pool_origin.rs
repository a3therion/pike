//! Controllable real origins for pool health, selection and at-most-once tests.
use super::{http_get, launch, port, wait_ready, Body, Bytes, Frame, Process};
use http_body_util::BodyExt;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    task::JoinSet,
    time::{sleep, timeout},
};

struct Backend {
    port: u16,
    healthy: Arc<AtomicBool>,
    fail_after_body: Arc<AtomicBool>,
    delivered: Arc<Mutex<Vec<String>>>,
}
async fn backend(name: &'static str, tasks: &mut JoinSet<()>) -> Backend {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let healthy = Arc::new(AtomicBool::new(true));
    let fail_after_body = Arc::new(AtomicBool::new(false));
    let delivered = Arc::new(Mutex::new(vec![]));
    let result = Backend {
        port,
        healthy: healthy.clone(),
        fail_after_body: fail_after_body.clone(),
        delivered: delivered.clone(),
    };
    tasks.spawn(async move {
        let mut connections=JoinSet::new();
        loop { tokio::select! {
            Some(_) = connections.join_next(), if !connections.is_empty()=>{},
            next=listener.accept()=>{
                let (io,_)=next.unwrap(); let healthy=healthy.clone(); let fail=fail_after_body.clone(); let delivered=delivered.clone();
                connections.spawn(async move {
                    let service=hyper::service::service_fn(move |mut request:Request<hyper::body::Incoming>| {
                        let healthy=healthy.clone(); let fail=fail.clone(); let delivered=delivered.clone();
                        async move {
                            if request.uri().path()=="/health" {
                                assert_eq!(request.method(),"HEAD");
                                return Ok::<_,std::io::Error>(Response::builder().status(if healthy.load(Ordering::SeqCst) {200} else {503}).body(Body::empty()).unwrap());
                            }
                            let id=request.uri().path().to_owned();
                            if request.method()=="POST" { delivered.lock().unwrap().push(id); }
                            let mut size=0;
                            while let Some(frame)=request.body_mut().frame().await {
                                let frame=frame.map_err(std::io::Error::other)?;
                                if let Ok(data)=frame.into_data() { size+=data.len(); }
                            }
                            if fail.load(Ordering::SeqCst) { return Err(std::io::Error::other("origin closed after consuming request")); }
                            Ok(Response::builder().header("x-origin",name).body(Body::from(size.to_string())).unwrap())
                        }
                    });
                    let _=hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(io),service).await;
                });
            }
        } }
    });
    result
}
async fn wait_health(inspector: u16, expected: &[bool], log: &Path) {
    let output = std::fs::read_to_string(log).unwrap();
    let token = output
        .lines()
        .find_map(|line| {
            line.strip_prefix("Inspector access: ")
                .and_then(|url| url.split_once('#').map(|(_, token)| token))
        })
        .expect("inspector access token");
    let client = reqwest::Client::new();
    timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(response) = client
                .get(format!("http://127.0.0.1:{inspector}/api/origins"))
                .bearer_auth(token)
                .send()
                .await
            {
                if let Ok(states) = response.json::<Vec<serde_json::Value>>().await {
                    if states.len() == expected.len()
                        && states.iter().zip(expected).all(|(state, expected)| {
                            state["checked"] == true && state["healthy"] == *expected
                        })
                    {
                        return;
                    }
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("pool health converges");
}
async fn distribution(public: u16, count: usize) -> [usize; 2] {
    let mut counts = [0, 0];
    for _ in 0..count {
        let response = http_get(public, "pool.pike.test", "/").await;
        if response.status() != 200 {
            let status = response.status();
            let body = response.text().await.unwrap();
            panic!("pool distribution returned {status}: {body}");
        }
        let index = match response.headers()["x-origin"].to_str().unwrap() {
            "a" => 0,
            "b" => 1,
            other => panic!("unknown origin {other}"),
        };
        counts[index] += 1;
        response.bytes().await.unwrap();
    }
    counts
}
fn rss(pid: u32) -> u64 {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse::<u64>()
        .unwrap()
        * 1024
}

pub async fn verify(public: u16, config: &Path, dir: &Path, transport: &str, relay: &Process) {
    let mut tasks = JoinSet::new();
    let a = backend("a", &mut tasks).await;
    let b = backend("b", &mut tasks).await;
    let inspector = port();
    let log = dir.join(format!("pool-{transport}.log"));
    let args = vec![
        "--config".into(),
        config.display().to_string(),
        "http".into(),
        "--subdomain".into(),
        "pool".into(),
        "--upstream".into(),
        format!("http://127.0.0.1:{}", a.port),
        "--upstream".into(),
        format!("http://127.0.0.1:{}", b.port),
        "--health-path".into(),
        "/health".into(),
        "--health-interval".into(),
        "1".into(),
        "--inspector-port".into(),
        inspector.to_string(),
        "--max-reconnects".into(),
        "0".into(),
    ];
    let mut cli = launch(Path::new(env!("CARGO_BIN_EXE_pike")), &args, &log);
    wait_ready(public, "pool.pike.test", &mut cli, &log).await;
    wait_health(inspector, &[true, true], &log).await;
    let output = std::fs::read_to_string(&log).unwrap();
    let token = output
        .lines()
        .find_map(|line| {
            line.strip_prefix("Inspector access: ")
                .and_then(|url| url.split_once('#').map(|(_, token)| token))
        })
        .unwrap();
    let replay_response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{inspector}/api/replay"))
        .bearer_auth(token)
        .json(
            &serde_json::json!({"method":"GET","path":"/standalone-replay",
            "headers":[],"body_base64":""}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(replay_response.status(), 200);
    let result: serde_json::Value = replay_response.json().await.unwrap();
    assert_eq!(result["status"], 200);
    assert_eq!(result["body_base64"], "MA==");
    println!("REPLAY LOCAL PASS {transport}: authenticated inspector -> relay -> current standalone pool");

    assert_eq!(distribution(public, 20).await, [10, 10]);
    a.healthy.store(false, Ordering::SeqCst);
    wait_health(inspector, &[false, true], &log).await;
    assert_eq!(distribution(public, 8).await, [0, 8]);
    b.healthy.store(false, Ordering::SeqCst);
    wait_health(inspector, &[false, false], &log).await;
    let response = http_get(public, "pool.pike.test", "/").await;
    assert_eq!(response.status(), 503);
    assert_eq!(response.headers()["retry-after"], "1");
    {
        use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Error};
        let socket = tokio::net::TcpStream::connect(("127.0.0.1", public))
            .await
            .unwrap();
        let request = "ws://pool.pike.test/ws".into_client_request().unwrap();
        match tokio_tungstenite::client_async(request, socket).await {
            Err(Error::Http(response)) => assert_eq!(response.status(), 503),
            _ => panic!("unavailable WebSocket pool must return 503"),
        }
    }
    let channel = tonic::transport::Endpoint::from_shared(format!("http://127.0.0.1:{public}"))
        .unwrap()
        .origin("http://pool.pike.test".parse().unwrap())
        .connect()
        .await
        .unwrap();
    let mut client = tonic::client::Grpc::new(channel);
    client.ready().await.unwrap();
    let unavailable = client
        .unary(
            tonic::Request::new(super::msg(b"unavailable")),
            "/echo.Echo/Unary".parse().unwrap(),
            super::codec(),
        )
        .await
        .unwrap_err();
    assert_eq!(unavailable.code(), tonic::Code::Unavailable);
    a.healthy.store(true, Ordering::SeqCst);
    b.healthy.store(true, Ordering::SeqCst);
    wait_health(inspector, &[true, true], &log).await;
    assert_eq!(distribution(public, 12).await, [6, 6]);
    // Both accept application bytes and then fail. Retrying would duplicate work.
    a.fail_after_body.store(true, Ordering::SeqCst);
    b.fail_after_body.store(true, Ordering::SeqCst);
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{public}/once"))
        .header("host", "pool.pike.test")
        .body("non-idempotent")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    let delivered = a.delivered.lock().unwrap().len() + b.delivered.lock().unwrap().len();
    assert_eq!(delivered, 1, "a failed POST must reach only one origin");
    a.fail_after_body.store(false, Ordering::SeqCst);
    b.fail_after_body.store(false, Ordering::SeqCst);
    // Repeated bounded-concurrency uploads through the pool. Memory excludes the
    // test origin/client process and samples only the actual CLI and relay.
    let baseline = rss(cli.0.id()) + rss(relay.0.id());
    let peak = Arc::new(std::sync::atomic::AtomicU64::new(baseline));
    let observed = peak.clone();
    let cli_pid = cli.0.id();
    let relay_pid = relay.0.id();
    let sampler = tokio::spawn(async move {
        loop {
            observed.fetch_max(rss(cli_pid) + rss(relay_pid), Ordering::SeqCst);
            sleep(Duration::from_millis(100)).await;
        }
    });
    let load_started = std::time::Instant::now();
    for round in 0..30 {
        let results = futures::future::join_all((0..2).map(|index| async move {
            let body = http_body_util::StreamBody::new(futures::stream::iter((0..32).map(|_| {
                Ok::<_, std::io::Error>(Frame::data(Bytes::from(vec![0x51; 32 * 1024])))
            })));
            let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(
                tokio::net::TcpStream::connect(("127.0.0.1", public))
                    .await
                    .unwrap(),
            ))
            .await
            .unwrap();
            let driver = tokio::spawn(connection);
            let request = Request::builder()
                .method("POST")
                .uri(format!("/load/{round}/{index}"))
                .header("host", "pool.pike.test")
                .body(body)
                .unwrap();
            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                Bytes::from_static(b"1048576")
            );
            driver.abort();
        }))
        .await;
        assert_eq!(results.len(), 2);
        sleep(Duration::from_secs(1)).await;
    }
    sampler.abort();
    let stopped = sampler.await.unwrap_err();
    assert!(stopped.is_cancelled(), "RSS sampler failed: {stopped}");
    let growth = peak.load(Ordering::SeqCst).saturating_sub(baseline);
    assert!(
        growth < 32 * 1024 * 1024,
        "pool CLI/relay RSS grew {growth} bytes"
    );
    let delivered = a.delivered.lock().unwrap().len() + b.delivered.lock().unwrap().len();
    assert_eq!(delivered, 61);
    println!("POOL PASS {transport}: distribution=10/10; health exclusion=0/8; all-down=503; recovery=6/6; failed-POST-deliveries=1; streamed-load=60MiB; load-seconds={}; rss-growth={growth}",load_started.elapsed().as_secs_f64());
    tasks.shutdown().await;
}
