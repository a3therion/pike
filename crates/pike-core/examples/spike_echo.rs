use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use pike_core::proto::ALPN_PROTOCOL;
use pike_core::quic::spike_echo_client::{ClientCommand, ClientEvent, SpikeEchoClient};
use pike_core::quic::spike_echo_server::{ServerCommand, ServerEvent, SpikeEchoServer};
use tokio::sync::mpsc;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::{connect_with_config, SimpleConnectionIdGenerator};
use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
use tokio_quiche::socket::Socket;
use tokio_quiche::ConnectionParams;
use uuid::Uuid;

const HELLO: &[u8] = b"hello";
const SERVER_INIT: &[u8] = b"server-init";

#[tokio::main]
async fn main() -> Result<()> {
    let cert_dir = std::env::temp_dir().join(format!("pike-spike-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&cert_dir)?;
    let (cert_path, key_path) = generate_self_signed_cert(&cert_dir)?;

    let (server_cmd_tx, mut server_event_rx, server_addr, server_task) =
        start_server(&cert_path, &key_path).await?;

    let (client_cmd_tx, mut client_event_rx) = Box::pin(start_client(server_addr)).await?;

    expect_connected(&mut client_event_rx).await?;
    expect_connected_server(&mut server_event_rx).await?;

    expect_echo(&mut client_event_rx).await?;

    server_cmd_tx
        .send(ServerCommand::SendServerInitiated(SERVER_INIT.to_vec()))
        .await?;

    expect_server_init(&mut client_event_rx).await?;

    client_cmd_tx.send(ClientCommand::Close).await?;
    server_cmd_tx.send(ServerCommand::Close).await?;

    expect_closed(&mut client_event_rx).await?;
    expect_closed_server(&mut server_event_rx).await?;

    server_task
        .await
        .context("server task join failed")?
        .context("server task failed")?;

    let _ = std::fs::remove_dir_all(cert_dir);

    println!("spike_echo passed: client/server echo + server-initiated stream");
    Ok(())
}

async fn start_server(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(
    mpsc::Sender<ServerCommand>,
    mpsc::Receiver<ServerEvent>,
    SocketAddr,
    tokio::task::JoinHandle<Result<()>>,
)> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;

    let mut settings = QuicSettings::default();
    settings.alpn = vec![ALPN_PROTOCOL.to_vec()];
    settings.max_idle_timeout = Some(Duration::from_secs(5));

    let cert_path_str = cert_path.to_string_lossy().to_string();
    let key_path_str = key_path.to_string_lossy().to_string();
    let params = ConnectionParams::new_server(
        settings,
        TlsCertificatePaths {
            cert: &cert_path_str,
            private_key: &key_path_str,
            kind: CertificateKind::X509,
        },
        Hooks::default(),
    );

    let mut listeners = listen(
        [socket],
        params,
        SimpleConnectionIdGenerator,
        DefaultMetrics,
    )?;

    let (server_cmd_tx, server_cmd_rx) = mpsc::channel(16);
    let (server_event_tx, server_event_rx) = mpsc::channel(16);

    let server_task = tokio::spawn(async move {
        let mut accept_rx = listeners.remove(0).into_inner();
        let conn = accept_rx
            .recv()
            .await
            .ok_or_else(|| anyhow!("listener closed before connection"))??;

        let server_app = SpikeEchoServer::new(server_event_tx, server_cmd_rx);
        conn.start(server_app);
        Ok(())
    });

    Ok((server_cmd_tx, server_event_rx, server_addr, server_task))
}

async fn start_client(
    server_addr: SocketAddr,
) -> Result<(mpsc::Sender<ClientCommand>, mpsc::Receiver<ClientEvent>)> {
    let mut settings = QuicSettings::default();
    settings.alpn = vec![ALPN_PROTOCOL.to_vec()];
    settings.verify_peer = false;
    settings.max_idle_timeout = Some(Duration::from_secs(5));

    let params = ConnectionParams::new_client(settings, None, Hooks::default());

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(server_addr).await?;

    let (client_cmd_tx, client_cmd_rx) = mpsc::channel(16);
    let (client_event_tx, client_event_rx) = mpsc::channel(16);

    let app = SpikeEchoClient::new(client_event_tx, client_cmd_rx, HELLO.to_vec());

    let socket = Socket::try_from(socket)?;
    let _connection = Box::pin(connect_with_config(socket, Some("localhost"), &params, app))
        .await
        .map_err(|error| anyhow!(error.to_string()))?;

    Ok((client_cmd_tx, client_event_rx))
}

async fn expect_connected(client_event_rx: &mut mpsc::Receiver<ClientEvent>) -> Result<()> {
    let event = recv_event(client_event_rx, "client connected").await?;
    if !matches!(event, ClientEvent::Connected) {
        return Err(anyhow!("unexpected client event: {event:?}"));
    }

    Ok(())
}

async fn expect_connected_server(server_event_rx: &mut mpsc::Receiver<ServerEvent>) -> Result<()> {
    let event = recv_event(server_event_rx, "server connected").await?;
    if !matches!(event, ServerEvent::Connected) {
        return Err(anyhow!("unexpected server event: {event:?}"));
    }

    Ok(())
}

async fn expect_echo(client_event_rx: &mut mpsc::Receiver<ClientEvent>) -> Result<()> {
    loop {
        let event = recv_event(client_event_rx, "echo response").await?;
        if let ClientEvent::EchoReceived(payload) = event {
            if payload == HELLO {
                return Ok(());
            }

            return Err(anyhow!(
                "echo payload mismatch: expected {HELLO:?}, got {payload:?}"
            ));
        }
    }
}

async fn expect_server_init(client_event_rx: &mut mpsc::Receiver<ClientEvent>) -> Result<()> {
    loop {
        let event = recv_event(client_event_rx, "server-initiated payload").await?;
        if let ClientEvent::ServerInitiatedReceived(payload) = event {
            if payload == SERVER_INIT {
                return Ok(());
            }

            return Err(anyhow!(
                "server-initiated payload mismatch: expected {SERVER_INIT:?}, got {payload:?}"
            ));
        }
    }
}

async fn expect_closed(client_event_rx: &mut mpsc::Receiver<ClientEvent>) -> Result<()> {
    loop {
        let event = recv_event(client_event_rx, "client close").await?;
        if matches!(event, ClientEvent::Closed) {
            return Ok(());
        }
    }
}

async fn expect_closed_server(server_event_rx: &mut mpsc::Receiver<ServerEvent>) -> Result<()> {
    loop {
        let event = recv_event(server_event_rx, "server close").await?;
        if matches!(event, ServerEvent::Closed) {
            return Ok(());
        }
    }
}

async fn recv_event<T: std::fmt::Debug>(rx: &mut mpsc::Receiver<T>, label: &str) -> Result<T> {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .with_context(|| format!("timed out waiting for {label}"))?
        .ok_or_else(|| anyhow!("event channel closed while waiting for {label}"))
}

fn generate_self_signed_cert(output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let cert_path = output_dir.join("cert.pem");
    let key_path = output_dir.join("key.pem");

    let status = Command::new("openssl")
        .arg("req")
        .arg("-x509")
        .arg("-newkey")
        .arg("rsa:2048")
        .arg("-nodes")
        .arg("-keyout")
        .arg(&key_path)
        .arg("-out")
        .arg(&cert_path)
        .arg("-days")
        .arg("1")
        .arg("-subj")
        .arg("/CN=localhost")
        .status()
        .context("failed to launch openssl")?;

    if !status.success() {
        return Err(anyhow!("openssl failed generating self-signed cert"));
    }

    Ok((cert_path, key_path))
}
