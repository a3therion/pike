use anyhow::{anyhow, bail, Result};
use pike_core::quic::client::{LocalData, PikeConnection};
use pike_core::types::{TunnelConfig, TunnelId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{error, info};

pub struct TcpTunnel {
    config: TunnelConfig,
    local_port: u16,
    local_host: String,
    remote_port: Option<u16>,
    connection: PikeConnection,
    tunnel_id: Option<TunnelId>,
}

impl TcpTunnel {
    pub fn new(
        config: TunnelConfig,
        port: u16,
        host: String,
        remote_port: Option<u16>,
        connection: PikeConnection,
    ) -> Self {
        Self {
            config,
            local_port: port,
            local_host: host,
            remote_port,
            connection,
            tunnel_id: None,
        }
    }

    pub async fn register(&mut self) -> Result<u16> {
        let (tunnel_id, registration_rx) = self
            .connection
            .request_tunnel_registration(self.config.clone())
            .await?;
        self.tunnel_id = Some(tunnel_id);

        let registration = match timeout(Duration::from_secs(10), registration_rx).await {
            Ok(Ok(registration)) => registration,
            Ok(Err(_)) => bail!("registration confirmation channel closed"),
            Err(_) => bail!("registration timed out after 10s"),
        };

        let assigned_port = registration.remote_port.or(self.remote_port).unwrap_or(0);
        info!(
            tunnel_id = %tunnel_id,
            local_addr = %format!("{}:{}", self.local_host, self.local_port),
            remote_port = assigned_port,
            "TCP tunnel registration confirmed by server"
        );

        Ok(assigned_port)
    }

    async fn proxy_once(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let local_addr = format!("{}:{}", self.local_host, self.local_port);
        let mut local_stream = TcpStream::connect(&local_addr)
            .await
            .map_err(|e| anyhow!("failed to connect to local TCP server {local_addr}: {e}"))?;

        local_stream.write_all(payload).await?;
        local_stream.shutdown().await?;

        let mut response = Vec::new();
        local_stream.read_to_end(&mut response).await?;
        Ok(response)
    }

    pub async fn run(&mut self) -> Result<()> {
        let tunnel_id = self.tunnel_id.unwrap_or(self.config.id);
        info!(
            local_addr = %format!("{}:{}", self.local_host, self.local_port),
            tunnel_id = %tunnel_id,
            "TCP tunnel running"
        );

        while let Some(msg) = self.connection.data_rx.recv().await {
            if msg.tunnel_id != tunnel_id {
                continue;
            }

            match self.proxy_once(&msg.payload).await {
                Ok(response_payload) => {
                    let _ = self
                        .connection
                        .data_tx
                        .send(LocalData {
                            stream_id: Some(msg.stream_id),
                            tunnel_id,
                            connection_id: msg.connection_id,
                            source_addr: msg.source_addr,
                            payload: response_payload,
                            fin: true,
                            streaming: false,
                        })
                        .await;
                }
                Err(e) => {
                    error!(stream_id = msg.stream_id, error = %e, "failed to proxy TCP payload");
                }
            }
        }

        Ok(())
    }
}
