pub mod http;
mod http_stream;
pub(crate) mod origin;
pub(crate) mod pool;
pub mod tcp;

pub use http::HttpTunnel;
pub use tcp::TcpTunnel;

pub mod udp;

/// TCP and UDP share connection, registration and reconnect orchestration.
pub enum PortTunnel {
    Tcp(TcpTunnel),
    Udp(udp::UdpTunnel),
}
impl PortTunnel {
    pub fn public_url(&self) -> Option<&str> {
        match self {
            Self::Tcp(t) => t.public_url(),
            Self::Udp(_) => None,
        }
    }
    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
        match self {
            Self::Tcp(t) => t.shutdown().await,
            Self::Udp(t) => t.shutdown().await,
        }
    }

    pub async fn register(&mut self) -> anyhow::Result<u16> {
        match self {
            Self::Tcp(t) => t.register().await,
            Self::Udp(t) => t.register().await,
        }
    }
    pub async fn run(&mut self) -> anyhow::Result<()> {
        match self {
            Self::Tcp(t) => t.run().await,
            Self::Udp(t) => t.run().await,
        }
    }
}
