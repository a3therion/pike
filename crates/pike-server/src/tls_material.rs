//! Bounded ClientHello parsing shared by HTTPS, raw TLS and ingress-injected
//! endpoints. The returned prefix is every byte read, so the caller can forward
//! or resume the handshake without loss.
use anyhow::{ensure, Result};
use std::io::Cursor;
use tokio::io::{AsyncRead, AsyncReadExt};

pub async fn read_hello<S: AsyncRead + Unpin>(
    mut socket: S,
) -> Result<(S, rustls::server::Accepted, Vec<u8>)> {
    let mut acceptor = rustls::server::Acceptor::default();
    let mut prefix = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let count = socket.read(&mut buffer).await?;
        ensure!(count > 0, "EOF before TLS ClientHello");
        ensure!(
            prefix.len() + count <= 64 * 1024,
            "TLS ClientHello exceeds 64 KiB"
        );
        prefix.extend_from_slice(&buffer[..count]);
        let mut input = Cursor::new(&buffer[..count]);
        while input.position() < count as u64 {
            ensure!(
                acceptor.read_tls(&mut input)? > 0,
                "TLS parser made no progress"
            );
        }
        match acceptor.accept() {
            Ok(Some(accepted)) => return Ok((socket, accepted, prefix)),
            Ok(None) => {}
            Err((error, _alert)) => return Err(error.into()),
        }
    }
}
