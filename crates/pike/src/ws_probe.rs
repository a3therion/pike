use std::time::Duration;

use anyhow::{anyhow, Result};
use colored::Colorize;
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

#[derive(Debug, Clone)]
pub struct WsTestOptions {
    pub port: u16,
    pub path: String,
    pub frames: u32,
    pub binary: bool,
    pub timeout: Duration,
}

pub async fn run_ws_test(options: WsTestOptions) -> Result<()> {
    if options.frames == 0 {
        return Err(anyhow!("--frames must be at least 1"));
    }

    let path = normalize_ws_path(&options.path)?;
    let url = format!("ws://127.0.0.1:{}{}", options.port, path);

    println!("{}", "Pike WebSocket local upstream test".bold());
    println!("  {} {}", "Target:".dimmed(), url);
    println!(
        "  {} {}",
        "Scope:".dimmed(),
        "local upstream only; this does not start or use a Pike tunnel"
    );

    let connect_result = tokio::time::timeout(options.timeout, connect_async(&url)).await;
    let (mut socket, response) = match connect_result {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => return Err(format_connect_error(&url, options.port, error)),
        Err(_) => {
            return Err(anyhow!(
                "timed out connecting to local WebSocket upstream at {url}; verify a service is listening on 127.0.0.1:{}",
                options.port
            ));
        }
    };

    println!(
        "  {} {}",
        "Handshake:".dimmed(),
        format!("HTTP {}", response.status()).green()
    );

    for frame_index in 1..=options.frames {
        let payload = format!("pike-test-ws-{frame_index}");
        if options.binary {
            socket.send(Message::binary(payload.as_bytes())).await?;
        } else {
            socket.send(Message::text(payload.clone())).await?;
        }

        let message = read_next_data_message(&mut socket, options.timeout).await?;
        match (options.binary, message) {
            (true, Message::Binary(bytes)) if bytes == payload.as_bytes() => {
                println!(
                    "  {} frame {}/{} binary echo ok",
                    "\u{25CF}".green(),
                    frame_index,
                    options.frames
                );
            }
            (false, Message::Text(text)) if text == payload => {
                println!(
                    "  {} frame {}/{} text echo ok",
                    "\u{25CF}".green(),
                    frame_index,
                    options.frames
                );
            }
            (true, other) => {
                return Err(anyhow!(
                    "frame {frame_index} did not echo the expected binary payload; received {}",
                    describe_message(&other)
                ));
            }
            (false, other) => {
                return Err(anyhow!(
                    "frame {frame_index} did not echo the expected text payload; received {}",
                    describe_message(&other)
                ));
            }
        }
    }

    let _ = socket.close(None).await;
    println!(
        "  {} {}",
        "\u{25CF}".green(),
        format!(
            "Local WebSocket echo passed. To test through Pike, run `pike http {}` and connect to the public URL with path `{}`.",
            options.port,
            path
        )
        .bold()
    );

    Ok(())
}

fn normalize_ws_path(path: &str) -> Result<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("--path cannot be empty"));
    }
    if trimmed.contains(char::is_whitespace) {
        return Err(anyhow!(
            "--path must be URL-encoded and cannot contain whitespace"
        ));
    }
    if trimmed.starts_with('/') {
        Ok(trimmed.to_string())
    } else {
        Ok(format!("/{trimmed}"))
    }
}

async fn read_next_data_message<S>(socket: &mut S, timeout: Duration) -> Result<Message>
where
    S: futures::Stream<Item = std::result::Result<Message, WsError>> + Unpin,
{
    loop {
        let next = tokio::time::timeout(timeout, socket.next()).await;
        let message = match next {
            Ok(Some(Ok(message))) => message,
            Ok(Some(Err(error))) => return Err(anyhow!("failed reading WebSocket frame: {error}")),
            Ok(None) => {
                return Err(anyhow!(
                    "WebSocket closed before an echo frame was received"
                ))
            }
            Err(_) => return Err(anyhow!("timed out waiting for WebSocket echo frame")),
        };

        match message {
            Message::Text(_) | Message::Binary(_) => return Ok(message),
            Message::Close(frame) => {
                return Err(anyhow!("WebSocket closed before echo: {:?}", frame));
            }
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }
}

fn format_connect_error(url: &str, port: u16, error: WsError) -> anyhow::Error {
    if let WsError::Io(io_error) = &error {
        return match io_error.kind() {
            std::io::ErrorKind::ConnectionRefused => anyhow!(
                "could not connect to local WebSocket upstream at {url}: no process is listening on 127.0.0.1:{port}"
            ),
            std::io::ErrorKind::TimedOut => anyhow!(
                "timed out connecting to local WebSocket upstream at {url}"
            ),
            std::io::ErrorKind::ConnectionReset => anyhow!(
                "local WebSocket upstream at {url} reset the connection during handshake"
            ),
            _ => anyhow!(
                "could not connect to local WebSocket upstream at {url}: {io_error}"
            ),
        };
    }

    anyhow!("could not complete WebSocket handshake with local upstream at {url}: {error}")
}

fn describe_message(message: &Message) -> &'static str {
    match message {
        Message::Text(_) => "text frame",
        Message::Binary(_) => "binary frame",
        Message::Ping(_) => "ping frame",
        Message::Pong(_) => "pong frame",
        Message::Close(_) => "close frame",
        Message::Frame(_) => "raw frame",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_ws_paths() {
        assert_eq!(normalize_ws_path("/media").unwrap(), "/media");
        assert_eq!(normalize_ws_path("media").unwrap(), "/media");
        assert_eq!(normalize_ws_path("/media?room=1").unwrap(), "/media?room=1");
    }

    #[test]
    fn rejects_empty_ws_path() {
        assert!(normalize_ws_path(" ").is_err());
    }

    #[test]
    fn rejects_ws_path_with_whitespace() {
        assert!(normalize_ws_path("/bad path").is_err());
    }
}
